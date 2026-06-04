/**
 * Export data shaping helpers for CSV/text downloads.
 */
(function registerExporters(global) {
  "use strict";

  const formatters = global.HarnessFormatters || {};
  const toCsv = formatters.toCsv || (() => "");

  const DID_COLUMNS = ["ecuAddress", "ecuName", "did", "name", "reads", "responses", "negatives", "pending", "latestValueAscii", "latestValueHex", "firstTimestamp", "lastTimestamp"];
  const EVENT_COLUMNS = ["id", "timestamp", "packet", "ecuAddress", "ecuName", "responseKind", "source", "target", "service", "serviceName", "did", "nrc", "nrcName", "raw"];
  const DTC_COLUMNS = ["recordType", "ecuAddress", "ecuName", "testerAddress", "dtc", "status", "statusLabels", "subFunction", "subFunctionName", "optionsHex", "snapshotRecordNumber", "extendedDataRecordNumber", "dataLength", "payloadAscii", "payloadHex", "timestamp", "packet", "responseKind", "resultType", "nrc", "nrcName", "raw"];
  const TRANSFER_COLUMNS = ["id", "ecuAddress", "ecuName", "testerAddress", "direction", "service", "startTimestamp", "endTimestamp", "expectedBlocks", "blocks", "acknowledgedBlocks", "reconstructedBytes", "pending", "negatives", "status", "exportable"];
  const DOWNLOAD_SESSION_COLUMNS = ["id", "ecuAddress", "ecuName", "testerAddress", "sessionType", "typeLabel", "startTimestamp", "endTimestamp", "requestPacket", "requestedBytes", "expectedBlocks", "blocks", "acknowledgedBlocks", "reconstructedBytes", "pending", "negatives", "status", "severity", "hexExportable"];
  const DOWNLOAD_VALIDATION_COLUMNS = ["sessionId", "ecuAddress", "ecuName", "sessionType", "severity", "category", "title", "detail", "packet"];
  const RATE_CAMPAIGN_COLUMNS = ["ecuAddress", "ecuName", "sessions", "payloadBytes", "activeTimeSeconds", "averageRateBps", "fastestRateBps", "slowestRateBps", "captureInfo"];
  const VALIDATION_COLUMNS = ["id", "severity", "category", "sourceTool", "entity", "ecuAddress", "sessionId", "flowKey", "nodeId", "title", "detail", "evidence", "packet", "timestamp"];
  const TCP_EVENT_COLUMNS = ["id", "timestamp", "packet", "type", "label", "src", "dst", "testerEndpoint", "doipNodeEndpoint", "ethernetLogicalAddress", "carriedLogicalAddresses", "flowControlStatus", "flowControlSeverity", "flowControlDirections", "latency", "ackNumber", "seq", "endSeq"];
  const TCP_ACK_COLUMNS = ["id", "direction", "testerEndpoint", "doipNodeEndpoint", "ethernetLogicalAddress", "carriedLogicalAddresses", "flowControlStatus", "flowControlSeverity", "flowControlDirections", "payloadPacket", "ackPacket", "payloadBytes", "latency", "sentTimestamp", "ackTimestamp"];

  function safeAddress(address) {
    return String(address || "").replace(/[^a-z0-9]/gi, "");
  }

  function exportSelected(kind, report, selectedEcuAddress, options = {}) {
    if (kind === "allDids") {
      return { filename: "uds-dids-all-ecus.csv", text: toCsv(report.diagnostics?.didReads || [], DID_COLUMNS) };
    }
    if (!selectedEcuAddress) return null;
    const safe = safeAddress(selectedEcuAddress);
    if (kind === "events") {
      return { filename: `uds-events-${safe}.csv`, text: toCsv(options.ecuEvents?.(selectedEcuAddress) || [], EVENT_COLUMNS) };
    }
    if (kind === "dids") {
      return { filename: `uds-dids-${safe}.csv`, text: toCsv((report.diagnostics?.didReads || []).filter((item) => item.ecuAddress === selectedEcuAddress), DID_COLUMNS) };
    }
    if (kind === "dtcs") {
      return { filename: `uds-dtcs-${safe}.csv`, text: toCsv((report.diagnostics?.dtcReads?.rows || []).filter((item) => item.ecuAddress === selectedEcuAddress), DTC_COLUMNS) };
    }
    if (kind === "transfers") {
      return { filename: `uds-transfers-${safe}.csv`, text: toCsv((report.diagnostics?.transfers || []).filter((item) => item.ecuAddress === selectedEcuAddress), TRANSFER_COLUMNS) };
    }
    return null;
  }

  function exportDownload(kind, report, options = {}) {
    const sessions = report.downloadAnalysis?.sessions || [];
    const ecuName = options.ecuName || (() => "");
    if (kind === "sessions") {
      return { filename: "software-download-segments.csv", text: toCsv(sessions, DOWNLOAD_SESSION_COLUMNS) };
    }
    if (kind === "rateCampaign") {
      const rows = (options.rateCampaignRows?.() || []).map((row) => ({
        ecuAddress: row.ecuAddress,
        ecuName: ecuName(row.ecuAddress),
        sessions: row.sessions,
        payloadBytes: row.payloadBytes,
        activeTimeSeconds: row.activeTime,
        averageRateBps: row.averageRateBps,
        fastestRateBps: row.fastestRateBps,
        slowestRateBps: row.slowestRateBps,
        captureInfo: row.captureInfo
      }));
      return { filename: "software-download-campaign-comparison.csv", text: toCsv(rows, RATE_CAMPAIGN_COLUMNS) };
    }
    if (kind === "validation") {
      const rows = sessions.flatMap((session) => (session.validation || []).map((finding) => ({
        sessionId: session.id,
        ecuAddress: session.ecuAddress,
        ecuName: ecuName(session.ecuAddress),
        sessionType: session.sessionType,
        severity: finding.severity,
        category: finding.category,
        title: finding.title,
        detail: finding.detail,
        packet: finding.packet
      })));
      return { filename: "software-download-validation.csv", text: toCsv(rows, DOWNLOAD_VALIDATION_COLUMNS) };
    }
    return null;
  }

  function exportValidationCentre(rows) {
    return { filename: "harness-validation-centre.csv", text: toCsv(rows || [], VALIDATION_COLUMNS) };
  }

  function identityFields(identity) {
    return {
      testerEndpoint: identity?.tester?.label || "",
      doipNodeEndpoint: identity?.doipNode?.label || "",
      ethernetLogicalAddress: (identity?.doipNode?.ethernetLogicalAddresses || []).join(" | "),
      carriedLogicalAddresses: (identity?.carriedLogicalAddresses || []).join(" | ")
    };
  }

  function flowControlFields(flow) {
    return {
      flowControlStatus: flow?.flowControl?.status?.label || "",
      flowControlSeverity: flow?.flowControl?.status?.severity || "",
      flowControlDirections: (flow?.flowControl?.directions || []).map((direction) =>
        `${direction.endpoint}: ${direction.status?.label || "OK"}, medianWindow=${direction.medianWindow ?? ""}, pureAcks=${direction.pureAcks || 0}, bytesPerAck=${Number.isFinite(direction.bytesPerAck) ? Math.round(direction.bytesPerAck) : ""}`
      ).join(" | ")
    };
  }

  function exportTcp(kind, report, selectedTcpFlowKey, options = {}) {
    if (!selectedTcpFlowKey) return null;
    const safe = String(selectedTcpFlowKey).replace(/[^a-z0-9]+/gi, "-").replace(/^-|-$/g, "");
    const flow = (report.tcpAnalysis?.flows || []).find((item) => item.key === selectedTcpFlowKey);
    const identity = flow ? options.transportFlowIdentity?.(flow, report) : null;
    if (kind === "events") {
      const rows = (report.tcpAnalysis?.events || [])
        .filter((event) => event.flowKey === selectedTcpFlowKey)
        .map((event) => ({ ...event, ...identityFields(identity), ...flowControlFields(flow) }));
      return { filename: `tcp-events-${safe}.csv`, text: toCsv(rows, TCP_EVENT_COLUMNS) };
    }
    const rows = (report.tcpAnalysis?.ackTimings || [])
      .filter((ack) => ack.flowKey === selectedTcpFlowKey)
      .map((ack) => ({ ...ack, ...identityFields(identity), ...flowControlFields(flow) }));
    return { filename: `tcp-ack-timings-${safe}.csv`, text: toCsv(rows, TCP_ACK_COLUMNS) };
  }

  function exportTopology(kind, topology) {
    const socketMap = topology.socketMap;
    if (socketMap?.sockets) {
      if (kind === "nodes") {
        const rows = socketMap.sockets.map((socket) => ({
          id: socket.id,
          ip: socket.ip,
          label: socket.label,
          directLogicalAddress: socket.directLogicalAddress,
          directName: socket.directName,
          observedIps: (socket.observedIps || []).join(" | "),
          autoIpAddresses: (socket.autoIpAddresses || []).join(" | "),
          dhcpIpAddresses: (socket.dhcpIpAddresses || []).join(" | "),
          macs: (socket.macs || []).join(" | "),
          eids: (socket.eids || []).join(" | "),
          vins: (socket.vins || []).join(" | "),
          routedLogicalAddresses: (socket.routed || []).map((item) => item.logicalAddress).join(" | "),
          rejectedTargets: (socket.rejected || []).map((item) => item.logicalAddress).join(" | "),
          packets: (socket.packets || []).join(" | "),
          evidence: (socket.evidence || []).join(" | ")
        }));
        return {
          filename: "topology-sockets.csv",
          text: toCsv(rows, ["id", "ip", "label", "directLogicalAddress", "directName", "observedIps", "autoIpAddresses", "dhcpIpAddresses", "macs", "eids", "vins", "routedLogicalAddresses", "rejectedTargets", "packets", "evidence"])
        };
      }
      const rows = socketMap.sockets.flatMap((socket) => [
        ...(socket.routed || []).map((item) => ({ socket, item, status: "routed" })),
        ...(socket.rejected || []).map((item) => ({ socket, item, status: "rejected" }))
      ]).map(({ socket, item, status }) => ({
        socketId: socket.id,
        socketIp: socket.ip,
        socketLogicalAddress: socket.directLogicalAddress,
        logicalAddress: item.logicalAddress,
        name: item.name,
        status,
        requests: item.requests || "",
        testers: (item.testers || []).join(" | "),
        services: (item.services || []).join(" | "),
        packets: (item.packets || []).join(" | "),
        evidence: (item.evidence || []).join(" | ")
      }));
      return {
        filename: "topology-socket-mappings.csv",
        text: toCsv(rows, ["socketId", "socketIp", "socketLogicalAddress", "logicalAddress", "name", "status", "requests", "testers", "services", "packets", "evidence"])
      };
    }
    if (kind === "nodes") {
      return {
        filename: "topology-nodes.csv",
        text: toCsv((topology.nodes || []).map((node) => ({
          id: node.id,
          role: node.role,
          label: node.label,
          logicalAddress: node.logicalAddress,
          friendlyName: node.friendlyName,
          ips: (node.ips || []).join(" | "),
          macs: (node.macs || []).join(" | "),
          eids: (node.eids || []).join(" | "),
          vins: (node.vins || []).join(" | "),
          ambiguous: Boolean(node.ambiguous),
          evidence: (node.evidence || []).join(" | ")
        })), ["id", "role", "label", "logicalAddress", "friendlyName", "ips", "macs", "eids", "vins", "ambiguous", "evidence"])
      };
    }
    return {
      filename: "topology-links.csv",
      text: toCsv((topology.edges || []).map((edge) => ({
        id: edge.id,
        kind: edge.kind,
        label: edge.label,
        source: edge.source,
        target: edge.target,
        count: edge.count,
        inferred: Boolean(edge.inferred),
        ambiguous: Boolean(edge.ambiguous),
        packets: (edge.packets || []).join(" | "),
        evidence: (edge.evidence || []).join(" | ")
      })), ["id", "kind", "label", "source", "target", "count", "inferred", "ambiguous", "packets", "evidence"])
    };
  }

  function downloadHexText(session) {
    return [
      "# Harness software download hex export",
      `# ECU: ${session.ecuAddress}`,
      `# Type: ${session.typeLabel}`,
      `# Session: ${session.id}`,
      `# Payload bytes: ${session.reconstructedBytes}`,
      ...(session.dataBlocks || []).map((block) => `block=${block.counter || ""} packet=${block.packet} time=${block.timestamp} bytes=${block.payloadBytes} ${block.payloadHex}`)
    ].join("\n");
  }

  global.HarnessExporters = Object.freeze({
    exportSelected,
    exportDownload,
    exportValidationCentre,
    exportTcp,
    exportTopology,
    downloadHexText
  });
})(window);
