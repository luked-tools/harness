/**
 * Validation-centre aggregation across downloads, transport, identity, UDS, parser, and topology evidence.
 */
(function registerValidationAnalysis(global) {
  "use strict";

  function addUnique(list, value) {
    if (value && !list.includes(value)) list.push(value);
  }

  function buildValidationCentre(report, options = {}) {
    const ecuLabel = options.ecuLabel || ((address) => address);
    const formatNumber = options.formatNumber || global.HarnessFormatters?.formatNumber || ((value) => String(value));
    const transportHealth = options.transportHealth || (() => ({ level: "ok" }));
    const defaultTcpAnalysis = options.defaultTcpAnalysis || { flows: [], events: [], gaps: [] };
    const findings = [];
    const affectedEcus = new Set();
    const affectedFlows = new Set();
    const affectedSessions = new Set();
    const addFinding = (finding) => {
      const severity = normaliseValidationSeverity(finding.severity);
      const row = {
        id: `VAL-${findings.length + 1}`,
        severity,
        category: finding.category || "Capture quality",
        sourceTool: finding.sourceTool || "Harness",
        title: finding.title || "Validation finding",
        detail: finding.detail || "",
        evidence: finding.evidence || finding.detail || "",
        packet: finding.packet || "",
        timestamp: finding.timestamp ?? null,
        ecuAddress: finding.ecuAddress || "",
        sessionId: finding.sessionId || "",
        flowKey: finding.flowKey || "",
        nodeId: finding.nodeId || "",
        validationKind: finding.validationKind || "finding",
        validationView: finding.validationView || "actionable",
        nrcClassification: finding.nrcClassification || "",
        nrc: finding.nrc || "",
        nrcName: finding.nrcName || "",
        originalService: finding.originalService || "",
        findingCount: finding.findingCount || 0,
        entity: finding.entity || validationEntity(finding, ecuLabel),
        jumpTarget: finding.jumpTarget || {}
      };
      findings.push(row);
      if (row.ecuAddress) affectedEcus.add(row.ecuAddress);
      if (row.flowKey) affectedFlows.add(row.flowKey);
      if (row.sessionId) affectedSessions.add(String(row.sessionId));
    };

    for (const item of report.downloadAnalysis?.findings || []) {
      if (item.severity === "info" && item.category === "Validation") continue;
      const session = (report.downloadAnalysis?.sessions || []).find((candidate) => String(candidate.id) === String(item.sessionId));
      addFinding({
        severity: item.severity,
        category: item.category === "Capture quality" ? "Capture quality" : "Software download",
        sourceTool: "Software Download",
        title: item.title,
        detail: item.detail,
        evidence: item.packet ? `packet ${item.packet}` : item.detail,
        packet: item.packet,
        timestamp: session?.startTimestamp ?? null,
        ecuAddress: item.ecuAddress,
        sessionId: item.sessionId,
        entity: item.ecuAddress ? ecuLabel(item.ecuAddress) : `Segment ${item.sessionId}`,
        jumpTarget: { tool: "download", sessionId: item.sessionId, tab: "validation" }
      });
    }

    const analysis = report.tcpAnalysis || defaultTcpAnalysis;
    const flows = (analysis.flows || []).map((flow) => ({ ...flow, health: transportHealth(flow, analysis) }));
    for (const flow of flows) {
      const health = flow.health || { level: "ok" };
      if (health.level !== "ok" && health.label !== "TCP gap") {
        addFinding({
          severity: health.level === "problem" ? "error" : health.level,
          category: "Transport / TCP",
          sourceTool: "Transport Timing",
          title: health.label,
          detail: health.detail,
          evidence: flow.key,
          flowKey: flow.key,
          entity: validationFlowEntity(flow),
          timestamp: flow.firstTimestamp ?? null,
          jumpTarget: { tool: "transport", flowKey: flow.key }
        });
      }
    }
    for (const gap of analysis.gaps || []) {
      addFinding({
        severity: "error",
        category: "Capture quality",
        sourceTool: "Transport Timing",
        title: "TCP stream gap",
        detail: `Capture missed ${formatNumber(gap.gap || 0)} TCP byte${Number(gap.gap) === 1 ? "" : "s"}; DoIP/UDS decoding may be incomplete.`,
        evidence: gap.flowKey,
        packet: gap.packet,
        timestamp: gap.timestamp,
        flowKey: gap.flowKey,
        entity: gap.flowKey,
        jumpTarget: { tool: "transport", flowKey: gap.flowKey }
      });
    }
    for (const group of slowAckFindings(analysis.events || [], formatNumber)) {
      addFinding(group);
    }

    for (const finding of report.identity?.findings || []) {
      addFinding({
        severity: finding.severity === "high" ? "error" : finding.severity === "medium" ? "warning" : "info",
        category: "Identity",
        sourceTool: "Address Identity",
        title: finding.title,
        detail: finding.evidence,
        evidence: finding.source || finding.entityType,
        entity: `${finding.entityType} ${finding.entityId}`,
        ecuAddress: finding.entityType === "Logical" ? finding.entityId : "",
        jumpTarget: { tool: "identity" }
      });
    }

    for (const warning of report.warnings || []) {
      if (/^TCP gap in DoIP stream/i.test(warning)) continue;
      addFinding({
        severity: "warning",
        category: "Parser",
        sourceTool: "Parser",
        title: "Parser warning",
        detail: warning,
        evidence: warning,
        entity: "Capture",
        jumpTarget: { tool: "discovery" }
      });
    }

    for (const finding of doipTargetRejectedByGatewayFindings(report)) {
      addFinding(finding);
    }

    for (const finding of diagnosticDoipNackFindings(report)) {
      addFinding(finding);
    }

    for (const finding of genericDoipNackFindings(report)) {
      addFinding(finding);
    }

    for (const finding of autoIpAfterDhcpFindings(report, ecuLabel)) {
      addFinding(finding);
    }

    const negativeByKey = new Map();
    for (const event of report.diagnostics?.udsEvents || []) {
      if (event.responseKind === "negative") {
        const recoveredSecurityInvalidKey = isSecurityInvalidKeyNegative(event) && isRecoveredSecurityInvalidKey(report, event);
        const key = negativeGroupKey(report, event, recoveredSecurityInvalidKey);
        const existing = negativeByKey.get(key) || { count: 0, packets: [], lastTimestamp: event.timestamp, event, recoveredSecurityInvalidKey };
        existing.count += 1;
        if (event.packet) addUnique(existing.packets, event.packet);
        existing.lastTimestamp = Math.max(existing.lastTimestamp || 0, event.timestamp || 0);
        negativeByKey.set(key, existing);
      }
    }
    for (const group of negativeByKey.values()) {
      const event = group.event;
      const classification = classifyNrcGroup(group);
      addFinding({
        severity: classification.severity,
        category: "UDS diagnostics",
        sourceTool: "UDS Analyser",
        title: `${event.originalService || event.service} negative response ${event.nrc || ""}`.trim(),
        detail: `${formatNumber(group.count)} negative response${group.count === 1 ? "" : "s"} from ${ecuLabel(event.ecuAddress)}: ${event.nrcName || "NRC"}. ${classification.detail}`,
        evidence: `packets ${group.packets.slice(0, 8).join(", ")}`,
        packet: group.packets[0],
        timestamp: group.lastTimestamp,
        ecuAddress: event.ecuAddress,
        validationKind: "nrc",
        validationView: classification.view,
        nrcClassification: classification.classification,
        nrc: event.nrc,
        nrcName: event.nrcName || "",
        originalService: event.originalService || event.service || "",
        findingCount: group.count,
        entity: ecuLabel(event.ecuAddress),
        jumpTarget: { tool: "uds", ecuAddress: event.ecuAddress, tab: "errors" }
      });
    }
    const pendingByEcu = new Map();
    for (const event of report.diagnostics?.udsEvents || []) {
      if (event.responseKind !== "pending") continue;
      const item = pendingByEcu.get(event.ecuAddress) || { count: 0, packets: [], timestamp: event.timestamp };
      item.count += 1;
      item.timestamp = Math.max(item.timestamp || 0, event.timestamp || 0);
      if (event.packet) addUnique(item.packets, event.packet);
      pendingByEcu.set(event.ecuAddress, item);
    }
    for (const [ecuAddress, item] of pendingByEcu.entries()) {
      if (item.count <= 5) continue;
      addFinding({
        severity: "info",
        category: "UDS diagnostics",
        sourceTool: "UDS Analyser",
        title: "Repeated response pending",
        detail: `${formatNumber(item.count)} NRC 0x78 ResponsePending messages were observed for ${ecuLabel(ecuAddress)}. ResponsePending is expected UDS flow-control behavior and is informational by default.`,
        evidence: `packets ${item.packets.slice(0, 8).join(", ")}`,
        packet: item.packets[0],
        timestamp: item.timestamp,
        ecuAddress,
        validationKind: "nrc-pending",
        validationView: "informational",
        nrcClassification: "informational",
        nrc: "0x78",
        nrcName: "Response pending",
        originalService: "",
        findingCount: item.count,
        entity: ecuLabel(ecuAddress),
        jumpTarget: { tool: "uds", ecuAddress, tab: "errors" }
      });
    }
    const groups = {
      bySeverity: countBy(findings, "severity"),
      bySource: countBy(findings, "sourceTool"),
      byCategory: countBy(findings, "category"),
      byEntity: countBy(findings, "entity")
    };
    const severityRank = { error: 0, warning: 1, info: 2, ok: 3 };
    findings.sort((a, b) => severityRank[a.severity] - severityRank[b.severity] || String(a.sourceTool).localeCompare(String(b.sourceTool)) || String(a.entity).localeCompare(String(b.entity)));
    findings.forEach((finding, index) => { finding.id = `VAL-${index + 1}`; });
    const nrcSummary = findings
      .filter((item) => item.validationKind === "nrc" || item.validationKind === "nrc-pending")
      .map((item) => ({
        id: item.id,
        severity: item.severity,
        classification: item.nrcClassification || item.validationView || "actionable",
        ecuAddress: item.ecuAddress,
        entity: item.entity,
        service: item.originalService,
        nrc: item.nrc,
        nrcName: item.nrcName,
        count: item.findingCount || 1,
        packet: item.packet,
        timestamp: item.timestamp,
        evidence: item.evidence,
        jumpTarget: item.jumpTarget
      }));
    return {
      summary: {
        errors: findings.filter((item) => item.severity === "error").length,
        warnings: findings.filter((item) => item.severity === "warning").length,
        info: findings.filter((item) => item.severity === "info").length,
        totalFindings: findings.length,
        actionableNrcs: findings.filter((item) => (item.validationKind === "nrc" || item.validationKind === "nrc-pending") && item.validationView === "actionable").length,
        informationalNrcs: findings.filter((item) => (item.validationKind === "nrc" || item.validationKind === "nrc-pending") && item.validationView === "informational").length,
        repeatedPendingGroups: findings.filter((item) => item.validationKind === "nrc-pending").length,
        affectedEcus: affectedEcus.size,
        affectedFlows: affectedFlows.size,
        affectedSessions: affectedSessions.size
      },
      findings,
      nrcSummary,
      groups
    };
  }

  function classifyNrcGroup(group) {
    const event = group.event || {};
    const service = event.originalService || event.service || "";
    const nrc = event.nrc || "";
    if (group.recoveredSecurityInvalidKey) {
      return {
        severity: "info",
        view: "informational",
        classification: "informational",
        detail: "This recovered SecurityAccess invalid-key attempt is kept as protocol evidence, but it is not action-required because a matching positive response followed."
      };
    }
    if (isSecurityInvalidKeyNegative(event)) {
      return {
        severity: "error",
        view: "actionable",
        classification: "actionable",
        detail: "Unrecovered SecurityAccess invalid-key responses are action-required."
      };
    }
    if (isTransferOrProgrammingNrc(service, nrc)) {
      return {
        severity: "error",
        view: "actionable",
        classification: "actionable",
        detail: "This service/NRC combination can affect programming, transfer, or request sequencing and is action-required."
      };
    }
    if (group.count >= 100) {
      return {
        severity: "warning",
        view: "actionable",
        classification: "actionable",
        detail: "The response is usually routine, but the high count makes it worth reviewing."
      };
    }
    if (isRoutineNrc(service, nrc)) {
      return {
        severity: "info",
        view: "informational",
        classification: "informational",
        detail: "This is commonly seen during service discovery, probing, or condition-dependent requests, so it is informational by default."
      };
    }
    return {
      severity: "warning",
      view: "actionable",
      classification: "actionable",
      detail: "This NRC is not in the routine probing list, so it remains action-required."
    };
  }

  function isTransferOrProgrammingNrc(service, nrc) {
    return ["0x24", "0x33", "0x36", "0x37", "0x70", "0x71", "0x72", "0x73"].includes(nrc) ||
      ["0x34", "0x35", "0x36", "0x37", "0x38"].includes(service);
  }

  function isRoutineNrc(service, nrc) {
    return ["0x11", "0x12", "0x22", "0x31"].includes(nrc) &&
      !["0x34", "0x35", "0x36", "0x37", "0x38"].includes(service);
  }

  function isRecoveredSecurityInvalidKey(report, event) {
    if (!isSecurityInvalidKeyNegative(event)) return false;
    const events = report.diagnostics?.udsEvents || [];
    const eventTime = Number(event.timestamp || 0);
    const matchingRequest = securityAccessRequestForNegative(report, event);
    const requestedSubFunction = matchingRequest?.subFunction || "";
    if (!requestedSubFunction) return false;
    return events.some((candidate) =>
      candidate.service === "0x67" &&
      candidate.ecuAddress === event.ecuAddress &&
      candidate.testerAddress === event.testerAddress &&
      candidate.subFunction === requestedSubFunction &&
      Number(candidate.timestamp || 0) >= eventTime &&
      Number(candidate.timestamp || 0) <= eventTime + 10
    );
  }

  function securityAccessRequestForNegative(report, event) {
    if (!isSecurityInvalidKeyNegative(event)) return null;
    const eventTime = Number(event.timestamp || 0);
    return (report.diagnostics?.udsEvents || [])
      .filter((candidate) =>
        candidate.direction === "request" &&
        candidate.service === "0x27" &&
        candidate.ecuAddress === event.ecuAddress &&
        candidate.testerAddress === event.testerAddress &&
        (event.requestEventId ? candidate.id === event.requestEventId : Number(candidate.timestamp || 0) <= eventTime)
      )
      .sort((a, b) => Number(b.timestamp || 0) - Number(a.timestamp || 0))[0] || null;
  }

  function isSecurityInvalidKeyNegative(event) {
    return event.originalService === "0x27" && event.nrc === "0x35";
  }

  function negativeGroupKey(report, event, recoveredSecurityInvalidKey = false) {
    if (!isSecurityInvalidKeyNegative(event)) return `${event.ecuAddress}|${event.originalService}|${event.nrc}`;
    const request = securityAccessRequestForNegative(report, event);
    return `${event.ecuAddress}|${event.testerAddress}|${event.originalService}|${event.nrc}|${request?.subFunction || ""}|${recoveredSecurityInvalidKey ? "recovered" : "unrecovered"}`;
  }

  function doipTargetRejectedByGatewayFindings(report) {
    const groups = new Map();
    for (const item of report.diagnostics?.ackNak || []) {
      if (item.type !== "0x8003" || item.ackCode !== "0x03" || !item.previousTarget) continue;
      const key = [item.previousTarget, item.srcIp || "", item.srcMac || "", item.previousSource || "", item.source || ""].join("|");
      const group = groups.get(key) || {
        target: item.previousTarget,
        tester: item.previousSource || "",
        gatewayLogical: item.source || "",
        gatewayIp: item.srcIp || "",
        gatewayMac: item.srcMac || "",
        ackCodeName: item.ackCodeName || "Unknown target address",
        packets: [],
        previousMessages: [],
        timestamp: item.timestamp ?? null
      };
      if (item.packet) addUnique(group.packets, item.packet);
      if (item.previousMessageHex) addUnique(group.previousMessages, item.previousMessageHex);
      group.timestamp = Math.max(group.timestamp || 0, item.timestamp || 0) || group.timestamp;
      groups.set(key, group);
    }
    return Array.from(groups.values()).map((group) => {
      const gateway = [group.gatewayIp, group.gatewayMac].filter(Boolean).join(" / ") || "gateway";
      const tester = group.tester ? ` from tester ${group.tester}` : "";
      const packetText = group.packets.length ? `packets ${group.packets.slice(0, 8).join(", ")}` : "";
      const previousText = group.previousMessages.length ? `; previous diagnostic bytes ${group.previousMessages.slice(0, 3).join(" | ")}` : "";
      return {
        severity: "warning",
        category: "DoIP diagnostics",
        sourceTool: "DoIP Discovery",
        title: "DoIP target rejected by gateway",
        detail: `Tester diagnostics${tester} for logical target ${group.target} were sent via ${gateway}, but the gateway returned diagnostic NACK 0x03 (${group.ackCodeName}). The gateway MAC is not treated as ownership evidence for that target.`,
        evidence: `${packetText}; gateway ${gateway}; target ${group.target}${tester}${previousText}`.replace(/^; /, ""),
        packet: group.packets[0],
        timestamp: group.timestamp,
        ecuAddress: group.target,
        entity: group.target,
        jumpTarget: { tool: "discovery" }
      };
    }).sort((a, b) => String(a.entity).localeCompare(String(b.entity)) || String(a.evidence).localeCompare(String(b.evidence)));
  }

  function genericDoipNackFindings(report) {
    const groups = new Map();
    for (const item of report.doip?.genericNacks || []) {
      const key = [item.nackCode || "", item.nackCodeName || "", item.srcIp || "", item.dstIp || ""].join("|");
      const group = groups.get(key) || {
        nackCode: item.nackCode || "",
        nackCodeName: item.nackCodeName || "Generic DoIP header negative acknowledgement",
        srcIp: item.srcIp || "",
        dstIp: item.dstIp || "",
        transport: item.transport || "",
        packets: [],
        timestamp: item.timestamp ?? null
      };
      if (item.packet) addUnique(group.packets, item.packet);
      group.timestamp = Math.max(group.timestamp || 0, item.timestamp || 0) || group.timestamp;
      groups.set(key, group);
    }
    return Array.from(groups.values()).map((group) => {
      const route = [group.srcIp, group.dstIp].filter(Boolean).join(" -> ") || "DoIP endpoint";
      const packetText = group.packets.length ? `packets ${group.packets.slice(0, 8).join(", ")}` : "";
      const codeText = group.nackCode ? `${group.nackCode} (${group.nackCodeName})` : group.nackCodeName;
      return {
        severity: ["0x02", "0x03", "0x04"].includes(group.nackCode) ? "error" : "warning",
        category: "DoIP transport",
        sourceTool: "DoIP Discovery",
        title: "DoIP transport/header NACK observed",
        detail: `A generic DoIP header negative acknowledgement was observed on ${route}: ${codeText}. This indicates the DoIP transport/protocol layer rejected a message before diagnostic payload handling.`,
        evidence: `${packetText}; ${group.transport || "DoIP"} ${route}`.replace(/^; /, ""),
        packet: group.packets[0],
        timestamp: group.timestamp,
        entity: route,
        jumpTarget: { tool: "discovery" }
      };
    }).sort((a, b) => String(a.entity).localeCompare(String(b.entity)) || String(a.title).localeCompare(String(b.title)));
  }

  function diagnosticDoipNackFindings(report) {
    const groups = new Map();
    for (const item of report.diagnostics?.ackNak || []) {
      if (item.type !== "0x8003") continue;
      if (item.ackCode === "0x03" && item.previousTarget) continue;
      const key = [item.ackCode || "", item.ackCodeName || "", item.srcIp || "", item.dstIp || "", item.source || "", item.target || "", item.previousTarget || ""].join("|");
      const group = groups.get(key) || {
        ackCode: item.ackCode || "",
        ackCodeName: item.ackCodeName || "Diagnostic negative acknowledgement",
        srcIp: item.srcIp || "",
        dstIp: item.dstIp || "",
        source: item.source || "",
        target: item.target || "",
        previousSource: item.previousSource || "",
        previousTarget: item.previousTarget || "",
        packets: [],
        previousMessages: [],
        timestamp: item.timestamp ?? null
      };
      if (item.packet) addUnique(group.packets, item.packet);
      if (item.previousMessageHex) addUnique(group.previousMessages, item.previousMessageHex);
      group.timestamp = Math.max(group.timestamp || 0, item.timestamp || 0) || group.timestamp;
      groups.set(key, group);
    }
    return Array.from(groups.values()).map((group) => {
      const route = [group.srcIp, group.dstIp].filter(Boolean).join(" -> ") || "DoIP endpoint";
      const packetText = group.packets.length ? `packets ${group.packets.slice(0, 8).join(", ")}` : "";
      const previousTarget = group.previousTarget ? `; previous target ${group.previousTarget}` : "";
      const previousText = group.previousMessages.length ? `; previous diagnostic bytes ${group.previousMessages.slice(0, 3).join(" | ")}` : "";
      const codeText = group.ackCode ? `${group.ackCode} (${group.ackCodeName})` : group.ackCodeName;
      return {
        severity: ["0x04", "0x05", "0x06", "0x08"].includes(group.ackCode) ? "error" : "warning",
        category: "DoIP diagnostics",
        sourceTool: "DoIP Discovery",
        title: "DoIP diagnostic NACK observed",
        detail: `A DoIP diagnostic message negative acknowledgement was observed on ${route}: ${codeText}. This means the DoIP entity rejected a diagnostic message after DoIP diagnostic payload handling.`,
        evidence: `${packetText}; ${route}; source ${group.source || "unknown"}; target ${group.target || "unknown"}${previousTarget}${previousText}`.replace(/^; /, ""),
        packet: group.packets[0],
        timestamp: group.timestamp,
        ecuAddress: group.previousTarget || group.target || "",
        entity: group.previousTarget || group.target || route,
        jumpTarget: { tool: "discovery" }
      };
    }).sort((a, b) => String(a.entity).localeCompare(String(b.entity)) || String(a.evidence).localeCompare(String(b.evidence)));
  }

  function autoIpAfterDhcpFindings(report, ecuLabel = (address) => address) {
    const transitions = global.HarnessIdentityAnalysis?.autoIpDhcpTransitions?.(report) || [];
    return transitions
      .map((transition) => ({
        ...transition,
        postAssignmentAutoIpResponseEvents: transition.postAssignmentAutoIpEvents.filter((event) => event.type === "UDS diagnostics" && event.direction === "response")
      }))
      .filter((transition) => transition.postAssignmentAutoIpResponseEvents.length)
      .map((transition) => {
        const firstAssignment = transition.assignments
          .slice()
          .sort((a, b) => Number(a.timestamp ?? a.packet ?? 0) - Number(b.timestamp ?? b.packet ?? 0))[0];
        const laterEvents = transition.postAssignmentAutoIpResponseEvents;
        const laterIps = Array.from(new Set(laterEvents.map((event) => event.ip).filter(Boolean)));
        const laterPackets = Array.from(new Set(laterEvents.map((event) => event.packet).filter(Boolean)));
        return {
          severity: "error",
          category: "DHCP / addressing",
          sourceTool: "Address Identity",
          title: "ECU continued using AutoIP after DHCP assignment",
          detail: `${ecuLabel(transition.logicalAddress)} was assigned DHCP address ${transition.dhcpIps.join(", ")} but later sent UDS responses from AutoIP ${laterIps.join(", ")}.`,
          evidence: `DHCP Ack packet ${firstAssignment?.packet || ""}; later AutoIP UDS response packets ${laterPackets.slice(0, 8).join(", ")}`.trim(),
          packet: laterPackets[0] || firstAssignment?.packet,
          timestamp: laterEvents[0]?.timestamp ?? firstAssignment?.timestamp ?? null,
          ecuAddress: transition.logicalAddress,
          entity: ecuLabel(transition.logicalAddress),
          jumpTarget: { tool: "topology", nodeId: report.doip?.logicalAddresses?.[transition.logicalAddress] ? `gateway:${transition.logicalAddress}` : `ecu:${transition.logicalAddress}` }
        };
      });
  }

  function slowAckFindings(events, formatNumber = (value) => String(value)) {
    const groups = new Map();
    for (const event of events || []) {
      if (event.type !== "Slow ACK") continue;
      const key = event.flowKey || `${event.src || ""}->${event.dst || ""}` || "unknown-flow";
      const group = groups.get(key) || {
        flowKey: event.flowKey || "",
        entity: event.flowKey || key,
        count: 0,
        packets: [],
        payloadPackets: [],
        maxLatency: null,
        firstTimestamp: event.timestamp ?? null,
        lastTimestamp: event.timestamp ?? null
      };
      group.count += 1;
      if (event.packet) addUnique(group.packets, event.packet);
      if (event.payloadPacket) addUnique(group.payloadPackets, event.payloadPacket);
      if (Number.isFinite(Number(event.latency))) group.maxLatency = Math.max(group.maxLatency ?? 0, Number(event.latency));
      group.firstTimestamp = minDefined(group.firstTimestamp, event.timestamp);
      group.lastTimestamp = maxDefined(group.lastTimestamp, event.timestamp);
      groups.set(key, group);
    }
    return Array.from(groups.values()).map((group) => {
      const latencyText = group.maxLatency !== null ? `; max latency ${formatSlowAckLatency(group.maxLatency)}` : "";
      const packetText = group.packets.length ? `ACK packets ${group.packets.slice(0, 8).join(", ")}` : "ACK packets not recorded";
      const payloadText = group.payloadPackets.length ? `; payload packets ${group.payloadPackets.slice(0, 8).join(", ")}` : "";
      return {
        severity: "warning",
        category: "Transport / TCP",
        sourceTool: "Transport Timing",
        title: "Slow ACK",
        detail: `${formatNumber(group.count)} slow TCP ACK${group.count === 1 ? "" : "s"} observed on this flow${latencyText}.`,
        evidence: `${packetText}${payloadText}`,
        packet: group.packets[0],
        timestamp: group.lastTimestamp,
        flowKey: group.flowKey,
        entity: group.entity,
        jumpTarget: { tool: "transport", flowKey: group.flowKey }
      };
    });
  }

  function formatSlowAckLatency(seconds) {
    const value = Number(seconds);
    if (!Number.isFinite(value)) return "n/a";
    if (value < 1) return `${Math.round(value * 1000)} ms`;
    return `${value.toFixed(3)} s`;
  }

  function minDefined(a, b) {
    if (a === null || a === undefined) return b ?? a;
    if (b === null || b === undefined) return a;
    return Math.min(Number(a), Number(b));
  }

  function maxDefined(a, b) {
    if (a === null || a === undefined) return b ?? a;
    if (b === null || b === undefined) return a;
    return Math.max(Number(a), Number(b));
  }

  function normaliseValidationSeverity(severity) {
    if (severity === "problem" || severity === "danger" || severity === "high") return "error";
    if (severity === "warn" || severity === "medium") return "warning";
    if (severity === "ok") return "info";
    return ["error", "warning", "info"].includes(severity) ? severity : "info";
  }

  function validationEntity(finding, ecuLabel = (address) => address) {
    if (finding.ecuAddress) return ecuLabel(finding.ecuAddress);
    if (finding.sessionId) return `Segment ${finding.sessionId}`;
    if (finding.flowKey) return finding.flowKey;
    if (finding.nodeId) return finding.nodeId;
    return "Capture";
  }

  function validationFlowEntity(flow) {
    const a = flow.endpointA || "";
    const b = flow.endpointB || "";
    return `${a} <-> ${b}`;
  }

  function countBy(items, key) {
    return items.reduce((acc, item) => {
      const value = item[key] || "Unknown";
      acc[value] = (acc[value] || 0) + 1;
      return acc;
    }, {});
  }

  global.HarnessValidationAnalysis = Object.freeze({
    buildValidationCentre,
    isRecoveredSecurityInvalidKey,
    securityAccessRequestForNegative,
    isSecurityInvalidKeyNegative,
    negativeGroupKey,
    classifyNrcGroup,
    isRoutineNrc,
    isTransferOrProgrammingNrc,
    doipTargetRejectedByGatewayFindings,
    diagnosticDoipNackFindings,
    genericDoipNackFindings,
    autoIpAfterDhcpFindings,
    slowAckFindings,
    normaliseValidationSeverity,
    validationEntity,
    validationFlowEntity,
    countBy
  });
})(window);
