/**
 * Network topology builder for diagnostic, announcement, and identity evidence.
 */
(function registerTopologyAnalysis(global) {
  "use strict";

  function addUnique(list, value) {
    if (value && !list.includes(value)) list.push(value);
  }

  function buildTopologyAnalysis(report, options = {}) {
    const ecuName = options.ecuName || ((address) => address);
    const ecuLabel = options.ecuLabel || ((address) => address);
    const buildIdentityAnalysis = options.buildIdentityAnalysis || global.HarnessIdentityAnalysis?.buildIdentityAnalysis || (() => ({ findings: [] }));
    const autoIpDhcpTransitions = global.HarnessIdentityAnalysis?.autoIpDhcpTransitions || (() => []);
    const expectedTransitions = autoIpDhcpTransitions(report);
    const expectedTransitionByLogical = new Map(expectedTransitions.map((transition) => [transition.logicalAddress, transition]));
    const nodes = new Map();
    const edges = new Map();
    const hostByIp = new Map();
    const hostByMac = new Map();
    const announcedByLogical = new Map();
    const gatewayByIp = new Map();
    const ambiguousIds = new Set();

    const addList = (target, values) => {
      for (const value of values || []) addUnique(target, value);
    };
    const ensureNode = (id, patch = {}) => {
      if (!nodes.has(id)) {
        nodes.set(id, {
          id,
          role: patch.role || "endpoint",
          label: patch.label || id,
          logicalAddress: "",
          friendlyName: "",
          ips: [],
          macs: [],
          eids: [],
          gids: [],
          vins: [],
          packets: [],
          timestamps: [],
          evidence: [],
          ambiguous: false
        });
      }
      const node = nodes.get(id);
      for (const key of ["role", "label", "logicalAddress", "friendlyName"]) {
        if (patch[key]) node[key] = patch[key];
      }
      for (const key of ["ips", "macs", "eids", "gids", "vins", "packets", "timestamps", "evidence"]) {
        addList(node[key], Array.isArray(patch[key]) ? patch[key] : patch[key] !== undefined && patch[key] !== null && patch[key] !== "" ? [patch[key]] : []);
      }
      node.ambiguous = node.ambiguous || Boolean(patch.ambiguous);
      return node;
    };
    const edgeKey = (source, target, kind) => `${source}|${target}|${kind}`;
    const ensureEdge = (source, target, kind, patch = {}) => {
      if (!source || !target || source === target) return null;
      const key = edgeKey(source, target, kind);
      if (!edges.has(key)) {
        edges.set(key, {
          id: `edge:${edges.size + 1}`,
          source,
          target,
          kind,
          label: patch.label || kind,
          packets: [],
          timestamps: [],
          evidence: [],
          count: 0,
          inferred: kind === "inferred" || Boolean(patch.inferred),
          ambiguous: false
        });
      }
      const edge = edges.get(key);
      edge.count += 1;
      if (patch.label) edge.label = patch.label;
      edge.inferred = edge.inferred || kind === "inferred" || Boolean(patch.inferred);
      edge.ambiguous = edge.ambiguous || Boolean(patch.ambiguous);
      addList(edge.packets, patch.packet !== undefined && patch.packet !== null ? [patch.packet] : patch.packets);
      addList(edge.timestamps, patch.timestamp !== undefined && patch.timestamp !== null ? [patch.timestamp] : patch.timestamps);
      addList(edge.evidence, patch.evidence ? [patch.evidence] : patch.evidenceList);
      return edge;
    };

    for (const host of Object.values(report.hosts || {})) {
      hostByMac.set(host.mac, host);
      for (const ipAddress of host.ips || []) {
        if (!hostByIp.has(ipAddress)) hostByIp.set(ipAddress, []);
        hostByIp.get(ipAddress).push(host);
      }
    }

    const endpointId = (ipAddress, macAddress) => macAddress ? `endpoint:${macAddress}` : ipAddress ? `endpoint:${ipAddress}` : "";
    const endpointFor = (ipAddress, macAddress, role = "endpoint", evidence = "") => {
      const hostsForIp = ipAddress ? hostByIp.get(ipAddress) || [] : [];
      const host = macAddress ? hostByMac.get(macAddress) : hostsForIp.length === 1 ? hostsForIp[0] : null;
      const macAddressValue = macAddress || host?.mac || "";
      const id = endpointId(ipAddress, macAddressValue);
      if (!id) return "";
      const ambiguous = !macAddressValue && hostsForIp.length > 1;
      ensureNode(id, {
        role,
        label: role === "dhcp" ? `DHCP server ${ipAddress || macAddressValue}` : `Endpoint ${ipAddress || macAddressValue}`,
        ips: host?.ips || (ipAddress ? [ipAddress] : []),
        macs: macAddressValue ? [macAddressValue] : hostsForIp.map((item) => item.mac),
        evidence: ambiguous ? `${evidence}; IP has multiple observed MAC owners` : evidence,
        ambiguous
      });
      return id;
    };

    for (const ipAddress of Object.keys(report.dhcp?.servers || {})) endpointFor(ipAddress, "", "dhcp", "DHCP server observation");

    for (const announcement of report.doip?.announcements || []) {
      const logical = announcement.logicalAddress;
      if (!logical) continue;
      const gatewayId = `gateway:${logical}`;
      announcedByLogical.set(logical, gatewayId);
      if (announcement.srcIp) gatewayByIp.set(announcement.srcIp, gatewayId);
      const name = ecuName(logical);
      ensureNode(gatewayId, {
        role: "gateway",
        label: name || logical,
        logicalAddress: logical,
        friendlyName: name,
        ips: [announcement.srcIp],
        macs: [announcement.srcMac],
        eids: [announcement.eid],
        gids: [announcement.gid],
        vins: [announcement.vin],
        packets: [announcement.packet],
        timestamps: [announcement.timestamp],
        evidence: `Vehicle announcement from ${announcement.srcIp || "unknown IP"}`
      });
      const endpoint = endpointFor(announcement.srcIp, announcement.srcMac, "endpoint", "DoIP announcement endpoint");
      ensureEdge(endpoint, gatewayId, "announcement", {
        label: "announcement",
        packet: announcement.packet,
        timestamp: announcement.timestamp,
        evidence: `${logical} announced VIN ${announcement.vin || "unknown"}`
      });
    }

    for (const event of report.traceEvents || []) {
      if (!["0x0005", "0x0006"].includes(event.payloadType)) continue;
      const tester = event.logicalAddress;
      if (!tester) continue;
      const testerId = `tester:${tester}`;
      ensureNode(testerId, {
        role: "tester",
        label: `Tester ${tester}`,
        logicalAddress: tester,
        ips: [event.srcIp, event.dstIp].filter(Boolean),
        packets: [event.packet],
        timestamps: [event.timestamp],
        evidence: event.payloadName
      });
      const gatewayId = gatewayByIp.get(event.dstIp) || gatewayByIp.get(event.srcIp) || "";
      if (gatewayId) {
        ensureEdge(testerId, gatewayId, "routing", {
          label: "routing activation",
          packet: event.packet,
          timestamp: event.timestamp,
          evidence: `${event.payloadName} ${event.srcIp || ""} -> ${event.dstIp || ""}`.trim()
        });
      }
    }

    for (const event of report.diagnostics?.udsEvents || []) {
      if (event.direction !== "request") continue;
      const testerId = `tester:${event.testerAddress}`;
      ensureNode(testerId, {
        role: "tester",
        label: `Tester ${event.testerAddress}`,
        logicalAddress: event.testerAddress,
        ips: [event.srcIp],
        packets: [event.packet],
        timestamps: [event.timestamp],
        evidence: "UDS request source"
      });
      const announcedGateway = announcedByLogical.get(event.ecuAddress);
      const pathGateway = gatewayByIp.get(event.dstIp);
      const ecuId = announcedGateway || `ecu:${event.ecuAddress}`;
      const ecu = report.diagnostics?.ecus?.[event.ecuAddress] || {};
      ensureNode(ecuId, {
        role: announcedGateway ? "gateway" : "ecu",
        label: ecuLabel(event.ecuAddress),
        logicalAddress: event.ecuAddress,
        friendlyName: ecu.name,
        ips: ecu.ips || [event.dstIp],
        eids: ecu.eids || [],
        gids: ecu.gids || [],
        vins: ecu.vins || [],
        packets: [event.packet],
        timestamps: [event.timestamp],
        evidence: `${event.service} ${event.serviceName}`
      });
      ensureEdge(testerId, pathGateway || ecuId, "diagnostic", {
        label: "diagnostic path",
        packet: event.packet,
        timestamp: event.timestamp,
        evidence: `${event.source} -> ${event.target} ${event.service} ${event.serviceName}`
      });
      if (pathGateway && pathGateway !== ecuId && !announcedGateway) {
        ensureEdge(pathGateway, ecuId, "inferred", {
          label: "inferred via gateway",
          packet: event.packet,
          timestamp: event.timestamp,
          inferred: true,
          evidence: `${event.ecuAddress} reached through ${event.dstIp || "gateway IP"}`
        });
      }
      const endpointHosts = event.dstIp ? hostByIp.get(event.dstIp) || [] : [];
      const endpoint = endpointFor(event.dstIp, "", "endpoint", "UDS diagnostic endpoint");
      if (endpoint && pathGateway) {
        ensureEdge(endpoint, pathGateway, "ownership", {
          label: "IP/MAC ownership",
          packet: event.packet,
          timestamp: event.timestamp,
          evidence: `${event.dstIp || "unknown IP"} carried diagnostics`,
          ambiguous: endpointHosts.length > 1
        });
      }
    }

    for (const transition of expectedTransitions) {
      const id = announcedByLogical.get(transition.logicalAddress) || `ecu:${transition.logicalAddress}`;
      ensureNode(id, {
        role: id.startsWith("gateway:") ? "gateway" : "ecu",
        label: ecuLabel(transition.logicalAddress),
        logicalAddress: transition.logicalAddress,
        ips: [...transition.autoIps, ...transition.dhcpIps],
        macs: transition.macs,
        packets: transition.assignments.map((assignment) => assignment.packet),
        timestamps: transition.assignments.map((assignment) => assignment.timestamp),
        evidence: `AutoIP followed by DHCP assignment (${transition.autoIps.join(", ")} -> ${transition.dhcpIps.join(", ")})`
      });
    }

    const identity = report.identity?.findings?.length ? report.identity : buildIdentityAnalysis(report);
    for (const finding of identity.findings || []) {
      if (!/multiple|conflict/i.test(`${finding.title} ${finding.evidence}`)) continue;
      if (finding.entityType === "Logical" && expectedTransitionByLogical.has(finding.entityId) && /multiple IP addresses/i.test(finding.title)) continue;
      const id = finding.entityType === "Logical" ? (announcedByLogical.get(finding.entityId) || `ecu:${finding.entityId}`) : finding.entityType === "MAC" ? `endpoint:${finding.entityId}` : `endpoint:${finding.entityId}`;
      ambiguousIds.add(id);
      ensureNode(id, {
        role: id.startsWith("ecu:") ? "ecu" : id.startsWith("gateway:") ? "gateway" : "endpoint",
        label: finding.entityId,
        logicalAddress: finding.entityType === "Logical" ? finding.entityId : "",
        ips: finding.entityType === "IP" ? [finding.entityId] : [],
        macs: finding.entityType === "MAC" ? [finding.entityId] : [],
        evidence: finding.title,
        ambiguous: true
      });
    }

    for (const id of ambiguousIds) {
      const node = nodes.get(id);
      if (node) node.ambiguous = true;
    }

    const nodeList = Array.from(nodes.values()).map((node) => ({
      ...node,
      packets: node.packets.filter((value, index, list) => value !== undefined && value !== null && list.indexOf(value) === index).slice(0, 20),
      timestamps: node.timestamps.filter((value, index, list) => value !== undefined && value !== null && list.indexOf(value) === index).slice(0, 20),
      evidence: node.evidence.filter(Boolean).slice(0, 8)
    })).sort((a, b) => topologyRoleRank(a.role) - topologyRoleRank(b.role) || a.label.localeCompare(b.label));
    const edgeList = Array.from(edges.values()).map((edge) => ({
      ...edge,
      packets: edge.packets.filter((value, index, list) => value !== undefined && value !== null && list.indexOf(value) === index).slice(0, 20),
      timestamps: edge.timestamps.filter((value, index, list) => value !== undefined && value !== null && list.indexOf(value) === index).slice(0, 20),
      evidence: edge.evidence.filter(Boolean).slice(0, 8)
    })).sort((a, b) => topologyEdgeRank(a.kind) - topologyEdgeRank(b.kind) || a.source.localeCompare(b.source));
    return {
      nodes: nodeList,
      edges: edgeList,
      socketMap: buildSocketMap(report, options),
      summary: {
        gateways: nodeList.filter((node) => node.role === "gateway").length,
        logicalEcus: nodeList.filter((node) => node.role === "ecu").length,
        testers: nodeList.filter((node) => node.role === "tester").length,
        endpoints: nodeList.filter((node) => node.role === "endpoint" || node.role === "dhcp").length,
        inferredLinks: edgeList.filter((edge) => edge.inferred || edge.kind === "inferred").length,
        ambiguousLinks: nodeList.filter((node) => node.ambiguous).length + edgeList.filter((edge) => edge.ambiguous).length
      }
    };
  }

  function buildSocketMap(report, options = {}) {
    const ecuLabel = options.ecuLabel || ((address) => address);
    const isAutoIpAddress = global.HarnessIdentityAnalysis?.isAutoIpAddress || ((ipAddress) => /^169\.254\./.test(String(ipAddress || "")));
    const autoIpDhcpTransitions = global.HarnessIdentityAnalysis?.autoIpDhcpTransitions || (() => []);
    const transitionByLogical = new Map(autoIpDhcpTransitions(report).map((transition) => [transition.logicalAddress, transition]));
    const sockets = new Map();
    const directByIp = new Map();
    const addList = (target, values) => {
      for (const value of values || []) addUnique(target, value);
    };
    const transitionFor = (logicalAddress, ipAddress) => {
      const transition = transitionByLogical.get(logicalAddress);
      if (!transition || !ipAddress) return null;
      return [...transition.autoIps, ...transition.dhcpIps].includes(ipAddress) ? transition : null;
    };
    const primarySocketIp = (ipAddress, patch = {}) => {
      const logicalAddress = patch.directLogicalAddress || patch.logicalAddress;
      const transition = transitionFor(logicalAddress, ipAddress);
      return transition?.dhcpIps?.[0] || ipAddress || "";
    };
    const ensureSocket = (ipAddress, patch = {}) => {
      const primaryIp = primarySocketIp(ipAddress, patch);
      const transition = transitionFor(patch.directLogicalAddress || patch.logicalAddress, ipAddress);
      const key = primaryIp || patch.srcMac || "unknown";
      const id = `socket:${key}`;
      if (!sockets.has(id)) {
        sockets.set(id, {
          id,
          ip: primaryIp || "",
          label: primaryIp || "Unknown socket",
          directLogicalAddress: "",
          directName: "",
          observedIps: [],
          autoIpAddresses: [],
          dhcpIpAddresses: [],
          macs: [],
          eids: [],
          gids: [],
          vins: [],
          packets: [],
          timestamps: [],
          routingActivations: [],
          announcements: [],
          routed: [],
          rejected: [],
          evidence: []
        });
      }
      const socket = sockets.get(id);
      if (patch.label) socket.label = patch.label;
      addUnique(socket.observedIps, ipAddress);
      if (transition) {
        addList(socket.autoIpAddresses, transition.autoIps.filter((ip) => ip === ipAddress || socket.observedIps.includes(ip)));
        addList(socket.dhcpIpAddresses, transition.dhcpIps.filter((ip) => ip === primaryIp || socket.observedIps.includes(ip)));
        addUnique(socket.evidence, `AutoIP followed by DHCP assignment (${transition.autoIps.join(", ")} -> ${transition.dhcpIps.join(", ")})`);
      } else if (isAutoIpAddress(ipAddress)) {
        addUnique(socket.autoIpAddresses, ipAddress);
      } else if (ipAddress) {
        addUnique(socket.dhcpIpAddresses, ipAddress);
      }
      if (patch.directLogicalAddress) {
        socket.directLogicalAddress = patch.directLogicalAddress;
        socket.directName = patch.directName || ecuLabel(patch.directLogicalAddress);
        directByIp.set(ipAddress, patch.directLogicalAddress);
        if (primaryIp) directByIp.set(primaryIp, patch.directLogicalAddress);
        for (const ip of transition?.autoIps || []) directByIp.set(ip, patch.directLogicalAddress);
        for (const ip of transition?.dhcpIps || []) directByIp.set(ip, patch.directLogicalAddress);
      }
      for (const keyName of ["macs", "eids", "gids", "vins", "packets", "timestamps", "evidence"]) {
        addList(socket[keyName], Array.isArray(patch[keyName]) ? patch[keyName] : patch[keyName] !== undefined && patch[keyName] !== null && patch[keyName] !== "" ? [patch[keyName]] : []);
      }
      if (patch.announcement) socket.announcements.push(patch.announcement);
      if (patch.routingActivation) socket.routingActivations.push(patch.routingActivation);
      return socket;
    };
    const ensureMapping = (socket, logicalAddress, patch = {}) => {
      if (!logicalAddress) return null;
      const existing = socket.routed.find((item) => item.logicalAddress === logicalAddress);
      const mapping = existing || {
        id: `${socket.id}|route:${logicalAddress}`,
        socketId: socket.id,
        logicalAddress,
        name: ecuLabel(logicalAddress),
        requests: 0,
        packets: [],
        timestamps: [],
        testers: [],
        services: [],
        evidence: []
      };
      mapping.requests += patch.request ? 1 : 0;
      addList(mapping.packets, patch.packet !== undefined && patch.packet !== null ? [patch.packet] : patch.packets);
      addList(mapping.timestamps, patch.timestamp !== undefined && patch.timestamp !== null ? [patch.timestamp] : patch.timestamps);
      addList(mapping.testers, patch.testerAddress ? [patch.testerAddress] : patch.testers);
      addList(mapping.services, patch.service ? [patch.service] : patch.services);
      addList(mapping.evidence, patch.evidence ? [patch.evidence] : patch.evidenceList);
      if (!existing) socket.routed.push(mapping);
      return mapping;
    };
    const ensureRejected = (socket, logicalAddress, patch = {}) => {
      if (!logicalAddress) return null;
      socket.routed = socket.routed.filter((item) => item.logicalAddress !== logicalAddress);
      const existing = socket.rejected.find((item) => item.logicalAddress === logicalAddress);
      const rejected = existing || {
        id: `${socket.id}|rejected:${logicalAddress}`,
        socketId: socket.id,
        logicalAddress,
        name: ecuLabel(logicalAddress),
        packets: [],
        timestamps: [],
        previousMessages: [],
        evidence: []
      };
      addList(rejected.packets, patch.packet !== undefined && patch.packet !== null ? [patch.packet] : patch.packets);
      addList(rejected.timestamps, patch.timestamp !== undefined && patch.timestamp !== null ? [patch.timestamp] : patch.timestamps);
      addList(rejected.previousMessages, patch.previousMessageHex ? [patch.previousMessageHex] : patch.previousMessages);
      addList(rejected.evidence, patch.evidence ? [patch.evidence] : patch.evidenceList);
      if (!existing) socket.rejected.push(rejected);
      return rejected;
    };
    const inferRejectedTargetFromRequest = (nack) => {
      const requests = (report.diagnostics?.udsEvents || []).filter((event) => {
        if (event.direction !== "request" || !event.ecuAddress || !event.dstIp) return false;
        if (nack.srcIp && event.dstIp !== nack.srcIp) return false;
        if (nack.previousSource && event.testerAddress && event.testerAddress !== nack.previousSource) return false;
        if (nack.packet && event.packet && Number(event.packet) > Number(nack.packet)) return false;
        if (!nack.packet && nack.timestamp !== undefined && event.timestamp !== undefined && Number(event.timestamp) > Number(nack.timestamp)) return false;
        return true;
      });
      requests.sort((a, b) => Number(b.packet ?? b.timestamp ?? 0) - Number(a.packet ?? a.timestamp ?? 0));
      return requests[0]?.ecuAddress || "";
    };

    for (const announcement of report.doip?.announcements || []) {
      if (!announcement.srcIp && !announcement.srcMac) continue;
      const socket = ensureSocket(announcement.srcIp, {
        label: announcement.logicalAddress ? `${ecuLabel(announcement.logicalAddress)} / ${announcement.srcIp || announcement.srcMac}` : announcement.srcIp || announcement.srcMac,
        logicalAddress: announcement.logicalAddress,
        directLogicalAddress: announcement.logicalAddress,
        directName: ecuLabel(announcement.logicalAddress),
        macs: [announcement.srcMac],
        eids: [announcement.eid],
        gids: [announcement.gid],
        vins: [announcement.vin],
        packets: [announcement.packet],
        timestamps: [announcement.timestamp],
        evidence: `Vehicle announcement ${announcement.logicalAddress || ""}`.trim(),
        announcement
      });
      if (!socket.ip && announcement.srcIp) socket.ip = primarySocketIp(announcement.srcIp, { directLogicalAddress: announcement.logicalAddress });
    }

    for (const event of report.traceEvents || []) {
      if (!["0x0005", "0x0006"].includes(event.payloadType)) continue;
      const ipAddress = event.payloadType === "0x0005" ? event.dstIp : event.srcIp;
      if (!ipAddress) continue;
      ensureSocket(ipAddress, {
        directLogicalAddress: event.payloadType === "0x0006" ? event.routingActivationEntityAddress : "",
        directName: event.payloadType === "0x0006" && event.routingActivationEntityAddress ? ecuLabel(event.routingActivationEntityAddress) : "",
        packets: [event.packet],
        timestamps: [event.timestamp],
        evidence: event.payloadName || "Routing activation",
        routingActivation: {
          packet: event.packet,
          timestamp: event.timestamp,
          sourceIp: event.srcIp,
          targetIp: event.dstIp,
          testerLogicalAddress: event.routingActivationTesterAddress || event.logicalAddress,
          entityLogicalAddress: event.routingActivationEntityAddress,
          responseCode: event.routingActivationResponseCode,
          responseCodeName: event.routingActivationResponseCodeName,
          type: event.payloadType
        }
      });
    }

    for (const event of report.diagnostics?.udsEvents || []) {
      if (event.direction !== "request" || !event.dstIp || !event.ecuAddress) continue;
      const socket = ensureSocket(event.dstIp, {
        logicalAddress: event.ecuAddress,
        packets: [event.packet],
        timestamps: [event.timestamp],
        evidence: `Diagnostic request to ${event.ecuAddress}`
      });
      const directLogical = directByIp.get(event.dstIp) || socket.directLogicalAddress;
      if (directLogical && directLogical === event.ecuAddress) continue;
      ensureMapping(socket, event.ecuAddress, {
        request: true,
        packet: event.packet,
        timestamp: event.timestamp,
        testerAddress: event.testerAddress,
        service: `${event.service || ""} ${event.serviceName || ""}`.trim(),
        evidence: `${event.source || event.testerAddress || "tester"} -> ${event.target || event.ecuAddress}`
      });
    }

    for (const item of report.diagnostics?.ackNak || []) {
      const rejectedTarget = item.previousTarget || inferRejectedTargetFromRequest(item);
      if (item.type !== "0x8003" || item.ackCode !== "0x03" || !rejectedTarget) continue;
      const socket = ensureSocket(item.srcIp, {
        macs: [item.srcMac],
        packets: [item.packet],
        timestamps: [item.timestamp],
        evidence: "Diagnostic NACK 0x03 unknown target"
      });
      ensureRejected(socket, rejectedTarget, {
        packet: item.packet,
        timestamp: item.timestamp,
        previousMessageHex: item.previousMessageHex,
        evidence: `Rejected by ${item.srcIp || "socket"} (${item.ackCodeName || item.ackCode})`
      });
    }

    const socketList = Array.from(sockets.values()).map((socket) => ({
      ...socket,
      routed: socket.routed.sort((a, b) => a.logicalAddress.localeCompare(b.logicalAddress)),
      rejected: socket.rejected.sort((a, b) => a.logicalAddress.localeCompare(b.logicalAddress))
    })).sort((a, b) => (b.directLogicalAddress ? 1 : 0) - (a.directLogicalAddress ? 1 : 0) || a.label.localeCompare(b.label));
    return {
      sockets: socketList,
      summary: {
        sockets: socketList.length,
        directLogicalAddresses: socketList.filter((socket) => socket.directLogicalAddress).length,
        routedLogicalAddresses: socketList.reduce((sum, socket) => sum + socket.routed.length, 0),
        rejectedTargets: socketList.reduce((sum, socket) => sum + socket.rejected.length, 0)
      }
    };
  }

  function topologyRoleRank(role) {
    return { tester: 1, dhcp: 2, endpoint: 3, gateway: 4, ecu: 5 }[role] || 9;
  }

  function topologyEdgeRank(kind) {
    return { routing: 1, announcement: 2, diagnostic: 3, inferred: 4, ownership: 5 }[kind] || 9;
  }

  global.HarnessTopologyAnalysis = Object.freeze({
    buildTopologyAnalysis,
    buildSocketMap,
    topologyRoleRank,
    topologyEdgeRank
  });
})(window);
