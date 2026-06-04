/**
 * Node-centric DoIP discovery lifecycle analysis.
 */
(function registerDoipLifecycleAnalysis(global) {
  "use strict";

  function addUnique(list, value) {
    if (value !== undefined && value !== null && value !== "" && !list.includes(value)) list.push(value);
  }

  function packetStage(key, label, status = "missing") {
    return { key, label, status, count: 0, firstPacket: "", firstTimestamp: null, packets: [], evidence: [], details: {} };
  }

  function addStageEvidence(stage, item, evidence) {
    const packet = item?.packet;
    const alreadyCountedPacket = packet && stage.packets.includes(packet);
    if (!alreadyCountedPacket) stage.count += 1;
    if (packet) addUnique(stage.packets, packet);
    if (evidence) addUnique(stage.evidence, evidence);
    if (stage.firstTimestamp === null || Number(item?.timestamp ?? Infinity) < Number(stage.firstTimestamp)) {
      stage.firstTimestamp = item?.timestamp ?? null;
      stage.firstPacket = item?.packet || stage.firstPacket;
    }
  }

  function observedStage(stage) {
    if (stage.count > 0 && stage.status !== "failed" && stage.status !== "out-of-order") stage.status = "observed";
    return stage;
  }

  function ensureNode(nodes, id, patch = {}) {
    if (!nodes.has(id)) {
      nodes.set(id, {
        id,
        role: patch.role || "unknown",
        logicalAddress: "",
        name: "",
        parentSocketName: "",
        parentSocketLogicalAddress: "",
        parentSocketIp: "",
        ips: [],
        macs: [],
        issues: [],
        evidence: [],
        stages: {
          arp: packetStage("arp", "ARP"),
          tcpSocket: packetStage("tcpSocket", "TCP socket"),
          vehicleAnnouncement: packetStage("vehicleAnnouncement", "Vehicle announcement"),
          vehicleIdResponse: packetStage("vehicleIdResponse", "Vehicle ID response", "not-applicable"),
          routingActivation: packetStage("routingActivation", "Routing activation"),
          diagnostics: packetStage("diagnostics", "Diagnostics")
        }
      });
    }
    const node = nodes.get(id);
    if (patch.role && node.role === "unknown") node.role = patch.role;
    if (patch.logicalAddress) node.logicalAddress = patch.logicalAddress;
    if (patch.name) node.name = patch.name;
    if (patch.parentSocketName) node.parentSocketName = patch.parentSocketName;
    if (patch.parentSocketLogicalAddress) node.parentSocketLogicalAddress = patch.parentSocketLogicalAddress;
    if (patch.parentSocketIp) node.parentSocketIp = patch.parentSocketIp;
    for (const ip of patch.ips || []) addUnique(node.ips, ip);
    for (const mac of patch.macs || []) addUnique(node.macs, mac);
    for (const evidence of patch.evidence || []) addUnique(node.evidence, evidence);
    return node;
  }

  function socketLifecycleId(socket = {}) {
    return socket.directLogicalAddress ? `logical:${socket.directLogicalAddress}` : socket.id;
  }

  function orderedStageTimestamp(stage) {
    return stage.firstTimestamp === null || stage.firstTimestamp === undefined ? Infinity : Number(stage.firstTimestamp);
  }

  function addDetail(list, value, keyFn = (item) => JSON.stringify(item)) {
    if (!value) return;
    const key = keyFn(value);
    if (!list.some((item) => keyFn(item) === key)) list.push(value);
  }

  function flowMatchesNode(flow, node) {
    const text = `${flow.endpointA || ""} ${flow.endpointB || ""}`;
    return (node.ips || []).some((ip) => text.includes(`${ip}:13400`));
  }

  function endpointForNode(flow, node) {
    const endpoints = [flow.endpointA, flow.endpointB].filter(Boolean);
    return endpoints.find((endpoint) => (node.ips || []).some((ip) => endpoint.startsWith(`${ip}:`))) || "";
  }

  function flowEvents(report, flowKey) {
    return (report.tcpAnalysis?.events || []).filter((event) => event.flowKey === flowKey);
  }

  function isVehicleIdRequest(sample) {
    return ["0x0001", "0x0002", "0x0003"].includes(sample?.payloadType);
  }

  function isVehicleIdResponse(sample) {
    return sample?.payloadType === "0x0004";
  }

  function requestTargetsNode(request, node) {
    if (!request) return false;
    if ((node.ips || []).includes(request.dstIp)) return true;
    return !request.dstIp || request.dstIp === "255.255.255.255" || request.dstIp.endsWith(".255");
  }

  function responseMatchesNode(response, node) {
    if (!response) return false;
    if (response.logicalAddress && response.logicalAddress === node.logicalAddress) return true;
    if ((node.ips || []).includes(response.srcIp)) return true;
    if ((node.macs || []).includes(response.srcMac)) return true;
    return false;
  }

  function populateVehicleIdDetails(report, nodes) {
    const samples = report.doip?.samples || [];
    const requests = samples.filter(isVehicleIdRequest).sort((a, b) => Number(a.timestamp || 0) - Number(b.timestamp || 0) || Number(a.packet || 0) - Number(b.packet || 0));
    const responses = samples.filter(isVehicleIdResponse);
    for (const node of nodes.values()) {
      const nodeResponses = responses.filter((sample) => responseMatchesNode(sample, node));
      const nodeRequests = requests.filter((sample) => requestTargetsNode(sample, node));
      const pairs = [];
      for (const response of nodeResponses) {
        const prior = nodeRequests
          .filter((request) => Number(request.timestamp ?? -Infinity) <= Number(response.timestamp ?? Infinity))
          .sort((a, b) => Number(b.timestamp || 0) - Number(a.timestamp || 0) || Number(b.packet || 0) - Number(a.packet || 0))[0];
        pairs.push({
          requestPacket: prior?.packet || "",
          responsePacket: response.packet || "",
          requestType: prior?.payloadName || "No matching request",
          responseIp: response.srcIp || "",
          logicalAddress: response.logicalAddress || node.logicalAddress || ""
        });
      }
      node.stages.vehicleIdResponse.details ||= {};
      node.stages.vehicleIdResponse.details.requests = nodeRequests.map((request) => ({
        packet: request.packet,
        timestamp: request.timestamp,
        type: request.payloadName,
        srcIp: request.srcIp,
        dstIp: request.dstIp
      }));
      node.stages.vehicleIdResponse.details.responses = nodeResponses.map((response) => ({
        packet: response.packet,
        timestamp: response.timestamp,
        logicalAddress: response.logicalAddress,
        srcIp: response.srcIp,
        vin: response.vin,
        eid: response.eid
      }));
      node.stages.vehicleIdResponse.details.pairs = pairs;
    }
  }

  function buildDoipLifecycle(report, options = {}) {
    const ecuLabel = options.ecuLabel || ((address) => address);
    const socketMap = report.topology?.socketMap || { sockets: [] };
    const nodes = new Map();
    const socketByLogical = new Map();

    for (const socket of socketMap.sockets || []) {
      if (socket.directLogicalAddress) socketByLogical.set(socket.directLogicalAddress, socket);
      const node = ensureNode(nodes, socketLifecycleId(socket), {
        role: socket.routed?.length ? "gateway-socket" : "ethernet-node",
        logicalAddress: socket.directLogicalAddress,
        name: socket.directName || (socket.directLogicalAddress ? ecuLabel(socket.directLogicalAddress) : socket.ip || socket.label),
        ips: socket.observedIps?.length ? socket.observedIps : [socket.ip],
        macs: socket.macs,
        evidence: socket.evidence
      });
      for (const announcement of socket.announcements || []) {
        addStageEvidence(node.stages.vehicleAnnouncement, announcement, `announcement ${announcement.logicalAddress || ""}`.trim());
      }
      for (const activation of socket.routingActivations || []) {
        const result = activation.responseCodeName || activation.responseCode || "";
        addStageEvidence(
          node.stages.routingActivation,
          activation,
          activation.type === "0x0006"
            ? `routing activation response ${activation.entityLogicalAddress || ""} ${result}`.trim()
            : "routing activation request"
        );
        node.stages.routingActivation.details.activations ||= [];
        addDetail(node.stages.routingActivation.details.activations, {
          packet: activation.packet,
          timestamp: activation.timestamp,
          type: activation.type,
          sourceIp: activation.sourceIp,
          targetIp: activation.targetIp,
          testerLogicalAddress: activation.testerLogicalAddress,
          entityLogicalAddress: activation.entityLogicalAddress,
          responseCode: activation.responseCode,
          responseCodeName: activation.responseCodeName
        }, (item) => `${item.packet}|${item.type}|${item.testerLogicalAddress}|${item.entityLogicalAddress}`);
      }
      observedStage(node.stages.vehicleAnnouncement);
      observedStage(node.stages.routingActivation);
    }

    for (const sample of report.doip?.samples || []) {
      if (sample.payloadType !== "0x0004") continue;
      const socket = (socketMap.sockets || []).find((item) =>
        item.directLogicalAddress === sample.logicalAddress ||
        item.ip === sample.srcIp ||
        (item.observedIps || []).includes(sample.srcIp) ||
        (item.macs || []).includes(sample.srcMac)
      );
      const node = ensureNode(nodes, socket ? socketLifecycleId(socket) : `doip:${sample.logicalAddress || sample.srcIp || sample.packet}`, {
        role: socket ? socket.routed?.length ? "gateway-socket" : "ethernet-node" : "ethernet-node",
        logicalAddress: sample.logicalAddress,
        name: sample.logicalAddress ? ecuLabel(sample.logicalAddress) : sample.srcIp,
        ips: [sample.srcIp],
        macs: [sample.srcMac]
      });
      addStageEvidence(node.stages.vehicleIdResponse, sample, sample.payloadName || "vehicle identification response");
      observedStage(node.stages.vehicleIdResponse);
    }

    for (const flow of report.tcpAnalysis?.flows || []) {
      for (const node of nodes.values()) {
        if (!flowMatchesNode(flow, node)) continue;
        addStageEvidence(node.stages.tcpSocket, { packet: "", timestamp: flow.firstTimestamp }, flow.key);
        const events = flowEvents(report, flow.key);
        const handshakes = events.filter((event) => event.type === "Handshake");
        const finishes = events.filter((event) => event.type === "FIN");
        const resets = events.filter((event) => event.type === "RST");
        node.stages.tcpSocket.details.flows ||= [];
        addDetail(node.stages.tcpSocket.details.flows, {
          key: flow.key,
          socketEndpoint: endpointForNode(flow, node),
          firstTimestamp: flow.firstTimestamp,
          lastTimestamp: flow.lastTimestamp,
          packets: flow.packets,
          payloadBytes: flow.payloadBytes,
          handshakeDuration: flow.handshakeDuration,
          opened: handshakes.length || (flow.handshakeDuration !== null && flow.handshakeDuration !== undefined ? 1 : 0),
          closed: finishes.length,
          resets: resets.length,
          openPackets: handshakes.map((event) => event.packet),
          closePackets: finishes.map((event) => event.packet),
          resetPackets: resets.map((event) => event.packet)
        }, (item) => item.key);
      }
    }

    for (const arp of report.arp?.samples || []) {
      for (const node of nodes.values()) {
        if (!node.ips.includes(arp.senderIp) && !node.ips.includes(arp.targetIp) && !node.macs.includes(arp.senderMac) && !node.macs.includes(arp.targetMac)) continue;
        addStageEvidence(node.stages.arp, arp, `${arp.operation} ${arp.senderIp} -> ${arp.targetIp}`);
      }
    }

    for (const socket of socketMap.sockets || []) {
      const node = nodes.get(socketLifecycleId(socket));
      if (!node) continue;
      for (const event of report.diagnostics?.udsEvents || []) {
        if (event.direction !== "request") continue;
        const throughSocket = event.dstIp && (event.dstIp === socket.ip || (socket.observedIps || []).includes(event.dstIp));
        const direct = socket.directLogicalAddress && event.ecuAddress === socket.directLogicalAddress;
        const routed = (socket.routed || []).some((item) => item.logicalAddress === event.ecuAddress);
        if (!throughSocket && !direct && !routed) continue;
        addStageEvidence(node.stages.diagnostics, event, `${event.testerAddress || "tester"} -> ${event.ecuAddress}`);
        node.stages.diagnostics.details.events ||= [];
        addDetail(node.stages.diagnostics.details.events, {
          packet: event.packet,
          timestamp: event.timestamp,
          direction: event.direction,
          testerAddress: event.testerAddress,
          ecuAddress: event.ecuAddress,
          service: event.service,
          serviceName: event.serviceName,
          srcIp: event.srcIp,
          dstIp: event.dstIp,
          responseKind: event.responseKind,
          nrc: event.nrc,
          nrcName: event.nrcName
        }, (item) => `${item.packet}|${item.direction}|${item.ecuAddress}|${item.service}|${item.nrc}`);
      }
      observedStage(node.stages.diagnostics);
      for (const route of socket.routed || []) {
        if (socketByLogical.has(route.logicalAddress)) continue;
        const routeNode = ensureNode(nodes, route.id, {
          role: "behind-socket",
          logicalAddress: route.logicalAddress,
          name: route.name || ecuLabel(route.logicalAddress),
          parentSocketName: socket.directName,
          parentSocketLogicalAddress: socket.directLogicalAddress,
          parentSocketIp: socket.ip,
          ips: [socket.ip],
          evidence: [`addressed through ${socket.ip || socket.label}`]
        });
        routeNode.stages.arp.status = "not-applicable";
        routeNode.stages.tcpSocket.status = "not-applicable";
        routeNode.stages.vehicleAnnouncement.status = "not-applicable";
        routeNode.stages.vehicleIdResponse.status = "not-applicable";
        routeNode.stages.routingActivation.status = "not-applicable";
        routeNode.stages.diagnostics.count = route.requests || 0;
        routeNode.stages.diagnostics.packets = [...(route.packets || [])];
        routeNode.stages.diagnostics.firstPacket = route.packets?.[0] || "";
        routeNode.stages.diagnostics.firstTimestamp = route.timestamps?.[0] ?? null;
        routeNode.stages.diagnostics.evidence = [...(route.evidence || [])];
        routeNode.stages.diagnostics.details.routedTarget = {
          socketIp: socket.ip,
          socketName: socket.directName,
          socketLogicalAddress: socket.directLogicalAddress,
          logicalAddress: route.logicalAddress,
          requests: route.requests || 0,
          testers: route.testers || [],
          services: route.services || []
        };
        observedStage(routeNode.stages.diagnostics);
      }
      for (const rejected of socket.rejected || []) {
        const rejectedNode = ensureNode(nodes, rejected.id, {
          role: "behind-socket",
          logicalAddress: rejected.logicalAddress,
          name: rejected.name || ecuLabel(rejected.logicalAddress),
          parentSocketName: socket.directName,
          parentSocketLogicalAddress: socket.directLogicalAddress,
          parentSocketIp: socket.ip,
          ips: [socket.ip],
          evidence: rejected.evidence
        });
        for (const key of ["arp", "tcpSocket", "vehicleAnnouncement", "vehicleIdResponse", "routingActivation"]) rejectedNode.stages[key].status = "not-applicable";
        rejectedNode.stages.diagnostics.status = "failed";
        rejectedNode.stages.diagnostics.count = rejected.packets?.length || 1;
        rejectedNode.stages.diagnostics.packets = [...(rejected.packets || [])];
        rejectedNode.stages.diagnostics.firstPacket = rejected.packets?.[0] || "";
        rejectedNode.stages.diagnostics.firstTimestamp = rejected.timestamps?.[0] ?? null;
        rejectedNode.stages.diagnostics.details.rejectedTarget = {
          socketIp: socket.ip,
          socketName: socket.directName,
          socketLogicalAddress: socket.directLogicalAddress,
          logicalAddress: rejected.logicalAddress,
          packets: rejected.packets || [],
          previousMessages: rejected.previousMessages || []
        };
        rejectedNode.issues.push({ severity: "warning", title: "DoIP target rejected", detail: `${rejected.logicalAddress} was rejected by diagnostic NACK 0x03.` });
      }
    }

    populateVehicleIdDetails(report, nodes);

    const arpVisible = Boolean(report.arp?.samples?.length);
    for (const node of nodes.values()) {
      for (const stage of Object.values(node.stages)) observedStage(stage);
      const directNode = node.role === "gateway-socket" || node.role === "ethernet-node";
      if (!arpVisible) node.stages.arp.status = "not-applicable";
      if (directNode && node.stages.tcpSocket.count === 0) node.stages.tcpSocket.status = "missing";
      if (directNode && node.stages.vehicleAnnouncement.count === 0 && node.stages.vehicleIdResponse.count === 0) node.stages.vehicleAnnouncement.status = "missing";
      if (node.stages.diagnostics.count > 0 && node.stages.routingActivation.count === 0 && directNode) {
        node.stages.routingActivation.status = "missing";
        node.issues.push({ severity: "warning", title: "Diagnostics without routing activation", detail: "UDS diagnostics were observed without matching routing activation evidence." });
      }
      if (node.stages.routingActivation.count > 0 && node.stages.diagnostics.firstTimestamp !== null && orderedStageTimestamp(node.stages.diagnostics) < orderedStageTimestamp(node.stages.routingActivation)) {
        node.stages.diagnostics.status = "out-of-order";
        node.issues.push({ severity: "warning", title: "Diagnostics before routing activation", detail: "Diagnostics were observed before routing activation evidence." });
      }
    }

    const nodeList = Array.from(nodes.values())
      .map((node) => ({ ...node, status: node.issues.length ? "issue" : Object.values(node.stages).some((stage) => stage.status === "failed") ? "failed" : "ok" }))
      .sort((a, b) => (b.issues.length - a.issues.length) || roleRank(a.role) - roleRank(b.role) || String(a.name || a.logicalAddress || a.id).localeCompare(String(b.name || b.logicalAddress || b.id)));

    return {
      nodes: nodeList,
      summary: {
        nodes: nodeList.length,
        issues: nodeList.filter((node) => node.issues.length).length,
        routingActive: nodeList.filter((node) => node.stages.routingActivation.status === "observed").length,
        rejected: nodeList.filter((node) => node.stages.diagnostics.status === "failed").length
      }
    };
  }

  function roleRank(role) {
    return { "gateway-socket": 1, "ethernet-node": 2, "behind-socket": 3, unknown: 9 }[role] || 9;
  }

  global.HarnessDoipLifecycleAnalysis = Object.freeze({
    buildDoipLifecycle
  });
})(window);
