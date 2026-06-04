/**
 * Network identity analysis for DHCP, ARP, DoIP, and UDS evidence.
 */
(function registerIdentityAnalysis(global) {
  "use strict";

  function addUnique(list, value) {
    if (value && !list.includes(value)) list.push(value);
  }

  function buildIdentityAnalysis(report) {
    const findings = [];
    const groups = new Map();
    const addFinding = (finding) => {
      findings.push(finding);
      const groupKey = `${finding.entityType}|${finding.entityId}`;
      if (!groups.has(groupKey)) groups.set(groupKey, { entityType: finding.entityType, entityId: finding.entityId, role: finding.role, findings: [] });
      const group = groups.get(groupKey);
      addUnique(group.roleList || (group.roleList = []), finding.role);
      group.role = group.roleList.filter(Boolean).join(", ");
      group.findings.push(finding);
    };
    const udsEvents = report.diagnostics?.udsEvents || [];
    const testerAddresses = new Set(udsEvents.map((event) => event.testerAddress).filter(Boolean));
    const ecuAddresses = new Set(Object.keys(report.diagnostics?.ecus || {}).filter((address) => !testerAddresses.has(address)));
    const logicalRoles = new Map();
    for (const address of testerAddresses) logicalRoles.set(address, "Diagnostic tester");
    for (const address of ecuAddresses) logicalRoles.set(address, "ECU");
    const serverIps = new Set(Object.keys(report.dhcp?.servers || {}));
    const clientMacs = new Set(Object.keys(report.dhcp?.clients || {}));
    const testerIps = new Set();
    const ecuIps = new Set();
    for (const event of udsEvents) {
      if (event.direction === "request") {
        if (event.srcIp) testerIps.add(event.srcIp);
        if (event.dstIp) ecuIps.add(event.dstIp);
      } else {
        if (event.dstIp) testerIps.add(event.dstIp);
        if (event.srcIp) ecuIps.add(event.srcIp);
      }
    }
    const hostMap = Object.values(report.hosts || {}).map((host) => ({
      mac: host.mac,
      ips: (host.ips || []).filter((ipAddress) => ipAddress !== "0.0.0.0"),
      packets: host.packets || 0,
      bytes: host.bytes || 0,
      dhcp: report.dhcp?.clients?.[host.mac] || null,
      logicalAddresses: [],
      roles: []
    }));
    const hostByMac = Object.fromEntries(hostMap.map((host) => [host.mac, host]));
    for (const host of hostMap) {
      if (clientMacs.has(host.mac)) addUnique(host.roles, "DHCP client");
      if (host.ips.some((ipAddress) => serverIps.has(ipAddress))) addUnique(host.roles, "DHCP server");
      if (host.ips.some((ipAddress) => testerIps.has(ipAddress))) addUnique(host.roles, "Diagnostic tester");
      if (host.ips.some((ipAddress) => ecuIps.has(ipAddress))) addUnique(host.roles, "ECU");
    }
    for (const announcement of report.doip?.announcements || []) {
      if (announcement.srcMac && hostByMac[announcement.srcMac]) {
        addUnique(hostByMac[announcement.srcMac].logicalAddresses, announcement.logicalAddress);
        addUnique(hostByMac[announcement.srcMac].roles, logicalRoles.get(announcement.logicalAddress) || "ECU");
      }
    }
    const relevantRoles = new Set(["DHCP client", "DHCP server", "Diagnostic tester", "ECU"]);
    const relevantHostMap = hostMap.filter((host) => host.roles.some((role) => relevantRoles.has(role)));
    const relevantMacs = new Set(relevantHostMap.map((host) => host.mac));
    const relevantIps = new Set(relevantHostMap.flatMap((host) => host.ips));
    const macsByIp = new Map();
    for (const host of relevantHostMap) {
      for (const ipAddress of host.ips) {
        if (!macsByIp.has(ipAddress)) macsByIp.set(ipAddress, new Set());
        macsByIp.get(ipAddress).add(host.mac);
      }
    }
    const ipOwners = new Map();
    const expectedAutoIpDhcpMacs = expectedAutoIpDhcpTransitionMacs(report);
    for (const host of relevantHostMap) {
      for (const ipAddress of host.ips) {
        if (!ipOwners.has(ipAddress)) ipOwners.set(ipAddress, new Set());
        ipOwners.get(ipAddress).add(host.mac);
      }
      if (host.ips.length > 1 && !expectedAutoIpDhcpMacs.has(host.mac)) {
        addFinding({
          severity: "medium",
          entityType: "MAC",
          entityId: host.mac,
          role: host.roles.join(", "),
          source: "Host/IP observation",
          title: `MAC ${host.mac} used multiple IP addresses`,
          evidence: host.ips.join(", ")
        });
      }
    }
    for (const [ipAddress, macs] of ipOwners.entries()) {
      if (macs.size > 1) {
        addFinding({
          severity: "high",
          entityType: "IP",
          entityId: ipAddress,
          role: Array.from(relevantHostMap.find((host) => host.ips.includes(ipAddress))?.roles || [serverIps.has(ipAddress) ? "DHCP server" : "Diagnostic entity"]).join(", "),
          source: "IP ownership observation",
          title: `IP ${ipAddress} appeared behind multiple MAC addresses`,
          evidence: Array.from(macs).join(", ")
        });
      }
    }
    const arpOwners = new Map();
    for (const sample of report.arp?.samples || []) {
      if (!sample.senderIp || sample.senderIp === "0.0.0.0") continue;
      if (!relevantIps.has(sample.senderIp) && !relevantMacs.has(sample.senderMac)) continue;
      if (!arpOwners.has(sample.senderIp)) arpOwners.set(sample.senderIp, new Set());
      if (sample.senderMac) arpOwners.get(sample.senderIp).add(sample.senderMac);
    }
    for (const [ipAddress, macs] of arpOwners.entries()) {
      if (macs.size > 1) {
        addFinding({
          severity: "high",
          entityType: "IP",
          entityId: ipAddress,
          role: serverIps.has(ipAddress) ? "DHCP server" : "Diagnostic/DHCP entity",
          source: "ARP",
          title: `ARP conflict candidate for ${ipAddress}`,
          evidence: Array.from(macs).join(", ")
        });
      }
    }
    for (const [macAddress, client] of Object.entries(report.dhcp?.clients || {})) {
      const discovers = client.messages?.Discover || 0;
      const requests = client.messages?.Request || 0;
      const acks = client.messages?.Ack || 0;
      if ((discovers || requests) && !acks) {
        const host = hostByMac[macAddress];
        addFinding({
          severity: "medium",
          entityType: "MAC",
          entityId: macAddress,
          role: host?.roles?.join(", ") || "DHCP client",
          source: "DHCP",
          title: `DHCP client ${macAddress} requested addressing without an observed Ack`,
          evidence: `Discover ${discovers}, Request ${requests}, Ack ${acks}; IPs ${(client.ips || []).join(", ") || "none"}`
        });
      }
    }
    const rejectedGatewayMacs = nackRejectedGatewayMacsByLogical(report);
    const logicalMacEvidence = new Map();
    for (const [logicalAddress, record] of Object.entries(report.doip?.logicalAddresses || {})) {
      logicalMacEvidence.set(logicalAddress, { doipMacs: record.sourceMacs || [], diagnosticMacs: [], eids: record.eids || [] });
    }
    for (const [address, ecu] of Object.entries(report.diagnostics?.ecus || {})) {
      if (!logicalMacEvidence.has(address)) logicalMacEvidence.set(address, { doipMacs: [], diagnosticMacs: [], eids: [] });
      const rejectedMacs = rejectedGatewayMacs.get(address) || new Set();
      for (const ipAddress of ecu.ips || []) {
        for (const macAddress of macsByIp.get(ipAddress) || []) {
          if (rejectedMacs.has(macAddress)) continue;
          addUnique(logicalMacEvidence.get(address).diagnosticMacs, macAddress);
        }
      }
    }
    for (const [logicalAddress, evidence] of logicalMacEvidence.entries()) {
      const allMacs = Array.from(new Set([...evidence.doipMacs, ...evidence.diagnosticMacs])).filter(Boolean);
      if (allMacs.length > 1) {
        const parts = [];
        if (evidence.doipMacs.length) parts.push(`DoIP source MACs: ${evidence.doipMacs.join(", ")}`);
        if (evidence.diagnosticMacs.length) parts.push(`UDS IP-resolved MACs: ${evidence.diagnosticMacs.join(", ")}`);
        if (evidence.eids.length) parts.push(`DoIP EIDs: ${evidence.eids.join(", ")}`);
        addFinding({
          severity: "high",
          entityType: "Logical",
          entityId: logicalAddress,
          role: logicalRoles.get(logicalAddress) || "ECU",
          source: "DoIP + UDS",
          title: `Logical address ${logicalAddress} resolved to multiple Ethernet MAC identities`,
          evidence: parts.join(" | ")
        });
      }
    }
    const logicalIpEvidence = new Map();
    const announcedOwnersByIp = new Map();
    for (const [logicalAddress, record] of Object.entries(report.doip?.logicalAddresses || {})) {
      logicalIpEvidence.set(logicalAddress, { doipIps: record.ips || [], diagnosticIps: [] });
      for (const ipAddress of record.ips || []) {
        if (!announcedOwnersByIp.has(ipAddress)) announcedOwnersByIp.set(ipAddress, new Set());
        announcedOwnersByIp.get(ipAddress).add(logicalAddress);
      }
    }
    for (const [address, ecu] of Object.entries(report.diagnostics?.ecus || {})) {
      if (!logicalIpEvidence.has(address)) logicalIpEvidence.set(address, { doipIps: [], diagnosticIps: [] });
      logicalIpEvidence.get(address).diagnosticIps = (ecu.ips || []).filter((ipAddress) => {
        const announcedOwners = announcedOwnersByIp.get(ipAddress);
        return !announcedOwners || announcedOwners.has(address);
      });
    }
    for (const [logicalAddress, evidence] of logicalIpEvidence.entries()) {
      const allIps = Array.from(new Set([...evidence.doipIps, ...evidence.diagnosticIps])).filter(Boolean);
      if (allIps.length > 1 && !isBenignAutoIpDhcpLogicalAddress(report, logicalAddress, allIps)) {
        const parts = [];
        if (evidence.doipIps.length) parts.push(`DoIP announcements: ${evidence.doipIps.join(", ")}`);
        if (evidence.diagnosticIps.length) parts.push(`UDS diagnostics: ${evidence.diagnosticIps.join(", ")}`);
        addFinding({
          severity: "medium",
          entityType: "Logical",
          entityId: logicalAddress,
          role: logicalRoles.get(logicalAddress) || "ECU",
          source: "DoIP + UDS",
          title: `Logical address ${logicalAddress} appeared on multiple IP addresses`,
          evidence: parts.join(" | ")
        });
      }
    }
    const severityRank = { high: 0, medium: 1, info: 2 };
    findings.sort((a, b) => severityRank[a.severity] - severityRank[b.severity] || a.title.localeCompare(b.title));
    for (const group of groups.values()) {
      group.findings.sort((a, b) => severityRank[a.severity] - severityRank[b.severity] || a.title.localeCompare(b.title));
    }
    return {
      findings,
      groups: Array.from(groups.values()).sort((a, b) => severityRank[a.findings[0]?.severity || "info"] - severityRank[b.findings[0]?.severity || "info"] || a.entityId.localeCompare(b.entityId)),
      hostMap: relevantHostMap.sort((a, b) => b.roles.length - a.roles.length || b.ips.length - a.ips.length || b.packets - a.packets),
      metrics: {
        hosts: relevantHostMap.length,
        ipAddresses: ipOwners.size,
        high: findings.filter((item) => item.severity === "high").length,
        medium: findings.filter((item) => item.severity === "medium").length,
        dhcpClients: Object.keys(report.dhcp?.clients || {}).length,
        logicalAddresses: Object.keys(report.doip?.logicalAddresses || {}).length
      }
    };
  }

  function isAutoIpAddress(ipAddress) {
    return /^169\.254\./.test(String(ipAddress || ""));
  }

  function isRoutableAddress(ipAddress) {
    return Boolean(ipAddress) && ipAddress !== "0.0.0.0" && !isAutoIpAddress(ipAddress);
  }

  function nackRejectedGatewayMacsByLogical(report) {
    const exclusions = new Map();
    for (const item of report.diagnostics?.ackNak || []) {
      const rejectedTarget = rejectedDiagnosticTarget(report, item);
      if (item.type !== "0x8003" || item.ackCode !== "0x03" || !rejectedTarget || !item.srcMac) continue;
      if (hasAcceptedDiagnosticEvidence(report, rejectedTarget, item.srcIp, item.srcMac)) continue;
      if (!exclusions.has(rejectedTarget)) exclusions.set(rejectedTarget, new Set());
      exclusions.get(rejectedTarget).add(item.srcMac);
    }
    return exclusions;
  }

  function rejectedDiagnosticTarget(report, nack) {
    if (nack?.previousTarget) return nack.previousTarget;
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
  }

  function hasAcceptedDiagnosticEvidence(report, logicalAddress, gatewayIp, gatewayMac) {
    return (report.diagnostics?.udsEvents || []).some((event) =>
      event.ecuAddress === logicalAddress &&
      event.direction === "response" &&
      (!gatewayIp || event.srcIp === gatewayIp)
    ) || (report.diagnostics?.ackNak || []).some((item) =>
      item.previousTarget === logicalAddress &&
      item.type === "0x8002" &&
      (!gatewayIp || item.srcIp === gatewayIp) &&
      (!gatewayMac || item.srcMac === gatewayMac)
    );
  }

  function isBenignAutoIpDhcpLogicalAddress(report, logicalAddress, ipAddresses) {
    const transition = autoIpDhcpTransitions(report).find((item) => item.logicalAddress === logicalAddress);
    if (!transition) return false;
    const expectedIps = new Set([...transition.autoIps, ...transition.dhcpIps]);
    return (ipAddresses || []).every((ipAddress) => expectedIps.has(ipAddress));
  }

  function dhcpAckAssignments(report) {
    return (report.dhcp?.samples || [])
      .filter((sample) => sample.messageType === "Ack" && sample.clientMac && isRoutableAddress(sample.yourIp))
      .map((sample) => ({
        clientMac: sample.clientMac,
        ip: sample.yourIp,
        packet: sample.packet,
        timestamp: sample.timestamp ?? null,
        serverId: sample.serverId || ""
      }));
  }

  function expectedAutoIpDhcpTransitionMacs(report) {
    const macs = new Set();
    for (const transition of autoIpDhcpTransitions(report)) {
      for (const macAddress of transition.macs) macs.add(macAddress);
    }
    return macs;
  }

  function autoIpDhcpTransitions(report) {
    const assignments = dhcpAckAssignments(report);
    if (!assignments.length) return [];
    const logicalAddresses = new Set([
      ...Object.keys(report.doip?.logicalAddresses || {}),
      ...Object.keys(report.diagnostics?.ecus || {})
    ]);
    const transitions = [];
    for (const logicalAddress of logicalAddresses) {
      const macs = logicalMacEvidence(report, logicalAddress);
      if (!macs.length) continue;
      const ips = logicalIpEvidence(report, logicalAddress);
      const autoIps = ips.filter(isAutoIpAddress);
      if (!autoIps.length) continue;
      const matchingAssignments = assignments.filter((assignment) => macs.includes(assignment.clientMac));
      if (!matchingAssignments.length) continue;
      const dhcpIps = Array.from(new Set(matchingAssignments.map((assignment) => assignment.ip)));
      const autoIpEvents = logicalAutoIpEvents(report, logicalAddress, autoIps);
      const postAssignmentAutoIpEvents = autoIpEvents.filter((event) =>
        matchingAssignments.some((assignment) => eventAfterAssignment(event, assignment))
      );
      transitions.push({
        logicalAddress,
        macs,
        autoIps,
        dhcpIps,
        assignments: matchingAssignments,
        autoIpEvents,
        postAssignmentAutoIpEvents
      });
    }
    return transitions;
  }

  function logicalMacEvidence(report, logicalAddress) {
    const macs = [];
    const record = report.doip?.logicalAddresses?.[logicalAddress] || {};
    for (const macAddress of record.sourceMacs || []) addUnique(macs, macAddress);
    for (const announcement of report.doip?.announcements || []) {
      if (announcement.logicalAddress === logicalAddress) addUnique(macs, announcement.srcMac);
    }
    return macs;
  }

  function logicalIpEvidence(report, logicalAddress) {
    const ips = [];
    const record = report.doip?.logicalAddresses?.[logicalAddress] || {};
    for (const ipAddress of record.ips || []) addUnique(ips, ipAddress);
    for (const announcement of report.doip?.announcements || []) {
      if (announcement.logicalAddress === logicalAddress) addUnique(ips, announcement.srcIp);
    }
    const ecu = report.diagnostics?.ecus?.[logicalAddress] || {};
    for (const ipAddress of ecu.ips || []) addUnique(ips, ipAddress);
    for (const event of report.diagnostics?.udsEvents || []) {
      if (event.ecuAddress !== logicalAddress) continue;
      if (event.direction === "request") addUnique(ips, event.dstIp);
      if (event.direction === "response") addUnique(ips, event.srcIp);
    }
    return ips.filter((ipAddress) => ipAddress && ipAddress !== "0.0.0.0");
  }

  function logicalAutoIpEvents(report, logicalAddress, autoIps) {
    const autoIpSet = new Set(autoIps);
    const events = [];
    for (const announcement of report.doip?.announcements || []) {
      if (announcement.logicalAddress !== logicalAddress || !autoIpSet.has(announcement.srcIp)) continue;
      events.push({ type: "DoIP announcement", ip: announcement.srcIp, packet: announcement.packet, timestamp: announcement.timestamp ?? null });
    }
    for (const event of report.diagnostics?.udsEvents || []) {
      if (event.ecuAddress !== logicalAddress) continue;
      const ipAddress = event.direction === "response" ? event.srcIp : event.dstIp;
      if (!autoIpSet.has(ipAddress)) continue;
      events.push({ type: "UDS diagnostics", direction: event.direction || "", ip: ipAddress, packet: event.packet, timestamp: event.timestamp ?? null });
    }
    return events;
  }

  function eventAfterAssignment(event, assignment) {
    if (event.timestamp !== null && event.timestamp !== undefined && assignment.timestamp !== null && assignment.timestamp !== undefined) {
      return Number(event.timestamp) > Number(assignment.timestamp);
    }
    if (event.packet !== undefined && event.packet !== null && assignment.packet !== undefined && assignment.packet !== null) {
      return Number(event.packet) > Number(assignment.packet);
    }
    return false;
  }

  global.HarnessIdentityAnalysis = Object.freeze({
    buildIdentityAnalysis,
    nackRejectedGatewayMacsByLogical,
    rejectedDiagnosticTarget,
    hasAcceptedDiagnosticEvidence,
    isAutoIpAddress,
    isRoutableAddress,
    isBenignAutoIpDhcpLogicalAddress,
    dhcpAckAssignments,
    expectedAutoIpDhcpTransitionMacs,
    autoIpDhcpTransitions,
    logicalMacEvidence,
    logicalIpEvidence,
    logicalAutoIpEvents,
    eventAfterAssignment
  });
})(window);
