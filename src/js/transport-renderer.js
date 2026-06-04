/**
 * Transport-view identity, health, filtering, and small HTML helpers.
 */
(function registerTransportRenderer(global) {
  "use strict";

  const formatters = global.HarnessFormatters || {};
  const escapeHtml = formatters.escapeHtml || ((value) => String(value ?? ""));
  const formatNumber = formatters.formatNumber || ((value) => String(value ?? ""));
  const formatBytes = formatters.formatBytes || ((value) => String(value ?? ""));
  const formatMs = formatters.formatMs || ((value) => String(value ?? ""));
  const { badge } = global.HarnessUi;

  function parseTransportEndpoint(endpoint) {
    const [ipAddress, port] = String(endpoint || "").split(":");
    return { ip: ipAddress || "", port: port || "" };
  }

  function resolveTransportEndpoint(ipAddress, port, report = {}) {
    const announced = (report.doip?.announcements || []).filter((item) => item.srcIp === ipAddress && item.logicalAddress);
    const testerAddresses = new Set();
    const carriedTargets = new Set();
    for (const event of report.diagnostics?.udsEvents || []) {
      if (event.direction === "request" && event.srcIp === ipAddress) testerAddresses.add(event.source);
      if (event.direction === "response" && event.dstIp === ipAddress) testerAddresses.add(event.target);
      if (event.dstIp === ipAddress || event.srcIp === ipAddress) {
        if (event.ecuAddress) carriedTargets.add(event.ecuAddress);
      }
    }
    const host = Object.values(report.hosts || {}).find((item) => (item.ips || []).includes(ipAddress));
    const testers = Array.from(testerAddresses).sort();
    const ethernetLogicalAddresses = Array.from(new Set(announced.map((item) => item.logicalAddress))).sort();
    const carriedLogicalAddresses = Array.from(carriedTargets).sort();
    const isDoipPort = String(port) === "13400";
    let role = "Unknown endpoint";
    let label = ipAddress ? `Endpoint ${ipAddress}` : "Unknown endpoint";
    if (testers.length && !isDoipPort) {
      role = "Tester";
      label = `Tester ${testers.join(", ")} / ${ipAddress}`;
    } else if (ethernetLogicalAddresses.length && isDoipPort) {
      role = "DoIP gateway/entity";
      label = `${ethernetLogicalAddresses.join(", ")} / ${ipAddress}`;
    } else if (isDoipPort) {
      role = "DoIP Ethernet node";
      label = `DoIP node ${ipAddress}`;
    }
    return { ip: ipAddress, port, role, label, ethernetLogicalAddresses, carriedLogicalAddresses, testerAddresses: testers, mac: host?.mac || "", raw: `${ipAddress}:${port}` };
  }

  function transportFlowIdentity(flow, report = {}, options = {}) {
    const tcpFlowKey = options.tcpFlowKey || ((srcIp, srcPort, dstIp, dstPort) => [`${srcIp}:${srcPort}`, `${dstIp}:${dstPort}`].sort().join(" <-> "));
    const aRaw = parseTransportEndpoint(flow.endpointA);
    const bRaw = parseTransportEndpoint(flow.endpointB);
    const a = resolveTransportEndpoint(aRaw.ip, aRaw.port, report);
    const b = resolveTransportEndpoint(bRaw.ip, bRaw.port, report);
    const doipNode = [a, b].find((item) => String(item.port) === "13400") || b;
    const tester = doipNode === a ? b : a;
    const carriedLogicalAddresses = carriedLogicalAddressesForFlow(flow, report, { tcpFlowKey }).filter((address) => !(doipNode.ethernetLogicalAddresses || []).includes(address));
    const nodeLabel = doipNode.ethernetLogicalAddresses?.length ? `${doipNode.ethernetLogicalAddresses.join(", ")} / ${doipNode.ip}` : doipNode.label;
    return {
      a,
      b,
      tester,
      doipNode,
      roles: `${tester.role} <-> ${doipNode.role}`,
      group: nodeLabel || doipNode.raw || "Unresolved DoIP node",
      carriedLogicalAddresses
    };
  }

  function carriedLogicalAddressesForFlow(flow, report = {}, options = {}) {
    const tcpFlowKey = options.tcpFlowKey || ((srcIp, srcPort, dstIp, dstPort) => [`${srcIp}:${srcPort}`, `${dstIp}:${dstPort}`].sort().join(" <-> "));
    const values = new Set();
    for (const event of report.diagnostics?.udsEvents || []) {
      if (tcpFlowKey(event.srcIp, event.srcPort, event.dstIp, event.dstPort) !== flow.key) continue;
      if (event.ecuAddress) values.add(event.ecuAddress);
    }
    return Array.from(values).sort();
  }

  function transportObservationSummary(flow) {
    const items = [];
    if (flow.retransmissions) items.push(badge(`${formatNumber(flow.retransmissions)} retrans`, "warn"));
    if (flow.duplicateAcks) items.push(badge(`${formatNumber(flow.duplicateAcks)} dup ACK`));
    if (flow.zeroWindows) items.push(badge(`${formatNumber(flow.zeroWindows)} zero win`, "danger"));
    if (flow.windowUpdates) items.push(badge(`${formatNumber(flow.windowUpdates)} win update`));
    return items.join(" ");
  }

  function formatWindowBytes(value) {
    return Number.isFinite(value) ? formatBytes(value) : "n/a";
  }

  function transportIssueMarkers(flow, events, gaps) {
    const markers = [];
    const flowControl = flow.flowControl?.status || { label: "OK", severity: "ok" };
    if (flowControl.label !== "OK") markers.push({ label: flowControl.label, severity: flowControl.severity, detail: flowControl.detail || "Flow-control pressure observed." });
    if (flow.retransmissions) markers.push({ label: "Retransmission", severity: "warning", detail: "TCP byte range or payload repeated before ACK." });
    if (flow.duplicateAcks) markers.push({ label: "Duplicate ACK", severity: flow.duplicateAcks > 5 ? "warning" : "info", detail: "Receiver repeated an ACK number; data may be missing or out of order." });
    if (flow.zeroWindows) markers.push({ label: "Zero window", severity: "problem", detail: "Receiver advertised no TCP buffer space." });
    if (gaps.length) markers.push({ label: "TCP gap", severity: "problem", detail: "Capture bytes or sequence continuity are missing; decoding may be incomplete." });
    if ((events || []).some((event) => event.type === "Slow ACK")) markers.push({ label: "Slow ACK", severity: "warning", detail: "Payload was acknowledged later than the configured slow-ACK threshold." });
    return markers;
  }

  function transportIssueClass(severity) {
    return severity === "problem" ? "danger" : severity === "warning" ? "warn" : severity === "info" ? "" : "ok";
  }

  function transportHealth(flow, analysis = {}) {
    const gaps = (analysis.gaps || []).filter((gap) => gap.flowKey === flow.key).length;
    const events = (analysis.events || []).filter((event) => event.flowKey === flow.key);
    const rst = events.filter((event) => event.type === "RST").length;
    const slowAck = events.filter((event) => event.type === "Slow ACK").length;
    if (gaps) return { level: "problem", label: "TCP gap", detail: `${formatNumber(gaps)} TCP gap observation${gaps === 1 ? "" : "s"}; decoding may be incomplete.` };
    if (flow.zeroWindows > 0) return { level: "problem", label: "Zero window", detail: `${formatNumber(flow.zeroWindows)} zero-window event${flow.zeroWindows === 1 ? "" : "s"}.` };
    if (flow.flowControl?.status?.severity === "problem") return { level: "problem", label: flow.flowControl.status.label, detail: flow.flowControl.status.detail };
    if (flow.flowControl?.status?.severity === "warning") return { level: "warning", label: flow.flowControl.status.label, detail: flow.flowControl.status.detail };
    if (flow.retransmissions > 0) return { level: "warning", label: "Retransmission", detail: `${formatNumber(flow.retransmissions)} retransmission observation${flow.retransmissions === 1 ? "" : "s"}.` };
    if (flow.duplicateAcks > 5) return { level: "warning", label: "Dup ACK burst", detail: `${formatNumber(flow.duplicateAcks)} duplicate ACK observations.` };
    if (Number(flow.p95AckLatency || 0) > 0.05) return { level: "warning", label: "Slow ACK", detail: `P95 ACK latency is ${formatMs(flow.p95AckLatency)}.` };
    if (rst) return { level: "info", label: "RST seen", detail: `${formatNumber(rst)} TCP reset packet${rst === 1 ? "" : "s"} observed.` };
    if (flow.duplicateAcks > 0) return { level: "info", label: "Dup ACK", detail: `${formatNumber(flow.duplicateAcks)} duplicate ACK observation${flow.duplicateAcks === 1 ? "" : "s"}.` };
    if (slowAck) return { level: "info", label: "Slow ACK", detail: `${formatNumber(slowAck)} slow ACK sample${slowAck === 1 ? "" : "s"}.` };
    return { level: "ok", label: "OK", detail: "No notable TCP timing issues observed." };
  }

  function filterTransportFlows(flows, filter, analysis = {}) {
    return flows.filter((flow) => {
      if (filter === "all") return true;
      if (filter === "ecus") return flow.identity.carriedLogicalAddresses.length > 0 || flow.identity.doipNode.ethernetLogicalAddresses?.length;
      if (filter === "testers") return flow.identity.tester?.role === "Tester";
      if (filter === "gateways") return flow.identity.doipNode.role.includes("DoIP");
      if (filter === "warnings") return flow.health.level !== "ok";
      if (filter === "retransmissions") return flow.retransmissions > 0;
      if (filter === "gaps") return (analysis.gaps || []).some((gap) => gap.flowKey === flow.key);
      return true;
    });
  }

  function endpointCell(endpoint) {
    return `<strong>${escapeHtml(endpoint.label)}</strong><br><code>${escapeHtml(endpoint.raw)}</code>${endpoint.mac ? `<br><code>${escapeHtml(endpoint.mac)}</code>` : ""}`;
  }

  function healthClass(level) {
    return level === "problem" ? "danger" : level === "warning" ? "warn" : level === "ok" ? "ok" : "";
  }

  function flowControlBadge(status = { label: "OK", severity: "ok" }) {
    return badge(status.label || "OK", healthClass(status.severity), { title: status.detail || "" });
  }

  function flowControlChartMax(values, smallWindowThreshold = 32768) {
    const clean = values.filter((value) => Number.isFinite(value) && value >= 0).sort((a, b) => a - b);
    if (!clean.length) return Math.max(1, smallWindowThreshold);
    const max = clean[clean.length - 1];
    const p95 = percentile(clean, 95) || max;
    const target = Math.max(1, smallWindowThreshold, Math.min(max, p95 * 1.25));
    return niceWindowCeil(target);
  }

  function flowControlChartRatio(value, chartMax, smallWindowThreshold = 4096) {
    const safeMax = Math.max(1, Number(chartMax) || 1);
    const clipped = Math.min(Math.max(0, Number(value) || 0), safeMax);
    const focusMax = Math.min(Math.max(1, Number(smallWindowThreshold) || 4096), safeMax);
    if (safeMax <= focusMax) return clipped / safeMax;
    const focusShare = 0.62;
    if (clipped <= focusMax) return (clipped / focusMax) * focusShare;
    return focusShare + ((clipped - focusMax) / Math.max(1, safeMax - focusMax)) * (1 - focusShare);
  }

  function niceWindowCeil(value) {
    const safe = Math.max(1, Number(value) || 1);
    const exponent = Math.floor(Math.log10(safe));
    const magnitude = 10 ** exponent;
    const normalised = safe / magnitude;
    const step = normalised <= 1 ? 1 : normalised <= 2 ? 2 : normalised <= 5 ? 5 : 10;
    return step * magnitude;
  }

  function percentile(values, p) {
    const sorted = values.filter((value) => Number.isFinite(value)).sort((a, b) => a - b);
    if (!sorted.length) return 0;
    const index = Math.floor((p / 100) * (sorted.length - 1));
    return sorted[Math.max(0, Math.min(sorted.length - 1, index))];
  }

  function endpointCard(endpoint, title) {
    const logical = endpoint.ethernetLogicalAddresses?.length ? `<code>Ethernet logical ${escapeHtml(endpoint.ethernetLogicalAddresses.join(", "))}</code>` : "";
    return `<section class="transport-endpoint-card"><span>${escapeHtml(title)}</span><strong>${escapeHtml(endpoint.label)}</strong><code>${escapeHtml(endpoint.raw)}</code>${endpoint.mac ? `<code>${escapeHtml(endpoint.mac)}</code>` : ""}${logical}<p>${escapeHtml(endpoint.role)}</p></section>`;
  }

  function summariseEventTypes(events) {
    const counts = new Map();
    for (const event of events) counts.set(event.type, (counts.get(event.type) || 0) + 1);
    return Array.from(counts.entries()).map(([type, count]) => `${count} ${type}`).join(", ");
  }

  global.HarnessTransportRenderer = Object.freeze({
    parseTransportEndpoint,
    resolveTransportEndpoint,
    transportFlowIdentity,
    carriedLogicalAddressesForFlow,
    transportObservationSummary,
    formatWindowBytes,
    transportIssueMarkers,
    transportIssueClass,
    transportHealth,
    filterTransportFlows,
    endpointCell,
    healthClass,
    flowControlBadge,
    flowControlChartMax,
    flowControlChartRatio,
    niceWindowCeil,
    endpointCard,
    summariseEventTypes
  });
})(window);
