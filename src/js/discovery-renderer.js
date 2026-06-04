/**
 * Rendering helpers for the home/discovery/raw-sample panels.
 */
(function registerDiscoveryRenderer(global) {
  "use strict";

  const formatters = global.HarnessFormatters || {};
  const escapeHtml = formatters.escapeHtml || ((value) => String(value ?? ""));
  const formatCell = formatters.formatCell || ((value) => String(value ?? ""));
  const formatNumber = formatters.formatNumber || ((value) => String(value ?? ""));
  const formatBytes = formatters.formatBytes || ((value) => String(value ?? ""));
  const { badge, emptyRow, table } = global.HarnessUi;
  const STAGE_ORDER = ["arp", "tcpSocket", "vehicleAnnouncement", "vehicleIdResponse", "routingActivation", "diagnostics"];

  function renderHome(report, deps) {
    const $ = deps.$;
    const hasCapture = Boolean(report.source);
    $("homeTitle").textContent = hasCapture ? "Choose a tool" : "Load a capture to begin";
    $("homeIntro").textContent = hasCapture ? "Each tool uses the loaded pcap." : "Open or drop a classic Ethernet pcap. Parsing stays local.";
    $("homeCaptureState").textContent = report.source ? `${formatBytes(report.summary.totalBytes || 0)} loaded` : "No capture loaded";
    $("emptyHome").hidden = hasCapture;
    document.body.classList.toggle("no-capture", !hasCapture);
    $("homeUdsCount").textContent = `${formatNumber(report.diagnostics?.udsEvents?.length || 0)} events`;
    $("homeValidationCount").textContent = `${formatNumber((report.validationCentre?.findings || []).filter((item) => item.severity === "error" || item.severity === "warning").length)} findings`;
    $("homeTraceCount").textContent = `${formatNumber(Object.keys(report.diagnostics?.ecus || {}).length)} lanes`;
    $("homeTransportCount").textContent = `${formatNumber(report.tcpAnalysis?.flows?.length || 0)} flows`;
    $("homeDidCount").textContent = `${formatNumber(report.diagnostics?.didReads?.length || 0)} DIDs`;
    $("homeTransferCount").textContent = `${formatNumber(report.diagnostics?.transfers?.length || 0)} transfers`;
    $("homeDiscoveryCount").textContent = `${formatNumber(report.doip?.announcements?.length || 0)} announcements`;
    $("homeIdentityCount").textContent = `${formatNumber(report.identity?.findings?.length || 0)} findings`;
    $("homeTopologyCount").textContent = `${formatNumber(report.topology?.edges?.length || 0)} links`;
    $("homePacketCount").textContent = `${formatNumber(report.summary?.totalPackets || 0)} packets`;
  }

  function renderHosts(report, query = "") {
    const q = query.trim().toLowerCase();
    const rows = Object.values(report.hosts || {})
      .filter((host) => !q || host.mac.toLowerCase().includes(q) || host.ips.join(" ").toLowerCase().includes(q))
      .sort((a, b) => b.packets - a.packets)
      .slice(0, 50)
      .map((host) => `<tr><td><code>${host.mac}</code></td><td>${host.ips.map((item) => `<code>${item}</code>`).join("<br>")}</td><td>${formatNumber(host.packets)}</td><td>${formatBytes(host.bytes)}</td></tr>`);
    return rows.join("") || emptyRow(4, "No matching hosts.");
  }

  function renderAnnouncements(announcements) {
    return announcements.length ? announcements.map((item) => `
    <div class="card">
      <div class="card-title"><strong>${escapeHtml(item.vin || "No VIN")}</strong><span class="pill">${escapeHtml(item.logicalAddress || "")}</span></div>
      <div class="kv">
        <div><span>Source</span><code>${escapeHtml(item.srcIp)}:${item.srcPort}</code></div>
        <div><span>EID</span><code>${escapeHtml(item.eid || "")}</code></div>
        <div><span>GID</span><code>${escapeHtml(item.gid || "")}</code></div>
        <div><span>Further action</span><code>${item.furtherActionRequired ?? ""}</code></div>
      </div>
    </div>
  `).join("") : `<div class="empty">No DoIP vehicle announcements decoded.</div>`;
  }

  function renderDhcp(report, barsHtml) {
    const clientRows = Object.values(report.dhcp.clients || {}).map((client) => `
    <tr><td><code>${client.mac}</code></td><td>${escapeHtml(client.hostname || "")}</td><td>${client.ips.map((item) => `<code>${item}</code>`).join("<br>")}</td><td>${escapeHtml(Object.entries(client.messages).map(([k, v]) => `${k}: ${v}`).join(", "))}</td></tr>
  `).join("");
    return `
    <div>${barsHtml(report.dhcp.messageTypes)}</div>
    ${table(["Client MAC", "Hostname", "IPs", "Messages"], clientRows, "No DHCP clients decoded.")}
  `;
  }

  function renderArp(report, barsHtml) {
    const rows = (report.arp.samples || []).slice(0, 40).map((item) => `
    <tr><td>${escapeHtml(item.operation)}</td><td><code>${item.senderIp}</code><br><code>${item.senderMac}</code></td><td><code>${item.targetIp}</code><br><code>${item.targetMac}</code></td></tr>
  `).join("");
    return `
    <div>${barsHtml(report.arp.operations)}</div>
    ${table(["Op", "Sender", "Target"], rows, "No ARP samples decoded.")}
  `;
  }

  function sampleTable(report, type) {
    const map = {
      doip: [report.doip.samples || [], ["packet", "transport", "srcIp", "dstIp", "payloadName", "ackCode", "ackCodeName", "nackCode", "nackCodeName", "routingActivationResponseCode", "routingActivationResponseCodeName", "source", "target", "previousTarget", "vin", "logicalAddress"]],
      dhcp: [report.dhcp.samples || [], ["packet", "messageType", "clientMac", "srcIp", "requestedIp", "yourIp", "hostname"]],
      arp: [report.arp.samples || [], ["packet", "operation", "senderIp", "senderMac", "targetIp", "targetMac"]],
      flows: [report.flows || [], ["transport", "src", "srcPort", "dst", "dstPort", "packets"]]
    };
    const [rows, columns] = map[type] || map.doip;
    return {
      head: `<tr>${columns.map((col) => `<th>${escapeHtml(col)}</th>`).join("")}</tr>`,
      body: rows.slice(0, 100).map((row) => `<tr>${columns.map((col) => `<td>${formatCell(row[col])}</td>`).join("")}</tr>`).join("") || emptyRow(columns.length, "No samples.")
    };
  }

  function lifecycleRoleLabel(role) {
    return {
      "gateway-socket": "Gateway/socket",
      "ethernet-node": "Ethernet node",
      "behind-socket": "Behind socket",
      unknown: "Unknown"
    }[role] || role || "Unknown";
  }

  function lifecycleStatusLabel(status) {
    return {
      observed: "Observed",
      missing: "Missing",
      failed: "Failed",
      "out-of-order": "Out of order",
      "not-applicable": "N/A"
    }[status] || status || "Unknown";
  }

  function lifecycleStatusClass(status) {
    return {
      observed: "ok",
      missing: "warn",
      failed: "danger",
      "out-of-order": "warn",
      "not-applicable": ""
    }[status] || "";
  }

  function nodeMatchesLifecycleFilter(node, filter) {
    if (filter === "issues") return node.issues?.length || Object.values(node.stages || {}).some((stage) => stage.status === "failed" || stage.status === "out-of-order");
    if (filter === "ethernet") return node.role === "ethernet-node";
    if (filter === "gateways") return node.role === "gateway-socket";
    if (filter === "behind") return node.role === "behind-socket";
    if (filter === "missing-routing") return node.stages?.routingActivation?.status === "missing";
    if (filter === "rejected") return node.stages?.diagnostics?.status === "failed";
    return true;
  }

  function filteredLifecycleNodes(lifecycle, filter = "all") {
    return (lifecycle?.nodes || []).filter((node) => nodeMatchesLifecycleFilter(node, filter));
  }

  function renderLifecycleSummary(lifecycle) {
    const summary = lifecycle?.summary || {};
    return [
      ["Lifecycle nodes", formatNumber(summary.nodes || 0)],
      ["Nodes with issues", formatNumber(summary.issues || 0)],
      ["Routing active", formatNumber(summary.routingActive || 0)],
      ["Rejected targets", formatNumber(summary.rejected || 0)]
    ].map(([label, value]) => `<div class="lifecycle-metric"><span>${label}</span><strong>${value}</strong></div>`).join("");
  }

  function renderLifecycleNodeList(lifecycle, selectedNodeId, filter = "all") {
    const nodes = filteredLifecycleNodes(lifecycle, filter);
    if (!nodes.length) return `<div class="empty">No DoIP lifecycle nodes match this filter.</div>`;
    return nodes.map((node) => {
      const title = node.name || node.logicalAddress || node.ips?.[0] || "Unknown node";
      const status = node.stages?.diagnostics?.status === "failed" ? "failed" : node.issues?.length ? "issue" : "ok";
      const logical = node.logicalAddress || "No logical address";
      const baseIpText = (node.ips || []).slice(0, 3).join(", ") || "No IP";
      const mappedHint = node.role === "behind-socket"
        ? [node.parentSocketName, node.parentSocketLogicalAddress].filter(Boolean).filter((item, index, list) => list.indexOf(item) === index).join(" ")
        : "";
      const ipText = mappedHint ? `${baseIpText} (${mappedHint})` : baseIpText;
      const nodeState = status === "failed"
        ? badge("Failed", "danger")
        : status === "issue"
          ? badge(`${formatNumber(node.issues?.length || 0)} issue${node.issues?.length === 1 ? "" : "s"}`, "warn")
          : badge("OK", "ok");
      return `
        <button class="lifecycle-node lifecycle-node-${status}${node.id === selectedNodeId ? " selected" : ""}" type="button" data-lifecycle-node="${escapeHtml(node.id)}">
          <span class="lifecycle-node-status">
            ${nodeState}
          </span>
          <strong class="lifecycle-node-title">${escapeHtml(title)}</strong>
          <span class="lifecycle-node-role">${escapeHtml(lifecycleRoleLabel(node.role))}</span>
          <code class="lifecycle-node-logical">${escapeHtml(logical)}</code>
          <code class="lifecycle-node-ip">${escapeHtml(ipText)}</code>
        </button>
      `;
    }).join("");
  }

  function compactDetailTable(columns, rows, emptyText) {
    if (!rows?.length) return `<div class="empty compact-empty">${escapeHtml(emptyText)}</div>`;
    return `
      <div class="table-wrap table-wrap-compact">
        <table>
          <thead><tr>${columns.map(([key, label]) => `<th>${escapeHtml(label || key)}</th>`).join("")}</tr></thead>
          <tbody>${rows.map((row) => `<tr>${columns.map(([key]) => `<td>${formatCell(row[key])}</td>`).join("")}</tr>`).join("")}</tbody>
        </table>
      </div>
    `;
  }

  function packetList(values) {
    return (values || []).slice(0, 6).map((packet) => `<code>${escapeHtml(packet)}</code>`).join(" ") || "None";
  }

  function renderTcpSocketDetails(stage) {
    const flows = stage.details?.flows || [];
    const rows = flows.map((flow) => ({
      socketEndpoint: flow.socketEndpoint || "DoIP endpoint",
      opened: flow.opened || 0,
      closed: flow.closed || 0,
      resets: flow.resets || 0,
      packets: flow.packets || 0,
      payloadBytes: flow.payloadBytes || 0,
      firstTimestamp: flow.firstTimestamp ?? "",
      lastTimestamp: flow.lastTimestamp ?? ""
    }));
    const timeline = flows.map((flow) => `
      <div class="lifecycle-mini-flow">
        <span>Open ${packetList(flow.openPackets)}</span>
        <span>Traffic ${formatNumber(flow.packets || 0)} packets</span>
        <span>${flow.resets ? `RST ${packetList(flow.resetPackets)}` : `Close ${packetList(flow.closePackets)}`}</span>
      </div>
    `).join("");
    return `
      <div class="lifecycle-stage-extra">
        <span>TCP socket summary</span>
        ${compactDetailTable([
          ["socketEndpoint", "Socket"],
          ["opened", "Opened"],
          ["closed", "Closed"],
          ["resets", "RST"],
          ["packets", "Packets"],
          ["payloadBytes", "Payload bytes"]
        ], rows, "No TCP socket flow evidence for this node.")}
        ${timeline ? `<div class="lifecycle-mini-timeline">${timeline}</div>` : ""}
      </div>
    `;
  }

  function renderVehicleIdDetails(stage) {
    const pairs = stage.details?.pairs || [];
    const requests = stage.details?.requests || [];
    const responses = stage.details?.responses || [];
    return `
      <div class="lifecycle-stage-extra">
        <span>Vehicle ID request / response pairing</span>
        ${compactDetailTable([
          ["requestPacket", "Request frame"],
          ["responsePacket", "Response frame"],
          ["requestType", "Request"],
          ["responseIp", "Response IP"],
          ["logicalAddress", "Logical"]
        ], pairs, "No paired vehicle ID responses for this node.")}
        <p class="lifecycle-stage-note">${formatNumber(requests.length)} request frame${requests.length === 1 ? "" : "s"}, ${formatNumber(responses.length)} response frame${responses.length === 1 ? "" : "s"} matched for this node.</p>
      </div>
    `;
  }

  function renderRoutingActivationDetails(stage) {
    const rows = (stage.details?.activations || []).map((item) => ({
      packet: item.packet,
      type: item.type === "0x0006" ? "Response" : "Request",
      testerLogicalAddress: item.testerLogicalAddress || "",
      entityLogicalAddress: item.entityLogicalAddress || "",
      responseCode: item.responseCode || "",
      responseCodeName: item.responseCodeName || "",
      route: `${item.sourceIp || ""} -> ${item.targetIp || ""}`.trim()
    }));
    return `
      <div class="lifecycle-stage-extra">
        <span>Routing activation detail</span>
        ${compactDetailTable([
          ["packet", "Frame"],
          ["type", "Type"],
          ["testerLogicalAddress", "Tester"],
          ["entityLogicalAddress", "Entity"],
          ["responseCode", "Code"],
          ["responseCodeName", "Result"],
          ["route", "IP route"]
        ], rows, "No routing activation request or response evidence for this node.")}
      </div>
    `;
  }

  function renderDiagnosticsDetails(stage) {
    const details = stage.details || {};
    const routed = details.routedTarget;
    const rejected = details.rejectedTarget;
    const eventCount = (details.events || []).length;
    return `
      <div class="lifecycle-stage-extra">
        <span>Diagnostics detail</span>
        ${routed ? `<p class="lifecycle-stage-note">Logical target <code>${escapeHtml(routed.logicalAddress)}</code> is addressed through <code>${escapeHtml(routed.socketIp || "")}</code>${routed.socketName ? ` (${escapeHtml(routed.socketName)})` : ""}. ${formatNumber(routed.requests || 0)} request${routed.requests === 1 ? "" : "s"} observed.</p>` : ""}
        ${rejected ? `<p class="lifecycle-stage-note">Logical target <code>${escapeHtml(rejected.logicalAddress)}</code> was rejected by <code>${escapeHtml(rejected.socketIp || "")}</code>${rejected.socketName ? ` (${escapeHtml(rejected.socketName)})` : ""}. Previous payloads: ${escapeHtml((rejected.previousMessages || []).slice(0, 3).join("; ") || "not available")}.</p>` : ""}
        ${!routed && !rejected ? `<p class="lifecycle-stage-note">${formatNumber(eventCount)} diagnostic event${eventCount === 1 ? "" : "s"} observed for this node.</p>` : ""}
      </div>
    `;
  }

  function renderStageSpecificDetails(stage) {
    if (stage.key === "tcpSocket") return renderTcpSocketDetails(stage);
    if (stage.key === "vehicleIdResponse") return renderVehicleIdDetails(stage);
    if (stage.key === "routingActivation") return renderRoutingActivationDetails(stage);
    if (stage.key === "diagnostics") return renderDiagnosticsDetails(stage);
    return "";
  }

  function selectedLifecycleStage(node, selectedStageKey) {
    const stages = node?.stages || {};
    if (selectedStageKey && stages[selectedStageKey]) return stages[selectedStageKey];
    return STAGE_ORDER.map((key) => stages[key]).find((stage) => stage && stage.status !== "not-applicable") || STAGE_ORDER.map((key) => stages[key]).find(Boolean);
  }

  function renderLifecycleTimeline(node, selectedStageKey) {
    if (!node) return `<div class="empty">Select a lifecycle node to inspect its sequence.</div>`;
    const selected = selectedLifecycleStage(node, selectedStageKey);
    return STAGE_ORDER.map((key) => node.stages?.[key]).filter(Boolean).map((stage, index) => `
      <button class="lifecycle-stage lifecycle-stage-${escapeHtml(stage.status)}${selected?.key === stage.key ? " selected" : ""}" type="button" data-lifecycle-stage="${escapeHtml(stage.key)}" data-flow-step="${index + 1}">
        <span class="lifecycle-stage-index">${index + 1}</span>
        <span class="lifecycle-stage-label">${escapeHtml(stage.label)}</span>
        ${badge(lifecycleStatusLabel(stage.status), lifecycleStatusClass(stage.status))}
      </button>
    `).join("");
  }

  function renderLifecycleStageDetail(node, selectedStageKey) {
    if (!node) return `<div class="empty">No lifecycle node selected.</div>`;
    const stage = selectedLifecycleStage(node, selectedStageKey);
    if (!stage) return `<div class="empty">No lifecycle stage evidence is available.</div>`;
    const hasFirstTimestamp = stage.firstTimestamp !== null && stage.firstTimestamp !== undefined;
    const packetText = (stage.packets || []).slice(0, 8).map((packet) => `<code>${escapeHtml(packet)}</code>`).join(" ");
    const evidence = (stage.evidence || []).slice(0, 8).map((item) => `<li>${escapeHtml(item)}</li>`).join("");
    const issues = (node.issues || []).map((issue) => `<li><strong>${escapeHtml(issue.title)}</strong> ${escapeHtml(issue.detail || "")}</li>`).join("");
    return `
      <div class="lifecycle-detail-head">
        <div>
          <h3>${escapeHtml(stage.label)}</h3>
          <p>${escapeHtml(lifecycleStatusLabel(stage.status))}${stage.count ? `, ${formatNumber(stage.count)} observed` : ""}</p>
        </div>
        <span class="pill">${escapeHtml(lifecycleRoleLabel(node.role))}</span>
      </div>
      <dl class="lifecycle-detail-grid">
        <div><dt>Node</dt><dd>${escapeHtml(node.name || node.logicalAddress || node.id)}</dd></div>
        <div><dt>Logical</dt><dd><code>${escapeHtml(node.logicalAddress || "")}</code></dd></div>
        <div><dt>IP evidence</dt><dd>${(node.ips || []).map((ip) => `<code>${escapeHtml(ip)}</code>`).join(" ") || "None"}</dd></div>
        <div><dt>MAC evidence</dt><dd>${(node.macs || []).slice(0, 4).map((mac) => `<code>${escapeHtml(mac)}</code>`).join(" ") || "None"}</dd></div>
        <div><dt>First packet</dt><dd>${stage.firstPacket ? `<code>${escapeHtml(stage.firstPacket)}</code>` : "None"}</dd></div>
        <div><dt>First time</dt><dd>${hasFirstTimestamp ? `${escapeHtml(stage.firstTimestamp)} s` : "None"}</dd></div>
      </dl>
      ${renderStageSpecificDetails(stage)}
      ${packetText ? `<div class="lifecycle-evidence"><span>Packet samples</span><p>${packetText}</p></div>` : ""}
      ${evidence ? `<div class="lifecycle-evidence"><span>Stage evidence</span><ul>${evidence}</ul></div>` : ""}
      ${issues ? `<div class="lifecycle-evidence lifecycle-issues"><span>Issues</span><ul>${issues}</ul></div>` : ""}
    `;
  }

  global.HarnessDiscoveryRenderer = Object.freeze({
    renderHome,
    renderHosts,
    renderAnnouncements,
    renderDhcp,
    renderArp,
    filteredLifecycleNodes,
    renderLifecycleSummary,
    renderLifecycleNodeList,
    renderLifecycleTimeline,
    lifecycleStatusClass,
    renderLifecycleStageDetail,
    sampleTable
  });
})(window);
