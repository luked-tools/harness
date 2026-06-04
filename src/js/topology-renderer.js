/**
 * Rendering helpers for topology filtering, geometry, details, and tables.
 */
(function registerTopologyRenderer(global) {
  "use strict";

  const formatters = global.HarnessFormatters || {};
  const escapeHtml = formatters.escapeHtml || ((value) => String(value ?? ""));
  const formatNumber = formatters.formatNumber || ((value) => String(value ?? ""));
  const { badge } = global.HarnessUi;

  function label(value, max = 19) {
    const text = String(value || "");
    return text.length > max ? `${text.slice(0, max - 3)}...` : text;
  }

  function roleVisible(node, roleState = {}) {
    if (node.ambiguous && roleState.ambiguous === false) return false;
    return roleState[node.role] !== false;
  }

  function edgeVisible(edge, edgeState = {}) {
    return edgeState[edge.kind] !== false && (!edge.inferred || edgeState.inferred !== false);
  }

  function filteredTopology(topology, states = {}) {
    const roleState = states.roleState || {};
    const edgeState = states.edgeState || {};
    const allowedNodes = new Set((topology.nodes || []).filter((node) => roleVisible(node, roleState)).map((node) => node.id));
    const edges = (topology.edges || []).filter((edge) => edgeVisible(edge, edgeState) && allowedNodes.has(edge.source) && allowedNodes.has(edge.target));
    for (const edge of edges) {
      allowedNodes.add(edge.source);
      allowedNodes.add(edge.target);
    }
    return {
      nodes: (topology.nodes || []).filter((node) => allowedNodes.has(node.id)),
      edges
    };
  }

  function gatewayGroups(topology, gatewayNodes) {
    const byGateway = gatewayNodes.map((gateway) => ({ gateway, ecus: [] }));
    const groupById = new Map(byGateway.map((group) => [group.gateway.id, group]));
    const ecuById = new Map((topology.nodes || []).filter((node) => node.role === "ecu").map((node) => [node.id, node]));
    for (const edge of topology.edges || []) {
      if (edge.kind !== "inferred") continue;
      const group = groupById.get(edge.source);
      const ecu = ecuById.get(edge.target);
      if (group && ecu && !group.ecus.some((item) => item.id === ecu.id)) group.ecus.push(ecu);
    }
    return byGateway.sort((a, b) => b.ecus.length - a.ecus.length || a.gateway.label.localeCompare(b.gateway.label));
  }

  function edgePath(source, target, edge, offset = 0) {
    const startX = source.x + 228;
    const endX = target.x - 10;
    const midX = startX + (endX - startX) * 0.52 + offset;
    if (edge.kind === "inferred") {
      const busX = midX + offset * 0.35;
      return `M ${startX} ${source.y} L ${busX} ${source.y} L ${busX} ${target.y} L ${endX} ${target.y}`;
    }
    if (edge.kind === "routing" || edge.kind === "diagnostic") {
      const laneOffset = (edge.kind === "routing" ? -18 : 18) + offset * 0.12;
      return `M ${startX} ${source.y + laneOffset} C ${midX} ${source.y + laneOffset}, ${midX} ${target.y + laneOffset}, ${endX} ${target.y + laneOffset}`;
    }
    return `M ${startX} ${source.y} C ${midX} ${source.y}, ${midX} ${target.y}, ${endX} ${target.y}`;
  }

  function edgeOffsets(edges, positions) {
    const grouped = new Map();
    for (const edge of edges || []) {
      const source = positions.get(edge.source);
      const target = positions.get(edge.target);
      if (!source || !target) continue;
      const key = `${edge.source}|${edge.kind}`;
      if (!grouped.has(key)) grouped.set(key, []);
      grouped.get(key).push(edge);
    }
    const offsets = new Map();
    for (const items of grouped.values()) {
      const sorted = items.sort((a, b) => (positions.get(a.target)?.y || 0) - (positions.get(b.target)?.y || 0));
      sorted.forEach((edge, index) => {
        const offset = (index - (sorted.length - 1) / 2) * 28;
        offsets.set(edge.id, offset);
      });
    }
    return offsets;
  }

  function edgeLabelPoint(source, target) {
    return {
      x: source.x + (target.x - source.x) * 0.55,
      y: (source.y + target.y) / 2 - 12
    };
  }

  function detailHtml(topology, selectedId) {
    const node = (topology.nodes || []).find((item) => item.id === selectedId);
    const edge = (topology.edges || []).find((item) => item.id === selectedId);
    if (!node && !edge) return `<div class="empty">No topology evidence decoded.</div>`;
    if (node) {
      return `
      <p class="eyebrow">Selected node</p>
      <h3>${escapeHtml(node.label)}</h3>
      <dl>
        <dt>Role</dt><dd>${escapeHtml(node.role)}${node.ambiguous ? ` ${badge("ambiguous", "warn")}` : ""}</dd>
        <dt>Logical address</dt><dd><code>${escapeHtml(node.logicalAddress || "")}</code></dd>
        <dt>Friendly name</dt><dd>${escapeHtml(node.friendlyName || "")}</dd>
        <dt>IPs</dt><dd>${node.ips.map((value) => `<code>${escapeHtml(value)}</code>`).join(" ") || ""}</dd>
        <dt>MAC</dt><dd>${node.macs.filter(Boolean).map((value) => `<code>${escapeHtml(value)}</code>`).join(" ") || ""}</dd>
        <dt>EID</dt><dd>${node.eids.filter(Boolean).map((value) => `<code>${escapeHtml(value)}</code>`).join(" ") || ""}</dd>
        <dt>VIN</dt><dd>${node.vins.map((value) => `<code>${escapeHtml(value)}</code>`).join(" ") || ""}</dd>
        <dt>Packets</dt><dd>${node.packets.map((value) => `<code>${escapeHtml(value)}</code>`).join(" ") || ""}</dd>
      </dl>
      <div class="topology-evidence">${node.evidence.map((item) => `<span>${escapeHtml(item)}</span>`).join("")}</div>
    `;
    }
    const source = (topology.nodes || []).find((item) => item.id === edge.source);
    const target = (topology.nodes || []).find((item) => item.id === edge.target);
    return `
    <p class="eyebrow">Selected link</p>
    <h3>${escapeHtml(edge.label)}</h3>
    <dl>
      <dt>Type</dt><dd>${escapeHtml(edge.kind)}${edge.inferred ? ` ${badge("inferred")}` : ""}</dd>
      <dt>From</dt><dd>${escapeHtml(source?.label || edge.source)}</dd>
      <dt>To</dt><dd>${escapeHtml(target?.label || edge.target)}</dd>
      <dt>Observations</dt><dd>${formatNumber(edge.count)}</dd>
      <dt>Packets</dt><dd>${edge.packets.map((value) => `<code>${escapeHtml(value)}</code>`).join(" ") || ""}</dd>
    </dl>
    <div class="topology-evidence">${edge.evidence.map((item) => `<span>${escapeHtml(item)}</span>`).join("")}</div>
  `;
  }

  function tableHtml(topology) {
    const nodes = topology.nodes || [];
    const edges = topology.edges || [];
    const downstreamByGateway = new Map();
    const ecuGatewayRows = [];
    for (const edge of edges.filter((item) => item.kind === "inferred")) {
      if (!downstreamByGateway.has(edge.source)) downstreamByGateway.set(edge.source, []);
      const source = nodes.find((node) => node.id === edge.source);
      const target = nodes.find((node) => node.id === edge.target);
      downstreamByGateway.get(edge.source).push(target?.label || edge.target);
      if (target) ecuGatewayRows.push({ edge, source, target });
    }
    const gateway = nodes.filter((node) => node.role === "gateway").map((node) => `
    <tr>
      <td><button class="link-button topology-select" type="button" data-topology-id="${escapeHtml(node.id)}">${escapeHtml(node.label)}</button></td>
      <td>${node.ips.map((value) => `<code>${escapeHtml(value)}</code>`).join("<br>")}</td>
      <td>${node.macs.filter(Boolean).map((value) => `<code>${escapeHtml(value)}</code>`).join("<br>")}</td>
      <td>${node.eids.filter(Boolean).map((value) => `<code>${escapeHtml(value)}</code>`).join("<br>")}</td>
      <td>${(downstreamByGateway.get(node.id) || []).map((value) => `<code>${escapeHtml(value)}</code>`).join("<br>") || ""}</td>
    </tr>
  `).join("") || `<tr><td colspan="5">No DoIP gateway/entity announcements decoded.</td></tr>`;
    const ecuGateway = ecuGatewayRows.map(({ edge, source, target }) => `
    <tr>
      <td><button class="link-button topology-select" type="button" data-topology-id="${escapeHtml(target.id)}">${escapeHtml(target.label)}</button></td>
      <td><button class="link-button topology-select" type="button" data-topology-id="${escapeHtml(edge.id)}">${escapeHtml(source?.label || edge.source)}</button><br>${(source?.ips || []).map((value) => `<code>${escapeHtml(value)}</code>`).join(" ")}</td>
      <td>${edge.evidence.map((item) => `<span>${escapeHtml(item)}</span>`).join("<br>")}</td>
    </tr>
  `).join("") || `<tr><td colspan="3">No inferred gateway-to-ECU relationships decoded.</td></tr>`;
    const ambiguous = [...nodes.filter((node) => node.ambiguous).map((node) => ({ id: node.id, label: node.label, type: node.role, evidence: node.evidence.join(" | ") })),
      ...edges.filter((edge) => edge.ambiguous).map((edge) => ({ id: edge.id, label: edge.label, type: edge.kind, evidence: edge.evidence.join(" | ") }))];
    const ambiguousRows = ambiguous.map((item) => `
    <tr>
      <td><button class="link-button topology-select" type="button" data-topology-id="${escapeHtml(item.id)}">${escapeHtml(item.label)}</button></td>
      <td>${escapeHtml(item.type)}</td>
      <td>${escapeHtml(item.evidence)}</td>
    </tr>
  `).join("") || `<tr><td colspan="3">No ambiguous topology identities detected.</td></tr>`;
    return { gateway, ecuGateway, ambiguous: ambiguousRows };
  }

  function socketMapHtml(socketMap, selectedId = "") {
    const sockets = socketMap?.sockets || [];
    if (!sockets.length) return `<div class="empty">No DoIP socket evidence decoded.</div>`;
    return `<div class="socket-map-grid">${sockets.map((socket) => {
      const selected = selectedId === socket.id;
      const routingActive = Boolean(socket.routingActivations?.length);
      const direct = socket.directLogicalAddress
        ? `<button class="socket-direct ${selected ? "selected" : ""}" type="button" data-topology-socket="${escapeHtml(socket.id)}"><span>Socket logical</span><strong>${escapeHtml(socket.directName || socket.directLogicalAddress)}</strong><code>${escapeHtml(socket.directLogicalAddress)}</code></button>`
        : `<button class="socket-direct ${selected ? "selected" : ""}" type="button" data-topology-socket="${escapeHtml(socket.id)}"><span>Socket endpoint</span><strong>${escapeHtml(socket.ip || socket.label)}</strong><code>logical unknown</code></button>`;
      const routed = socket.routed.map((item) => `
        <button class="socket-route ${selectedId === item.id ? "selected" : ""}" type="button" data-topology-route="${escapeHtml(item.id)}">
          <span>${escapeHtml(item.name || item.logicalAddress)}</span>
          <code>${escapeHtml(item.logicalAddress)}</code>
          <small>${formatNumber(item.requests || 0)} request${item.requests === 1 ? "" : "s"}</small>
        </button>
      `).join("") || `<div class="socket-empty">No additional logical addresses observed through this socket.</div>`;
      const rejected = socket.rejected.map((item) => `
        <button class="socket-route rejected ${selectedId === item.id ? "selected" : ""}" type="button" data-topology-route="${escapeHtml(item.id)}">
          <span>${escapeHtml(item.name || item.logicalAddress)}</span>
          <code>${escapeHtml(item.logicalAddress)}</code>
          <small>rejected by NACK 0x03</small>
        </button>
      `).join("");
      const hasRejectedTargets = Boolean(socket.rejected?.length);
      return `<article class="socket-card ${selected ? "selected" : ""} ${routingActive ? "routing-active" : ""} ${hasRejectedTargets ? "has-rejected-targets" : ""}" data-socket-card="${escapeHtml(socket.id)}">
        <header>
          <div class="socket-card-status">
            <span>TCP socket endpoint</span>
            ${routingActive ? `<span class="socket-status-pill">Routing active</span>` : ""}
            ${hasRejectedTargets ? `<span class="socket-status-pill rejected">Unknown target</span>` : ""}
          </div>
          <h3>${escapeHtml(socket.ip || socket.label)}</h3>
          <p>${[socket.macs[0], socket.vins[0], socket.eids[0]].filter(Boolean).map(escapeHtml).join(" | ")}</p>
          ${socket.autoIpAddresses?.length && socket.dhcpIpAddresses?.length ? `<p class="socket-transition">AutoIP ${socket.autoIpAddresses.map(escapeHtml).join(", ")} -> DHCP ${socket.dhcpIpAddresses.map(escapeHtml).join(", ")}</p>` : ""}
        </header>
        ${direct}
        <div class="socket-route-list">
          <span class="socket-section-label">Addressed through this socket</span>
          ${routed}
          ${rejected ? `<span class="socket-section-label">Rejected targets</span>${rejected}` : ""}
        </div>
      </article>`;
    }).join("")}</div>`;
  }

  function socketNodeMapHtml(socketMap, selectedId = "") {
    const sockets = socketMap?.sockets || [];
    if (!sockets.length) return `<div class="empty">No DoIP socket evidence decoded.</div>`;
    return `<div class="socket-node-map">${socketFlowHtml(sockets, selectedId)}</div>`;
  }

  function socketFlowHtml(sockets, selectedId = "") {
    const socketByLogical = new Map(sockets.filter((socket) => socket.directLogicalAddress).map((socket) => [socket.directLogicalAddress, socket]));
    const rows = sockets.map((socket) => {
      const testers = uniqueValues([
        ...(socket.routingActivations || []).map((item) => item.testerLogicalAddress),
        ...(socket.routed || []).flatMap((item) => item.testers || [])
      ]);
      const ethernetNodes = (socket.routed || [])
        .map((item) => ({ route: item, socket: socketByLogical.get(item.logicalAddress) }))
        .filter((item) => item.socket && item.socket.id !== socket.id);
      const ethernetIds = new Set(ethernetNodes.map((item) => item.route.logicalAddress));
      const logicalList = (socket.routed || []).filter((item) => !ethernetIds.has(item.logicalAddress));
      const downstream = [
        ...ethernetNodes.map(({ route, socket: downstreamSocket }) => ({
          id: downstreamSocket.id,
          label: downstreamSocket.directName || route.name || route.logicalAddress,
          logicalAddress: route.logicalAddress,
          meta: downstreamSocket.ip || "socket observed",
          kind: "ethernet"
        })),
        ...(!ethernetNodes.length && socket.directLogicalAddress ? [{
          id: socket.id,
          label: socket.directName || socket.directLogicalAddress,
          logicalAddress: socket.directLogicalAddress,
          meta: "direct socket",
          kind: "direct"
        }] : [])
      ];
      const routingActive = Boolean(socket.routingActivations?.length);
      const rejectedTargets = (socket.rejected || []).map((item) => `
        <button class="socket-graph-node rejected-node ${selectedId === item.id ? "selected" : ""}" type="button" data-topology-route="${escapeHtml(item.id)}">
          <span>Unknown target</span>
          <strong>${escapeHtml(item.name || item.logicalAddress)}</strong>
          <code>${escapeHtml(item.logicalAddress)}</code>
          <small>NACK 0x03 from ${escapeHtml(socket.directName || socket.directLogicalAddress || socket.ip || "socket")}</small>
        </button>
      `).join("");
      return `<section class="socket-graph-row ${routingActive ? "routing-active" : ""} ${rejectedTargets ? "has-rejected-targets" : ""}">
        <div class="socket-graph-cluster tester-cluster">
          <p>Tester</p>
          ${(testers.length ? testers : ["Observed tester"]).map((tester) => `<span class="socket-graph-node tester-node"><strong>${escapeHtml(tester)}</strong></span>`).join("")}
        </div>
        <div class="socket-graph-link" aria-hidden="true"></div>
        <button class="socket-graph-node socket-node ${selectedId === socket.id ? "selected" : ""}" type="button" data-topology-socket="${escapeHtml(socket.id)}">
          <span>${routingActive ? "Routing active" : "Socket"}</span>
          <strong>${escapeHtml(socket.directName || socket.ip || socket.label)}</strong>
          <code>${escapeHtml(socket.directLogicalAddress || socket.ip || "unknown")}</code>
        </button>
        <div class="socket-graph-link" aria-hidden="true"></div>
        <div class="socket-graph-cluster downstream-cluster">
          <p>${ethernetNodes.length ? "Ethernet node" : "Logical address"}</p>
          ${downstream.length ? downstream.map((item) => `
            <button class="socket-graph-node downstream-node ${selectedId === item.id ? "selected" : ""}" type="button" data-topology-socket="${escapeHtml(item.id)}">
              <span>${escapeHtml(item.kind === "ethernet" ? "Own TCP socket" : "Direct")}</span>
              <strong>${escapeHtml(item.label)}</strong>
              <code>${escapeHtml(item.logicalAddress)}</code>
              <small>${escapeHtml(item.meta)}</small>
            </button>
          `).join("") : `<div class="socket-flow-empty">No downstream Ethernet node observed</div>`}
          ${rejectedTargets ? `<div class="socket-rejected-branch"><p>Rejected unknown target</p>${rejectedTargets}</div>` : ""}
          ${logicalList.length ? `<details class="socket-logical-list"><summary>Other logical addresses</summary>
            <div>
              ${logicalList.map((item) => `<button type="button" data-topology-route="${escapeHtml(item.id)}" class="${selectedId === item.id ? "selected" : ""}"><span>${escapeHtml(item.name || item.logicalAddress)}</span><code>${escapeHtml(item.logicalAddress)}</code></button>`).join("")}
            </div>
          </details>` : ""}
        </div>
      </section>`;
    }).join("");
    return `<div class="socket-graph" aria-label="Tester to socket to downstream Ethernet node map">${rows}</div>`;
  }

  function uniqueValues(values) {
    return Array.from(new Set((values || []).filter(Boolean)));
  }

  function socketDetailHtml(socketMap, selectedId) {
    const sockets = socketMap?.sockets || [];
    const socket = sockets.find((item) => item.id === selectedId) || sockets.find((item) => (item.routed || []).some((route) => route.id === selectedId) || (item.rejected || []).some((route) => route.id === selectedId));
    if (!socket) return `<div class="empty">Select a socket or logical address to inspect the connection evidence.</div>`;
    const routed = (socket.routed || []).find((item) => item.id === selectedId);
    const rejected = (socket.rejected || []).find((item) => item.id === selectedId);
    if (routed || rejected) {
      const item = routed || rejected;
      return `
        <p class="eyebrow">${rejected ? "Rejected target" : "Routed logical address"}</p>
        <h3>${escapeHtml(item.name || item.logicalAddress)}</h3>
        <dl>
          <dt>Logical</dt><dd><code>${escapeHtml(item.logicalAddress)}</code></dd>
          <dt>Socket IP</dt><dd><code>${escapeHtml(socket.ip || "")}</code></dd>
          <dt>Socket logical</dt><dd><code>${escapeHtml(socket.directLogicalAddress || "unknown")}</code></dd>
          <dt>Evidence</dt><dd>${formatNumber((item.packets || []).length)} packet${(item.packets || []).length === 1 ? "" : "s"} observed</dd>
          ${routed ? `<dt>Requests</dt><dd>${formatNumber(item.requests || 0)}</dd><dt>Testers</dt><dd>${(item.testers || []).map((value) => `<code>${escapeHtml(value)}</code>`).join(" ")}</dd>` : ""}
        </dl>
        <div class="topology-evidence">${(item.evidence || []).map((value) => `<span>${escapeHtml(value)}</span>`).join("")}</div>
      `;
    }
    return `
      <p class="eyebrow">Socket endpoint</p>
      <h3>${escapeHtml(socket.label || socket.ip || "Socket")}</h3>
      <dl>
        <dt>IP</dt><dd><code>${escapeHtml(socket.ip || "")}</code></dd>
        <dt>Observed IPs</dt><dd>${(socket.observedIps || []).map((value) => `<code>${escapeHtml(value)}</code>`).join(" ")}</dd>
        <dt>AutoIP/DHCP</dt><dd>${socket.autoIpAddresses?.length && socket.dhcpIpAddresses?.length ? `${socket.autoIpAddresses.map((value) => `<code>${escapeHtml(value)}</code>`).join(" ")} -> ${socket.dhcpIpAddresses.map((value) => `<code>${escapeHtml(value)}</code>`).join(" ")}` : ""}</dd>
        <dt>Logical</dt><dd><code>${escapeHtml(socket.directLogicalAddress || "unknown")}</code></dd>
        <dt>Name</dt><dd>${escapeHtml(socket.directName || "")}</dd>
        <dt>MAC</dt><dd>${(socket.macs || []).map((value) => `<code>${escapeHtml(value)}</code>`).join(" ")}</dd>
        <dt>EID</dt><dd>${(socket.eids || []).map((value) => `<code>${escapeHtml(value)}</code>`).join(" ")}</dd>
        <dt>VIN</dt><dd>${(socket.vins || []).map((value) => `<code>${escapeHtml(value)}</code>`).join(" ")}</dd>
        <dt>Routing</dt><dd>${socket.routingActivations?.length ? `<span class="socket-status-pill">Routing active</span> ${formatNumber(socket.routingActivations.length)} activation packet${socket.routingActivations.length === 1 ? "" : "s"}` : "No routing activation observed"}</dd>
        <dt>Routed</dt><dd>${formatNumber((socket.routed || []).length)}</dd>
        <dt>Rejected</dt><dd>${formatNumber((socket.rejected || []).length)}</dd>
      </dl>
      <div class="topology-evidence">${(socket.evidence || []).map((value) => `<span>${escapeHtml(value)}</span>`).join("")}</div>
    `;
  }

  function socketTableHtml(socketMap) {
    const sockets = socketMap?.sockets || [];
    const socketRows = sockets.map((socket) => `
      <tr>
        <td><button class="link-button topology-select" type="button" data-topology-id="${escapeHtml(socket.id)}">${escapeHtml(socket.ip || socket.label)}</button></td>
        <td><code>${escapeHtml(socket.directLogicalAddress || "")}</code></td>
        <td>${escapeHtml(socket.directName || "")}</td>
        <td>${(socket.routed || []).map((item) => `<code>${escapeHtml(item.logicalAddress)}</code>`).join(" ")}</td>
        <td>${(socket.rejected || []).map((item) => `<code>${escapeHtml(item.logicalAddress)}</code>`).join(" ")}${socket.autoIpAddresses?.length && socket.dhcpIpAddresses?.length ? `<div class="subtle">AutoIP ${socket.autoIpAddresses.map(escapeHtml).join(", ")} -> DHCP ${socket.dhcpIpAddresses.map(escapeHtml).join(", ")}</div>` : ""}</td>
      </tr>
    `).join("") || `<tr><td colspan="5">No DoIP socket evidence decoded.</td></tr>`;
    const mappingRows = sockets.flatMap((socket) => [
      ...(socket.routed || []).map((item) => ({ socket, item, status: "routed" })),
      ...(socket.rejected || []).map((item) => ({ socket, item, status: "rejected" }))
    ]).map(({ socket, item, status }) => `
      <tr>
        <td><button class="link-button topology-select" type="button" data-topology-id="${escapeHtml(item.id)}">${escapeHtml(item.name || item.logicalAddress)}</button></td>
        <td><code>${escapeHtml(item.logicalAddress)}</code></td>
        <td><code>${escapeHtml(socket.ip || "")}</code></td>
        <td>${escapeHtml(status)}</td>
        <td>${(item.packets || []).map((value) => `<code>${escapeHtml(value)}</code>`).join(" ")}</td>
      </tr>
    `).join("") || `<tr><td colspan="5">No routed logical-address mappings decoded.</td></tr>`;
    return { sockets: socketRows, mappings: mappingRows };
  }

  global.HarnessTopologyRenderer = Object.freeze({
    label,
    roleVisible,
    edgeVisible,
    filteredTopology,
    gatewayGroups,
    edgePath,
    edgeOffsets,
    edgeLabelPoint,
    detailHtml,
    tableHtml,
    socketMapHtml,
    socketNodeMapHtml,
    socketDetailHtml,
    socketTableHtml
  });
})(window);
