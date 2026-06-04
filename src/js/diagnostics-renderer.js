/**
 * Rendering helpers for ECU diagnostic subpanels.
 */
(function registerDiagnosticsRenderer(global) {
  "use strict";

  const formatters = global.HarnessFormatters || {};
  const escapeHtml = formatters.escapeHtml || ((value) => String(value ?? ""));
  const formatNumber = formatters.formatNumber || ((value) => String(value ?? ""));
  const formatDurationValue = formatters.formatDurationValue || ((value) => `${formatNumber(value)} s`);
  const hexByte = formatters.hexByte || ((value) => `0x${Number(value || 0).toString(16).padStart(2, "0")}`);
  const { badge, metricGrid, rawBytesCell } = global.HarnessUi;
  const serviceName = global.HarnessUds?.serviceName || (() => "Service");

  function routineControlLabel(subFunction) {
    const labels = {
      "0x01": "Start routine",
      "0x02": "Stop routine",
      "0x03": "Request routine results"
    };
    return labels[subFunction] || (subFunction ? `Control ${subFunction}` : "");
  }

  function routineOptionBytes(raw) {
    const bytes = String(raw || "").trim().split(/\s+/).filter(Boolean);
    return bytes.length > 4 ? bytes.slice(4).join(" ") : "";
  }

  function transferExpectationHtml(transfer) {
    if (transfer.expectedBlocks === undefined && transfer.acknowledgedBlocks === undefined) return "";
    return `<span class="transfer-inline-metrics">Expected ${transfer.expectedBlocks ?? "?"} / Data ${transfer.blocks ?? 0} / ACKed ${transfer.acknowledgedBlocks ?? 0}</span>`;
  }

  function transferStatusClass(transfer) {
    if (transfer.status === "completed") return "ok";
    if (transfer.status === "completed with errors" || transfer.negatives > 0) return "danger";
    if (transfer.status === "completed with gaps" || transfer.missingSequences?.length) return "warn";
    return "";
  }

  function renderEcuTransfers(transfers, options = {}) {
    const formatTimeDelta = options.formatTimeDelta || (() => "");
    const rows = (transfers || []).map((item) => `
    <tr>
      <td>${item.id}</td><td>${escapeHtml(item.direction)}</td><td><code>${escapeHtml(item.request.memoryAddress || "")}</code></td><td>${item.request.memorySize ?? ""}</td><td>${item.expectedBlocks ?? ""}</td><td>${formatNumber(item.blocks)}</td><td>${formatNumber(item.acknowledgedBlocks || 0)}</td><td>${formatNumber(item.reconstructedBytes)}</td>
      <td>${item.pending}</td><td>${item.negatives}</td><td>${transferExpectationHtml(item)}${escapeHtml(item.missingSequences.join(", "))}</td><td>${badge(item.status, transferStatusClass(item))}</td>
      <td><button type="button" class="open-download-session" data-transfer="${item.id}">Open</button></td>
    </tr>
  `).join("");
    return `<div class="table-wrap"><table><thead><tr><th>ID</th><th>Direction</th><th>Address</th><th>Size</th><th>Expected blocks</th><th>Data blocks</th><th>ACKed blocks</th><th>Payload bytes</th><th>Pending</th><th>NRC</th><th>Gaps</th><th>Status</th><th>Software Download</th></tr></thead><tbody>${rows || `<tr><td colspan="13">No transfers decoded for this ECU.</td></tr>`}</tbody></table></div>
    <p class="overview-note">Expected blocks use RequestDownload size and ECU max block length. ACKed blocks are positive <code>0x76</code> responses. If ACKed exceeds data blocks, payload evidence may be missing.</p>`;
  }

  function renderEcuRoutines(events, options = {}) {
    const routineName = options.routineName || (() => "");
    const formatTimeDelta = options.formatTimeDelta || (() => "");
    const ecuAddress = options.ecuAddress || "";
    const groups = new Map();
    for (const event of events.filter((item) => item.routineId)) {
      const key = event.routineId;
      if (!groups.has(key)) {
        groups.set(key, {
          routineId: key,
          name: routineName(key, ecuAddress),
          starts: 0,
          stops: 0,
          results: 0,
          positives: 0,
          negatives: 0,
          pending: 0,
          firstTimestamp: event.timestamp,
          lastTimestamp: event.timestamp,
          optionPreviews: new Set()
        });
      }
      const group = groups.get(key);
      group.firstTimestamp = Math.min(group.firstTimestamp, event.timestamp);
      group.lastTimestamp = Math.max(group.lastTimestamp, event.timestamp);
      if (event.subFunction === "0x01" && event.direction === "request") group.starts += 1;
      if (event.subFunction === "0x02" && event.direction === "request") group.stops += 1;
      if (event.subFunction === "0x03" && event.direction === "request") group.results += 1;
      if (event.responseKind === "positive") group.positives += 1;
      if (event.responseKind === "negative") group.negatives += 1;
      if (event.responseKind === "pending") group.pending += 1;
      const routineOptions = routineOptionBytes(event.raw);
      if (routineOptions) group.optionPreviews.add(routineOptions);
    }
    const summaryRows = Array.from(groups.values()).sort((a, b) => a.routineId.localeCompare(b.routineId)).map((item) => `
    <tr>
      <td><code>${escapeHtml(item.routineId)}</code></td>
      <td>${escapeHtml(item.name || "")}</td>
      <td>${formatNumber(item.starts)}</td>
      <td>${formatNumber(item.stops)}</td>
      <td>${formatNumber(item.results)}</td>
      <td>${formatNumber(item.positives)}</td>
      <td>${formatNumber(item.pending)}</td>
      <td>${formatNumber(item.negatives)}</td>
      <td><code>${escapeHtml(Array.from(item.optionPreviews).slice(0, 3).join(" | "))}</code></td>
      <td>${formatTimeDelta(item.firstTimestamp)}</td>
      <td>${formatTimeDelta(item.lastTimestamp)}</td>
    </tr>`).join("");
    const eventRows = events.map((event) => `
    <tr>
      <td>${event.id}</td>
      <td>${formatTimeDelta(event.timestamp)}</td>
      <td>${event.packet}</td>
      <td>${badge(event.responseKind, event.responseKind === "negative" ? "danger" : event.responseKind === "pending" ? "warn" : event.responseKind === "positive" ? "ok" : "")}</td>
      <td>${escapeHtml(event.service)} ${escapeHtml(event.serviceName)}</td>
      <td>${escapeHtml(routineControlLabel(event.subFunction))}</td>
      <td><code>${escapeHtml(event.routineId || "")}</code></td>
      <td>${escapeHtml(event.routineId ? routineName(event.routineId, ecuAddress) : "")}</td>
      <td><code>${escapeHtml(routineOptionBytes(event.raw))}</code></td>
      <td>${event.nrc ? badge(`${event.nrc} ${event.nrcName || ""}`, "warn") : ""}</td>
      ${rawBytesCell(event.raw)}
    </tr>`).join("");
    return `
    <div class="uds-routine-layout">
      <section class="overview-panel">
        <h4>Routine Summary</h4>
        <div class="table-wrap"><table><thead><tr><th>Routine ID</th><th>Name</th><th>Start</th><th>Stop</th><th>Results</th><th>Positive</th><th>Pending</th><th>NRC</th><th>Control options</th><th>First</th><th>Last</th></tr></thead><tbody>${summaryRows || `<tr><td colspan="11">No routine identifiers decoded for this ECU.</td></tr>`}</tbody></table></div>
      </section>
      <section class="overview-panel">
        <h4>Routine Evidence</h4>
        <div class="table-wrap"><table><thead><tr><th>ID</th><th>Time</th><th>Packet</th><th>Kind</th><th>Service</th><th>Control</th><th>Routine ID</th><th>Name</th><th>Control options</th><th>NRC</th><th>Raw UDS</th></tr></thead><tbody>${eventRows || `<tr><td colspan="11">No Routine Control traffic decoded for this ECU.</td></tr>`}</tbody></table></div>
      </section>
    </div>`;
  }

  function renderEcuRaw(events, options = {}) {
    const formatTimeDelta = options.formatTimeDelta || (() => "");
    const ecuLabel = options.ecuLabel || ((address) => address);
    const rows = events.slice(0, 500).map((event) => `
    <tr><td>${event.id}</td><td>${formatTimeDelta(event.timestamp)}</td><td>${escapeHtml(event.responseKind)}</td><td><code>${escapeHtml(ecuLabel(event.source))}</code></td><td><code>${escapeHtml(ecuLabel(event.target))}</code></td><td>${escapeHtml(event.serviceName)}</td>${rawBytesCell(event.raw)}</tr>
  `).join("");
    return `<div class="table-wrap"><table><thead><tr><th>ID</th><th>Time</th><th>Kind</th><th>Source</th><th>Target</th><th>Service</th><th>Raw UDS</th></tr></thead><tbody>${rows || `<tr><td colspan="7">No raw events.</td></tr>`}</tbody></table></div>`;
  }

  function renderEcuOverview(ecu, options = {}) {
    const events = options.events || [];
    const didRows = options.didReads || [];
    const transfers = options.transfers || [];
    const barsHtml = options.barsHtml || (() => "");
    const serviceStats = baseServiceDistribution(events, ecu.serviceStats);
    const didEvents = events.filter((event) => event.service === "0x22" || event.service === "0x62" || event.originalService === "0x22");
    const responseMix = {
      Requests: ecu.requests || 0,
      Positive: Math.max(0, (ecu.responses || 0) - (ecu.negatives || 0) - (ecu.pending || 0)),
      Pending: ecu.pending || 0,
      Negative: ecu.negatives || 0
    };
    const didActivity = {
      "DID read requests": didEvents.filter((event) => event.service === "0x22").length,
      "DID positive responses": didEvents.filter((event) => event.service === "0x62").length,
      "DID response pending (NRC 0x78)": didEvents.filter((event) => event.originalService === "0x22" && event.responseKind === "pending").length,
      "DID negative responses (0x7F)": didEvents.filter((event) => event.originalService === "0x22" && event.responseKind === "negative").length
    };
    const transferState = {
      "Transfer sessions": transfers.length,
      "TransferData blocks": transfers.reduce((sum, item) => sum + (item.blocks || 0), 0),
      "Completed sessions": transfers.filter((item) => item.status === "completed").length,
      "Exportable payloads": transfers.filter((item) => item.exportable).length,
      "Open sessions": transfers.filter((item) => item.status === "open").length,
      "Completed with gaps": transfers.filter((item) => item.status === "completed with gaps").length
    };
    const transferIssues = {
      "Transfer response pending (NRC 0x78)": transfers.reduce((sum, item) => sum + (item.pending || 0), 0),
      "Transfer negative responses (0x7F)": transfers.reduce((sum, item) => sum + (item.negatives || 0), 0),
      "Sequence gaps": transfers.reduce((sum, item) => sum + (item.missingSequences?.length || 0), 0)
    };
    return `
    ${metricGrid([
      ["Requests", ecu.requests],
      ["Responses", ecu.responses],
      ["Pending", ecu.pending],
      ["Negative", ecu.negatives],
      ["DIDs", didRows.length || ecu.didCount],
      ["Transfers", ecu.transferCount],
      ["Services", Object.keys(serviceStats || {}).length],
      ["Duration", formatDurationValue((ecu.lastTimestamp || 0) - (ecu.firstTimestamp || 0))]
    ])}
    <div class="overview-visual-grid">
      <section class="overview-panel"><h4>Service Distribution</h4>${barsHtml(serviceStats)}</section>
      <section class="overview-panel"><h4>Response Mix</h4>${barsHtml(responseMix)}</section>
      <section class="overview-panel"><h4>DID Activity</h4>${barsHtml(didActivity)}<p class="overview-note">Pending means NRC 0x78 for a DID read. Negative responses are <code>0x7F</code> replies to Service <code>0x22</code>.</p></section>
      <section class="overview-panel"><h4>Transfer State</h4>${barsHtml(transferState)}</section>
      <section class="overview-panel"><h4>Transfer Issues</h4>${barsHtml(transferIssues)}</section>
      <section class="overview-panel"><h4>Negative Response Codes</h4>${barsHtml(ecu.nrcStats)}</section>
    </div>
  `;
  }

  function renderEcuTimeline(events, options = {}) {
    const renderCompactTimeline = options.renderCompactTimeline || (() => "");
    return renderCompactTimeline((events || []).slice(0, 260));
  }

  function renderEcuDids(histories, options = {}) {
    const expandedDidGroups = options.expandedDidGroups || new Set();
    const ecuAddress = options.ecuAddress || "";
    const formatTimeDelta = options.formatTimeDelta || (() => "");
    const didPlotStatus = options.didPlotStatus || (() => ({ plottable: false, reason: "" }));
    const truncateMiddle = options.truncateMiddle || ((value) => value);
    const ecuLabel = options.ecuLabel || ((address) => address);
    const rows = (histories || []).flatMap((history) => {
      const key = `${ecuAddress}|${history.did}`;
      const collapsed = !expandedDidGroups.has(key);
      const plot = didPlotStatus(history);
      const plotAction = plot.plottable ? `<button type="button" data-did-plot="${escapeHtml(key)}" title="${escapeHtml(plot.reason)}">Plot value</button>` : "";
      const parent = `<tr class="did-group-row ${collapsed ? "collapsed" : ""}">
      <td><button type="button" class="table-collapse" data-did-toggle="${escapeHtml(key)}" aria-expanded="${collapsed ? "false" : "true"}">${collapsed ? "+" : "-"}</button><code>${escapeHtml(history.did)}</code></td>
      <td>${escapeHtml(history.name || "")}</td>
      <td>${formatNumber(history.reads)}</td>
      <td>${formatNumber(history.responses)}</td>
      <td>${formatNumber(history.negatives)}</td>
      <td><code>${escapeHtml(history.latestValueAscii || "")}</code></td>
      <td><code class="did-preview did-hex-preview" title="${escapeHtml(history.latestValueHex || "")}">${escapeHtml(truncateMiddle(history.latestValueHex || "", 96))}</code></td>
      <td>${formatTimeDelta(history.firstTimestamp)}</td>
      <td>${formatTimeDelta(history.lastTimestamp)}</td>
      <td>${plotAction}</td>
    </tr>`;
      if (collapsed) return [parent];
      const childRows = (history.events || []).filter((event) => event.service === "0x62" && event.responseKind === "positive").map((event) => `<tr class="did-history-row">
        <td></td>
        <td>${formatTimeDelta(event.timestamp)}</td>
        <td>${event.packet}</td>
        <td colspan="2"><code>${escapeHtml(ecuLabel(event.source))} -> ${escapeHtml(ecuLabel(event.target))}</code></td>
        <td colspan="2"><code class="did-preview" title="${escapeHtml(event.valueAscii || "")}">${escapeHtml(truncateMiddle(event.valueAscii || "", 80))}</code></td>
        <td colspan="2"><code class="did-preview" title="${escapeHtml(event.valueHex || "")}">${escapeHtml(truncateMiddle(event.valueHex || "", 96))}</code></td>
        <td><code class="did-preview" title="${escapeHtml(event.raw || "")}">${escapeHtml(truncateMiddle(event.raw || "", 96))}</code></td>
      </tr>`);
      return [parent, `<tr class="did-history-head"><td></td><td>Time</td><td>Packet</td><td colspan="2">Route</td><td colspan="2">ASCII</td><td colspan="2">Hex</td><td>Raw UDS</td></tr>`, ...childRows];
    }).join("");
    return `<div class="table-wrap"><table class="did-history-table"><thead><tr><th>DID</th><th>Name</th><th>Reads</th><th>Responses</th><th>NRC</th><th>Latest ASCII</th><th>Latest Hex</th><th>First</th><th>Last</th><th>Actions</th></tr></thead><tbody>${rows || `<tr><td colspan="10">No DID reads decoded for this ECU.</td></tr>`}</tbody></table></div>`;
  }

  function renderEcuDtcs(ecu, dtcReads = { rows: [], summary: [] }, options = {}) {
    const formatTimeDelta = options.formatTimeDelta || (() => "");
    const ecuLabel = options.ecuLabel || ((address) => address);
    const truncateMiddle = options.truncateMiddle || ((value) => value);
    const rows = (dtcReads.rows || []).filter((item) => item.ecuAddress === ecu.address);
    const summary = (dtcReads.summary || []).filter((item) => item.ecuAddress === ecu.address);
    const snapshotRows = rows.filter((item) => item.recordType === "snapshot");
    const extendedRows = rows.filter((item) => item.recordType === "extendedData");
    const metrics = {
      "DTC requests": rows.filter((item) => item.recordType === "request").length,
      "Positive responses": rows.filter((item) => item.responseKind === "positive").length,
      "DTC records": rows.filter((item) => item.recordType === "dtcRecord").length,
      "Snapshot records": snapshotRows.length,
      "Extended records": extendedRows.length,
      "Persistent after clear": summary.filter((item) => item.persistentAfterClear).length,
      "Pending": rows.filter((item) => item.responseKind === "pending").length,
      "Negative": rows.filter((item) => item.responseKind === "negative").length
    };
    const summaryRows = summary.map((item) => `<tr class="${item.persistentAfterClear ? "dtc-persistent-row" : ""}"><td><code>${escapeHtml(item.dtc)}</code></td><td><code>${escapeHtml(item.status || "")}</code></td><td>${escapeHtml(item.statusLabels || "")}</td><td>${dtcClearStateHtml(item, formatTimeDelta)}</td><td>${formatNumber(item.responses)}</td><td>${formatTimeDelta(item.firstTimestamp)}</td><td>${formatTimeDelta(item.lastTimestamp)}</td><td>${item.latestPacket}</td></tr>`).join("");
    const snapshotTable = snapshotRows.map((item) => `<tr><td><code>${escapeHtml(item.dtc || "")}</code></td><td><code>${escapeHtml(item.snapshotRecordNumber || "")}</code></td><td>${formatNumber(item.dataLength || 0)}</td><td><code>${escapeHtml(item.payloadAscii || "")}</code></td><td><code class="dtc-hex-preview" title="${escapeHtml(item.payloadHex || "")}">${escapeHtml(truncateMiddle(item.payloadHex || "", 96))}</code></td><td>${formatTimeDelta(item.timestamp)}</td><td>${item.packet}</td></tr>`).join("");
    const extendedTable = extendedRows.map((item) => `<tr><td><code>${escapeHtml(item.dtc || "")}</code></td><td><code>${escapeHtml(item.extendedDataRecordNumber || "")}</code></td><td>${formatNumber(item.dataLength || 0)}</td><td><code>${escapeHtml(item.payloadAscii || "")}</code></td><td><code class="dtc-hex-preview" title="${escapeHtml(item.payloadHex || "")}">${escapeHtml(truncateMiddle(item.payloadHex || "", 96))}</code></td><td>${formatTimeDelta(item.timestamp)}</td><td>${item.packet}</td></tr>`).join("");
    const evidenceRows = rows.map((item) => `<tr>
    <td>${formatTimeDelta(item.timestamp)}</td><td>${item.packet}</td><td><code>${escapeHtml(ecuLabel(item.source || ""))}</code> -> <code>${escapeHtml(ecuLabel(item.target || ""))}</code></td>
    <td>${escapeHtml(item.service)} ${escapeHtml(item.serviceName || "")}</td><td><code>${escapeHtml(item.subFunction || "")}</code> ${escapeHtml(item.subFunctionName || "")}</td>
    <td><code>${escapeHtml(item.optionsHex || "")}</code></td><td>${escapeHtml(item.resultType || item.recordType || "")}</td>
    <td>${item.nrc ? badge(`${item.nrc} ${item.nrcName || ""}`, "warn") : ""}</td>${rawBytesCell(item.raw || "")}
  </tr>`).join("");
    return `<div class="uds-dtc-layout">
    ${metricGrid(Object.entries(metrics))}
    <section class="overview-panel"><h4>DTC Summary</h4><div class="table-wrap"><table><thead><tr><th>DTC</th><th>Status</th><th>Status bits</th><th>Clear state</th><th>Responses</th><th>First</th><th>Last</th><th>Latest packet</th></tr></thead><tbody>${summaryRows || `<tr><td colspan="8">No DTC records decoded for this ECU.</td></tr>`}</tbody></table></div></section>
    <section class="overview-panel"><h4>Snapshot Records</h4><div class="table-wrap"><table><thead><tr><th>DTC</th><th>Record</th><th>Bytes</th><th>ASCII</th><th>Hex preview</th><th>Time</th><th>Packet</th></tr></thead><tbody>${snapshotTable || `<tr><td colspan="7">No DTC snapshot records decoded for this ECU.</td></tr>`}</tbody></table></div></section>
    <section class="overview-panel"><h4>Extended Data Records</h4><div class="table-wrap"><table><thead><tr><th>DTC</th><th>Record</th><th>Bytes</th><th>ASCII</th><th>Hex preview</th><th>Time</th><th>Packet</th></tr></thead><tbody>${extendedTable || `<tr><td colspan="7">No DTC extended data records decoded for this ECU.</td></tr>`}</tbody></table></div></section>
    <section class="overview-panel"><h4>Request/Response Evidence</h4><div class="table-wrap"><table><thead><tr><th>Time</th><th>Packet</th><th>Route</th><th>Service</th><th>Sub-function</th><th>Options</th><th>Result</th><th>NRC</th><th>Raw UDS</th></tr></thead><tbody>${evidenceRows || `<tr><td colspan="9">No DTC read traffic decoded for this ECU.</td></tr>`}</tbody></table></div></section>
  </div>`;
  }

  function dtcClearStateHtml(item, formatTimeDelta) {
    if (!item.clearGroup) return `<span class="subtle">No clear seen</span>`;
    const title = `Clear ${item.clearGroup} at packet ${item.clearPacket || "?"}${item.clearTimestamp !== null && item.clearTimestamp !== undefined ? ` (${formatTimeDelta(item.clearTimestamp)})` : ""}`;
    return item.persistentAfterClear
      ? badge("Persisted after clear", "danger", { title })
      : badge("After clear", "ok", { title });
  }

  function renderEcuServices(ecu, options = {}) {
    const formatTimeDelta = options.formatTimeDelta || (() => "");
    const rows = serviceBreakdown(options.events || [], ecu.serviceStats);
    const totals = {
      Services: rows.length,
      Requests: rows.reduce((sum, item) => sum + item.requests, 0),
      "Positive responses": rows.reduce((sum, item) => sum + item.positives, 0),
      "Response pendings": rows.reduce((sum, item) => sum + item.pending, 0),
      "Negative responses": rows.reduce((sum, item) => sum + item.negatives, 0)
    };
    const body = rows.map((item) => `<tr>
      <td><code>${escapeHtml(item.service)}</code></td>
      <td>${escapeHtml(item.name)}</td>
      <td>${formatNumber(item.total)}</td>
      <td>${formatNumber(item.requests)}</td>
      <td>${formatNumber(item.positives)}</td>
      <td>${formatNumber(item.pending)}</td>
      <td>${formatNumber(item.negatives)}</td>
      <td>${item.firstTimestamp !== null ? formatTimeDelta(item.firstTimestamp) : ""}</td>
      <td>${item.lastTimestamp !== null ? formatTimeDelta(item.lastTimestamp) : ""}</td>
      <td><code>${escapeHtml(item.packets.slice(0, 8).join(", "))}</code>${item.packets.length > 8 ? ` <span class="subtle">+${formatNumber(item.packets.length - 8)} more</span>` : ""}</td>
    </tr>`).join("");
    return `<div class="service-detail-panel">
      ${metricGrid(Object.entries(totals))}
      <div class="table-wrap"><table><thead><tr><th>Service</th><th>Name</th><th>Total</th><th>Requests</th><th>Positive</th><th>Pending</th><th>Negative</th><th>First</th><th>Last</th><th>Packets</th></tr></thead><tbody>${body || `<tr><td colspan="10">No services decoded for this ECU.</td></tr>`}</tbody></table></div>
    </div>`;
  }

  function renderEcuErrors(ecu, options = {}) {
    return (options.barsHtml || (() => ""))(ecu.nrcStats);
  }

  function baseServiceDistribution(events = [], fallbackStats = {}) {
    const stats = {};
    for (const event of events || []) {
      const key = baseServiceKey(event);
      if (!key) continue;
      stats[key] = (stats[key] || 0) + 1;
    }
    return Object.keys(stats).length ? stats : normalizeServiceStats(fallbackStats);
  }

  function serviceBreakdown(events = [], fallbackStats = {}) {
    const groups = new Map();
    const ensure = (key) => {
      const parsed = parseServiceKey(key);
      if (!groups.has(key)) {
        groups.set(key, {
          key,
          service: parsed.service,
          name: parsed.name,
          total: 0,
          requests: 0,
          positives: 0,
          pending: 0,
          negatives: 0,
          firstTimestamp: null,
          lastTimestamp: null,
          packets: []
        });
      }
      return groups.get(key);
    };
    for (const event of events || []) {
      const key = baseServiceKey(event);
      if (!key) continue;
      const group = ensure(key);
      group.total += 1;
      if (event.responseKind === "request" || event.direction === "request") group.requests += 1;
      else if (event.responseKind === "positive") group.positives += 1;
      else if (event.responseKind === "pending") group.pending += 1;
      else if (event.responseKind === "negative") group.negatives += 1;
      const timestamp = Number(event.timestamp);
      if (Number.isFinite(timestamp)) {
        group.firstTimestamp = group.firstTimestamp === null ? timestamp : Math.min(group.firstTimestamp, timestamp);
        group.lastTimestamp = group.lastTimestamp === null ? timestamp : Math.max(group.lastTimestamp, timestamp);
      }
      if (event.packet !== null && event.packet !== undefined && !group.packets.includes(event.packet)) group.packets.push(event.packet);
    }
    if (!groups.size) {
      for (const [key, count] of Object.entries(normalizeServiceStats(fallbackStats))) {
        const group = ensure(key);
        group.total = Number(count || 0);
      }
    }
    return Array.from(groups.values()).sort((a, b) => b.total - a.total || a.service.localeCompare(b.service) || a.name.localeCompare(b.name));
  }

  function parseServiceKey(key) {
    const text = String(key || "");
    const match = text.match(/^(0x[0-9a-f]{2})\s*(.*)$/i);
    return match ? { service: match[1], name: match[2] || "" } : { service: "", name: text };
  }

  function normalizeServiceStats(stats = {}) {
    const normalized = {};
    for (const [key, count] of Object.entries(stats || {})) {
      const rawKey = String(key);
      const match = rawKey.match(/0x([0-9a-f]{2})/i);
      const sid = match ? parseInt(match[1], 16) : NaN;
      const baseSid = Number.isFinite(sid) && sid !== 0x7f && sid >= 0x40 ? sid - 0x40 : sid;
      const fallbackName = rawKey.replace(/^0x[0-9a-f]{2}\s*/i, "").replace(/\s+response$/i, "").trim();
      const referenceName = Number.isFinite(baseSid) ? serviceName(baseSid) : "";
      const name = referenceName && referenceName !== "Service" ? referenceName : fallbackName;
      const baseKey = Number.isFinite(baseSid) && baseSid !== 0x7f ? `${hexByte(baseSid)} ${name}`.trim() : key;
      normalized[baseKey] = (normalized[baseKey] || 0) + Number(count || 0);
    }
    return normalized;
  }

  function baseServiceKey(event = {}) {
    const service = String(event.service || "");
    const serviceSid = service.startsWith("0x") ? parseInt(service.slice(2), 16) : NaN;
    const original = event.originalService || (Number.isFinite(serviceSid) && serviceSid !== 0x7f && serviceSid >= 0x40 ? hexByte(serviceSid - 0x40) : service);
    if (!original || original === "0x7f") return "";
    const originalSid = String(original).startsWith("0x") ? parseInt(String(original).slice(2), 16) : NaN;
    const referenceName = Number.isFinite(originalSid) ? serviceName(originalSid) : "";
    const eventBaseName = event.serviceName ? String(event.serviceName).replace(/\s+response$/i, "").trim() : "";
    const name = event.originalServiceName || (original === service && event.serviceName ? event.serviceName : referenceName && referenceName !== "Service" ? referenceName : eventBaseName);
    return `${original} ${name}`.trim();
  }

  global.HarnessDiagnosticsRenderer = Object.freeze({
    routineControlLabel,
    routineOptionBytes,
    transferExpectationHtml,
    transferStatusClass,
    baseServiceDistribution,
    serviceBreakdown,
    baseServiceKey,
    renderEcuOverview,
    renderEcuTimeline,
    renderEcuDids,
    renderEcuDtcs,
    renderEcuTransfers,
    renderEcuRoutines,
    renderEcuServices,
    renderEcuErrors,
    renderEcuRaw
  });
})(window);
