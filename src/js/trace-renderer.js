/**
 * Trace-view support helpers for layer metadata, filtering, DID samples, and compact labels.
 */
(function registerTraceRenderer(global) {
  "use strict";

  const formatters = global.HarnessFormatters || {};
  const escapeHtml = formatters.escapeHtml || ((value) => String(value ?? ""));
  const formatNumber = formatters.formatNumber || ((value) => String(value ?? ""));
  const formatMs = formatters.formatMs || ((value) => `${value} ms`);
  const hexByte = formatters.hexByte || ((value) => `0x${Number(value || 0).toString(16).padStart(2, "0")}`);
  const hexToBytes = formatters.hexToBytes || (() => new Uint8Array());
  const { badge } = global.HarnessUi;

  function traceTypeKey(event) {
    return `${event.category}:${event.type || event.label}`;
  }

  function traceCategoryLabel(category) {
    return { uds: "UDS", doip: "DoIP", dhcp: "DHCP", arp: "ARP", ack: "DoIP ACK/NAK", transport: "TCP" }[category] || category;
  }

  function traceCategoryRank(category) {
    return { doip: 0, dhcp: 1, arp: 2, ack: 3, uds: 4, transport: 5 }[category] ?? 9;
  }

  function removeArpOnlyTraceLanes(events) {
    const lanes = new Map();
    for (const event of events) {
      if (!lanes.has(event.laneKey)) lanes.set(event.laneKey, { categories: new Set(), events: [] });
      const lane = lanes.get(event.laneKey);
      lane.categories.add(event.category);
      lane.events.push(event);
    }
    const kept = [];
    let hiddenLanes = 0;
    let hiddenEvents = 0;
    for (const lane of lanes.values()) {
      if (lane.categories.size === 1 && lane.categories.has("arp")) {
        hiddenLanes += 1;
        hiddenEvents += lane.events.length;
        continue;
      }
      kept.push(...lane.events);
    }
    return { events: kept.sort((a, b) => (a.timestamp || 0) - (b.timestamp || 0)), hiddenLanes, hiddenEvents };
  }

  function layerCounts(events) {
    const counts = {};
    for (const event of events) counts[event.category] = (counts[event.category] || 0) + 1;
    return counts;
  }

  function advancedGroups(events, traceTypeState = {}) {
    const grouped = new Map();
    for (const event of events) {
      const key = traceTypeKey(event);
      if (!grouped.has(event.category)) grouped.set(event.category, new Map());
      if (!grouped.get(event.category).has(key)) {
        grouped.get(event.category).set(key, { key, label: event.label || event.type || key, count: 0 });
      }
      grouped.get(event.category).get(key).count += 1;
      traceTypeState[key] ??= true;
    }
    return grouped;
  }

  function traceLayerEnabled(event, traceLayerState = {}, traceTypeState = {}) {
    if (!traceLayerState[event.category]) return false;
    const key = traceTypeKey(event);
    return traceTypeState[key] !== false;
  }

  function renderLayerCounts(events) {
    const counts = layerCounts(events);
    const order = ["doip", "dhcp", "arp", "ack", "uds", "transport"];
    return order
      .filter((category) => counts[category])
      .map((category) => `<span class="trace-count ${escapeHtml(category)}">${escapeHtml(traceCategoryLabel(category))} <strong>${formatNumber(counts[category])}</strong></span>`)
      .join("");
  }

  function renderAdvancedPanel(events, traceTypeState = {}) {
    const grouped = advancedGroups(events, traceTypeState);
    return Array.from(grouped.entries()).map(([category, types]) => `
    <div class="trace-layer-group">
      <strong>${escapeHtml(traceCategoryLabel(category))}</strong>
      ${Array.from(types.values()).sort((a, b) => a.label.localeCompare(b.label)).map((item) => `
        <label><input class="trace-type-toggle" type="checkbox" data-trace-type="${escapeHtml(item.key)}" ${traceTypeState[item.key] !== false ? "checked" : ""}> ${escapeHtml(item.label)} <code>${formatNumber(item.count)}</code></label>
      `).join("")}
    </div>
  `).join("") || `<div class="empty">No trace layers available.</div>`;
  }

  function traceKindMatches(event, kindFilter) {
    if (kindFilter === "all") return true;
    if (event.category !== "uds") return true;
    if (kindFilter === "transfer") return Boolean(event.transfer);
    return event.responseKind === kindFilter || event.type === kindFilter;
  }

  function buildTraceLanes(events) {
    const laneMap = new Map();
    for (const event of events) {
      if (!laneMap.has(event.laneKey)) laneMap.set(event.laneKey, { label: event.laneLabel || event.laneKey, rank: traceCategoryRank(event.category), events: [] });
      const lane = laneMap.get(event.laneKey);
      lane.rank = Math.min(lane.rank, traceCategoryRank(event.category));
      lane.events.push(event);
    }
    return Array.from(laneMap.entries()).sort((a, b) => a[1].rank - b[1].rank || a[1].label.localeCompare(b[1].label));
  }

  function buildTraceViewport(events, options = {}) {
    const traceLayerState = options.traceLayerState || {};
    const traceTypeState = options.traceTypeState || {};
    const ecuFilter = options.ecuFilter || "all";
    const kindFilter = options.kindFilter || "all";
    const traceZoomRange = options.traceZoomRange || null;
    const traceCompareSelection = (options.traceCompareSelection || []).map(String);
    const traceLinkedEventIds = options.traceLinkedEventIds || { primary: null, pair: new Set(), pending: new Set() };
    const traceZoomHistory = options.traceZoomHistory || [];
    const formatTimeDelta = options.formatTimeDelta || (() => "");
    const formatBytes = options.formatBytes || ((value) => `${value ?? 0} B`);
    const ecuLabel = options.ecuLabel || ((address) => address);

    const filteredEvents = events
      .filter((event) => traceLayerEnabled(event, traceLayerState, traceTypeState))
      .filter((event) => ecuFilter === "all" || event.logicalAddress === ecuFilter || event.ecuAddress === ecuFilter)
      .filter((event) => traceKindMatches(event, kindFilter))
      .sort((a, b) => (a.timestamp || 0) - (b.timestamp || 0));
    const laneFiltered = removeArpOnlyTraceLanes(filteredEvents);
    const allEvents = laneFiltered.events;
    const fullStart = allEvents[0]?.timestamp || 0;
    const fullEnd = allEvents[allEvents.length - 1]?.timestamp || fullStart;
    const traceFullRange = allEvents.length ? { start: fullStart, end: fullEnd } : null;
    const activeRange = traceZoomRange && traceFullRange
      ? { start: Math.max(traceFullRange.start, traceZoomRange.start), end: Math.min(traceFullRange.end, traceZoomRange.end) }
      : traceFullRange ? { ...traceFullRange } : null;
    if (activeRange && activeRange.end < activeRange.start) activeRange.end = activeRange.start;
    const visibleEvents = activeRange
      ? allEvents.filter((event) => event.timestamp >= activeRange.start && event.timestamp <= activeRange.end)
      : [];
    const visibleIds = new Set(visibleEvents.map((event) => String(event.id)));
    const compareSelection = traceCompareSelection.filter((id) => visibleIds.has(String(id)));
    const lanes = buildTraceLanes(visibleEvents);
    const start = activeRange?.start || 0;
    const end = activeRange?.end || start;
    const duration = Math.max(end - start, 0.000001);
    const fullDuration = traceFullRange ? Math.max(traceFullRange.end - traceFullRange.start, 0.000001) : duration;
    const markerScale = Math.min(8, Math.sqrt(Math.max(1, fullDuration / duration)));
    const trackPadPercent = 1.2;
    const ticks = Array.from({ length: 6 }, (_, index) => start + (duration * index) / 5);

    const summaryText = `${formatNumber(visibleEvents.length)} visible of ${formatNumber(allEvents.length)} events across ${formatNumber(lanes.length)} lanes${laneFiltered.hiddenLanes ? `; ${formatNumber(laneFiltered.hiddenLanes)} ARP-only lanes hidden` : ""}.`;
    const windowText = activeRange ? `${formatTimeDelta(start)} to ${formatTimeDelta(end)}` : "Full range";
    let html = "";
    if (!allEvents.length) {
      html = `<div class="empty">No diagnostic events match this trace filter.</div>`;
    } else if (!visibleEvents.length) {
      html = `<div class="empty">No events in this zoom window. Use Reset zoom to return to the filtered range.</div>`;
    } else {
      html = `
    <div class="trace-scale">
      <div></div>
      <div class="trace-axis">${ticks.map((tick) => `<span>${formatTimeDelta(tick)}</span>`).join("")}</div>
    </div>
    <div class="trace-lanes">
      ${lanes.map(([, lane]) => {
        const laneEvents = lane.events;
        const logicalAddress = laneEvents.find((event) => event.logicalAddress)?.logicalAddress;
        return `
          <div class="trace-lane">
            <button class="trace-lane-label" type="button" ${logicalAddress ? `data-trace-ecu="${escapeHtml(logicalAddress)}"` : ""}>
              <code>${escapeHtml(lane.label)}</code>
              <span>${formatNumber(laneEvents.length)} events</span>
            </button>
            <div class="trace-track">
              ${ticks.map((_, index) => `<i style="left:${index * 20}%"></i>`).join("")}
              ${laneEvents.map((event) => {
                const baseWidth = event.transfer || event.category !== "uds" ? 0.72 : 0.24;
                const width = Math.min(4.2, baseWidth * markerScale);
                const rawLeft = ((event.timestamp - start) / duration) * (100 - trackPadPercent * 2 - width) + trackPadPercent;
                const left = Math.max(trackPadPercent, Math.min(100 - trackPadPercent - width, rawLeft));
                const label = `${event.laneLabel || ""} ${event.label || ""} ${formatTimeDelta(event.timestamp)}`;
                const kindClass = event.responseKind || event.category;
                const selected = compareSelection.includes(String(event.id));
                const linkedPrimary = String(traceLinkedEventIds.primary || "") === String(event.id);
                const linkedPair = traceLinkedEventIds.pair?.has(String(event.id));
                const linkedPending = traceLinkedEventIds.pending?.has(String(event.id));
                const linkedMuted = traceLinkedEventIds.primary && event.category === "uds" && !linkedPrimary && !linkedPair && !linkedPending;
                const linkClasses = [linkedPrimary ? "linked-primary" : "", linkedPair ? "linked-pair" : "", linkedPending ? "linked-pending" : "", linkedMuted ? "linked-muted" : ""].filter(Boolean).join(" ");
                return `<button class="trace-slice ${escapeHtml(event.category)} ${escapeHtml(kindClass)}${event.transfer ? " transfer" : ""}${selected ? " compared" : ""}${linkClasses ? ` ${linkClasses}` : ""}" type="button" aria-label="${escapeHtml(label)}" data-trace-event="${event.id}" style="left:${left}%;width:${width}%"></button>`;
              }).join("")}
            </div>
          </div>
        `;
      }).join("")}
    </div>
  `;
    }
    return {
      allEvents,
      visibleEvents,
      lanes,
      traceFullRange,
      activeRange,
      compareSelection,
      summaryText,
      windowText,
      layerCountsHtml: renderLayerCounts(allEvents),
      zoomResetDisabled: !traceZoomRange,
      zoomBackDisabled: !traceZoomHistory.length,
      dragStart: start,
      dragEnd: end,
      html
    };
  }

  function traceTransferSummary(transfer) {
    if (!transfer) return "";
    const parts = [transfer.type].filter(Boolean);
    if (transfer.blockCounter !== null && transfer.blockCounter !== undefined) parts.push(`block ${transfer.blockCounter}`);
    if (transfer.dataLength !== null && transfer.dataLength !== undefined) parts.push(`${formatNumber(transfer.dataLength)} B`);
    if (transfer.memoryAddress) parts.push(transfer.memoryAddress);
    if (transfer.memorySize !== null && transfer.memorySize !== undefined) parts.push(`${formatNumber(transfer.memorySize)} B`);
    return parts.join(" - ");
  }

  function traceLatencyLabel(startEvent, endEvent) {
    if (!startEvent || !endEvent) return "";
    return formatMs(Math.max(0, Number(endEvent.timestamp || 0) - Number(startEvent.timestamp || 0)));
  }

  function renderTraceTooltipContent(event, options = {}) {
    const formatTimeDelta = options.formatTimeDelta || (() => "");
    const relation = options.relation || null;
    const didValue = event.valueAscii || event.valueHex;
    const isUds = event.category === "uds";
    const relationDetails = [];
    if (relation?.udsEvent) {
      if (relation.request && String(relation.request.id) !== String(relation.udsEvent.id)) {
        relationDetails.push(["Request", `packet ${relation.request.packet} ${traceLatencyLabel(relation.request, relation.udsEvent)} before`]);
      }
      if (relation.finalResponse && relation.request && String(relation.finalResponse.id) !== String(relation.udsEvent.id)) {
        relationDetails.push(["Final response", `packet ${relation.finalResponse.packet}, +${traceLatencyLabel(relation.request, relation.finalResponse)}`]);
      }
      if (relation.pendingResponses.length) {
        relationDetails.push(["Pending", `${formatNumber(relation.pendingResponses.length)} response${relation.pendingResponses.length === 1 ? "" : "s"}${relation.request ? `, first +${traceLatencyLabel(relation.request, relation.pendingResponses[0])}` : ""}`]);
      }
      if (relation.udsEvent.direction === "request" && !relation.finalResponse && !relation.pendingResponses.length) {
        relationDetails.push(["Pairing", "No paired response observed"]);
      }
      if (relation.udsEvent.direction === "response" && !relation.request) {
        relationDetails.push(["Pairing", "Request not observed"]);
      }
    }
    const details = [
      ["Time", formatTimeDelta(event.timestamp)],
      event.logicalAddress ? ["Logical", event.logicalAddress] : null,
      event.laneLabel ? ["Lane", event.laneLabel] : null,
      event.source && event.target ? ["Route", `${event.source} -> ${event.target}`] : null,
      event.srcIp || event.dstIp ? ["IP", `${event.srcIp || ""}${event.srcPort ? `:${event.srcPort}` : ""} -> ${event.dstIp || ""}${event.dstPort ? `:${event.dstPort}` : ""}`] : null,
      ["Layer", traceCategoryLabel(event.category)],
      ["Type", event.label || event.type || ""],
      isUds && event.responseKind ? ["Kind", event.responseKind] : null,
      isUds && event.service ? ["Service", `${event.service} ${event.serviceName}`] : null,
      event.did ? ["DID", `${event.did}${event.didName ? ` ${event.didName}` : ""}`] : null,
      didValue ? ["Value", didValue] : null,
      event.nrc ? ["NRC", `${event.nrc} ${event.nrcName || ""}`] : null,
      event.transfer ? ["Transfer", traceTransferSummary(event.transfer)] : null,
      event.ackCode ? ["ACK", `${event.ackCode}${event.previousMessageHex ? ` prev ${event.previousMessageHex.slice(0, 48)}` : ""}`] : null,
      event.xid ? ["XID", event.xid] : null,
      event.clientMac ? ["Client", event.clientMac] : null,
      event.hostname ? ["Host", event.hostname] : null,
      event.requestedIp ? ["Requested", event.requestedIp] : null,
      event.yourIp ? ["Offered", event.yourIp] : null,
      event.serverId ? ["Server", event.serverId] : null,
      event.operation ? ["ARP", `${event.operation} ${event.srcMac || ""} ${event.srcIp || ""} -> ${event.targetMac || ""} ${event.targetIp || ""}`] : null,
      event.vin ? ["VIN", event.vin] : null,
      event.eid ? ["EID", event.eid] : null,
      ...relationDetails,
      event.packet ? ["Packet", event.packet] : null,
      event.raw ? ["Raw", event.raw.slice(0, 112)] : null
    ].filter((item) => item && item[1] !== "");
    return `
    <div class="trace-tooltip-title">
      <strong>${escapeHtml(event.label || event.serviceName || event.type || "Trace event")}</strong>
      ${badge(traceCategoryLabel(event.category), event.responseKind === "negative" ? "warn" : event.responseKind === "positive" ? "ok" : "")}
    </div>
    <div class="trace-tooltip-grid">
      ${details.map(([label, value]) => `
        <span>${escapeHtml(label)}</span>
        <code>${escapeHtml(value)}</code>
      `).join("")}
    </div>
  `;
  }

  function didPlotSamples(history) {
    return (history.events || [])
      .filter((event) => event.service === "0x62" && event.responseKind === "positive")
      .map((event) => {
        const bytes = hexToBytes(event.valueHex || "");
        return bytes.length === 1 ? {
          eventId: event.id,
          timestamp: event.timestamp,
          packet: event.packet,
          hex: hexByte(bytes[0]),
          value: bytes[0]
        } : null;
      });
  }

  function didPlotStatus(history) {
    const responses = (history.events || []).filter((event) => event.service === "0x62" && event.responseKind === "positive");
    const samples = didPlotSamples(history);
    if (responses.length < 2) return { plottable: false, reason: "Need at least two positive DID responses.", samples: [] };
    if (samples.some((sample) => !sample)) return { plottable: false, reason: "Only one-byte positive response values can be plotted in this version.", samples: [] };
    return { plottable: true, reason: "Plot unsigned one-byte values.", samples };
  }

  function truncateMiddle(value, maxLength) {
    const text = String(value || "");
    if (text.length <= maxLength) return text;
    const head = Math.ceil((maxLength - 5) / 2);
    const tail = Math.floor((maxLength - 5) / 2);
    return `${text.slice(0, head)} ... ${text.slice(text.length - tail)}`;
  }

  function renderCompactTimeline(events, options = {}) {
    const formatTimeDelta = options.formatTimeDelta || (() => "");
    const ecuLabel = options.ecuLabel || ((address) => address);
    if (!events.length) return `<div class="empty">No events for this ECU.</div>`;
    return `<div class="timeline">${events.map((event) => `
    <div class="timeline-item ${escapeHtml(event.responseKind)}">
      <div class="timeline-time">${formatTimeDelta(event.timestamp)}</div>
      <div class="timeline-route">${escapeHtml(ecuLabel(event.source))} -> ${escapeHtml(ecuLabel(event.target))}</div>
      <div class="timeline-body">
        <strong>${escapeHtml(event.service)} ${escapeHtml(event.serviceName)}</strong>
        ${event.did ? badge(`${event.did} ${event.didName || ""}`) : ""}
        ${event.nrc ? badge(`${event.nrc} ${event.nrcName}`, "warn") : ""}
        ${event.transfer ? badge(event.transfer.type || "Transfer", "ok") : ""}
        <code>${escapeHtml(event.raw)}</code>
      </div>
    </div>
  `).join("")}</div>`;
  }

  global.HarnessTraceRenderer = Object.freeze({
    traceTypeKey,
    traceCategoryLabel,
    traceCategoryRank,
    traceLayerEnabled,
    removeArpOnlyTraceLanes,
    layerCounts,
    renderLayerCounts,
    advancedGroups,
    renderAdvancedPanel,
    buildTraceViewport,
    traceTransferSummary,
    traceLatencyLabel,
    renderTraceTooltipContent,
    didPlotSamples,
    didPlotStatus,
    truncateMiddle,
    renderCompactTimeline
  });
})(window);
