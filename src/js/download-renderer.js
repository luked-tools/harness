/**
 * Rendering helpers for software-download views.
 */
(function registerDownloadRenderer(global) {
  "use strict";

  const formatters = global.HarnessFormatters || {};
  const escapeHtml = formatters.escapeHtml || ((value) => String(value ?? ""));
  const formatNumber = formatters.formatNumber || ((value) => String(value ?? ""));
  const formatBytes = formatters.formatBytes || ((value) => `${value ?? 0} B`);
  const formatRate = formatters.formatRate || (() => "n/a");
  const formatDurationValue = formatters.formatDurationValue || (() => "n/a");
  const { badge, metricGrid, metrics: metricsHtml, rawBytesCell } = global.HarnessUi;

  /**
   * Convert a download severity value into the badge class used by the UI.
   */
  function downloadSeverityClass(severity) {
    return severity === "error" ? "danger" : severity === "warning" ? "warn" : severity === "ok" ? "ok" : "";
  }

  function formatTimelineDuration(seconds) {
    const value = Math.max(0, Number(seconds) || 0);
    if (value < 1) return `${(value * 1000).toFixed(0)} ms`;
    if (value < 10) return `${value.toFixed(2)} s`;
    if (value < 60) return `${value.toFixed(1)} s`;
    const minutes = Math.floor(value / 60);
    const rest = Math.round(value % 60);
    return `${minutes}m ${rest}s`;
  }

  function timelineSessionBounds(session = {}, domain = {}) {
    const domainStart = Number.isFinite(Number(domain.start)) ? Number(domain.start) : 0;
    const domainEnd = Number.isFinite(Number(domain.end)) ? Number(domain.end) : domainStart;
    const domainDuration = Math.max(0.000001, domainEnd - domainStart);
    const rawStart = Number.isFinite(Number(session.startTimestamp)) ? Number(session.startTimestamp) : domainStart;
    const rawEnd = Number.isFinite(Number(session.endTimestamp)) ? Number(session.endTimestamp) : rawStart;
    const orderedStart = Math.min(rawStart, rawEnd);
    const orderedEnd = Math.max(rawStart, rawEnd);
    const start = Math.min(Math.max(orderedStart, domainStart), domainEnd);
    const end = Math.min(Math.max(orderedEnd, domainStart), domainEnd);
    const leftPercent = ((start - domainStart) / domainDuration) * 100;
    const rightPercent = ((end - domainStart) / domainDuration) * 100;
    const widthPercent = Math.max(0, rightPercent - leftPercent);
    return {
      rawStart,
      rawEnd,
      start,
      end,
      leftPercent: Math.min(100, Math.max(0, leftPercent)),
      widthPercent: Math.min(100, Math.max(0, widthPercent)),
      durationSeconds: Math.max(0, orderedEnd - orderedStart),
      clipped: orderedStart < domainStart || orderedEnd > domainEnd
    };
  }

  /**
   * Place overlapping transfer sessions into visual rows for the campaign timeline.
   */
  function layoutCampaignSessions(sessions) {
    const rows = [];
    const items = [];
    const domain = campaignTimelineDomain(sessions);
    for (const session of [...sessions].sort((a, b) => (a.startTimestamp || 0) - (b.startTimestamp || 0) || (a.endTimestamp || 0) - (b.endTimestamp || 0))) {
      const bounds = timelineSessionBounds(session, domain);
      const start = bounds.start;
      const end = bounds.end;
      let row = rows.findIndex((rowEnd) => start >= rowEnd);
      if (row === -1) {
        row = rows.length;
        rows.push(end);
      } else {
        rows[row] = end;
      }
      items.push({ session, row });
    }
    return { items, rows: Math.max(1, rows.length) };
  }

  function campaignTimelineDomain(sessions = []) {
    const starts = sessions.map((item) => Number(item.startTimestamp)).filter(Number.isFinite);
    const ends = sessions.map((item) => Number(item.endTimestamp ?? item.startTimestamp)).filter(Number.isFinite);
    const start = starts.length ? Math.min(...starts) : 0;
    const end = ends.length ? Math.max(...ends) : start;
    return { start, end, duration: Math.max(0.000001, end - start) };
  }

  function niceAxisMax(value) {
    const raw = Math.max(1, Number(value) || 1);
    const exponent = Math.floor(Math.log10(raw));
    const base = 10 ** exponent;
    const scaled = raw / base;
    const nice = scaled <= 1 ? 1 : scaled <= 2 ? 2 : scaled <= 5 ? 5 : 10;
    return nice * base;
  }

  function compactRateBuckets(buckets, targetCount) {
    if (buckets.length <= targetCount) return buckets;
    const groupSize = Math.ceil(buckets.length / targetCount);
    const grouped = [];
    for (let index = 0; index < buckets.length; index += groupSize) {
      const group = buckets.slice(index, index + groupSize);
      const seconds = group.reduce((sum, bucket) => sum + (bucket.seconds || 0), 0);
      const bytes = group.reduce((sum, bucket) => sum + (bucket.bytes || 0), 0);
      grouped.push({
        index: grouped.length,
        start: group[0].start,
        end: group[group.length - 1].end,
        seconds,
        bytes,
        rateBps: seconds > 0 ? bytes / seconds : null
      });
    }
    return grouped;
  }

  function didValueDomain(minValue, maxValue) {
    if (minValue === maxValue) {
      const pad = minValue === 0 || minValue === 255 ? 5 : Math.max(2, Math.ceil(Math.abs(minValue) * 0.08));
      return { min: Math.max(0, minValue - pad), max: Math.min(255, maxValue + pad) };
    }
    const range = maxValue - minValue;
    const padding = Math.max(1, Math.ceil(range * 0.12));
    return {
      min: Math.max(0, minValue - padding),
      max: Math.min(255, maxValue + padding)
    };
  }

  function numericTicks(minValue, maxValue, count) {
    const span = Math.max(1, maxValue - minValue);
    const rawStep = span / Math.max(1, count - 1);
    const exponent = Math.floor(Math.log10(rawStep));
    const base = 10 ** exponent;
    const scaled = rawStep / base;
    const step = (scaled <= 1 ? 1 : scaled <= 2 ? 2 : scaled <= 5 ? 5 : 10) * base;
    const start = Math.ceil(minValue / step) * step;
    const ticks = [];
    for (let value = start; value <= maxValue + step * 0.25; value += step) {
      const rounded = Math.round(value * 1000) / 1000;
      if (rounded >= minValue - 0.001 && rounded <= maxValue + 0.001) ticks.push(rounded);
    }
    if (!ticks.includes(minValue)) ticks.unshift(minValue);
    if (!ticks.includes(maxValue)) ticks.push(maxValue);
    return Array.from(new Set(ticks)).sort((a, b) => a - b).slice(0, 7);
  }

  function timeSampleTicks(samples, maxTicks) {
    const count = Math.min(maxTicks, samples.length);
    if (count <= 1) return [samples[0]];
    const indexes = new Set();
    for (let i = 0; i < count; i += 1) indexes.add(Math.round((i * (samples.length - 1)) / (count - 1)));
    return Array.from(indexes).sort((a, b) => a - b).map((index) => samples[index]);
  }

  function didAxisTickCount(width, labels) {
    const longest = Math.max(1, ...labels.map((label) => String(label || "").length));
    const estimatedLabelWidth = Math.min(110, Math.max(54, longest * 6.2));
    return Math.max(2, Math.min(6, Math.floor((width - 100) / estimatedLabelWidth)));
  }

  function compactTimeAxisLabel(label) {
    const text = String(label || "");
    const match = text.match(/^([+-]?)(\d+)(?:\.(\d+))?s$/);
    if (!match) return text.length > 10 ? `${text.slice(0, 9)}...` : text;
    const sign = match[1] || "";
    const seconds = Number(match[2]);
    const fraction = match[3] || "";
    if (seconds >= 60) {
      const minutes = Math.floor(seconds / 60);
      const remainder = seconds % 60;
      return `${sign}${minutes}m${String(remainder).padStart(2, "0")}s`;
    }
    if (seconds >= 10) return `${sign}${seconds}s`;
    return `${sign}${seconds}${fraction ? `.${fraction.slice(0, 1)}` : ""}s`;
  }

  function renderDidLineChart(samples, options = {}) {
    const formatTimeDelta = options.formatTimeDelta || (() => "");
    const width = Math.min(1400, Math.max(760, 120 + samples.length * 42));
    const height = 330;
    const pad = { left: 64, right: 22, top: 24, bottom: 48 };
    const first = samples[0].timestamp;
    const last = samples[samples.length - 1].timestamp;
    const duration = Math.max(0.000001, last - first);
    const values = samples.map((sample) => sample.value);
    const yDomain = didValueDomain(Math.min(...values), Math.max(...values));
    const x = (timestamp) => pad.left + ((timestamp - first) / duration) * (width - pad.left - pad.right);
    const y = (value) => pad.top + (1 - (value - yDomain.min) / Math.max(1, yDomain.max - yDomain.min)) * (height - pad.top - pad.bottom);
    const points = samples.map((sample) => `${x(sample.timestamp).toFixed(2)},${y(sample.value).toFixed(2)}`).join(" ");
    const yTicks = numericTicks(yDomain.min, yDomain.max, 5);
    const previewTicks = timeSampleTicks(samples, 6);
    const xTicks = timeSampleTicks(samples, didAxisTickCount(width, previewTicks.map((sample) => compactTimeAxisLabel(formatTimeDelta(sample.timestamp)))));
    return `<svg class="did-line-chart" viewBox="0 0 ${width} ${height}" role="img" aria-label="DID unsigned byte value over time">
    <line class="axis" x1="${pad.left}" y1="${pad.top}" x2="${pad.left}" y2="${height - pad.bottom}"></line>
    <line class="axis" x1="${pad.left}" y1="${height - pad.bottom}" x2="${width - pad.right}" y2="${height - pad.bottom}"></line>
    ${yTicks.map((tick) => `<g><line class="grid" x1="${pad.left}" y1="${y(tick).toFixed(2)}" x2="${width - pad.right}" y2="${y(tick).toFixed(2)}"></line><text x="12" y="${(y(tick) + 4).toFixed(2)}">${formatNumber(tick)}</text></g>`).join("")}
    ${xTicks.map((sample, index) => {
      const fullLabel = formatTimeDelta(sample.timestamp);
      return `<text x="${x(sample.timestamp).toFixed(2)}" y="${height - 12}" text-anchor="${index === 0 ? "start" : index === xTicks.length - 1 ? "end" : "middle"}"><title>${escapeHtml(fullLabel)}</title>${escapeHtml(compactTimeAxisLabel(fullLabel))}</text>`;
    }).join("")}
    <polyline class="did-line" points="${points}"></polyline>
    ${samples.map((sample) => `<circle class="did-point" tabindex="0" cx="${x(sample.timestamp).toFixed(2)}" cy="${y(sample.value).toFixed(2)}" r="4"
      data-time="${escapeHtml(formatTimeDelta(sample.timestamp))}" data-packet="${sample.packet}" data-hex="${escapeHtml(sample.hex)}" data-value="${sample.value}"></circle>`).join("")}
  </svg>`;
  }

  function renderDidPlotModal(history, samples, options = {}) {
    const formatTimeDelta = options.formatTimeDelta || (() => "");
    const values = samples.map((sample) => sample.value);
    const min = Math.min(...values);
    const max = Math.max(...values);
    const latest = samples[samples.length - 1];
    return `
    ${metricGrid([
      ["Samples", samples.length],
      ["Minimum", min],
      ["Maximum", max],
      ["Latest", latest.value],
      ["First seen", formatTimeDelta(samples[0].timestamp)],
      ["Last seen", formatTimeDelta(latest.timestamp)]
    ])}
    <div class="did-chart-wrap">
      ${renderDidLineChart(samples, { formatTimeDelta })}
      <div class="did-chart-tooltip" hidden></div>
    </div>
    <div class="table-wrap"><table><thead><tr><th>Time</th><th>Packet</th><th>Hex</th><th>Value</th></tr></thead><tbody>
      ${samples.map((sample) => `<tr><td>${formatTimeDelta(sample.timestamp)}</td><td>${sample.packet}</td><td><code>${escapeHtml(sample.hex)}</code></td><td>${formatNumber(sample.value)}</td></tr>`).join("")}
    </tbody></table></div>
  `;
  }

  function renderDirectionDiagram(session, options = {}) {
    const ecuCode = options.ecuCode || ((address) => escapeHtml(address));
    const download = session.sessionType !== "upload";
    const directionClass = download ? "download" : "upload";
    const label = session.sessionType === "upload" ? "ECU payload via 0x76" : "Tester payload via 0x36";
    const arrowPath = download
      ? `<circle class="direction-svg-dot" cx="12" cy="22" r="4"></circle><path class="direction-svg-line" d="M16 22 H184"></path><path class="direction-svg-head" d="M176 14 L188 22 L176 30"></path>`
      : `<circle class="direction-svg-dot" cx="188" cy="22" r="4"></circle><path class="direction-svg-line" d="M184 22 H16"></path><path class="direction-svg-head" d="M24 14 L12 22 L24 30"></path>`;
    return `<div class="direction-diagram">
    <div class="direction-node"><strong>Tester</strong><br><code>${escapeHtml(session.testerAddress)}</code></div>
    <div class="direction-arrow ${directionClass}" aria-label="${escapeHtml(label)}">
      <svg viewBox="0 0 200 44" role="img" aria-label="${escapeHtml(label)}">${arrowPath}</svg>
      <small>${escapeHtml(label)}</small>
    </div>
    <div class="direction-node"><strong>ECU</strong><br>${ecuCode(session.ecuAddress)}</div>
  </div>`;
  }

  function renderPayloadProgress(session) {
    const pct = session.progress === null ? null : Math.round(session.progress * 100);
    const progressBytes = session.progressPayloadBytes ?? session.reconstructedBytes ?? 0;
    const observedBytes = session.observedPayloadBytes ?? session.reconstructedBytes ?? 0;
    const observedNote = session.requestedBytes && observedBytes > progressBytes
      ? `<p class="subtle">${formatBytes(observedBytes)} observed in the capture including retries or repeated transfer blocks.</p>`
      : "";
    return `<div class="progress-panel">
    <h4>Payload Progress</h4>
    <div class="payload-progress"><span style="width:${pct ?? 0}%"></span></div>
    <p class="subtle">${formatNumber(progressBytes)}${session.requestedBytes ? ` of ${formatNumber(session.requestedBytes)}` : ""} bytes${pct !== null ? ` (${pct}%)` : ""}</p>
    ${observedNote}
    <p>${badge(session.hexExportable ? "Hex exportable" : "Not exportable", session.hexExportable ? "ok" : "warn")}</p>
  </div>`;
  }

  function renderBlockStrip(session) {
    const slots = blockStripSlots(session);
    return `<div class="block-strip-panel">
    <h4>Block Completeness</h4>
    <div class="block-strip">${slots.map((slot) => `<span class="block-slot ${slot.classes}" title="${escapeHtml(blockSlotTitle(slot))}">${slot.repeatCount ? `<span>${formatNumber(slot.repeatCount + 1)}</span>` : ""}</span>`).join("")}</div>
  </div>`;
  }

  function blockStripSlots(session) {
    const blockCounts = new Map();
    const blocks = [...(session.dataBlocks || [])].sort((a, b) => (a.timestamp || 0) - (b.timestamp || 0) || (a.packet || 0) - (b.packet || 0));
    for (const block of blocks) {
      const counterValue = parseCounter(block.counter);
      if (counterValue === null) continue;
      blockCounts.set(counterValue, (blockCounts.get(counterValue) || 0) + 1);
    }
    const firstCounter = blocks.map((block) => parseCounter(block.counter)).find((counter) => counter !== null);
    const startCounter = firstCounter === undefined ? 1 : firstCounter;
    const expectedSlots = Math.min(Math.max(session.expectedBlocks || session.blocks || blocks.length || 0, 0), 256);
    const duplicateCounters = new Set((session.duplicateCounters || []).map(parseCounter).filter((counter) => counter !== null));
    return Array.from({ length: 256 }, (_, index) => {
      const counterValue = (startCounter + index) & 0xff;
      const counter = `0x${counterValue.toString(16).padStart(2, "0")}`;
      const observations = blockCounts.get(counterValue) || 0;
      const observed = observations > 0;
      const required = index < expectedSlots;
      const repeatCount = Math.max(0, observations - 1);
      const duplicate = duplicateCounters.has(counterValue);
      const repeated = repeatCount > 0;
      const state = observed ? duplicate ? "duplicate" : repeated ? "repeated" : "observed" : required ? "missing" : "not-required";
      const classes = [observed ? "observed" : required ? "missing" : "unused", duplicate ? "duplicate" : repeated ? "repeat" : ""].filter(Boolean).join(" ");
      return { ordinal: index + 1, counter, state, classes, repeatCount, observations, required };
    });
  }

  function blockSlotTitle(slot) {
    const repeatText = slot.repeatCount ? `, ${slot.repeatCount} repeated observation${slot.repeatCount === 1 ? "" : "s"}` : "";
    return `Block ${slot.counter}: ${slot.state}${repeatText}`;
  }

  function parseCounter(counter) {
    const text = String(counter || "");
    const match = text.match(/^0x([0-9a-f]{1,2})$/i);
    if (!match) return null;
    return parseInt(match[1], 16);
  }

  function renderSequenceHealth(session) {
    const rows = [
      ["Expected blocks", session.expectedBlocks ?? "Unknown"],
      ["Observed data blocks", session.blocks || 0],
      ["Assigned 0x76 responses", session.acknowledgedBlocks || 0],
      ["Observed 0x76 responses", (session.ackObservedEvents || []).length],
      ["Response pending", session.pending || 0],
      ["Negative responses", session.negatives || 0]
    ];
    return `<div class="sequence-health-grid">${rows.map(([label, value]) => `
    <div class="sequence-health-item"><span>${escapeHtml(label)}</span><strong>${typeof value === "number" ? formatNumber(value) : escapeHtml(value)}</strong></div>
  `).join("")}</div>`;
  }

  function buildRateTimingRows(session) {
    const ackByRequest = new Map((session.ackBlocks || []).filter((ack) => ack.requestEventId).map((ack) => [ack.requestEventId, ack]));
    const observedByCounter = new Map();
    for (const ack of session.ackObservedEvents || []) {
      if (!observedByCounter.has(ack.counter)) observedByCounter.set(ack.counter, []);
      observedByCounter.get(ack.counter).push(ack);
    }
    const blocks = [...(session.dataBlocks || [])].sort((a, b) => (a.timestamp || 0) - (b.timestamp || 0) || (a.packet || 0) - (b.packet || 0));
    return blocks.map((block, index) => {
      const previous = index ? blocks[index - 1] : null;
      const delta = previous && Number.isFinite(Number(block.timestamp)) && Number.isFinite(Number(previous.timestamp)) ? block.timestamp - previous.timestamp : null;
      const ack = ackByRequest.get(block.eventId) || null;
      const observed = ack || (observedByCounter.get(block.counter) || []).shift() || null;
      const ackLatency = ack && Number.isFinite(Number(ack.timestamp)) ? ack.timestamp - block.timestamp : null;
      return {
        counter: block.counter,
        dataPacket: block.packet,
        ackPacket: ack?.packet || observed?.packet || "",
        payloadBytes: block.payloadBytes || 0,
        delta,
        ackLatency,
        instantaneousRateBps: delta && delta > 0 ? (block.payloadBytes || 0) / delta : null,
        ackStatus: ack ? "paired" : observed ? "observed" : "not observed",
        ackClass: ack ? "ok" : observed ? "info" : "warn"
      };
    });
  }

  function renderRateChart(buckets, session, options = {}) {
    const formatTimeDelta = options.formatTimeDelta || (() => "");
    if (!buckets.length || (session.dataBlocks || []).length < 2) return `<div class="empty">Not enough timed payload blocks for a throughput chart.</div>`;
    const compact = compactRateBuckets(buckets, 20);
    const rates = compact.map((bucket) => bucket.rateBps || 0);
    const minRate = Math.min(...rates, 0);
    const maxRate = niceAxisMax(Math.max(...rates, 1));
    const chartWidth = 720;
    const chartHeight = 150;
    const pad = { top: 16, right: 18, bottom: 30, left: 72 };
    const plotWidth = chartWidth - pad.left - pad.right;
    const plotHeight = chartHeight - pad.top - pad.bottom;
    const yRange = Math.max(1, maxRate - minRate);
    const points = compact.map((bucket, index) => {
      const denom = Math.max(1, compact.length - 1);
      const x = pad.left + (index / denom) * plotWidth;
      const y = pad.top + plotHeight - (((bucket.rateBps || 0) - minRate) / yRange) * plotHeight;
      return { x, y, bucket };
    });
    const linePath = points.map((point, index) => `${index ? "L" : "M"}${point.x.toFixed(1)} ${point.y.toFixed(1)}`).join(" ");
    const areaPath = `${linePath} L${points[points.length - 1].x.toFixed(1)} ${pad.top + plotHeight} L${points[0].x.toFixed(1)} ${pad.top + plotHeight} Z`;
    const ticks = [0, 0.25, 0.5, 0.75, 1];
    const grid = ticks.map((tick) => {
      const y = pad.top + plotHeight - tick * plotHeight;
      const value = minRate + tick * yRange;
      return `<g><line x1="${pad.left}" y1="${y.toFixed(1)}" x2="${pad.left + plotWidth}" y2="${y.toFixed(1)}" class="rate-grid-line"></line><text x="${pad.left - 8}" y="${(y + 3).toFixed(1)}" class="rate-axis-label y">${escapeHtml(formatRate(value))}</text></g>`;
    }).join("");
    return `<section class="rate-chart-panel">
    <div class="rate-chart-head"><h4>Throughput Over Time</h4><span>${formatRate(minRate)} to ${formatRate(maxRate)}</span></div>
    <div class="rate-chart-wrap">
    <svg class="rate-line-chart" viewBox="0 0 ${chartWidth} ${chartHeight}" role="img" aria-label="Throughput over time line chart">
      ${grid}
      <line x1="${pad.left}" y1="${pad.top}" x2="${pad.left}" y2="${pad.top + plotHeight}" class="rate-axis-line"></line>
      <line x1="${pad.left}" y1="${pad.top + plotHeight}" x2="${pad.left + plotWidth}" y2="${pad.top + plotHeight}" class="rate-axis-line"></line>
      <path class="rate-area" d="${areaPath}"></path>
      <path class="rate-line" d="${linePath}"></path>
      ${points.map((point) => `<circle class="rate-point" cx="${point.x.toFixed(1)}" cy="${point.y.toFixed(1)}" r="4" data-rate="${escapeHtml(formatRate(point.bucket.rateBps))}" data-window="${escapeHtml(`${formatTimeDelta(point.bucket.start)} to ${formatTimeDelta(point.bucket.end)}`)}" data-bytes="${escapeHtml(`${formatBytes(point.bucket.bytes || 0)} in ${formatDurationValue(point.bucket.seconds)}`)}"></circle>`).join("")}
      <text x="${pad.left}" y="${chartHeight - 5}" class="rate-axis-label">${escapeHtml(formatTimeDelta(compact[0].start))}</text>
      <text x="${chartWidth - pad.right}" y="${chartHeight - 5}" class="rate-axis-label end">${escapeHtml(formatTimeDelta(compact[compact.length - 1].end))}</text>
    </svg>
    <div class="rate-tooltip" hidden></div>
    </div>
  </section>`;
  }

  function renderDownloadRate(session, options = {}) {
    const formatTimeDelta = options.formatTimeDelta || (() => "");
    const rate = session.rate || {};
    const intervals = rate.blockIntervals || [];
    const ackLatencies = rate.ackLatencies || [];
    const rows = buildRateTimingRows(session);
    return `
    <p class="overview-note">Capture-observed application throughput from UDS TransferData evidence. This is not ECU-internal programming speed.</p>
    <div class="sequence-health-grid">
      <div class="sequence-health-item"><span>Payload bytes</span><strong>${formatBytes(session.reconstructedBytes || 0)}</strong></div>
      <div class="sequence-health-item"><span>Active duration</span><strong>${formatDurationValue(rate.activePayloadDuration)}</strong></div>
      <div class="sequence-health-item"><span>Session duration</span><strong>${formatDurationValue(rate.sessionDuration)}</strong></div>
      <div class="sequence-health-item"><span>Average payload rate</span><strong>${formatRate(rate.averagePayloadRateBps)}</strong></div>
      <div class="sequence-health-item"><span>Average session rate</span><strong>${formatRate(rate.averageSessionRateBps)}</strong></div>
      <div class="sequence-health-item"><span>Median block interval</span><strong>${formatDurationValue(rate.medianBlockInterval)}</strong></div>
      <div class="sequence-health-item"><span>P95 block interval</span><strong>${formatDurationValue(rate.p95BlockInterval)}</strong></div>
      <div class="sequence-health-item"><span>Median ACK latency</span><strong>${formatDurationValue(rate.medianAckLatency)}</strong></div>
      <div class="sequence-health-item"><span>P95 ACK latency</span><strong>${formatDurationValue(rate.p95AckLatency)}</strong></div>
    </div>
    <div class="rate-actions"><button id="openRateCampaignModal" type="button">Campaign comparison</button></div>
    ${renderRateChart(rate.rateBuckets || [], session, { formatTimeDelta })}
    ${intervals.length || ackLatencies.length ? "" : `<div class="empty">This session has fewer than two timed payload blocks or no paired ACK latency evidence.</div>`}
    <div class="table-wrap"><table><thead><tr><th>#</th><th>Counter</th><th>Data packet</th><th>ACK packet</th><th>Bytes</th><th>Block delta</th><th>ACK latency</th><th>Instant rate</th><th>ACK status</th></tr></thead><tbody>
      ${rows.map((row, index) => `<tr><td>${index + 1}</td><td>${escapeHtml(row.counter || "")}</td><td>${row.dataPacket || ""}</td><td>${row.ackPacket || ""}</td><td>${formatNumber(row.payloadBytes || 0)}</td><td>${formatDurationValue(row.delta)}</td><td>${formatDurationValue(row.ackLatency)}</td><td>${formatRate(row.instantaneousRateBps)}</td><td>${badge(row.ackStatus, row.ackClass)}</td></tr>`).join("") || `<tr><td colspan="9">No block timing rows available.</td></tr>`}
    </tbody></table></div>
  `;
  }

  function renderDownloadBlocks(session) {
    const ackQueues = new Map();
    const ackByRequest = new Map();
    const observedQueues = new Map();
    for (const ack of session.ackBlocks || []) {
      if (ack.requestEventId) ackByRequest.set(ack.requestEventId, ack);
      if (!ackQueues.has(ack.counter)) ackQueues.set(ack.counter, []);
      ackQueues.get(ack.counter).push(ack);
    }
    for (const ack of session.ackObservedEvents || []) {
      if (!observedQueues.has(ack.counter)) observedQueues.set(ack.counter, []);
      observedQueues.get(ack.counter).push(ack);
    }
    const rows = (session.dataBlocks || []).map((block, index) => {
      const pairedAck = ackByRequest.get(block.eventId);
      const ack = pairedAck || (ackQueues.get(block.counter) || []).shift();
      if (pairedAck) {
        const queue = ackQueues.get(block.counter) || [];
        const queueIndex = queue.findIndex((item) => item.eventId === pairedAck.eventId);
        if (queueIndex >= 0) queue.splice(queueIndex, 1);
      }
      const observedAck = ack || (observedQueues.get(block.counter) || []).shift();
      const ackStatus = session.sessionType === "upload"
        ? "ECU payload"
        : ack
          ? `ACK packet ${ack.packet}`
          : observedAck
            ? `Observed packet ${observedAck.packet}`
            : "No 0x76 observed";
      const ackClass = ack ? "ok" : observedAck ? "info" : session.sessionType === "upload" ? "info" : "warn";
      return `<tr><td>${index + 1}</td><td>${escapeHtml(block.counter || "")}</td><td>${escapeHtml(block.direction)}</td><td>${block.packet}</td><td>${ack?.packet || observedAck?.packet || ""}</td><td>${badge(ackStatus, ackClass)}</td><td>${formatNumber(block.payloadBytes)}</td><td><code>${escapeHtml(block.payloadHex.slice(0, 96))}${block.payloadHex.length > 96 ? " ..." : ""}</code></td></tr>`;
    }).join("");
    const coordination = session.sessionType === "upload" && session.coordinationBlocks?.length ? `<p class="overview-note">Upload coordination requests: ${session.coordinationBlocks.map((item) => `${item.counter} packet ${item.packet}`).join(", ")}</p>` : "";
    return `<div class="table-wrap"><table><thead><tr><th>#</th><th>Counter</th><th>Direction</th><th>Data packet</th><th>ACK packet</th><th>ACK status</th><th>Bytes</th><th>Hex preview</th></tr></thead><tbody>${rows || `<tr><td colspan="8">No payload blocks reconstructed.</td></tr>`}</tbody></table></div>${coordination}`;
  }

  function renderDownloadTimeline(sessions, options = {}) {
    const selectedDownloadSessionId = options.selectedDownloadSessionId;
    const ecuLabel = options.ecuLabel || ((address) => address);
    if (!sessions.length) return `<div class="empty">No transfer segments match the filters.</div>`;
    const { start, end, duration } = campaignTimelineDomain(sessions);
    const byEcu = new Map();
    for (const session of sessions) {
      if (!byEcu.has(session.ecuAddress)) byEcu.set(session.ecuAddress, []);
      byEcu.get(session.ecuAddress).push(session);
    }
    return `<div class="campaign-timeline">
    ${Array.from(byEcu.entries()).sort((a, b) => a[0].localeCompare(b[0])).map(([ecu, ecuSessions]) => {
      const laidOut = layoutCampaignSessions(ecuSessions);
      const laneHeight = Math.max(36, laidOut.rows * 28 + 8);
      const laneLabel = ecuLabel(ecu);
      return `
      <div class="campaign-lane" style="--lane-height:${laneHeight}px;">
        <button type="button" class="campaign-label" data-download-session="${ecuSessions[0].id}" title="${escapeHtml(laneLabel)}">${escapeHtml(laneLabel)}</button>
        <div class="campaign-track">
          ${laidOut.items.map(({ session, row }) => {
            const bounds = timelineSessionBounds(session, { start, end });
            const width = Math.min(100, Math.max(0.7, bounds.widthPercent));
            const left = Math.min(Math.max(0, bounds.leftPercent), Math.max(0, 100 - width));
            const durationText = formatTimelineDuration(bounds.durationSeconds);
            const showLabel = width >= 5;
            const label = ecuLabel(session.ecuAddress);
            return `<button type="button" class="campaign-bar ${escapeHtml(session.severity)} ${String(session.id) === String(selectedDownloadSessionId) ? "selected" : ""} ${showLabel ? "has-label" : ""}" aria-label="${escapeHtml(`${label} ${session.typeLabel} ${durationText} ${formatBytes(session.reconstructedBytes || 0)} ${session.severity}`)}" data-download-session="${session.id}" style="left:${left}%;width:${width}%;--bar-top:${7 + row * 28}px;" title="${escapeHtml(`${label} ${session.typeLabel} ${durationText} ${formatBytes(session.reconstructedBytes || 0)} ${session.severity}`)}">${showLabel ? escapeHtml(durationText) : ""}</button>`;
          }).join("")}
        </div>
      </div>`;
    }).join("")}
  </div>`;
  }

  function timelineExportColours(style) {
    const get = (name, fallback) => style?.getPropertyValue?.(name)?.trim() || fallback;
    return {
      bg: get("--bg", "#f5f5f5"),
      surface: get("--surface", "#ffffff"),
      surface2: get("--surface2", "#f0f0f0"),
      border: get("--border", "#e0e0e0"),
      grid: get("--border", "#e0e0e0"),
      gridStrong: get("--border2", "#cccccc"),
      text: get("--text", "#111111"),
      text2: get("--text2", "#555555"),
      barText: "#17351f",
      ok: "#9ed8ad",
      warning: get("--warning", "#e8883a"),
      error: get("--danger", "#d93030")
    };
  }

  function buildDownloadTimelineExportModel(sessions, options = {}) {
    const ecuLabel = options.ecuLabel || ((address) => address);
    const lanes = new Map();
    for (const session of sessions) {
      if (!lanes.has(session.ecuAddress)) lanes.set(session.ecuAddress, []);
      lanes.get(session.ecuAddress).push(session);
    }
    const laidOut = Array.from(lanes.entries()).sort((a, b) => a[0].localeCompare(b[0])).map(([ecu, laneSessions]) => ({
      ecu: ecuLabel(ecu),
      ...layoutCampaignSessions(laneSessions)
    }));
    const { start, end, duration } = campaignTimelineDomain(sessions);
    const laneLabelWidth = 172;
    const plotWidth = 1180;
    const titleHeight = 64;
    const axisHeight = 34;
    const legendHeight = 38;
    const laneGap = 10;
    const laneHeights = laidOut.map((lane) => Math.max(36, lane.rows * 28 + 8));
    const width = laneLabelWidth + plotWidth + 48;
    const height = titleHeight + axisHeight + legendHeight + laneHeights.reduce((sum, item) => sum + item, 0) + laneGap * Math.max(0, laneHeights.length - 1) + 34;
    return { sessions, laidOut, start, end, duration, laneLabelWidth, plotWidth, titleHeight, axisHeight, legendHeight, laneGap, laneHeights, width, height };
  }

  function drawTimelineAxis(ctx, x, y, width, start, end, colours, options = {}) {
    const firstTimestamp = options.firstTimestamp || start;
    ctx.strokeStyle = colours.border;
    ctx.beginPath();
    ctx.moveTo(x, y + 24);
    ctx.lineTo(x + width, y + 24);
    ctx.stroke();
    ctx.fillStyle = colours.text2;
    ctx.font = "11px 'Cascadia Mono', Consolas, monospace";
    ctx.textBaseline = "alphabetic";
    const span = Math.max(0.000001, end - start);
    for (let i = 0; i <= 10; i += 1) {
      const tickX = x + (width * i) / 10;
      const value = start + (span * i) / 10;
      ctx.strokeStyle = colours.border;
      ctx.beginPath();
      ctx.moveTo(tickX, y + 18);
      ctx.lineTo(tickX, y + 29);
      ctx.stroke();
      ctx.fillText(`+${(value - firstTimestamp).toFixed(2)}s`, tickX - (i === 10 ? 48 : 0), y + 14);
    }
  }

  function drawTimelineLegend(ctx, x, y, colours) {
    const items = [["ok", "Pass / clean"], ["warning", "Warning"], ["error", "Error"]];
    ctx.font = "12px Bahnschrift, Segoe UI, sans-serif";
    ctx.textBaseline = "middle";
    for (const [key, label] of items) {
      ctx.fillStyle = colours[key];
      ctx.fillRect(x, y, 28, 12);
      ctx.strokeStyle = colours.border;
      ctx.strokeRect(x, y, 28, 12);
      ctx.fillStyle = colours.text2;
      ctx.fillText(label, x + 36, y + 6);
      x += 132;
    }
  }

  function drawDownloadTimelineExport(ctx, model, colours, options = {}) {
    const formatTimeDelta = options.formatTimeDelta || (() => "");
    const firstTimestamp = options.firstTimestamp || model.start;
    ctx.fillStyle = colours.bg;
    ctx.fillRect(0, 0, model.width, model.height);
    ctx.fillStyle = colours.text;
    ctx.font = "700 20px Bahnschrift, Segoe UI, sans-serif";
    ctx.fillText("Harness Software Download Campaign Timeline", 24, 30);
    ctx.fillStyle = colours.text2;
    ctx.font = "12px 'Cascadia Mono', Consolas, monospace";
    ctx.fillText(`${formatNumber(model.sessions.length)} sessions | ${formatTimeDelta(model.start)} to ${formatTimeDelta(model.end)} | ${formatNumber(model.laidOut.length)} ECU lanes`, 24, 50);

    const plotX = model.laneLabelWidth + 24;
    drawTimelineAxis(ctx, plotX, model.titleHeight, model.plotWidth, model.start, model.end, colours, { firstTimestamp });
    let y = model.titleHeight + model.axisHeight;
    for (let laneIndex = 0; laneIndex < model.laidOut.length; laneIndex += 1) {
      const lane = model.laidOut[laneIndex];
      const laneHeight = model.laneHeights[laneIndex];
      ctx.fillStyle = colours.surface2;
      ctx.fillRect(plotX, y, model.plotWidth, laneHeight);
      ctx.strokeStyle = colours.border;
      ctx.strokeRect(plotX, y, model.plotWidth, laneHeight);
      for (let i = 0; i <= 10; i += 1) {
        const x = plotX + (model.plotWidth * i) / 10;
        ctx.strokeStyle = i % 5 === 0 ? colours.gridStrong : colours.grid;
        ctx.beginPath();
        ctx.moveTo(x, y);
        ctx.lineTo(x, y + laneHeight);
        ctx.stroke();
      }
      ctx.fillStyle = colours.text;
      ctx.font = "700 12px 'Cascadia Mono', Consolas, monospace";
      ctx.textBaseline = "middle";
      ctx.fillText(lane.ecu, 24, y + laneHeight / 2);
      for (const { session, row } of lane.items) {
        const bounds = timelineSessionBounds(session, model);
        const barWidth = Math.min(model.plotWidth, Math.max(4, (bounds.widthPercent / 100) * model.plotWidth));
        const x = plotX + Math.min(Math.max(0, (bounds.leftPercent / 100) * model.plotWidth), Math.max(0, model.plotWidth - barWidth));
        const barY = y + 7 + row * 28;
        ctx.fillStyle = colours[session.severity] || colours.ok;
        ctx.strokeStyle = colours.border;
        ctx.fillRect(x, barY, barWidth, 22);
        ctx.strokeRect(x, barY, barWidth, 22);
        const durationText = formatTimelineDuration(bounds.durationSeconds);
        if (barWidth >= Math.max(52, ctx.measureText(durationText).width + 12)) {
          ctx.fillStyle = colours.barText;
          ctx.font = "700 10px 'Cascadia Mono', Consolas, monospace";
          ctx.textBaseline = "middle";
          ctx.fillText(durationText, x + 6, barY + 11);
        }
      }
      y += laneHeight + model.laneGap;
    }
    drawTimelineLegend(ctx, 24, model.height - 44, colours);
  }

  function conditionServiceGroup(event) {
    const sid = (event.originalService || event.service || "").toLowerCase();
    const service = (event.service || "").toLowerCase();
    const key = sid || service;
    if (["0x10", "0x50"].includes(key)) return "Diagnostic session";
    if (["0x27", "0x67"].includes(key)) return "Security access";
    if (["0x31", "0x71"].includes(key)) return "Routine control";
    if (["0x28", "0x68"].includes(key)) return "Communication control";
    if (["0x3e", "0x7e"].includes(key)) return "Tester present";
    if (["0x11", "0x51"].includes(key)) return "ECU reset";
    if (["0x85", "0xc5"].includes(key)) return "DTC setting";
    return "";
  }

  function conditionDetail(event) {
    const parts = [];
    if (event.subFunction) parts.push(`sub ${event.subFunction}`);
    if (event.routineId) parts.push(`routine ${event.routineId}`);
    if (event.nrc) parts.push(`NRC ${event.nrc} ${event.nrcName || ""}`.trim());
    return parts.join(" | ");
  }

  function downloadConditionEvents(session, udsEvents) {
    return (udsEvents || [])
      .filter((event) => event.ecuAddress === session.ecuAddress && event.testerAddress === session.testerAddress && conditionServiceGroup(event))
      .map((event) => ({
        ...event,
        phase: event.timestamp < session.startTimestamp ? "Pre" : event.timestamp > (session.endTimestamp ?? session.startTimestamp) ? "Post" : "During"
      }))
      .filter((event) => event.phase === "During" || Math.abs(event.timestamp - session.startTimestamp) <= 60 || Math.abs(event.timestamp - (session.endTimestamp ?? session.startTimestamp)) <= 60)
      .sort((a, b) => a.timestamp - b.timestamp);
  }

  function renderDownloadConditions(session, udsEvents, options = {}) {
    const formatTimeDelta = options.formatTimeDelta || (() => "");
    const events = downloadConditionEvents(session, udsEvents);
    const rowsForPhase = (phase) => events.filter((event) => event.phase === phase).map((event) => `<tr>
    <td>${escapeHtml(event.phase)}</td>
    <td>${formatTimeDelta(event.timestamp)}</td>
    <td>${event.packet}</td>
    <td>${badge(event.responseKind, event.responseKind === "negative" ? "danger" : event.responseKind === "positive" ? "ok" : "")}</td>
    <td>${escapeHtml(conditionServiceGroup(event))}</td>
    <td>${escapeHtml(event.service)} ${escapeHtml(event.serviceName)}</td>
    <td>${escapeHtml(conditionDetail(event))}</td>
    ${rawBytesCell(event.raw)}
  </tr>`).join("");
    const sections = ["Pre", "Post"].map((phase) => {
      const rows = rowsForPhase(phase);
      return `<tr class="prepost-section-row"><td colspan="8">${escapeHtml(phase)} transfer</td></tr>${rows || `<tr><td colspan="8">No ${phase.toLowerCase()} condition services found.</td></tr>`}`;
    }).join("");
    return `<div class="table-wrap"><table><thead><tr><th>Phase</th><th>Time</th><th>Packet</th><th>Kind</th><th>Condition</th><th>Service</th><th>Detail</th><th>Raw UDS</th></tr></thead><tbody>${events.length ? sections : `<tr><td colspan="8">No pre/post condition services found near this transfer.</td></tr>`}</tbody></table></div>`;
  }

  function renderGroupedDownloadRows(groups, sessions, options = {}) {
    const ecuCode = options.ecuCode || ((address) => escapeHtml(address));
    const collapsedDownloadGroups = options.collapsedDownloadGroups || new Set();
    const collapsedDownloadEcuGroups = options.collapsedDownloadEcuGroups || new Set();
    const selectedDownloadSessionId = options.selectedDownloadSessionId;
    const visible = new Set(sessions.map((session) => String(session.id)));
    const rows = [];
    for (const group of groups) {
      const groupSessions = group.sessions.filter((session) => visible.has(String(session.id)));
      if (!groupSessions.length) continue;
      const groupKey = String(group.key || group.label || "unknown");
      const groupCollapsed = collapsedDownloadGroups.has(groupKey);
      rows.push(`<tr class="download-group-row ${groupCollapsed ? "collapsed" : ""}"><td colspan="9">
      <button type="button" class="download-collapse" data-download-group-toggle="${escapeHtml(groupKey)}" aria-expanded="${groupCollapsed ? "false" : "true"}">${groupCollapsed ? "+" : "-"}</button>
      <strong>${escapeHtml(group.label)}</strong>
      <span>${formatNumber(groupSessions.length)} transfer segments</span>
      <span>${formatNumber(new Set(groupSessions.map((item) => item.ecuAddress)).size)} ECUs</span>
      <span>${formatBytes(groupSessions.reduce((sum, item) => sum + (item.reconstructedBytes || 0), 0))}</span>
      ${badge(`${formatNumber(groupSessions.filter((item) => item.severity === "ok").length)} pass`, "ok")}
      ${badge(`${formatNumber(groupSessions.filter((item) => item.severity === "warning").length)} warn`, "warn")}
      ${badge(`${formatNumber(groupSessions.filter((item) => item.severity === "error").length)} fail`, "danger")}
    </td></tr>`);
      if (groupCollapsed) continue;
      const byEcu = new Map();
      for (const session of groupSessions) {
        if (!byEcu.has(session.ecuAddress)) byEcu.set(session.ecuAddress, []);
        byEcu.get(session.ecuAddress).push(session);
      }
      for (const [ecu, ecuSessions] of Array.from(byEcu.entries()).sort((a, b) => a[0].localeCompare(b[0]))) {
        const ecuKey = `${groupKey}|${ecu}`;
        const ecuCollapsed = collapsedDownloadEcuGroups.has(ecuKey);
        rows.push(`<tr class="download-ecu-row ${ecuCollapsed ? "collapsed" : ""}"><td colspan="9">
        <button type="button" class="download-collapse" data-download-ecu-toggle="${escapeHtml(ecuKey)}" aria-expanded="${ecuCollapsed ? "false" : "true"}">${ecuCollapsed ? "+" : "-"}</button>
        <strong>${ecuCode(ecu)}</strong>
        <span>${formatNumber(ecuSessions.length)} transfer segments</span>
        <span>${formatBytes(ecuSessions.reduce((sum, item) => sum + (item.reconstructedBytes || 0), 0))}</span>
        ${badge(`${formatNumber(ecuSessions.filter((item) => item.severity === "ok").length)} pass`, "ok")}
        ${badge(`${formatNumber(ecuSessions.filter((item) => item.severity === "warning").length)} warn`, "warn")}
        ${badge(`${formatNumber(ecuSessions.filter((item) => item.severity === "error").length)} fail`, "danger")}
      </td></tr>`);
        if (ecuCollapsed) continue;
        for (const session of ecuSessions) {
          rows.push(`
        <tr data-download-session="${session.id}" class="${String(session.id) === String(selectedDownloadSessionId) ? "selected" : ""}">
          <td>${ecuCode(session.ecuAddress)}</td>
          <td>${escapeHtml(session.typeLabel)}</td>
          <td><code>${escapeHtml(session.request?.memoryAddress || "")}</code></td>
          <td>${session.requestedBytes ?? ""}</td>
          <td>${session.expectedBlocks ?? "Unknown"}</td>
          <td>${formatNumber(session.blocks)}</td>
          <td>${formatNumber(session.acknowledgedBlocks || 0)}</td>
          <td>${formatNumber(session.reconstructedBytes)}</td>
          <td>${badge(session.severity, downloadSeverityClass(session.severity))}</td>
        </tr>`);
        }
      }
    }
    return rows.join("") || `<tr><td colspan="9">No software transfer segments match the filters.</td></tr>`;
  }

  function renderDownloadOverview(session, options = {}) {
    const ecuCode = options.ecuCode || ((address) => escapeHtml(address));
    const transferExitAlert = session.status === "completed" ? "" : `
    <div class="validation-card error transfer-exit-alert">
      <strong>TransferExit missing</strong>
      <p>No matching RequestTransferExit was observed for this transfer. Treat this as an incomplete programming sequence unless the capture ended before TransferExit occurred.</p>
    </div>`;
    return `
    ${transferExitAlert}
    <div class="download-graphics">
      ${renderDirectionDiagram(session, { ecuCode })}
      ${renderPayloadProgress(session)}
    </div>
    <section class="overview-panel rate-overview-card">
      <h4>Transfer Rate</h4>
      <div class="sequence-health-grid">
        <div class="sequence-health-item"><span>Payload rate</span><strong>${formatRate(session.rate?.averagePayloadRateBps)}</strong></div>
        <div class="sequence-health-item"><span>Session rate</span><strong>${formatRate(session.rate?.averageSessionRateBps)}</strong></div>
        <div class="sequence-health-item"><span>Active duration</span><strong>${formatDurationValue(session.rate?.activePayloadDuration)}</strong></div>
      </div>
    </section>
    ${renderBlockStrip(session)}
    <section class="overview-panel">
      <h4>Sequence Health</h4>
      ${renderSequenceHealth(session)}
    </section>
  `;
  }

  function campaignPeakParallelism(sessions) {
    const points = [];
    for (const session of sessions) {
      const start = session.startTimestamp;
      const end = session.endTimestamp ?? session.startTimestamp;
      if (!Number.isFinite(start) || !Number.isFinite(end)) continue;
      points.push({ time: start, delta: 1 });
      points.push({ time: Math.max(start, end), delta: -1 });
    }
    let active = 0;
    let peak = 0;
    for (const point of points.sort((a, b) => a.time - b.time || b.delta - a.delta)) {
      active += point.delta;
      peak = Math.max(peak, active);
    }
    return peak;
  }

  function renderDownloadCampaignSummary(sessions, options = {}) {
    const ecuLabel = options.ecuLabel || ((address) => address);
    const ecuCode = options.ecuCode || ((address) => escapeHtml(address));
    if (!sessions.length) return `<div class="empty">No transfer segments match the filters.</div>`;
    const ecus = Array.from(new Set(sessions.map((session) => session.ecuAddress)));
    const start = Math.min(...sessions.map((session) => session.startTimestamp ?? Infinity));
    const end = Math.max(...sessions.map((session) => session.endTimestamp ?? session.startTimestamp ?? -Infinity));
    const sessionDuration = Number.isFinite(start) && Number.isFinite(end) ? end - start : null;
    const statusFor = (items) => items.some((item) => item.severity === "error") ? "error" : items.some((item) => item.severity === "warning") ? "warning" : "ok";
    const ecuStatus = ecus.map((ecu) => ({ ecu, sessions: sessions.filter((session) => session.ecuAddress === ecu) }));
    const slowest = sessions.slice().sort((a, b) => ((b.endTimestamp ?? b.startTimestamp ?? 0) - (b.startTimestamp ?? 0)) - ((a.endTimestamp ?? a.startTimestamp ?? 0) - (a.startTimestamp ?? 0)))[0];
    const gateways = new Map();
    for (const session of sessions) {
      const key = session.gatewayLabel || session.gatewayIp || "Unknown gateway/IP";
      if (!gateways.has(key)) gateways.set(key, []);
      gateways.get(key).push(session);
    }
    const metrics = [
      ["ECUs attempted", ecus.length],
      ["Passed", ecuStatus.filter((item) => statusFor(item.sessions) === "ok").length],
      ["Warnings", ecuStatus.filter((item) => statusFor(item.sessions) === "warning").length],
      ["Failed", ecuStatus.filter((item) => statusFor(item.sessions) === "error").length],
      ["Total payload", formatBytes(sessions.reduce((sum, item) => sum + (item.reconstructedBytes || 0), 0))],
      ["Campaign time", formatDurationValue(sessionDuration)],
      ["Peak parallelism", campaignPeakParallelism(sessions)],
      ["Slowest ECU", slowest ? ecuLabel(slowest.ecuAddress) : "n/a"]
    ];
    const gatewayRows = Array.from(gateways.entries()).sort((a, b) => a[0].localeCompare(b[0])).map(([label, items]) => `
    <tr>
      <td>${escapeHtml(label)}</td>
      <td>${formatNumber(new Set(items.map((item) => item.ecuAddress)).size)}</td>
      <td>${formatNumber(items.length)}</td>
      <td>${formatBytes(items.reduce((sum, item) => sum + (item.reconstructedBytes || 0), 0))}</td>
      <td>${badge(statusFor(items), downloadSeverityClass(statusFor(items)))}</td>
    </tr>`).join("");
    const issueRows = sessions.flatMap((session) => (session.validation || [])
      .filter((finding) => finding.severity === "error" || finding.severity === "warning")
      .map((finding) => ({ session, finding })))
      .slice(0, 18)
      .map(({ session, finding }) => `<tr><td>${ecuCode(session.ecuAddress)}</td><td>${badge(finding.severity, downloadSeverityClass(finding.severity))}</td><td>${escapeHtml(finding.category)}</td><td>${escapeHtml(finding.title)}</td><td>${finding.packet ? `<code>${escapeHtml(finding.packet)}</code>` : ""}</td></tr>`).join("");
    return `
    <div class="overview-grid campaign-summary-grid">
      ${metricsHtml(metrics)}
    </div>
    <div class="grid two">
      <section class="overview-panel">
        <h4>Gateway/IP Rollup</h4>
        <div class="table-wrap"><table><thead><tr><th>Gateway/IP</th><th>ECUs</th><th>Segments</th><th>Payload</th><th>Status</th></tr></thead><tbody>${gatewayRows || `<tr><td colspan="5">No gateway data.</td></tr>`}</tbody></table></div>
      </section>
      <section class="overview-panel">
        <h4>Campaign Issues</h4>
        <div class="table-wrap"><table><thead><tr><th>ECU</th><th>Severity</th><th>Group</th><th>Finding</th><th>Packet</th></tr></thead><tbody>${issueRows || `<tr><td colspan="5">No validation warnings or errors in the filtered campaign.</td></tr>`}</tbody></table></div>
      </section>
    </div>`;
  }

  function renderDownloadMatrix(rows, options = {}) {
    const selectedDownloadSessionId = options.selectedDownloadSessionId;
    const ecuCode = options.ecuCode || ((address) => escapeHtml(address));
    return `<div class="table-wrap"><table class="download-matrix"><thead><tr><th>Gateway/IP</th><th>ECU</th><th>Segments</th><th>Download</th><th>Upload</th><th>File</th><th>Payload</th><th>Blocks</th><th>NRC</th><th>Capture</th><th>Hex</th><th>Status</th></tr></thead><tbody>
    ${rows.map((row) => `<tr data-matrix-session="${row.sessionIds[0] || ""}" class="${(row.sessionIds || []).map(String).includes(String(selectedDownloadSessionId)) ? "selected" : ""}">
      <td>${escapeHtml(row.groupLabel)}</td>
      <td>${ecuCode(row.ecuAddress)}</td>
      <td>${formatNumber(row.sessions)}</td>
      <td>${formatNumber(row.downloads)}</td>
      <td>${formatNumber(row.uploads)}</td>
      <td>${formatNumber(row.fileTransfers)}</td>
      <td>${formatBytes(row.payloadBytes)}</td>
      <td>${badge(row.blockAgreement, row.blockAgreement === "pass" ? "ok" : "warn", { title: row.blockDetail || "" })}</td>
      <td>${formatNumber(row.nrcs)}</td>
      <td>${formatNumber(row.captureWarnings)}</td>
      <td>${formatNumber(row.exportable)}</td>
      <td>${badge(row.severity, downloadSeverityClass(row.severity))}</td>
    </tr>`).join("") || `<tr><td colspan="12">No ECU summary rows match the filters.</td></tr>`}
  </tbody></table></div>`;
  }

  function renderDownloadValidation(session) {
    const realFindings = (session.validation || []).filter((finding) => finding.severity !== "info" || finding.category !== "Validation");
    if (!realFindings.some((finding) => finding.severity === "error" || finding.severity === "warning")) {
      return `<div class="validation-success">
      <strong>No validation issues found</strong>
      <p>Observed transfer evidence is internally consistent.</p>
      ${metricGrid([
        ["Expected", session.expectedBlocks ?? "Unknown"],
        ["Data blocks", session.blocks],
        ["ACKed", session.acknowledgedBlocks || 0],
        ["Payload", formatBytes(session.reconstructedBytes || 0)],
        ["TransferExit", session.status === "completed" ? "Observed" : "Missing"],
        ["Hex export", session.hexExportable ? "Enabled" : "Disabled"]
      ])}
      <p class="overview-note">Expected blocks are estimated from requested size and max block length. Data blocks are reconstructed payload-bearing blocks. ACKed blocks are positive block responses where applicable.</p>
    </div>`;
    }
    const categories = ["Completeness", "Sequence", "Responses", "Capture quality"];
    return `<div class="validation-list">${categories.map((category) => {
      const findings = realFindings.filter((finding) => finding.category === category);
      if (!findings.length) return "";
      return `<section class="validation-group"><h4>${escapeHtml(category)}</h4>${findings.map((finding) => `
    <div class="validation-card ${escapeHtml(finding.severity)}">
      <strong>${escapeHtml(finding.title)}</strong>
      <p>${escapeHtml(finding.detail)}</p>
      <div class="validation-evidence">${finding.packet ? `<code>packet ${escapeHtml(finding.packet)}</code>` : ""}</div>
    </div>
  `).join("")}</section>`;
    }).join("")}</div>`;
  }

  function renderDownloadRaw(session, options = {}) {
    const formatTimeDelta = options.formatTimeDelta || (() => "");
    const events = session.events || [];
    const rawLimit = Number(options.rawLimit) || 64;
    const rows = events.map((event) => {
      const rawCell = rawBytesCell(event.raw, { expandable: false, limit: rawLimit, titleLimit: 128 });
      return `<tr><td>${event.id}</td><td>${formatTimeDelta(event.timestamp)}</td><td>${event.packet}</td><td>${escapeHtml(event.responseKind)}</td><td>${escapeHtml(event.serviceName)}</td>${rawCell}</tr>`;
    }).join("");
    return `<p class="overview-note">Raw UDS bytes are capped in this table to keep large or out-of-sequence downloads responsive. All ${formatNumber(events.length)} raw message${events.length === 1 ? "" : "s"} remain listed; use exports for complete payload data.</p>
    <div class="table-wrap"><table><thead><tr><th>ID</th><th>Time</th><th>Packet</th><th>Kind</th><th>Service</th><th>Raw UDS</th></tr></thead><tbody>${rows || `<tr><td colspan="6">No raw messages.</td></tr>`}</tbody></table></div>`;
  }

  global.HarnessDownloadRenderer = {
    downloadSeverityClass,
    formatTimelineDuration,
    timelineSessionBounds,
    campaignTimelineDomain,
    layoutCampaignSessions,
    niceAxisMax,
    compactRateBuckets,
    didValueDomain,
    numericTicks,
    timeSampleTicks,
    didAxisTickCount,
    compactTimeAxisLabel,
    renderDidLineChart,
    renderDidPlotModal,
    renderDirectionDiagram,
    renderPayloadProgress,
    renderBlockStrip,
    blockStripSlots,
    blockSlotTitle,
    parseCounter,
    renderSequenceHealth,
    buildRateTimingRows,
    renderRateChart,
    renderDownloadRate,
    renderDownloadBlocks,
    renderDownloadTimeline,
    timelineExportColours,
    buildDownloadTimelineExportModel,
    drawTimelineAxis,
    drawTimelineLegend,
    drawDownloadTimelineExport,
    conditionServiceGroup,
    conditionDetail,
    downloadConditionEvents,
    renderDownloadConditions,
    renderGroupedDownloadRows,
    renderDownloadOverview,
    campaignPeakParallelism,
    renderDownloadCampaignSummary,
    renderDownloadMatrix,
    renderDownloadValidation,
    renderDownloadRaw
  };
})(window);
