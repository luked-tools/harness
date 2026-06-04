/**
 * Rendering and filtering helpers for the validation centre view.
 */
(function registerValidationRenderer(global) {
  "use strict";

  const formatters = global.HarnessFormatters || {};
  const escapeHtml = formatters.escapeHtml || ((value) => String(value ?? ""));
  const formatNumber = formatters.formatNumber || ((value) => String(value ?? ""));
  const { badge, metrics: metricsList } = global.HarnessUi;

  function summaryText(summary = {}, visibleCount = null, modeLabel = "") {
    const total = summary.totalFindings ?? ((summary.errors || 0) + (summary.warnings || 0) + (summary.info || 0));
    const visibleText = visibleCount !== null ? `${formatNumber(visibleCount)} visible of ${formatNumber(total)} total. ` : "";
    const modeText = modeLabel ? `${modeLabel}. ` : "";
    return `${visibleText}${modeText}${formatNumber(summary.errors || 0)} errors, ${formatNumber(summary.warnings || 0)} warnings, ${formatNumber(summary.info || 0)} info.`;
  }

  function metricsHtml(summary = {}, findings = []) {
    return metricsList([
      ["Errors", summary.errors || 0],
      ["Warnings", summary.warnings || 0],
      nrcMetric("Severe NRCs", summary.actionableNrcs || 0),
      nrcMetric("Low Priority NRCs", summary.informationalNrcs || 0),
      nrcMetric("Diagnostic Response Pendings", summary.repeatedPendingGroups || 0),
      ["Affected ECUs", summary.affectedEcus || 0],
      ["Affected TCP flows", summary.affectedFlows || 0]
    ]);
  }

  function nrcMetric(label, value) {
    return {
      label,
      value,
      options: {
        valueHtml: `<button class="mini-metric-action" type="button" data-open-validation-nrc-summary="true" title="Open NRC summary">${formatNumber(value)}</button>`
      }
    };
  }

  function filterOptions(findings, key) {
    return Array.from(new Set(findings.map((item) => item[key]).filter(Boolean))).sort();
  }

  function selectOptionsHtml(values, allLabel) {
    return [`<option value="all">${escapeHtml(allLabel)}</option>`].concat(values.map((value) => `<option value="${escapeHtml(value)}">${escapeHtml(value)}</option>`)).join("");
  }

  function filteredFindings(findings, filters = {}) {
    const severity = filters.severity || "all";
    const source = filters.source || "all";
    const category = filters.category || "all";
    const view = filters.view || filters.type || "all";
    const query = String(filters.query || "").trim().toLowerCase();
    return findings.filter((finding) => {
      const severityMatch = severity === "all" || severity === "actionable" && (finding.severity === "error" || finding.severity === "warning") || finding.severity === severity;
      const sourceMatch = source === "all" || finding.sourceTool === source;
      const categoryMatch = category === "all" || finding.category === category;
      const viewMatch = validationViewFilterMatch(finding, view);
      const haystack = `${finding.severity} ${finding.category} ${finding.sourceTool} ${finding.title} ${finding.detail} ${finding.evidence} ${finding.entity} ${finding.ecuAddress} ${finding.packet} ${finding.nrc || ""} ${finding.nrcName || ""}`.toLowerCase();
      return severityMatch && sourceMatch && categoryMatch && viewMatch && (!query || haystack.includes(query));
    });
  }

  function validationViewFilterMatch(finding, view) {
    if (view === "all") return true;
    if (view === "nrc-summary") return finding.validationKind === "nrc" || finding.validationKind === "nrc-pending";
    if (view === "network") return finding.sourceTool === "Transport Timing" || finding.category === "Transport / TCP" || finding.category === "Capture quality" || finding.sourceTool === "Parser";
    if (view === "identity-topology") return finding.sourceTool === "Address Identity" || finding.sourceTool === "Node Map" || ["Identity", "Topology", "DHCP / addressing"].includes(finding.category);
    if (view === "download") return finding.sourceTool === "Software Download" || finding.category === "Software download";
    if (view === "informational") return finding.validationView === "informational" || finding.severity === "info";
    return finding.validationView !== "informational" && (finding.severity === "error" || finding.severity === "warning");
  }

  function validationTypeFilterMatch(finding, type) {
    if (type === "all") return true;
    if (["action-required", "nrc-summary", "network", "identity-topology", "download", "informational"].includes(type)) return validationViewFilterMatch(finding, type);
    const text = `${finding.title} ${finding.detail} ${finding.nrc || ""}`.toLowerCase();
    if (type === "hide-security-invalid-key") return !(finding.sourceTool === "UDS Analyser" && text.includes("0x27") && (text.includes("0x35") || text.includes("invalid key")) && text.includes("later matching securityaccess positive response"));
    if (type === "hide-unpaired") return !text.includes("unpaired uds message");
    if (type === "hide-pending") return !text.includes("response pending");
    return true;
  }

  function viewModeLabel(view) {
    return {
      "action-required": "Action Suggested",
      all: "All findings",
      "nrc-summary": "UDS NRC summary",
      network: "Network / TCP",
      "identity-topology": "Identity / topology",
      download: "Software download",
      informational: "Informational"
    }[view] || "Action Suggested";
  }

  function emptyStateText(view) {
    return `No validation findings match the ${viewModeLabel(view).toLowerCase()} view and current filters.`;
  }

  function nrcSummaryHtml(items = [], options = {}) {
    const selectedId = options.selectedId || "";
    const ecuCode = options.ecuCode || ((address) => `<code>${escapeHtml(address)}</code>`);
    const formatTimeDelta = options.formatTimeDelta || (() => "");
    if (!items.length) return `<div class="empty">No UDS NRC groups match the current filters.</div>`;
    const groups = groupNrcSummaryByEcu(items);
    return `
      <div class="nrc-ecu-groups">
        ${groups.map((group) => `
          <section class="nrc-ecu-group">
            <div class="nrc-ecu-head">
              <div>
                <h4>${group.ecuAddress ? ecuCode(group.ecuAddress) : `<code>${escapeHtml(group.entity || "Capture")}</code>`} <span>${escapeHtml(group.entity && group.entity !== group.ecuAddress ? group.entity : "")}</span></h4>
                <p>${formatNumber(group.items.length)} NRC group${group.items.length === 1 ? "" : "s"} · ${formatNumber(group.responses)} response${group.responses === 1 ? "" : "s"}</p>
              </div>
              <div class="nrc-ecu-counts">
                ${badge(group.severity, validationSeverityClass(group.severity))}
                <span>${formatNumber(group.actionable)} actionable</span>
                <span>${formatNumber(group.informational)} info</span>
              </div>
            </div>
            <div class="nrc-summary-grid">
              ${group.items.map((item) => `
                <button class="nrc-summary-card${item.id === selectedId ? " selected" : ""}" type="button" data-validation-id="${escapeHtml(item.id)}">
                  <span class="nrc-summary-head">${badge(item.severity, validationSeverityClass(item.severity))}<strong>${escapeHtml(item.service || "UDS")} / ${escapeHtml(item.nrc || "")}</strong></span>
                  <span>${escapeHtml(item.nrcName || "NRC")} · ${formatNumber(item.count || 0)} response${Number(item.count) === 1 ? "" : "s"}</span>
                  <span class="subtle">${escapeHtml(item.classification || "")}${item.packet ? ` · packet ${escapeHtml(item.packet)}` : ""}${item.timestamp !== null && item.timestamp !== undefined ? ` · ${escapeHtml(formatTimeDelta(item.timestamp))}` : ""}</span>
                </button>
              `).join("")}
            </div>
          </section>
        `).join("")}
      </div>
    `;
  }

  function groupNrcSummaryByEcu(items = []) {
    const severityRank = { error: 3, warning: 2, info: 1 };
    const groups = new Map();
    for (const item of items) {
      const key = item.ecuAddress || item.entity || "Capture";
      if (!groups.has(key)) {
        groups.set(key, { key, ecuAddress: item.ecuAddress || "", entity: item.entity || item.ecuAddress || "Capture", items: [], responses: 0, actionable: 0, informational: 0, severity: "info" });
      }
      const group = groups.get(key);
      group.items.push(item);
      group.responses += Number(item.count || 0);
      if (item.classification === "informational" || item.severity === "info") group.informational += 1;
      else group.actionable += 1;
      if ((severityRank[item.severity] || 0) > (severityRank[group.severity] || 0)) group.severity = item.severity;
    }
    return Array.from(groups.values())
      .map((group) => ({
        ...group,
        items: group.items.slice().sort((a, b) => (severityRank[b.severity] || 0) - (severityRank[a.severity] || 0) || String(a.service).localeCompare(String(b.service)) || String(a.nrc).localeCompare(String(b.nrc)))
      }))
      .sort((a, b) => (severityRank[b.severity] || 0) - (severityRank[a.severity] || 0) || String(a.entity || a.ecuAddress).localeCompare(String(b.entity || b.ecuAddress)));
  }

  function compactText(value, limit = 96) {
    const text = String(value || "").replace(/\s+/g, " ").trim();
    if (text.length <= limit) return text;
    const slice = text.slice(0, Math.max(0, limit - 3)).trimEnd();
    const boundary = slice.lastIndexOf(" ");
    return `${(boundary > 12 ? slice.slice(0, boundary) : slice).trimEnd()}...`;
  }

  function evidenceCellHtml(finding = {}) {
    const evidence = String(finding.evidence || "").replace(/\s+/g, " ").trim();
    const packetHtml = finding.packet ? `<code>packet ${escapeHtml(finding.packet)}</code>` : "";
    if (!evidence) return `<td class="validation-evidence-cell">${packetHtml}</td>`;
    const commaCount = (evidence.match(/,/g) || []).length;
    const looksLikePacketList = /\bpackets?\b/i.test(evidence);
    const shouldCollapse = evidence.length > 90 || (looksLikePacketList && commaCount >= 5);
    if (!shouldCollapse) {
      return `<td class="validation-evidence-cell" title="${escapeHtml(evidence)}">${packetHtml}${packetHtml ? "<br>" : ""}<span class="subtle">${escapeHtml(evidence)}</span></td>`;
    }
    return `<td class="validation-evidence-cell" title="${escapeHtml(evidence)}">${packetHtml}${packetHtml ? "<br>" : ""}
      <details class="validation-evidence-collapsed">
        <summary><span>${escapeHtml(compactText(evidence, 72))}</span></summary>
        <span class="validation-evidence-full">${escapeHtml(evidence)}</span>
      </details>
    </td>`;
  }

  function findingRowHtml(finding, options = {}) {
    const selectedId = options.selectedId || "";
    const ecuCode = options.ecuCode || ((address) => `<code>${escapeHtml(address)}</code>`);
    const formatTimeDelta = options.formatTimeDelta || (() => "");
    const title = compactText(finding.title, 58);
    const detail = compactText(finding.detail, 110);
    const fullFindingText = [finding.title, finding.detail].filter(Boolean).join(" - ");
    return `<tr data-validation-id="${escapeHtml(finding.id)}" class="${finding.id === selectedId ? "selected" : ""}">
    <td>${badge(finding.severity, validationSeverityClass(finding.severity))}</td>
    <td>${escapeHtml(finding.sourceTool)}<br><span class="subtle">${escapeHtml(finding.category)}</span></td>
    <td>${finding.ecuAddress ? ecuCode(finding.ecuAddress) : `<code>${escapeHtml(finding.entity || "")}</code>`}</td>
    <td class="validation-finding-cell" title="${escapeHtml(fullFindingText)}"><strong>${escapeHtml(title)}</strong><br><span class="subtle">${escapeHtml(detail)}</span></td>
    ${evidenceCellHtml(finding)}
    <td>${formatTimeDelta(finding.timestamp)}</td>
    <td><button type="button" data-validation-jump="${escapeHtml(finding.id)}">Open</button></td>
  </tr>`;
  }

  function detailHtml(finding, options = {}) {
    const formatTimeDelta = options.formatTimeDelta || (() => "");
    return `<h3>${escapeHtml(finding.title)}</h3>
    <div class="validation-detail-stack">
      ${badge(finding.severity, validationSeverityClass(finding.severity))}
      ${badge(finding.sourceTool)}
      ${badge(finding.category)}
    </div>
    <dl>
      <dt>Entity</dt><dd>${escapeHtml(finding.entity || finding.ecuAddress || "Capture")}</dd>
      <dt>Detail</dt><dd>${escapeHtml(finding.detail || "")}</dd>
      <dt>Evidence</dt><dd>${escapeHtml(finding.evidence || "No extra evidence.")}</dd>
      <dt>Packet</dt><dd>${finding.packet ? `<code>${escapeHtml(finding.packet)}</code>` : "n/a"}</dd>
      <dt>Time</dt><dd>${formatTimeDelta(finding.timestamp)}</dd>
    </dl>
    <button type="button" data-validation-detail-jump="${escapeHtml(finding.id)}">Open source tool</button>`;
  }

  function validationSeverityClass(severity) {
    return severity === "error" ? "danger" : severity === "warning" ? "warn" : severity === "info" ? "" : "ok";
  }

  global.HarnessValidationRenderer = Object.freeze({
    summaryText,
    metricsHtml,
    filterOptions,
    selectOptionsHtml,
    filteredFindings,
    validationViewFilterMatch,
    validationTypeFilterMatch,
    viewModeLabel,
    emptyStateText,
    nrcSummaryHtml,
    groupNrcSummaryByEcu,
    compactText,
    evidenceCellHtml,
    findingRowHtml,
    detailHtml,
    validationSeverityClass
  });
})(window);
