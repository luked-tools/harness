/**
 * Shared HTML snippets for repeated UI patterns.
 *
 * This module is intentionally small: it commonises stable presentation
 * primitives while leaving feature-specific renderers in their own modules.
 */
(function registerUiRenderer(global) {
  "use strict";

  const formatters = global.HarnessFormatters || {};
  const escapeHtml = formatters.escapeHtml || ((value) => String(value ?? ""));
  const formatNumber = formatters.formatNumber || ((value) => String(value ?? ""));

  function metric(label, value, options = {}) {
    const valueHtml = options.valueHtml !== undefined
      ? options.valueHtml
      : escapeHtml(options.formatValue ? options.formatValue(value) : defaultMetricValue(value));
    return `<div class="mini-metric"><span>${escapeHtml(label)}</span><strong>${valueHtml}</strong></div>`;
  }

  function metrics(items = [], options = {}) {
    return items.map((item) => {
      const label = Array.isArray(item) ? item[0] : item.label;
      const value = Array.isArray(item) ? item[1] : item.value;
      const itemOptions = Array.isArray(item) ? options : { ...options, ...(item.options || {}) };
      return metric(label, value, itemOptions);
    }).join("");
  }

  function metricGrid(items = [], options = {}) {
    return `<div class="overview-grid">${metrics(items, options)}</div>`;
  }

  function badge(label, className = "", options = {}) {
    const classes = ["badge", className].filter(Boolean).join(" ");
    const title = options.title ? ` title="${escapeHtml(options.title)}"` : "";
    return `<span class="${escapeHtml(classes)}"${title}>${escapeHtml(label)}</span>`;
  }

  function badges(items = []) {
    return items.map((item) => Array.isArray(item) ? badge(item[0], item[1], item[2]) : badge(item.label, item.className, item.options)).join(" ");
  }

  function emptyRow(colspan, message) {
    return `<tr><td colspan="${Number(colspan) || 1}">${escapeHtml(message)}</td></tr>`;
  }

  function table(headers = [], rowsHtml = "", emptyMessage = "No rows.", options = {}) {
    const wrapClass = ["table-wrap", options.wrapClass].filter(Boolean).join(" ");
    const tableClass = options.tableClass ? ` class="${escapeHtml(options.tableClass)}"` : "";
    const body = rowsHtml || emptyRow(headers.length || options.colspan || 1, emptyMessage);
    return `<div class="${escapeHtml(wrapClass)}"><table${tableClass}><thead><tr>${headers.map((header) => `<th>${escapeHtml(header)}</th>`).join("")}</tr></thead><tbody>${body}</tbody></table></div>`;
  }

  function compactCode(value, options = {}) {
    const text = String(value ?? "");
    const limit = Number(options.limit) || 96;
    const expandedLimit = Number(options.expandedLimit) || 4096;
    const titleLimit = Number(options.titleLimit) || 256;
    const className = options.className || "raw-uds-preview";
    const preview = text.length > limit ? `${text.slice(0, limit).trimEnd()} ...` : text;
    if (text.length <= limit) return `<code class="${escapeHtml(className)}" title="${escapeHtml(text)}">${escapeHtml(text)}</code>`;
    const expanded = text.length > expandedLimit ? `${text.slice(0, expandedLimit).trimEnd()} ...` : text;
    const title = text.length > titleLimit ? `${formatNumber(text.length)} characters; expand for a capped preview` : text;
    const truncationNote = text.length > expandedLimit
      ? `<span class="raw-uds-truncation">Showing the first ${formatNumber(expandedLimit)} of ${formatNumber(text.length)} characters. Use the relevant export for the complete payload.</span>`
      : "";
    return `<details class="${escapeHtml(className)}" title="${escapeHtml(title)}">
      <summary><code>${escapeHtml(preview)}</code></summary>
      <code class="raw-uds-full">${escapeHtml(expanded)}</code>
      ${truncationNote}
    </details>`;
  }

  function rawBytesCell(value, options = {}) {
    return `<td class="raw-uds-cell">${compactCode(value, options)}</td>`;
  }

  function defaultMetricValue(value) {
    return typeof value === "number" ? formatNumber(value) : String(value ?? "");
  }

  global.HarnessUi = Object.freeze({
    badge,
    badges,
    emptyRow,
    compactCode,
    metric,
    metrics,
    metricGrid,
    rawBytesCell,
    table
  });
})(window);
