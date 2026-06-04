/**
 * Pure formatting helpers for table cells, exports, byte strings, and timings.
 *
 * These helpers deliberately avoid reading application state. Callers that need
 * report-relative values should pass that context in explicitly.
 */
(function registerFormatters(global) {
  "use strict";

  function hexByte(value) {
    return `0x${Number(value || 0).toString(16).padStart(2, "0")}`;
  }

  function hexWord(value) {
    return `0x${Number(value || 0).toString(16).padStart(4, "0")}`;
  }

  function bytesToHex(bytes) {
    return Array.from(bytes || [], (byte) => byte.toString(16).padStart(2, "0")).join(" ");
  }

  function hexToBytes(hex) {
    if (!hex) return new Uint8Array();
    return new Uint8Array(String(hex).split(/\s+/).filter((part) => /^[0-9a-f]{2}$/i.test(part)).map((part) => parseInt(part, 16)));
  }

  function bytesToAsciiPreview(bytes) {
    return Array.from(bytes || [], (byte) => byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : ".").join("").replace(/\.+$/g, "").trim();
  }

  function escapeHtml(value) {
    return String(value ?? "").replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" }[char]));
  }

  function formatCell(value) {
    if (value === null || value === undefined) return "";
    if (typeof value === "number") return Number.isInteger(value) ? formatNumber(value) : value.toFixed(6);
    return `<code>${escapeHtml(String(value))}</code>`;
  }

  function formatNumber(value) {
    return Number(value || 0).toLocaleString();
  }

  function formatBytes(value) {
    const units = ["B", "KB", "MB", "GB"];
    let size = value;
    let unit = 0;
    while (size >= 1024 && unit < units.length - 1) {
      size /= 1024;
      unit += 1;
    }
    return `${size.toFixed(unit ? 1 : 0)} ${units[unit]}`;
  }

  function formatRate(value) {
    if (value === null || value === undefined || !Number.isFinite(Number(value)) || Number(value) <= 0) return "n/a";
    return `${formatBytes(Number(value))}/s`;
  }

  function formatDurationValue(seconds) {
    if (seconds === null || seconds === undefined || !Number.isFinite(Number(seconds)) || Number(seconds) <= 0) return "n/a";
    const value = Number(seconds);
    if (value < 0.001) return `${(value * 1000000).toFixed(0)} us`;
    if (value < 1) return `${(value * 1000).toFixed(2)} ms`;
    if (value < 60) return `${value.toFixed(3)} s`;
    const minutes = Math.floor(value / 60);
    const rest = value % 60;
    return `${minutes}m ${rest.toFixed(1)}s`;
  }

  function formatMs(seconds) {
    if (seconds === null || seconds === undefined || Number.isNaN(Number(seconds))) return "";
    return `${(Number(seconds) * 1000).toFixed(3)} ms`;
  }

  function formatTimeDelta(timestamp, firstTimestamp = timestamp) {
    if (timestamp === null || timestamp === undefined) return "";
    const first = firstTimestamp || timestamp;
    return `+${Number(timestamp - first).toFixed(3)}s`;
  }

  function toCsv(rows, columns) {
    const escapeCsv = (value) => {
      const text = String(value ?? "");
      return /[",\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
    };
    return [columns.join(","), ...rows.map((row) => columns.map((col) => escapeCsv(row[col])).join(","))].join("\n");
  }

  global.HarnessFormatters = Object.freeze({
    hexByte,
    hexWord,
    bytesToHex,
    hexToBytes,
    bytesToAsciiPreview,
    escapeHtml,
    formatCell,
    formatNumber,
    formatBytes,
    formatRate,
    formatDurationValue,
    formatMs,
    formatTimeDelta,
    toCsv
  });
})(window);
