/**
 * Pure helpers for user-provided ECU, DID, routine, and CSV name mappings.
 */
(function registerMappingUtils(global) {
  "use strict";

  const { hexWord, escapeHtml } = global.HarnessFormatters;

  function normaliseLogicalAddress(value) {
    const raw = String(value || "").trim();
    if (!raw) return "";
    const embeddedHex = raw.match(/0x([0-9a-f]{1,4})\b/i);
    const hex = embeddedHex
      ? embeddedHex[1].toLowerCase()
      : raw.toLowerCase().replace(/^0x/, "").replace(/[^0-9a-f]/g, "");
    if (!hex) return "";
    if (hex.length > 4) return "";
    return `0x${hex.padStart(4, "0")}`;
  }

  function normaliseDecimalLogicalAddress(value) {
    const raw = String(value || "").trim();
    if (!/^\d+$/.test(raw)) return "";
    const decimal = Number.parseInt(raw, 10);
    if (!Number.isInteger(decimal) || decimal < 0 || decimal > 0xffff) return "";
    return `0x${decimal.toString(16).padStart(4, "0")}`;
  }

  function looksLikeAddressHeader(header) {
    const exact = [
      "logicaladdress",
      "logicaladdresshex",
      "logicaladdr",
      "logical",
      "address",
      "ecuaddress",
      "ecuaddresshex",
      "doiplogicaladdress",
      "doipaddress",
      "diagaddress",
      "diagnosticaddress",
      "diagnosticlogicaladdress",
      "sourceaddress",
      "targetaddress",
      "sa"
    ];
    return exact.includes(header) ||
      header.includes("logical") && header.includes("address") ||
      header.includes("diagnostic") && header.includes("address") ||
      header.includes("diag") && header.includes("address") ||
      header.includes("doip") && header.includes("address");
  }

  function looksLikeNameHeader(header) {
    const exact = ["name", "ecu", "label", "friendlyname", "ecuname", "node", "nodename", "unit", "unitname"];
    return exact.includes(header) || header.endsWith("name") || header.endsWith("label");
  }

  function firstLogicalAddressCell(cells) {
    return cells.find((cell) => normaliseLogicalAddress(cell)) || "";
  }

  function splitCsvLine(line) {
    const cells = [];
    let current = "";
    let quoted = false;
    for (let index = 0; index < line.length; index += 1) {
      const char = line[index];
      if (char === "\"" && quoted && line[index + 1] === "\"") {
        current += "\"";
        index += 1;
      } else if (char === "\"") {
        quoted = !quoted;
      } else if (char === "," && !quoted) {
        cells.push(current.trim());
        current = "";
      } else {
        current += char;
      }
    }
    cells.push(current.trim());
    return cells;
  }

  function parseEcuMapCsv(text) {
    const lines = String(text || "").split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
    if (!lines.length) return {};
    const first = splitCsvLine(lines[0]).map((cell) => cell.toLowerCase().replace(/[^a-z0-9]/g, ""));
    const acronymHeaders = ["acronym", "ecuacronym", "shortname", "shortlabel", "shortcode", "alias"];
    const addressIndexCandidate = first.findIndex(looksLikeAddressHeader);
    const acronymIndexCandidate = first.findIndex((cell) => acronymHeaders.includes(cell));
    const nameIndexCandidate = first.findIndex(looksLikeNameHeader);
    const hasHeader = addressIndexCandidate >= 0 && (acronymIndexCandidate >= 0 || nameIndexCandidate >= 0);
    const addressIndex = hasHeader ? addressIndexCandidate : 0;
    const acronymIndex = hasHeader ? first.findIndex((cell) => acronymHeaders.includes(cell)) : -1;
    const nameIndex = hasHeader ? nameIndexCandidate : 1;
    const rows = hasHeader ? lines.slice(1) : lines;
    const map = {};
    for (const line of rows) {
      const cells = splitCsvLine(line);
      let address = cells[addressIndex] || firstLogicalAddressCell(cells);
      let name = hasHeader && acronymIndex >= 0 ? cells[acronymIndex] || cells[nameIndex] || "" : cells[nameIndex] || "";
      if (!hasHeader && !normaliseLogicalAddress(address) && normaliseLogicalAddress(name)) {
        [address, name] = [name, address];
      }
      const key = normaliseLogicalAddress(address);
      const label = String(name || "").trim();
      if (key && label) {
        map[key] = label;
        const decimalKey = normaliseDecimalLogicalAddress(address);
        if (decimalKey && !map[decimalKey]) map[decimalKey] = label;
      }
    }
    if (!Object.keys(map).length && lines.length) throw new Error("No logical-address mappings found. Use columns such as logicalAddress,name.");
    return map;
  }

  function didName(did, userMappings = {}) {
    return userMappings.dids?.[hexWord(did)] || userMappings.dids?.[hexWord(did).toLowerCase()] || "";
  }

  function routineName(routineId, userMappings = {}) {
    const key = typeof routineId === "number" ? hexWord(routineId) : String(routineId || "");
    return userMappings.routines?.[key] || userMappings.routines?.[key.toLowerCase()] || "";
  }

  function ecuName(address, userMappings = {}, importedEcuMap = {}) {
    const key = normaliseLogicalAddress(address);
    const compactKey = key.replace(/^0x0+/, "0x");
    const decimalAliasKey = normaliseLogicalAddress(String(Number.parseInt(String(key || "0x0").replace(/^0x/, ""), 16)));
    return importedEcuMap[key] ||
      importedEcuMap[compactKey] ||
      importedEcuMap[String(address || "").toLowerCase()] ||
      importedEcuMap[address] ||
      importedEcuMap[decimalAliasKey] ||
      userMappings.ecus?.[address] ||
      userMappings.ecus?.[String(address || "").toLowerCase()] ||
      userMappings.ecus?.[key] ||
      userMappings.ecus?.[compactKey] ||
      "";
  }

  function ecuLabel(address, options = {}, userMappings = {}, importedEcuMap = {}) {
    const name = ecuName(address, userMappings, importedEcuMap);
    if (!name) return String(address || "");
    if (options.withAddress) return `${name} (${address})`;
    return name;
  }

  function ecuCode(address, options = {}, userMappings = {}, importedEcuMap = {}) {
    return `<code title="${escapeHtml(String(address || ""))}">${escapeHtml(ecuLabel(address, options, userMappings, importedEcuMap))}</code>`;
  }

  global.HarnessMappingUtils = Object.freeze({
    normaliseLogicalAddress,
    normaliseDecimalLogicalAddress,
    splitCsvLine,
    parseEcuMapCsv,
    didName,
    routineName,
    ecuName,
    ecuLabel,
    ecuCode
  });
})(window);
