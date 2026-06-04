/**
 * UDS diagnostic aggregation.
 *
 * This module operates on decoded UDS event rows and builds the report-level
 * DID, DTC, request/response pairing, and transfer-session summaries.
 */
(function registerDiagnosticAnalysis(global) {
  "use strict";

  const {
    hexByte,
    hexToBytes,
    bytesToHex
  } = global.HarnessFormatters;
  const {
    decodeDtcRequest,
    decodeDtcResponse
  } = global.HarnessUds;

  function addUnique(list, value) {
    if (value && !list.includes(value)) list.push(value);
  }

  function buildDtcReads(report) {
    const dtcRows = [];
    const summary = new Map();
    const clearCommands = [];
    const pushSummary = (event, record) => {
      if (!record?.dtc) return;
      const key = `${event.ecuAddress}|${record.dtc}|${record.status || ""}`;
      if (!summary.has(key)) {
        summary.set(key, {
          recordType: "dtcSummary",
          ecuAddress: event.ecuAddress,
          testerAddress: event.testerAddress,
          dtc: record.dtc,
          status: record.status || "",
          statusLabels: record.statusLabels || "",
          responses: 0,
          firstTimestamp: event.timestamp,
          lastTimestamp: event.timestamp,
          latestPacket: event.packet
        });
      }
      const item = summary.get(key);
      item.responses += 1;
      item.firstTimestamp = Math.min(item.firstTimestamp, event.timestamp);
      item.lastTimestamp = Math.max(item.lastTimestamp, event.timestamp);
      item.latestPacket = event.packet;
    };
    for (const event of report.diagnostics.udsEvents || []) {
      if (!["0x14", "0x54", "0x19", "0x59", "0x7f"].includes(event.service)) continue;
      if (event.service === "0x7f" && event.originalService !== "0x19" && event.originalService !== "0x14") continue;
      if (event.service === "0x14") {
        const group = clearDtcGroup(event.raw);
        const clear = {
          ecuAddress: event.ecuAddress,
          testerAddress: event.testerAddress,
          eventId: event.id,
          timestamp: event.timestamp,
          packet: event.packet,
          group
        };
        clearCommands.push(clear);
        dtcRows.push({
          ecuAddress: event.ecuAddress,
          testerAddress: event.testerAddress,
          eventId: event.id,
          requestEventId: "",
          timestamp: event.timestamp,
          packet: event.packet,
          source: event.source,
          target: event.target,
          service: event.service,
          serviceName: event.serviceName,
          responseKind: event.responseKind,
          subFunction: "",
          subFunctionName: "",
          optionsHex: group,
          statusMask: "",
          dtcFormatIdentifier: "",
          dtcCount: "",
          nrc: "",
          nrcName: "",
          raw: event.raw,
          recordType: "clearRequest",
          resultType: "clear",
          dtc: group,
          status: "",
          statusLabels: "",
          snapshotRecordNumber: "",
          extendedDataRecordNumber: "",
          dataLength: "",
          payloadHex: "",
          payloadAscii: ""
        });
        continue;
      }
      if (event.service === "0x54" || event.originalService === "0x14") {
        dtcRows.push({
          ecuAddress: event.ecuAddress,
          testerAddress: event.testerAddress,
          eventId: event.id,
          requestEventId: event.requestEventId || "",
          timestamp: event.timestamp,
          packet: event.packet,
          source: event.source,
          target: event.target,
          service: event.service,
          serviceName: event.serviceName,
          responseKind: event.responseKind,
          subFunction: "",
          subFunctionName: "",
          optionsHex: "",
          statusMask: "",
          dtcFormatIdentifier: "",
          dtcCount: "",
          nrc: event.nrc || "",
          nrcName: event.nrcName || "",
          raw: event.raw,
          recordType: event.responseKind === "negative" ? "clearNegative" : "clearResponse",
          resultType: "clear",
          dtc: "",
          status: "",
          statusLabels: "",
          snapshotRecordNumber: "",
          extendedDataRecordNumber: "",
          dataLength: "",
          payloadHex: "",
          payloadAscii: ""
        });
        continue;
      }
      if (!event.dtc && (event.service === "0x19" || event.service === "0x59")) {
        const bytes = hexToBytes(event.raw);
        event.dtc = event.service === "0x19" ? decodeDtcRequest(bytes) : decodeDtcResponse(bytes);
      }
      const dtc = event.dtc || {};
      const base = {
        ecuAddress: event.ecuAddress,
        testerAddress: event.testerAddress,
        eventId: event.id,
        requestEventId: event.requestEventId || "",
        timestamp: event.timestamp,
        packet: event.packet,
        source: event.source,
        target: event.target,
        service: event.service,
        serviceName: event.serviceName,
        responseKind: event.responseKind,
        subFunction: dtc.subFunction !== null && dtc.subFunction !== undefined ? hexByte(dtc.subFunction) : "",
        subFunctionName: dtc.subFunctionName || "",
        optionsHex: dtc.optionsHex || "",
        statusMask: dtc.statusMask || dtc.statusAvailabilityMask || "",
        dtcFormatIdentifier: dtc.dtcFormatIdentifier || "",
        dtcCount: dtc.dtcCount ?? "",
        nrc: event.nrc || "",
        nrcName: event.nrcName || "",
        raw: event.raw
      };
      dtcRows.push({ ...base, recordType: event.service === "0x19" ? "request" : event.responseKind, resultType: dtc.resultType || "", dtc: dtc.dtc || "", status: "", statusLabels: "", snapshotRecordNumber: dtc.snapshotRecordNumber || "", extendedDataRecordNumber: dtc.extendedDataRecordNumber || "", dataLength: "", payloadHex: "", payloadAscii: "" });
      for (const record of dtc.dtcRecords || []) {
        pushSummary(event, record);
        dtcRows.push({ ...base, recordType: "dtcRecord", resultType: dtc.resultType || "dtcList", dtc: record.dtc, status: record.status || "", statusLabels: record.statusLabels || "", snapshotRecordNumber: "", extendedDataRecordNumber: "", dataLength: "", payloadHex: "", payloadAscii: "" });
      }
      for (const record of dtc.snapshotRecords || []) {
        pushSummary(event, record);
        dtcRows.push({ ...base, recordType: "snapshot", resultType: dtc.resultType || "snapshot", dtc: record.dtc, status: record.status || "", statusLabels: record.statusLabels || "", snapshotRecordNumber: record.snapshotRecordNumber || "", extendedDataRecordNumber: "", dataLength: record.dataLength ?? "", payloadHex: record.payloadHex || "", payloadAscii: record.payloadAscii || "" });
      }
      for (const record of dtc.extendedRecords || []) {
        pushSummary(event, record);
        dtcRows.push({ ...base, recordType: "extendedData", resultType: dtc.resultType || "extendedData", dtc: record.dtc, status: record.status || "", statusLabels: record.statusLabels || "", snapshotRecordNumber: "", extendedDataRecordNumber: record.extendedDataRecordNumber || "", dataLength: record.dataLength ?? "", payloadHex: record.payloadHex || "", payloadAscii: record.payloadAscii || "" });
      }
    }
    const summaryRows = Array.from(summary.values()).sort((a, b) => a.ecuAddress.localeCompare(b.ecuAddress) || a.dtc.localeCompare(b.dtc));
    for (const item of summaryRows) annotateClearPersistence(item, clearCommands);
    report.diagnostics.dtcReads = {
      rows: dtcRows,
      summary: summaryRows,
      clearCommands
    };
  }

  function clearDtcGroup(raw) {
    const bytes = hexToBytes(raw || "");
    return bytes.length >= 4 ? bytesToHex(bytes.slice(1, 4)).replaceAll(" ", "").toUpperCase() : "";
  }

  function annotateClearPersistence(summary, clearCommands = []) {
    const matching = clearCommands
      .filter((clear) => clear.ecuAddress === summary.ecuAddress && clear.timestamp <= summary.lastTimestamp && clearAppliesToDtc(clear.group, summary.dtc))
      .sort((a, b) => b.timestamp - a.timestamp || b.packet - a.packet);
    const clear = matching[0];
    summary.persistentAfterClear = Boolean(clear && summary.lastTimestamp > clear.timestamp);
    summary.clearGroup = clear?.group || "";
    summary.clearPacket = clear?.packet || "";
    summary.clearTimestamp = clear?.timestamp ?? null;
  }

  function clearAppliesToDtc(group, dtc) {
    const clearGroup = String(group || "").replace(/[^0-9a-f]/gi, "").toUpperCase();
    const code = String(dtc || "").replace(/[^0-9a-f]/gi, "").toUpperCase();
    if (clearGroup.length !== 6 || code.length !== 6) return false;
    if (clearGroup === "FFFFFF") return true;
    for (let index = 0; index < 6; index += 2) {
      const groupByte = clearGroup.slice(index, index + 2);
      if (groupByte !== "FF" && groupByte !== code.slice(index, index + 2)) return false;
    }
    return true;
  }

  function pairUdsEvents(report) {
    const pending = new Map();
    const functionalPending = new Map();
    for (const event of report.diagnostics.udsEvents) {
      const key = `${event.testerAddress}|${event.ecuAddress}`;
      if (event.direction === "request") {
        const sid = parseInt(event.service.slice(2), 16);
        const pendingKey = `${key}|${sid}`;
        if (!pending.has(pendingKey)) pending.set(pendingKey, []);
        pending.get(pendingKey).push(event);
        if (isFunctionalLogicalAddress(event.target)) {
          const functionalKey = `${event.testerAddress}|${sid}`;
          if (!functionalPending.has(functionalKey)) functionalPending.set(functionalKey, []);
          functionalPending.get(functionalKey).push(event);
          event.functionalTarget = event.target;
        }
        continue;
      }
      const originalSid = event.originalService ? parseInt(event.originalService.slice(2), 16) : null;
      if (originalSid === null) continue;
      const pendingKey = `${key}|${originalSid}`;
      const candidates = pending.get(pendingKey) || [];
      const requestIndex = findMatchingUdsRequestIndex(candidates, event, originalSid);
      let request = requestIndex >= 0 ? candidates[requestIndex] : null;
      let functionalRequest = false;
      let functionalCandidates = [];
      let functionalIndex = -1;
      if (!request) {
        const functionalKey = `${event.testerAddress}|${originalSid}`;
        functionalCandidates = functionalPending.get(functionalKey) || [];
        functionalIndex = findMatchingUdsRequestIndex(functionalCandidates, event, originalSid);
        request = functionalIndex >= 0 ? functionalCandidates[functionalIndex] : null;
        functionalRequest = Boolean(request);
      }
      if (request) {
        request.paired = true;
        request.responseEventId ||= event.id;
        addUnique(request.responseEventIds || (request.responseEventIds = []), event.id);
        event.paired = true;
        event.requestEventId = request.id;
        if (functionalRequest) {
          event.functionalRequest = true;
          event.functionalTarget = request.target;
        }
        if (!event.did && request.did) {
          event.did = request.did;
          event.didName = request.didName;
        }
        if (event.responseKind !== "pending" && !functionalRequest) {
          candidates.splice(requestIndex, 1);
          if (!candidates.length) pending.delete(pendingKey);
        }
      } else {
        report.diagnostics.unmatchedMessages.push(event);
      }
    }
  }

  function isFunctionalLogicalAddress(address) {
    const value = typeof address === "number" ? address : parseInt(String(address || "").replace(/^0x/i, ""), 16);
    return Number.isFinite(value) && value >= 0xe000 && value <= 0xefff;
  }

  function findMatchingUdsRequestIndex(candidates, response, originalSid) {
    if (!candidates.length) return -1;
    const responseCounter = response.transfer?.blockCounter;
    if (originalSid === 0x36 && responseCounter !== null && responseCounter !== undefined) {
      const index = candidates.findIndex((request) => request.transfer?.blockCounter === responseCounter);
      if (index >= 0) return index;
    }
    if (originalSid === 0x22 && response.did) {
      const index = candidates.findIndex((request) => request.did === response.did);
      if (index >= 0) return index;
    }
    if (originalSid === 0x31 && response.routineId) {
      const index = candidates.findIndex((request) => request.routineId === response.routineId);
      if (index >= 0) return index;
    }
    return 0;
  }

  function buildDidReads(report) {
    const groups = new Map();
    for (const event of report.diagnostics.udsEvents) {
      if (!event.did || !["0x22", "0x62", "0x7f"].includes(event.service)) continue;
      if (event.service === "0x7f" && event.originalService !== "0x22") continue;
      const key = `${event.ecuAddress}|${event.did}`;
      if (!groups.has(key)) {
        groups.set(key, {
          ecuAddress: event.ecuAddress,
          did: event.did,
          name: event.didName,
          reads: 0,
          responses: 0,
          negatives: 0,
          pending: 0,
          latestValueHex: "",
          latestValueAscii: "",
          firstTimestamp: event.timestamp,
          lastTimestamp: event.timestamp
        });
      }
      const item = groups.get(key);
      item.firstTimestamp = Math.min(item.firstTimestamp, event.timestamp);
      item.lastTimestamp = Math.max(item.lastTimestamp, event.timestamp);
      if (event.service === "0x22") item.reads += 1;
      if (event.service === "0x62") {
        item.responses += 1;
        item.latestValueHex = event.valueHex;
        item.latestValueAscii = event.valueAscii;
      }
      if (event.responseKind === "negative") item.negatives += 1;
      if (event.responseKind === "pending") item.pending += 1;
    }
    report.diagnostics.didReads = Array.from(groups.values()).sort((a, b) => a.ecuAddress.localeCompare(b.ecuAddress) || a.did.localeCompare(b.did));
  }

  function buildTransfers(report) {
    const activeTransfers = new Map();
    for (const event of report.diagnostics.udsEvents) {
      const sid = event.service;
      if (!["0x34", "0x35", "0x36", "0x37", "0x38", "0x74", "0x75", "0x76", "0x77", "0x78", "0x7f"].includes(sid)) continue;
      if (sid === "0x7f" && !["0x34", "0x35", "0x36", "0x37", "0x38"].includes(event.originalService)) continue;
      const ecu = event.ecuAddress;
      if ((sid === "0x34" || sid === "0x35" || sid === "0x38") && event.direction === "request") {
        const transfer = {
          id: report.diagnostics.transfers.length + 1,
          ecuAddress: ecu,
          testerAddress: event.testerAddress,
          direction: sid === "0x35" ? "upload" : sid === "0x38" ? "fileTransfer" : "download",
          service: event.service,
          startTimestamp: event.timestamp,
          endTimestamp: event.timestamp,
          requestPacket: event.packet,
          requestEventId: event.id,
          request: event.transfer || {},
          responses: 0,
          pending: 0,
          negatives: 0,
          blocks: 0,
          expectedBlocks: null,
          expectedBlocksEstimated: false,
          expectedBlockShortfall: null,
          acknowledgedBlocks: 0,
          responseBlockCounters: [],
          dataBlocks: [],
          ackBlocks: [],
          coordinationBlocks: [],
          pendingEvents: [],
          negativeEvents: [],
          timelineEventIds: [event.id],
          suppressedDuplicateMessages: 0,
          captureNotes: [],
          dataBlockPackets: [],
          maxBlockLength: null,
          expectedNextBlock: null,
          missingSequences: [],
          responseCodes: [],
          dataHex: "",
          reconstructedBytes: 0,
          exportable: false,
          status: "open"
        };
        activeTransfers.set(transferKey(event), transfer);
        report.diagnostics.transfers.push(transfer);
        continue;
      }
      const transfer = activeTransfers.get(transferKey(event));
      if (!transfer) continue;
      transfer.endTimestamp = event.timestamp;
      if (event.responseKind === "pending") {
        transfer.pending += 1;
        transfer.pendingEvents.push({ eventId: event.id, packet: event.packet, timestamp: event.timestamp, service: event.originalService, nrc: event.nrc, nrcName: event.nrcName });
        transfer.timelineEventIds.push(event.id);
        continue;
      }
      if (event.responseKind === "negative") {
        transfer.negatives += 1;
        transfer.responseCodes.push(`${event.originalService} ${event.nrc} ${event.nrcName}`);
        transfer.negativeEvents.push({ eventId: event.id, packet: event.packet, timestamp: event.timestamp, service: event.originalService, nrc: event.nrc, nrcName: event.nrcName });
        transfer.timelineEventIds.push(event.id);
        continue;
      }
      transfer.responses += event.direction === "response" ? 1 : 0;
      transfer.timelineEventIds.push(event.id);
      if ((sid === "0x74" || sid === "0x75") && event.transfer?.maxBlockLength) {
        transfer.maxBlockLength = event.transfer.maxBlockLength;
        const payloadCapacity = Math.max(1, event.transfer.maxBlockLength - 2);
        if (transfer.request?.memorySize) {
          transfer.expectedBlocks = Math.ceil(transfer.request.memorySize / payloadCapacity);
          transfer.expectedBlocksEstimated = true;
        }
      }
      if (transfer.direction !== "upload" && sid === "0x76" && event.transfer?.blockCounter !== null && event.transfer?.blockCounter !== undefined) {
        transfer.acknowledgedBlocks += 1;
        addUnique(transfer.responseBlockCounters, hexByte(event.transfer.blockCounter));
        transfer.ackBlocks.push({ eventId: event.id, requestEventId: event.requestEventId || null, packet: event.packet, timestamp: event.timestamp, counter: hexByte(event.transfer.blockCounter), raw: event.raw });
      }
      if (transfer.direction === "upload" && sid === "0x36" && event.transfer?.blockCounter !== null && event.transfer?.blockCounter !== undefined) {
        transfer.coordinationBlocks.push({ eventId: event.id, packet: event.packet, timestamp: event.timestamp, counter: hexByte(event.transfer.blockCounter), raw: event.raw });
      }
      if (isTransferDataPayload(transfer, event)) recordTransferBlock(transfer, event);
      if (sid === "0x37" || sid === "0x77") {
        if (transfer.expectedBlocks !== null && transfer.blocks < transfer.expectedBlocks) {
          transfer.expectedBlockShortfall = { expected: transfer.expectedBlocks, observed: transfer.blocks };
        }
        transfer.status = transfer.negatives ? "completed with errors" : transfer.missingSequences.length ? "completed with gaps" : "completed";
        transfer.exportable = transfer.blocks > 0 && transfer.missingSequences.length === 0 && transfer.negatives === 0;
        activeTransfers.delete(transferKey(event));
      }
    }
    for (const transfer of report.diagnostics.transfers) {
      if (transfer.status === "open") transfer.exportable = false;
    }
  }

  function transferKey(event) {
    return `${event.ecuAddress || ""}|${event.testerAddress || ""}`;
  }

  function isTransferDataPayload(transfer, event) {
    if (!event.transfer) return false;
    if (transfer.direction === "upload") return event.service === "0x76" && event.direction === "response";
    return event.service === "0x36" && event.direction === "request";
  }

  function recordTransferBlock(transfer, event) {
    const block = event.transfer.blockCounter;
    const counter = block === null ? "" : hexByte(block);
    const lastBlock = (transfer.dataBlocks || [])[transfer.dataBlocks.length - 1];
    const adjacentExactDuplicate = lastBlock && lastBlock.counter === counter && lastBlock.raw === event.raw && lastBlock.source === event.source && lastBlock.target === event.target;
    if (adjacentExactDuplicate) {
      transfer.suppressedDuplicateMessages += 1;
      addUnique(transfer.captureNotes, `Suppressed adjacent duplicate TransferData ${counter || "unknown counter"} at packet ${event.packet}`);
      return;
    }
    if (block !== null && transfer.expectedNextBlock !== null && block !== transfer.expectedNextBlock && isForwardCounterGap(transfer.expectedNextBlock, block)) {
      transfer.missingSequences.push(`${hexByte(transfer.expectedNextBlock)}->${hexByte(block)}`);
    } else if (block !== null && transfer.expectedNextBlock !== null && block !== transfer.expectedNextBlock) {
      addUnique(transfer.captureNotes, `Observed non-forward TransferData counter transition ${hexByte(transfer.expectedNextBlock)}->${hexByte(block)} at packet ${event.packet}; treated as restart/retry context, not missing payload.`);
    }
    transfer.expectedNextBlock = block === null ? null : (block + 1) & 0xff;
    transfer.blocks += 1;
    transfer.dataBlockPackets.push(event.packet);
    const bytes = hexToBytes(event.raw).slice(2);
    transfer.reconstructedBytes += bytes.length;
    const blockHex = bytesToHex(bytes);
    transfer.dataHex += transfer.dataHex && blockHex ? ` ${blockHex}` : blockHex;
    transfer.dataBlocks.push({
      eventId: event.id,
      packet: event.packet,
      timestamp: event.timestamp,
      direction: event.direction,
      source: event.source,
      target: event.target,
      counter,
      payloadBytes: bytes.length,
      payloadHex: blockHex,
      raw: event.raw
    });
  }

  function isForwardCounterGap(expected, observed) {
    if (observed === expected) return false;
    return observed > expected || expected - observed > 128;
  }

  global.HarnessDiagnosticAnalysis = Object.freeze({
    pairUdsEvents,
    buildDidReads,
    buildDtcReads,
    buildTransfers,
    isFunctionalLogicalAddress,
    findMatchingUdsRequestIndex,
    transferKey,
    isForwardCounterGap
  });
})(window);
