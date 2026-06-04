/**
 * Pure UDS naming and payload decoding helpers.
 *
 * The application layer owns packet/report mutation; this module only turns UDS
 * bytes into stable decoded objects.
 */
(function registerUdsDecoder(global) {
  "use strict";

  const {
    UDS_SERVICE_NAMES,
    UDS_NRC_NAMES,
    DTC_SUBFUNCTION_NAMES,
    DTC_STATUS_BITS
  } = global.HarnessProtocol;
  const {
    hexByte,
    bytesToHex,
    bytesToAsciiPreview
  } = global.HarnessFormatters;

  function serviceName(sid, userMappings = {}) {
    return userMappings.services?.[hexByte(sid)] ||
      userMappings.services?.[hexByte(sid).toLowerCase()] ||
      UDS_SERVICE_NAMES[sid] ||
      `Service ${hexByte(sid)}`;
  }

  function nrcName(nrc, userMappings = {}) {
    return userMappings.nrcs?.[hexByte(nrc)] ||
      userMappings.nrcs?.[hexByte(nrc).toLowerCase()] ||
      UDS_NRC_NAMES[nrc] ||
      `NRC ${hexByte(nrc)}`;
  }

  function dtcSubFunctionName(subFunction) {
    const value = typeof subFunction === "string" ? parseInt(subFunction.slice(2), 16) : subFunction;
    return DTC_SUBFUNCTION_NAMES[value] || (Number.isFinite(value) ? `DTC sub-function ${hexByte(value)}` : "");
  }

  function dtcStatusLabels(statusByte) {
    const value = typeof statusByte === "string" ? parseInt(statusByte.slice(2), 16) : statusByte;
    if (!Number.isFinite(value)) return "";
    return DTC_STATUS_BITS.filter((_, bit) => value & (1 << bit)).join(", ") || "none";
  }

  function decodeUds(uds, userMappings = {}) {
    const sid = uds[0];
    const decoded = {
      sid,
      name: serviceName(sid, userMappings),
      originalSid: null,
      nrc: null,
      did: null,
      routineId: null,
      subFunction: null,
      dtc: null,
      transfer: null,
      valueHex: "",
      valueAscii: ""
    };
    if (sid === 0x7f && uds.length >= 3) {
      decoded.originalSid = uds[1];
      decoded.nrc = uds[2];
      decoded.name = "Negative Response";
      return decoded;
    }
    const baseSid = sid >= 0x40 ? sid - 0x40 : sid;
    if (sid >= 0x40) decoded.originalSid = baseSid;
    if ([0x10, 0x11, 0x27, 0x28, 0x3e, 0x50, 0x51, 0x67, 0x7e, 0x83, 0x84, 0x85, 0x86, 0x87].includes(sid) && uds.length >= 2) {
      decoded.subFunction = uds[1];
    }
    if (sid === 0x19) decoded.dtc = decodeDtcRequest(uds);
    if (sid === 0x59) decoded.dtc = decodeDtcResponse(uds);
    if ((sid === 0x22 || sid === 0x62 || sid === 0x2e || sid === 0x6e || sid === 0x2f || sid === 0x6f) && uds.length >= 3) {
      decoded.did = (uds[1] << 8) | uds[2];
      if (uds.length > 3) {
        const value = uds.slice(3);
        decoded.valueHex = bytesToHex(value);
        decoded.valueAscii = bytesToAsciiPreview(value);
      }
    }
    if ((sid === 0x31 || sid === 0x71) && uds.length >= 4) {
      decoded.subFunction = uds[1];
      decoded.routineId = (uds[2] << 8) | uds[3];
    }
    if (sid === 0x34 || sid === 0x35) decoded.transfer = decodeRequestTransfer(uds, userMappings);
    if (sid === 0x74 || sid === 0x75) decoded.transfer = decodeTransferRequestResponse(uds, userMappings);
    if (sid === 0x36 || sid === 0x76) decoded.transfer = decodeTransferData(uds, userMappings);
    if (sid === 0x37 || sid === 0x77 || sid === 0x38 || sid === 0x78) {
      decoded.transfer = { type: serviceName(sid, userMappings), rawLength: uds.length };
    }
    return decoded;
  }

  function dtcCode(bytes) {
    return bytes?.length === 3 ? bytesToHex(bytes).replaceAll(" ", "").toUpperCase() : "";
  }

  function decodeDtcRequest(uds) {
    const subFunction = uds.length >= 2 ? uds[1] : null;
    const optionBytes = uds.slice(2);
    const out = {
      subFunction,
      subFunctionName: subFunction === null ? "" : dtcSubFunctionName(subFunction),
      optionsHex: bytesToHex(optionBytes),
      resultType: "request"
    };
    if (optionBytes.length >= 1 && [0x01, 0x02, 0x07, 0x08, 0x0f, 0x11, 0x12, 0x13, 0x17, 0x1a].includes(subFunction)) out.statusMask = hexByte(optionBytes[0]);
    if (optionBytes.length >= 3 && [0x04, 0x06, 0x09, 0x10, 0x18, 0x19].includes(subFunction)) out.dtc = dtcCode(optionBytes.slice(0, 3));
    if (optionBytes.length >= 4 && [0x04, 0x18].includes(subFunction)) out.snapshotRecordNumber = hexByte(optionBytes[3]);
    if (optionBytes.length >= 4 && [0x06, 0x10, 0x19].includes(subFunction)) out.extendedDataRecordNumber = hexByte(optionBytes[3]);
    if (optionBytes.length >= 1 && subFunction === 0x05) out.snapshotRecordNumber = hexByte(optionBytes[0]);
    return out;
  }

  function decodeDtcResponse(uds) {
    const subFunction = uds.length >= 2 ? uds[1] : null;
    const out = {
      subFunction,
      subFunctionName: subFunction === null ? "" : dtcSubFunctionName(subFunction),
      optionsHex: bytesToHex(uds.slice(2)),
      resultType: "unknown",
      dtcRecords: [],
      snapshotRecords: [],
      extendedRecords: []
    };
    const body = uds.slice(2);
    if ([0x01, 0x07, 0x11, 0x12].includes(subFunction) && body.length >= 4) {
      out.resultType = "count";
      out.statusAvailabilityMask = hexByte(body[0]);
      out.dtcFormatIdentifier = hexByte(body[1]);
      out.dtcCount = (body[2] << 8) | body[3];
      return out;
    }
    if ([0x02, 0x08, 0x0a, 0x0f, 0x13, 0x15, 0x17, 0x1a].includes(subFunction) && body.length >= 1) {
      out.resultType = "dtcList";
      out.statusAvailabilityMask = hexByte(body[0]);
      const records = body.slice(1);
      if (records.length % 4 === 0) {
        for (let i = 0; i < records.length; i += 4) {
          out.dtcRecords.push({ dtc: dtcCode(records.slice(i, i + 3)), status: hexByte(records[i + 3]), statusLabels: dtcStatusLabels(records[i + 3]) });
        }
      }
      return out;
    }
    if (subFunction === 0x03 && body.length >= 4) {
      out.resultType = "snapshotIdentification";
      for (let i = 0; i + 3 < body.length; i += 4) {
        out.snapshotRecords.push({ dtc: dtcCode(body.slice(i, i + 3)), snapshotRecordNumber: hexByte(body[i + 3]), payloadHex: "", payloadAscii: "", dataLength: 0 });
      }
      return out;
    }
    if ([0x04, 0x05, 0x18].includes(subFunction) && body.length >= 5) {
      out.resultType = "snapshot";
      const statusOffset = body.length >= 6 ? 3 : null;
      const recordOffset = statusOffset === null ? 3 : 4;
      const payloadOffset = recordOffset + 1;
      const payload = body.slice(payloadOffset);
      out.snapshotRecords.push({
        dtc: dtcCode(body.slice(0, 3)),
        status: statusOffset === null ? null : hexByte(body[statusOffset]),
        statusLabels: statusOffset === null ? "" : dtcStatusLabels(body[statusOffset]),
        snapshotRecordNumber: hexByte(body[recordOffset]),
        dataLength: payload.length,
        payloadHex: bytesToHex(payload.slice(0, 64)),
        payloadAscii: bytesToAsciiPreview(payload.slice(0, 64))
      });
      return out;
    }
    if ([0x06, 0x10, 0x19].includes(subFunction) && body.length >= 5) {
      out.resultType = "extendedData";
      const statusOffset = body.length >= 6 ? 3 : null;
      const recordOffset = statusOffset === null ? 3 : 4;
      const payloadOffset = recordOffset + 1;
      const payload = body.slice(payloadOffset);
      out.extendedRecords.push({
        dtc: dtcCode(body.slice(0, 3)),
        status: statusOffset === null ? null : hexByte(body[statusOffset]),
        statusLabels: statusOffset === null ? "" : dtcStatusLabels(body[statusOffset]),
        extendedDataRecordNumber: hexByte(body[recordOffset]),
        dataLength: payload.length,
        payloadHex: bytesToHex(payload.slice(0, 64)),
        payloadAscii: bytesToAsciiPreview(payload.slice(0, 64))
      });
      return out;
    }
    return out;
  }

  function decodeRequestTransfer(uds, userMappings = {}) {
    const dataFormat = uds[1] ?? null;
    const lengthFormat = uds[2] ?? null;
    const addressLength = lengthFormat === null ? 0 : lengthFormat & 0x0f;
    const sizeLength = lengthFormat === null ? 0 : lengthFormat >> 4;
    const addressBytes = uds.slice(3, 3 + addressLength);
    const sizeBytes = uds.slice(3 + addressLength, 3 + addressLength + sizeLength);
    return {
      type: serviceName(uds[0], userMappings),
      dataFormat: dataFormat === null ? null : hexByte(dataFormat),
      lengthFormat: lengthFormat === null ? null : hexByte(lengthFormat),
      memoryAddress: addressBytes.length ? `0x${Array.from(addressBytes, (b) => b.toString(16).padStart(2, "0")).join("")}` : "",
      memorySize: sizeBytes.length ? parseInt(Array.from(sizeBytes, (b) => b.toString(16).padStart(2, "0")).join(""), 16) : null
    };
  }

  function decodeTransferRequestResponse(uds, userMappings = {}) {
    const lengthFormat = uds[1] ?? null;
    const lengthBytes = lengthFormat === null ? 0 : (lengthFormat >> 4) || (lengthFormat & 0x0f);
    const valueBytes = uds.slice(2, 2 + lengthBytes);
    const maxBlockLength = valueBytes.length ? parseInt(Array.from(valueBytes, (b) => b.toString(16).padStart(2, "0")).join(""), 16) : null;
    return {
      type: serviceName(uds[0], userMappings),
      lengthFormat: lengthFormat === null ? null : hexByte(lengthFormat),
      maxBlockLength
    };
  }

  function decodeTransferData(uds, userMappings = {}) {
    const blockCounter = uds.length >= 2 ? uds[1] : null;
    const data = uds.slice(2);
    return {
      type: serviceName(uds[0], userMappings),
      blockCounter,
      dataLength: data.length,
      dataHex: bytesToHex(data.slice(0, 32)),
      dataAscii: bytesToAsciiPreview(data.slice(0, 64))
    };
  }

  global.HarnessUds = Object.freeze({
    serviceName,
    nrcName,
    dtcSubFunctionName,
    dtcStatusLabels,
    decodeUds,
    dtcCode,
    decodeDtcRequest,
    decodeDtcResponse,
    decodeRequestTransfer,
    decodeTransferRequestResponse,
    decodeTransferData
  });
})(window);
