/**
 * Software download/session analysis for UDS transfer workflows.
 */
(function registerDownloadAnalysis(global) {
  "use strict";

  const formatters = global.HarnessFormatters || {};
  const tcpAnalysis = global.HarnessTcpAnalysis || {};

  function addUnique(list, value) {
    if (value && !list.includes(value)) list.push(value);
  }

  function defaultOptions(options = {}) {
    return {
      ecuLabel: options.ecuLabel || ((address) => address),
      formatNumber: options.formatNumber || formatters.formatNumber || ((value) => String(value)),
      hexByte: options.hexByte || formatters.hexByte || ((value) => `0x${Number(value || 0).toString(16).padStart(2, "0")}`),
      percentile: options.percentile || tcpAnalysis.percentile || ((values) => values.filter(Number.isFinite)[0] ?? null),
      tcpFlowKey: options.tcpFlowKey || ((srcIp, srcPort, dstIp, dstPort) => [`${srcIp}:${srcPort}`, `${dstIp}:${dstPort}`].sort().join(" <-> "))
    };
  }

  function buildDownloadAnalysis(report, options = {}) {
    const opts = defaultOptions(options);
    const sessions = (report.diagnostics?.transfers || []).map((transfer) => enrichDownloadSession(report, transfer, opts));
    const findings = sessions.flatMap((session) => session.validation.map((finding) => ({
      sessionId: session.id,
      ecuAddress: session.ecuAddress,
      ...finding
    })));
    const groups = buildDownloadGroups(sessions);
    const matrixRows = buildDownloadMatrixRows(groups, opts);
    return {
      sessions,
      groups,
      matrixRows,
      findings,
      metrics: {
        sessions: sessions.length,
        downloads: sessions.filter((item) => item.sessionType === "download").length,
        uploads: sessions.filter((item) => item.sessionType === "upload").length,
        fileTransfers: sessions.filter((item) => item.sessionType === "fileTransfer").length,
        exportable: sessions.filter((item) => item.hexExportable).length,
        errors: findings.filter((item) => item.severity === "error").length,
        warnings: findings.filter((item) => item.severity === "warning").length
      }
    };
  }

  function enrichDownloadSession(report, transfer, options = {}) {
    const opts = defaultOptions(options);
    const ackObservations = downloadAckObservations(report, transfer, opts);
    const enrichedTransfer = assignObservedDownloadAcks(transfer, ackObservations);
    const events = transferEvents(report, enrichedTransfer, ackObservations);
    const ackMismatchSummary = downloadAckMismatchSummary(enrichedTransfer, ackObservations);
    const validation = validateDownloadSession(report, enrichedTransfer, events, opts, ackMismatchSummary);
    const severity = validation.some((item) => item.severity === "error") ? "error" : validation.some((item) => item.severity === "warning") ? "warning" : "ok";
    const requestedBytes = enrichedTransfer.request?.memorySize || null;
    const observedPayloadBytes = enrichedTransfer.reconstructedBytes || 0;
    const progressPayloadBytes = requestedBytes ? Math.min(observedPayloadBytes, requestedBytes) : observedPayloadBytes;
    const progress = requestedBytes ? Math.min(1, progressPayloadBytes / requestedBytes) : null;
    const duplicateCounters = downloadDuplicateFindings(enrichedTransfer, { ackMismatchSummary })
      .filter((item) => item.title === "TransferData block counters reused with different payload")
      .flatMap((item) => item.counters || [item.detail.match(/0x[0-9a-f]+/i)?.[0]].filter(Boolean));
    const ackHealth = downloadAckHealth(enrichedTransfer, ackObservations);
    const rate = buildTransferRateAnalysis(enrichedTransfer, opts);
    const hexExportable = enrichedTransfer.exportable && validation.every((item) => item.severity !== "error" && !(item.category === "Completeness" && item.severity === "warning")) && (enrichedTransfer.dataBlocks || []).length > 0;
    return {
      ...enrichedTransfer,
      gatewayIp: downloadGatewayIp(report, enrichedTransfer, events),
      gatewayLabel: downloadGatewayLabel(report, enrichedTransfer, events),
      sessionType: enrichedTransfer.direction === "fileTransfer" ? "fileTransfer" : enrichedTransfer.direction,
      typeLabel: enrichedTransfer.direction === "upload" ? "RequestUpload" : enrichedTransfer.direction === "fileTransfer" ? "RequestFileTransfer" : "RequestDownload",
      requestedBytes,
      observedPayloadBytes,
      progressPayloadBytes,
      progress,
      severity,
      validation,
      hexExportable,
      ackObservedEvents: ackObservations.events,
      ackMissingCounters: ackHealth.missing,
      ackUnassignedCounters: ackHealth.unassigned,
      ackExtraCounters: ackHealth.extra,
      ackMismatchSummary,
      rate,
      duplicateCounters: Array.from(new Set(duplicateCounters)),
      events
    };
  }

  function assignObservedDownloadAcks(transfer, ackObservations) {
    if (transfer.direction === "upload") return transfer;
    const ackBlocks = [...(transfer.ackBlocks || [])];
    const usedAckEvents = new Set(ackBlocks.map((ack) => ack.eventId).filter(Boolean));
    const ackByRequest = new Set(ackBlocks.map((ack) => ack.requestEventId).filter(Boolean));
    let inferred = 0;
    for (const block of [...(transfer.dataBlocks || [])].sort((a, b) => (a.timestamp || 0) - (b.timestamp || 0) || (a.packet || 0) - (b.packet || 0))) {
      if (!block.counter || ackByRequest.has(block.eventId)) continue;
      const candidate = (ackObservations.events || [])
        .filter((ack) =>
          ack.counter === block.counter &&
          !usedAckEvents.has(ack.eventId) &&
          Number(ack.timestamp) >= Number(block.timestamp) - 0.000001
        )
        .sort((a, b) => (a.timestamp || 0) - (b.timestamp || 0) || (a.packet || 0) - (b.packet || 0))[0];
      if (!candidate) continue;
      ackBlocks.push({
        ...candidate,
        requestEventId: block.eventId,
        assignment: candidate.requestEventId ? "paired" : "counter-time"
      });
      usedAckEvents.add(candidate.eventId);
      ackByRequest.add(block.eventId);
      inferred += 1;
    }
    if (!inferred) return transfer;
    const responseBlockCounters = Array.from(new Set(ackBlocks.map((ack) => ack.counter).filter(Boolean)));
    return {
      ...transfer,
      ackBlocks,
      acknowledgedBlocks: ackBlocks.length,
      responseBlockCounters,
      captureNotes: [...(transfer.captureNotes || []), `Assigned ${inferred} TransferData positive response${inferred === 1 ? "" : "s"} by block counter and timestamp evidence.`]
    };
  }

  function buildTransferRateAnalysis(transfer, options = {}) {
    const opts = defaultOptions(options);
    const blocks = [...(transfer.dataBlocks || [])]
      .filter((block) => Number.isFinite(Number(block.timestamp)))
      .sort((a, b) => a.timestamp - b.timestamp || (a.packet || 0) - (b.packet || 0));
    const ackByRequest = new Map((transfer.ackBlocks || []).filter((ack) => ack.requestEventId).map((ack) => [ack.requestEventId, ack]));
    const activeStart = blocks[0]?.timestamp ?? null;
    const activeEnd = blocks[blocks.length - 1]?.timestamp ?? null;
    const activePayloadDuration = activeStart !== null && activeEnd !== null && blocks.length > 1 ? Math.max(0, activeEnd - activeStart) : null;
    const sessionDuration = Number.isFinite(Number(transfer.startTimestamp)) && Number.isFinite(Number(transfer.endTimestamp)) && transfer.endTimestamp > transfer.startTimestamp
      ? transfer.endTimestamp - transfer.startTimestamp
      : null;
    const blockIntervals = [];
    const ackLatencies = [];
    let previous = null;
    for (const block of blocks) {
      const delta = previous ? block.timestamp - previous.timestamp : null;
      const ack = ackByRequest.get(block.eventId) || null;
      const ackLatency = ack && Number.isFinite(Number(ack.timestamp)) ? ack.timestamp - block.timestamp : null;
      if (delta !== null && delta >= 0) {
        blockIntervals.push({
          counter: block.counter,
          packet: block.packet,
          timestamp: block.timestamp,
          payloadBytes: block.payloadBytes || 0,
          delta,
          instantaneousRateBps: delta > 0 ? (block.payloadBytes || 0) / delta : null
        });
      }
      if (ackLatency !== null && ackLatency >= 0) {
        ackLatencies.push({
          counter: block.counter,
          dataPacket: block.packet,
          ackPacket: ack.packet,
          latency: ackLatency
        });
      }
      previous = block;
    }
    return {
      activePayloadDuration,
      sessionDuration,
      averagePayloadRateBps: activePayloadDuration && activePayloadDuration > 0 ? (transfer.reconstructedBytes || 0) / activePayloadDuration : null,
      averageSessionRateBps: sessionDuration && sessionDuration > 0 ? (transfer.reconstructedBytes || 0) / sessionDuration : null,
      medianBlockInterval: opts.percentile(blockIntervals.map((item) => item.delta), 50),
      p95BlockInterval: opts.percentile(blockIntervals.map((item) => item.delta), 95),
      medianAckLatency: opts.percentile(ackLatencies.map((item) => item.latency), 50),
      p95AckLatency: opts.percentile(ackLatencies.map((item) => item.latency), 95),
      blockIntervals,
      ackLatencies,
      rateBuckets: buildRateBuckets(blocks)
    };
  }

  function buildRateBuckets(blocks) {
    if (!blocks.length) return [];
    const start = blocks[0].timestamp;
    const end = blocks[blocks.length - 1].timestamp;
    const duration = Math.max(0, end - start);
    const bucketCount = duration > 0 ? Math.min(48, Math.max(8, Math.ceil(duration / 0.5))) : 1;
    const bucketSeconds = duration > 0 ? duration / bucketCount : 1;
    const buckets = Array.from({ length: bucketCount }, (_, index) => ({
      index,
      start: start + index * bucketSeconds,
      end: start + (index + 1) * bucketSeconds,
      seconds: bucketSeconds,
      bytes: 0,
      rateBps: 0
    }));
    for (const block of blocks) {
      const index = duration > 0 ? Math.min(bucketCount - 1, Math.floor((block.timestamp - start) / bucketSeconds)) : 0;
      buckets[index].bytes += block.payloadBytes || 0;
    }
    for (const bucket of buckets) bucket.rateBps = bucket.seconds > 0 ? bucket.bytes / bucket.seconds : null;
    return buckets;
  }

  function downloadAckObservations(report, transfer, options = {}) {
    const opts = defaultOptions(options);
    const dataBlocks = transfer.dataBlocks || [];
    const blockTimes = dataBlocks.map((block) => Number(block.timestamp)).filter(Number.isFinite);
    const dataCounters = new Set(dataBlocks.map((block) => block.counter).filter(Boolean));
    const firstBlockTime = blockTimes.length ? Math.min(...blockTimes) : transfer.startTimestamp;
    const lastBlockTime = blockTimes.length ? Math.max(...blockTimes) : transfer.endTimestamp;
    const start = Math.min(transfer.startTimestamp || firstBlockTime || 0, firstBlockTime || transfer.startTimestamp || 0) - 0.75;
    const end = Math.max(transfer.endTimestamp || lastBlockTime || 0, lastBlockTime || transfer.endTimestamp || 0) + 2;
    const events = (report.diagnostics?.udsEvents || [])
      .filter((event) => {
        if (event.service !== "0x76" || event.timestamp < start || event.timestamp > end) return false;
        const counter = event.transfer?.blockCounter !== null && event.transfer?.blockCounter !== undefined ? opts.hexByte(event.transfer.blockCounter) : "";
        const sameSessionRoute = event.ecuAddress === transfer.ecuAddress && (!transfer.testerAddress || event.testerAddress === transfer.testerAddress);
        const sameEcuCounter = Boolean(counter && dataCounters.has(counter) && event.ecuAddress === transfer.ecuAddress);
        const sameTesterCounter = Boolean(counter && dataCounters.has(counter) && (!transfer.testerAddress || event.testerAddress === transfer.testerAddress));
        return sameSessionRoute || sameEcuCounter || sameTesterCounter;
      })
      .map((event) => ({
        eventId: event.id,
        requestEventId: event.requestEventId || null,
        packet: event.packet,
        timestamp: event.timestamp,
        counter: event.transfer?.blockCounter !== null && event.transfer?.blockCounter !== undefined ? opts.hexByte(event.transfer.blockCounter) : "",
        ecuAddress: event.ecuAddress,
        testerAddress: event.testerAddress,
        raw: event.raw
      }))
      .sort((a, b) => (a.timestamp || 0) - (b.timestamp || 0) || (a.packet || 0) - (b.packet || 0));
    return { events, counters: new Set(events.map((event) => event.counter).filter(Boolean)) };
  }

  function downloadAckHealth(transfer, observations = null) {
    if (transfer.direction === "upload") return { missing: [], unassigned: [], extra: [] };
    const observed = observations || { events: [], counters: new Set() };
    const ackByRequest = new Set((transfer.ackBlocks || []).map((block) => block.requestEventId).filter(Boolean));
    const dataCounters = new Set((transfer.dataBlocks || []).map((block) => block.counter).filter(Boolean));
    const missing = [];
    const unassigned = [];
    for (const block of transfer.dataBlocks || []) {
      if (!block.counter || ackByRequest.has(block.eventId)) continue;
      if ((transfer.ackBlocks || []).some((ack) => ack.counter === block.counter)) continue;
      if (observed.counters.has(block.counter)) {
        if (!unassigned.includes(block.counter)) unassigned.push(block.counter);
      } else if (!missing.includes(block.counter)) {
        missing.push(block.counter);
      }
    }
    const extra = [];
    for (const block of transfer.ackBlocks || []) {
      if (!block.counter || block.requestEventId) continue;
      if (!dataCounters.has(block.counter) && !extra.includes(block.counter)) extra.push(block.counter);
    }
    return { missing, unassigned, extra };
  }

  function downloadGatewayIp(report, transfer, events) {
    const request = events.find((event) => event.direction === "request" && event.dstIp);
    const response = events.find((event) => event.direction === "response" && event.srcIp);
    return request?.dstIp || response?.srcIp || (report.diagnostics?.ecus?.[transfer.ecuAddress]?.ips || [])[0] || "unknown";
  }

  function downloadGatewayLabel(report, transfer, events) {
    const ipAddress = downloadGatewayIp(report, transfer, events);
    const announced = (report.doip?.announcements || []).find((item) => item.srcIp === ipAddress);
    return announced?.logicalAddress ? `${ipAddress} / ${announced.logicalAddress}` : ipAddress === "unknown" ? "Unknown gateway/IP" : ipAddress;
  }

  function buildDownloadGroups(sessions) {
    const groupMap = new Map();
    for (const session of sessions) {
      const groupKey = session.gatewayIp || "unknown";
      if (!groupMap.has(groupKey)) {
        groupMap.set(groupKey, { key: groupKey, label: session.gatewayLabel || groupKey, sessions: [], ecus: [], payloadBytes: 0, pass: 0, warning: 0, fail: 0, lastTimestamp: 0 });
      }
      const group = groupMap.get(groupKey);
      group.sessions.push(session);
      addUnique(group.ecus, session.ecuAddress);
      group.payloadBytes += session.reconstructedBytes || 0;
      group.pass += session.severity === "ok" ? 1 : 0;
      group.warning += session.severity === "warning" ? 1 : 0;
      group.fail += session.severity === "error" ? 1 : 0;
      group.lastTimestamp = Math.max(group.lastTimestamp, session.endTimestamp || 0);
    }
    return Array.from(groupMap.values()).sort((a, b) => b.fail - a.fail || b.warning - a.warning || a.label.localeCompare(b.label));
  }

  function buildDownloadMatrixRows(groups, options = {}) {
    const opts = defaultOptions(options);
    return groups.flatMap((group) => {
      const byEcu = new Map();
      for (const session of group.sessions) {
        if (!byEcu.has(session.ecuAddress)) byEcu.set(session.ecuAddress, []);
        byEcu.get(session.ecuAddress).push(session);
      }
      return Array.from(byEcu.entries()).map(([ecuAddress, sessions]) => {
        const severity = sessions.some((item) => item.severity === "error") ? "error" : sessions.some((item) => item.severity === "warning") ? "warning" : "ok";
        const blockStatus = downloadMatrixBlockStatus(sessions, opts);
        return {
          groupKey: group.key,
          groupLabel: group.label,
          ecuAddress,
          sessionIds: sessions.map((item) => item.id),
          sessions: sessions.length,
          downloads: sessions.filter((item) => item.sessionType === "download").length,
          uploads: sessions.filter((item) => item.sessionType === "upload").length,
          fileTransfers: sessions.filter((item) => item.sessionType === "fileTransfer").length,
          payloadBytes: sessions.reduce((sum, item) => sum + (item.reconstructedBytes || 0), 0),
          blockAgreement: blockStatus.state,
          blockDetail: blockStatus.detail,
          nrcs: sessions.reduce((sum, item) => sum + (item.negatives || 0), 0),
          captureWarnings: sessions.reduce((sum, item) => sum + (item.validation || []).filter((finding) => finding.category === "Capture quality" && finding.severity === "warning").length, 0),
          exportable: sessions.filter((item) => item.hexExportable).length,
          severity
        };
      });
    }).sort((a, b) => a.groupLabel.localeCompare(b.groupLabel) || a.ecuAddress.localeCompare(b.ecuAddress));
  }

  function downloadMatrixBlockStatus(sessions, options = {}) {
    const opts = defaultOptions(options);
    const findings = sessions.flatMap((session) =>
      (session.validation || [])
        .filter((finding) => ["Completeness", "Sequence"].includes(finding.category) && ["error", "warning"].includes(finding.severity))
        .map((finding) => `${opts.ecuLabel(session.ecuAddress)} segment ${session.id}: ${finding.title}`)
    );
    if (findings.length) return { state: "warn", detail: findings.join("; ") };
    const totals = sessions.reduce((acc, session) => {
      acc.expected += session.expectedBlocks ?? 0;
      acc.data += session.blocks || 0;
      acc.acks += session.acknowledgedBlocks || 0;
      return acc;
    }, { expected: 0, data: 0, acks: 0 });
    return {
      state: "pass",
      detail: `No completeness or sequence warnings. Expected ${totals.expected || "unknown"} / data ${totals.data} / ACKed ${totals.acks}.`
    };
  }

  function transferEvents(report, transfer, ackObservations = null) {
    const ids = new Set(transfer.timelineEventIds || []);
    for (const block of transfer.dataBlocks || []) if (block.eventId) ids.add(block.eventId);
    for (const block of transfer.coordinationBlocks || []) if (block.eventId) ids.add(block.eventId);
    for (const event of transfer.pendingEvents || []) if (event.eventId) ids.add(event.eventId);
    for (const event of transfer.negativeEvents || []) if (event.eventId) ids.add(event.eventId);
    for (const ack of transfer.ackBlocks || []) if (ack.eventId) ids.add(ack.eventId);
    for (const ack of ackObservations?.events || []) if (ack.eventId) ids.add(ack.eventId);
    return (report.diagnostics?.udsEvents || [])
      .filter((event) => ids.has(event.id) || isSameTransferBoundaryEvent(event, transfer))
      .sort((a, b) => (a.timestamp || 0) - (b.timestamp || 0) || (a.packet || 0) - (b.packet || 0));
  }

  function isSameTransferBoundaryEvent(event, transfer) {
    if (event.ecuAddress !== transfer.ecuAddress || event.testerAddress !== transfer.testerAddress) return false;
    if (event.timestamp < transfer.startTimestamp - 0.001 || event.timestamp > transfer.endTimestamp + 0.001) return false;
    if (event.id === transfer.requestEventId) return true;
    if (event.service === "0x74" && transfer.service === "0x34") return true;
    if (event.service === "0x75" && transfer.service === "0x35") return true;
    if (event.service === "0x77" || event.service === "0x37") return true;
    if (event.service === "0x78" && transfer.service === "0x38") return true;
    if (event.service === "0x7f" && ["0x34", "0x35", "0x36", "0x37", "0x38"].includes(event.originalService)) return true;
    return false;
  }

  function validateDownloadSession(report, transfer, events, options = {}, ackMismatchSummary = null) {
    const opts = defaultOptions(options);
    const findings = [];
    const addFinding = (severity, category, title, detail, packet = transfer.requestPacket, extra = {}) => findings.push({ severity, category, title, detail, packet, ...extra });
    const duplicateFindings = downloadDuplicateFindings(transfer, { ackMismatchSummary });
    if (transfer.status === "open") addFinding("error", "Completeness", "Session did not reach TransferExit", "The capture contains a transfer start but no matching RequestTransferExit. Treat this as an incomplete programming sequence unless the capture ended before the ECU could send or receive TransferExit.");
    if (!transfer.blocks) addFinding("warning", "Completeness", "No reconstructable payload blocks", "Harness observed transfer control messages but no payload-bearing TransferData blocks.");
    if (transfer.expectedBlockShortfall) {
      const shortfall = transfer.expectedBlockShortfall;
      addFinding("info", "Completeness estimate", "Estimated block count exceeds reconstructed blocks", `Estimated ${shortfall.expected} blocks from RequestDownload size and ECU max block length, reconstructed ${shortfall.observed}. This is an estimate and is not treated as missing payload unless byte count or counter-gap evidence also disagrees.`);
    }
    if (transfer.request?.memorySize && transfer.reconstructedBytes < transfer.request.memorySize) {
      addFinding("warning", "Completeness", "Payload bytes below requested size", `Requested ${opts.formatNumber(transfer.request.memorySize)} bytes but reconstructed ${opts.formatNumber(transfer.reconstructedBytes)} bytes.`);
    }
    if (transfer.request?.memorySize && transfer.reconstructedBytes > transfer.request.memorySize) {
      addFinding("info", "Completeness estimate", "Observed payload bytes exceed requested size", `Observed ${opts.formatNumber(transfer.reconstructedBytes)} TransferData payload bytes for a request of ${opts.formatNumber(transfer.request.memorySize)} bytes. Extra observed bytes are usually tester retries, repeated counters, or a broken transfer sequence and are not counted as additional progress.`);
    }
    if (transfer.missingSequences?.length) addFinding("warning", "Sequence", "Block counter gaps detected", transfer.missingSequences.join(", "));
    if (ackMismatchSummary?.count) addFinding(
      "error",
      "Sequence",
      "ECU acknowledged wrong TransferData block counter",
      ackMismatchDetail(ackMismatchSummary, opts),
      ackMismatchSummary.firstPacket || transfer.requestPacket
    );
    for (const duplicate of duplicateFindings) addFinding(duplicate.severity, "Sequence", duplicate.title, duplicate.detail, duplicate.packet, duplicate);
    if (transfer.negatives > 0) addFinding("error", "Responses", "Transfer negative response observed", transferNegativeResponseDetail(transfer, opts));
    if (transfer.pending > 5) addFinding("info", "Responses", "Repeated response pending", `${transfer.pending} ResponsePending messages were observed.`);
    if (transfer.direction !== "upload" && transfer.acknowledgedBlocks !== transfer.blocks) {
      const ackObservations = downloadAckObservations(report, transfer, opts);
      const ackHealth = downloadAckHealth(transfer, ackObservations);
      const missingCounters = ackHealth.missing || [];
      const unassignedCounters = ackHealth.unassigned || [];
      const extraCounters = ackHealth.extra || [];
      const missing = missingCounters.length ? ` Missing response counters: ${missingCounters.join(", ")}.` : "";
      const unassigned = unassignedCounters.length ? ` Observed but not confidently assigned to this session: ${unassignedCounters.join(", ")}.` : "";
      const extra = extraCounters.length ? ` Extra response counters: ${extraCounters.join(", ")}.` : "";
      addFinding("info", "Capture quality", "TransferData response assignment is incomplete", `${transfer.blocks} payload blocks and ${transfer.acknowledgedBlocks || 0} assigned positive 0x76 responses were observed.${missing}${unassigned}${extra} Harness does not treat this as a transfer failure because interleaved/coalesced DoIP traffic can make assignment ambiguous.`);
    }
    const flowKeys = new Set(events.map((event) => opts.tcpFlowKey(event.srcIp, event.srcPort, event.dstIp, event.dstPort)).filter((key) => !key.includes("undefined")));
    const gaps = (report.tcpAnalysis?.gaps || []).filter((gap) => flowKeys.has(gap.flowKey) && gap.timestamp >= transfer.startTimestamp - 0.1 && gap.timestamp <= transfer.endTimestamp + 0.1);
    if (gaps.length) addFinding("warning", "Capture quality", "TCP stream gaps near transfer", `${gaps.length} TCP gap observations overlap this transfer window.`, gaps[0].packet);
    if (transfer.suppressedDuplicateMessages) addFinding("info", "Capture quality", "Suppressed duplicate TransferData observations", `${transfer.suppressedDuplicateMessages} exact duplicate TransferData observations were suppressed as likely retransmission/reassembly artefacts.`);
    for (const note of transfer.captureNotes || []) addFinding("info", "Capture quality", note, note);
    if (events.some((event) => typeof event.raw === "string" && event.raw.includes("..."))) addFinding("warning", "Capture quality", "Raw UDS was truncated in report", "The retained/generated report has truncated raw UDS bytes, so reconstruction may be limited.");
    if (!findings.length) addFinding("info", "Validation", "No validation issues found", "Observed transfer evidence is internally consistent.");
    return findings;
  }

  function downloadDuplicateFindings(transfer, options = {}) {
    const blocksInOrder = [...(transfer.dataBlocks || [])].sort((a, b) => (a.timestamp || 0) - (b.timestamp || 0) || (a.packet || 0) - (b.packet || 0));
    const byCounter = new Map();
    blocksInOrder.forEach((block, index) => {
      if (!block.counter) return;
      if (!byCounter.has(block.counter)) byCounter.set(block.counter, []);
      byCounter.get(block.counter).push({ block, index });
    });
    const differentPayloadCounters = [];
    const identicalPayloadCounters = [];
    let firstPacket = null;
    let repeatObservations = 0;
    for (const [counter, entries] of byCounter.entries()) {
      const blocks = entries.map((entry) => entry.block);
      const uniqueEvents = new Map(blocks.map((block) => [block.eventId, block]));
      if (uniqueEvents.size <= 1) continue;
      const unexpectedRepeats = entries.filter((entry, index) => {
        if (index === 0) return false;
        const previous = entries[index - 1];
        return (entry.index - previous.index) % 256 !== 0;
      });
      if (!unexpectedRepeats.length) continue;
      repeatObservations += unexpectedRepeats.length;
      firstPacket ??= unexpectedRepeats[0].block.packet;
      const payloads = new Set(blocks.map((block) => block.payloadHex));
      if (payloads.size > 1) {
        const hasCaptureLossEvidence = (transfer.missingSequences || []).some(isForwardMissingSequence);
        differentPayloadCounters.push({ counter, severity: hasCaptureLossEvidence ? "warning" : "error" });
      } else {
        identicalPayloadCounters.push(counter);
      }
    }
    const findings = [];
    if (differentPayloadCounters.length) {
      const hasAckMismatch = Boolean(options.ackMismatchSummary?.count);
      const warningOnly = differentPayloadCounters.every((item) => item.severity === "warning");
      const counters = differentPayloadCounters.map((item) => item.counter);
      findings.push({
        severity: hasAckMismatch ? "info" : warningOnly ? "warning" : "error",
        title: "TransferData block counters reused with different payload",
        detail: duplicatePayloadDetail(counters, repeatObservations, options.ackMismatchSummary),
        packet: firstPacket,
        counters,
        suppressValidationCentre: hasAckMismatch
      });
    }
    if (identicalPayloadCounters.length) {
      findings.push({
        severity: "info",
        title: "Repeated block counter with identical payload suppressed",
        detail: `${identicalPayloadCounters.length} block counter${identicalPayloadCounters.length === 1 ? "" : "s"} repeated with identical payload bytes; this is treated as retry/reassembly context, not a protocol failure. Counters: ${sampleList(identicalPayloadCounters)}.`,
        packet: firstPacket,
        counters: identicalPayloadCounters,
        suppressValidationCentre: true
      });
    }
    return findings;
  }

  function downloadAckMismatchSummary(transfer, observations = null) {
    if (transfer.direction === "upload") return { count: 0, samples: [] };
    const blocks = [...(transfer.dataBlocks || [])]
      .filter((block) => block.counter)
      .sort((a, b) => (a.timestamp || 0) - (b.timestamp || 0) || (a.packet || 0) - (b.packet || 0));
    const acks = [...(observations?.events || transfer.ackBlocks || [])]
      .filter((ack) => ack.counter)
      .sort((a, b) => (a.timestamp || 0) - (b.timestamp || 0) || (a.packet || 0) - (b.packet || 0));
    const mismatches = [];
    let blockIndex = 0;
    for (const ack of acks) {
      while (blockIndex + 1 < blocks.length && Number(blocks[blockIndex + 1].timestamp) <= Number(ack.timestamp) + 0.000001) blockIndex += 1;
      const request = blocks[blockIndex];
      if (!request || Number(request.timestamp) > Number(ack.timestamp) + 0.000001) continue;
      if (request.counter === ack.counter) continue;
      const requestValue = parseCounterValue(request.counter);
      const ackValue = parseCounterValue(ack.counter);
      mismatches.push({
        requestCounter: request.counter,
        ackCounter: ack.counter,
        requestPacket: request.packet,
        ackPacket: ack.packet,
        requestTimestamp: request.timestamp,
        ackTimestamp: ack.timestamp,
        offset: signedCounterOffset(requestValue, ackValue)
      });
    }
    if (!mismatches.length) return { count: 0, samples: [] };
    const offsetCounts = new Map();
    for (const item of mismatches) offsetCounts.set(item.offset, (offsetCounts.get(item.offset) || 0) + 1);
    const dominant = Array.from(offsetCounts.entries()).sort((a, b) => b[1] - a[1])[0] || [null, 0];
    return {
      count: mismatches.length,
      firstPacket: mismatches[0].ackPacket,
      lastPacket: mismatches[mismatches.length - 1].ackPacket,
      dominantOffset: dominant[0],
      dominantOffsetCount: dominant[1],
      samples: mismatches.slice(0, 5)
    };
  }

  function ackMismatchDetail(summary, options = {}) {
    const opts = defaultOptions(options);
    const offsetText = summary.dominantOffset === -1
      ? "Most common pattern: ECU ACK appears 1 block behind tester."
      : summary.dominantOffset === 1
        ? "Most common pattern: ECU ACK appears 1 block ahead of tester."
        : Number.isFinite(summary.dominantOffset)
          ? `Most common counter offset: ${summary.dominantOffset > 0 ? "+" : ""}${summary.dominantOffset}.`
          : "";
    const samples = (summary.samples || [])
      .map((item) => `tester ${item.requestCounter} packet ${item.requestPacket} -> ECU ${item.ackCounter} packet ${item.ackPacket}`)
      .join("; ");
    return `${opts.formatNumber(summary.count)} ACK mismatch${summary.count === 1 ? "" : "es"} observed between chronological TransferData requests and positive 0x76 responses. ${offsetText} Packet range ${summary.firstPacket || ""}-${summary.lastPacket || ""}.${samples ? ` Samples: ${samples}.` : ""}`;
  }

  function duplicatePayloadDetail(counters, repeatObservations, ackMismatchSummary = null) {
    const cause = ackMismatchSummary?.count
      ? " This appears secondary to the TransferData ACK counter mismatch in this session."
      : "";
    return `${counters.length} block counter${counters.length === 1 ? "" : "s"} reused before the expected 256-block wrap distance with different payload bytes across ${repeatObservations} repeat observation${repeatObservations === 1 ? "" : "s"}. Counters: ${sampleList(counters)}.${cause}`;
  }

  function transferNegativeResponseDetail(transfer, options = {}) {
    const opts = defaultOptions(options);
    const groups = new Map();
    const negatives = transfer.negativeEvents?.length
      ? transfer.negativeEvents
      : (transfer.responseCodes || []).map((value) => {
          const [service = "", nrc = "", ...nameParts] = String(value).split(/\s+/);
          return { service, nrc, nrcName: nameParts.join(" ") };
        });
    for (const item of negatives) {
      const service = item.service || "unknown service";
      const nrc = item.nrc || "unknown NRC";
      const key = `${service}|${nrc}|${item.nrcName || ""}`;
      if (!groups.has(key)) {
        groups.set(key, {
          service,
          nrc,
          nrcName: item.nrcName || "",
          count: 0,
          packets: [],
          firstPacket: item.packet || null,
          lastPacket: item.packet || null
        });
      }
      const group = groups.get(key);
      group.count += 1;
      if (item.packet) {
        group.packets.push(item.packet);
        group.firstPacket ??= item.packet;
        group.lastPacket = item.packet;
      }
    }
    const rows = Array.from(groups.values()).sort((a, b) => b.count - a.count || String(a.nrc).localeCompare(String(b.nrc)));
    const summary = rows.slice(0, 6).map((group) => {
      const name = group.nrcName ? ` ${group.nrcName}` : "";
      const packetText = group.packets.length
        ? ` packets ${sampleList(group.packets.map((packet) => String(packet)), 5)}${group.packets.length > 5 ? `; last ${group.lastPacket}` : ""}`
        : "";
      return `${group.service} ${group.nrc}${name}: ${opts.formatNumber(group.count)}${packetText}`;
    }).join("; ");
    const extra = rows.length > 6 ? `; plus ${opts.formatNumber(rows.length - 6)} other NRC group${rows.length - 6 === 1 ? "" : "s"}` : "";
    return `${opts.formatNumber(transfer.negatives || negatives.length)} transfer negative response${(transfer.negatives || negatives.length) === 1 ? "" : "s"} observed. ${summary || "A transfer service received a 0x7F response"}${extra}.`;
  }

  function sampleList(values, limit = 12) {
    const list = values.slice(0, limit).join(", ");
    return values.length > limit ? `${list}, ...` : list;
  }

  function parseCounterValue(counter) {
    const value = parseInt(String(counter || "").replace(/^0x/i, ""), 16);
    return Number.isFinite(value) ? value & 0xff : null;
  }

  function signedCounterOffset(requestValue, ackValue) {
    if (requestValue === null || ackValue === null) return null;
    const raw = (ackValue - requestValue + 256) & 0xff;
    return raw > 127 ? raw - 256 : raw;
  }

  function isForwardMissingSequence(sequence) {
    const match = String(sequence || "").match(/0x([0-9a-f]{2})\s*->\s*0x([0-9a-f]{2})/i);
    if (!match) return false;
    const expected = parseInt(match[1], 16);
    const observed = parseInt(match[2], 16);
    if (observed === expected) return false;
    return observed > expected || expected - observed > 128;
  }

  global.HarnessDownloadAnalysis = Object.freeze({
    buildDownloadAnalysis,
    enrichDownloadSession,
    assignObservedDownloadAcks,
    buildTransferRateAnalysis,
    buildRateBuckets,
    downloadAckObservations,
    downloadAckHealth,
    downloadGatewayIp,
    downloadGatewayLabel,
    buildDownloadGroups,
    buildDownloadMatrixRows,
    downloadMatrixBlockStatus,
    transferEvents,
    isSameTransferBoundaryEvent,
    validateDownloadSession,
    downloadDuplicateFindings,
    downloadAckMismatchSummary,
    transferNegativeResponseDetail,
    isForwardMissingSequence
  });
})(window);
