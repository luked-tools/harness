/**
 * TCP DoIP stream reassembly helpers used by the PCAP parser.
 */
(function registerTcpDoipReassembly(global) {
  "use strict";

  function tcpConnectionKey(srcIp, srcPort, dstIp, dstPort, options = {}) {
    const endpointKey = options.endpointKey || ((ipAddress, port) => `${ipAddress}:${port}`);
    return [endpointKey(srcIp, srcPort), endpointKey(dstIp, dstPort)].sort().join(" <-> ");
  }

  function collectTcpSegment(tcpSegments, srcIp, srcPort, dstIp, dstPort, connectionEpoch, seq, view, start, end, packet, timestamp, srcMac = "") {
    const key = [srcIp, srcPort, dstIp, dstPort, connectionEpoch].join("|");
    if (!tcpSegments.has(key)) tcpSegments.set(key, { srcIp, srcPort, dstIp, dstPort, connectionEpoch, segments: [] });
    tcpSegments.get(key).segments.push({
      seq,
      packet,
      timestamp,
      srcMac,
      bytes: new Uint8Array(view.buffer, view.byteOffset + start, end - start)
    });
  }

  function parseTcpDoipSegments(tcpSegments, report, announcementKeys, options = {}) {
    const parseDoipBytes = options.parseDoipBytes || (() => 0);
    const tcpFlowKey = options.tcpFlowKey || ((srcIp, srcPort, dstIp, dstPort) => tcpConnectionKey(srcIp, srcPort, dstIp, dstPort));
    const ensureTcpAnalysis = options.ensureTcpAnalysis || ((targetReport) => {
      targetReport.tcpAnalysis ||= { flows: [], events: [], ackTimings: [], retransmissions: 0, duplicateAcks: 0, zeroWindows: 0, windowUpdates: 0, gaps: [] };
      return targetReport.tcpAnalysis;
    });

    for (const flowInfo of tcpSegments.values()) {
      const ordered = coalesceTcpSegments(flowInfo.segments);
      const bytes = [];
      const metas = [];
      let expectedSeq = null;
      const flushChunk = () => {
        if (!bytes.length) return;
        const chunkBytes = new Uint8Array(bytes);
        const chunkMetas = metas.slice();
        parseDoipBytes(
          chunkBytes,
          (offset) => chunkMetas[Math.min(offset, chunkMetas.length - 1)] || ordered[0],
          "TCP",
          flowInfo.srcIp,
          flowInfo.srcPort,
          flowInfo.dstIp,
          flowInfo.dstPort,
          report,
          announcementKeys
        );
        bytes.length = 0;
        metas.length = 0;
      };
      for (const segment of ordered) {
        if (expectedSeq !== null && segment.seq < expectedSeq) {
          const overlap = expectedSeq - segment.seq;
          if (overlap >= segment.bytes.length) continue;
          const trimmed = segment.bytes.subarray(overlap);
          for (const byte of trimmed) {
            metas.push(segment);
            bytes.push(byte);
          }
          expectedSeq += trimmed.length;
        } else {
          if (expectedSeq !== null && segment.seq > expectedSeq) {
            report.warnings.push(`TCP gap in DoIP stream ${flowInfo.srcIp}:${flowInfo.srcPort} -> ${flowInfo.dstIp}:${flowInfo.dstPort}`);
            ensureTcpAnalysis(report).gaps.push({
              flowKey: tcpFlowKey(flowInfo.srcIp, flowInfo.srcPort, flowInfo.dstIp, flowInfo.dstPort),
              timestamp: segment.timestamp,
              packet: segment.packet,
              expectedSeq,
              actualSeq: segment.seq,
              gap: segment.seq - expectedSeq
            });
            flushChunk();
          }
          for (const byte of segment.bytes) {
            metas.push(segment);
            bytes.push(byte);
          }
          expectedSeq = segment.seq + segment.bytes.length;
        }
      }
      flushChunk();
    }
  }

  function doipPayloadScore(bytes) {
    if (!bytes?.length) return 0;
    if (bytes.length < 8) return bytes.length;
    const version = bytes[0];
    const inverse = bytes[1];
    const payloadLength = ((bytes[4] << 24) | (bytes[5] << 16) | (bytes[6] << 8) | bytes[7]) >>> 0;
    const validHeader = (version ^ inverse) === 0xff;
    const completeMessage = validHeader && 8 + payloadLength <= bytes.length;
    return (completeMessage ? 100000 : validHeader ? 50000 : 0) + bytes.length;
  }

  function coalesceTcpSegments(segments) {
    const bySeq = new Map();
    for (const segment of segments) {
      const existing = bySeq.get(segment.seq);
      if (!existing || doipPayloadScore(segment.bytes) > doipPayloadScore(existing.bytes)) {
        bySeq.set(segment.seq, segment);
      }
    }
    return Array.from(bySeq.values()).sort((a, b) => a.seq - b.seq || a.packet - b.packet);
  }

  global.HarnessTcpDoipReassembly = Object.freeze({
    tcpConnectionKey,
    collectTcpSegment,
    parseTcpDoipSegments,
    doipPayloadScore,
    coalesceTcpSegments
  });
})(window);
