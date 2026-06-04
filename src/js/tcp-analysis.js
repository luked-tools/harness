/**
 * TCP transport timing and flow-control analysis.
 *
 * This module consumes normalized TCP packet observations from the parser and
 * returns report-ready flow metrics plus trace-event payloads.
 */
(function registerTcpAnalysis(global) {
  "use strict";

  const TCP_SMALL_WINDOW_THRESHOLD = 4096;
  const TCP_ACK_HEAVY_MIN_ACKS = 20;
  const TCP_ACK_HEAVY_RATIO = 0.8;

  function endpointKey(ipAddress, port) {
    return `${ipAddress}:${port}`;
  }

  function percentile(values, p) {
    if (!values.length) return null;
    const sorted = [...values].sort((a, b) => a - b);
    if (p <= 0) return sorted[0];
    if (p >= 100) return sorted[sorted.length - 1];
    const index = Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1);
    return sorted[index];
  }

  function downsampleSamples(samples, maxItems) {
    if (samples.length <= maxItems) return samples;
    const step = samples.length / maxItems;
    return Array.from({ length: maxItems }, (_, index) => samples[Math.floor(index * step)]);
  }

  function ensureFlowControlDirection(flow, direction, endpoint, peer) {
    flow.flowControl ||= { directions: {}, status: { label: "OK", severity: "ok", detail: "No receive-window pressure observed." } };
    flow.flowControl.directions[direction] ||= {
      direction,
      endpoint,
      peer,
      packets: 0,
      pureAcks: 0,
      payloadPacketsSent: 0,
      payloadBytesSent: 0,
      payloadPacketsReceived: 0,
      payloadBytesReceived: 0,
      zeroWindows: 0,
      windowUpdates: 0,
      smallWindowSamples: 0,
      windows: [],
      samples: []
    };
    return flow.flowControl.directions[direction];
  }

  function finaliseFlowControl(flow) {
    const directions = Object.values(flow.flowControl?.directions || {}).map((item) => {
      const windows = item.windows.filter((value) => Number.isFinite(value));
      const ackToPayloadRatio = item.payloadPacketsReceived ? item.pureAcks / item.payloadPacketsReceived : null;
      const bytesPerAck = item.pureAcks ? item.payloadBytesReceived / item.pureAcks : null;
      const smallWindowRatio = windows.length ? item.smallWindowSamples / windows.length : 0;
      const status = flowControlDirectionStatus({ ...item, windows, ackToPayloadRatio, bytesPerAck, smallWindowRatio });
      return {
        ...item,
        windows: undefined,
        samples: downsampleSamples(item.samples || [], 600),
        minWindow: percentile(windows, 0),
        medianWindow: percentile(windows, 50),
        p95Window: percentile(windows, 95),
        latestWindow: windows.length ? windows[windows.length - 1] : null,
        ackToPayloadRatio,
        bytesPerAck,
        smallWindowRatio,
        status
      };
    });
    const status = flowControlOverallStatus(directions);
    return { directions, status, smallWindowThreshold: TCP_SMALL_WINDOW_THRESHOLD };
  }

  function flowControlDirectionStatus(direction) {
    const ackHeavy = direction.pureAcks >= TCP_ACK_HEAVY_MIN_ACKS && direction.ackToPayloadRatio !== null && direction.ackToPayloadRatio >= TCP_ACK_HEAVY_RATIO;
    const tinyAckBytes = direction.pureAcks >= TCP_ACK_HEAVY_MIN_ACKS && direction.bytesPerAck !== null && direction.bytesPerAck < 2048;
    const smallWindow = direction.smallWindowSamples >= 5 && direction.smallWindowRatio >= 0.2;
    const severeSmallWindow = direction.smallWindowSamples >= 10 && direction.smallWindowRatio >= 0.65;
    if (direction.zeroWindows > 0) return { label: "Zero window", severity: "problem", detail: "Receiver advertised no TCP buffer space." };
    if (severeSmallWindow && (ackHeavy || tinyAckBytes)) return { label: "Buffer pressure", severity: "problem", detail: "Sustained small receive window with high ACK cadence." };
    if (smallWindow && (ackHeavy || tinyAckBytes || direction.windowUpdates >= 5)) return { label: "Buffer pressure", severity: "warning", detail: "Small receive window and ACK cadence may reduce DoIP throughput." };
    if (smallWindow) return { label: "Small window", severity: "warning", detail: "Advertised receive window is repeatedly small." };
    if (ackHeavy || tinyAckBytes) return { label: "ACK-heavy", severity: "warning", detail: "Receiver ACKs frequently relative to observed payload." };
    if (direction.windowUpdates >= 5) return { label: "Window churn", severity: "info", detail: "Receive window changed frequently." };
    return { label: "OK", severity: "ok", detail: "No receive-window pressure observed." };
  }

  function flowControlOverallStatus(directions) {
    const rank = { problem: 3, warning: 2, info: 1, ok: 0 };
    return directions.map((item) => item.status || { label: "OK", severity: "ok" })
      .sort((a, b) => (rank[b.severity] || 0) - (rank[a.severity] || 0))[0] || { label: "OK", severity: "ok", detail: "No receive-window pressure observed." };
  }

  function analyzeTcpTransport(packets, options = {}) {
    const existingGaps = options.gaps || [];
    const analysis = { flows: [], events: [], ackTimings: [], retransmissions: 0, duplicateAcks: 0, zeroWindows: 0, windowUpdates: 0, gaps: existingGaps };
    const traceEvents = [];
    const flows = new Map();
    const states = new Map();
    const ensureFlow = (packet) => {
      if (!flows.has(packet.flowKey)) {
        const endpoints = packet.flowKey.split(" <-> ");
        flows.set(packet.flowKey, {
          key: packet.flowKey,
          endpointA: endpoints[0],
          endpointB: endpoints[1],
          packets: 0,
          payloadBytes: 0,
          retransmissions: 0,
          duplicateAcks: 0,
          zeroWindows: 0,
          windowUpdates: 0,
          handshakeDuration: null,
          firstTimestamp: packet.timestamp,
          lastTimestamp: packet.timestamp,
          ackLatencies: [],
          flowControl: { directions: {}, status: { label: "OK", severity: "ok", detail: "No receive-window pressure observed." } }
        });
        states.set(packet.flowKey, { unacked: new Map(), lastAck: new Map(), duplicateAckStreak: new Map(), lastWindow: new Map(), windowScale: new Map(), smallWindowFlagged: new Set(), syn: null, synAck: null });
      }
      return flows.get(packet.flowKey);
    };
    const addEvent = (packet, type, label, detail = {}) => {
      const event = { id: analysis.events.length + 1, flowKey: packet.flowKey, timestamp: packet.timestamp, packet: packet.packet, type, label, src: endpointKey(packet.srcIp, packet.srcPort), dst: endpointKey(packet.dstIp, packet.dstPort), ...detail };
      analysis.events.push(event);
      traceEvents.push({ category: "transport", type, label, laneKey: `tcp:${packet.flowKey}`, laneLabel: `TCP ${packet.flowKey}`, timestamp: packet.timestamp, packet: packet.packet, srcIp: packet.srcIp, srcPort: packet.srcPort, dstIp: packet.dstIp, dstPort: packet.dstPort });
    };

    for (const packet of [...packets].sort((a, b) => a.timestamp - b.timestamp || a.packet - b.packet)) {
      const flow = ensureFlow(packet);
      const state = states.get(packet.flowKey);
      flow.packets += 1;
      flow.payloadBytes += packet.payloadLength;
      flow.firstTimestamp = Math.min(flow.firstTimestamp, packet.timestamp);
      flow.lastTimestamp = Math.max(flow.lastTimestamp, packet.timestamp);
      state.unacked.set(packet.directionKey, state.unacked.get(packet.directionKey) || []);
      const srcEndpoint = endpointKey(packet.srcIp, packet.srcPort);
      const dstEndpoint = endpointKey(packet.dstIp, packet.dstPort);
      if (packet.flags.syn && Number.isFinite(packet.windowScale)) state.windowScale.set(packet.directionKey, packet.windowScale);
      const advertisedWindow = packet.windowSize * (2 ** (state.windowScale.get(packet.directionKey) || 0));
      let directionControl = null;
      if (!packet.flags.rst) {
        directionControl = ensureFlowControlDirection(flow, packet.directionKey, srcEndpoint, dstEndpoint);
        directionControl.packets += 1;
        directionControl.windows.push(advertisedWindow);
        directionControl.samples.push({
          timestamp: packet.timestamp,
          packet: packet.packet,
          direction: packet.directionKey,
          windowSize: advertisedWindow,
          rawWindowSize: packet.windowSize,
          windowScale: state.windowScale.get(packet.directionKey) || 0,
          ackNumber: packet.ackNumber,
          payloadLength: packet.payloadLength,
          pureAck: Boolean(packet.flags.ack && !packet.hasPayload && !packet.flags.syn && !packet.flags.fin)
        });
        if (advertisedWindow > 0 && advertisedWindow <= TCP_SMALL_WINDOW_THRESHOLD) {
          directionControl.smallWindowSamples += 1;
          if (!state.smallWindowFlagged.has(packet.directionKey)) {
            state.smallWindowFlagged.add(packet.directionKey);
            addEvent(packet, "Small window", "TCP small advertised receive window", { windowSize: advertisedWindow, rawWindowSize: packet.windowSize, windowScale: state.windowScale.get(packet.directionKey) || 0 });
          }
        }
      }

      if (packet.flags.syn && !packet.flags.ack) state.syn = packet.timestamp;
      if (packet.flags.syn && packet.flags.ack) state.synAck = packet.timestamp;
      if (packet.flags.ack && !packet.flags.syn && state.syn !== null && state.synAck !== null && flow.handshakeDuration === null) {
        flow.handshakeDuration = packet.timestamp - state.syn;
        addEvent(packet, "Handshake", "TCP handshake completed", { duration: flow.handshakeDuration });
      }

      const lastWindow = state.lastWindow.get(packet.directionKey);
      if (!packet.flags.rst && packet.windowSize === 0 && lastWindow !== 0) {
        flow.zeroWindows += 1;
        directionControl.zeroWindows += 1;
        analysis.zeroWindows += 1;
        addEvent(packet, "Zero window", "TCP zero window", { windowSize: packet.windowSize });
      } else if (!packet.flags.rst && lastWindow === 0 && packet.windowSize > 0) {
        flow.windowUpdates += 1;
        directionControl.windowUpdates += 1;
        analysis.windowUpdates += 1;
        addEvent(packet, "Window update", "TCP window reopened", { windowSize: packet.windowSize });
      }
      if (!packet.flags.rst) state.lastWindow.set(packet.directionKey, packet.windowSize);

      if (packet.hasPayload) {
        directionControl ||= ensureFlowControlDirection(flow, packet.directionKey, srcEndpoint, dstEndpoint);
        directionControl.payloadPacketsSent += 1;
        directionControl.payloadBytesSent += packet.payloadLength;
        const reverseDirection = `${dstEndpoint} -> ${srcEndpoint}`;
        const receiverControl = ensureFlowControlDirection(flow, reverseDirection, dstEndpoint, srcEndpoint);
        receiverControl.payloadPacketsReceived += 1;
        receiverControl.payloadBytesReceived += packet.payloadLength;
        const unacked = state.unacked.get(packet.directionKey);
        const repeated = unacked.find((item) => item.seq === packet.seq && item.endSeq === packet.endSeq);
        if (repeated) {
          flow.retransmissions += 1;
          analysis.retransmissions += 1;
          addEvent(packet, "Retransmission", "TCP retransmission", { seq: packet.seq, endSeq: packet.endSeq, originalPacket: repeated.packet });
        } else {
          unacked.push({ seq: packet.seq, endSeq: packet.endSeq, timestamp: packet.timestamp, packet: packet.packet, bytes: packet.payloadLength });
        }
      }

      if (packet.flags.ack) {
        const lastAck = state.lastAck.get(packet.directionKey);
        const pureAck = !packet.hasPayload && !packet.flags.syn && !packet.flags.fin && !packet.flags.rst;
        const acknowledgedDirection = `${dstEndpoint} -> ${srcEndpoint}`;
        const hasOutstandingReverseData = (state.unacked.get(acknowledgedDirection) || []).some((item) => item.endSeq > packet.ackNumber);
        const duplicateStreak = pureAck && lastAck === packet.ackNumber ? (state.duplicateAckStreak.get(packet.directionKey) || 0) + 1 : 0;
        state.duplicateAckStreak.set(packet.directionKey, duplicateStreak);
        if (duplicateStreak >= 2 && hasOutstandingReverseData) {
          flow.duplicateAcks += 1;
          analysis.duplicateAcks += 1;
          addEvent(packet, "Duplicate ACK", "TCP duplicate ACK burst", { ackNumber: packet.ackNumber, duplicateStreak });
        }
        if (pureAck) directionControl.pureAcks += 1;
        state.lastAck.set(packet.directionKey, packet.ackNumber);
        for (const [direction, unacked] of state.unacked.entries()) {
          if (direction === packet.directionKey) continue;
          const remaining = [];
          for (const item of unacked) {
            if (item.endSeq <= packet.ackNumber) {
              const latency = packet.timestamp - item.timestamp;
              const ack = { id: analysis.ackTimings.length + 1, flowKey: packet.flowKey, direction, payloadPacket: item.packet, ackPacket: packet.packet, payloadBytes: item.bytes, latency, sentTimestamp: item.timestamp, ackTimestamp: packet.timestamp };
              analysis.ackTimings.push(ack);
              flow.ackLatencies.push(latency);
              if (latency > 0.05) addEvent(packet, "Slow ACK", "TCP slow ACK", { latency, payloadPacket: item.packet });
            } else {
              remaining.push(item);
            }
          }
          state.unacked.set(direction, remaining);
        }
      }

      if (packet.flags.rst) addEvent(packet, "RST", "TCP reset");
      if (packet.flags.fin) addEvent(packet, "FIN", "TCP finish");
    }

    analysis.flows = Array.from(flows.values()).map((flow) => {
      const latencies = flow.ackLatencies;
      const median = percentile(latencies, 50);
      const p95 = percentile(latencies, 95);
      return { ...flow, ackSamples: latencies.length, minAckLatency: percentile(latencies, 0), medianAckLatency: median, p95AckLatency: p95, maxAckLatency: percentile(latencies, 100), flowControl: finaliseFlowControl(flow) };
    }).sort((a, b) => b.packets - a.packets);

    return { analysis, traceEvents };
  }

  global.HarnessTcpAnalysis = Object.freeze({
    TCP_SMALL_WINDOW_THRESHOLD,
    percentile,
    downsampleSamples,
    analyzeTcpTransport
  });
})(window);
