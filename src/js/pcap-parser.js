/**
 * Classic Ethernet PCAP parser and lightweight protocol decoders.
 */
(function registerPcapParser(global) {
  "use strict";

  const protocol = global.HarnessProtocol || {};
  const formatters = global.HarnessFormatters || {};
  const reassembly = global.HarnessTcpDoipReassembly || {};
  const tcpAnalysis = global.HarnessTcpAnalysis || {};

  const DOIP_PORT = protocol.DOIP_PORT || 13400;
  const DHCP_PORTS = protocol.DHCP_PORTS || new Set([67, 68]);
  const ETH_IPV4 = protocol.ETH_IPV4 || 0x0800;
  const ETH_ARP = protocol.ETH_ARP || 0x0806;
  const VLAN_TYPES = protocol.VLAN_TYPES || new Set([0x8100, 0x88a8, 0x9100]);
  const DHCP_TYPES = protocol.DHCP_TYPES || {};
  const DOIP_TYPES = protocol.DOIP_TYPES || {};
  const DOIP_GENERIC_NACK_CODES = protocol.DOIP_GENERIC_NACK_CODES || {};
  const DOIP_DIAGNOSTIC_NACK_CODES = protocol.DOIP_DIAGNOSTIC_NACK_CODES || {};
  const DOIP_ROUTING_ACTIVATION_RESPONSE_CODES = protocol.DOIP_ROUTING_ACTIVATION_RESPONSE_CODES || {};
  const hexWord = formatters.hexWord || ((value) => `0x${Number(value || 0).toString(16).padStart(4, "0")}`);
  const hexByte = formatters.hexByte || ((value) => `0x${Number(value || 0).toString(16).padStart(2, "0")}`);
  const bytesToHex = formatters.bytesToHex || ((bytes) => Array.from(bytes || [], (byte) => byte.toString(16).padStart(2, "0")).join(" "));

  function defaultAdd(map, key, count = 1) {
    map[key] = (map[key] || 0) + count;
  }

  function defaultAddUnique(list, value) {
    if (value && !list.includes(value)) list.push(value);
  }

  function defaultPushSample(list, sample, limit = 140) {
    if (list.length < limit) list.push(sample);
  }

  function defaultMac(view, offset) {
    return Array.from({ length: 6 }, (_, i) => view.getUint8(offset + i).toString(16).padStart(2, "0")).join(":");
  }

  function defaultIp(view, offset) {
    return Array.from({ length: 4 }, (_, i) => view.getUint8(offset + i)).join(".");
  }

  function defaultAscii(view, offset, length) {
    let out = "";
    for (let i = 0; i < length; i += 1) {
      const c = view.getUint8(offset + i);
      if (c >= 32 && c <= 126) out += String.fromCharCode(c);
    }
    return out.trim();
  }

  function defaultEmptyReport() {
    return {
      source: "",
      pcap: {},
      summary: { totalPackets: 0, totalBytes: 0, durationSeconds: 0, protocolCounts: {} },
      hosts: {},
      arp: { count: 0, operations: {}, samples: [] },
      dhcp: { count: 0, messageTypes: {}, clients: {}, servers: {}, samples: [] },
      doip: { count: 0, udpCount: 0, tcpCount: 0, payloadTypes: {}, announcements: [], logicalAddresses: {}, samples: [], genericNacks: [] },
      diagnostics: { ecus: {}, udsEvents: [], didReads: [], dtcReads: [], transfers: [], serviceStats: {}, negativeResponses: {}, sessions: [], securityAccess: [], routineControls: [], unmatchedMessages: [], ackNak: [] },
      downloadAnalysis: { sessions: [], findings: [], metrics: {} },
      validationCentre: { summary: {}, findings: [], groups: {} },
      traceEvents: [],
      tcpAnalysis: { flows: [], events: [], ackTimings: [], retransmissions: 0, duplicateAcks: 0, zeroWindows: 0, windowUpdates: 0, gaps: [] },
      identity: { findings: [], hostMap: [], metrics: {} },
      topology: { nodes: [], edges: [], summary: {} },
      flows: [],
      topTalkers: [],
      warnings: []
    };
  }

  function resolveOptions(options = {}) {
    return {
      emptyReport: options.emptyReport || defaultEmptyReport,
      buildIdentityAnalysis: options.buildIdentityAnalysis || ((report) => report.identity),
      buildTopologyAnalysis: options.buildTopologyAnalysis || ((report) => report.topology),
      buildValidationCentre: options.buildValidationCentre || ((report) => report.validationCentre),
      finalizeDiagnostics: options.finalizeDiagnostics || (() => {}),
      finalizeTcpAnalysis: options.finalizeTcpAnalysis || ((report) => { report.tcpAnalysis ||= defaultEmptyReport().tcpAnalysis; }),
      parseDiagnosticMessage: options.parseDiagnosticMessage || (() => {}),
      parseDiagnosticAckNak: options.parseDiagnosticAckNak || parseDiagnosticAckNak,
      traceLaneForLogical: options.traceLaneForLogical || ((role, address) => ({ laneKey: `${role}:${address}`, laneLabel: `${role} ${address}` })),
      traceLaneForEndpoint: options.traceLaneForEndpoint || ((prefix, macAddress, ipAddress) => ({ laneKey: macAddress ? `mac:${macAddress}` : `ip:${ipAddress || prefix}`, laneLabel: ipAddress || macAddress || prefix })),
      enrichEcuFromAnnouncement: options.enrichEcuFromAnnouncement || (() => {}),
      add: options.add || defaultAdd,
      addUnique: options.addUnique || defaultAddUnique,
      pushSample: options.pushSample || defaultPushSample,
      pushTraceEvent: options.pushTraceEvent || ((report, event) => {
        report.traceEvents ||= [];
        report.traceEvents.push({ id: report.traceEvents.length + 1, severity: "info", ...event });
      }),
      ensureHost: options.ensureHost || ((hosts, macAddress) => {
        hosts[macAddress] ||= { mac: macAddress, ips: [], packets: 0, bytes: 0 };
        return hosts[macAddress];
      }),
      mac: options.mac || defaultMac,
      ip: options.ip || defaultIp,
      ascii: options.ascii || defaultAscii,
      tcpFlowKey: options.tcpFlowKey || ((srcIp, srcPort, dstIp, dstPort) => [`${srcIp}:${srcPort}`, `${dstIp}:${dstPort}`].sort().join(" <-> ")),
      tcpFlags: options.tcpFlags || ((byte) => ({
        fin: Boolean(byte & 0x01),
        syn: Boolean(byte & 0x02),
        rst: Boolean(byte & 0x04),
        psh: Boolean(byte & 0x08),
        ack: Boolean(byte & 0x10),
        urg: Boolean(byte & 0x20),
        names: [byte & 0x02 ? "SYN" : "", byte & 0x10 ? "ACK" : "", byte & 0x01 ? "FIN" : "", byte & 0x04 ? "RST" : "", byte & 0x08 ? "PSH" : ""].filter(Boolean)
      })),
      tcpWindowScale: options.tcpWindowScale || (() => null),
      collectTcpTimingPacket: options.collectTcpTimingPacket || ((list, packet) => list.push(packet))
    };
  }

  function flow(flows, src, srcPort, dst, dstPort, transport) {
    const key = [src, srcPort, dst, dstPort, transport].join("|");
    if (!flows.has(key)) flows.set(key, { src, srcPort, dst, dstPort, transport, packets: 0 });
    flows.get(key).packets += 1;
  }

  function tcpConnectionKey(srcIp, srcPort, dstIp, dstPort) {
    if (reassembly.tcpConnectionKey) {
      return reassembly.tcpConnectionKey(srcIp, srcPort, dstIp, dstPort, {
        endpointKey: (ipAddress, port) => `${ipAddress}:${port}`
      });
    }
    return [`${srcIp}:${srcPort}`, `${dstIp}:${dstPort}`].sort().join(" <-> ");
  }

  function collectTcpSegment(tcpSegments, srcIp, srcPort, dstIp, dstPort, connectionEpoch, seq, view, start, end, packet, timestamp, srcMac) {
    reassembly.collectTcpSegment(tcpSegments, srcIp, srcPort, dstIp, dstPort, connectionEpoch, seq, view, start, end, packet, timestamp, srcMac);
  }

  function parseTcpDoipSegments(tcpSegments, report, announcementKeys, options) {
    reassembly.parseTcpDoipSegments(tcpSegments, report, announcementKeys, {
      parseDoipBytes: (bytes, metaForOffset, transport, srcIp, srcPort, dstIp, dstPort, targetReport, keys) => parseDoipBytes(bytes, metaForOffset, transport, srcIp, srcPort, dstIp, dstPort, targetReport, keys, options),
      tcpFlowKey: options.tcpFlowKey,
      ensureTcpAnalysis: (targetReport) => {
        targetReport.tcpAnalysis ||= options.emptyReport().tcpAnalysis;
        return targetReport.tcpAnalysis;
      }
    });
  }

  function parsePcap(buffer, source, rawOptions = {}) {
    const options = resolveOptions(rawOptions);
    const view = new DataView(buffer);
    if (view.byteLength < 24) throw new Error("File is too small to be a pcap.");
    const magic = view.getUint32(0, false);
    const magicLE = view.getUint32(0, true);
    let littleEndian;
    let nano = false;
    if (magicLE === 0xa1b2c3d4) littleEndian = true;
    else if (magic === 0xa1b2c3d4) littleEndian = false;
    else if (magicLE === 0xa1b23c4d) {
      littleEndian = true;
      nano = true;
    } else if (magic === 0xa1b23c4d) {
      littleEndian = false;
      nano = true;
    } else {
      throw new Error("Unsupported capture format. This lightweight app accepts classic pcap, not pcapng.");
    }

    const network = view.getUint32(20, littleEndian);
    if (network !== 1) throw new Error(`Unsupported pcap link type ${network}; expected Ethernet.`);

    const report = options.emptyReport();
    report.source = source;
    report.pcap = {
      format: "pcap",
      version: `${view.getUint16(4, littleEndian)}.${view.getUint16(6, littleEndian)}`,
      snaplen: view.getUint32(16, littleEndian),
      linkType: network
    };

    const flows = new Map();
    const talkers = {};
    const announcementKeys = new Set();
    const tcpSegments = new Map();
    const tcpConnectionEpochs = new Map();
    const tcpTimingPackets = [];
    const divisor = nano ? 1_000_000_000 : 1_000_000;
    let offset = 24;
    let packet = 0;

    while (offset + 16 <= view.byteLength) {
      const tsSec = view.getUint32(offset, littleEndian);
      const tsFrac = view.getUint32(offset + 4, littleEndian);
      const inclLen = view.getUint32(offset + 8, littleEndian);
      const origLen = view.getUint32(offset + 12, littleEndian);
      offset += 16;
      const frameStart = offset;
      const frameEnd = frameStart + inclLen;
      offset = frameEnd;
      if (frameEnd > view.byteLength || inclLen < 14) continue;

      packet += 1;
      const timestamp = tsSec + tsFrac / divisor;
      report.summary.firstTimestamp ??= timestamp;
      report.summary.lastTimestamp = timestamp;
      report.summary.totalPackets += 1;
      report.summary.totalBytes += origLen;

      const srcMac = options.mac(view, frameStart + 6);
      const host = options.ensureHost(report.hosts, srcMac);
      host.packets += 1;
      host.bytes += origLen;
      options.add(talkers, srcMac);

      let etherType = view.getUint16(frameStart + 12, false);
      let pos = frameStart + 14;
      while (VLAN_TYPES.has(etherType) && pos + 4 <= frameEnd) {
        etherType = view.getUint16(pos + 2, false);
        pos += 4;
      }

      if (etherType === ETH_ARP && pos + 28 <= frameEnd) {
        parseArp(view, pos, packet, timestamp, report, options);
        continue;
      }
      if (etherType !== ETH_IPV4 || pos + 20 > frameEnd) {
        options.add(report.summary.protocolCounts, `EtherType 0x${etherType.toString(16).padStart(4, "0")}`);
        continue;
      }

      const ihl = (view.getUint8(pos) & 0x0f) * 4;
      if ((view.getUint8(pos) >> 4) !== 4 || pos + ihl > frameEnd) continue;
      const proto = view.getUint8(pos + 9);
      const srcIp = options.ip(view, pos + 12);
      const dstIp = options.ip(view, pos + 16);
      options.addUnique(host.ips, srcIp);
      const l4 = pos + ihl;

      if (proto === 17 && l4 + 8 <= frameEnd) {
        const srcPort = view.getUint16(l4, false);
        const dstPort = view.getUint16(l4 + 2, false);
        const udpLen = view.getUint16(l4 + 4, false);
        const payloadStart = l4 + 8;
        const payloadEnd = Math.min(l4 + udpLen, frameEnd);
        flow(flows, srcIp, srcPort, dstIp, dstPort, "UDP");
        if (DHCP_PORTS.has(srcPort) || DHCP_PORTS.has(dstPort)) {
          parseDhcp(view, payloadStart, payloadEnd, packet, timestamp, srcMac, srcIp, dstIp, report, options);
        } else if (srcPort === DOIP_PORT || dstPort === DOIP_PORT) {
          options.add(report.summary.protocolCounts, "DoIP UDP");
          report.doip.count += 1;
          report.doip.udpCount += 1;
          parseDoip(view, payloadStart, payloadEnd, packet, timestamp, "UDP", srcIp, srcPort, dstIp, dstPort, srcMac, report, announcementKeys, options);
        } else {
          options.add(report.summary.protocolCounts, "UDP");
        }
      } else if (proto === 6 && l4 + 20 <= frameEnd) {
        const srcPort = view.getUint16(l4, false);
        const dstPort = view.getUint16(l4 + 2, false);
        const dataOffset = (view.getUint8(l4 + 12) >> 4) * 4;
        const seq = view.getUint32(l4 + 4, false);
        const ackNumber = view.getUint32(l4 + 8, false);
        const flagByte = view.getUint8(l4 + 13);
        const flags = options.tcpFlags(flagByte);
        const windowSize = view.getUint16(l4 + 14, false);
        const windowScale = options.tcpWindowScale(view, l4 + 20, l4 + dataOffset);
        const payloadStart = l4 + dataOffset;
        const tcpPayloadLength = Math.max(0, frameEnd - payloadStart);
        flow(flows, srcIp, srcPort, dstIp, dstPort, "TCP");
        if (srcPort === DOIP_PORT || dstPort === DOIP_PORT) {
          options.collectTcpTimingPacket(tcpTimingPackets, { packet, timestamp, srcIp, srcPort, dstIp, dstPort, seq, ackNumber, flags, windowSize, windowScale, headerLength: dataOffset, payloadLength: tcpPayloadLength });
          options.add(report.summary.protocolCounts, "DoIP TCP");
          report.doip.count += 1;
          report.doip.tcpCount += 1;
          const connectionKey = tcpConnectionKey(srcIp, srcPort, dstIp, dstPort);
          let connectionEpoch = tcpConnectionEpochs.get(connectionKey) || 0;
          if (flags.syn && !flags.ack) {
            connectionEpoch += 1;
            tcpConnectionEpochs.set(connectionKey, connectionEpoch);
          }
          if (tcpPayloadLength) {
            collectTcpSegment(tcpSegments, srcIp, srcPort, dstIp, dstPort, connectionEpoch, seq, view, payloadStart, frameEnd, packet, timestamp, srcMac);
          }
        } else {
          options.add(report.summary.protocolCounts, "TCP");
        }
      } else {
        options.add(report.summary.protocolCounts, `IP proto ${proto}`);
      }
    }

    report.summary.durationSeconds = Number(((report.summary.lastTimestamp || 0) - (report.summary.firstTimestamp || 0)).toFixed(6));
    parseTcpDoipSegments(tcpSegments, report, announcementKeys, options);
    options.finalizeTcpAnalysis(report, tcpTimingPackets);
    options.finalizeDiagnostics(report);
    report.identity = options.buildIdentityAnalysis(report);
    report.topology = options.buildTopologyAnalysis(report);
    report.validationCentre = options.buildValidationCentre(report);
    report.topTalkers = Object.entries(talkers)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 30)
      .map(([key, count]) => ({ key, count }));
    report.flows = Array.from(flows.values()).sort((a, b) => b.packets - a.packets).slice(0, 80);
    return report;
  }

  function parseArp(view, pos, packet, timestamp, report, rawOptions = {}) {
    const options = resolveOptions(rawOptions);
    options.add(report.summary.protocolCounts, "ARP");
    report.arp.count += 1;
    if (view.getUint16(pos, false) !== 1 || view.getUint16(pos + 2, false) !== ETH_IPV4) return;
    const opCode = view.getUint16(pos + 6, false);
    const operation = opCode === 1 ? "request" : opCode === 2 ? "reply" : `op-${opCode}`;
    const senderMac = options.mac(view, pos + 8);
    const senderIp = options.ip(view, pos + 14);
    const targetMac = options.mac(view, pos + 18);
    const targetIp = options.ip(view, pos + 24);
    options.add(report.arp.operations, operation);
    const host = options.ensureHost(report.hosts, senderMac);
    options.addUnique(host.ips, senderIp);
    options.pushTraceEvent(report, {
      category: "arp",
      type: operation,
      label: `ARP ${operation}`,
      ...options.traceLaneForEndpoint("ARP", senderMac, senderIp),
      timestamp,
      packet,
      operation,
      srcMac: senderMac,
      srcIp: senderIp,
      targetMac,
      targetIp
    });
    options.pushSample(report.arp.samples, { packet, timestamp, operation, senderMac, senderIp, targetMac, targetIp });
  }

  function parseDhcp(view, start, end, packet, timestamp, srcMac, srcIp, dstIp, report, rawOptions = {}) {
    const options = resolveOptions(rawOptions);
    if (end - start < 240 || view.getUint32(start + 236, false) !== 0x63825363) return;
    options.add(report.summary.protocolCounts, "DHCP");
    report.dhcp.count += 1;
    const op = view.getUint8(start);
    const xid = view.getUint32(start + 4, false).toString(16).padStart(8, "0");
    const clientMac = options.mac(view, start + 28);
    const yourIp = options.ip(view, start + 16);
    const opt = {};
    let pos = start + 240;
    while (pos < end) {
      const code = view.getUint8(pos++);
      if (code === 255) break;
      if (code === 0) continue;
      if (pos >= end) break;
      const len = view.getUint8(pos++);
      opt[code] = [pos, len];
      pos += len;
    }
    const optByte = (code) => opt[code] ? view.getUint8(opt[code][0]) : 0;
    const optIp = (code) => opt[code] && opt[code][1] === 4 ? options.ip(view, opt[code][0]) : null;
    const optAscii = (code) => opt[code] ? options.ascii(view, opt[code][0], opt[code][1]) : null;
    const optU32 = (code) => opt[code] && opt[code][1] === 4 ? view.getUint32(opt[code][0], false) : null;
    const messageType = DHCP_TYPES[optByte(53)] || `Type ${optByte(53)}`;
    const hostname = optAscii(12);
    const requestedIp = optIp(50);
    const serverId = optIp(54);
    const vendor = optAscii(60);
    const leaseSeconds = optU32(51);

    options.add(report.dhcp.messageTypes, messageType);
    report.dhcp.clients[clientMac] ||= { mac: clientMac, hostname: null, messages: {}, ips: [] };
    const client = report.dhcp.clients[clientMac];
    options.add(client.messages, messageType);
    if (hostname) client.hostname = hostname;
    if (yourIp !== "0.0.0.0") options.addUnique(client.ips, yourIp);
    if (requestedIp) options.addUnique(client.ips, requestedIp);
    if (serverId) {
      report.dhcp.servers[serverId] ||= { messages: {}, offeredIps: [] };
      options.add(report.dhcp.servers[serverId].messages, messageType);
      if (yourIp !== "0.0.0.0") options.addUnique(report.dhcp.servers[serverId].offeredIps, yourIp);
    }
    const dhcpLane = op === 2
      ? options.traceLaneForEndpoint("DHCP server", null, serverId || srcIp)
      : options.traceLaneForEndpoint("DHCP client", clientMac, requestedIp || yourIp || srcIp);
    const sample = {
      packet,
      timestamp,
      messageType,
      op: op === 1 ? "request" : op === 2 ? "reply" : op,
      xid,
      clientMac,
      srcIp,
      dstIp,
      yourIp,
      requestedIp,
      serverId,
      hostname,
      vendor,
      leaseSeconds
    };
    options.pushTraceEvent(report, {
      category: "dhcp",
      type: messageType,
      label: `DHCP ${messageType}`,
      ...dhcpLane,
      ...sample
    });
    options.pushSample(report.dhcp.samples, sample);
  }

  function parseDoip(view, start, end, packet, timestamp, transport, srcIp, srcPort, dstIp, dstPort, srcMac, report, announcementKeys, rawOptions = {}) {
    const bytes = new Uint8Array(view.buffer.slice(start, end));
    return parseDoipBytes(bytes, () => ({ packet, timestamp, srcMac }), transport, srcIp, srcPort, dstIp, dstPort, report, announcementKeys, rawOptions);
  }

  function diagnosticAckCodeName(payloadType, ackCode) {
    if (payloadType === "0x8003") return DOIP_DIAGNOSTIC_NACK_CODES[ackCode] || "Diagnostic negative acknowledgement";
    return "";
  }

  function genericNackCodeName(nackCode) {
    return DOIP_GENERIC_NACK_CODES[nackCode] || "Generic DoIP header negative acknowledgement";
  }

  function routingActivationResponseCodeName(code) {
    return DOIP_ROUTING_ACTIVATION_RESPONSE_CODES[code] || "Routing activation response";
  }

  function parseGenericNack(view, bodyStart, payloadLength, doipSample, report) {
    const nackCodeValue = payloadLength >= 1 ? view.getUint8(bodyStart) : null;
    const nackCode = nackCodeValue === null ? "" : hexByte(nackCodeValue);
    const nackCodeName = nackCodeValue === null ? "Generic DoIP header negative acknowledgement" : genericNackCodeName(nackCodeValue);
    doipSample.nackCode = nackCode;
    doipSample.nackCodeName = nackCodeName;
    report.doip ||= {};
    report.doip.genericNacks ||= [];
    report.doip.genericNacks.push({
      packet: doipSample.packet,
      timestamp: doipSample.timestamp,
      transport: doipSample.transport,
      srcIp: doipSample.srcIp,
      srcMac: doipSample.srcMac,
      srcPort: doipSample.srcPort,
      dstIp: doipSample.dstIp,
      dstPort: doipSample.dstPort,
      payloadType: doipSample.payloadType,
      payloadName: doipSample.payloadName,
      nackCode,
      nackCodeName,
      payloadLength
    });
  }

  function previousDiagnosticAddresses(view, bodyStart, payloadLength) {
    if (payloadLength < 9) return { previousSource: "", previousTarget: "" };
    return {
      previousSource: hexWord(view.getUint16(bodyStart + 5, false)),
      previousTarget: hexWord(view.getUint16(bodyStart + 7, false))
    };
  }

  function parseDiagnosticAckNak(view, bodyStart, payloadLength, doipSample, report) {
    const source = view.getUint16(bodyStart, false);
    const target = view.getUint16(bodyStart + 2, false);
    const ackCodeValue = view.getUint8(bodyStart + 4);
    const ackCode = hexByte(ackCodeValue);
    const previousStart = view.byteOffset + bodyStart + 5;
    const previousEnd = view.byteOffset + bodyStart + payloadLength;
    const previous = payloadLength > 5 ? bytesToHex(new Uint8Array(view.buffer.slice(previousStart, previousEnd))) : "";
    const previousAddresses = previousDiagnosticAddresses(view, bodyStart, payloadLength);
    const ackCodeName = diagnosticAckCodeName(doipSample.payloadType, ackCodeValue);
    doipSample.source = hexWord(source);
    doipSample.target = hexWord(target);
    doipSample.ackCode = ackCode;
    doipSample.ackCodeName = ackCodeName;
    doipSample.previousMessageHex = previous;
    doipSample.previousSource = previousAddresses.previousSource;
    doipSample.previousTarget = previousAddresses.previousTarget;
    report.diagnostics ||= {};
    report.diagnostics.ackNak ||= [];
    report.diagnostics.ackNak.push({
      packet: doipSample.packet,
      timestamp: doipSample.timestamp,
      type: doipSample.payloadType,
      typeName: doipSample.payloadName,
      srcIp: doipSample.srcIp,
      srcMac: doipSample.srcMac,
      srcPort: doipSample.srcPort,
      dstIp: doipSample.dstIp,
      dstPort: doipSample.dstPort,
      source: doipSample.source,
      target: doipSample.target,
      ackCode,
      ackCodeName,
      previousSource: previousAddresses.previousSource,
      previousTarget: previousAddresses.previousTarget,
      previousMessageHex: previous
    });
  }

  function parseDoipBytes(bytes, metaForOffset, transport, srcIp, srcPort, dstIp, dstPort, report, announcementKeys, rawOptions = {}) {
    const options = resolveOptions(rawOptions);
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    let pos = 0;
    let parsed = 0;
    while (pos + 8 <= bytes.length) {
      const version = view.getUint8(pos);
      const inverse = view.getUint8(pos + 1);
      const payloadType = view.getUint16(pos + 2, false);
      const payloadLength = view.getUint32(pos + 4, false);
      const bodyStart = pos + 8;
      const bodyEnd = bodyStart + payloadLength;
      if ((version ^ inverse) !== 0xff || bodyEnd > bytes.length) {
        pos += 1;
        continue;
      }
      const meta = metaForOffset(pos) || {};
      const key = `0x${payloadType.toString(16).padStart(4, "0")} ${DOIP_TYPES[payloadType] || "Unknown"}`;
      options.add(report.doip.payloadTypes, key);
      const sample = {
        packet: meta.packet,
        timestamp: meta.timestamp,
        transport,
        srcIp,
        srcMac: meta.srcMac || "",
        srcPort,
        dstIp,
        dstPort,
        protocolVersion: `0x${version.toString(16).padStart(2, "0")}`,
        payloadType: `0x${payloadType.toString(16).padStart(4, "0")}`,
        payloadName: DOIP_TYPES[payloadType] || "Unknown",
        payloadLength
      };
      if (payloadType === 0x0000) {
        parseGenericNack(view, bodyStart, payloadLength, sample, report);
      } else if (payloadType === 0x0004 && payloadLength >= 32) {
        const vin = options.ascii(view, bodyStart, 17);
        const logical = view.getUint16(bodyStart + 17, false);
        const logicalAddress = `0x${logical.toString(16).padStart(4, "0")}`;
        const eid = options.mac(view, bodyStart + 19);
        const gid = options.mac(view, bodyStart + 25);
        sample.vin = vin;
        sample.logicalAddress = logicalAddress;
        sample.eid = eid;
        sample.gid = gid;
        sample.furtherActionRequired = view.getUint8(bodyStart + 31);
        sample.vinGidSyncStatus = payloadLength >= 33 ? view.getUint8(bodyStart + 32) : null;
        report.doip.logicalAddresses[logicalAddress] ||= { count: 0, vins: [], eids: [], sourceMacs: [], ips: [] };
        const logicalRecord = report.doip.logicalAddresses[logicalAddress];
        logicalRecord.vins ||= [];
        logicalRecord.eids ||= [];
        logicalRecord.sourceMacs ||= [];
        logicalRecord.ips ||= [];
        logicalRecord.count += 1;
        options.addUnique(logicalRecord.vins, vin);
        options.addUnique(logicalRecord.eids, eid);
        options.addUnique(logicalRecord.sourceMacs, sample.srcMac);
        options.addUnique(logicalRecord.ips, srcIp);
        const announcementKey = [vin, logicalAddress, eid, gid, srcIp, sample.srcMac].join("|");
        if (!announcementKeys.has(announcementKey)) {
          announcementKeys.add(announcementKey);
          report.doip.announcements.push({ ...sample });
        }
        options.enrichEcuFromAnnouncement(report, sample);
      } else if ((payloadType === 0x0005 || payloadType === 0x0006) && payloadLength >= 2) {
        sample.logicalAddress = hexWord(view.getUint16(bodyStart, false));
        sample.routingActivationTesterAddress = sample.logicalAddress;
        if (payloadType === 0x0006 && payloadLength >= 4) {
          sample.routingActivationEntityAddress = hexWord(view.getUint16(bodyStart + 2, false));
          if (payloadLength >= 5) {
            const responseCode = view.getUint8(bodyStart + 4);
            sample.routingActivationResponseCode = hexByte(responseCode);
            sample.routingActivationResponseCodeName = routingActivationResponseCodeName(responseCode);
          }
        }
      } else if (payloadType === 0x8001 && payloadLength >= 5) {
        options.parseDiagnosticMessage(view, bodyStart, payloadLength, sample, report);
      } else if ((payloadType === 0x8002 || payloadType === 0x8003) && payloadLength >= 5) {
        options.parseDiagnosticAckNak(view, bodyStart, payloadLength, sample, report);
      }
      if (payloadType !== 0x8001) {
        const category = payloadType === 0x8002 || payloadType === 0x8003 ? "ack" : "doip";
        const lane = sample.logicalAddress ? options.traceLaneForLogical("ecu", sample.logicalAddress) : { laneKey: "doip:setup", laneLabel: "DoIP Setup" };
        options.pushTraceEvent(report, {
          category,
          type: sample.payloadType,
          label: sample.payloadName,
          ...lane,
          timestamp: sample.timestamp,
          packet: sample.packet,
          transport,
          srcIp,
          srcPort,
          dstIp,
          dstPort,
          payloadType: sample.payloadType,
          payloadName: sample.payloadName,
          payloadLength,
          source: sample.source,
          target: sample.target,
          ackCode: sample.ackCode,
          ackCodeName: sample.ackCodeName,
          nackCode: sample.nackCode,
          nackCodeName: sample.nackCodeName,
          previousSource: sample.previousSource,
          previousTarget: sample.previousTarget,
          previousMessageHex: sample.previousMessageHex,
          logicalAddress: sample.logicalAddress,
          routingActivationTesterAddress: sample.routingActivationTesterAddress,
          routingActivationEntityAddress: sample.routingActivationEntityAddress,
          routingActivationResponseCode: sample.routingActivationResponseCode,
          routingActivationResponseCodeName: sample.routingActivationResponseCodeName,
          vin: sample.vin,
          eid: sample.eid,
          gid: sample.gid
        });
      }
      options.pushSample(report.doip.samples, sample);
      parsed += 1;
      pos = bodyEnd;
    }
    return parsed;
  }

  global.HarnessPcapParser = {
    parsePcap,
    parseArp,
    parseDhcp,
    parseDoip,
    parseDoipBytes,
    parseGenericNack,
    parseDiagnosticAckNak,
    genericNackCodeName,
    routingActivationResponseCodeName,
    diagnosticAckCodeName,
    previousDiagnosticAddresses,
    flow
  };
})(window);
