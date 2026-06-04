const {
  DOIP_PORT,
  DHCP_PORTS,
  ETH_IPV4,
  ETH_ARP,
  VLAN_TYPES,
  DHCP_TYPES,
  DOIP_TYPES
} = window.HarnessProtocol;

const {
  hexByte,
  hexWord,
  bytesToHex,
  hexToBytes,
  bytesToAsciiPreview,
  escapeHtml,
  formatCell,
  formatNumber,
  formatBytes,
  formatDurationValue,
  formatMs,
  toCsv
} = window.HarnessFormatters;
const { badge, metricGrid } = window.HarnessUi;
const formatTimeDelta = (timestamp) => window.HarnessFormatters.formatTimeDelta(timestamp, currentReport.summary?.firstTimestamp || timestamp);

const PERSIST_DB = "harness-capture-cache";
const PERSIST_STORE = "captures";
const PERSIST_KEY = "last-report";
const PERSIST_VERSION = 8;
const ECU_MAP_STORAGE_KEY = "harness-ecu-map-v1";
const persistenceConfig = {
  dbName: PERSIST_DB,
  storeName: PERSIST_STORE,
  key: PERSIST_KEY,
  version: PERSIST_VERSION
};

let currentReport = emptyReport();
let selectedEcuAddress = null;
let selectedDiagnosticTab = "overview";
let selectedTcpFlowKey = null;
let expandedDidGroups = new Set();
let activeTool = "home";
let selectedTopologyItem = null;
let selectedValidationFindingId = null;
let selectedLifecycleNodeId = null;
let selectedLifecycleStageKey = null;
let importedEcuMap = loadEcuMapFromStorage();
let cancelCachedLoad = false;
let pendingCachedReport = null;

const TOOL_META = {
  home: {
    eyebrow: "Harness workbench",
    title: "Analysis instruments",
    description: "Choose a tool for the loaded capture."
  },
  uds: {
    eyebrow: "UDS",
    title: "UDS Analyser",
    description: "Inspect services, sessions, NRCs, timelines, and raw UDS by ECU."
  },
  validation: {
    eyebrow: "Validation",
    title: "Validation Centre",
    description: "Review warnings and errors across download, TCP, identity, UDS, topology, and parsing."
  },
  trace: {
    eyebrow: "Trace",
    title: "Protocol Trace",
    description: "View diagnostic activity in ECU lanes."
  },
  transport: {
    eyebrow: "TCP",
    title: "Transport Timing",
    description: "Analyse DoIP TCP timing, retransmits, duplicate ACKs, and windows."
  },
  dids: {
    eyebrow: "DID",
    title: "DID Explorer",
    description: "Review Service 0x22 and 0x62 values by ECU."
  },
  transfers: {
    eyebrow: "Software",
    title: "Software Download",
    description: "Validate transfers, payloads, timing, and hex exports."
  },
  download: {
    eyebrow: "Software",
    title: "Software Download",
    description: "Validate transfers, payloads, timing, and hex exports."
  },
  discovery: {
    eyebrow: "DoIP",
    title: "Discovery Console",
    description: "Review capture totals, hosts, DoIP, DHCP, and ARP."
  },
  identity: {
    eyebrow: "L2/L3",
    title: "Address Identity",
    description: "Find IP/MAC reuse, DHCP gaps, ARP conflicts, and logical-address drift."
  },
  topology: {
    eyebrow: "Topology",
    title: "Node Map",
    description: "Map testers, gateways, endpoints, and logical ECUs."
  },
  raw: {
    eyebrow: "Raw",
    title: "Packet Samples",
    description: "Inspect DoIP, DHCP, ARP, and flow samples."
  }
};

const TOOL_INFO = {
  validation: {
    title: "Validation Centre",
    summary: "A triage view for findings that may need review across diagnostics, transport, identity, topology, parser, and software download evidence.",
    sections: [
      ["What this tool shows", ["Actionable and informational findings grouped from the rest of the workbench.", "Routine NRCs remain inspectable, but the default presentation is designed to reduce noise."]],
      ["How to read it", ["Use the view mode first, then severity/source/category/search as secondary filters.", "Select a finding to see compact evidence and use Open to jump to the source tool."]],
      ["Evidence used", ["UDS NRC groups, DoIP ACK/NACKs, TCP timing events, identity checks, topology evidence, parser warnings, and SWDL validation."]],
      ["Important assumptions", ["DoIP unknown-target NACKs are treated as rejected diagnostic routes, not ownership evidence.", "AutoIP after DHCP is only a validation problem when later UDS responses are observed from AutoIP."]]
    ]
  },
  uds: {
    title: "UDS Analyser",
    summary: "A per-ECU diagnostic view for services, sessions, DIDs, DTCs, transfers, routines, errors, timelines, and raw UDS messages.",
    sections: [
      ["What this tool shows", ["The left table lists logical ECUs observed in UDS or DoIP evidence.", "The tabs show decoded diagnostic activity for the selected ECU."]],
      ["How to read it", ["Start with Overview for service mix and counts, then move to DIDs, DTCs, Transfers, or Raw Messages for detail.", "The ECU name is mapped when an imported ECU map or built-in mappings contain the logical address."]],
      ["Evidence used", ["UDS requests/responses carried over DoIP, decoded service payloads, DTC/DID/transfer builders, and imported ECU mappings."]],
      ["Known limits", ["Partial captures may contain requests without matching responses.", "Very long raw payloads are previewed in tables and remain available via hover or expanded detail where supported."]]
    ]
  },
  dids: {
    title: "DID Explorer",
    summary: "A focused view of ReadDataByIdentifier traffic and returned DID values across ECUs.",
    sections: [
      ["What this tool shows", ["DID requests and positive responses grouped by ECU and DID.", "Value previews, ASCII previews, history rows, and plots for numeric-looking values."]],
      ["How to read it", ["Use grouped rows to compare latest values and expand histories when needed.", "Plots are useful for repeated values but are not a signal that the DID is semantically numeric."]],
      ["Evidence used", ["UDS 0x22 requests, 0x62 positive responses, source/target logical addresses, timestamps, and raw payload bytes."]],
      ["Known limits", ["The tool does not know DID semantics unless mappings are provided.", "Hex previews are capped in tables to keep layout readable."]]
    ]
  },
  download: {
    title: "Software Download",
    summary: "A software-download analysis view for RequestDownload/Upload/FileTransfer sessions, TransferData blocks, validation, timing, and exportable hex.",
    sections: [
      ["What this tool shows", ["Transfer sessions grouped by ECU and gateway/IP path.", "Payload progress, block counters, ACK evidence, pre/post conditions, raw messages, and campaign summary exports."]],
      ["How to read it", ["Select a transfer segment on the left, then use the tabs for matrix, overview, block grid, validation, timeline, and raw evidence.", "Missing TransferExit is treated as a major completeness issue."]],
      ["Evidence used", ["UDS 0x34/0x35/0x38, 0x36, 0x76, 0x37/0x77, timestamps, packet numbers, payload bytes, and validation findings."]],
      ["Important assumptions", ["Repeated block counters can be normal wraparound; duplicates are not automatically bad.", "Unobserved block-counter slots outside the required range are shown as non-issues."]]
    ]
  },
  trace: {
    title: "Protocol Trace",
    summary: "A time-lane view of diagnostic and network events across the capture.",
    sections: [
      ["What this tool shows", ["UDS, DoIP, DHCP, ARP, DoIP ACK/NACK, and optional TCP events in timeline lanes.", "Layer toggles help narrow the view to the protocol evidence you care about."]],
      ["How to read it", ["Use filters to focus on an ECU or event kind, then click/hover timeline items for packet and timing context.", "Use Measure to compare time deltas between events."]],
      ["Evidence used", ["Trace events emitted during parsing plus diagnostic, transport, and discovery analysis events."]],
      ["Known limits", ["Timeline completeness depends on what was captured; missing setup traffic may simply be outside the pcap."]]
    ]
  },
  transport: {
    title: "Transport Timing",
    summary: "A TCP/DoIP transport view for socket flows, ACK timing, retransmissions, receive windows, resets, and capture gaps.",
    sections: [
      ["What this tool shows", ["DoIP TCP flows between testers and Ethernet nodes.", "Flow-control charts, ACK timing, duplicate ACKs, retransmissions, zero-window events, resets, and gaps."]],
      ["How to read it", ["Select a flow to inspect endpoints, timing details, notable events, and the receive-window graph.", "The receive-window graph expands the low-window range so 0-4 KB behaviour remains visible."]],
      ["Evidence used", ["TCP packet metadata, sequence/ACK tracking, payload lengths, DoIP port flows, and reconstructed transport events."]],
      ["Important assumptions", ["RST packets with zero window are not treated as zero-window flow-control issues.", "Partial captures may create gaps where sequence continuity cannot be proven."]]
    ]
  },
  discovery: {
    title: "Discovery Console",
    summary: "A discovery and lifecycle view for DoIP nodes, announcements, vehicle ID responses, routing activation, DHCP, ARP, TCP sockets, and diagnostics.",
    sections: [
      ["What this tool shows", ["A node-centric DoIP lifecycle panel plus raw discovery evidence.", "Lifecycle stages include ARP, TCP socket, vehicle discovery, routing activation, and diagnostics."]],
      ["How to read it", ["Use filters to focus on issues, Ethernet nodes, gateways/sockets, behind-socket logicals, missing routing, or rejected targets.", "Select a node and then a stage to inspect concise evidence."]],
      ["Evidence used", ["ARP, TCP flows, DoIP vehicle announcements, vehicle ID requests/responses, routing activation, UDS events, and DoIP NACKs."]],
      ["Important assumptions", ["Behind-socket logical addresses do not require their own TCP socket unless separately announced.", "AutoIP-to-DHCP can be one expected lifecycle when DHCP Ack evidence supports it."]]
    ]
  },
  topology: {
    title: "Node Map",
    summary: "A simplified DoIP socket map showing which Ethernet nodes need their own TCP sockets and which logical addresses are routed through them.",
    sections: [
      ["What this tool shows", ["Socket endpoints, direct logical addresses, routed logical addresses, and rejected unknown targets.", "The graphical modal shows tester to gateway/socket to downstream Ethernet-node relationships."]],
      ["How to read it", ["Cards show socket IP, direct logical address, routing activation, and logicals addressed through that socket.", "Rejected unknown-target branches indicate requests sent through the wrong Ethernet node."]],
      ["Evidence used", ["DoIP announcements, routing activation, UDS request destination IPs, socket-map evidence, and diagnostic NACK 0x03."]],
      ["Important assumptions", ["Unknown-target NACKs do not imply MAC ownership of the attempted logical ECU.", "The attempted ECU is taken from embedded previous diagnostic target, or inferred from the nearest prior request to that socket."]]
    ]
  },
  identity: {
    title: "Address Identity",
    summary: "A network identity view for IP/MAC ownership, DHCP/ARP evidence, and logical-address identity consistency.",
    sections: [
      ["What this tool shows", ["Host/IP observations, DHCP clients, ARP conflicts, logical-address MAC/IP evidence, and identity findings."]],
      ["How to read it", ["Use findings to spot conflicts, then inspect host-map evidence for IPs, MACs, DHCP state, and roles.", "Multiple IPs on one MAC can be expected, especially AutoIP followed by DHCP."]],
      ["Evidence used", ["Host observations, ARP samples, DHCP samples, DoIP announcements, UDS ECU IPs, and DoIP diagnostic NACKs."]],
      ["Important assumptions", ["Wrong-node unknown-target NACK responses are excluded from MAC ownership evidence.", "AutoIP plus DHCP assignment is not treated as ambiguous by itself."]]
    ]
  },
  raw: {
    title: "Packet Samples",
    summary: "A compact sample view for decoded protocol records and observed flows.",
    sections: [
      ["What this tool shows", ["Sample tables for DoIP, DHCP, ARP, and flow evidence extracted during parsing."]],
      ["How to read it", ["Choose the sample type from the dropdown and use the table as raw supporting context for other tools."]],
      ["Evidence used", ["Parser output, decoded DoIP payload metadata, DHCP/ARP samples, and flow summaries."]],
      ["Known limits", ["This is a sample/context view, not a full packet browser or Wireshark replacement."]]
    ]
  }
};
TOOL_INFO.transfers = TOOL_INFO.download;

const $ = (id) => document.getElementById(id);

function setCaptureOverlayState(state, detail = "") {
  const overlay = $("captureOverlay");
  if (!overlay) return;
  const title = $("captureOverlayTitle");
  const text = $("captureOverlayText");
  const kicker = $("captureOverlayKicker");
  const openButton = $("captureOverlayOpen");
  const stopButton = $("captureOverlayStop");
  const cachedButton = $("captureOverlayLoadCached");
  const isLoading = state === "loading" || state === "checking-cache";
  overlay.classList.toggle("is-loading", isLoading);
  overlay.hidden = state === "loaded";
  if (state === "checking-cache") {
    if (kicker) kicker.textContent = "Checking browser cache";
    if (title) title.textContent = "Checking for cached file";
    if (text) text.textContent = "Looking for a previously loaded capture in this browser.";
    if (openButton) openButton.hidden = true;
    if (cachedButton) cachedButton.hidden = true;
    if (stopButton) stopButton.hidden = true;
    return;
  }
  if (state === "loading") {
    if (kicker) kicker.textContent = "Parsing capture";
    if (title) title.textContent = "Loading capture";
    if (text) text.textContent = detail ? `Reading and analysing ${detail}. The workbench will unlock when parsing has finished.` : "Reading and analysing the pcap. The workbench will unlock when parsing has finished.";
    if (openButton) openButton.hidden = true;
    if (cachedButton) cachedButton.hidden = true;
    if (stopButton) stopButton.hidden = true;
    return;
  }
  if (state === "cached-ready") {
    if (kicker) kicker.textContent = "Cached capture found";
    if (title) title.textContent = "Load cached file?";
    if (text) text.textContent = detail || "A previously loaded capture is available in this browser.";
    if (openButton) openButton.hidden = true;
    if (cachedButton) cachedButton.hidden = false;
    if (stopButton) stopButton.hidden = false;
    return;
  }
  if (state === "error") {
    if (kicker) kicker.textContent = "Capture could not be loaded";
    if (title) title.textContent = "Choose another pcap";
    if (text) text.textContent = detail || "The selected file could not be parsed.";
    if (openButton) openButton.hidden = false;
    if (cachedButton) cachedButton.hidden = true;
    if (stopButton) stopButton.hidden = true;
    return;
  }
  if (kicker) kicker.textContent = "Capture required";
  if (title) title.textContent = "Load a pcap to begin";
  if (text) text.textContent = "Open or drop a classic Ethernet pcap here. The page will unlock once a capture has been loaded.";
  if (openButton) openButton.hidden = false;
  if (cachedButton) cachedButton.hidden = true;
  if (stopButton) stopButton.hidden = true;
}

const downloadController = window.HarnessDownloadController.createDownloadController({
  $,
  getReport: () => currentReport,
  buildDownloadAnalysis,
  ecuCode,
  ecuLabel,
  ecuName,
  formatTimeDelta,
  didHistoryForEcu,
  downloadText,
  downloadHexText
});

const traceController = window.HarnessTraceController.createTraceController({
  $,
  getReport: () => currentReport,
  traceEventsForReport,
  formatTimeDelta,
  escapeHtml,
  ecuLabel,
  openEcuTimeline(ecuAddress) {
    selectedEcuAddress = ecuAddress;
    selectedDiagnosticTab = "timeline";
    openTool("uds");
  }
});

function emptyReport() {
  return {
    source: "",
    pcap: {},
    summary: { totalPackets: 0, totalBytes: 0, durationSeconds: 0, protocolCounts: {} },
    hosts: {},
    arp: { count: 0, operations: {}, samples: [] },
    dhcp: { count: 0, messageTypes: {}, clients: {}, servers: {}, samples: [] },
    doip: {
      count: 0,
      udpCount: 0,
      tcpCount: 0,
      payloadTypes: {},
      announcements: [],
      logicalAddresses: {},
      samples: [],
      genericNacks: []
    },
    diagnostics: {
      ecus: {},
      udsEvents: [],
      didReads: [],
      dtcReads: [],
      transfers: [],
      serviceStats: {},
      negativeResponses: {},
      sessions: [],
      securityAccess: [],
      routineControls: [],
      unmatchedMessages: [],
      ackNak: []
    },
    downloadAnalysis: { sessions: [], findings: [], metrics: {} },
    validationCentre: { summary: {}, findings: [], groups: {} },
    traceEvents: [],
    tcpAnalysis: { flows: [], events: [], ackTimings: [], retransmissions: 0, duplicateAcks: 0, zeroWindows: 0, windowUpdates: 0, gaps: [] },
    identity: { findings: [], hostMap: [], metrics: {} },
    topology: { nodes: [], edges: [], summary: {} },
    doipLifecycle: { nodes: [], summary: {} },
    flows: [],
    topTalkers: [],
    warnings: []
  };
}

function mac(view, offset) {
  return Array.from({ length: 6 }, (_, i) => view.getUint8(offset + i).toString(16).padStart(2, "0")).join(":");
}

function ip(view, offset) {
  return Array.from({ length: 4 }, (_, i) => view.getUint8(offset + i)).join(".");
}

function ascii(view, offset, length) {
  let out = "";
  for (let i = 0; i < length; i += 1) {
    const c = view.getUint8(offset + i);
    if (c >= 32 && c <= 126) out += String.fromCharCode(c);
  }
  return out.trim();
}

function add(map, key, count = 1) {
  map[key] = (map[key] || 0) + count;
}

function ensureHost(hosts, macAddress) {
  hosts[macAddress] ||= { mac: macAddress, ips: [], packets: 0, bytes: 0 };
  return hosts[macAddress];
}

function addUnique(list, value) {
  if (value && !list.includes(value)) list.push(value);
}

function pushSample(list, sample, limit = 140) {
  if (list.length < limit) list.push(sample);
}

function pushTraceEvent(report, event) {
  report.traceEvents ||= [];
  report.traceEvents.push({
    id: report.traceEvents.length + 1,
    severity: "info",
    ...event
  });
}

function traceLaneForLogical(role, address) {
  const label = role === "tester" ? ecuLabel(address, { withAddress: Boolean(ecuName(address)) }) : ecuLabel(address);
  return { laneKey: `${role}:${address}`, laneLabel: `${role === "tester" ? "Tester" : "ECU"} ${label}` };
}

function traceLaneForEndpoint(prefix, macAddress, ipAddress) {
  if (macAddress) return { laneKey: `mac:${macAddress}`, laneLabel: `MAC ${macAddress}` };
  if (ipAddress) return { laneKey: `ip:${ipAddress}`, laneLabel: `${prefix} ${ipAddress}` };
  return { laneKey: prefix.toLowerCase(), laneLabel: prefix };
}

function endpointKey(ipAddress, port) {
  return `${ipAddress}:${port}`;
}

function tcpFlowKey(srcIp, srcPort, dstIp, dstPort) {
  return [endpointKey(srcIp, srcPort), endpointKey(dstIp, dstPort)].sort().join(" <-> ");
}

function tcpFlags(byte) {
  return {
    fin: Boolean(byte & 0x01),
    syn: Boolean(byte & 0x02),
    rst: Boolean(byte & 0x04),
    psh: Boolean(byte & 0x08),
    ack: Boolean(byte & 0x10),
    urg: Boolean(byte & 0x20),
    names: [
      byte & 0x02 ? "SYN" : "",
      byte & 0x10 ? "ACK" : "",
      byte & 0x01 ? "FIN" : "",
      byte & 0x04 ? "RST" : "",
      byte & 0x08 ? "PSH" : ""
    ].filter(Boolean)
  };
}

function tcpSeqEnd(seq, payloadLength, flags) {
  return (seq + payloadLength + (flags.syn ? 1 : 0) + (flags.fin ? 1 : 0)) >>> 0;
}

function tcpWindowScale(view, start, end) {
  let pos = start;
  while (pos < end) {
    const kind = view.getUint8(pos);
    if (kind === 0) break;
    if (kind === 1) {
      pos += 1;
      continue;
    }
    if (pos + 1 >= end) break;
    const length = view.getUint8(pos + 1);
    if (length < 2 || pos + length > end) break;
    if (kind === 3 && length === 3) return view.getUint8(pos + 2);
    pos += length;
  }
  return null;
}

function collectTcpTimingPacket(list, packet) {
  list.push({
    ...packet,
    flowKey: tcpFlowKey(packet.srcIp, packet.srcPort, packet.dstIp, packet.dstPort),
    directionKey: `${endpointKey(packet.srcIp, packet.srcPort)} -> ${endpointKey(packet.dstIp, packet.dstPort)}`,
    endSeq: tcpSeqEnd(packet.seq, packet.payloadLength, packet.flags),
    hasPayload: packet.payloadLength > 0
  });
}

function parsePcap(buffer, source) {
  return window.HarnessPcapParser.parsePcap(buffer, source, pcapParserOptions());
}

function pcapParserOptions() {
  return {
    emptyReport,
    buildIdentityAnalysis,
    buildTopologyAnalysis,
    buildValidationCentre,
    finalizeDiagnostics,
    finalizeTcpAnalysis,
    parseDiagnosticMessage,
    parseDiagnosticAckNak,
    traceLaneForLogical,
    traceLaneForEndpoint,
    enrichEcuFromAnnouncement,
    add,
    addUnique,
    pushSample,
    pushTraceEvent,
    ensureHost,
    mac,
    ip,
    ascii,
    tcpFlowKey,
    tcpFlags,
    tcpSeqEnd,
    tcpWindowScale,
    collectTcpTimingPacket
  };
}

function tcpConnectionKey(srcIp, srcPort, dstIp, dstPort) {
  return window.HarnessTcpDoipReassembly.tcpConnectionKey(srcIp, srcPort, dstIp, dstPort, { endpointKey });
}

function collectTcpSegment(tcpSegments, srcIp, srcPort, dstIp, dstPort, connectionEpoch, seq, view, start, end, packet, timestamp, srcMac) {
  window.HarnessTcpDoipReassembly.collectTcpSegment(tcpSegments, srcIp, srcPort, dstIp, dstPort, connectionEpoch, seq, view, start, end, packet, timestamp, srcMac);
}

function parseTcpDoipSegments(tcpSegments, report, announcementKeys) {
  window.HarnessTcpDoipReassembly.parseTcpDoipSegments(tcpSegments, report, announcementKeys, {
    parseDoipBytes,
    tcpFlowKey,
    ensureTcpAnalysis: (targetReport) => {
      targetReport.tcpAnalysis ||= emptyReport().tcpAnalysis;
      return targetReport.tcpAnalysis;
    }
  });
}

function doipPayloadScore(bytes) {
  return window.HarnessTcpDoipReassembly.doipPayloadScore(bytes);
}

function coalesceTcpSegments(segments) {
  return window.HarnessTcpDoipReassembly.coalesceTcpSegments(segments);
}

function percentile(values, p) {
  return window.HarnessTcpAnalysis.percentile(values, p);
}

const TCP_SMALL_WINDOW_THRESHOLD = window.HarnessTcpAnalysis.TCP_SMALL_WINDOW_THRESHOLD;

function finalizeTcpAnalysis(report, packets) {
  const { analysis, traceEvents } = window.HarnessTcpAnalysis.analyzeTcpTransport(packets, { gaps: report.tcpAnalysis?.gaps || [] });
  for (const event of traceEvents) pushTraceEvent(report, event);
  report.tcpAnalysis = analysis;
}

function parseArp(view, pos, packet, timestamp, report) {
  return window.HarnessPcapParser.parseArp(view, pos, packet, timestamp, report, pcapParserOptions());
}

function parseDhcp(view, start, end, packet, timestamp, srcMac, srcIp, dstIp, report) {
  return window.HarnessPcapParser.parseDhcp(view, start, end, packet, timestamp, srcMac, srcIp, dstIp, report, pcapParserOptions());
}

function parseDoip(view, start, end, packet, timestamp, transport, srcIp, srcPort, dstIp, dstPort, srcMac, report, announcementKeys) {
  return window.HarnessPcapParser.parseDoip(view, start, end, packet, timestamp, transport, srcIp, srcPort, dstIp, dstPort, srcMac, report, announcementKeys, pcapParserOptions());
}

function parseDoipBytes(bytes, metaForOffset, transport, srcIp, srcPort, dstIp, dstPort, report, announcementKeys) {
  return window.HarnessPcapParser.parseDoipBytes(bytes, metaForOffset, transport, srcIp, srcPort, dstIp, dstPort, report, announcementKeys, pcapParserOptions());
}

function flow(flows, src, srcPort, dst, dstPort, transport) {
  return window.HarnessPcapParser.flow(flows, src, srcPort, dst, dstPort, transport);
}

function mappings() {
  return window.UDS_MAPPINGS || { ecus: {}, dids: {}, routines: {}, services: {}, nrcs: {} };
}

function serviceName(sid) {
  return window.HarnessUds.serviceName(sid, mappings());
}

function nrcName(nrc) {
  return window.HarnessUds.nrcName(nrc, mappings());
}

function dtcSubFunctionName(subFunction) {
  return window.HarnessUds.dtcSubFunctionName(subFunction);
}

function dtcStatusLabels(statusByte) {
  return window.HarnessUds.dtcStatusLabels(statusByte);
}

function decodeUds(uds) {
  return window.HarnessUds.decodeUds(uds, mappings());
}

function dtcCode(bytes) {
  return window.HarnessUds.dtcCode(bytes);
}

function decodeDtcRequest(uds) {
  return window.HarnessUds.decodeDtcRequest(uds);
}

function decodeDtcResponse(uds) {
  return window.HarnessUds.decodeDtcResponse(uds);
}

function normaliseLogicalAddress(value) {
  return window.HarnessMappingUtils.normaliseLogicalAddress(value);
}

function loadEcuMapFromStorage() {
  try {
    const parsed = JSON.parse(localStorage.getItem(ECU_MAP_STORAGE_KEY) || "{}");
    if (!parsed || typeof parsed !== "object") return {};
    return Object.fromEntries(Object.entries(parsed).map(([key, value]) => [normaliseLogicalAddress(key), String(value || "").trim()]).filter(([key, value]) => key && value));
  } catch {
    return {};
  }
}

function saveEcuMapToStorage(map) {
  try {
    localStorage.setItem(ECU_MAP_STORAGE_KEY, JSON.stringify(map || {}));
  } catch (error) {
    console.warn("Harness could not cache the ECU map.", error);
  }
}

function splitCsvLine(line) {
  return window.HarnessMappingUtils.splitCsvLine(line);
}

function parseEcuMapCsv(text) {
  return window.HarnessMappingUtils.parseEcuMapCsv(text);
}

function applyEcuMap(report) {
  if (!report?.diagnostics?.ecus) return;
  for (const [address, ecu] of Object.entries(report.diagnostics.ecus)) {
    ecu.name = ecuName(address);
  }
  for (const event of report.diagnostics.udsEvents || []) {
    event.ecuName = ecuName(event.ecuAddress);
  }
  for (const row of report.diagnostics.didReads || []) row.ecuName = ecuName(row.ecuAddress);
  for (const row of report.diagnostics.transfers || []) row.ecuName = ecuName(row.ecuAddress);
  for (const row of report.diagnostics.dtcReads?.rows || []) row.ecuName = ecuName(row.ecuAddress);
  for (const row of report.diagnostics.dtcReads?.summary || []) row.ecuName = ecuName(row.ecuAddress);
  for (const session of report.downloadAnalysis?.sessions || []) session.ecuName = ecuName(session.ecuAddress);
  for (const row of report.downloadAnalysis?.matrixRows || []) row.ecuName = ecuName(row.ecuAddress);
}

function ecuMapStatusText() {
  const count = Object.keys(importedEcuMap || {}).length;
  return count ? `${formatNumber(count)} ECU name mapping${count === 1 ? "" : "s"} cached` : "No ECU name map loaded";
}

function didName(did) {
  return window.HarnessMappingUtils.didName(did, mappings());
}

function routineName(routineId) {
  return window.HarnessMappingUtils.routineName(routineId, mappings());
}

function ecuName(address) {
  return window.HarnessMappingUtils.ecuName(address, mappings(), importedEcuMap);
}

function ecuLabel(address, options = {}) {
  return window.HarnessMappingUtils.ecuLabel(address, options, mappings(), importedEcuMap);
}

function ecuCode(address, options = {}) {
  return window.HarnessMappingUtils.ecuCode(address, options, mappings(), importedEcuMap);
}

function ensureEcu(report, address) {
  report.diagnostics.ecus[address] ||= {
    address,
    name: ecuName(address),
    ips: [],
    macs: [],
    vins: [],
    eids: [],
    gids: [],
    requests: 0,
    responses: 0,
    negatives: 0,
    pending: 0,
    didCount: 0,
    transferCount: 0,
    firstTimestamp: null,
    lastTimestamp: null,
    serviceStats: {},
    nrcStats: {}
  };
  return report.diagnostics.ecus[address];
}

function touchEcu(report, address, timestamp, ipAddress) {
  const ecu = ensureEcu(report, address);
  if (ipAddress) addUnique(ecu.ips, ipAddress);
  if (timestamp !== undefined && timestamp !== null) {
    ecu.firstTimestamp ??= timestamp;
    ecu.lastTimestamp = Math.max(ecu.lastTimestamp || timestamp, timestamp);
  }
  return ecu;
}

function enrichEcuFromAnnouncement(report, announcement) {
  if (!announcement.logicalAddress) return;
  const ecu = touchEcu(report, announcement.logicalAddress, announcement.timestamp, announcement.srcIp);
  addUnique(ecu.macs, announcement.srcMac);
  addUnique(ecu.vins, announcement.vin);
  addUnique(ecu.eids, announcement.eid);
  addUnique(ecu.gids, announcement.gid);
}

function parseDiagnosticMessage(view, bodyStart, payloadLength, doipSample, report) {
  const source = view.getUint16(bodyStart, false);
  const target = view.getUint16(bodyStart + 2, false);
  const udsStart = bodyStart + 4;
  const udsLength = payloadLength - 4;
  if (udsLength <= 0) return;
  const uds = new Uint8Array(view.buffer.slice(udsStart, udsStart + udsLength));
  const decoded = decodeUds(uds);
  const isNegative = decoded.sid === 0x7f;
  const isPositive = decoded.sid >= 0x40 && decoded.sid !== 0x7f;
  const ecuAddress = hexWord(isPositive || isNegative ? source : target);
  const testerAddress = hexWord(isPositive || isNegative ? target : source);
  const ecuIp = isPositive || isNegative ? doipSample.srcIp : doipSample.dstIp;
  const ecu = touchEcu(report, ecuAddress, doipSample.timestamp, ecuIp);
  const event = {
    id: report.diagnostics.udsEvents.length + 1,
    packet: doipSample.packet,
    timestamp: doipSample.timestamp,
    transport: doipSample.transport,
    srcIp: doipSample.srcIp,
    srcPort: doipSample.srcPort,
    dstIp: doipSample.dstIp,
    dstPort: doipSample.dstPort,
    source: hexWord(source),
    target: hexWord(target),
    ecuAddress,
    testerAddress,
    direction: isPositive || isNegative ? "response" : "request",
    responseKind: isNegative ? (decoded.nrc === 0x78 ? "pending" : "negative") : isPositive ? "positive" : "request",
    service: hexByte(decoded.sid),
    serviceName: decoded.name,
    originalService: decoded.originalSid !== null && decoded.originalSid !== undefined ? hexByte(decoded.originalSid) : null,
    originalServiceName: decoded.originalSid !== null && decoded.originalSid !== undefined ? serviceName(decoded.originalSid) : null,
    nrc: decoded.nrc !== null && decoded.nrc !== undefined ? hexByte(decoded.nrc) : null,
    nrcName: decoded.nrc !== null && decoded.nrc !== undefined ? nrcName(decoded.nrc) : null,
    did: decoded.did !== null && decoded.did !== undefined ? hexWord(decoded.did) : null,
    didName: decoded.did !== null && decoded.did !== undefined ? didName(decoded.did, ecuAddress) : "",
    routineId: decoded.routineId !== null && decoded.routineId !== undefined ? hexWord(decoded.routineId) : null,
    subFunction: decoded.subFunction !== null && decoded.subFunction !== undefined ? hexByte(decoded.subFunction) : null,
    dtc: decoded.dtc,
    transfer: decoded.transfer,
    raw: bytesToHex(uds),
    valueHex: decoded.valueHex,
    valueAscii: decoded.valueAscii,
    paired: false
  };
  doipSample.uds = event;
  report.diagnostics.udsEvents.push(event);
  pushTraceEvent(report, {
    category: "uds",
    type: event.responseKind,
    label: `${event.service} ${event.serviceName}`,
    ...traceLaneForLogical("ecu", ecuAddress),
    timestamp: event.timestamp,
    packet: event.packet,
    transport: event.transport,
    srcIp: event.srcIp,
    srcPort: event.srcPort,
    dstIp: event.dstIp,
    dstPort: event.dstPort,
    logicalAddress: ecuAddress,
    testerAddress,
    udsEventId: event.id,
    responseKind: event.responseKind,
    service: event.service,
    serviceName: event.serviceName,
    originalService: event.originalService,
    originalServiceName: event.originalServiceName,
    source: event.source,
    target: event.target,
    did: event.did,
    didName: event.didName,
    routineId: event.routineId,
    dtc: event.dtc,
    nrc: event.nrc,
    nrcName: event.nrcName,
    transfer: event.transfer,
    raw: event.raw,
    valueHex: event.valueHex,
    valueAscii: event.valueAscii,
    severity: event.responseKind === "negative" ? "danger" : event.responseKind === "pending" ? "pending" : "info"
  });
  add(report.diagnostics.serviceStats, diagnosticBaseServiceKey(event));
  add(ecu.serviceStats, diagnosticBaseServiceKey(event));
  if (event.direction === "request") ecu.requests += 1;
  else ecu.responses += 1;
  if (event.responseKind === "pending") ecu.pending += 1;
  if (event.responseKind === "negative") {
    ecu.negatives += 1;
    const key = `${event.originalService || event.service} ${event.originalServiceName || event.serviceName} / ${event.nrc} ${event.nrcName}`;
    add(report.diagnostics.negativeResponses, key);
    add(ecu.nrcStats, key);
  }
  if (decoded.sid === 0x10 || decoded.sid === 0x50) report.diagnostics.sessions.push(event);
  if (decoded.sid === 0x27 || decoded.sid === 0x67) report.diagnostics.securityAccess.push(event);
  if (decoded.sid === 0x31 || decoded.sid === 0x71) report.diagnostics.routineControls.push(event);
}

function diagnosticBaseServiceKey(event) {
  const serviceSid = event.service?.startsWith("0x") ? parseInt(event.service.slice(2), 16) : NaN;
  const originalService = event.originalService || (Number.isFinite(serviceSid) && serviceSid !== 0x7f && serviceSid >= 0x40 ? hexByte(serviceSid - 0x40) : event.service);
  const originalSid = originalService?.startsWith("0x") ? parseInt(originalService.slice(2), 16) : NaN;
  const name = event.originalServiceName || (Number.isFinite(originalSid) ? serviceName(originalSid) : event.serviceName);
  return `${originalService || event.service} ${name || ""}`.trim();
}

function parseDiagnosticAckNak(view, bodyStart, payloadLength, doipSample, report) {
  return window.HarnessPcapParser.parseDiagnosticAckNak(view, bodyStart, payloadLength, doipSample, report);
}

function finalizeDiagnostics(report) {
  report.diagnostics.udsEvents.sort((a, b) => (a.timestamp || 0) - (b.timestamp || 0) || (a.packet || 0) - (b.packet || 0) || (a.id || 0) - (b.id || 0));
  pairUdsEvents(report);
  buildDidReads(report);
  buildDtcReads(report);
  buildTransfers(report);
  report.downloadAnalysis = buildDownloadAnalysis(report);
  for (const did of report.diagnostics.didReads) {
    ensureEcu(report, did.ecuAddress).didCount += 1;
  }
  for (const transfer of report.diagnostics.transfers) {
    ensureEcu(report, transfer.ecuAddress).transferCount += 1;
  }
}

function buildDtcReads(report) {
  window.HarnessDiagnosticAnalysis.buildDtcReads(report);
}

function pairUdsEvents(report) {
  window.HarnessDiagnosticAnalysis.pairUdsEvents(report);
}

function isFunctionalLogicalAddress(address) {
  return window.HarnessDiagnosticAnalysis.isFunctionalLogicalAddress(address);
}

function findMatchingUdsRequestIndex(candidates, response, originalSid) {
  return window.HarnessDiagnosticAnalysis.findMatchingUdsRequestIndex(candidates, response, originalSid);
}

function buildDidReads(report) {
  window.HarnessDiagnosticAnalysis.buildDidReads(report);
}

function buildTransfers(report) {
  window.HarnessDiagnosticAnalysis.buildTransfers(report);
}

function downloadAnalysisOptions() {
  return {
    ecuLabel,
    formatNumber,
    hexByte,
    percentile,
    tcpFlowKey
  };
}

function buildDownloadAnalysis(report) {
  return window.HarnessDownloadAnalysis.buildDownloadAnalysis(report, downloadAnalysisOptions());
}

function enrichDownloadSession(report, transfer) {
  return window.HarnessDownloadAnalysis.enrichDownloadSession(report, transfer, downloadAnalysisOptions());
}

function assignObservedDownloadAcks(transfer, ackObservations) {
  return window.HarnessDownloadAnalysis.assignObservedDownloadAcks(transfer, ackObservations);
}

function buildTransferRateAnalysis(transfer) {
  return window.HarnessDownloadAnalysis.buildTransferRateAnalysis(transfer, downloadAnalysisOptions());
}

function buildRateBuckets(blocks) {
  return window.HarnessDownloadAnalysis.buildRateBuckets(blocks);
}

function downloadAckObservations(report, transfer) {
  return window.HarnessDownloadAnalysis.downloadAckObservations(report, transfer, downloadAnalysisOptions());
}

function downloadAckHealth(transfer, observations = null) {
  return window.HarnessDownloadAnalysis.downloadAckHealth(transfer, observations);
}

function downloadGatewayIp(report, transfer, events) {
  return window.HarnessDownloadAnalysis.downloadGatewayIp(report, transfer, events);
}

function downloadGatewayLabel(report, transfer, events) {
  return window.HarnessDownloadAnalysis.downloadGatewayLabel(report, transfer, events);
}

function buildDownloadGroups(sessions) {
  return window.HarnessDownloadAnalysis.buildDownloadGroups(sessions);
}

function buildDownloadMatrixRows(groups) {
  return window.HarnessDownloadAnalysis.buildDownloadMatrixRows(groups, downloadAnalysisOptions());
}

function downloadMatrixBlockStatus(sessions) {
  return window.HarnessDownloadAnalysis.downloadMatrixBlockStatus(sessions, downloadAnalysisOptions());
}

function transferEvents(report, transfer, ackObservations = null) {
  return window.HarnessDownloadAnalysis.transferEvents(report, transfer, ackObservations);
}

function isSameTransferBoundaryEvent(event, transfer) {
  return window.HarnessDownloadAnalysis.isSameTransferBoundaryEvent(event, transfer);
}

function validateDownloadSession(report, transfer, events) {
  return window.HarnessDownloadAnalysis.validateDownloadSession(report, transfer, events, downloadAnalysisOptions());
}

function downloadDuplicateFindings(transfer) {
  return window.HarnessDownloadAnalysis.downloadDuplicateFindings(transfer);
}

function buildValidationCentre(report) {
  return window.HarnessValidationAnalysis.buildValidationCentre(report, {
    ecuLabel,
    formatNumber,
    transportHealth,
    defaultTcpAnalysis: emptyReport().tcpAnalysis
  });
}

function isRecoveredSecurityInvalidKey(report, event) {
  return window.HarnessValidationAnalysis.isRecoveredSecurityInvalidKey(report, event);
}

function normaliseValidationSeverity(severity) {
  return window.HarnessValidationAnalysis.normaliseValidationSeverity(severity);
}

function validationEntity(finding) {
  return window.HarnessValidationAnalysis.validationEntity(finding, ecuLabel);
}

function validationFlowEntity(flow) {
  return window.HarnessValidationAnalysis.validationFlowEntity(flow);
}

function countBy(items, key) {
  return window.HarnessValidationAnalysis.countBy(items, key);
}

function render(report) {
  report.diagnostics ||= emptyReport().diagnostics;
  refreshTransferAnalysis(report);
  currentReport = report;
  applyEcuMap(report);
  report.identity = buildIdentityAnalysis(report);
  report.topology = buildTopologyAnalysis(report);
  report.doipLifecycle = buildDoipLifecycle(report);
  report.validationCentre = buildValidationCentre(report);
  $("sourceLabel").textContent = report.source ? `${report.source} - ${formatNumber(report.summary.totalPackets)} packets` : "Load a pcap to inspect UDS, DoIP, DHCP, ARP, and TCP.";
  const captureMetricsHtml = [
    ["Packets", formatNumber(report.summary.totalPackets)],
    ["Duration", formatDurationValue(report.summary.durationSeconds || 0)],
    ["Bytes", formatBytes(report.summary.totalBytes || 0)],
    ["DoIP port traffic", formatNumber(report.doip.count)],
    ["Decoded DoIP messages", formatNumber(report.doip.samples?.length || 0)],
    ["DHCP", formatNumber(report.dhcp.count)],
    ["ARP", formatNumber(report.arp.count)]
  ].map(([label, value]) => `<div class="metric"><span>${label}</span><strong>${value}</strong></div>`).join("");
  $("metrics").innerHTML = captureMetricsHtml;
  $("discoveryMetrics").innerHTML = captureMetricsHtml;
  $("announcementCount").textContent = report.doip.announcements.length;
  $("doipCount").textContent = report.doip.samples?.length || 0;
  $("dhcpCount").textContent = report.dhcp.count;
  $("arpCount").textContent = report.arp.count;
  renderBars("protocolMix", filterObject(report.summary.protocolCounts, $("protocolFilter").value));
  renderHosts();
  renderAnnouncements(report.doip.announcements);
  renderBars("doipPayloads", report.doip.payloadTypes);
  renderDhcp(report);
  renderArp(report);
  renderDoipLifecycle(report);
  renderDiagnostics(report);
  renderTrace(report);
  renderTransport(report);
  renderDownloadTool(report);
  renderSamples();
  renderIdentity(report);
  renderTopology(report);
  renderValidationCentre(report);
  renderHome(report);
  applyToolView();
}

function refreshTransferAnalysis(report) {
  const diagnostics = report.diagnostics;
  if (!diagnostics?.udsEvents?.length) return;
  const hasTruncatedRaw = diagnostics.udsEvents.some((event) => typeof event.raw === "string" && event.raw.includes("..."));
  if (!hasTruncatedRaw) {
    diagnostics.udsEvents.sort((a, b) => (a.timestamp || 0) - (b.timestamp || 0) || (a.packet || 0) - (b.packet || 0) || (a.id || 0) - (b.id || 0));
    diagnostics.transfers = [];
    buildTransfers(report);
    for (const ecu of Object.values(diagnostics.ecus || {})) ecu.transferCount = 0;
    for (const transfer of diagnostics.transfers) ensureEcu(report, transfer.ecuAddress).transferCount += 1;
  }
  buildDtcReads(report);
  report.downloadAnalysis = buildDownloadAnalysis(report);
  report.validationCentre = buildValidationCentre(report);
}

function renderHome(report) {
  window.HarnessDiscoveryRenderer.renderHome(report, { $ });
}

function openTool(tool) {
  if (tool === "transfers") tool = "download";
  activeTool = tool;
  if (tool === "home") {
    applyToolView();
    window.scrollTo({ top: 0, behavior: "smooth" });
    return;
  }
  if (tool === "dids") selectedDiagnosticTab = "dids";
  if (tool === "raw") selectedDiagnosticTab = selectedDiagnosticTab || "overview";
  if (tool === "identity") selectedDiagnosticTab = selectedDiagnosticTab || "overview";
  if (tool === "validation") selectedDiagnosticTab = selectedDiagnosticTab || "overview";
  if (tool === "topology") selectedDiagnosticTab = selectedDiagnosticTab || "overview";
  if (tool === "discovery") selectedDiagnosticTab = selectedDiagnosticTab || "overview";
  if (tool === "uds") selectedDiagnosticTab = selectedDiagnosticTab || "overview";
  renderDiagnostics(currentReport);
  renderTransport(currentReport);
  renderDownloadTool(currentReport);
  renderTopology(currentReport);
  renderDoipLifecycle(currentReport);
  renderValidationCentre(currentReport);
  applyToolView();
  $("workbenchView").scrollIntoView({ block: "start", behavior: "smooth" });
}

function applyToolView() {
  const isHome = activeTool === "home";
  $("homeView").hidden = !isHome;
  $("workbenchView").hidden = isHome;
  const meta = TOOL_META[activeTool] || TOOL_META.home;
  $("toolEyebrow").textContent = meta.eyebrow;
  $("toolTitle").textContent = meta.title;
  $("toolDescription").textContent = meta.description;
  $("toolInfoButton").hidden = isHome;
  for (const button of document.querySelectorAll("[data-tool-open]")) {
    button.classList.toggle("active", button.dataset.toolOpen === activeTool || activeTool === "dids" && button.dataset.toolOpen === "uds");
  }
  document.body.dataset.tool = activeTool;
}

function renderToolInfo(tool = activeTool) {
  const info = TOOL_INFO[tool] || TOOL_INFO.uds;
  $("toolInfoEyebrow").textContent = TOOL_META[tool]?.eyebrow || "Tool info";
  $("toolInfoTitle").textContent = info.title || TOOL_META[tool]?.title || "Tool Info";
  $("toolInfoSummary").textContent = info.summary || TOOL_META[tool]?.description || "";
  $("toolInfoBody").innerHTML = `<div class="tool-info-grid">
    ${(info.sections || []).map(([heading, items]) => `<section class="tool-info-section">
      <h4>${escapeHtml(heading)}</h4>
      <ul>${(items || []).map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>
    </section>`).join("")}
  </div>`;
}

function openToolInfoModal() {
  renderToolInfo(activeTool === "home" ? "uds" : activeTool);
  $("toolInfoModal").hidden = false;
}

function closeToolInfoModal() {
  $("toolInfoModal").hidden = true;
}

function openAppHelpModal() {
  $("appHelpModal").hidden = false;
}

function closeAppHelpModal() {
  $("appHelpModal").hidden = true;
}

function filterObject(object, query) {
  const q = query.trim().toLowerCase();
  if (!q) return object;
  return Object.fromEntries(Object.entries(object).filter(([key]) => key.toLowerCase().includes(q)));
}

function renderBars(id, object) {
  const entries = Object.entries(object || {}).sort((a, b) => b[1] - a[1]);
  if (!entries.length) {
    $(id).innerHTML = `<div class="empty">No matching data.</div>`;
    return;
  }
  const max = Math.max(...entries.map(([, value]) => value));
  $(id).innerHTML = entries.map(([key, value]) => `
    <div class="bar-row" title="${escapeHtml(`${key}: ${formatNumber(value)}`)}">
      <div class="bar-label">${escapeHtml(key)}</div>
      <div class="bar-track"><div class="bar-fill" style="width:${(value / max) * 100}%"></div></div>
      <strong>${formatNumber(value)}</strong>
    </div>
  `).join("");
}

function renderHosts() {
  $("hostsTable").innerHTML = window.HarnessDiscoveryRenderer.renderHosts(currentReport, $("hostFilter").value);
}

function renderAnnouncements(announcements) {
  $("announcements").innerHTML = window.HarnessDiscoveryRenderer.renderAnnouncements(announcements);
}

function renderDhcp(report) {
  $("dhcpSummary").innerHTML = window.HarnessDiscoveryRenderer.renderDhcp(report, barsHtml);
}

function renderArp(report) {
  $("arpSummary").innerHTML = window.HarnessDiscoveryRenderer.renderArp(report, barsHtml);
}

function buildIdentityAnalysis(report) {
  return window.HarnessIdentityAnalysis.buildIdentityAnalysis(report);
}

function isAutoIpAddress(ipAddress) {
  return window.HarnessIdentityAnalysis.isAutoIpAddress(ipAddress);
}

function isBenignAutoIpDhcpLogicalAddress(report, logicalAddress, ipAddresses) {
  return window.HarnessIdentityAnalysis.isBenignAutoIpDhcpLogicalAddress(report, logicalAddress, ipAddresses);
}

function buildTopologyAnalysis(report) {
  return window.HarnessTopologyAnalysis.buildTopologyAnalysis(report, {
    ecuName,
    ecuLabel,
    buildIdentityAnalysis
  });
}

function buildDoipLifecycle(report) {
  return window.HarnessDoipLifecycleAnalysis.buildDoipLifecycle(report, { ecuLabel });
}

function selectDefaultLifecycleNode(lifecycle, filter) {
  const renderer = window.HarnessDiscoveryRenderer;
  const filtered = renderer.filteredLifecycleNodes(lifecycle, filter);
  if (filtered.some((node) => node.id === selectedLifecycleNodeId)) return;
  selectedLifecycleNodeId = filtered[0]?.id || lifecycle.nodes?.[0]?.id || null;
  selectedLifecycleStageKey = null;
}

function renderDoipLifecycle(report) {
  report.doipLifecycle ||= buildDoipLifecycle(report);
  const lifecycle = report.doipLifecycle;
  const filter = $("doipLifecycleFilter").value || "all";
  selectDefaultLifecycleNode(lifecycle, filter);
  const selectedNode = (lifecycle.nodes || []).find((node) => node.id === selectedLifecycleNodeId);
  $("doipLifecycleSummary").textContent = lifecycle.summary?.nodes
    ? `${formatNumber(lifecycle.summary.nodes)} nodes, ${formatNumber(lifecycle.summary.issues || 0)} with issues.`
    : "No DoIP socket lifecycle evidence decoded.";
  $("doipLifecycleMetrics").innerHTML = window.HarnessDiscoveryRenderer.renderLifecycleSummary(lifecycle);
  $("doipLifecycleNodes").innerHTML = window.HarnessDiscoveryRenderer.renderLifecycleNodeList(lifecycle, selectedLifecycleNodeId, filter);
  $("doipLifecycleTimeline").innerHTML = window.HarnessDiscoveryRenderer.renderLifecycleTimeline(selectedNode, selectedLifecycleStageKey);
  $("doipLifecycleStageDetail").innerHTML = window.HarnessDiscoveryRenderer.renderLifecycleStageDetail(selectedNode, selectedLifecycleStageKey);
}

function renderIdentity(report) {
  report.identity ||= buildIdentityAnalysis(report);
  $("identitySummary").textContent = window.HarnessIdentityRenderer.summaryText(report.identity);
  $("identityMetrics").innerHTML = window.HarnessIdentityRenderer.metricsHtml(report.identity.metrics);
  $("identityFindings").innerHTML = window.HarnessIdentityRenderer.findingsHtml(report.identity.groups, $("identitySeverity").value);
  $("identityHostMap").innerHTML = window.HarnessIdentityRenderer.hostMapHtml(report.identity.hostMap, { ecuCode });
}

function renderTopology(report) {
  report.topology ||= buildTopologyAnalysis(report);
  const topology = report.topology;
  const socketMap = topology.socketMap || { sockets: [], summary: {} };
  const summary = socketMap.summary || {};
  $("topologySummary").textContent = `${formatNumber(summary.sockets || 0)} TCP socket endpoints, ${formatNumber(summary.directLogicalAddresses || 0)} direct logical addresses, ${formatNumber(summary.routedLogicalAddresses || 0)} routed logical addresses, ${formatNumber(summary.rejectedTargets || 0)} rejected targets.`;
  renderTopologyMap(socketMap);
  renderTopologyDetail(socketMap);
  renderTopologyTables(socketMap);
  renderTopologyNodeMap(socketMap);
}

function renderTopologyMap(socketMap) {
  $("topologyMap").innerHTML = window.HarnessTopologyRenderer.socketMapHtml(socketMap, selectedTopologyItem);
}

function renderTopologyDetail(socketMap) {
  const sockets = socketMap.sockets || [];
  const selectedSocket = sockets.find((item) => item.id === selectedTopologyItem);
  const selectedMapping = sockets.some((socket) => [...(socket.routed || []), ...(socket.rejected || [])].some((item) => item.id === selectedTopologyItem));
  if (!selectedSocket && !selectedMapping) selectedTopologyItem = sockets[0]?.id || null;
  $("topologyDetail").innerHTML = window.HarnessTopologyRenderer.socketDetailHtml(socketMap, selectedTopologyItem);
}

function renderTopologyTables(socketMap) {
  const tables = window.HarnessTopologyRenderer.socketTableHtml(socketMap);
  $("topologyGatewayTable").innerHTML = tables.sockets;
  $("topologyEcuGatewayTable").innerHTML = tables.mappings;
}

function renderTopologyNodeMap(socketMap) {
  $("topologyNodeMapBody").innerHTML = window.HarnessTopologyRenderer.socketNodeMapHtml(socketMap, selectedTopologyItem);
}

function selectTopologyItemFromTarget(target) {
  if (!target) return false;
  selectedTopologyItem = target.dataset.topologySocket || target.dataset.topologyRoute;
  renderTopology(currentReport);
  return true;
}

function renderValidationCentre(report) {
  report.validationCentre ||= buildValidationCentre(report);
  const analysis = report.validationCentre;
  const findings = filteredValidationFindings(analysis.findings || []);
  const view = $("validationViewFilter")?.value || "all";
  if (!selectedValidationFindingId || !findings.some((item) => item.id === selectedValidationFindingId)) {
    selectedValidationFindingId = findings[0]?.id || null;
  }
  const summary = analysis.summary || {};
  $("validationSummary").textContent = window.HarnessValidationRenderer.summaryText(summary, findings.length);
  $("validationMetrics").innerHTML = window.HarnessValidationRenderer.metricsHtml(summary, analysis.findings || []);
  syncValidationFilterOptions(analysis.findings || []);
  const nrcItems = filteredValidationNrcSummary(analysis.nrcSummary || [], analysis.findings || []);
  $("validationNrcSummary").innerHTML = window.HarnessValidationRenderer.nrcSummaryHtml(nrcItems, {
    selectedId: selectedValidationFindingId,
    ecuCode,
    formatTimeDelta
  });
  $("validationNrcSummarySubtitle").textContent = `${formatNumber(nrcItems.length)} grouped NRC item${nrcItems.length === 1 ? "" : "s"} for ${window.HarnessValidationRenderer.viewModeLabel(view).toLowerCase()} and current filters.`;
  for (const button of $("validationNrcSummary").querySelectorAll("[data-validation-id]")) {
    button.addEventListener("click", () => {
      selectedValidationFindingId = button.dataset.validationId;
      $("validationNrcSummaryModal").hidden = true;
      renderValidationCentre(currentReport);
    });
  }
  $("validationFindings").innerHTML = findings.map((finding) => renderValidationFindingRow(finding)).join("") || `<tr><td colspan="7">${escapeHtml(window.HarnessValidationRenderer.emptyStateText(view))}</td></tr>`;
  for (const row of $("validationFindings").querySelectorAll("[data-validation-id]")) {
    row.addEventListener("click", (event) => {
      if (event.target.closest("button, a, input, select, textarea, summary, details")) return;
      selectedValidationFindingId = row.dataset.validationId;
      renderValidationCentre(currentReport);
    });
  }
  for (const button of $("validationFindings").querySelectorAll("[data-validation-jump]")) {
    button.addEventListener("click", (event) => {
      event.stopPropagation();
      const finding = (analysis.findings || []).find((item) => item.id === button.dataset.validationJump);
      jumpToValidationFinding(finding);
    });
  }
  const selected = findings.find((item) => item.id === selectedValidationFindingId);
  $("validationDetail").innerHTML = selected ? renderValidationDetail(selected) : `<div class="empty">Select a finding to inspect its evidence.</div>`;
  const detailJump = $("validationDetail").querySelector("[data-validation-detail-jump]");
  if (detailJump) {
    detailJump.addEventListener("click", () => jumpToValidationFinding(selected));
  }
}

function syncValidationFilterOptions(findings) {
  syncSelectOptions("validationSourceFilter", window.HarnessValidationRenderer.filterOptions(findings, "sourceTool"), "All sources");
  syncSelectOptions("validationCategoryFilter", window.HarnessValidationRenderer.filterOptions(findings, "category"), "All categories");
}

function syncSelectOptions(id, values, allLabel) {
  const select = $(id);
  const selected = select.value || "all";
  select.innerHTML = window.HarnessValidationRenderer.selectOptionsHtml(values, allLabel);
  select.value = values.includes(selected) ? selected : "all";
}

function filteredValidationFindings(findings) {
  return window.HarnessValidationRenderer.filteredFindings(findings, {
    severity: $("validationSeverityFilter")?.value || "actionable",
    source: $("validationSourceFilter")?.value || "all",
    category: $("validationCategoryFilter")?.value || "all",
    view: $("validationViewFilter")?.value || "all",
    query: $("validationSearch")?.value || ""
  });
}

function filteredValidationNrcSummary(nrcSummary, allFindings) {
  const visibleIds = new Set(filteredValidationFindings(allFindings).filter((finding) => finding.validationKind === "nrc" || finding.validationKind === "nrc-pending").map((finding) => finding.id));
  return nrcSummary.filter((item) => visibleIds.has(item.id));
}

function validationTypeFilterMatch(finding, type) {
  return window.HarnessValidationRenderer.validationTypeFilterMatch(finding, type);
}

function renderValidationFindingRow(finding) {
  return window.HarnessValidationRenderer.findingRowHtml(finding, {
    selectedId: selectedValidationFindingId,
    ecuCode,
    formatTimeDelta
  });
}

function renderValidationDetail(finding) {
  return window.HarnessValidationRenderer.detailHtml(finding, { formatTimeDelta });
}

function validationSeverityClass(severity) {
  return window.HarnessValidationRenderer.validationSeverityClass(severity);
}

function jumpToValidationFinding(finding) {
  if (!finding) return;
  const target = finding.jumpTarget || {};
  if (target.ecuAddress || finding.ecuAddress) selectedEcuAddress = target.ecuAddress || finding.ecuAddress;
  if (target.tab) {
    if (target.tool === "download") downloadController.setSelectedTab(target.tab);
    else selectedDiagnosticTab = target.tab;
  }
  if (target.sessionId || finding.sessionId) downloadController.setSelectedSession(Number(target.sessionId || finding.sessionId));
  if (target.flowKey || finding.flowKey) selectedTcpFlowKey = target.flowKey || finding.flowKey;
  if (target.nodeId || finding.nodeId) selectedTopologyItem = target.nodeId || finding.nodeId;
  if (target.tool === "download") downloadController.resetFilters();
  if (target.tool === "transport" && $("transportFlowFilter")) $("transportFlowFilter").value = "all";
  openTool(target.tool || "validation");
}

function renderTransport(report) {
  const analysis = report.tcpAnalysis || emptyReport().tcpAnalysis;
  const allFlows = (analysis.flows || []).map((flow) => ({ ...flow, identity: transportFlowIdentity(flow, report, analysis), health: transportHealth(flow, analysis) }));
  const filter = $("transportFlowFilter")?.value || "all";
  const flows = filterTransportFlows(allFlows, filter, analysis);
  if (!flows.length) selectedTcpFlowKey = null;
  else if (!selectedTcpFlowKey || !flows.some((flow) => flow.key === selectedTcpFlowKey)) selectedTcpFlowKey = flows[0].key;
  $("transportSummary").textContent = `${formatNumber(allFlows.length)} DoIP TCP flows, ${formatNumber(analysis.ackTimings?.length || 0)} ACK timing samples, ${formatNumber(analysis.events?.length || 0)} notable events.`;
  $("tcpFlowTable").innerHTML = renderTransportFlowRows(flows);
  for (const row of $("tcpFlowTable").querySelectorAll("tr[data-tcp-flow]")) {
    row.addEventListener("click", () => {
      selectedTcpFlowKey = row.dataset.tcpFlow;
      renderTransport(currentReport);
    });
  }
  const flow = allFlows.find((item) => item.key === selectedTcpFlowKey);
  if (!flow) {
    $("tcpFlowDetail").innerHTML = `<div class="empty">No TCP flow selected.</div>`;
    return;
  }
  const events = (analysis.events || []).filter((event) => event.flowKey === flow.key).slice(0, 120);
  const acks = (analysis.ackTimings || []).filter((ack) => ack.flowKey === flow.key).sort((a, b) => b.latency - a.latency).slice(0, 60);
  const gaps = (analysis.gaps || []).filter((gap) => gap.flowKey === flow.key);
  const directionRows = transportDirectionRows(flow, analysis);
  const interpretation = transportInterpretation(flow, events, gaps, report);
  $("tcpFlowDetail").innerHTML = `
    ${renderTransportFlowDiagram(flow, events, gaps)}
    <div class="transport-endpoints">
      ${transportEndpointCard(flow.identity.tester, "Tester endpoint")}
      ${transportEndpointCard(flow.identity.doipNode, "DoIP Ethernet node")}
    </div>
    ${renderFlowControlPanel(flow)}
    ${metricGrid([
      ["Handshake", formatMs(flow.handshakeDuration)],
      ["ACK samples", flow.ackSamples],
      ["Min ACK", formatMs(flow.minAckLatency)],
      ["Max ACK", formatMs(flow.maxAckLatency)],
      ["Retrans", flow.retransmissions],
      ["Dup ACK", flow.duplicateAcks],
      ["Zero Win", flow.zeroWindows],
      ["Window Updates", flow.windowUpdates]
    ])}
    <section class="transport-interpretation">
      <h4>Interpretation</h4>
      ${interpretation.map((item) => `<div class="transport-note ${escapeHtml(item.severity)}"><strong>${escapeHtml(item.title)}</strong><p>${escapeHtml(item.detail)}</p>${item.evidence ? `<code>${escapeHtml(item.evidence)}</code>` : ""}</div>`).join("")}
    </section>
    <div class="table-wrap"><table><thead><tr><th>Direction</th><th>Payload</th><th>ACK samples</th><th>Median ACK</th><th>P95 ACK</th><th>Retrans</th><th>Dup ACK</th></tr></thead><tbody>
      ${directionRows.map((row) => `<tr><td><code>${escapeHtml(row.direction)}</code></td><td>${formatBytes(row.payloadBytes)}</td><td>${formatNumber(row.ackSamples)}</td><td>${formatMs(row.medianAckLatency)}</td><td>${formatMs(row.p95AckLatency)}</td><td>${formatNumber(row.retransmissions)}</td><td>${formatNumber(row.duplicateAcks)}</td></tr>`).join("") || `<tr><td colspan="7">No direction metrics available.</td></tr>`}
    </tbody></table></div>
    <div class="grid two">
      <div class="table-wrap"><table><thead><tr><th>Type</th><th>Time</th><th>Packet</th><th>Detail</th></tr></thead><tbody>
        ${events.map((event) => `<tr data-tcp-event-type="${escapeHtml(event.type)}"><td>${escapeHtml(event.type)}</td><td>${formatTimeDelta(event.timestamp)}</td><td>${event.packet}</td><td>${escapeHtml(event.label)} ${event.latency ? formatMs(event.latency) : ""}</td></tr>`).join("") || `<tr><td colspan="4">No notable events.</td></tr>`}
      </tbody></table></div>
      <div class="table-wrap"><table><thead><tr><th>Latency</th><th>Payload pkt</th><th>ACK pkt</th><th>Bytes</th><th>Direction</th></tr></thead><tbody>
        ${acks.map((ack) => `<tr><td>${formatMs(ack.latency)}</td><td>${ack.payloadPacket}</td><td>${ack.ackPacket}</td><td>${formatNumber(ack.payloadBytes)}</td><td><code>${escapeHtml(ack.direction)}</code></td></tr>`).join("") || `<tr><td colspan="5">No ACK timing samples.</td></tr>`}
      </tbody></table></div>
    </div>
  `;
  for (const marker of $("tcpFlowDetail").querySelectorAll("[data-transport-issue]")) {
    marker.addEventListener("click", () => {
      const row = Array.from($("tcpFlowDetail").querySelectorAll("[data-tcp-event-type]")).find((item) => item.dataset.tcpEventType === marker.dataset.transportIssue);
      if (!row) return;
      row.classList.add("event-highlight");
      row.scrollIntoView({ block: "center", behavior: "smooth" });
      setTimeout(() => row.classList.remove("event-highlight"), 1200);
    });
  }
}

function parseTransportEndpoint(endpoint) {
  return window.HarnessTransportRenderer.parseTransportEndpoint(endpoint);
}

function resolveTransportEndpoint(ipAddress, port, report = currentReport) {
  return window.HarnessTransportRenderer.resolveTransportEndpoint(ipAddress, port, report);
}

function transportFlowIdentity(flow, report = currentReport) {
  return window.HarnessTransportRenderer.transportFlowIdentity(flow, report, { tcpFlowKey });
}

function carriedLogicalAddressesForFlow(flow, report = currentReport) {
  return window.HarnessTransportRenderer.carriedLogicalAddressesForFlow(flow, report, { tcpFlowKey });
}

function transportObservationSummary(flow) {
  return window.HarnessTransportRenderer.transportObservationSummary(flow);
}

function renderFlowControlPanel(flow) {
  const directions = flow.flowControl?.directions || [];
  const status = flow.flowControl?.status || { label: "OK", severity: "ok", detail: "No receive-window pressure observed." };
  return `<section class="flow-control-panel">
    <div class="flow-control-head">
      <div>
        <h4>Flow Control</h4>
        <p>${escapeHtml(status.detail || "Observed TCP receive-window and ACK cadence.")}</p>
      </div>
      ${flowControlBadge(status)}
    </div>
    <div class="flow-control-cards">
      ${directions.map((direction) => renderFlowControlDirectionCard(direction)).join("") || `<div class="empty">No flow-control samples available.</div>`}
    </div>
    ${renderFlowControlChart(flow)}
  </section>`;
}

function renderFlowControlDirectionCard(direction) {
  const ackRatio = Number.isFinite(direction.ackToPayloadRatio) ? `${direction.ackToPayloadRatio.toFixed(2)} ACK/payload pkt` : "n/a";
  const bytesPerAck = Number.isFinite(direction.bytesPerAck) ? formatBytes(direction.bytesPerAck) : "n/a";
  return `<article class="flow-control-card ${escapeHtml(direction.status?.severity || "ok")}">
    <div class="flow-control-card-head">
      <strong>${escapeHtml(direction.endpoint || "Endpoint")}</strong>
      ${flowControlBadge(direction.status)}
    </div>
    <span>${escapeHtml(direction.direction || "")}</span>
    <dl>
      <dt>Median window</dt><dd>${formatWindowBytes(direction.medianWindow)}</dd>
      <dt>Min window</dt><dd>${formatWindowBytes(direction.minWindow)}</dd>
      <dt>Pure ACKs</dt><dd>${formatNumber(direction.pureAcks || 0)}</dd>
      <dt>ACK cadence</dt><dd>${escapeHtml(ackRatio)}</dd>
      <dt>Bytes per ACK</dt><dd>${escapeHtml(bytesPerAck)}</dd>
      <dt>Small windows</dt><dd>${formatNumber(direction.smallWindowSamples || 0)}</dd>
      <dt>Zero/window updates</dt><dd>${formatNumber(direction.zeroWindows || 0)} / ${formatNumber(direction.windowUpdates || 0)}</dd>
    </dl>
  </article>`;
}

function formatWindowBytes(value) {
  return window.HarnessTransportRenderer.formatWindowBytes(value);
}

function renderFlowControlChart(flow) {
  const directions = flow.flowControl?.directions || [];
  const samples = directions.flatMap((direction, index) => (direction.samples || []).map((sample) => ({ ...sample, lane: index, endpoint: direction.endpoint })));
  if (samples.length < 2) return `<div class="flow-control-chart empty">Not enough window samples for charting.</div>`;
  const width = 760;
  const height = 230;
  const pad = { left: 76, right: 24, top: 24, bottom: 52 };
  const minTime = Math.min(...samples.map((item) => item.timestamp));
  const maxTime = Math.max(...samples.map((item) => item.timestamp));
  const windowValues = samples.map((item) => Number(item.windowSize || 0)).filter((value) => Number.isFinite(value));
  const maxWindow = Math.max(1, ...windowValues);
  const chartMax = flowControlChartMax(windowValues, TCP_SMALL_WINDOW_THRESHOLD);
  const isClipped = maxWindow > chartMax;
  const xFor = (timestamp) => pad.left + ((timestamp - minTime) / Math.max(0.000001, maxTime - minTime)) * (width - pad.left - pad.right);
  const yFor = (windowSize) => pad.top + (1 - flowControlChartRatio(windowSize, chartMax, TCP_SMALL_WINDOW_THRESHOLD)) * (height - pad.top - pad.bottom);
  const colours = ["var(--accent)", "var(--success)", "var(--warning)"];
  const lines = directions.map((direction, index) => {
    const points = downsampleSamples(direction.samples || [], 180).map((sample) => `${xFor(sample.timestamp).toFixed(1)},${yFor(sample.windowSize || 0).toFixed(1)}`).join(" ");
    return points ? `<polyline class="flow-window-line" style="stroke:${colours[index % colours.length]}" points="${points}"></polyline>` : "";
  }).join("");
  const legend = directions.map((direction, index) => `<span><i style="background:${colours[index % colours.length]}"></i>${escapeHtml(direction.endpoint || direction.direction || `Direction ${index + 1}`)}</span>`).join("");
  const ticks = downsampleSamples(samples.filter((item) => item.pureAck), 80).map((sample) => {
    const x = xFor(sample.timestamp).toFixed(1);
    return `<line class="flow-ack-tick" x1="${x}" x2="${x}" y1="${height - pad.bottom + 5}" y2="${height - pad.bottom + 15}"><title>${escapeHtml(sample.endpoint || "")} ACK packet ${sample.packet}, ${formatTimeDelta(sample.timestamp)}, window ${formatWindowBytes(sample.windowSize)}</title></line>`;
  }).join("");
  const points = downsampleSamples(samples, 80).map((sample) => `<circle class="flow-window-point" cx="${xFor(sample.timestamp).toFixed(1)}" cy="${yFor(sample.windowSize || 0).toFixed(1)}" r="3"><title>${escapeHtml(sample.direction || "")}\nPacket ${sample.packet}\n${formatTimeDelta(sample.timestamp)}\nWindow ${formatWindowBytes(sample.windowSize)}${sample.windowScale ? ` scaled x${2 ** sample.windowScale}` : ""}\nRaw window ${sample.rawWindowSize ?? sample.windowSize}\nACK ${sample.ackNumber ?? ""}\nPayload ${formatBytes(sample.payloadLength || 0)}</title></circle>`).join("");
  const threshold = Math.min(chartMax, TCP_SMALL_WINDOW_THRESHOLD);
  const thresholdY = yFor(threshold).toFixed(1);
  const guideTicks = [
    { value: chartMax, label: `${isClipped ? ">=" : ""}${formatWindowBytes(chartMax)}`, top: true },
    { value: threshold, label: formatWindowBytes(threshold) },
    { value: Math.min(1536, chartMax), label: formatWindowBytes(Math.min(1536, chartMax)) },
    { value: 0, label: "0 B" }
  ].filter((tick, index, ticks) => ticks.findIndex((item) => item.value === tick.value) === index);
  const guideLines = guideTicks.filter((tick) => tick.value > 0 && tick.value < chartMax).map((tick) => `<line class="flow-grid-line" x1="${pad.left}" y1="${yFor(tick.value).toFixed(1)}" x2="${width - pad.right}" y2="${yFor(tick.value).toFixed(1)}"></line>`).join("");
  const guideLabels = guideTicks.map((tick) => {
    const y = tick.top ? pad.top + 4 : tick.value === 0 ? height - pad.bottom : yFor(tick.value).toFixed(1);
    return `<text class="flow-axis-label" x="${pad.left - 8}" y="${y}" text-anchor="end">${escapeHtml(tick.label)}</text>`;
  }).join("");
  return `<div class="flow-control-chart">
    <svg viewBox="0 0 ${width} ${height}" role="img" aria-label="TCP advertised receive window over time">
      ${guideLines}
      <line class="flow-axis" x1="${pad.left}" y1="${height - pad.bottom}" x2="${width - pad.right}" y2="${height - pad.bottom}"></line>
      <line class="flow-axis" x1="${pad.left}" y1="${pad.top}" x2="${pad.left}" y2="${height - pad.bottom}"></line>
      <text class="flow-axis-label" x="${pad.left}" y="${height - 8}">${escapeHtml(formatTimeDelta(minTime))}</text>
      <text class="flow-axis-label" x="${width - pad.right}" y="${height - 8}" text-anchor="end">${escapeHtml(formatTimeDelta(maxTime))}</text>
      ${guideLabels}
      <text class="flow-axis-title" transform="translate(17 ${height / 2}) rotate(-90)" text-anchor="middle">Receive window</text>
      <text class="flow-axis-title" x="${(pad.left + width - pad.right) / 2}" y="${height - 8}" text-anchor="middle">Capture time</text>
      <line class="flow-small-window-line" x1="${pad.left}" x2="${width - pad.right}" y1="${thresholdY}" y2="${thresholdY}"></line>
      <text class="flow-threshold-label" x="${width - pad.right}" y="${Math.max(pad.top + 10, Number(thresholdY) - 5)}" text-anchor="end">small window ${escapeHtml(formatWindowBytes(TCP_SMALL_WINDOW_THRESHOLD))}</text>
      ${lines}
      ${ticks}
      ${points}
    </svg>
    <div class="flow-chart-legend">${legend}<span><em></em>pure ACK tick</span></div>
    ${isClipped ? `<p class="flow-chart-note">Y-axis expands the 0-${escapeHtml(formatWindowBytes(TCP_SMALL_WINDOW_THRESHOLD))} range and clips outliers above ${escapeHtml(formatWindowBytes(chartMax))}; highest observed window is ${escapeHtml(formatWindowBytes(maxWindow))}.</p>` : `<p class="flow-chart-note">Y-axis expands the 0-${escapeHtml(formatWindowBytes(TCP_SMALL_WINDOW_THRESHOLD))} range so small receive windows remain visible.</p>`}
  </div>`;
}

function flowControlChartMax(values, smallWindowThreshold = TCP_SMALL_WINDOW_THRESHOLD) {
  return window.HarnessTransportRenderer.flowControlChartMax(values, smallWindowThreshold);
}

function flowControlChartRatio(value, chartMax, smallWindowThreshold = TCP_SMALL_WINDOW_THRESHOLD) {
  return window.HarnessTransportRenderer.flowControlChartRatio(value, chartMax, smallWindowThreshold);
}

function downsampleSamples(samples, maxItems) {
  return window.HarnessTcpAnalysis.downsampleSamples(samples, maxItems);
}

function renderTransportFlowDiagram(flow, events, gaps) {
  const markers = transportIssueMarkers(flow, events, gaps);
  return `<section class="transport-flow-diagram">
    <div class="transport-diagram-node">
      <span>Tester</span>
      <strong>${escapeHtml(flow.identity.tester.label)}</strong>
      <code>${escapeHtml(flow.identity.tester.raw)}</code>
    </div>
    <div class="transport-diagram-link">
      <span>TCP DoIP flow</span>
      <div class="transport-diagram-line"></div>
      <div class="transport-issue-markers">${markers.map((item) => `<button class="badge ${transportIssueClass(item.severity)}" type="button" data-transport-issue="${escapeHtml(item.label)}" title="${escapeHtml(item.detail)}">${escapeHtml(item.label)}</button>`).join("") || badge("clean", "ok")}</div>
    </div>
    <div class="transport-diagram-node">
      <span>Ethernet DoIP node</span>
      <strong>${escapeHtml(flow.identity.doipNode.label)}</strong>
      <code>${escapeHtml(flow.identity.doipNode.raw)}</code>
    </div>
  </section>`;
}

function transportIssueMarkers(flow, events, gaps) {
  return window.HarnessTransportRenderer.transportIssueMarkers(flow, events, gaps);
}

function transportIssueClass(severity) {
  return window.HarnessTransportRenderer.transportIssueClass(severity);
}

function transportHealth(flow, analysis = currentReport.tcpAnalysis || {}) {
  return window.HarnessTransportRenderer.transportHealth(flow, analysis);
}

function filterTransportFlows(flows, filter, analysis = currentReport.tcpAnalysis || {}) {
  return window.HarnessTransportRenderer.filterTransportFlows(flows, filter, analysis);
}

function renderTransportFlowRows(flows) {
  if (!flows.length) return `<tr><td colspan="8">No DoIP TCP flows match this filter.</td></tr>`;
  const rows = [];
  let lastGroup = "";
  for (const flow of flows.sort((a, b) => String(a.identity.group).localeCompare(String(b.identity.group)) || b.packets - a.packets)) {
    if (flow.identity.group !== lastGroup) {
      lastGroup = flow.identity.group;
      rows.push(`<tr class="transport-group-row"><td colspan="8"><strong>${escapeHtml(lastGroup)}</strong></td></tr>`);
    }
    const observations = transportObservationSummary(flow);
    rows.push(`
      <tr data-tcp-flow="${escapeHtml(flow.key)}" class="${flow.key === selectedTcpFlowKey ? "selected" : ""}">
        <td>${transportEndpointCell(flow.identity.tester)}</td>
        <td>${transportEndpointCell(flow.identity.doipNode)}</td>
        <td>${formatNumber(flow.packets)}</td>
        <td>${formatBytes(flow.payloadBytes)}</td>
        <td>${formatMs(flow.p95AckLatency)}</td>
        <td>${flowControlBadge(flow.flowControl?.status)}</td>
        <td>${observations || `<span class="subtle">none</span>`}</td>
        <td>${badge(flow.health.label, transportHealthClass(flow.health.level))}</td>
      </tr>`);
  }
  return rows.join("");
}

function transportEndpointCell(endpoint) {
  return window.HarnessTransportRenderer.endpointCell(endpoint);
}

function transportHealthClass(level) {
  return window.HarnessTransportRenderer.healthClass(level);
}

function flowControlBadge(status = { label: "OK", severity: "ok" }) {
  return window.HarnessTransportRenderer.flowControlBadge(status);
}

function transportEndpointCard(endpoint, title) {
  return window.HarnessTransportRenderer.endpointCard(endpoint, title);
}

function transportDirectionRows(flow, analysis = currentReport.tcpAnalysis || {}) {
  return [flow.endpointA, flow.endpointB].map((endpoint) => {
    const ackRows = (analysis.ackTimings || []).filter((ack) => ack.flowKey === flow.key && ack.direction.startsWith(endpoint));
    const latencies = ackRows.map((ack) => ack.latency).filter((latency) => Number.isFinite(latency));
    const events = (analysis.events || []).filter((event) => event.flowKey === flow.key && event.src === endpoint);
    return {
      direction: endpoint,
      payloadBytes: ackRows.reduce((sum, ack) => sum + (ack.payloadBytes || 0), 0),
      ackSamples: ackRows.length,
      medianAckLatency: percentile(latencies, 50),
      p95AckLatency: percentile(latencies, 95),
      retransmissions: events.filter((event) => event.type === "Retransmission").length,
      duplicateAcks: events.filter((event) => event.type === "Duplicate ACK").length
    };
  });
}

function transportInterpretation(flow, events, gaps, report = currentReport) {
  const items = [{ severity: flow.health.level, title: `Health: ${flow.health.label}`, detail: flow.health.detail, evidence: flow.key }];
  const downloadOverlap = transportDownloadOverlap(flow, events, report);
  if (flow.retransmissions > 0) items.push({ severity: "warning", title: "Retransmission", detail: "TCP byte range or payload repeated before ACK.", evidence: `${formatNumber(flow.retransmissions)} retransmission events` });
  if (flow.duplicateAcks > 0) items.push({ severity: flow.duplicateAcks > 5 ? "warning" : "info", title: "Duplicate ACK", detail: "Receiver repeated an ACK number; data may be missing or out of order.", evidence: `${formatNumber(flow.duplicateAcks)} duplicate ACKs` });
  if (flow.flowControl?.status && flow.flowControl.status.label !== "OK") items.push({ severity: flow.flowControl.status.severity, title: `Flow control: ${flow.flowControl.status.label}`, detail: flow.flowControl.status.detail || "Receive-window or ACK cadence pressure was observed.", evidence: flow.flowControl.directions.map((direction) => `${direction.endpoint}: ${direction.status.label}`).join(" | ") });
  if (flow.zeroWindows > 0) items.push({ severity: "problem", title: "Zero window", detail: "Receiver advertised no TCP buffer space.", evidence: `${formatNumber(flow.zeroWindows)} zero-window events` });
  if (gaps.length) items.push({ severity: "problem", title: "TCP gap", detail: "Capture bytes or sequence continuity are missing; DoIP/UDS decoding may be incomplete.", evidence: gaps.map((gap) => `packet ${gap.packet || "?"} gap ${gap.gap || "?"}`).join(", ") });
  if (events.some((event) => event.type === "RST")) items.push({ severity: "info", title: "TCP reset observed", detail: "TCP reset observed. Treat as context unless paired with gaps or missing data.", evidence: events.filter((event) => event.type === "RST").map((event) => `packet ${event.packet}`).join(", ") });
  if (downloadOverlap.sessions.length) items.push({ severity: downloadOverlap.severity, title: downloadOverlap.title, detail: downloadOverlap.detail, evidence: downloadOverlap.evidence });
  if (items.length === 1) items.push({ severity: "ok", title: "No notable transport concerns", detail: "No retransmissions, duplicate ACK bursts, zero windows, resets, or gaps observed.", evidence: "" });
  return items;
}

function transportDownloadOverlap(flow, events, report = currentReport) {
  const sessions = [];
  const flowStart = flow.firstTimestamp ?? 0;
  const flowEnd = flow.lastTimestamp ?? flowStart;
  const eventTypes = new Set((events || []).map((event) => event.type));
  const noteworthyEvents = (events || []).filter((event) => ["Retransmission", "Duplicate ACK", "Zero window", "Window update", "Small window", "Slow ACK", "TCP gap", "RST"].includes(event.type));
  for (const session of report.downloadAnalysis?.sessions || []) {
    const start = session.startTimestamp ?? 0;
    const end = session.endTimestamp ?? start;
    if (end < flowStart - 0.1 || start > flowEnd + 0.1) continue;
    const sessionEvents = (session.events || []).filter((event) => event.srcIp || event.dstIp);
    const sameFlow = sessionEvents.some((event) => {
      if (!event.srcIp || !event.dstIp || !event.srcPort || !event.dstPort) return false;
      return tcpFlowKey(event.srcIp, event.srcPort, event.dstIp, event.dstPort) === flow.key;
    });
    const overlappingTransportEvents = noteworthyEvents.filter((event) => event.timestamp >= start - 0.1 && event.timestamp <= end + 0.1);
    if (!sameFlow && !overlappingTransportEvents.length) continue;
    sessions.push({ session, sameFlow, overlappingTransportEvents });
  }
  const uniqueSessions = sessions.filter((item, index, array) => array.findIndex((candidate) => candidate.session.id === item.session.id) === index);
  const impacted = uniqueSessions.filter((item) => item.overlappingTransportEvents.length);
  const severity = impacted.some((item) => item.overlappingTransportEvents.some((event) => event.type === "Zero window")) ? "warning" : "info";
  const title = impacted.length ? "TCP observations during software download" : "Carries software download traffic";
  const detail = impacted.length
    ? "TCP observations overlap these transfer segments; review when checking throughput or missing data."
    : "This TCP flow carried software-transfer traffic. No notable TCP event overlapped the transfer window.";
  const evidence = uniqueSessions.slice(0, 6).map(({ session, overlappingTransportEvents }) => {
    const duration = formatDurationValue((session.endTimestamp ?? session.startTimestamp ?? 0) - (session.startTimestamp ?? 0));
    const eventSummary = overlappingTransportEvents.length
      ? `; TCP events: ${summariseEventTypes(overlappingTransportEvents)}`
      : "";
    return `${ecuLabel(session.ecuAddress)} ${session.typeLabel || session.sessionType || "transfer"} segment ${session.id}, packets ${session.requestPacket || "?"}-${session.endPacket || "?"}, ${formatBytes(session.reconstructedBytes || 0)}, ${duration}${eventSummary}`;
  }).join(" | ");
  return { sessions: uniqueSessions, severity, title, detail, evidence, eventTypes };
}

function summariseEventTypes(events) {
  return window.HarnessTransportRenderer.summariseEventTypes(events);
}

function renderDownloadTool(report) {
  downloadController.render(report);
}

function openDidPlotModal(key) {
  downloadController.openDidPlotModal(key);
}

function rateCampaignRows() {
  return downloadController.rateCampaignRows();
}

function setupCollapsibleTablePanes() {
  for (const pane of document.querySelectorAll(".collapsible-table-pane")) {
    if (pane.dataset.tablePaneReady) continue;
    pane.dataset.tablePaneReady = "true";
    const title = pane.dataset.tablePaneLabel || "Table";
    const controls = document.createElement("div");
    controls.className = "table-pane-controls";
    controls.innerHTML = `
      <span class="table-pane-title">${escapeHtml(title)}</span>
      <span class="table-pane-actions">
        <button class="table-pane-toggle" type="button" data-table-pane-state="collapsed" title="Collapse ${escapeHtml(title)}" aria-label="Collapse ${escapeHtml(title)}">-</button>
        <button class="table-pane-toggle" type="button" data-table-pane-state="normal" title="Normal ${escapeHtml(title)} width" aria-label="Normal ${escapeHtml(title)} width">=</button>
        <button class="table-pane-toggle" type="button" data-table-pane-state="expanded" title="Expand ${escapeHtml(title)} horizontally" aria-label="Expand ${escapeHtml(title)} horizontally">+</button>
      </span>
    `;
    pane.prepend(controls);
    setTablePaneState(pane, "normal");
  }
}

function setupTableScrollMirrors() {
  for (const wrap of document.querySelectorAll(".table-wrap")) {
    if (wrap.dataset.scrollMirror === "false") {
      wrap.querySelector(":scope > .table-scrollbar-proxy")?.remove();
      wrap.dataset.scrollMirrorReady = "false";
      continue;
    }
    if (!wrap.dataset.scrollMirrorReady) {
      wrap.dataset.scrollMirrorReady = "true";
      const mirror = document.createElement("div");
      mirror.className = "table-scrollbar-proxy";
      mirror.setAttribute("aria-hidden", "true");
      mirror.innerHTML = `<div></div>`;
      const controls = wrap.querySelector(":scope > .table-pane-controls");
      const table = wrap.querySelector(":scope > table");
      if (table) table.after(mirror);
      else if (controls) controls.after(mirror);
      else wrap.prepend(mirror);
      mirror.addEventListener("scroll", () => {
        if (wrap.dataset.syncingScroll === "wrap") return;
        wrap.dataset.syncingScroll = "mirror";
        wrap.scrollLeft = mirror.scrollLeft;
        delete wrap.dataset.syncingScroll;
      });
      wrap.addEventListener("scroll", () => {
        if (wrap.dataset.syncingScroll === "mirror") return;
        wrap.dataset.syncingScroll = "wrap";
        mirror.scrollLeft = wrap.scrollLeft;
        delete wrap.dataset.syncingScroll;
      });
    }
    refreshTableScrollMirror(wrap);
  }
}

function refreshTableScrollMirror(wrap) {
  const mirror = wrap.querySelector(":scope > .table-scrollbar-proxy");
  const controls = wrap.querySelector(":scope > .table-pane-controls");
  const table = wrap.querySelector(":scope > table");
  if (!mirror || !table || wrap.classList.contains("is-collapsed")) {
    if (mirror) mirror.hidden = true;
    if (controls) controls.style.minWidth = "";
    return;
  }
  const needsHorizontalScroll = table.scrollWidth > wrap.clientWidth + 1;
  mirror.hidden = !needsHorizontalScroll;
  if (controls) controls.style.minWidth = wrap.dataset.fixedTableControls === "true" ? "" : `${Math.max(table.scrollWidth, wrap.clientWidth)}px`;
  if (!needsHorizontalScroll) return;
  mirror.firstElementChild.style.width = `${table.scrollWidth}px`;
  mirror.scrollLeft = wrap.scrollLeft;
}

let tableScrollMirrorQueued = false;

function queueTableScrollMirrorRefresh() {
  if (tableScrollMirrorQueued) return;
  tableScrollMirrorQueued = true;
  requestAnimationFrame(() => {
    tableScrollMirrorQueued = false;
    setupTableScrollMirrors();
  });
}

function tablePaneLayout(pane) {
  return pane.closest(".validation-centre-layout, .transport-layout, .download-layout, .diagnostics-layout");
}

function setTablePaneState(pane, state) {
  const nextState = ["collapsed", "normal", "expanded"].includes(state) ? state : "normal";
  const layout = tablePaneLayout(pane);
  pane.classList.toggle("is-collapsed", nextState === "collapsed");
  pane.classList.toggle("is-expanded", nextState === "expanded");
  pane.dataset.tablePaneState = nextState;
  if (layout) {
    layout.classList.toggle("table-pane-collapsed", nextState === "collapsed");
    layout.classList.toggle("table-pane-expanded", nextState === "expanded");
  }
  for (const button of pane.querySelectorAll("[data-table-pane-state]")) {
    const active = button.dataset.tablePaneState === nextState;
    button.classList.toggle("active", active);
    button.setAttribute("aria-pressed", active ? "true" : "false");
  }
  queueTableScrollMirrorRefresh();
}

function renderDiagnostics(report) {
  const ecus = Object.values(report.diagnostics?.ecus || {}).sort((a, b) => b.requests + b.responses - (a.requests + a.responses));
  $("diagnosticsSummary").textContent = `${formatNumber(report.diagnostics?.udsEvents?.length || 0)} UDS events across ${formatNumber(ecus.length)} ECUs.`;
  if (!selectedEcuAddress || !report.diagnostics.ecus[selectedEcuAddress]) selectedEcuAddress = ecus[0]?.address || null;
  renderEcuTable(ecus);
  renderSelectedEcu();
}

function renderEcuTable(ecus) {
  const q = $("ecuFilter").value.trim().toLowerCase();
  const rows = ecus
    .filter((ecu) => !q || [ecu.address, ecu.name, ...(ecu.ips || []), ...(ecu.vins || []), ...(ecu.eids || [])].join(" ").toLowerCase().includes(q))
    .map((ecu) => `
      <tr data-ecu="${escapeHtml(ecu.address)}" class="${ecu.address === selectedEcuAddress ? "selected" : ""}">
        <td>${ecuCode(ecu.address)}</td>
        <td>${escapeHtml(ecu.name ? ecu.address : "")}</td>
        <td>${(ecu.ips || []).map((item) => `<code>${escapeHtml(item)}</code>`).join("<br>")}</td>
        <td>${formatNumber(ecu.requests)}</td>
        <td>${formatNumber(ecu.responses)}</td>
        <td>${formatNumber(ecu.didCount)}</td>
        <td>${formatNumber(ecu.transferCount)}</td>
        <td>${formatNumber(ecu.negatives)}</td>
        <td>${formatTimeDelta(ecu.lastTimestamp)}</td>
      </tr>
    `);
  $("ecuTable").innerHTML = rows.join("") || `<tr><td colspan="9">No diagnostic ECUs match the filter.</td></tr>`;
  for (const row of $("ecuTable").querySelectorAll("tr[data-ecu]")) {
    row.addEventListener("click", () => {
      selectedEcuAddress = row.dataset.ecu;
      renderDiagnostics(currentReport);
    });
  }
}

function renderSelectedEcu() {
  const ecu = currentReport.diagnostics?.ecus?.[selectedEcuAddress];
  if (!ecu) {
    $("selectedEcuTitle").textContent = "No ECU selected";
    $("selectedEcuMeta").textContent = "Diagnostics appear after parsing.";
    $("ecuTabContent").innerHTML = `<div class="empty">No UDS diagnostics decoded.</div>`;
    return;
  }
  $("selectedEcuTitle").textContent = ecuLabel(ecu.address, { withAddress: Boolean(ecu.name) });
  $("selectedEcuMeta").textContent = [
    ecu.ips?.length ? `IPs ${ecu.ips.join(", ")}` : "",
    ecu.vins?.filter(Boolean).length ? `VIN ${ecu.vins.filter(Boolean).join(", ")}` : "",
    ecu.eids?.length ? `EID ${ecu.eids.join(", ")}` : "",

  ].filter(Boolean).join(" | ") || "No announcement metadata for this logical address.";
  for (const button of document.querySelectorAll(".tab")) {
    button.classList.toggle("active", button.dataset.tab === selectedDiagnosticTab);
  }
  const renderers = {
    overview: renderEcuOverview,
    timeline: renderEcuTimeline,
    dids: renderEcuDids,
    dtcs: renderEcuDtcs,
    transfers: renderEcuTransfers,
    routines: renderEcuRoutines,
    services: renderEcuServices,
    errors: renderEcuErrors,
    raw: renderEcuRaw
  };
  $("ecuTabContent").innerHTML = renderers[selectedDiagnosticTab](ecu);
  wireTransferOpenButtons();
  wireDidHistoryControls();
}

function ecuEvents(address) {
  return (currentReport.diagnostics?.udsEvents || []).filter((event) => event.ecuAddress === address);
}

function wireDidHistoryControls() {
  for (const button of $("ecuTabContent").querySelectorAll("[data-did-toggle]")) {
    button.addEventListener("click", () => {
      const key = button.dataset.didToggle;
      if (expandedDidGroups.has(key)) expandedDidGroups.delete(key);
      else expandedDidGroups.add(key);
      renderSelectedEcu();
    });
  }
  for (const button of $("ecuTabContent").querySelectorAll("[data-did-plot]")) {
    button.addEventListener("click", () => openDidPlotModal(button.dataset.didPlot));
  }
}

function renderEcuOverview(ecu) {
  return window.HarnessDiagnosticsRenderer.renderEcuOverview(ecu, {
    events: ecuEvents(ecu.address),
    didReads: (currentReport.diagnostics?.didReads || []).filter((item) => item.ecuAddress === ecu.address),
    transfers: (currentReport.diagnostics?.transfers || []).filter((item) => item.ecuAddress === ecu.address),
    barsHtml
  });
}

function renderEcuTimeline(ecu) {
  return window.HarnessDiagnosticsRenderer.renderEcuTimeline(ecuEvents(ecu.address), { renderCompactTimeline });
}

function traceEventsForReport(report) {
  const logicalByMac = new Map();
  const logicalByIp = new Map();
  for (const ecu of Object.values(report.diagnostics?.ecus || {})) {
    for (const macAddress of ecu.macs || []) logicalByMac.set(macAddress, ecu.address);
    for (const ipAddress of ecu.ips || []) logicalByIp.set(ipAddress, ecu.address);
  }
  const stableLane = (event) => {
    if (event.logicalAddress) return event;
    const logicalAddress = logicalByMac.get(event.srcMac) || logicalByMac.get(event.clientMac) || logicalByIp.get(event.srcIp) || logicalByIp.get(event.requestedIp) || logicalByIp.get(event.yourIp);
    return logicalAddress ? { ...event, logicalAddress, ...traceLaneForLogical("ecu", logicalAddress) } : event;
  };
  if (report.traceEvents?.length) return report.traceEvents.map(stableLane);
  const events = (report.diagnostics?.udsEvents || []).map((event, index) => stableLane({
    id: index + 1,
    category: "uds",
    type: event.responseKind,
    label: `${event.service} ${event.serviceName}`,
    ...traceLaneForLogical("ecu", event.ecuAddress),
    timestamp: event.timestamp,
    packet: event.packet,
    transport: event.transport,
    srcIp: event.srcIp,
    srcPort: event.srcPort,
    dstIp: event.dstIp,
    dstPort: event.dstPort,
    logicalAddress: event.ecuAddress,
    testerAddress: event.testerAddress,
    udsEventId: event.id,
    responseKind: event.responseKind,
    service: event.service,
    serviceName: event.serviceName,
    source: event.source,
    target: event.target,
    did: event.did,
    didName: event.didName,
    nrc: event.nrc,
    nrcName: event.nrcName,
    transfer: event.transfer,
    raw: event.raw,
    valueHex: event.valueHex,
    valueAscii: event.valueAscii
  }));
  for (const sample of report.doip?.samples || []) {
    if (sample.payloadType === "0x8001") continue;
    const category = sample.payloadType === "0x8002" || sample.payloadType === "0x8003" ? "ack" : "doip";
    const lane = sample.logicalAddress ? traceLaneForLogical("ecu", sample.logicalAddress) : { laneKey: "doip:setup", laneLabel: "DoIP Setup" };
    events.push(stableLane({
      id: events.length + 1,
      category,
      type: sample.payloadType,
      label: sample.payloadName,
      ...lane,
      timestamp: sample.timestamp,
      packet: sample.packet,
      transport: sample.transport,
      srcIp: sample.srcIp,
      srcPort: sample.srcPort,
      dstIp: sample.dstIp,
      dstPort: sample.dstPort,
      payloadType: sample.payloadType,
      payloadName: sample.payloadName,
      payloadLength: sample.payloadLength,
      logicalAddress: sample.logicalAddress,
      vin: sample.vin,
      eid: sample.eid,
      gid: sample.gid
    }));
  }
  for (const sample of report.dhcp?.samples || []) {
    const lane = sample.op === "reply"
      ? traceLaneForEndpoint("DHCP server", null, sample.serverId || sample.srcIp)
      : traceLaneForEndpoint("DHCP client", sample.clientMac, sample.requestedIp || sample.yourIp || sample.srcIp);
    events.push(stableLane({
      id: events.length + 1,
      category: "dhcp",
      type: sample.messageType,
      label: `DHCP ${sample.messageType}`,
      ...lane,
      timestamp: sample.timestamp,
      packet: sample.packet,
      op: sample.op,
      xid: sample.xid,
      clientMac: sample.clientMac,
      srcIp: sample.srcIp,
      dstIp: sample.dstIp,
      yourIp: sample.yourIp,
      requestedIp: sample.requestedIp,
      serverId: sample.serverId,
      hostname: sample.hostname,
      vendor: sample.vendor,
      leaseSeconds: sample.leaseSeconds
    }));
  }
  for (const sample of report.arp?.samples || []) {
    events.push(stableLane({
      id: events.length + 1,
      category: "arp",
      type: sample.operation,
      label: `ARP ${sample.operation}`,
      ...traceLaneForEndpoint("ARP", sample.senderMac, sample.senderIp),
      timestamp: sample.timestamp,
      packet: sample.packet,
      operation: sample.operation,
      srcMac: sample.senderMac,
      srcIp: sample.senderIp,
      targetMac: sample.targetMac,
      targetIp: sample.targetIp
    }));
  }
  return events.sort((a, b) => (a.timestamp || 0) - (b.timestamp || 0));
}

function traceTypeKey(event) {
  return window.HarnessTraceRenderer.traceTypeKey(event);
}

function traceCategoryLabel(category) {
  return window.HarnessTraceRenderer.traceCategoryLabel(category);
}

function traceCategoryRank(category) {
  return window.HarnessTraceRenderer.traceCategoryRank(category);
}

function traceLayerEnabled(event) {
  return window.HarnessTraceRenderer.traceLayerEnabled(event, traceController.state.layerState, traceController.state.typeState);
}

function removeArpOnlyTraceLanes(events) {
  return window.HarnessTraceRenderer.removeArpOnlyTraceLanes(events);
}

function renderTrace(report, preserveSelection = false, resetZoom = false) {
  traceController.render(report, preserveSelection, resetZoom);
}

function traceLatencyLabel(startEvent, endEvent) {
  return window.HarnessTraceRenderer.traceLatencyLabel(startEvent, endEvent);
}

function traceTransferSummary(transfer) {
  return window.HarnessTraceRenderer.traceTransferSummary(transfer);
}

function didHistoryForEcu(ecuAddress) {
  const summaries = new Map((currentReport.diagnostics?.didReads || [])
    .filter((item) => item.ecuAddress === ecuAddress)
    .map((item) => [item.did, { ...item, events: [] }]));
  for (const event of currentReport.diagnostics?.udsEvents || []) {
    if (event.ecuAddress !== ecuAddress) continue;
    if (!event.did || !["0x22", "0x62", "0x7f"].includes(event.service)) continue;
    if (event.service === "0x7f" && event.originalService !== "0x22") continue;
    if (!summaries.has(event.did)) {
      summaries.set(event.did, {
        ecuAddress,
        did: event.did,
        name: event.didName || "",
        reads: 0,
        responses: 0,
        negatives: 0,
        pending: 0,
        latestValueHex: "",
        latestValueAscii: "",
        firstTimestamp: event.timestamp,
        lastTimestamp: event.timestamp,
        events: []
      });
    }
    const item = summaries.get(event.did);
    item.events.push(event);
    item.firstTimestamp = Math.min(item.firstTimestamp, event.timestamp);
    item.lastTimestamp = Math.max(item.lastTimestamp, event.timestamp);
  }
  return Array.from(summaries.values())
    .map((item) => ({ ...item, events: item.events.sort((a, b) => (a.timestamp || 0) - (b.timestamp || 0) || (a.packet || 0) - (b.packet || 0)) }))
    .sort((a, b) => a.did.localeCompare(b.did));
}

function didPlotSamples(history) {
  return window.HarnessTraceRenderer.didPlotSamples(history);
}

function didPlotStatus(history) {
  return window.HarnessTraceRenderer.didPlotStatus(history);
}

function truncateMiddle(value, maxLength) {
  return window.HarnessTraceRenderer.truncateMiddle(value, maxLength);
}

function renderTraceTooltipContent(event) {
  return traceController.tooltipContent(event);
}

function renderCompactTimeline(events) {
  return window.HarnessTraceRenderer.renderCompactTimeline(events, { formatTimeDelta, ecuLabel });
}

function renderEcuDids(ecu) {
  return window.HarnessDiagnosticsRenderer.renderEcuDids(didHistoryForEcu(ecu.address), {
    ecuAddress: ecu.address,
    expandedDidGroups,
    didPlotStatus,
    truncateMiddle,
    formatTimeDelta,
    ecuLabel
  });
}

function renderEcuDtcs(ecu) {
  return window.HarnessDiagnosticsRenderer.renderEcuDtcs(ecu, currentReport.diagnostics?.dtcReads || { rows: [], summary: [] }, {
    formatTimeDelta,
    ecuLabel,
    truncateMiddle
  });
}

function renderEcuTransfers(ecu) {
  const transfers = (currentReport.diagnostics.transfers || []).filter((item) => item.ecuAddress === ecu.address);
  return window.HarnessDiagnosticsRenderer.renderEcuTransfers(transfers, { formatTimeDelta });
}

function routineControlLabel(subFunction) {
  return window.HarnessDiagnosticsRenderer.routineControlLabel(subFunction);
}

function routineOptionBytes(raw) {
  return window.HarnessDiagnosticsRenderer.routineOptionBytes(raw);
}

function renderEcuRoutines(ecu) {
  const events = ecuEvents(ecu.address)
    .filter((event) => event.service === "0x31" || event.service === "0x71" || (event.service === "0x7f" && event.originalService === "0x31"))
    .sort((a, b) => a.timestamp - b.timestamp);
  return window.HarnessDiagnosticsRenderer.renderEcuRoutines(events, {
    ecuAddress: ecu.address,
    routineName,
    formatTimeDelta
  });
}

function transferExpectationHtml(transfer) {
  return window.HarnessDiagnosticsRenderer.transferExpectationHtml(transfer);
}

function transferStatusClass(transfer) {
  return window.HarnessDiagnosticsRenderer.transferStatusClass(transfer);
}

function renderEcuServices(ecu) {
  return window.HarnessDiagnosticsRenderer.renderEcuServices(ecu, { events: ecuEvents(ecu.address), formatTimeDelta });
}

function renderEcuErrors(ecu) {
  return window.HarnessDiagnosticsRenderer.renderEcuErrors(ecu, { barsHtml });
}

function renderEcuRaw(ecu) {
  return window.HarnessDiagnosticsRenderer.renderEcuRaw(ecuEvents(ecu.address), {
    formatTimeDelta,
    ecuLabel
  });
}

function barsHtml(object) {
  const entries = Object.entries(object || {}).sort((a, b) => b[1] - a[1]);
  if (!entries.length) return `<div class="empty">No data.</div>`;
  const max = Math.max(...entries.map(([, value]) => value));
  return `<div class="bars">${entries.map(([key, value]) => `
    <div class="bar-row" title="${escapeHtml(`${key}: ${formatNumber(value)}`)}"><div class="bar-label">${escapeHtml(key)}</div><div class="bar-track"><div class="bar-fill" style="width:${(value / max) * 100}%"></div></div><strong>${formatNumber(value)}</strong></div>
  `).join("")}</div>`;
}

function renderSamples() {
  const table = window.HarnessDiscoveryRenderer.sampleTable(currentReport, $("sampleSelect").value);
  $("sampleHead").innerHTML = table.head;
  $("sampleBody").innerHTML = table.body;
}

function downloadText(filename, text, type = "text/csv") {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function exportSelected(kind) {
  const exportFile = window.HarnessExporters.exportSelected(kind, currentReport, selectedEcuAddress, { ecuEvents });
  if (exportFile) downloadText(exportFile.filename, exportFile.text);
}

function exportDownload(kind) {
  if (kind === "timeline") {
    exportDownloadTimelinePng();
    return;
  }
  const exportFile = window.HarnessExporters.exportDownload(kind, currentReport, { ecuName, rateCampaignRows });
  if (exportFile) downloadText(exportFile.filename, exportFile.text);
}

function exportValidationCentre() {
  const rows = filteredValidationFindings(currentReport.validationCentre?.findings || []);
  const exportFile = window.HarnessExporters.exportValidationCentre(rows);
  downloadText(exportFile.filename, exportFile.text);
}

function exportDownloadTimelinePng() {
  downloadController.exportTimelinePng();
}

function exportTcp(kind) {
  const exportFile = window.HarnessExporters.exportTcp(kind, currentReport, selectedTcpFlowKey, { transportFlowIdentity });
  if (exportFile) downloadText(exportFile.filename, exportFile.text);
}

function exportTopology(kind) {
  const topology = currentReport.topology || buildTopologyAnalysis(currentReport);
  const exportFile = window.HarnessExporters.exportTopology(kind, topology);
  downloadText(exportFile.filename, exportFile.text);
}

function wireTransferOpenButtons() {
  for (const button of document.querySelectorAll(".open-download-session")) {
    button.addEventListener("click", () => {
      downloadController.setSelectedSession(button.dataset.transfer);
      openTool("download");
    });
  }
}

function downloadHexText(session) {
  return window.HarnessExporters.downloadHexText(session);
}

function openPersistDb() {
  return window.HarnessPersistence.openPersistDb(persistenceConfig);
}

async function loadPersistedReport() {
  return window.HarnessPersistence.loadPersistedReport(persistenceConfig);
}

async function persistReport(report) {
  return window.HarnessPersistence.persistReport(report, persistenceConfig, { warn: console.warn });
}

async function clearPersistedReport() {
  return window.HarnessPersistence.clearPersistedReport(persistenceConfig, { warn: console.warn });
}

async function handleFile(file) {
  $("sourceLabel").textContent = `Parsing ${file.name}...`;
  $("unloadCapture").hidden = true;
  setCaptureOverlayState("loading", file.name);
  await new Promise((resolve) => setTimeout(resolve, 20));
  try {
    const report = parsePcap(await file.arrayBuffer(), file.name);
    render(report);
    setCaptureOverlayState("loaded");
    $("unloadCapture").hidden = false;
    persistReport(report);
  } catch (error) {
    $("sourceLabel").textContent = error.message;
    $("unloadCapture").hidden = !currentReport.source;
    setCaptureOverlayState("error", error.message);
  }
}

async function unloadCapture() {
  await clearPersistedReport();
  pendingCachedReport = null;
  cancelCachedLoad = true;
  currentReport = emptyReport();
  selectedEcuAddress = null;
  selectedDiagnosticTab = "overview";
  selectedTcpFlowKey = null;
  expandedDidGroups = new Set();
  selectedTopologyItem = null;
  selectedValidationFindingId = null;
  selectedLifecycleNodeId = null;
  selectedLifecycleStageKey = null;
  downloadController.resetFilters();
  $("fileInput").value = "";
  $("unloadCapture").hidden = true;
  render(currentReport);
  $("sourceLabel").textContent = "Load a pcap to inspect UDS, DoIP, DHCP, ARP, and TCP.";
  setCaptureOverlayState("empty");
}

async function handleEcuMapFile(file) {
  try {
    const map = parseEcuMapCsv(await file.text());
    importedEcuMap = map;
    saveEcuMapToStorage(importedEcuMap);
    render(currentReport);
    $("sourceLabel").textContent = `${ecuMapStatusText()} from ${file.name}`;
  } catch (error) {
    $("sourceLabel").textContent = `ECU map import failed: ${error.message}`;
  }
}

$("fileInput").addEventListener("change", (event) => {
  const [file] = event.target.files;
  if (file) handleFile(file);
});

$("captureOverlayOpen").addEventListener("click", () => {
  $("fileInput").click();
});

$("unloadCapture").addEventListener("click", () => {
  unloadCapture();
});

$("captureOverlayLoadCached").addEventListener("click", async () => {
  if (!pendingCachedReport || cancelCachedLoad) return;
  const report = pendingCachedReport;
  pendingCachedReport = null;
  setCaptureOverlayState("loading", report.source || "cached capture");
  await new Promise((resolve) => setTimeout(resolve, 20));
  render(report);
  $("unloadCapture").hidden = false;
  setCaptureOverlayState("loaded");
});

$("captureOverlayStop").addEventListener("click", async () => {
  cancelCachedLoad = true;
  pendingCachedReport = null;
  $("unloadCapture").hidden = true;
  render(currentReport);
  setCaptureOverlayState("empty");
  await clearPersistedReport();
});

for (const eventName of ["dragenter", "dragover"]) {
  $("captureOverlay").addEventListener(eventName, (event) => {
    event.preventDefault();
    $("captureOverlay").classList.add("dragging");
  });
}
for (const eventName of ["dragleave", "drop"]) {
  $("captureOverlay").addEventListener(eventName, (event) => {
    event.preventDefault();
    $("captureOverlay").classList.remove("dragging");
  });
}
$("captureOverlay").addEventListener("drop", (event) => {
  const [file] = event.dataTransfer.files;
  if (file) handleFile(file);
});

$("ecuMapInput").addEventListener("change", (event) => {
  const [file] = event.target.files;
  if (file) handleEcuMapFile(file);
  event.target.value = "";
});

$("clearEcuMap").addEventListener("click", () => {
  importedEcuMap = {};
  saveEcuMapToStorage(importedEcuMap);
  render(currentReport);
  $("sourceLabel").textContent = "ECU name map cleared";
});

$("protocolFilter").addEventListener("input", () => render(currentReport));
$("hostFilter").addEventListener("input", renderHosts);
$("sampleSelect").addEventListener("change", renderSamples);
$("doipLifecycleFilter").addEventListener("change", () => renderDoipLifecycle(currentReport));
$("ecuFilter").addEventListener("input", () => renderDiagnostics(currentReport));
$("identitySeverity").addEventListener("change", () => renderIdentity(currentReport));
traceController.bindControls();
$("exportEvents").addEventListener("click", () => exportSelected("events"));
$("exportDids").addEventListener("click", () => exportSelected("dids"));
$("exportAllDids").addEventListener("click", () => exportSelected("allDids"));
$("exportDtcs").addEventListener("click", () => exportSelected("dtcs"));
$("exportTransfers").addEventListener("click", () => exportSelected("transfers"));
$("exportTcpEvents").addEventListener("click", () => exportTcp("events"));
$("exportTcpAcks").addEventListener("click", () => exportTcp("acks"));
$("transportFlowFilter").addEventListener("change", () => renderTransport(currentReport));
$("validationViewFilter").addEventListener("change", () => renderValidationCentre(currentReport));
$("validationSeverityFilter").addEventListener("change", () => renderValidationCentre(currentReport));
$("validationSourceFilter").addEventListener("change", () => renderValidationCentre(currentReport));
$("validationCategoryFilter").addEventListener("change", () => renderValidationCentre(currentReport));
$("validationSearch").addEventListener("input", () => renderValidationCentre(currentReport));
$("exportValidationCentre").addEventListener("click", exportValidationCentre);
setupCollapsibleTablePanes();
setupTableScrollMirrors();
new MutationObserver(queueTableScrollMirrorRefresh).observe(document.body, { childList: true, subtree: true });
window.addEventListener("resize", queueTableScrollMirrorRefresh);
document.addEventListener("click", (event) => {
  const button = event.target.closest("[data-table-pane-state]");
  if (!button) return;
  const pane = button.closest(".collapsible-table-pane");
  if (!pane) return;
  setTablePaneState(pane, button.dataset.tablePaneState);
});
$("exportDownloadSessions").addEventListener("click", () => exportDownload("sessions"));
$("exportDownloadValidation").addEventListener("click", () => exportDownload("validation"));
$("exportDownloadTimeline").addEventListener("click", () => exportDownload("timeline"));
$("exportRateCampaignCsv").addEventListener("click", () => exportDownload("rateCampaign"));
downloadController.bindControls();
$("openValidationNrcSummary").addEventListener("click", () => {
  renderValidationCentre(currentReport);
  $("validationNrcSummaryModal").hidden = false;
});
$("validationMetrics").addEventListener("click", (event) => {
  if (!event.target.closest("[data-open-validation-nrc-summary]")) return;
  renderValidationCentre(currentReport);
  $("validationNrcSummaryModal").hidden = false;
});
$("closeValidationNrcSummary").addEventListener("click", () => {
  $("validationNrcSummaryModal").hidden = true;
});
$("validationNrcSummaryModal").addEventListener("click", (event) => {
  if (event.target === $("validationNrcSummaryModal")) $("validationNrcSummaryModal").hidden = true;
});
$("toolInfoButton").addEventListener("click", openToolInfoModal);
$("closeToolInfo").addEventListener("click", closeToolInfoModal);
$("toolInfoModal").addEventListener("click", (event) => {
  if (event.target === $("toolInfoModal")) closeToolInfoModal();
});
$("appHelpButton").addEventListener("click", openAppHelpModal);
$("closeAppHelp").addEventListener("click", closeAppHelpModal);
$("appHelpModal").addEventListener("click", (event) => {
  if (event.target === $("appHelpModal")) closeAppHelpModal();
});
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && !$("toolInfoModal").hidden) closeToolInfoModal();
  if (event.key === "Escape" && !$("appHelpModal").hidden) closeAppHelpModal();
});
$("openTopologyNodeMap").addEventListener("click", () => {
  renderTopology(currentReport);
  $("topologyNodeMapModal").hidden = false;
});
$("closeTopologyNodeMap").addEventListener("click", () => {
  $("topologyNodeMapModal").hidden = true;
});
$("topologyNodeMapModal").addEventListener("click", (event) => {
  if (event.target === $("topologyNodeMapModal")) $("topologyNodeMapModal").hidden = true;
});
$("exportTopologyNodes").addEventListener("click", () => exportTopology("nodes"));
$("exportTopologyEdges").addEventListener("click", () => exportTopology("edges"));
$("toolBack").addEventListener("click", () => openTool("home"));
for (const button of document.querySelectorAll("[data-tool-open]")) {
  button.addEventListener("click", () => openTool(button.dataset.toolOpen));
}
$("doipLifecycleNodes").addEventListener("click", (event) => {
  const button = event.target.closest("[data-lifecycle-node]");
  if (!button) return;
  selectedLifecycleNodeId = button.dataset.lifecycleNode;
  selectedLifecycleStageKey = null;
  renderDoipLifecycle(currentReport);
});
$("doipLifecycleNodes").addEventListener("keydown", (event) => {
  if (event.key !== "Enter" && event.key !== " ") return;
  const button = event.target.closest("[data-lifecycle-node]");
  if (!button) return;
  event.preventDefault();
  selectedLifecycleNodeId = button.dataset.lifecycleNode;
  selectedLifecycleStageKey = null;
  renderDoipLifecycle(currentReport);
});
$("doipLifecycleTimeline").addEventListener("click", (event) => {
  const button = event.target.closest("[data-lifecycle-stage]");
  if (!button) return;
  selectedLifecycleStageKey = button.dataset.lifecycleStage;
  renderDoipLifecycle(currentReport);
});
$("doipLifecycleTimeline").addEventListener("keydown", (event) => {
  if (event.key !== "Enter" && event.key !== " ") return;
  const button = event.target.closest("[data-lifecycle-stage]");
  if (!button) return;
  event.preventDefault();
  selectedLifecycleStageKey = button.dataset.lifecycleStage;
  renderDoipLifecycle(currentReport);
});
$("topologyMap").addEventListener("click", (event) => {
  const target = event.target.closest("[data-topology-socket], [data-topology-route]");
  selectTopologyItemFromTarget(target);
});
$("topologyMap").addEventListener("keydown", (event) => {
  if (event.key !== "Enter" && event.key !== " ") return;
  const target = event.target.closest("[data-topology-socket], [data-topology-route]");
  if (!target) return;
  event.preventDefault();
  selectTopologyItemFromTarget(target);
});
$("topologyNodeMapBody").addEventListener("click", (event) => {
  const target = event.target.closest("[data-topology-socket], [data-topology-route]");
  selectTopologyItemFromTarget(target);
});
$("topologyNodeMapBody").addEventListener("keydown", (event) => {
  if (event.key !== "Enter" && event.key !== " ") return;
  const target = event.target.closest("[data-topology-socket], [data-topology-route]");
  if (!target) return;
  event.preventDefault();
  selectTopologyItemFromTarget(target);
});
$("topologyTool").addEventListener("click", (event) => {
  const button = event.target.closest(".topology-select");
  if (!button) return;
  selectedTopologyItem = button.dataset.topologyId;
  renderTopology(currentReport);
});
for (const button of document.querySelectorAll(".tab")) {
  button.addEventListener("click", () => {
    selectedDiagnosticTab = button.dataset.tab;
    activeTool = activeTool === "home" ? "uds" : activeTool;
    renderSelectedEcu();
    applyToolView();
  });
}
for (const eventName of ["dragenter", "dragover"]) {
  $("dropZone").addEventListener(eventName, (event) => {
    event.preventDefault();
    $("dropZone").classList.add("dragging");
  });
}
for (const eventName of ["dragleave", "drop"]) {
  $("dropZone").addEventListener(eventName, (event) => {
    event.preventDefault();
    $("dropZone").classList.remove("dragging");
  });
}
$("dropZone").addEventListener("drop", (event) => {
  const [file] = event.dataTransfer.files;
  if (file) handleFile(file);
});

async function initApp() {
  setCaptureOverlayState("checking-cache");
  const persisted = await loadPersistedReport();
  if (cancelCachedLoad) {
    render(currentReport);
    $("unloadCapture").hidden = true;
    setCaptureOverlayState("empty");
    return;
  }
  render(currentReport);
  $("unloadCapture").hidden = true;
  if (persisted?.summary) {
    pendingCachedReport = persisted;
    setCaptureOverlayState("cached-ready", `${persisted.source || "A previous capture"} is available from this browser cache.`);
    return;
  }
  setCaptureOverlayState("empty");
}

initApp();
