const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const root = path.resolve(__dirname, "..");

function readProjectFile(...parts) {
  return fs.readFileSync(path.join(root, ...parts), "utf8");
}

function assertJavaScriptParses(file) {
  assert.doesNotThrow(
    () => new vm.Script(readProjectFile(file), { filename: file }),
    `${file} should parse as JavaScript`
  );
}

function loadProtocolReference() {
  const sandbox = { window: {} };
  vm.createContext(sandbox);
  vm.runInContext(readProjectFile("src", "js", "protocol-reference.js"), sandbox);
  return sandbox.window.HarnessProtocol;
}

function loadFormatters() {
  const sandbox = { window: {} };
  vm.createContext(sandbox);
  vm.runInContext(readProjectFile("src", "js", "formatters.js"), sandbox);
  return sandbox.window.HarnessFormatters;
}

function loadUiRenderer() {
  const sandbox = { window: {} };
  vm.createContext(sandbox);
  vm.runInContext(readProjectFile("src", "js", "formatters.js"), sandbox);
  vm.runInContext(readProjectFile("src", "js", "ui-renderer.js"), sandbox);
  return sandbox.window.HarnessUi;
}

function loadUdsDecoder() {
  const sandbox = { window: {} };
  vm.createContext(sandbox);
  vm.runInContext(readProjectFile("src", "js", "protocol-reference.js"), sandbox);
  vm.runInContext(readProjectFile("src", "js", "formatters.js"), sandbox);
  vm.runInContext(readProjectFile("src", "js", "uds-decoder.js"), sandbox);
  return sandbox.window.HarnessUds;
}

function loadMappingUtils() {
  const sandbox = { window: {} };
  vm.createContext(sandbox);
  vm.runInContext(readProjectFile("src", "js", "formatters.js"), sandbox);
  vm.runInContext(readProjectFile("src", "js", "mapping-utils.js"), sandbox);
  return sandbox.window.HarnessMappingUtils;
}

function loadTcpAnalysis() {
  const sandbox = { window: {} };
  vm.createContext(sandbox);
  vm.runInContext(readProjectFile("src", "js", "tcp-analysis.js"), sandbox);
  return sandbox.window.HarnessTcpAnalysis;
}

function loadTcpDoipReassembly() {
  const sandbox = { window: {} };
  vm.createContext(sandbox);
  vm.runInContext(readProjectFile("src", "js", "tcp-doip-reassembly.js"), sandbox);
  return sandbox.window.HarnessTcpDoipReassembly;
}

function loadPcapParser() {
  const sandbox = { window: {} };
  vm.createContext(sandbox);
  vm.runInContext(readProjectFile("src", "js", "protocol-reference.js"), sandbox);
  vm.runInContext(readProjectFile("src", "js", "formatters.js"), sandbox);
  vm.runInContext(readProjectFile("src", "js", "tcp-doip-reassembly.js"), sandbox);
  vm.runInContext(readProjectFile("src", "js", "pcap-parser.js"), sandbox);
  return sandbox.window.HarnessPcapParser;
}

function loadDiagnosticAnalysis() {
  const sandbox = { window: {} };
  vm.createContext(sandbox);
  vm.runInContext(readProjectFile("src", "js", "protocol-reference.js"), sandbox);
  vm.runInContext(readProjectFile("src", "js", "formatters.js"), sandbox);
  vm.runInContext(readProjectFile("src", "js", "uds-decoder.js"), sandbox);
  vm.runInContext(readProjectFile("src", "js", "diagnostic-analysis.js"), sandbox);
  return sandbox.window.HarnessDiagnosticAnalysis;
}

function loadIdentityAnalysis() {
  const sandbox = { window: {} };
  vm.createContext(sandbox);
  vm.runInContext(readProjectFile("src", "js", "identity-analysis.js"), sandbox);
  return sandbox.window.HarnessIdentityAnalysis;
}

function loadTopologyAnalysis() {
  const sandbox = { window: {} };
  vm.createContext(sandbox);
  vm.runInContext(readProjectFile("src", "js", "identity-analysis.js"), sandbox);
  vm.runInContext(readProjectFile("src", "js", "topology-analysis.js"), sandbox);
  return sandbox.window.HarnessTopologyAnalysis;
}

function loadValidationAnalysis() {
  const sandbox = { window: {} };
  vm.createContext(sandbox);
  vm.runInContext(readProjectFile("src", "js", "formatters.js"), sandbox);
  vm.runInContext(readProjectFile("src", "js", "identity-analysis.js"), sandbox);
  vm.runInContext(readProjectFile("src", "js", "validation-analysis.js"), sandbox);
  return sandbox.window.HarnessValidationAnalysis;
}

function loadDoipLifecycleAnalysis() {
  const sandbox = { window: {} };
  vm.createContext(sandbox);
  vm.runInContext(readProjectFile("src", "js", "doip-lifecycle-analysis.js"), sandbox);
  return sandbox.window.HarnessDoipLifecycleAnalysis;
}

function loadDownloadAnalysis() {
  const sandbox = { window: {} };
  vm.createContext(sandbox);
  vm.runInContext(readProjectFile("src", "js", "formatters.js"), sandbox);
  vm.runInContext(readProjectFile("src", "js", "tcp-analysis.js"), sandbox);
  vm.runInContext(readProjectFile("src", "js", "download-analysis.js"), sandbox);
  return sandbox.window.HarnessDownloadAnalysis;
}

function loadDiscoveryRenderer() {
  const sandbox = { window: {}, document: { body: { classList: { toggle() {} } } } };
  vm.createContext(sandbox);
  vm.runInContext(readProjectFile("src", "js", "formatters.js"), sandbox);
  vm.runInContext(readProjectFile("src", "js", "ui-renderer.js"), sandbox);
  vm.runInContext(readProjectFile("src", "js", "discovery-renderer.js"), sandbox);
  return sandbox.window.HarnessDiscoveryRenderer;
}

function loadValidationRenderer() {
  const sandbox = { window: {} };
  vm.createContext(sandbox);
  vm.runInContext(readProjectFile("src", "js", "formatters.js"), sandbox);
  vm.runInContext(readProjectFile("src", "js", "ui-renderer.js"), sandbox);
  vm.runInContext(readProjectFile("src", "js", "validation-renderer.js"), sandbox);
  return sandbox.window.HarnessValidationRenderer;
}

function loadIdentityRenderer() {
  const sandbox = { window: {} };
  vm.createContext(sandbox);
  vm.runInContext(readProjectFile("src", "js", "formatters.js"), sandbox);
  vm.runInContext(readProjectFile("src", "js", "ui-renderer.js"), sandbox);
  vm.runInContext(readProjectFile("src", "js", "identity-renderer.js"), sandbox);
  return sandbox.window.HarnessIdentityRenderer;
}

function loadTransportRenderer() {
  const sandbox = { window: {} };
  vm.createContext(sandbox);
  vm.runInContext(readProjectFile("src", "js", "formatters.js"), sandbox);
  vm.runInContext(readProjectFile("src", "js", "ui-renderer.js"), sandbox);
  vm.runInContext(readProjectFile("src", "js", "transport-renderer.js"), sandbox);
  return sandbox.window.HarnessTransportRenderer;
}

function loadTopologyRenderer() {
  const sandbox = { window: {} };
  vm.createContext(sandbox);
  vm.runInContext(readProjectFile("src", "js", "formatters.js"), sandbox);
  vm.runInContext(readProjectFile("src", "js", "ui-renderer.js"), sandbox);
  vm.runInContext(readProjectFile("src", "js", "topology-renderer.js"), sandbox);
  return sandbox.window.HarnessTopologyRenderer;
}

function loadDiagnosticsRenderer() {
  const sandbox = { window: {} };
  vm.createContext(sandbox);
  vm.runInContext(readProjectFile("src", "js", "formatters.js"), sandbox);
  vm.runInContext(readProjectFile("src", "js", "ui-renderer.js"), sandbox);
  vm.runInContext(readProjectFile("src", "js", "diagnostics-renderer.js"), sandbox);
  return sandbox.window.HarnessDiagnosticsRenderer;
}

function loadTraceRenderer() {
  const sandbox = { window: {} };
  vm.createContext(sandbox);
  vm.runInContext(readProjectFile("src", "js", "formatters.js"), sandbox);
  vm.runInContext(readProjectFile("src", "js", "ui-renderer.js"), sandbox);
  vm.runInContext(readProjectFile("src", "js", "trace-renderer.js"), sandbox);
  return sandbox.window.HarnessTraceRenderer;
}

function loadDownloadRenderer() {
  const sandbox = { window: {} };
  vm.createContext(sandbox);
  vm.runInContext(readProjectFile("src", "js", "formatters.js"), sandbox);
  vm.runInContext(readProjectFile("src", "js", "ui-renderer.js"), sandbox);
  vm.runInContext(readProjectFile("src", "js", "download-renderer.js"), sandbox);
  return sandbox.window.HarnessDownloadRenderer;
}

function loadDownloadController() {
  const sandbox = { window: {}, document: { querySelectorAll: () => [] }, getComputedStyle: () => ({ getPropertyValue: () => "" }) };
  vm.createContext(sandbox);
  vm.runInContext(readProjectFile("src", "js", "formatters.js"), sandbox);
  vm.runInContext(readProjectFile("src", "js", "ui-renderer.js"), sandbox);
  vm.runInContext(readProjectFile("src", "js", "download-renderer.js"), sandbox);
  vm.runInContext(readProjectFile("src", "js", "trace-renderer.js"), sandbox);
  vm.runInContext(readProjectFile("src", "js", "download-controller.js"), sandbox);
  return sandbox.window.HarnessDownloadController;
}

function loadTraceController() {
  const sandbox = { window: {}, document: { querySelectorAll: () => [] } };
  vm.createContext(sandbox);
  vm.runInContext(readProjectFile("src", "js", "formatters.js"), sandbox);
  vm.runInContext(readProjectFile("src", "js", "ui-renderer.js"), sandbox);
  vm.runInContext(readProjectFile("src", "js", "trace-renderer.js"), sandbox);
  vm.runInContext(readProjectFile("src", "js", "trace-controller.js"), sandbox);
  return sandbox.window.HarnessTraceController;
}

function loadPersistence() {
  const sandbox = { window: {} };
  vm.createContext(sandbox);
  vm.runInContext(readProjectFile("src", "js", "persistence.js"), sandbox);
  return sandbox.window.HarnessPersistence;
}

function loadExporters() {
  const sandbox = { window: {} };
  vm.createContext(sandbox);
  vm.runInContext(readProjectFile("src", "js", "formatters.js"), sandbox);
  vm.runInContext(readProjectFile("src", "js", "exporters.js"), sandbox);
  return sandbox.window.HarnessExporters;
}

function plain(value) {
  return JSON.parse(JSON.stringify(value));
}

function fakeElement(overrides = {}) {
  const listeners = {};
  return {
    value: "all",
    checked: false,
    hidden: false,
    disabled: false,
    dataset: {},
    style: { setProperty() {}, removeProperty() {} },
    classList: { add() {}, remove() {}, toggle() {} },
    addEventListener(type, handler) {
      listeners[type] = handler;
    },
    dispatch(type, event = {}) {
      listeners[type]?.({ target: this, ...event });
    },
    querySelectorAll() {
      return [];
    },
    querySelector() {
      return null;
    },
    setAttribute() {},
    getBoundingClientRect() {
      return { left: 0, top: 0, width: 100, height: 20, bottom: 20 };
    },
    listeners,
    ...overrides
  };
}

function assertHtmlLoadsScriptBeforeApp() {
  const html = readProjectFile("index.html");
  const mappingsIndex = html.indexOf("mappings.js");
  const protocolIndex = html.indexOf("src/js/protocol-reference.js");
  const formattersIndex = html.indexOf("src/js/formatters.js");
  const uiRendererIndex = html.indexOf("src/js/ui-renderer.js");
  const mappingIndex = html.indexOf("src/js/mapping-utils.js");
  const udsIndex = html.indexOf("src/js/uds-decoder.js");
  const reassemblyIndex = html.indexOf("src/js/tcp-doip-reassembly.js");
  const parserIndex = html.indexOf("src/js/pcap-parser.js");
  const tcpIndex = html.indexOf("src/js/tcp-analysis.js");
  const diagnosticIndex = html.indexOf("src/js/diagnostic-analysis.js");
  const identityIndex = html.indexOf("src/js/identity-analysis.js");
  const topologyIndex = html.indexOf("src/js/topology-analysis.js");
  const downloadIndex = html.indexOf("src/js/download-analysis.js");
  const validationIndex = html.indexOf("src/js/validation-analysis.js");
  const lifecycleIndex = html.indexOf("src/js/doip-lifecycle-analysis.js");
  const discoveryRendererIndex = html.indexOf("src/js/discovery-renderer.js");
  const validationRendererIndex = html.indexOf("src/js/validation-renderer.js");
  const identityRendererIndex = html.indexOf("src/js/identity-renderer.js");
  const transportRendererIndex = html.indexOf("src/js/transport-renderer.js");
  const topologyRendererIndex = html.indexOf("src/js/topology-renderer.js");
  const diagnosticsRendererIndex = html.indexOf("src/js/diagnostics-renderer.js");
  const traceRendererIndex = html.indexOf("src/js/trace-renderer.js");
  const downloadRendererIndex = html.indexOf("src/js/download-renderer.js");
  const downloadControllerIndex = html.indexOf("src/js/download-controller.js");
  const traceControllerIndex = html.indexOf("src/js/trace-controller.js");
  const exportersIndex = html.indexOf("src/js/exporters.js");
  const persistenceIndex = html.indexOf("src/js/persistence.js");
  const appIndex = html.indexOf("app.js");

  assert.ok(mappingsIndex > -1, "index.html should load mappings.js");
  assert.ok(protocolIndex > -1, "index.html should load the protocol reference module");
  assert.ok(formattersIndex > -1, "index.html should load the formatters module");
  assert.ok(uiRendererIndex > -1, "index.html should load the shared UI renderer module");
  assert.ok(mappingIndex > -1, "index.html should load the mapping utilities module");
  assert.ok(udsIndex > -1, "index.html should load the UDS decoder module");
  assert.ok(reassemblyIndex > -1, "index.html should load the TCP DoIP reassembly module");
  assert.ok(parserIndex > -1, "index.html should load the PCAP parser module");
  assert.ok(tcpIndex > -1, "index.html should load the TCP analysis module");
  assert.ok(diagnosticIndex > -1, "index.html should load the diagnostic analysis module");
  assert.ok(identityIndex > -1, "index.html should load the identity analysis module");
  assert.ok(topologyIndex > -1, "index.html should load the topology analysis module");
  assert.ok(downloadIndex > -1, "index.html should load the download analysis module");
  assert.ok(validationIndex > -1, "index.html should load the validation analysis module");
  assert.ok(lifecycleIndex > -1, "index.html should load the DoIP lifecycle analysis module");
  assert.ok(discoveryRendererIndex > -1, "index.html should load the discovery renderer module");
  assert.ok(validationRendererIndex > -1, "index.html should load the validation renderer module");
  assert.ok(identityRendererIndex > -1, "index.html should load the identity renderer module");
  assert.ok(transportRendererIndex > -1, "index.html should load the transport renderer module");
  assert.ok(topologyRendererIndex > -1, "index.html should load the topology renderer module");
  assert.ok(diagnosticsRendererIndex > -1, "index.html should load the diagnostics renderer module");
  assert.ok(traceRendererIndex > -1, "index.html should load the trace renderer module");
  assert.ok(downloadRendererIndex > -1, "index.html should load the download renderer module");
  assert.ok(downloadControllerIndex > -1, "index.html should load the download controller module");
  assert.ok(traceControllerIndex > -1, "index.html should load the trace controller module");
  assert.ok(exportersIndex > -1, "index.html should load the exporters module");
  assert.ok(persistenceIndex > -1, "index.html should load the persistence module");
  assert.ok(appIndex > -1, "index.html should load app.js");
  assert.ok(mappingsIndex < protocolIndex, "mappings.js must load before protocol reference");
  assert.ok(protocolIndex < formattersIndex, "protocol reference must load before formatters");
  assert.ok(formattersIndex < uiRendererIndex, "formatters must load before shared UI renderer");
  assert.ok(uiRendererIndex < mappingIndex, "shared UI renderer must load before mapping utilities");
  assert.ok(mappingIndex < udsIndex, "mapping utilities must load before UDS decoder");
  assert.ok(udsIndex < reassemblyIndex, "UDS decoder must load before TCP DoIP reassembly");
  assert.ok(reassemblyIndex < parserIndex, "TCP DoIP reassembly must load before PCAP parser");
  assert.ok(parserIndex < tcpIndex, "PCAP parser must load before TCP analysis");
  assert.ok(tcpIndex < diagnosticIndex, "TCP analysis must load before diagnostic analysis");
  assert.ok(diagnosticIndex < identityIndex, "diagnostic analysis must load before identity analysis");
  assert.ok(identityIndex < topologyIndex, "identity analysis must load before topology analysis");
  assert.ok(topologyIndex < downloadIndex, "topology analysis must load before download analysis");
  assert.ok(downloadIndex < validationIndex, "download analysis must load before validation analysis");
  assert.ok(validationIndex < lifecycleIndex, "validation analysis must load before DoIP lifecycle analysis");
  assert.ok(lifecycleIndex < discoveryRendererIndex, "DoIP lifecycle analysis must load before discovery renderer");
  assert.ok(discoveryRendererIndex < validationRendererIndex, "discovery renderer must load before validation renderer");
  assert.ok(validationRendererIndex < identityRendererIndex, "validation renderer must load before identity renderer");
  assert.ok(identityRendererIndex < transportRendererIndex, "identity renderer must load before transport renderer");
  assert.ok(transportRendererIndex < topologyRendererIndex, "transport renderer must load before topology renderer");
  assert.ok(topologyRendererIndex < diagnosticsRendererIndex, "topology renderer must load before diagnostics renderer");
  assert.ok(diagnosticsRendererIndex < traceRendererIndex, "diagnostics renderer must load before trace renderer");
  assert.ok(traceRendererIndex < downloadRendererIndex, "trace renderer must load before download renderer");
  assert.ok(downloadRendererIndex < downloadControllerIndex, "download renderer must load before download controller");
  assert.ok(downloadControllerIndex < traceControllerIndex, "download controller must load before trace controller");
  assert.ok(traceControllerIndex < exportersIndex, "trace controller must load before exporters");
  assert.ok(exportersIndex < persistenceIndex, "exporters must load before persistence");
  assert.ok(persistenceIndex < appIndex, "persistence must load before app.js");
  assert.ok(html.includes('id="openValidationNrcSummary"'), "Validation Centre should expose an NRC summary modal button");
  assert.ok(html.includes('id="validationNrcSummaryModal"'), "Validation Centre should include an NRC summary modal");
  assert.ok(html.indexOf('id="validationNrcSummaryModal"') < html.indexOf('id="validationNrcSummary"'), "NRC summary content should live inside the modal");
  assert.ok(html.indexOf('<option value="all">All findings</option>') < html.indexOf('<option value="action-required">Action Suggested</option>'), "Validation Centre should default to all findings");
  assert.ok(html.includes('id="discoveryMetrics" class="overview-grid discovery-capture-metrics"'), "Discovery summary metrics should live inside the Discovery Console panel");
  assert.ok(html.includes("Decoded DoIP Messages"), "Discovery payload panel should label decoded DoIP messages rather than generic packets");
  assert.ok(html.includes("Announcements, decoded DoIP messages, DHCP, ARP, and hosts."), "Discovery home text should distinguish decoded DoIP messages");
  assert.ok(html.includes('class="table-wrap validation-table-wrap collapsible-table-pane" data-table-pane-label="Validation findings" data-scroll-mirror="false"'), "Validation Centre should not use the sticky horizontal scrollbar mirror");
  assert.ok(html.includes('class="table-wrap ecu-list-wrap collapsible-table-pane" data-table-pane-label="ECU list" data-fixed-table-controls="true"'), "UDS ECU list controls should stay visible instead of scrolling horizontally with the table");
  assert.ok(html.includes('class="table-wrap download-session-wrap collapsible-table-pane" data-table-pane-label="Transfer segments" data-fixed-table-controls="true"'), "SWDL transfer table controls should stay visible instead of scrolling horizontally with the table");
  assert.ok(html.includes('class="table-wrap transport-flow-wrap collapsible-table-pane" data-table-pane-label="TCP timing windows" data-fixed-table-controls="true"'), "Transport Timing flow table controls should stay visible instead of scrolling horizontally with the table");
  assert.ok(html.includes('id="toolInfoButton"'), "workbench header should expose a Tool Info button");
  assert.ok(html.includes('id="toolInfoModal"'), "app should include a reusable Tool Info modal");
  assert.ok(html.includes('id="toolInfoBody"'), "Tool Info modal should have a dedicated body container");
  assert.ok(html.includes('id="appHelpButton"'), "topbar should expose a Help button next to Home");
  assert.ok(html.includes('id="appHelpModal"'), "app should include a reusable Help modal");
  assert.ok(html.includes("Luke Darragh"), "Help modal should credit the author");
  assert.ok(html.includes("https://www.linkedin.com/in/ldarragh/"), "Help modal should link to Luke Darragh's LinkedIn");
  assert.ok(html.includes("https://github.com/luked-tools/harness.git"), "Help modal should include the repository source address");
  assert.ok(html.includes("our new robot friends"), "Help modal should include the robot friends build note");
  assert.ok(html.includes('id="downloadExportableOnly" type="checkbox"> Exportable hex only'), "SWDL exportable filter should use explicit hex wording");
  assert.ok(html.indexOf('id="downloadExportableOnly"') < html.indexOf('id="downloadEcuFilter"'), "SWDL exportable hex filter should sit at the left of the filter row");
  assert.ok(html.includes('id="captureOverlay"'), "app should include a blocking capture overlay");
  assert.ok(html.includes('id="captureOverlayOpen"'), "capture overlay should provide an open-pcap action");
  assert.ok(html.includes('id="captureOverlayLoadCached"'), "capture overlay should provide an explicit load-cached action");
  assert.ok(html.includes('id="captureOverlayStop"'), "capture overlay should provide a stop action while cached files load");
  assert.ok(html.includes('id="unloadCapture"'), "topbar should include an unload file button");
  assert.ok(html.indexOf('id="clearEcuMap"') < html.indexOf('id="unloadCapture"'), "unload file button should sit in the topbar actions");
  assert.ok(html.indexOf('id="captureOverlay"') > html.indexOf("</main>"), "capture overlay should sit outside the main app shell so it can cover the page");
}

function assertScrollPaneCssContracts() {
  const css = readProjectFile("styles.css");
  const tableWrapRule = css.match(/(?:^|\n)\.table-wrap\s*\{[^}]+\}/)?.[0] || "";
  assert.ok(tableWrapRule.includes("overflow-x: auto"), "ordinary table wrappers should keep horizontal scrolling");
  assert.ok(tableWrapRule.includes("max-height: none"), "ordinary table wrappers should not cap their own vertical height");
  const downloadTabTableRule = css.match(/\.download-tab-pane-matrix\s*>\s*\.table-wrap,[\s\S]+?\.download-tab-pane-raw\s*>\s*\.table-wrap\s*\{[^}]+\}/)?.[0] || "";
  assert.ok(downloadTabTableRule.includes("height: auto"), "download tab tables should expand into the tab scroll pane");
  assert.ok(css.includes(".table-scrollbar-proxy"), "wide tables should expose a horizontal scrollbar proxy");
  const proxyRule = css.match(/\.table-scrollbar-proxy\s*\{[^}]+\}/)?.[0] || "";
  assert.ok(proxyRule.includes("bottom: 0"), "scrollbar proxy should sit at the bottom rather than between pane and table headings");
  assert.ok(proxyRule.includes("border-top"), "bottom scrollbar proxy should separate from table content without cutting table headings");
  assert.ok(css.includes(".collapsible-table-pane .table-scrollbar-proxy"), "collapsible table panes should place the proxy in the bottom row");
  assert.ok(css.includes("grid-template-columns: minmax(920px, 2.8fr) minmax(220px, 0.45fr)"), "expanded Validation Centre table should materially widen the table pane");
  assert.ok(css.includes('body[data-tool="validation"] #validationTool'), "Validation Centre should receive a tool-group top strip");
  assert.ok(css.includes('body[data-tool="transport"] #transportTool'), "Transport tool should receive a tool-group top strip");
  assert.ok(css.includes('body[data-tool="discovery"] #discoveryTool > .panel'), "Discovery panels should receive a tool-group top strip");
  assert.equal(css.includes('body[data-tool="discovery"] #metrics'), false, "Discovery should not show the standalone metrics strip");
  assert.ok(css.includes(".discovery-capture-metrics"), "Discovery in-panel metrics should have local spacing");
  assert.ok(css.includes(".lifecycle-stage:not(:last-child)::after"), "DoIP lifecycle stages should show connector lines between steps");
  assert.ok(css.includes(".lifecycle-stage:not(:last-child)::before"), "DoIP lifecycle stages should show arrow heads between steps");
  assert.ok(css.includes(".lifecycle-stage-index"), "DoIP lifecycle stages should include numbered step markers");
  assert.ok(css.includes(".lifecycle-node-status"), "DoIP lifecycle node rows should use a fixed status column");
  assert.ok(css.includes("grid-template-columns: 78px minmax(0, 1fr) minmax(104px, auto)"), "DoIP lifecycle node rows should align title, role, logical, and IP into columns");
  assert.ok(css.includes(".lifecycle-stage .badge"), "DoIP lifecycle stage state should use shared badge styling");
  assert.ok(css.includes(".lifecycle-node-status .badge"), "DoIP lifecycle node status pills should sit consistently on the left of the node row");
  assert.ok(css.includes("bottom: 9px"), "DoIP lifecycle stage pills should be centred at the bottom of the stage button");
  assert.ok(css.includes("transform: translateX(-50%)"), "DoIP lifecycle stage pills should be horizontally centred");
  assert.equal(css.includes(".lifecycle-node-meta"), false, "DoIP lifecycle node rows should not use bespoke tiny metadata styling");
  assert.equal(css.includes(".lifecycle-node-head"), false, "DoIP lifecycle node rows should not use stacked header metadata layout");
  assert.ok(css.includes("height: 82px"), "DoIP lifecycle stage buttons should keep a stable height when selected");
  assert.ok(css.includes("grid-template-rows: auto minmax(260px, 1fr)"), "DoIP lifecycle workspace should reserve stable detail-panel height");
  assert.ok(css.includes("max-height: 420px"), "DoIP lifecycle detail should scroll internally instead of resizing the flow area");
  const collapsibleRule = css.match(/\.collapsible-table-pane\s*\{[^}]+\}/)?.[0] || "";
  assert.ok(collapsibleRule.includes("overflow: auto"), "collapsible table panes should own vertical scrolling");
  assert.ok(collapsibleRule.includes("grid-template-rows: auto minmax(0, 1fr) auto"), "collapsible table panes should reserve a bottom row for the horizontal scrollbar proxy");
  const paneControlsRule = css.match(/(^|\n)\.table-pane-controls\s*\{[^}]+\}/)?.[0] || "";
  assert.ok(paneControlsRule.includes("position: relative"), "table pane controls should not float over sticky table headers");
  assert.ok(css.includes(".validation-finding-cell"), "Validation Centre finding text should be constrained so it does not stretch the table");
  assert.ok(css.includes(".validation-evidence-cell"), "Validation Centre evidence text should be constrained so packet lists do not stretch the table");
  assert.ok(css.includes(".validation-evidence-collapsed"), "long Validation Centre evidence should be collapsible");
  assert.ok(css.includes(".socket-card.has-rejected-targets"), "Node map socket cards should visibly flag rejected unknown targets");
  assert.ok(css.includes(".socket-status-pill.rejected"), "Node map socket cards should include a rejected-target pill style");
  assert.ok(css.includes(".socket-graph-row.has-rejected-targets"), "Node map should visually flag sockets with rejected unknown targets");
  assert.ok(css.includes(".rejected-node"), "Node map rejected targets should have a dedicated error style");
  assert.ok(css.includes("width: min(100%, 940px)"), "Node map rows should not leave a large blank right column");
  assert.ok(css.includes(".mini-metric-action"), "clickable mini metrics should retain metric styling");
  const directToolTablesRule = css.match(/body\[data-tool="identity"\]\s+#identityTool\s+\.table-wrap,[\s\S]+?body\[data-tool="raw"\]\s+#rawTool\s+\.table-wrap\s*\{[^}]+\}/)?.[0] || "";
  assert.ok(directToolTablesRule.includes("overflow: auto"), "direct identity/raw table panels should retain their own scroll area");
  assert.equal(/body\[data-tool="dids"\]\s+#ecuTabContent\s+\.table-wrap,[\s\S]+max-height:\s*calc\(100vh - 390px\)/.test(css), false, "DID tab tables should rely on the tab-content scroll pane");
  assert.equal(/body\[data-tool="transfers"\]\s+#ecuTabContent\s+\.table-wrap,[\s\S]+max-height:\s*calc\(100vh - 390px\)/.test(css), false, "transfer tab tables should rely on the tab-content scroll pane");
  assert.ok(css.includes(".did-hex-preview"), "DID latest hex previews should be capped so long values do not stretch tables");
  assert.ok(css.includes(".dtc-hex-preview"), "DTC hex previews should be capped so long values do not stretch tables");
  assert.ok(css.includes(".dtc-persistent-row"), "DTCs observed after a clear command should be visually highlighted");
  assert.ok(css.includes(".capture-overlay"), "capture overlay should grey out the page until a capture is loaded");
  assert.ok(css.includes("[hidden]") && css.includes("display: none !important"), "hidden controls should not be overridden by button styling");
  assert.ok(css.includes(".capture-overlay.dragging"), "capture overlay should show drag feedback");
  assert.ok(css.includes("@keyframes capture-spin"), "capture overlay should include a parsing animation");
  assert.ok(css.includes(".capture-overlay.is-loading"), "capture overlay should expose a loading state");
  assert.ok(css.includes("overflow-wrap: anywhere"), "capture overlay text should wrap long filenames safely");
  assert.ok(css.includes("grid-template-columns: minmax(460px, 0.78fr) minmax(0, 1.22fr)"), "UDS ECU list pane should have a practical default width");
  assert.ok(css.includes(".ecu-list-wrap .table-pane-controls"), "UDS ECU list table controls should remain visible while horizontally scrolling the table");
  assert.ok(css.includes("grid-template-rows: auto auto min-content"), "UDS ECU list rows should stay compact when only a few ECUs are present");
  assert.ok(css.includes("grid-template-columns: minmax(520px, 0.98fr) minmax(0, 1.32fr)"), "SWDL transfer table should have a practical default width");
  assert.ok(css.includes(".download-session-wrap .table-pane-controls"), "SWDL transfer table controls should remain visible while horizontally scrolling the table");
  assert.ok(css.includes(".download-session-wrap td:first-child"), "SWDL transfer table should wrap long ECU and validation cells instead of stretching horizontally");
  assert.ok(css.includes(".transport-flow-wrap .table-pane-controls"), "Transport Timing flow table controls should remain visible while horizontally scrolling the table");
  assert.ok(css.includes(".transport-flow-wrap td:first-child"), "Transport Timing flow table should wrap long endpoint and observation cells instead of stretching horizontally");
  assert.ok(css.includes(".tool-info-button"), "Tool Info button should be positioned in the shared tool header");
  assert.ok(css.includes(".tool-info-grid"), "Tool Info modal should use a structured grid layout");
  assert.ok(css.includes(".tool-info-section"), "Tool Info modal should style logical content sections");
  assert.ok(css.includes(".header-action-group"), "topbar buttons should be visually grouped");
  assert.ok(css.includes(".app-help-modal"), "Help modal should have dedicated layout styling");
  assert.ok(css.includes(".app-help-grid"), "Help modal should arrange content in logical sections");
  const app = readProjectFile("app.js");
  assert.ok(app.includes("setupTableScrollMirrors"), "app should install synchronized top scrollbars for wide tables");
  assert.ok(app.includes('$("discoveryMetrics").innerHTML = captureMetricsHtml'), "Discovery metrics should render inside the Discovery Console panel");
  assert.ok(app.includes("DoIP port traffic"), "Discovery metrics should clarify DoIP port traffic count");
  assert.ok(app.includes("Decoded DoIP messages"), "Discovery metrics should include decoded DoIP message count");
  assert.ok(app.includes('wrap.dataset.scrollMirror === "false"'), "individual tables should be able to opt out of scrollbar mirrors");
  assert.ok(app.includes('closest("button, a, input, select, textarea, summary, details")'), "Validation evidence packet details should not be closed by row selection rerenders");
  assert.ok(app.includes("table.after(mirror)"), "scrollbar proxy should be placed after the table rather than between controls and headings");
  assert.ok(app.includes("controls.style.minWidth"), "table pane controls should span the full table width");
  assert.ok(app.includes('wrap.dataset.fixedTableControls === "true"'), "individual table panes should be able to keep controls fixed within the visible pane");
  assert.ok(app.includes("const TOOL_INFO"), "Tool Info content should be maintained in a dedicated map");
  assert.ok(app.includes("function renderToolInfo"), "Tool Info modal should render content for the active tool");
  assert.ok(app.includes('$("toolInfoButton").addEventListener("click", openToolInfoModal)'), "Tool Info button should open the modal");
  assert.ok(app.includes("function openAppHelpModal"), "topbar Help button should open the app Help modal");
  assert.ok(app.includes('$("appHelpButton").addEventListener("click", openAppHelpModal)'), "Help button should be wired to the Help modal");
  assert.ok(app.includes("MutationObserver(queueTableScrollMirrorRefresh)"), "wide-table scrollbar setup should refresh after rendered table changes");
  assert.ok(app.includes("data-open-validation-nrc-summary"), "NRC metric counters should open the NRC summary modal");
  assert.ok(app.includes('setCaptureOverlayState("loading"'), "file loading should show the parsing overlay");
  assert.ok(app.includes('setCaptureOverlayState("checking-cache"'), "initial restore should check cache without showing the stop action as if a file exists");
  assert.ok(app.includes('setCaptureOverlayState("cached-ready"'), "cached report restore should wait for explicit user action");
  assert.equal(app.includes("setTimeout(resolve, 250)"), false, "cached report restore should not race the stop button with a timeout");
  assert.ok(app.includes("pendingCachedReport = persisted"), "cached report should be held pending until the user chooses to load it");
  assert.ok(app.includes("render(currentReport);\n  setCaptureOverlayState(\"empty\");\n  await clearPersistedReport();"), "stop cached load should return to the empty modal before async cache clearing completes");
  assert.ok(app.includes('setCaptureOverlayState("loaded"'), "successful parsing should hide the capture overlay");
  assert.ok(app.includes('setCaptureOverlayState("error"'), "parse failures should keep the overlay visible with an error");
  assert.ok(app.includes('$("captureOverlay").addEventListener("drop"'), "capture overlay should accept dropped pcap files");
  assert.ok(app.includes("async function unloadCapture"), "topbar unload button should reset the loaded capture");
  assert.ok(app.includes("clearPersistedReport"), "unloading should clear the cached capture");
  assert.ok(app.includes("cancelCachedLoad"), "cached restore should be cancellable from the modal");
}

function assertProtocolReferenceContracts() {
  const protocol = loadProtocolReference();

  assert.equal(protocol.DOIP_PORT, 13400);
  assert.equal(protocol.DHCP_TYPES[5], "Ack");
  assert.equal(protocol.DOIP_TYPES[0x0000], "Generic DoIP header negative acknowledgement");
  assert.equal(protocol.DOIP_TYPES[0x8001], "Diagnostic message");
  assert.equal(protocol.DOIP_GENERIC_NACK_CODES[0x02], "Message too large");
  assert.equal(protocol.DOIP_DIAGNOSTIC_NACK_CODES[0x03], "Unknown target address");
  assert.equal(protocol.DOIP_DIAGNOSTIC_NACK_CODES[0x05], "Out of memory");
  assert.equal(protocol.DOIP_ROUTING_ACTIVATION_RESPONSE_CODES[0x10], "Routing successfully activated");
  assert.equal(protocol.UDS_SERVICE_NAMES[0x22], "Read Data By Identifier");
  assert.equal(protocol.UDS_NRC_NAMES[0x78], "Response pending");
  assert.ok(protocol.DHCP_PORTS.has(67));
  assert.ok(protocol.VLAN_TYPES.has(0x8100));
  assert.ok(Object.isFrozen(protocol), "protocol reference should be immutable at the top level");
}

function assertPythonToolingRemoved() {
  assert.equal(fs.existsSync(path.join(root, "tools", "analyze_pcap.py")), false);
  assert.equal(fs.existsSync(path.join(root, "tools", "protocol_reference.py")), false);
}

function assertFormatterContracts() {
  const formatters = loadFormatters();
  const bytes = new Uint8Array([0, 10, 16, 255]);

  assert.equal(formatters.hexByte(15), "0x0f");
  assert.equal(formatters.hexWord(4660), "0x1234");
  assert.equal(formatters.bytesToHex(bytes), "00 0a 10 ff");
  assert.deepEqual(Array.from(formatters.hexToBytes("00 0a nope 10 ff")), Array.from(bytes));
  assert.equal(formatters.bytesToAsciiPreview(new Uint8Array([72, 105, 0, 46, 46])), "Hi");

  assert.equal(formatters.escapeHtml("&<>\"'"), "&amp;&lt;&gt;&quot;&#39;");
  assert.equal(formatters.formatCell(null), "");
  assert.equal(formatters.formatCell(12), "12");
  assert.equal(formatters.formatCell(1.23456789), "1.234568");
  assert.equal(formatters.formatCell("<ecu>"), "<code>&lt;ecu&gt;</code>");

  assert.equal(formatters.formatBytes(512), "512 B");
  assert.equal(formatters.formatBytes(1536), "1.5 KB");
  assert.equal(formatters.formatRate(2048), "2.0 KB/s");
  assert.equal(formatters.formatRate(0), "n/a");
  assert.equal(formatters.formatDurationValue(0.0005), "500 us");
  assert.equal(formatters.formatDurationValue(0.5), "500.00 ms");
  assert.equal(formatters.formatDurationValue(1.25), "1.250 s");
  assert.equal(formatters.formatDurationValue(65.2), "1m 5.2s");
  assert.equal(formatters.formatMs(0.123456), "123.456 ms");
  assert.equal(formatters.formatTimeDelta(12.5, 10), "+2.500s");

  assert.equal(
    formatters.toCsv(
      [
        { plain: "alpha", comma: "a,b", quote: 'a"b', newline: "a\nb", missing: null },
        { plain: undefined, comma: "ok", quote: "fine", newline: "done" }
      ],
      ["plain", "comma", "quote", "newline", "missing"]
    ),
    'plain,comma,quote,newline,missing\nalpha,"a,b","a""b","a\nb",\n,ok,fine,done,'
  );
}

function assertUiRendererContracts() {
  const ui = loadUiRenderer();

  assert.equal(ui.metric("Packets", 1200), '<div class="mini-metric"><span>Packets</span><strong>1,200</strong></div>');
  assert.equal(ui.metric("ECU <A>", "<ready>"), '<div class="mini-metric"><span>ECU &lt;A&gt;</span><strong>&lt;ready&gt;</strong></div>');
  assert.equal(ui.metrics([["Errors", 1], ["Status", "OK"]]), '<div class="mini-metric"><span>Errors</span><strong>1</strong></div><div class="mini-metric"><span>Status</span><strong>OK</strong></div>');
  assert.ok(ui.metricGrid([["Warnings", 2]]).startsWith('<div class="overview-grid">'));
  assert.equal(ui.badge("warn <x>", "warn", { title: "a & b" }), '<span class="badge warn" title="a &amp; b">warn &lt;x&gt;</span>');
  assert.equal(ui.badges([["OK", "ok"], ["Info", ""]]), '<span class="badge ok">OK</span> <span class="badge">Info</span>');
  assert.equal(ui.emptyRow(2, "No <rows>"), '<tr><td colspan="2">No &lt;rows&gt;</td></tr>');
  assert.equal(ui.table(["A", "B"], "<tr><td>1</td><td>2</td></tr>", "Empty"), '<div class="table-wrap"><table><thead><tr><th>A</th><th>B</th></tr></thead><tbody><tr><td>1</td><td>2</td></tr></tbody></table></div>');
  assert.ok(ui.compactCode("aa ".repeat(80), { limit: 32 }).includes("<details"));
  assert.ok(ui.compactCode("aa bb", { limit: 32 }).includes('title="aa bb"'));
  assert.ok(ui.rawBytesCell("aa ".repeat(80), { limit: 32 }).includes('class="raw-uds-cell"'));
}

function assertUdsDecoderContracts() {
  const uds = loadUdsDecoder();
  const mapped = {
    services: { "0x22": "Mapped Read DID" },
    nrcs: { "0x78": "Mapped Pending" }
  };

  assert.equal(uds.serviceName(0x22), "Read Data By Identifier");
  assert.equal(uds.serviceName(0xfe), "Service 0xfe");
  assert.equal(uds.nrcName(0x78), "Response pending");
  assert.equal(uds.nrcName(0xfe), "NRC 0xfe");
  assert.equal(uds.serviceName(0x22, mapped), "Mapped Read DID");
  assert.equal(uds.nrcName(0x78, mapped), "Mapped Pending");

  assert.deepEqual(
    plain(uds.decodeUds(new Uint8Array([0x7f, 0x22, 0x78]))),
    {
      sid: 0x7f,
      name: "Negative Response",
      originalSid: 0x22,
      nrc: 0x78,
      did: null,
      routineId: null,
      subFunction: null,
      dtc: null,
      transfer: null,
      valueHex: "",
      valueAscii: ""
    }
  );

  assert.deepEqual(
    plain(uds.decodeUds(new Uint8Array([0x62, 0xf1, 0x90, 0x56, 0x49, 0x4e]))),
    {
      sid: 0x62,
      name: "Read Data By Identifier Response",
      originalSid: 0x22,
      nrc: null,
      did: 0xf190,
      routineId: null,
      subFunction: null,
      dtc: null,
      transfer: null,
      valueHex: "56 49 4e",
      valueAscii: "VIN"
    }
  );

  const dtc = uds.decodeDtcResponse(new Uint8Array([0x59, 0x02, 0xff, 0x01, 0x02, 0x03, 0x09]));
  assert.equal(dtc.resultType, "dtcList");
  assert.equal(dtc.statusAvailabilityMask, "0xff");
  assert.deepEqual(plain(dtc.dtcRecords), [{ dtc: "010203", status: "0x09", statusLabels: "testFailed, confirmedDTC" }]);

  assert.deepEqual(
    plain(uds.decodeRequestTransfer(new Uint8Array([0x34, 0x00, 0x22, 0x12, 0x34, 0x10, 0x00]))),
    {
      type: "Request Download",
      dataFormat: "0x00",
      lengthFormat: "0x22",
      memoryAddress: "0x1234",
      memorySize: 4096
    }
  );
  assert.deepEqual(
    plain(uds.decodeTransferData(new Uint8Array([0x36, 0x02, 0x41, 0x42, 0x00]))),
    {
      type: "Transfer Data",
      blockCounter: 2,
      dataLength: 3,
      dataHex: "41 42 00",
      dataAscii: "AB"
    }
  );
}

function assertMappingUtilityContracts() {
  const mapping = loadMappingUtils();
  const userMappings = {
    dids: { "0xf190": "VIN" },
    routines: { "0x0203": "Erase memory" },
    ecus: { "0x716": "Compact static", "0x1001": "Static Gateway" }
  };
  const imported = { "0x1001": "Imported Gateway" };

  assert.equal(mapping.normaliseLogicalAddress("1001"), "0x1001");
  assert.equal(mapping.normaliseLogicalAddress("0x716"), "0x0716");
  assert.equal(mapping.normaliseLogicalAddress("Gateway (0x1001)"), "0x1001");
  assert.equal(mapping.normaliseLogicalAddress("0x123456"), "");
  assert.equal(mapping.normaliseLogicalAddress("zzzz"), "");
  assert.deepEqual(plain(mapping.splitCsvLine('"0x1001","Gateway, Main","A ""quoted"" name"')), ["0x1001", "Gateway, Main", 'A "quoted" name']);
  assert.deepEqual(plain(mapping.parseEcuMapCsv("logicalAddress,name\n0x1001,Gateway\n716,Body")), { "0x1001": "Gateway", "0x0716": "Body", "0x02cc": "Body" });
  assert.equal(mapping.normaliseDecimalLogicalAddress("1001"), "0x03e9");
  assert.equal(mapping.normaliseDecimalLogicalAddress("0x1001"), "");
  assert.deepEqual(plain(mapping.parseEcuMapCsv("logicalAddress,name,acronym\n0x1001,Central Gateway,CGW")), { "0x1001": "CGW" });
  assert.deepEqual(plain(mapping.parseEcuMapCsv("ECU Address,Short Name\n0x2222,BCM")), { "0x2222": "BCM" });
  assert.deepEqual(plain(mapping.parseEcuMapCsv("DoIP Logical Address,Description,Acronym\nGateway (0x1001),Central Gateway,CGW")), { "0x1001": "CGW" });
  assert.deepEqual(plain(mapping.parseEcuMapCsv("Name,Diag Address\nBCM,0x2222")), { "0x2222": "BCM" });
  assert.deepEqual(plain(mapping.parseEcuMapCsv("Unit,0x1001")), { "0x1001": "Unit" });
  assert.throws(() => mapping.parseEcuMapCsv("name,address\nGateway,zzzz"), /No logical-address mappings/);
  assert.throws(() => mapping.parseEcuMapCsv("name,address\nGateway,0x123456"), /No logical-address mappings/);

  assert.equal(mapping.didName(0xf190, userMappings), "VIN");
  assert.equal(mapping.routineName(0x0203, userMappings), "Erase memory");
  assert.equal(mapping.ecuName("0x1001", userMappings, imported), "Imported Gateway");
  assert.equal(mapping.ecuName("0x0e80", {}, { "0xe80": "Tester" }), "Tester");
  assert.equal(mapping.ecuName("0x03e9", {}, { "0x1001": "Decimal listed ECU" }), "Decimal listed ECU");
  assert.equal(mapping.ecuName("0x0716", userMappings, {}), "Compact static");
  assert.equal(mapping.ecuLabel("0x1001", { withAddress: true }, userMappings, imported), "Imported Gateway (0x1001)");
  assert.equal(mapping.ecuLabel("0x9999", {}, userMappings, imported), "0x9999");
  assert.equal(mapping.ecuCode("0x1001", {}, { ecus: { "0x1001": "<Gateway>" } }, {}), '<code title="0x1001">&lt;Gateway&gt;</code>');
}

function tcpPacket(overrides) {
  const srcIp = overrides.srcIp || "10.0.0.1";
  const dstIp = overrides.dstIp || "10.0.0.2";
  const srcPort = overrides.srcPort ?? 1000;
  const dstPort = overrides.dstPort ?? 13400;
  const src = `${srcIp}:${srcPort}`;
  const dst = `${dstIp}:${dstPort}`;
  const flowKey = [src, dst].sort().join(" <-> ");
  const payloadLength = overrides.payloadLength || 0;
  return {
    packet: overrides.packet,
    timestamp: overrides.timestamp,
    srcIp,
    srcPort,
    dstIp,
    dstPort,
    seq: overrides.seq ?? 0,
    ackNumber: overrides.ackNumber ?? 0,
    flags: { syn: false, ack: false, fin: false, rst: false, ...overrides.flags },
    windowSize: overrides.windowSize ?? 8192,
    windowScale: overrides.windowScale ?? null,
    payloadLength,
    hasPayload: payloadLength > 0,
    endSeq: (overrides.seq ?? 0) + payloadLength + (overrides.flags?.syn ? 1 : 0) + (overrides.flags?.fin ? 1 : 0),
    flowKey,
    directionKey: `${src} -> ${dst}`
  };
}

function assertTcpAnalysisContracts() {
  const tcp = loadTcpAnalysis();
  const packets = [
    tcpPacket({ packet: 1, timestamp: 0, seq: 100, flags: { syn: true }, windowScale: 0 }),
    tcpPacket({ packet: 2, timestamp: 0.01, srcIp: "10.0.0.2", srcPort: 13400, dstIp: "10.0.0.1", dstPort: 1000, seq: 500, ackNumber: 101, flags: { syn: true, ack: true }, windowScale: 0 }),
    tcpPacket({ packet: 3, timestamp: 0.02, seq: 101, ackNumber: 501, flags: { ack: true } }),
    tcpPacket({ packet: 4, timestamp: 0.03, seq: 101, ackNumber: 501, flags: { ack: true }, payloadLength: 10 }),
    tcpPacket({ packet: 5, timestamp: 0.04, seq: 101, ackNumber: 501, flags: { ack: true }, payloadLength: 10 }),
    tcpPacket({ packet: 6, timestamp: 0.09, srcIp: "10.0.0.2", srcPort: 13400, dstIp: "10.0.0.1", dstPort: 1000, seq: 501, ackNumber: 111, flags: { ack: true } }),
    tcpPacket({ packet: 7, timestamp: 0.095, seq: 111, ackNumber: 501, flags: { ack: true }, payloadLength: 10 }),
    tcpPacket({ packet: 8, timestamp: 0.10, srcIp: "10.0.0.2", srcPort: 13400, dstIp: "10.0.0.1", dstPort: 1000, seq: 501, ackNumber: 111, flags: { ack: true } }),
    tcpPacket({ packet: 9, timestamp: 0.11, srcIp: "10.0.0.2", srcPort: 13400, dstIp: "10.0.0.1", dstPort: 1000, seq: 501, ackNumber: 111, flags: { ack: true }, windowSize: 0 }),
    tcpPacket({ packet: 10, timestamp: 0.12, srcIp: "10.0.0.2", srcPort: 13400, dstIp: "10.0.0.1", dstPort: 1000, seq: 501, ackNumber: 111, flags: { ack: true }, windowSize: 8192 })
  ];
  const { analysis, traceEvents } = tcp.analyzeTcpTransport(packets, { gaps: [{ flowKey: "known-gap" }] });
  const eventTypes = analysis.events.map((event) => event.type);

  assert.equal(tcp.percentile([1, 3, 2], 50), 2);
  assert.deepEqual(plain(tcp.downsampleSamples([0, 1, 2, 3], 2)), [0, 2]);
  assert.equal(analysis.flows.length, 1);
  assert.equal(analysis.retransmissions, 1);
  assert.equal(analysis.duplicateAcks, 2);
  assert.equal(analysis.zeroWindows, 1);
  assert.equal(analysis.windowUpdates, 1);
  assert.equal(analysis.ackTimings.length, 1);
  assert.equal(Number(analysis.flows[0].handshakeDuration.toFixed(2)), 0.02);
  assert.equal(analysis.flows[0].flowControl.status.label, "Zero window");
  assert.deepEqual(analysis.gaps, [{ flowKey: "known-gap" }]);
  assert.ok(eventTypes.includes("Handshake"));
  assert.ok(eventTypes.includes("Retransmission"));
  assert.ok(eventTypes.includes("Slow ACK"));
  assert.ok(eventTypes.includes("Duplicate ACK"));
  assert.ok(eventTypes.includes("Zero window"));
  assert.ok(eventTypes.includes("Window update"));
  assert.ok(traceEvents.every((event) => event.category === "transport"));

  const resetOnly = tcp.analyzeTcpTransport([
    tcpPacket({ packet: 20, timestamp: 1, seq: 1, flags: { syn: true }, windowSize: 8192 }),
    tcpPacket({ packet: 21, timestamp: 1.01, srcIp: "10.0.0.2", srcPort: 13400, dstIp: "10.0.0.1", dstPort: 1000, seq: 1, ackNumber: 2, flags: { rst: true, ack: true }, windowSize: 0 })
  ]);
  assert.equal(resetOnly.analysis.zeroWindows, 0);
  assert.equal(resetOnly.analysis.windowUpdates, 0);
  assert.equal(resetOnly.analysis.flows[0].zeroWindows, 0);
  assert.equal(resetOnly.analysis.flows[0].flowControl.status.label, "OK");
  assert.ok(resetOnly.analysis.events.some((event) => event.type === "RST"));
  assert.equal(resetOnly.analysis.events.some((event) => event.type === "Zero window"), false);
}

function assertTcpDoipReassemblyContracts() {
  const reassembly = loadTcpDoipReassembly();
  const completeDoip = new Uint8Array([0x02, 0xfd, 0x80, 0x01, 0, 0, 0, 1, 0xaa]);
  const partialDoip = new Uint8Array([0x02, 0xfd, 0x80, 0x01, 0, 0, 0, 4, 0xaa]);
  const duplicateSeq = [
    { seq: 2, packet: 3, bytes: new Uint8Array([3]) },
    { seq: 1, packet: 2, bytes: new Uint8Array([2]) },
    { seq: 1, packet: 1, bytes: completeDoip }
  ];
  const tcpSegments = new Map();
  const report = { warnings: [], tcpAnalysis: { gaps: [] } };
  const chunks = [];
  const view = new DataView(new Uint8Array([10, 11, 12, 13]).buffer);

  assert.equal(reassembly.tcpConnectionKey("b", 2, "a", 1), "a:1 <-> b:2");
  assert.ok(reassembly.doipPayloadScore(completeDoip) > reassembly.doipPayloadScore(partialDoip));
  assert.deepEqual(plain(reassembly.coalesceTcpSegments(duplicateSeq).map((segment) => segment.packet)), [1, 3]);

  reassembly.collectTcpSegment(tcpSegments, "10.0.0.1", 50000, "10.0.0.2", 13400, 1, 100, view, 0, 2, 1, 1, "aa:aa:aa:aa:aa:aa");
  reassembly.collectTcpSegment(tcpSegments, "10.0.0.1", 50000, "10.0.0.2", 13400, 1, 101, view, 1, 3, 2, 2, "aa:aa:aa:aa:aa:aa");
  reassembly.collectTcpSegment(tcpSegments, "10.0.0.1", 50000, "10.0.0.2", 13400, 1, 105, view, 3, 4, 3, 3, "aa:aa:aa:aa:aa:aa");
  reassembly.parseTcpDoipSegments(tcpSegments, report, new Set(), {
    tcpFlowKey: (srcIp, srcPort, dstIp, dstPort) => `${srcIp}:${srcPort}>${dstIp}:${dstPort}`,
    parseDoipBytes: (bytes, metaForOffset, transport, srcIp, srcPort, dstIp, dstPort) => {
      chunks.push({
        bytes: Array.from(bytes),
        firstPacket: metaForOffset(0).packet,
        firstSrcMac: metaForOffset(0).srcMac,
        transport,
        srcIp,
        srcPort,
        dstIp,
        dstPort
      });
    }
  });

  assert.deepEqual(plain(chunks), [
    { bytes: [10, 11, 12], firstPacket: 1, firstSrcMac: "aa:aa:aa:aa:aa:aa", transport: "TCP", srcIp: "10.0.0.1", srcPort: 50000, dstIp: "10.0.0.2", dstPort: 13400 },
    { bytes: [13], firstPacket: 3, firstSrcMac: "aa:aa:aa:aa:aa:aa", transport: "TCP", srcIp: "10.0.0.1", srcPort: 50000, dstIp: "10.0.0.2", dstPort: 13400 }
  ]);
  assert.equal(report.warnings.length, 1);
  assert.deepEqual(plain(report.tcpAnalysis.gaps[0]), {
    flowKey: "10.0.0.1:50000>10.0.0.2:13400",
    timestamp: 3,
    packet: 3,
    expectedSeq: 103,
    actualSeq: 105,
    gap: 2
  });
}

function assertPcapParserContracts() {
  const parser = loadPcapParser();
  const report = {
    doip: { payloadTypes: {}, announcements: [], logicalAddresses: {}, samples: [] },
    diagnostics: { ackNak: [] },
    traceEvents: []
  };
  const vin = Array.from(Buffer.from("WVWZZZ1JZXW000001", "ascii"));
  const payload = new Uint8Array([
    ...vin,
    0x10, 0x01,
    1, 2, 3, 4, 5, 6,
    7, 8, 9, 10, 11, 12,
    0
  ]);
  const bytes = new Uint8Array([0x02, 0xfd, 0x00, 0x04, 0, 0, 0, payload.length, ...payload]);
  const announcementKeys = new Set();

  assert.throws(() => parser.parsePcap(new ArrayBuffer(4), "tiny.pcap"), /too small/);
  assert.equal(parser.parseDoipBytes(bytes, () => ({ packet: 1, timestamp: 2, srcMac: "aa:bb:cc:dd:ee:ff" }), "UDP", "10.0.0.1", 13400, "10.0.0.2", 50000, report, announcementKeys), 1);
  assert.equal(report.doip.samples[0].payloadName, "Vehicle announcement / identification response");
  assert.equal(report.doip.samples[0].srcMac, "aa:bb:cc:dd:ee:ff");
  assert.equal(report.doip.announcements[0].logicalAddress, "0x1001");
  assert.deepEqual(plain(report.doip.logicalAddresses["0x1001"].ips), ["10.0.0.1"]);
  assert.deepEqual(plain(report.doip.logicalAddresses["0x1001"].sourceMacs), ["aa:bb:cc:dd:ee:ff"]);
  assert.equal(report.traceEvents[0].category, "doip");

  assert.equal(parser.parseDoipBytes(bytes, () => ({ packet: 2, timestamp: 3, srcMac: "bb:cc:dd:ee:ff:00" }), "UDP", "10.0.0.1", 13400, "10.0.0.2", 50000, report, announcementKeys), 1);
  assert.equal(report.doip.announcements.length, 2);
  assert.deepEqual(plain(report.doip.logicalAddresses["0x1001"].sourceMacs), ["aa:bb:cc:dd:ee:ff", "bb:cc:dd:ee:ff:00"]);

  const previousDiagnostic = [0x0e, 0x00, 0x22, 0x22, 0x22, 0xf1, 0x90];
  const nackPayload = new Uint8Array([
    0x10, 0x01,
    0x0e, 0x00,
    0x03,
    ...previousDiagnostic
  ]);
  const nackBytes = new Uint8Array([0x02, 0xfd, 0x80, 0x03, 0, 0, 0, nackPayload.length, ...nackPayload]);
  assert.equal(parser.parseDoipBytes(nackBytes, () => ({ packet: 3, timestamp: 4, srcMac: "bb:bb:bb:bb:bb:bb" }), "TCP", "10.0.0.20", 13400, "10.0.0.10", 50000, report, announcementKeys), 1);
  assert.equal(parser.diagnosticAckCodeName("0x8003", 0x03), "Unknown target address");
  assert.equal(parser.diagnosticAckCodeName("0x8003", 0x05), "Out of memory");
  assert.deepEqual(plain(report.diagnostics.ackNak[0]), {
    packet: 3,
    timestamp: 4,
    type: "0x8003",
    typeName: "Diagnostic message negative acknowledgement",
    srcIp: "10.0.0.20",
    srcMac: "bb:bb:bb:bb:bb:bb",
    srcPort: 13400,
    dstIp: "10.0.0.10",
    dstPort: 50000,
    source: "0x1001",
    target: "0x0e00",
    ackCode: "0x03",
    ackCodeName: "Unknown target address",
    previousSource: "0x0e00",
    previousTarget: "0x2222",
    previousMessageHex: "0e 00 22 22 22 f1 90"
  });

  const memoryNackPayload = new Uint8Array([
    0x10, 0x01,
    0x0e, 0x00,
    0x05,
    ...previousDiagnostic
  ]);
  const memoryNackBytes = new Uint8Array([0x02, 0xfd, 0x80, 0x03, 0, 0, 0, memoryNackPayload.length, ...memoryNackPayload]);
  assert.equal(parser.parseDoipBytes(memoryNackBytes, () => ({ packet: 33, timestamp: 4.5, srcMac: "bb:bb:bb:bb:bb:bb" }), "TCP", "10.0.0.20", 13400, "10.0.0.10", 50000, report, announcementKeys), 1);
  assert.deepEqual(plain(report.diagnostics.ackNak[1]), {
    packet: 33,
    timestamp: 4.5,
    type: "0x8003",
    typeName: "Diagnostic message negative acknowledgement",
    srcIp: "10.0.0.20",
    srcMac: "bb:bb:bb:bb:bb:bb",
    srcPort: 13400,
    dstIp: "10.0.0.10",
    dstPort: 50000,
    source: "0x1001",
    target: "0x0e00",
    ackCode: "0x05",
    ackCodeName: "Out of memory",
    previousSource: "0x0e00",
    previousTarget: "0x2222",
    previousMessageHex: "0e 00 22 22 22 f1 90"
  });
  assert.equal(report.doip.samples.find((sample) => sample.packet === 33).ackCodeName, "Out of memory");

  const routingResponsePayload = new Uint8Array([0x0e, 0x00, 0x14, 0xb4, 0x10]);
  const routingResponseBytes = new Uint8Array([0x02, 0xfd, 0x00, 0x06, 0, 0, 0, routingResponsePayload.length, ...routingResponsePayload]);
  assert.equal(parser.parseDoipBytes(routingResponseBytes, () => ({ packet: 40676, timestamp: 40.676, srcMac: "cc:cc:cc:cc:cc:cc" }), "TCP", "10.0.0.30", 13400, "10.0.0.10", 50000, report, announcementKeys), 1);
  const routingSample = report.doip.samples.find((sample) => sample.packet === 40676);
  const routingTrace = report.traceEvents.find((event) => event.packet === 40676);
  assert.equal(routingSample.logicalAddress, "0x0e00");
  assert.equal(routingSample.routingActivationTesterAddress, "0x0e00");
  assert.equal(routingSample.routingActivationEntityAddress, "0x14b4");
  assert.equal(routingSample.routingActivationResponseCode, "0x10");
  assert.equal(routingSample.routingActivationResponseCodeName, "Routing successfully activated");
  assert.equal(routingTrace.routingActivationTesterAddress, "0x0e00");
  assert.equal(routingTrace.routingActivationEntityAddress, "0x14b4");
  assert.equal(routingTrace.routingActivationResponseCodeName, "Routing successfully activated");

  const genericNackBytes = new Uint8Array([0x02, 0xfd, 0x00, 0x00, 0, 0, 0, 1, 0x02]);
  assert.equal(parser.parseDoipBytes(genericNackBytes, () => ({ packet: 50, timestamp: 5, srcMac: "dd:dd:dd:dd:dd:dd" }), "TCP", "10.0.0.20", 13400, "10.0.0.10", 50000, report, announcementKeys), 1);
  assert.equal(parser.genericNackCodeName(0x02), "Message too large");
  assert.deepEqual(plain(report.doip.genericNacks[0]), {
    packet: 50,
    timestamp: 5,
    transport: "TCP",
    srcIp: "10.0.0.20",
    srcMac: "dd:dd:dd:dd:dd:dd",
    srcPort: 13400,
    dstIp: "10.0.0.10",
    dstPort: 50000,
    payloadType: "0x0000",
    payloadName: "Generic DoIP header negative acknowledgement",
    nackCode: "0x02",
    nackCodeName: "Message too large",
    payloadLength: 1
  });
  assert.equal(report.doip.samples.find((sample) => sample.packet === 50).nackCodeName, "Message too large");
  assert.equal(report.traceEvents.find((event) => event.packet === 50).nackCodeName, "Message too large");
}

function diagnosticEvent(overrides) {
  return {
    id: overrides.id,
    packet: overrides.packet ?? overrides.id,
    timestamp: overrides.timestamp ?? overrides.id / 100,
    ecuAddress: overrides.ecuAddress || "0x1001",
    testerAddress: overrides.testerAddress || "0x0e00",
    source: overrides.source || (overrides.direction === "response" ? "0x1001" : "0x0e00"),
    target: overrides.target || (overrides.direction === "response" ? "0x0e00" : "0x1001"),
    direction: overrides.direction,
    responseKind: overrides.responseKind || (overrides.direction === "response" ? "positive" : "request"),
    service: overrides.service,
    serviceName: overrides.serviceName || "",
    originalService: overrides.originalService || null,
    nrc: overrides.nrc || null,
    nrcName: overrides.nrcName || "",
    did: overrides.did || null,
    didName: overrides.didName || "",
    routineId: overrides.routineId || null,
    transfer: overrides.transfer || null,
    raw: overrides.raw || "",
    valueHex: overrides.valueHex || "",
    valueAscii: overrides.valueAscii || "",
    paired: false
  };
}

function diagnosticReport(events) {
  return {
    diagnostics: {
      udsEvents: events,
      unmatchedMessages: [],
      didReads: [],
      dtcReads: [],
      transfers: []
    }
  };
}

function assertDiagnosticAnalysisContracts() {
  const diagnostics = loadDiagnosticAnalysis();
  assert.equal(diagnostics.isFunctionalLogicalAddress("0xe000"), true);
  assert.equal(diagnostics.isFunctionalLogicalAddress("0x1001"), false);

  const report = diagnosticReport([
    diagnosticEvent({ id: 1, service: "0x22", serviceName: "Read Data By Identifier", direction: "request", did: "0xf190", didName: "VIN", raw: "22 f1 90" }),
    diagnosticEvent({ id: 2, service: "0x62", serviceName: "Read Data By Identifier Response", direction: "response", did: "0xf190", didName: "VIN", originalService: "0x22", raw: "62 f1 90 41", valueHex: "41", valueAscii: "A" }),
    diagnosticEvent({ id: 3, service: "0x59", serviceName: "Read DTC Information Response", direction: "response", raw: "59 02 ff 01 02 03 09" }),
    diagnosticEvent({ id: 4, service: "0x34", serviceName: "Request Download", direction: "request", transfer: { memorySize: 4 }, raw: "34 00 11 00 04" }),
    diagnosticEvent({ id: 5, service: "0x74", serviceName: "Request Download Response", direction: "response", transfer: { maxBlockLength: 6 }, raw: "74 10 06" }),
    diagnosticEvent({ id: 6, service: "0x36", serviceName: "Transfer Data", direction: "request", transfer: { blockCounter: 1 }, raw: "36 01 aa bb" }),
    diagnosticEvent({ id: 7, service: "0x76", serviceName: "Transfer Data Response", direction: "response", originalService: "0x36", transfer: { blockCounter: 1 }, raw: "76 01" }),
    diagnosticEvent({ id: 8, service: "0x37", serviceName: "Request Transfer Exit", direction: "request", raw: "37" }),
    diagnosticEvent({ id: 9, service: "0x77", serviceName: "Request Transfer Exit Response", direction: "response", originalService: "0x37", raw: "77" })
  ]);

  diagnostics.pairUdsEvents(report);
  diagnostics.buildDidReads(report);
  diagnostics.buildDtcReads(report);
  diagnostics.buildTransfers(report);

  assert.equal(report.diagnostics.udsEvents[0].responseEventId, 2);
  assert.equal(report.diagnostics.udsEvents[1].requestEventId, 1);
  assert.equal(report.diagnostics.didReads.length, 1);
  assert.deepEqual(plain(report.diagnostics.didReads[0]), {
    ecuAddress: "0x1001",
    did: "0xf190",
    name: "VIN",
    reads: 1,
    responses: 1,
    negatives: 0,
    pending: 0,
    latestValueHex: "41",
    latestValueAscii: "A",
    firstTimestamp: 0.01,
    lastTimestamp: 0.02
  });
  assert.equal(report.diagnostics.dtcReads.summary[0].dtc, "010203");
  assert.equal(report.diagnostics.dtcReads.summary[0].statusLabels, "testFailed, confirmedDTC");
  const clearReport = diagnosticReport([
    diagnosticEvent({ id: 1, service: "0x14", serviceName: "Clear Diagnostic Information", direction: "request", responseKind: "request", raw: "14 ff ff ff", timestamp: 1, packet: 10 }),
    diagnosticEvent({ id: 2, service: "0x59", serviceName: "Read DTC Information Response", direction: "response", responseKind: "positive", raw: "59 02 ff 01 02 03 09", timestamp: 2, packet: 20 })
  ]);
  diagnostics.buildDtcReads(clearReport);
  assert.equal(clearReport.diagnostics.dtcReads.clearCommands.length, 1);
  assert.equal(clearReport.diagnostics.dtcReads.summary[0].persistentAfterClear, true);
  assert.equal(clearReport.diagnostics.dtcReads.summary[0].clearGroup, "FFFFFF");
  assert.equal(report.diagnostics.transfers.length, 1);
  assert.equal(report.diagnostics.transfers[0].status, "completed");
  assert.equal(report.diagnostics.transfers[0].blocks, 1);
  assert.equal(report.diagnostics.transfers[0].acknowledgedBlocks, 1);
  assert.equal(report.diagnostics.transfers[0].reconstructedBytes, 2);
  assert.equal(report.diagnostics.transfers[0].dataHex, "aa bb");

  const shortfallReport = diagnosticReport([
    diagnosticEvent({ id: 20, service: "0x34", direction: "request", transfer: { memorySize: 10 }, raw: "34" }),
    diagnosticEvent({ id: 21, service: "0x74", direction: "response", transfer: { maxBlockLength: 6 }, raw: "74 10 06" }),
    diagnosticEvent({ id: 22, service: "0x36", direction: "request", transfer: { blockCounter: 1 }, raw: "36 01 aa bb" }),
    diagnosticEvent({ id: 23, service: "0x37", direction: "request", raw: "37" }),
    diagnosticEvent({ id: 24, service: "0x77", direction: "response", originalService: "0x37", raw: "77" })
  ]);
  diagnostics.buildTransfers(shortfallReport);
  assert.equal(shortfallReport.diagnostics.transfers[0].status, "completed");
  assert.deepEqual(plain(shortfallReport.diagnostics.transfers[0].missingSequences), []);
  assert.deepEqual(plain(shortfallReport.diagnostics.transfers[0].expectedBlockShortfall), { expected: 3, observed: 1 });

  const retryReport = diagnosticReport([
    diagnosticEvent({ id: 30, service: "0x34", direction: "request", transfer: { memorySize: 6 }, raw: "34" }),
    diagnosticEvent({ id: 31, service: "0x36", direction: "request", transfer: { blockCounter: 1 }, raw: "36 01 aa" }),
    diagnosticEvent({ id: 32, service: "0x36", direction: "request", transfer: { blockCounter: 2 }, raw: "36 02 bb" }),
    diagnosticEvent({ id: 33, service: "0x36", direction: "request", transfer: { blockCounter: 2 }, raw: "36 02 cc" })
  ]);
  diagnostics.buildTransfers(retryReport);
  assert.deepEqual(plain(retryReport.diagnostics.transfers[0].missingSequences), []);
  assert.ok(retryReport.diagnostics.transfers[0].captureNotes[0].includes("non-forward"));

  const gapReport = diagnosticReport([
    diagnosticEvent({ id: 40, service: "0x34", direction: "request", transfer: { memorySize: 6 }, raw: "34" }),
    diagnosticEvent({ id: 41, service: "0x36", direction: "request", transfer: { blockCounter: 1 }, raw: "36 01 aa" }),
    diagnosticEvent({ id: 42, service: "0x36", direction: "request", transfer: { blockCounter: 3 }, raw: "36 03 cc" })
  ]);
  diagnostics.buildTransfers(gapReport);
  assert.deepEqual(plain(gapReport.diagnostics.transfers[0].missingSequences), ["0x02->0x03"]);

  const duplicateObservationReport = diagnosticReport([
    diagnosticEvent({ id: 45, service: "0x34", direction: "request", transfer: { memorySize: 2 }, raw: "34" }),
    diagnosticEvent({ id: 46, service: "0x36", direction: "request", transfer: { blockCounter: 1 }, raw: "36 01 ff" }),
    diagnosticEvent({ id: 47, service: "0x36", direction: "request", transfer: { blockCounter: 1 }, raw: "36 01 ff" })
  ]);
  diagnostics.buildTransfers(duplicateObservationReport);
  assert.equal(duplicateObservationReport.diagnostics.transfers[0].blocks, 1);
  assert.equal(duplicateObservationReport.diagnostics.transfers[0].suppressedDuplicateMessages, 1);

  const wrappedPaddingEvents = [
    diagnosticEvent({ id: 60, service: "0x34", direction: "request", transfer: { memorySize: 257 }, raw: "34" })
  ];
  for (let index = 0; index < 257; index += 1) {
    const counter = (index + 1) & 0xff;
    wrappedPaddingEvents.push(diagnosticEvent({
      id: 61 + index,
      service: "0x36",
      direction: "request",
      transfer: { blockCounter: counter },
      raw: `36 ${counter.toString(16).padStart(2, "0")} ff`
    }));
  }
  const wrappedPaddingReport = diagnosticReport(wrappedPaddingEvents);
  diagnostics.buildTransfers(wrappedPaddingReport);
  assert.equal(wrappedPaddingReport.diagnostics.transfers[0].blocks, 257);
  assert.equal(wrappedPaddingReport.diagnostics.transfers[0].reconstructedBytes, 257);
  assert.equal(wrappedPaddingReport.diagnostics.transfers[0].suppressedDuplicateMessages, 0);
  assert.deepEqual(plain(wrappedPaddingReport.diagnostics.transfers[0].missingSequences), []);

  const parallelReport = diagnosticReport([
    diagnosticEvent({ id: 50, service: "0x34", direction: "request", testerAddress: "0x0e00", transfer: { memorySize: 2 }, raw: "34" }),
    diagnosticEvent({ id: 51, service: "0x34", direction: "request", testerAddress: "0x0e01", transfer: { memorySize: 2 }, raw: "34" }),
    diagnosticEvent({ id: 52, service: "0x36", direction: "request", testerAddress: "0x0e00", transfer: { blockCounter: 1 }, raw: "36 01 aa" }),
    diagnosticEvent({ id: 53, service: "0x36", direction: "request", testerAddress: "0x0e01", transfer: { blockCounter: 1 }, raw: "36 01 bb" })
  ]);
  diagnostics.buildTransfers(parallelReport);
  assert.equal(parallelReport.diagnostics.transfers.length, 2);
  assert.deepEqual(plain(parallelReport.diagnostics.transfers.map((item) => item.blocks)), [1, 1]);
  assert.equal(diagnostics.transferKey({ ecuAddress: "0x1001", testerAddress: "0x0e00" }), "0x1001|0x0e00");
  assert.equal(diagnostics.isForwardCounterGap(3, 2), false);
  assert.equal(diagnostics.isForwardCounterGap(2, 3), true);
}

function assertIdentityAnalysisContracts() {
  const identity = loadIdentityAnalysis();

  assert.equal(identity.isAutoIpAddress("169.254.12.34"), true);
  assert.equal(identity.isAutoIpAddress("10.0.0.1"), false);

  const report = {
    hosts: {
      tester: { mac: "aa:aa:aa:aa:aa:aa", ips: ["10.0.0.10", "10.0.0.11"], packets: 8, bytes: 800 },
      ecuPrimary: { mac: "bb:bb:bb:bb:bb:bb", ips: ["10.0.0.20"], packets: 6, bytes: 600 },
      ecuAlias: { mac: "cc:cc:cc:cc:cc:cc", ips: ["10.0.0.20"], packets: 4, bytes: 400 }
    },
    dhcp: {
      clients: {
        "aa:aa:aa:aa:aa:aa": { mac: "aa:aa:aa:aa:aa:aa", messages: { Discover: 1, Request: 1 }, ips: ["10.0.0.10"] }
      },
      servers: {}
    },
    arp: {
      samples: [
        { senderIp: "10.0.0.20", senderMac: "bb:bb:bb:bb:bb:bb" },
        { senderIp: "10.0.0.20", senderMac: "cc:cc:cc:cc:cc:cc" },
        { senderIp: "10.0.0.20", senderMac: "dd:dd:dd:dd:dd:dd" }
      ]
    },
    doip: {
      logicalAddresses: {
        "0x1001": {
          eids: ["11:22:33:44:55:66"],
          sourceMacs: ["bb:bb:bb:bb:bb:bb"],
          ips: ["10.0.0.20", "10.0.0.21"]
        }
      },
      announcements: [
        { eid: "11:22:33:44:55:66", srcMac: "bb:bb:bb:bb:bb:bb", logicalAddress: "0x1001" }
      ]
    },
    diagnostics: {
      ecus: {
        "0x1001": { ips: ["10.0.0.20"] }
      },
      udsEvents: [
        {
          direction: "request",
          testerAddress: "0x0e00",
          ecuAddress: "0x1001",
          srcIp: "10.0.0.10",
          dstIp: "10.0.0.20"
        },
        {
          direction: "response",
          testerAddress: "0x0e00",
          ecuAddress: "0x1001",
          srcIp: "10.0.0.20",
          dstIp: "10.0.0.10"
        }
      ]
    }
  };
  const analysis = identity.buildIdentityAnalysis(report);
  const titles = analysis.findings.map((finding) => finding.title);

  assert.equal(analysis.metrics.hosts, 3);
  assert.equal(analysis.metrics.high, 3);
  assert.equal(analysis.metrics.medium, 3);
  assert.ok(titles.some((title) => title.includes("used multiple IP addresses")));
  assert.ok(titles.some((title) => title.includes("appeared behind multiple MAC addresses")));
  assert.ok(titles.some((title) => title.includes("ARP conflict candidate")));
  assert.ok(titles.some((title) => title.includes("resolved to multiple Ethernet MAC identities")));
  assert.ok(titles.some((title) => title.includes("appeared on multiple IP addresses")));
  assert.ok(analysis.findings.some((finding) => finding.title.includes("ARP conflict candidate") && finding.evidence.includes("dd:dd:dd:dd:dd:dd")));

  const rejectedGatewayReport = {
    hosts: {
      gateway: { mac: "bb:bb:bb:bb:bb:bb", ips: ["10.0.0.20"], packets: 8, bytes: 800 },
      ethernetNode: { mac: "cc:cc:cc:cc:cc:cc", ips: ["10.0.0.21"], packets: 6, bytes: 600 },
      tester: { mac: "aa:aa:aa:aa:aa:aa", ips: ["10.0.0.10"], packets: 4, bytes: 400 }
    },
    dhcp: { clients: {}, servers: {} },
    arp: { samples: [] },
    doip: {
      logicalAddresses: {
        "0x2222": { sourceMacs: ["cc:cc:cc:cc:cc:cc"], eids: ["22:22:22:22:22:22"], ips: ["10.0.0.21"] }
      },
      announcements: [{ logicalAddress: "0x2222", srcMac: "cc:cc:cc:cc:cc:cc" }]
    },
    diagnostics: {
      ecus: { "0x2222": { ips: ["10.0.0.20"] } },
      udsEvents: [{ direction: "request", testerAddress: "0x0e00", ecuAddress: "0x2222", srcIp: "10.0.0.10", dstIp: "10.0.0.20" }],
      ackNak: [{ type: "0x8003", ackCode: "0x03", srcMac: "bb:bb:bb:bb:bb:bb", srcIp: "10.0.0.20", previousTarget: "0x2222" }]
    }
  };
  const rejectedGateway = identity.buildIdentityAnalysis(rejectedGatewayReport);
  assert.deepEqual(plain(Array.from(identity.nackRejectedGatewayMacsByLogical(rejectedGatewayReport).get("0x2222"))), ["bb:bb:bb:bb:bb:bb"]);
  assert.equal(rejectedGateway.findings.some((finding) => finding.title.includes("resolved to multiple Ethernet MAC identities")), false);

  const rejectedGatewayWithoutPreviousTarget = {
    ...rejectedGatewayReport,
    diagnostics: {
      ...rejectedGatewayReport.diagnostics,
      udsEvents: [{ direction: "request", testerAddress: "0x0e00", ecuAddress: "0x2222", srcIp: "10.0.0.10", dstIp: "10.0.0.20", packet: 10, timestamp: 10 }],
      ackNak: [{ type: "0x8003", ackCode: "0x03", srcMac: "bb:bb:bb:bb:bb:bb", srcIp: "10.0.0.20", target: "0x0e00", previousTarget: "", packet: 11, timestamp: 11 }]
    }
  };
  const rejectedGatewayWithoutPreviousTargetAnalysis = identity.buildIdentityAnalysis(rejectedGatewayWithoutPreviousTarget);
  assert.equal(identity.rejectedDiagnosticTarget(rejectedGatewayWithoutPreviousTarget, rejectedGatewayWithoutPreviousTarget.diagnostics.ackNak[0]), "0x2222");
  assert.deepEqual(plain(Array.from(identity.nackRejectedGatewayMacsByLogical(rejectedGatewayWithoutPreviousTarget).get("0x2222"))), ["bb:bb:bb:bb:bb:bb"]);
  assert.equal(identity.nackRejectedGatewayMacsByLogical(rejectedGatewayWithoutPreviousTarget).has("0x0e00"), false);
  assert.equal(rejectedGatewayWithoutPreviousTargetAnalysis.findings.some((finding) => finding.title.includes("resolved to multiple Ethernet MAC identities")), false);

  const nonRejectedGateway = identity.buildIdentityAnalysis({
    ...rejectedGatewayReport,
    diagnostics: {
      ...rejectedGatewayReport.diagnostics,
      ackNak: [{ type: "0x8003", ackCode: "0x04", srcMac: "bb:bb:bb:bb:bb:bb", srcIp: "10.0.0.20", previousTarget: "0x2222" }]
    }
  });
  assert.equal(nonRejectedGateway.findings.some((finding) => finding.title.includes("resolved to multiple Ethernet MAC identities")), true);

  const acceptedGatewayReport = {
    ...rejectedGatewayReport,
    diagnostics: {
      ...rejectedGatewayReport.diagnostics,
      udsEvents: [
        ...rejectedGatewayReport.diagnostics.udsEvents,
        { direction: "response", testerAddress: "0x0e00", ecuAddress: "0x2222", srcIp: "10.0.0.20", dstIp: "10.0.0.10" }
      ]
    }
  };
  const acceptedGateway = identity.buildIdentityAnalysis(acceptedGatewayReport);
  assert.equal(identity.hasAcceptedDiagnosticEvidence(rejectedGatewayReport, "0x2222", "10.0.0.20", "bb:bb:bb:bb:bb:bb"), false);
  assert.equal(identity.hasAcceptedDiagnosticEvidence(acceptedGatewayReport, "0x2222", "10.0.0.20", "bb:bb:bb:bb:bb:bb"), true);
  assert.equal(acceptedGateway.findings.some((finding) => finding.title.includes("resolved to multiple Ethernet MAC identities")), true);

  const benignReport = {
    hosts: {
      ecu: { mac: "dd:dd:dd:dd:dd:dd", ips: ["169.254.1.2", "10.0.0.30"] }
    },
    dhcp: {
      clients: {
        "dd:dd:dd:dd:dd:dd": { ips: ["10.0.0.30"] }
      },
      samples: [{ messageType: "Ack", clientMac: "dd:dd:dd:dd:dd:dd", yourIp: "10.0.0.30", packet: 2, timestamp: 2 }]
    },
    doip: {
      logicalAddresses: {
        "0x1001": { sourceMacs: ["dd:dd:dd:dd:dd:dd"], ips: ["169.254.1.2", "10.0.0.30"] }
      },
      announcements: [
        { logicalAddress: "0x1001", srcMac: "dd:dd:dd:dd:dd:dd", srcIp: "169.254.1.2", packet: 1, timestamp: 1 },
        { logicalAddress: "0x1001", srcMac: "dd:dd:dd:dd:dd:dd", srcIp: "10.0.0.30", packet: 3, timestamp: 3 }
      ]
    },
    diagnostics: {
      ecus: {
        "0x1001": { ips: ["169.254.1.2", "10.0.0.30"] }
      }
    }
  };
  assert.deepEqual(plain(identity.dhcpAckAssignments(benignReport)), [{ clientMac: "dd:dd:dd:dd:dd:dd", ip: "10.0.0.30", packet: 2, timestamp: 2, serverId: "" }]);
  assert.equal(
    identity.isBenignAutoIpDhcpLogicalAddress(benignReport, "0x1001", ["169.254.1.2", "10.0.0.30"]),
    true
  );
  assert.equal(
    identity.isBenignAutoIpDhcpLogicalAddress(benignReport, "0x1001", ["169.254.1.2", "10.0.0.31"]),
    false
  );
  assert.equal(identity.buildIdentityAnalysis(benignReport).findings.some((finding) => finding.title.includes("used multiple IP addresses")), false);

  const requestedOnlyReport = {
    ...benignReport,
    dhcp: {
      clients: benignReport.dhcp.clients,
      samples: [{ messageType: "Request", clientMac: "dd:dd:dd:dd:dd:dd", requestedIp: "10.0.0.30", yourIp: "0.0.0.0", packet: 2, timestamp: 2 }]
    }
  };
  assert.equal(identity.isBenignAutoIpDhcpLogicalAddress(requestedOnlyReport, "0x1001", ["169.254.1.2", "10.0.0.30"]), false);
}

function assertTopologyAnalysisContracts() {
  const topologyModule = loadTopologyAnalysis();
  const report = {
    hosts: {
      tester: { mac: "aa:aa:aa:aa:aa:aa", ips: ["10.0.0.10"], packets: 8, bytes: 800 },
      gateway: { mac: "bb:bb:bb:bb:bb:bb", ips: ["10.0.0.20"], packets: 6, bytes: 600 },
      dhcp: { mac: "dd:dd:dd:dd:dd:dd", ips: ["10.0.0.1"], packets: 3, bytes: 300 }
    },
    dhcp: {
      servers: { "10.0.0.1": { packets: 3 } },
      clients: {}
    },
    doip: {
      announcements: [
        {
          logicalAddress: "0x1001",
          srcIp: "10.0.0.20",
          srcMac: "bb:bb:bb:bb:bb:bb",
          eid: "11:22:33:44:55:66",
          gid: "00:11",
          vin: "VIN123",
          packet: 1,
          timestamp: 1
        }
      ]
    },
    diagnostics: {
      ecus: {
        "0x1001": { ips: ["10.0.0.20"], name: "Gateway ECU" },
        "0x2222": { ips: ["10.0.0.20"], name: "Body ECU" }
      },
      udsEvents: [
        {
          direction: "request",
          testerAddress: "0x0e00",
          ecuAddress: "0x1001",
          srcIp: "10.0.0.10",
          dstIp: "10.0.0.20",
          packet: 2,
          timestamp: 2,
          service: "0x22",
          serviceName: "Read Data By Identifier",
          source: "0x0e00",
          target: "0x1001"
        },
        {
          direction: "request",
          testerAddress: "0x0e00",
          ecuAddress: "0x2222",
          srcIp: "10.0.0.10",
          dstIp: "10.0.0.20",
          packet: 3,
          timestamp: 3,
          service: "0x22",
          serviceName: "Read Data By Identifier",
          source: "0x0e00",
          target: "0x2222"
        }
      ]
    },
    traceEvents: [
      {
        payloadType: "0x0005",
        logicalAddress: "0x0e00",
        srcIp: "10.0.0.10",
        dstIp: "10.0.0.20",
        packet: 4,
        timestamp: 4,
        payloadName: "Routing activation request"
      }
    ],
    identity: {
      findings: [
        {
          entityType: "Logical",
          entityId: "0x1001",
          title: "Logical address 0x1001 resolved to multiple Ethernet MAC identities",
          evidence: "multiple identities"
        }
      ]
    }
  };
  const topology = topologyModule.buildTopologyAnalysis(report, {
    ecuName: (address) => address === "0x1001" ? "Gateway ECU" : "",
    ecuLabel: (address) => {
      if (address === "0x1001") return "Gateway ECU";
      if (address === "0x2222") return "Body ECU (0x2222)";
      return address;
    }
  });
  const nodeIds = topology.nodes.map((node) => node.id);
  const edgeKinds = topology.edges.map((edge) => edge.kind);
  const gateway = topology.nodes.find((node) => node.id === "gateway:0x1001");
  const body = topology.nodes.find((node) => node.id === "ecu:0x2222");

  assert.equal(topologyModule.topologyRoleRank("tester") < topologyModule.topologyRoleRank("gateway"), true);
  assert.equal(topologyModule.topologyEdgeRank("routing") < topologyModule.topologyEdgeRank("ownership"), true);
  assert.ok(nodeIds.includes("tester:0x0e00"));
  assert.ok(nodeIds.includes("gateway:0x1001"));
  assert.ok(nodeIds.includes("ecu:0x2222"));
  assert.ok(nodeIds.includes("endpoint:dd:dd:dd:dd:dd:dd"));
  assert.equal(gateway.label, "0x1001");
  assert.equal(gateway.friendlyName, "Gateway ECU");
  assert.equal(gateway.ambiguous, true);
  assert.equal(body.label, "Body ECU (0x2222)");
  assert.equal(topology.summary.gateways, 1);
  assert.equal(topology.summary.logicalEcus, 1);
  assert.equal(topology.summary.testers, 1);
  assert.equal(topology.summary.endpoints, 2);
  assert.equal(topology.summary.inferredLinks, 1);
  assert.equal(topology.summary.ambiguousLinks, 1);
  assert.ok(edgeKinds.includes("announcement"));
  assert.ok(edgeKinds.includes("routing"));
  assert.ok(edgeKinds.includes("diagnostic"));
  assert.ok(edgeKinds.includes("inferred"));
  assert.ok(edgeKinds.includes("ownership"));
  assert.equal(topology.socketMap.summary.sockets, 1);
  assert.equal(topology.socketMap.summary.directLogicalAddresses, 1);
  assert.equal(topology.socketMap.summary.routedLogicalAddresses, 1);
  assert.equal(topology.socketMap.sockets[0].directLogicalAddress, "0x1001");
  assert.equal(topology.socketMap.sockets[0].routed[0].logicalAddress, "0x2222");

  const socketMapTopology = topologyModule.buildTopologyAnalysis({
    hosts: {},
    dhcp: { servers: {}, clients: {} },
    doip: {
      announcements: [
        { logicalAddress: "0x1001", srcIp: "10.0.0.20", srcMac: "bb:bb:bb:bb:bb:bb", eid: "11:22:33:44:55:66", vin: "GWVIN", packet: 1, timestamp: 1 },
        { logicalAddress: "0x2222", srcIp: "10.0.0.30", srcMac: "cc:cc:cc:cc:cc:cc", eid: "22:33:44:55:66:77", vin: "ETHVIN", packet: 4, timestamp: 4 }
      ]
    },
    diagnostics: {
      ecus: {
        "0x1001": { ips: ["10.0.0.20"], name: "Gateway" },
        "0x2222": { ips: ["10.0.0.30"], name: "Ethernet ECU" },
        "0x3333": { ips: ["10.0.0.30"], name: "Behind Ethernet ECU" }
      },
      udsEvents: [
        { direction: "request", testerAddress: "0x0e00", ecuAddress: "0x2222", srcIp: "10.0.0.10", dstIp: "10.0.0.20", packet: 2, timestamp: 2, service: "0x22", serviceName: "Read", source: "0x0e00", target: "0x2222" },
        { direction: "request", testerAddress: "0x0e00", ecuAddress: "0x2222", srcIp: "10.0.0.10", dstIp: "10.0.0.20", packet: 3, timestamp: 3, service: "0x22", serviceName: "Read", source: "0x0e00", target: "0x2222" },
        { direction: "request", testerAddress: "0x0e00", ecuAddress: "0x3333", srcIp: "10.0.0.10", dstIp: "10.0.0.30", packet: 5, timestamp: 5, service: "0x10", serviceName: "Session", source: "0x0e00", target: "0x3333" },
        { direction: "request", testerAddress: "0x0e00", ecuAddress: "0x5555", srcIp: "10.0.0.10", dstIp: "10.0.0.20", packet: 8, timestamp: 8, service: "0x22", serviceName: "Read", source: "0x0e00", target: "0x5555" }
      ],
      ackNak: [
        { type: "0x8003", ackCode: "0x03", ackCodeName: "Unknown target address", srcIp: "10.0.0.30", srcMac: "cc:cc:cc:cc:cc:cc", previousTarget: "0x4444", previousMessageHex: "0e 00 44 44 22 f1 90", packet: 6, timestamp: 6 },
        { type: "0x8003", ackCode: "0x03", ackCodeName: "Unknown target address", srcIp: "10.0.0.20", srcMac: "bb:bb:bb:bb:bb:bb", target: "0x0e00", previousTarget: "", packet: 9, timestamp: 9 }
      ]
    },
    traceEvents: [
      { payloadType: "0x0005", logicalAddress: "0x0e00", srcIp: "10.0.0.10", dstIp: "10.0.0.20", packet: 7, timestamp: 7, payloadName: "Routing activation request" },
      { payloadType: "0x0005", logicalAddress: "0x0e00", srcIp: "10.0.0.10", dstIp: "10.0.0.30", packet: 8, timestamp: 8, payloadName: "Routing activation request" }
    ]
  }, {
    ecuLabel: (address) => ({ "0x1001": "Central Gateway", "0x2222": "Ethernet ECU", "0x3333": "Behind Ethernet ECU", "0x4444": "Rejected ECU" }[address] || address)
  });
  const gatewaySocket = socketMapTopology.socketMap.sockets.find((socket) => socket.ip === "10.0.0.20");
  const ethernetSocket = socketMapTopology.socketMap.sockets.find((socket) => socket.ip === "10.0.0.30");
  assert.equal(socketMapTopology.socketMap.summary.sockets, 2);
  assert.equal(gatewaySocket.directLogicalAddress, "0x1001");
  assert.equal(gatewaySocket.routed.length, 1);
  assert.equal(gatewaySocket.routed[0].logicalAddress, "0x2222");
  assert.equal(gatewaySocket.routed[0].requests, 2);
  assert.deepEqual(plain(gatewaySocket.routed[0].packets), [2, 3]);
  assert.equal(gatewaySocket.rejected[0].logicalAddress, "0x5555");
  assert.equal(gatewaySocket.rejected.some((item) => item.logicalAddress === "0x0e00"), false);
  assert.equal(gatewaySocket.routed.some((item) => item.logicalAddress === "0x5555"), false);
  assert.equal(ethernetSocket.directLogicalAddress, "0x2222");
  assert.equal(ethernetSocket.routed[0].logicalAddress, "0x3333");
  assert.equal(ethernetSocket.rejected[0].logicalAddress, "0x4444");
  assert.equal(ethernetSocket.routed.some((item) => item.logicalAddress === "0x4444"), false);

  const responseOnlyRoutingTopology = topologyModule.buildTopologyAnalysis({
    hosts: {},
    dhcp: { servers: {}, clients: {} },
    doip: { announcements: [] },
    diagnostics: { ecus: {}, udsEvents: [], ackNak: [] },
    traceEvents: [
      {
        payloadType: "0x0006",
        logicalAddress: "0x0e00",
        routingActivationTesterAddress: "0x0e00",
        routingActivationEntityAddress: "0x14b4",
        srcIp: "10.0.0.44",
        dstIp: "10.0.0.10",
        packet: 40676,
        timestamp: 40.676,
        payloadName: "Routing activation response"
      }
    ]
  }, { ecuLabel: (address) => ({ "0x14b4": "Ethernet Node" }[address] || address) });
  const responseOnlySocket = responseOnlyRoutingTopology.socketMap.sockets.find((socket) => socket.directLogicalAddress === "0x14b4");
  assert.equal(responseOnlySocket.ip, "10.0.0.44");
  assert.equal(responseOnlySocket.directName, "Ethernet Node");
  assert.equal(responseOnlySocket.routingActivations[0].packet, 40676);
  assert.equal(responseOnlySocket.routingActivations[0].entityLogicalAddress, "0x14b4");

  const transitionedSocketTopology = topologyModule.buildTopologyAnalysis({
    hosts: {},
    dhcp: {
      servers: {},
      clients: { "ee:ee:ee:ee:ee:ee": { mac: "ee:ee:ee:ee:ee:ee", messages: { Ack: 1 }, ips: ["10.0.0.40"] } },
      samples: [{ messageType: "Ack", clientMac: "ee:ee:ee:ee:ee:ee", yourIp: "10.0.0.40", packet: 3, timestamp: 3 }]
    },
    doip: {
      logicalAddresses: { "0x3333": { sourceMacs: ["ee:ee:ee:ee:ee:ee"], ips: ["169.254.1.2", "10.0.0.40"] } },
      announcements: [
        { logicalAddress: "0x3333", srcIp: "169.254.1.2", srcMac: "ee:ee:ee:ee:ee:ee", eid: "33:44:55:66:77:88", packet: 1, timestamp: 1 },
        { logicalAddress: "0x3333", srcIp: "10.0.0.40", srcMac: "ee:ee:ee:ee:ee:ee", eid: "33:44:55:66:77:88", packet: 4, timestamp: 4 }
      ]
    },
    diagnostics: {
      ecus: { "0x3333": { ips: ["169.254.1.2", "10.0.0.40"], name: "Ethernet ECU" } },
      udsEvents: [
        { direction: "request", testerAddress: "0x0e00", ecuAddress: "0x5555", srcIp: "10.0.0.10", dstIp: "10.0.0.40", packet: 5, timestamp: 5, service: "0x22", serviceName: "Read", source: "0x0e00", target: "0x5555" }
      ]
    },
    traceEvents: [{ payloadType: "0x0005", logicalAddress: "0x0e00", srcIp: "10.0.0.10", dstIp: "10.0.0.40", packet: 6, timestamp: 6, payloadName: "Routing activation request" }]
  });
  const transitionedSockets = transitionedSocketTopology.socketMap.sockets.filter((socket) => socket.directLogicalAddress === "0x3333");
  assert.equal(transitionedSockets.length, 1);
  assert.equal(transitionedSockets[0].ip, "10.0.0.40");
  assert.deepEqual(plain(transitionedSockets[0].observedIps), ["169.254.1.2", "10.0.0.40"]);
  assert.deepEqual(plain(transitionedSockets[0].autoIpAddresses), ["169.254.1.2"]);
  assert.deepEqual(plain(transitionedSockets[0].dhcpIpAddresses), ["10.0.0.40"]);
  assert.equal(transitionedSockets[0].routed[0].logicalAddress, "0x5555");

  const ambiguousTopology = topologyModule.buildTopologyAnalysis({
    hosts: {
      primary: { mac: "bb:bb:bb:bb:bb:bb", ips: ["10.0.0.20"] },
      alias: { mac: "cc:cc:cc:cc:cc:cc", ips: ["10.0.0.20"] }
    },
    dhcp: { servers: {}, clients: {} },
    doip: { announcements: [{ logicalAddress: "0x1001", srcIp: "10.0.0.20", srcMac: "bb:bb:bb:bb:bb:bb", eid: "11:22:33:44:55:66" }] },
    diagnostics: {
      ecus: { "0x2222": { ips: ["10.0.0.20"] } },
      udsEvents: [{ direction: "request", testerAddress: "0x0e00", ecuAddress: "0x2222", dstIp: "10.0.0.20", packet: 1, timestamp: 1, service: "0x22", serviceName: "Read" }]
    },
    traceEvents: [],
    identity: { findings: [] }
  });
  const ambiguousEndpoint = ambiguousTopology.nodes.find((node) => node.id === "endpoint:10.0.0.20");
  assert.equal(ambiguousEndpoint.ambiguous, true);
  assert.deepEqual(plain(ambiguousEndpoint.macs.sort()), ["bb:bb:bb:bb:bb:bb", "cc:cc:cc:cc:cc:cc"]);

  const autoIpDhcpTopologyReport = {
    hosts: {
      ecu: { mac: "ee:ee:ee:ee:ee:ee", ips: ["169.254.1.2", "10.0.0.40"], packets: 10, bytes: 1000 }
    },
    dhcp: {
      servers: {},
      clients: { "ee:ee:ee:ee:ee:ee": { mac: "ee:ee:ee:ee:ee:ee", messages: { Ack: 1 }, ips: ["10.0.0.40"] } },
      samples: [{ messageType: "Ack", clientMac: "ee:ee:ee:ee:ee:ee", yourIp: "10.0.0.40", packet: 2, timestamp: 2 }]
    },
    doip: {
      logicalAddresses: { "0x3333": { sourceMacs: ["ee:ee:ee:ee:ee:ee"], ips: ["169.254.1.2", "10.0.0.40"] } },
      announcements: [
        { logicalAddress: "0x3333", srcIp: "169.254.1.2", srcMac: "ee:ee:ee:ee:ee:ee", packet: 1, timestamp: 1 },
        { logicalAddress: "0x3333", srcIp: "10.0.0.40", srcMac: "ee:ee:ee:ee:ee:ee", packet: 3, timestamp: 3 }
      ]
    },
    diagnostics: { ecus: { "0x3333": { ips: ["169.254.1.2", "10.0.0.40"] } }, udsEvents: [] },
    traceEvents: []
  };
  const autoIpDhcpTopology = topologyModule.buildTopologyAnalysis(autoIpDhcpTopologyReport);
  const autoIpDhcpNode = autoIpDhcpTopology.nodes.find((node) => node.logicalAddress === "0x3333");
  assert.equal(autoIpDhcpNode.ambiguous, false);
  assert.ok(autoIpDhcpNode.evidence.some((item) => item.includes("AutoIP followed by DHCP assignment")));
  assert.equal(autoIpDhcpTopology.summary.ambiguousLinks, 0);

  const requestedOnlyTopology = topologyModule.buildTopologyAnalysis({
    ...autoIpDhcpTopologyReport,
    dhcp: {
      ...autoIpDhcpTopologyReport.dhcp,
      samples: [{ messageType: "Request", clientMac: "ee:ee:ee:ee:ee:ee", requestedIp: "10.0.0.40", yourIp: "0.0.0.0", packet: 2, timestamp: 2 }]
    }
  });
  assert.equal(requestedOnlyTopology.nodes.some((node) => node.ambiguous), true);
}

function assertValidationAnalysisContracts() {
  const validation = loadValidationAnalysis();
  const report = {
    downloadAnalysis: {
      sessions: [{ id: 7, startTimestamp: 1.5 }],
      findings: [
        { severity: "high", category: "Validation", title: "Missing block", detail: "Gap in transfer", sessionId: 7, ecuAddress: "0x1001", packet: 11 }
      ]
    },
    tcpAnalysis: {
      flows: [{ key: "10.0.0.1:1 <-> 10.0.0.2:2", endpointA: "10.0.0.1:1", endpointB: "10.0.0.2:2", firstTimestamp: 2 }],
      gaps: [{ gap: 12, flowKey: "gap-flow", packet: 12, timestamp: 3 }],
      events: [{ type: "Slow ACK", label: "ACK took 120 ms", flowKey: "slow-flow", packet: 13, timestamp: 4 }]
    },
    identity: {
      findings: [{ severity: "high", title: "Logical conflict", evidence: "two owners", source: "DoIP", entityType: "Logical", entityId: "0x1001" }]
    },
    warnings: ["Malformed packet", "TCP gap in DoIP stream ignored here"],
    diagnostics: {
      udsEvents: [
        { responseKind: "negative", originalService: "0x22", service: "0x7f", nrc: "0x31", nrcName: "Request out of range", ecuAddress: "0x1001", testerAddress: "0x0e00", packet: 14, timestamp: 5 },
        { responseKind: "pending", ecuAddress: "0x1001", packet: 15, timestamp: 6 },
        { responseKind: "pending", ecuAddress: "0x1001", packet: 16, timestamp: 7 },
        { responseKind: "pending", ecuAddress: "0x1001", packet: 17, timestamp: 8 },
        { responseKind: "pending", ecuAddress: "0x1001", packet: 18, timestamp: 9 },
        { responseKind: "pending", ecuAddress: "0x1001", packet: 19, timestamp: 10 },
        { responseKind: "pending", ecuAddress: "0x1001", packet: 20, timestamp: 11 }
      ]
    },
    topology: {
      nodes: [{ id: "gateway:0x1001", label: "Gateway", ambiguous: true, evidence: ["conflict"], packets: [21], timestamps: [12], logicalAddress: "0x1001" }]
    }
  };
  const result = validation.buildValidationCentre(report, {
    ecuLabel: (address) => `Gateway (${address})`,
    transportHealth: () => ({ level: "problem", label: "Retransmissions", detail: "flow retransmitted" })
  });
  const titles = result.findings.map((finding) => finding.title);

  assert.equal(validation.normaliseValidationSeverity("high"), "error");
  assert.equal(validation.validationEntity({ ecuAddress: "0x1001" }, (address) => `ECU ${address}`), "ECU 0x1001");
  assert.equal(validation.validationFlowEntity({ endpointA: "a", endpointB: "b" }), "a <-> b");
  assert.deepEqual(plain(validation.countBy([{ level: "a" }, { level: "a" }, {}], "level")), { a: 2, Unknown: 1 });
  assert.equal(result.summary.errors, 4);
  assert.equal(result.summary.warnings, 2);
  assert.equal(result.summary.info, 2);
  assert.equal(result.summary.informationalNrcs, 2);
  assert.equal(result.summary.repeatedPendingGroups, 1);
  assert.equal(result.summary.affectedEcus, 1);
  assert.equal(result.summary.affectedFlows, 3);
  assert.equal(result.summary.affectedSessions, 1);
  assert.ok(titles.includes("Missing block"));
  assert.ok(titles.includes("Retransmissions"));
  assert.ok(titles.includes("TCP stream gap"));
  assert.ok(titles.includes("Slow ACK"));
  assert.ok(titles.includes("Logical conflict"));
  assert.ok(titles.includes("Parser warning"));
  assert.ok(titles.includes("0x22 negative response 0x31"));
  assert.ok(titles.includes("Repeated response pending"));
  const pendingFinding = result.findings.find((finding) => finding.title === "Repeated response pending");
  assert.equal(pendingFinding.severity, "info");
  assert.equal(pendingFinding.validationView, "informational");
  assert.equal(pendingFinding.nrcClassification, "informational");
  assert.ok(pendingFinding.detail.includes("expected UDS flow-control"));
  assert.equal(titles.includes("Ambiguous topology identity"), false);
  assert.equal(titles.includes("TCP gap in DoIP stream ignored here"), false);

  assert.equal(
    validation.isRecoveredSecurityInvalidKey(
      { diagnostics: { udsEvents: [
        { id: 1, direction: "request", service: "0x27", subFunction: "0x02", ecuAddress: "0x1001", testerAddress: "0x0e00", timestamp: 0.9 },
        { service: "0x67", subFunction: "0x02", ecuAddress: "0x1001", testerAddress: "0x0e00", timestamp: 2 }
      ] } },
      { requestEventId: 1, originalService: "0x27", nrc: "0x35", ecuAddress: "0x1001", testerAddress: "0x0e00", timestamp: 1 }
    ),
    true
  );
  assert.equal(
    validation.isRecoveredSecurityInvalidKey(
      { diagnostics: { udsEvents: [
        { id: 1, direction: "request", service: "0x27", subFunction: "0x02", ecuAddress: "0x1001", testerAddress: "0x0e00", timestamp: 0.9 },
        { service: "0x67", subFunction: "0x04", ecuAddress: "0x1001", testerAddress: "0x0e00", timestamp: 2 }
      ] } },
      { requestEventId: 1, originalService: "0x27", nrc: "0x35", ecuAddress: "0x1001", testerAddress: "0x0e00", timestamp: 1 }
    ),
    false
  );

  const mixedSecurity = validation.buildValidationCentre({
    downloadAnalysis: { sessions: [], findings: [] },
    tcpAnalysis: { flows: [], events: [], gaps: [] },
    identity: { findings: [] },
    warnings: [],
    topology: { nodes: [] },
    diagnostics: {
      udsEvents: [
        { id: 1, direction: "request", service: "0x27", subFunction: "0x02", ecuAddress: "0x1001", testerAddress: "0x0e00", timestamp: 0.9 },
        { id: 2, responseKind: "negative", requestEventId: 1, originalService: "0x27", service: "0x7f", nrc: "0x35", nrcName: "Invalid key", ecuAddress: "0x1001", testerAddress: "0x0e00", packet: 2, timestamp: 1 },
        { id: 3, service: "0x67", subFunction: "0x02", ecuAddress: "0x1001", testerAddress: "0x0e00", timestamp: 2 },
        { id: 4, direction: "request", service: "0x27", subFunction: "0x04", ecuAddress: "0x1001", testerAddress: "0x0e00", timestamp: 20 },
        { id: 5, responseKind: "negative", requestEventId: 4, originalService: "0x27", service: "0x7f", nrc: "0x35", nrcName: "Invalid key", ecuAddress: "0x1001", testerAddress: "0x0e00", packet: 5, timestamp: 21 }
      ]
    }
  });
  assert.equal(mixedSecurity.summary.errors, 1);
  assert.equal(mixedSecurity.summary.info, 1);
  assert.equal(mixedSecurity.findings.filter((finding) => finding.title === "0x27 negative response 0x35").length, 2);

  const ordinaryNegatives = validation.buildValidationCentre({
    downloadAnalysis: { sessions: [], findings: [] },
    tcpAnalysis: { flows: [], events: [], gaps: [] },
    identity: { findings: [] },
    warnings: [],
    topology: { nodes: [] },
    diagnostics: {
      udsEvents: [
        { responseKind: "negative", originalService: "0x22", service: "0x7f", nrc: "0x31", nrcName: "Request out of range", ecuAddress: "0x1001", testerAddress: "0x0e00", packet: 6, timestamp: 6 },
        { responseKind: "negative", originalService: "0x22", service: "0x7f", nrc: "0x31", nrcName: "Request out of range", ecuAddress: "0x1001", testerAddress: "0x0e01", packet: 7, timestamp: 7 }
      ]
    }
  });
  assert.equal(validation.isSecurityInvalidKeyNegative({ originalService: "0x22", nrc: "0x31" }), false);
  assert.equal(ordinaryNegatives.findings.filter((finding) => finding.title === "0x22 negative response 0x31").length, 1);
  assert.ok(ordinaryNegatives.findings[0].detail.includes("2 negative responses"));
  assert.equal(ordinaryNegatives.findings[0].severity, "info");
  assert.equal(ordinaryNegatives.findings[0].validationView, "informational");
  assert.equal(ordinaryNegatives.nrcSummary.length, 1);
  assert.equal(ordinaryNegatives.findings[0].evidence, "packets 6, 7");

  const transferNegative = validation.buildValidationCentre({
    downloadAnalysis: { sessions: [], findings: [] },
    tcpAnalysis: { flows: [], events: [], gaps: [] },
    identity: { findings: [] },
    warnings: [],
    topology: { nodes: [] },
    diagnostics: {
      udsEvents: [
        { responseKind: "negative", originalService: "0x36", service: "0x7f", nrc: "0x72", nrcName: "General programming failure", ecuAddress: "0x1001", testerAddress: "0x0e00", packet: 8, timestamp: 8 }
      ]
    }
  });
  assert.equal(transferNegative.findings[0].severity, "error");
  assert.equal(transferNegative.findings[0].validationView, "actionable");

  const slowAckGrouped = validation.buildValidationCentre({
    downloadAnalysis: { sessions: [], findings: [] },
    tcpAnalysis: {
      flows: [],
      gaps: [],
      events: [
        { type: "Slow ACK", label: "TCP slow ACK", flowKey: "flow-a", packet: 101, payloadPacket: 91, latency: 0.08, timestamp: 1 },
        { type: "Slow ACK", label: "TCP slow ACK", flowKey: "flow-a", packet: 102, payloadPacket: 92, latency: 0.12, timestamp: 2 },
        { type: "Slow ACK", label: "TCP slow ACK", flowKey: "flow-b", packet: 201, payloadPacket: 191, latency: 0.06, timestamp: 3 }
      ]
    },
    identity: { findings: [] },
    warnings: [],
    topology: { nodes: [] },
    diagnostics: { udsEvents: [] }
  });
  const slowAckFindings = slowAckGrouped.findings.filter((finding) => finding.title === "Slow ACK");
  const flowAFinding = slowAckFindings.find((finding) => finding.flowKey === "flow-a");
  assert.equal(slowAckFindings.length, 2);
  assert.ok(flowAFinding.detail.includes("2 slow TCP ACKs"));
  assert.ok(flowAFinding.detail.includes("120 ms"));
  assert.ok(flowAFinding.evidence.includes("ACK packets 101, 102"));

  const rejectedTarget = validation.buildValidationCentre({
    downloadAnalysis: { sessions: [], findings: [] },
    tcpAnalysis: { flows: [], events: [], gaps: [] },
    identity: { findings: [] },
    warnings: [],
    topology: { nodes: [] },
    diagnostics: {
      ackNak: [
        {
          packet: 30,
          timestamp: 3,
          type: "0x8003",
          ackCode: "0x03",
          ackCodeName: "Unknown target address",
          srcIp: "10.0.0.20",
          srcMac: "bb:bb:bb:bb:bb:bb",
          source: "0x1001",
          target: "0x0e00",
          previousSource: "0x0e00",
          previousTarget: "0x2222",
          previousMessageHex: "0e 00 22 22 22 f1 90"
        },
        {
          packet: 31,
          timestamp: 4,
          type: "0x8003",
          ackCode: "0x03",
          ackCodeName: "Unknown target address",
          srcIp: "10.0.0.20",
          srcMac: "bb:bb:bb:bb:bb:bb",
          source: "0x1001",
          target: "0x0e00",
          previousSource: "0x0e00",
          previousTarget: "0x2222",
          previousMessageHex: "0e 00 22 22 22 f1 91"
        }
      ],
      udsEvents: []
    }
  });
  const rejectedFinding = rejectedTarget.findings.find((finding) => finding.title === "DoIP target rejected by gateway");
  assert.equal(rejectedTarget.findings.filter((finding) => finding.title === "DoIP target rejected by gateway").length, 1);
  assert.equal(rejectedFinding.severity, "warning");
  assert.equal(rejectedFinding.ecuAddress, "0x2222");
  assert.ok(rejectedFinding.detail.includes("NACK 0x03"));
  assert.ok(rejectedFinding.detail.includes("Unknown target address"));
  assert.ok(rejectedFinding.detail.includes("bb:bb:bb:bb:bb:bb"));
  assert.ok(rejectedFinding.evidence.includes("packets 30, 31"));
  assert.ok(rejectedFinding.evidence.includes("0e 00 22 22 22 f1 90"));

  const diagnosticNackValidation = validation.buildValidationCentre({
    downloadAnalysis: { sessions: [], findings: [] },
    tcpAnalysis: { flows: [], events: [], gaps: [] },
    identity: { findings: [] },
    warnings: [],
    topology: { nodes: [] },
    diagnostics: {
      ackNak: [
        {
          packet: 35,
          timestamp: 3.5,
          type: "0x8003",
          ackCode: "0x05",
          ackCodeName: "Out of memory",
          srcIp: "10.0.0.20",
          dstIp: "10.0.0.10",
          source: "0x1001",
          target: "0x0e00",
          previousSource: "0x0e00",
          previousTarget: "0x2222",
          previousMessageHex: "0e 00 22 22 22 f1 90"
        }
      ],
      udsEvents: []
    }
  });
  const diagnosticNackFinding = diagnosticNackValidation.findings.find((finding) => finding.title === "DoIP diagnostic NACK observed");
  assert.equal(diagnosticNackFinding.severity, "error");
  assert.equal(diagnosticNackFinding.category, "DoIP diagnostics");
  assert.ok(diagnosticNackFinding.detail.includes("0x05"));
  assert.ok(diagnosticNackFinding.detail.includes("Out of memory"));
  assert.ok(diagnosticNackFinding.evidence.includes("packets 35"));

  const genericNackValidation = validation.buildValidationCentre({
    downloadAnalysis: { sessions: [], findings: [] },
    tcpAnalysis: { flows: [], events: [], gaps: [] },
    identity: { findings: [] },
    warnings: [],
    topology: { nodes: [] },
    doip: {
      genericNacks: [
        { packet: 40, timestamp: 4, transport: "TCP", srcIp: "10.0.0.20", dstIp: "10.0.0.10", nackCode: "0x02", nackCodeName: "Message too large" },
        { packet: 41, timestamp: 5, transport: "TCP", srcIp: "10.0.0.20", dstIp: "10.0.0.10", nackCode: "0x02", nackCodeName: "Message too large" }
      ]
    },
    diagnostics: { udsEvents: [] }
  });
  const genericNackFinding = genericNackValidation.findings.find((finding) => finding.title === "DoIP transport/header NACK observed");
  assert.equal(genericNackFinding.severity, "error");
  assert.equal(genericNackFinding.category, "DoIP transport");
  assert.ok(genericNackFinding.detail.includes("0x02"));
  assert.ok(genericNackFinding.detail.includes("Message too large"));
  assert.ok(genericNackFinding.evidence.includes("packets 40, 41"));

  const autoIpDhcpReport = {
    downloadAnalysis: { sessions: [], findings: [] },
    tcpAnalysis: { flows: [], events: [], gaps: [] },
    identity: { findings: [] },
    warnings: [],
    topology: { nodes: [] },
    hosts: {
      ecu: { mac: "ee:ee:ee:ee:ee:ee", ips: ["169.254.1.2", "10.0.0.40"], packets: 10, bytes: 1000 }
    },
    dhcp: {
      clients: { "ee:ee:ee:ee:ee:ee": { mac: "ee:ee:ee:ee:ee:ee", messages: { Ack: 1 }, ips: ["10.0.0.40"] } },
      samples: [{ messageType: "Ack", clientMac: "ee:ee:ee:ee:ee:ee", yourIp: "10.0.0.40", packet: 2, timestamp: 2 }]
    },
    doip: {
      logicalAddresses: { "0x3333": { sourceMacs: ["ee:ee:ee:ee:ee:ee"], ips: ["169.254.1.2", "10.0.0.40"] } },
      announcements: [
        { logicalAddress: "0x3333", srcIp: "169.254.1.2", srcMac: "ee:ee:ee:ee:ee:ee", packet: 1, timestamp: 1 },
        { logicalAddress: "0x3333", srcIp: "10.0.0.40", srcMac: "ee:ee:ee:ee:ee:ee", packet: 3, timestamp: 3 }
      ]
    },
    diagnostics: { ecus: { "0x3333": { ips: ["169.254.1.2", "10.0.0.40"] } }, udsEvents: [] }
  };
  const expectedTransition = validation.buildValidationCentre(autoIpDhcpReport);
  assert.equal(expectedTransition.findings.some((finding) => finding.title === "ECU continued using AutoIP after DHCP assignment"), false);

  const continuedAutoIp = validation.buildValidationCentre({
    ...autoIpDhcpReport,
    doip: {
      ...autoIpDhcpReport.doip,
      announcements: [
        ...autoIpDhcpReport.doip.announcements,
        { logicalAddress: "0x3333", srcIp: "169.254.1.2", srcMac: "ee:ee:ee:ee:ee:ee", packet: 4, timestamp: 4 }
      ]
    }
  }, { ecuLabel: (address) => `ECU ${address}` });
  assert.equal(continuedAutoIp.findings.some((finding) => finding.title === "ECU continued using AutoIP after DHCP assignment"), false);

  const continuedAutoIpRequestOnly = validation.buildValidationCentre({
    ...autoIpDhcpReport,
    diagnostics: {
      ecus: { "0x3333": { ips: ["169.254.1.2", "10.0.0.40"] } },
      udsEvents: [{ ecuAddress: "0x3333", direction: "request", dstIp: "169.254.1.2", packet: 4, timestamp: 4 }]
    }
  }, { ecuLabel: (address) => `ECU ${address}` });
  assert.equal(continuedAutoIpRequestOnly.findings.some((finding) => finding.title === "ECU continued using AutoIP after DHCP assignment"), false);

  const continuedAutoIpResponse = validation.buildValidationCentre({
    ...autoIpDhcpReport,
    diagnostics: {
      ecus: { "0x3333": { ips: ["169.254.1.2", "10.0.0.40"] } },
      udsEvents: [{ ecuAddress: "0x3333", direction: "response", srcIp: "169.254.1.2", packet: 4, timestamp: 4 }]
    }
  }, { ecuLabel: (address) => `ECU ${address}` });
  const autoIpFinding = continuedAutoIpResponse.findings.find((finding) => finding.title === "ECU continued using AutoIP after DHCP assignment");
  assert.equal(autoIpFinding.severity, "error");
  assert.equal(autoIpFinding.ecuAddress, "0x3333");
  assert.ok(autoIpFinding.detail.includes("10.0.0.40"));
  assert.ok(autoIpFinding.detail.includes("169.254.1.2"));
  assert.ok(autoIpFinding.evidence.includes("DHCP Ack packet 2"));
  assert.ok(autoIpFinding.evidence.includes("later AutoIP UDS response packets 4"));
}

function assertDownloadAnalysisContracts() {
  const downloads = loadDownloadAnalysis();
  const transfer = {
    id: 7,
    direction: "download",
    service: "0x34",
    status: "completed",
    ecuAddress: "0x1001",
    testerAddress: "0x0e00",
    requestEventId: 1,
    requestPacket: 101,
    startTimestamp: 1,
    endTimestamp: 2,
    request: { memorySize: 4 },
    blocks: 2,
    expectedBlocks: 2,
    reconstructedBytes: 4,
    acknowledgedBlocks: 0,
    ackBlocks: [],
    dataBlocks: [
      { eventId: 2, counter: "0x01", packet: 102, timestamp: 1.2, payloadBytes: 2, payloadHex: "aa bb" },
      { eventId: 3, counter: "0x02", packet: 103, timestamp: 1.4, payloadBytes: 2, payloadHex: "cc dd" },
      { eventId: 4, counter: "0x02", packet: 104, timestamp: 1.5, payloadBytes: 2, payloadHex: "ee ff" }
    ],
    coordinationBlocks: [],
    pendingEvents: [],
    negativeEvents: [],
    timelineEventIds: [1, 5],
    missingSequences: [],
    negatives: 0,
    pending: 0,
    responseCodes: [],
    exportable: true
  };
  const report = {
    diagnostics: {
      ecus: { "0x1001": { ips: ["10.0.0.20"] } },
      udsEvents: [
        { id: 1, service: "0x34", direction: "request", ecuAddress: "0x1001", testerAddress: "0x0e00", timestamp: 1, packet: 101, srcIp: "10.0.0.10", srcPort: 50000, dstIp: "10.0.0.20", dstPort: 13400, raw: "34" },
        { id: 2, service: "0x36", direction: "request", ecuAddress: "0x1001", testerAddress: "0x0e00", timestamp: 1.2, packet: 102, srcIp: "10.0.0.10", srcPort: 50000, dstIp: "10.0.0.20", dstPort: 13400, raw: "36 01 aa bb" },
        { id: 3, service: "0x36", direction: "request", ecuAddress: "0x1001", testerAddress: "0x0e00", timestamp: 1.4, packet: 103, srcIp: "10.0.0.10", srcPort: 50000, dstIp: "10.0.0.20", dstPort: 13400, raw: "36 02 cc dd" },
        { id: 4, service: "0x36", direction: "request", ecuAddress: "0x1001", testerAddress: "0x0e00", timestamp: 1.5, packet: 104, srcIp: "10.0.0.10", srcPort: 50000, dstIp: "10.0.0.20", dstPort: 13400, raw: "36 02 ee ff" },
        { id: 5, service: "0x77", direction: "response", ecuAddress: "0x1001", testerAddress: "0x0e00", timestamp: 2, packet: 105, srcIp: "10.0.0.20", srcPort: 13400, dstIp: "10.0.0.10", dstPort: 50000, raw: "77" },
        { id: 6, service: "0x76", direction: "response", ecuAddress: "0x1001", testerAddress: "0x0e00", timestamp: 1.25, packet: 106, transfer: { blockCounter: 1 }, raw: "76 01" },
        { id: 7, service: "0x76", direction: "response", ecuAddress: "0x1001", testerAddress: "0x0e00", timestamp: 1.45, packet: 107, transfer: { blockCounter: 2 }, raw: "76 02" }
      ],
      transfers: [transfer]
    },
    doip: {
      announcements: [{ srcIp: "10.0.0.20", logicalAddress: "0x1001" }]
    },
    tcpAnalysis: {
      gaps: []
    }
  };
  const ackObservations = downloads.downloadAckObservations(report, transfer);
  const assigned = downloads.assignObservedDownloadAcks(transfer, ackObservations);
  const duplicateFindings = downloads.downloadDuplicateFindings(transfer);
  const duplicateWithCaptureLoss = downloads.downloadDuplicateFindings({
    ...transfer,
    expectedBlocks: 300,
    blocks: 2,
    missingSequences: ["0x03->0xff"]
  });
  const duplicateWithBackwardRepeat = downloads.downloadDuplicateFindings({
    ...transfer,
    missingSequences: ["0x03->0x02"]
  });
  const rate = downloads.buildTransferRateAnalysis(assigned);
  const analysis = downloads.buildDownloadAnalysis(report, { ecuLabel: (address) => `Gateway (${address})` });
  const estimateOnly = downloads.enrichDownloadSession(report, {
    ...transfer,
    expectedBlocks: 3,
    expectedBlockShortfall: { expected: 3, observed: 2 },
    reconstructedBytes: 4,
    dataBlocks: transfer.dataBlocks.slice(0, 2),
    ackBlocks: [],
    acknowledgedBlocks: 0,
    missingSequences: []
  });
  const wrappedCounterTransfer = {
    ...transfer,
    dataBlocks: Array.from({ length: 257 }, (_, index) => {
      const counter = `0x${(((index + 1) & 0xff).toString(16).padStart(2, "0"))}`;
      return { eventId: 200 + index, counter, packet: 300 + index, timestamp: index, payloadBytes: 1, payloadHex: "ff" };
    }),
    missingSequences: []
  };
  const openTransfer = downloads.enrichDownloadSession(report, {
    ...transfer,
    status: "open",
    dataBlocks: transfer.dataBlocks.slice(0, 2),
    ackBlocks: [],
    acknowledgedBlocks: 0,
    missingSequences: []
  });

  assert.equal(ackObservations.events.length, 2);
  assert.equal(assigned.acknowledgedBlocks, 2);
  assert.deepEqual(plain(downloads.downloadAckHealth(assigned, ackObservations)), { missing: [], unassigned: [], extra: [] });
  assert.equal(duplicateFindings.length, 1);
  assert.equal(duplicateFindings[0].severity, "error");
  assert.equal(downloads.isForwardMissingSequence("0x03->0x02"), false);
  assert.equal(downloads.isForwardMissingSequence("0x03->0xff"), true);
  assert.equal(duplicateWithCaptureLoss[0].severity, "warning");
  assert.equal(duplicateWithBackwardRepeat[0].severity, "error");
  assert.equal(downloads.downloadDuplicateFindings(wrappedCounterTransfer).length, 0);
  assert.equal(openTransfer.severity, "error");
  assert.ok(openTransfer.validation.some((finding) => finding.title === "Session did not reach TransferExit" && finding.severity === "error"));
  assert.equal(openTransfer.hexExportable, false);
  assert.equal(estimateOnly.validation.some((finding) => finding.title === "Expected payload blocks are missing"), false);
  assert.ok(estimateOnly.validation.some((finding) => finding.title === "Estimated block count exceeds reconstructed blocks" && finding.severity === "info"));
  assert.equal(estimateOnly.validation.some((finding) => finding.category === "Completeness" && finding.severity === "warning"), false);
  assert.equal(rate.blockIntervals.length, 2);
  assert.equal(rate.ackLatencies.length, 2);
  assert.equal(rate.rateBuckets.length, 8);
  assert.equal(downloads.downloadGatewayIp(report, assigned, downloads.transferEvents(report, assigned, ackObservations)), "10.0.0.20");
  assert.equal(downloads.downloadGatewayLabel(report, assigned, downloads.transferEvents(report, assigned, ackObservations)), "10.0.0.20 / 0x1001");
  assert.equal(downloads.isSameTransferBoundaryEvent(report.diagnostics.udsEvents[4], assigned), true);
  assert.equal(analysis.metrics.sessions, 1);
  assert.equal(analysis.metrics.downloads, 1);
  assert.equal(analysis.metrics.errors, 1);
  assert.equal(analysis.sessions[0].gatewayLabel, "10.0.0.20 / 0x1001");
  assert.equal(analysis.sessions[0].severity, "error");
  assert.equal(analysis.groups.length, 1);
  assert.equal(analysis.matrixRows.length, 1);
  assert.equal(analysis.matrixRows[0].blockAgreement, "warn");
}

function assertDoipLifecycleAnalysisContracts() {
  const lifecycleModule = loadDoipLifecycleAnalysis();
  const ecuLabel = (address) => ({ "0x1001": "CGW", "0x2222": "Body", "0x3333": "Door", "0x4444": "Rejected" }[address] || address);
  const baseSocket = {
    id: "socket:10.0.0.20",
    ip: "10.0.0.20",
    label: "10.0.0.20",
    directLogicalAddress: "0x1001",
    directName: "CGW",
    observedIps: ["169.254.1.20", "10.0.0.20"],
    macs: ["bb:bb:bb:bb:bb:bb"],
    announcements: [{ packet: 3, timestamp: 0.3, logicalAddress: "0x1001" }],
    routingActivations: [{ packet: 4, timestamp: 0.4, type: "0x0006", testerLogicalAddress: "0x0e00", entityLogicalAddress: "0x1001", responseCode: "0x10", responseCodeName: "Routing successfully activated", sourceIp: "10.0.0.20", targetIp: "10.0.0.10" }],
    routed: [],
    rejected: [],
    evidence: ["AutoIP followed by DHCP assignment"]
  };
  const report = {
    topology: { socketMap: { sockets: [{ ...baseSocket }] } },
    arp: { samples: [{ packet: 1, timestamp: 0.1, operation: "request", senderIp: "10.0.0.10", senderMac: "aa", targetIp: "10.0.0.20", targetMac: "bb:bb:bb:bb:bb:bb" }] },
    tcpAnalysis: {
      flows: [{ key: "10.0.0.10:50000 <-> 10.0.0.20:13400", endpointA: "10.0.0.10:50000", endpointB: "10.0.0.20:13400", firstTimestamp: 0.2, lastTimestamp: 0.6, packets: 8, payloadBytes: 128, handshakeDuration: 0.02 }],
      events: [
        { flowKey: "10.0.0.10:50000 <-> 10.0.0.20:13400", type: "Handshake", packet: 2 },
        { flowKey: "10.0.0.10:50000 <-> 10.0.0.20:13400", type: "FIN", packet: 6 }
      ]
    },
    doip: {
      samples: [
        { packet: 2, timestamp: 0.25, payloadType: "0x0001", payloadName: "Vehicle identification request", srcIp: "10.0.0.10", dstIp: "10.0.0.20" },
        { packet: 3, timestamp: 0.3, payloadType: "0x0004", payloadName: "Vehicle announcement / identification response", srcIp: "10.0.0.20", srcMac: "bb:bb:bb:bb:bb:bb", logicalAddress: "0x1001", vin: "VIN", eid: "eid" }
      ]
    },
    diagnostics: { udsEvents: [{ packet: 5, timestamp: 0.5, direction: "request", dstIp: "10.0.0.20", ecuAddress: "0x1001", testerAddress: "0x0e00", service: "0x22", serviceName: "Read Data By Identifier" }] }
  };
  const lifecycle = lifecycleModule.buildDoipLifecycle(report, { ecuLabel });
  const gateway = lifecycle.nodes.find((node) => node.logicalAddress === "0x1001");
  assert.equal(lifecycle.summary.nodes, 1);
  assert.equal(lifecycle.summary.issues, 0);
  assert.equal(lifecycle.summary.routingActive, 1);
  assert.equal(gateway.stages.arp.status, "observed");
  assert.equal(gateway.stages.tcpSocket.status, "observed");
  assert.equal(gateway.stages.vehicleAnnouncement.status, "observed");
  assert.equal(gateway.stages.vehicleIdResponse.status, "observed");
  assert.equal(gateway.stages.routingActivation.status, "observed");
  assert.ok(gateway.stages.routingActivation.evidence.some((item) => item.includes("routing activation response 0x1001")));
  assert.equal(gateway.stages.routingActivation.details.activations[0].responseCodeName, "Routing successfully activated");
  assert.equal(gateway.stages.diagnostics.status, "observed");
  assert.equal(gateway.stages.tcpSocket.details.flows[0].opened, 1);
  assert.equal(gateway.stages.tcpSocket.details.flows[0].closed, 1);
  assert.equal(gateway.stages.vehicleIdResponse.details.pairs[0].requestPacket, 2);
  assert.equal(gateway.stages.vehicleIdResponse.details.pairs[0].responsePacket, 3);
  assert.equal(gateway.stages.diagnostics.details.events[0].serviceName, "Read Data By Identifier");
  assert.deepEqual(plain(gateway.ips), ["169.254.1.20", "10.0.0.20"]);

  const idResponseOnly = lifecycleModule.buildDoipLifecycle({
    ...report,
    topology: { socketMap: { sockets: [{ ...baseSocket, announcements: [] }] } }
  }, { ecuLabel });
  const idResponseNode = idResponseOnly.nodes.find((node) => node.logicalAddress === "0x1001");
  assert.equal(idResponseNode.stages.vehicleAnnouncement.status, "missing");
  assert.equal(idResponseNode.stages.vehicleIdResponse.status, "observed");

  const missingRouting = lifecycleModule.buildDoipLifecycle({
    ...report,
    topology: { socketMap: { sockets: [{ ...baseSocket, routingActivations: [] }] } }
  }, { ecuLabel });
  const missingGateway = missingRouting.nodes.find((node) => node.logicalAddress === "0x1001");
  assert.equal(missingGateway.stages.routingActivation.status, "missing");
  assert.equal(missingGateway.issues[0].title, "Diagnostics without routing activation");

  const duplicateSocketLifecycle = lifecycleModule.buildDoipLifecycle({
    topology: {
      socketMap: {
        sockets: [
          { ...baseSocket, id: "socket:169.254.1.20", ip: "169.254.1.20", observedIps: ["169.254.1.20"], routingActivations: [{ packet: 4, timestamp: 0.4, type: "0x0006", testerLogicalAddress: "0x0e00", entityLogicalAddress: "0x1001" }] },
          { ...baseSocket, id: "socket:10.0.0.20", ip: "10.0.0.20", observedIps: ["10.0.0.20"], announcements: [], routingActivations: [] }
        ]
      }
    },
    arp: { samples: [] },
    tcpAnalysis: { flows: [{ key: "10.0.0.10:50000 <-> 10.0.0.20:13400", endpointA: "10.0.0.10:50000", endpointB: "10.0.0.20:13400", firstTimestamp: 0.2 }] },
    doip: { samples: [] },
    diagnostics: { udsEvents: [{ packet: 5, timestamp: 0.5, direction: "request", dstIp: "10.0.0.20", ecuAddress: "0x1001", testerAddress: "0x0e00" }] }
  }, { ecuLabel });
  const duplicateGatewayNodes = duplicateSocketLifecycle.nodes.filter((node) => node.logicalAddress === "0x1001");
  assert.equal(duplicateGatewayNodes.length, 1);
  assert.equal(duplicateGatewayNodes[0].stages.routingActivation.status, "observed");
  assert.equal(duplicateGatewayNodes[0].stages.diagnostics.status, "observed");
  assert.equal(duplicateGatewayNodes[0].issues.length, 0);
  assert.deepEqual(plain(duplicateGatewayNodes[0].ips), ["169.254.1.20", "10.0.0.20"]);

  const behind = lifecycleModule.buildDoipLifecycle({
    ...report,
    topology: { socketMap: { sockets: [{ ...baseSocket, routed: [{ id: "socket:10.0.0.20|route:0x3333", logicalAddress: "0x3333", name: "Door", requests: 2, packets: [7, 8], timestamps: [0.7, 0.8], evidence: ["2 requests"] }] }] } }
  }, { ecuLabel });
  const behindNode = behind.nodes.find((node) => node.logicalAddress === "0x3333");
  assert.equal(behindNode.role, "behind-socket");
  assert.equal(behindNode.parentSocketLogicalAddress, "0x1001");
  assert.equal(behindNode.stages.tcpSocket.status, "not-applicable");
  assert.equal(behindNode.stages.diagnostics.count, 2);
  assert.equal(behindNode.stages.diagnostics.details.routedTarget.socketName, "CGW");

  const rejected = lifecycleModule.buildDoipLifecycle({
    ...report,
    topology: { socketMap: { sockets: [{ ...baseSocket, rejected: [{ id: "socket:10.0.0.20|rejected:0x4444", logicalAddress: "0x4444", name: "Rejected", packets: [9, 10], timestamps: [0.9, 1.0], evidence: ["NACK 0x03"] }] }] } }
  }, { ecuLabel });
  const rejectedNode = rejected.nodes.find((node) => node.logicalAddress === "0x4444");
  assert.equal(rejected.summary.rejected, 1);
  assert.equal(rejectedNode.stages.diagnostics.status, "failed");
  assert.equal(rejectedNode.issues[0].title, "DoIP target rejected");
}

function assertDiscoveryRendererContracts() {
  const renderer = loadDiscoveryRenderer();
  const report = {
    source: "sample.pcap",
    summary: { totalBytes: 1536, totalPackets: 2 },
    diagnostics: { udsEvents: [{}, {}], ecus: { "0x1001": {} }, didReads: [{}], transfers: [{}, {}] },
    validationCentre: { findings: [{ severity: "error" }, { severity: "info" }] },
    tcpAnalysis: { flows: [{}] },
    doip: {
      announcements: [{ vin: "<VIN>", logicalAddress: "0x1001", srcIp: "10.0.0.20", srcPort: 13400, eid: "aa", gid: "bb", furtherActionRequired: 1 }],
      samples: [{ packet: 1, transport: "TCP", srcIp: "10.0.0.10", dstIp: "10.0.0.20", payloadName: "Diagnostic message", vin: "", logicalAddress: "0x1001" }]
    },
    identity: { findings: [{}] },
    topology: { edges: [{}, {}] },
    hosts: {
      a: { mac: "aa:aa:aa:aa:aa:aa", ips: ["10.0.0.10"], packets: 2, bytes: 1536 }
    },
    dhcp: {
      messageTypes: { Discover: 1 },
      clients: { a: { mac: "aa:aa:aa:aa:aa:aa", hostname: "<host>", ips: ["10.0.0.10"], messages: { Discover: 1 } } },
      samples: []
    },
    arp: {
      operations: { request: 1 },
      samples: [{ operation: "request", senderIp: "10.0.0.10", senderMac: "aa", targetIp: "10.0.0.20", targetMac: "bb" }]
    },
    flows: [{ transport: "TCP", src: "a", srcPort: 1, dst: "b", dstPort: 2, packets: 3 }]
  };
  const homeNodes = {};
  const $ = (id) => homeNodes[id] ||= { textContent: "", hidden: false };
  const originalDocument = global.document;
  global.document = { body: { classList: { toggle() {} } } };
  try {
    renderer.renderHome(report, { $ });
  } finally {
    global.document = originalDocument;
  }

  assert.equal(homeNodes.homeCaptureState.textContent, "1.5 KB loaded");
  assert.equal(homeNodes.homeUdsCount.textContent, "2 events");
  assert.equal(homeNodes.homeValidationCount.textContent, "1 findings");
  assert.ok(renderer.renderHosts(report, "aa").includes("aa:aa:aa:aa:aa:aa"));
  assert.ok(renderer.renderAnnouncements(report.doip.announcements).includes("&lt;VIN&gt;"));
  assert.ok(renderer.renderDhcp(report, () => "<div>bars</div>").includes("&lt;host&gt;"));
  assert.ok(renderer.renderArp(report, () => "<div>bars</div>").includes("10.0.0.20"));
  const lifecycle = {
    summary: { nodes: 2, issues: 1, routingActive: 1, rejected: 1 },
    nodes: [
      {
        id: "socket:10.0.0.20",
        role: "gateway-socket",
        name: "CGW",
        logicalAddress: "0x1001",
        ips: ["10.0.0.20"],
        macs: ["aa"],
        issues: [],
        stages: {
          arp: { key: "arp", label: "ARP", status: "observed", count: 1, firstPacket: 1, firstTimestamp: 0.1, packets: [1], evidence: ["request"] },
          tcpSocket: { key: "tcpSocket", label: "TCP socket", status: "observed", count: 1, firstPacket: "", firstTimestamp: 0.2, packets: [], evidence: ["flow"], details: { flows: [{ key: "flow", socketEndpoint: "10.0.0.20:13400", opened: 1, closed: 1, resets: 0, packets: 10, payloadBytes: 200, openPackets: [2], closePackets: [9] }] } },
          vehicleAnnouncement: { key: "vehicleAnnouncement", label: "Vehicle announcement", status: "observed", count: 1, firstPacket: 3, firstTimestamp: 0.3, packets: [3], evidence: ["announcement"] },
          vehicleIdResponse: { key: "vehicleIdResponse", label: "Vehicle ID response", status: "not-applicable", count: 0, firstPacket: "", firstTimestamp: null, packets: [], evidence: [], details: { requests: [{ packet: 2 }], responses: [{ packet: 3 }], pairs: [{ requestPacket: 2, responsePacket: 3, requestType: "Vehicle identification request", responseIp: "10.0.0.20", logicalAddress: "0x1001" }] } },
          routingActivation: { key: "routingActivation", label: "Routing activation", status: "observed", count: 1, firstPacket: 4, firstTimestamp: 0.4, packets: [4], evidence: ["activation"], details: { activations: [{ packet: 4, type: "0x0006", testerLogicalAddress: "0x0e00", entityLogicalAddress: "0x1001", responseCode: "0x10", responseCodeName: "Routing successfully activated", sourceIp: "10.0.0.20", targetIp: "10.0.0.10" }] } },
          diagnostics: { key: "diagnostics", label: "Diagnostics", status: "observed", count: 2, firstPacket: 5, firstTimestamp: 0.5, packets: [5, 6], evidence: ["0x0e00 -> 0x1001"], details: { events: [{ packet: 5, direction: "request", ecuAddress: "0x1001", service: "0x22", serviceName: "Read Data By Identifier" }] } }
        }
      },
      {
        id: "socket:10.0.0.20|rejected:0x2222",
        role: "behind-socket",
        name: "Body",
        logicalAddress: "0x2222",
        parentSocketName: "CGW",
        parentSocketLogicalAddress: "0x1001",
        ips: ["10.0.0.20"],
        macs: [],
        issues: [{ title: "DoIP target rejected", detail: "NACK 0x03" }],
        stages: {
          diagnostics: { key: "diagnostics", label: "Diagnostics", status: "failed", count: 1, firstPacket: 7, firstTimestamp: 0.7, packets: [7], evidence: ["NACK"], details: { rejectedTarget: { socketIp: "10.0.0.20", socketName: "CGW", socketLogicalAddress: "0x1001", logicalAddress: "0x2222", previousMessages: ["0e 00 22 22"] } } }
        }
      }
    ]
  };
  assert.ok(renderer.renderLifecycleSummary(lifecycle).includes("Rejected targets"));
  assert.equal(renderer.filteredLifecycleNodes(lifecycle, "rejected").length, 1);
  const lifecycleNodeList = renderer.renderLifecycleNodeList(lifecycle, "socket:10.0.0.20", "all");
  assert.ok(lifecycleNodeList.includes("CGW"));
  assert.ok(lifecycleNodeList.includes("lifecycle-node-status"));
  assert.ok(lifecycleNodeList.includes("lifecycle-node-role"));
  assert.ok(lifecycleNodeList.includes("10.0.0.20 (CGW 0x1001)"));
  assert.ok(lifecycleNodeList.includes("badge ok"));
  assert.ok(lifecycleNodeList.indexOf("badge ok") < lifecycleNodeList.indexOf("lifecycle-node-title"));
  const lifecycleTimeline = renderer.renderLifecycleTimeline(lifecycle.nodes[0], "routingActivation");
  assert.ok(lifecycleTimeline.includes("Routing activation"));
  assert.ok(lifecycleTimeline.includes('data-flow-step="1"'));
  assert.ok(lifecycleTimeline.includes("lifecycle-stage-index"));
  assert.ok(lifecycleTimeline.includes("badge ok"));
  assert.equal(renderer.lifecycleStatusClass("missing"), "warn");
  assert.ok(renderer.renderLifecycleStageDetail(lifecycle.nodes[0], "tcpSocket").includes("TCP socket summary"));
  assert.ok(renderer.renderLifecycleStageDetail(lifecycle.nodes[0], "vehicleIdResponse").includes("Vehicle ID request / response pairing"));
  assert.ok(renderer.renderLifecycleStageDetail(lifecycle.nodes[0], "routingActivation").includes("Routing successfully activated"));
  assert.ok(renderer.renderLifecycleStageDetail(lifecycle.nodes[0], "diagnostics").includes("1 diagnostic event observed"));
  assert.ok(renderer.renderLifecycleStageDetail(lifecycle.nodes[0], "diagnostics").includes("Packet samples"));
  assert.ok(renderer.renderLifecycleStageDetail(lifecycle.nodes[1], "diagnostics").includes("DoIP target rejected"));
  assert.ok(renderer.sampleTable(report, "doip").head.includes("<th>packet</th>"));
  assert.ok(renderer.sampleTable(report, "doip").head.includes("<th>ackCodeName</th>"));
  assert.ok(renderer.sampleTable(report, "doip").head.includes("<th>nackCodeName</th>"));
  assert.ok(renderer.sampleTable(report, "doip").head.includes("<th>routingActivationResponseCodeName</th>"));
  assert.ok(renderer.sampleTable(report, "flows").body.includes("<td><code>TCP</code></td>"));
}

function assertValidationRendererContracts() {
  const renderer = loadValidationRenderer();
  const findings = [
    {
      id: "VAL-1",
      severity: "error",
      category: "UDS diagnostics",
      sourceTool: "UDS Analyser",
      title: "0x27 negative response 0x35",
      detail: "Invalid key",
      evidence: "packet 10",
      validationKind: "nrc",
      validationView: "actionable",
      nrc: "0x35",
      nrcName: "Invalid key",
      originalService: "0x27",
      findingCount: 1,
      entity: "Gateway",
      ecuAddress: "0x1001",
      packet: 10,
      timestamp: 1.25
    },
    {
      id: "VAL-2",
      severity: "info",
      category: "Capture quality",
      sourceTool: "Parser",
      title: "Parser warning",
      detail: "Benign",
      evidence: "",
      validationView: "informational",
      entity: "Capture",
      packet: "",
      timestamp: null
    }
  ];

  assert.equal(renderer.summaryText({ errors: 1, warnings: 2, info: 3, totalFindings: 6 }, 2, "Action Suggested"), "2 visible of 6 total. Action Suggested. 1 errors, 2 warnings, 3 info.");
  const metrics = renderer.metricsHtml({ errors: 1, warnings: 0, actionableNrcs: 1, informationalNrcs: 2, repeatedPendingGroups: 3, affectedEcus: 1, affectedFlows: 2 }, findings);
  assert.ok(metrics.includes("Severe NRCs"));
  assert.ok(metrics.includes("Low Priority NRCs"));
  assert.ok(metrics.includes("Diagnostic Response Pendings"));
  assert.equal((metrics.match(/data-open-validation-nrc-summary/g) || []).length, 3);
  assert.ok(metrics.includes("Affected TCP flows"));
  assert.equal(renderer.compactText("word ".repeat(40), 24), "word word word word...");
  assert.ok(renderer.evidenceCellHtml({ packet: 10, evidence: "packets 1, 2, 3, 4, 5, 6, 7, 8, 9, 10" }).includes("validation-evidence-collapsed"));
  assert.ok(renderer.evidenceCellHtml({ packet: 10, evidence: "packet 10" }).includes("packet 10"));
  assert.deepEqual(plain(renderer.filterOptions(findings, "sourceTool")), ["Parser", "UDS Analyser"]);
  assert.ok(renderer.selectOptionsHtml(["Parser"], "All sources").includes('<option value="Parser">Parser</option>'));
  assert.equal(renderer.filteredFindings(findings, { severity: "all" }).length, 2);
  assert.equal(renderer.filteredFindings(findings, { view: "action-required", severity: "all" }).length, 1);
  assert.equal(renderer.filteredFindings(findings, { view: "informational", severity: "all", source: "Parser" }).length, 1);
  assert.equal(renderer.filteredFindings(findings, { severity: "all", query: "gateway" }).length, 1);
  assert.equal(renderer.validationViewFilterMatch(findings[0], "nrc-summary"), true);
  assert.equal(renderer.viewModeLabel("nrc-summary"), "UDS NRC summary");
  assert.ok(renderer.emptyStateText("network").includes("network / tcp"));
  const nrcSummary = [
    { id: "VAL-1", severity: "error", classification: "actionable", ecuAddress: "0x1001", entity: "Gateway", service: "0x27", nrc: "0x35", nrcName: "Invalid key", count: 1, packet: 10, timestamp: 1.25 },
    { id: "VAL-3", severity: "info", classification: "informational", ecuAddress: "0x1001", entity: "Gateway", service: "0x22", nrc: "0x31", nrcName: "Request out of range", count: 8, packet: 11, timestamp: 2 },
    { id: "VAL-4", severity: "info", classification: "informational", ecuAddress: "0x2222", entity: "Body", service: "0x22", nrc: "0x31", nrcName: "Request out of range", count: 2, packet: 12, timestamp: 3 }
  ];
  const groupedNrcs = renderer.groupNrcSummaryByEcu(nrcSummary);
  assert.equal(groupedNrcs.length, 2);
  assert.equal(groupedNrcs[0].ecuAddress, "0x1001");
  assert.equal(groupedNrcs[0].responses, 9);
  assert.equal(groupedNrcs[0].actionable, 1);
  assert.ok(renderer.nrcSummaryHtml(nrcSummary, { ecuCode: (address) => `<code>${address}</code>`, formatTimeDelta: () => "+1.250s" }).includes("NRC groups"));
  assert.ok(renderer.nrcSummaryHtml(nrcSummary, { ecuCode: (address) => `<code>${address}</code>`, formatTimeDelta: () => "+1.250s" }).includes("Invalid key"));
  assert.equal(renderer.validationTypeFilterMatch(findings[0], "hide-security-invalid-key"), true);
  assert.equal(renderer.validationTypeFilterMatch({
    ...findings[0],
    severity: "info",
    detail: `${findings[0].detail} A later matching SecurityAccess positive response was observed.`
  }, "hide-security-invalid-key"), false);
  assert.equal(renderer.validationSeverityClass("error"), "danger");
  assert.ok(renderer.findingRowHtml(findings[0], {
    selectedId: "VAL-1",
    ecuCode: (address) => `<code>${address}</code>`,
    formatTimeDelta: () => "+1.250s"
  }).includes('class="selected"'));
  assert.ok(renderer.findingRowHtml({ ...findings[0], detail: "long ".repeat(40) }, {
    selectedId: "VAL-1",
    ecuCode: (address) => `<code>${address}</code>`,
    formatTimeDelta: () => "+1.250s"
  }).includes("validation-finding-cell"));
  assert.ok(renderer.detailHtml(findings[0], { formatTimeDelta: () => "+1.250s" }).includes("Open source tool"));
}

function assertIdentityRendererContracts() {
  const renderer = loadIdentityRenderer();
  const identity = {
    findings: [{}, {}],
    groups: [
      {
        entityType: "Logical",
        entityId: "0x1001",
        role: "ECU",
        findings: [
          { severity: "high", title: "Logical conflict <x>", source: "DoIP", evidence: "aa & bb" },
          { severity: "medium", title: "IP drift", source: "UDS", evidence: "10.0.0.1" }
        ]
      }
    ],
    hostMap: [
      {
        mac: "aa:aa:aa:aa:aa:aa",
        roles: ["ECU"],
        ips: ["10.0.0.20"],
        dhcp: { messages: { Ack: 1 } },
        logicalAddresses: ["0x1001"]
      }
    ],
    metrics: { high: 1, medium: 1, hosts: 1, ipAddresses: 1, dhcpClients: 1, logicalAddresses: 1 }
  };

  assert.ok(renderer.summaryText(identity).includes("2 findings across 1"));
  assert.ok(renderer.metricsHtml(identity.metrics).includes("<strong>1</strong>"));
  assert.ok(renderer.findingsHtml(identity.groups, "high").includes("Logical conflict &lt;x&gt;"));
  assert.equal(renderer.findingsHtml(identity.groups, "low").includes("No findings for this filter"), true);
  assert.ok(renderer.hostMapHtml(identity.hostMap, { ecuCode: (address) => `<code>${address}</code>` }).includes("Ack: 1"));
}

function assertTransportRendererContracts() {
  const renderer = loadTransportRenderer();
  const flowKey = "10.0.0.10:50000 <-> 10.0.0.20:13400";
  const report = {
    doip: { announcements: [{ srcIp: "10.0.0.20", logicalAddress: "0x1001" }] },
    diagnostics: {
      udsEvents: [
        { direction: "request", srcIp: "10.0.0.10", dstIp: "10.0.0.20", srcPort: 50000, dstPort: 13400, source: "0x0e00", target: "0x1001", ecuAddress: "0x1001" },
        { direction: "response", srcIp: "10.0.0.20", dstIp: "10.0.0.10", srcPort: 13400, dstPort: 50000, source: "0x1001", target: "0x0e00", ecuAddress: "0x1001" }
      ]
    },
    hosts: {
      tester: { mac: "aa:aa:aa:aa:aa:aa", ips: ["10.0.0.10"] },
      gateway: { mac: "bb:bb:bb:bb:bb:bb", ips: ["10.0.0.20"] }
    }
  };
  const flow = {
    key: flowKey,
    endpointA: "10.0.0.10:50000",
    endpointB: "10.0.0.20:13400",
    packets: 4,
    retransmissions: 1,
    duplicateAcks: 6,
    zeroWindows: 0,
    windowUpdates: 1,
    p95AckLatency: 0.02,
    flowControl: { status: { label: "OK", severity: "ok", detail: "" } }
  };
  const identity = renderer.transportFlowIdentity(flow, report);
  const analysis = { gaps: [{ flowKey }], events: [{ flowKey, type: "Slow ACK" }] };
  const withIdentity = { ...flow, identity, health: renderer.transportHealth(flow, analysis) };

  assert.deepEqual(plain(renderer.parseTransportEndpoint("10.0.0.10:50000")), { ip: "10.0.0.10", port: "50000" });
  assert.equal(identity.tester.role, "Tester");
  assert.equal(identity.doipNode.role, "DoIP gateway/entity");
  assert.deepEqual(plain(identity.carriedLogicalAddresses), []);
  assert.ok(renderer.transportObservationSummary(flow).includes("retrans"));
  assert.equal(renderer.formatWindowBytes(1536), "1.5 KB");
  assert.equal(renderer.transportIssueMarkers(flow, analysis.events, analysis.gaps).length, 4);
  assert.equal(renderer.transportIssueClass("problem"), "danger");
  assert.equal(withIdentity.health.label, "TCP gap");
  assert.equal(renderer.filterTransportFlows([withIdentity], "warnings", analysis).length, 1);
  assert.equal(renderer.filterTransportFlows([withIdentity], "gaps", analysis).length, 1);
  assert.ok(renderer.endpointCell(identity.tester).includes("Tester"));
  assert.equal(renderer.healthClass("warning"), "warn");
  assert.ok(renderer.flowControlBadge({ label: "Zero window", severity: "problem", detail: "blocked" }).includes("danger"));
  assert.equal(renderer.niceWindowCeil(32769), 50000);
  assert.equal(renderer.flowControlChartMax([0, 1000, 1500, 2000, 250000], 32768), 50000);
  assert.equal(renderer.flowControlChartRatio(0, 50000, 4096), 0);
  assert.ok(renderer.flowControlChartRatio(1536, 50000, 4096) > 0.2);
  assert.ok(renderer.flowControlChartRatio(4096, 50000, 4096) > 0.6);
  assert.equal(renderer.flowControlChartRatio(50000, 50000, 4096), 1);
  assert.ok(renderer.endpointCard(identity.doipNode, "Node").includes("Ethernet logical"));
  assert.equal(renderer.summariseEventTypes([{ type: "A" }, { type: "A" }, { type: "B" }]), "2 A, 1 B");
}

function assertTopologyRendererContracts() {
  const renderer = loadTopologyRenderer();
  const topology = {
    nodes: [
      { id: "tester:1", role: "tester", label: "Tester", logicalAddress: "0x0e00", friendlyName: "", ips: ["10.0.0.10"], macs: [], eids: [], vins: [], packets: [1], evidence: ["request"], ambiguous: false },
      { id: "gateway:1", role: "gateway", label: "Gateway", logicalAddress: "0x1001", friendlyName: "Gateway ECU", ips: ["10.0.0.20"], macs: ["aa"], eids: ["aa"], vins: ["VIN"], packets: [2], evidence: ["announcement"], ambiguous: true },
      { id: "ecu:1", role: "ecu", label: "Body", logicalAddress: "0x2222", friendlyName: "Body ECU", ips: [], macs: [], eids: [], vins: [], packets: [3], evidence: ["inferred"], ambiguous: false }
    ],
    edges: [
      { id: "edge:1", source: "tester:1", target: "gateway:1", kind: "routing", label: "routing", count: 1, packets: [1], evidence: ["routing"], inferred: false, ambiguous: false },
      { id: "edge:2", source: "gateway:1", target: "ecu:1", kind: "inferred", label: "inferred", count: 2, packets: [2], evidence: ["via gateway"], inferred: true, ambiguous: true }
    ]
  };
  const positions = new Map([
    ["tester:1", { x: 100, y: 100 }],
    ["gateway:1", { x: 300, y: 100 }],
    ["ecu:1", { x: 500, y: 200 }]
  ]);

  assert.equal(renderer.label("abcdefghijklmnopqrstuvwxyz", 10), "abcdefg...");
  assert.equal(renderer.roleVisible(topology.nodes[1], { ambiguous: false, gateway: true }), false);
  assert.equal(renderer.edgeVisible(topology.edges[1], { inferred: false }), false);
  assert.equal(renderer.filteredTopology(topology, { roleState: { ambiguous: true }, edgeState: { routing: true, inferred: true } }).nodes.length, 3);
  assert.equal(renderer.gatewayGroups(topology, [topology.nodes[1]])[0].ecus[0].id, "ecu:1");
  assert.ok(renderer.edgePath({ x: 100, y: 100 }, { x: 300, y: 200 }, topology.edges[1]).includes("L"));
  assert.equal(renderer.edgeOffsets(topology.edges, positions).size, 2);
  assert.deepEqual(plain(renderer.edgeLabelPoint({ x: 0, y: 0 }, { x: 100, y: 100 })), { x: 55.00000000000001, y: 38 });
  assert.ok(renderer.detailHtml(topology, "gateway:1").includes("Gateway ECU"));
  assert.ok(renderer.detailHtml(topology, "edge:2").includes("Selected link"));
  const tables = renderer.tableHtml(topology);
  assert.ok(tables.gateway.includes("Gateway"));
  assert.ok(tables.ecuGateway.includes("Body"));
  assert.ok(tables.ambiguous.includes("Gateway"));

  const socketMap = {
    sockets: [{
      id: "socket:10.0.0.20",
      ip: "10.0.0.20",
      label: "Central Gateway / 10.0.0.20",
      directLogicalAddress: "0x1001",
      directName: "Central Gateway",
      observedIps: ["169.254.1.2", "10.0.0.20"],
      autoIpAddresses: ["169.254.1.2"],
      dhcpIpAddresses: ["10.0.0.20"],
      macs: ["aa:bb:cc:dd:ee:ff"],
      eids: ["11:22:33:44:55:66"],
      vins: ["VIN123"],
      evidence: ["Vehicle announcement 0x1001"],
      routingActivations: [{ packet: 7, timestamp: 7 }],
      routed: [{
        id: "socket:10.0.0.20|route:0x2222",
        logicalAddress: "0x2222",
        name: "Body ECU",
        requests: 2,
        packets: [2, 3],
        testers: ["0x0e00"],
        evidence: ["0x0e00 -> 0x2222"]
      }],
      rejected: [{
        id: "socket:10.0.0.20|rejected:0x4444",
        logicalAddress: "0x4444",
        name: "Rejected ECU",
        packets: [4],
        evidence: ["Rejected by 10.0.0.20"]
      }]
    }]
  };
  assert.ok(renderer.socketMapHtml(socketMap, "socket:10.0.0.20").includes("TCP socket endpoint"));
  assert.ok(renderer.socketMapHtml(socketMap, "socket:10.0.0.20").includes("has-rejected-targets"));
  assert.ok(renderer.socketMapHtml(socketMap, "socket:10.0.0.20").includes("Unknown target"));
  assert.equal(renderer.socketMapHtml(socketMap, "socket:10.0.0.20").includes("socket-graph"), false);
  assert.ok(renderer.socketNodeMapHtml(socketMap, "socket:10.0.0.20").includes("socket-graph"));
  assert.ok(renderer.socketNodeMapHtml(socketMap, "socket:10.0.0.20").includes("0x0e00"));
  assert.ok(renderer.socketNodeMapHtml(socketMap, "socket:10.0.0.20").includes("Other logical addresses"));
  assert.ok(renderer.socketNodeMapHtml(socketMap, "socket:10.0.0.20").includes("has-rejected-targets"));
  assert.ok(renderer.socketNodeMapHtml(socketMap, "socket:10.0.0.20").includes("rejected-node"));
  assert.ok(renderer.socketNodeMapHtml(socketMap, "socket:10.0.0.20").includes("Unknown target"));
  assert.ok(renderer.socketNodeMapHtml(socketMap, "socket:10.0.0.20").includes("NACK 0x03"));
  assert.ok(renderer.socketNodeMapHtml({
    sockets: [
      socketMap.sockets[0],
      { ...socketMap.sockets[0], id: "socket:10.0.0.30", ip: "10.0.0.30", directLogicalAddress: "0x2222", directName: "Body ECU", routed: [], rejected: [] }
    ]
  }, "socket:10.0.0.30").includes("Own TCP socket"));
  assert.ok(renderer.socketMapHtml(socketMap, "socket:10.0.0.20").includes("Routing active"));
  assert.ok(renderer.socketMapHtml(socketMap, "socket:10.0.0.20").includes("routing-active"));
  assert.ok(renderer.socketMapHtml(socketMap, "socket:10.0.0.20").includes("AutoIP"));
  assert.ok(renderer.socketMapHtml(socketMap, "socket:10.0.0.20|route:0x2222").includes("Body ECU"));
  assert.ok(renderer.socketMapHtml({ sockets: [] }).includes("No DoIP socket evidence decoded"));
  assert.ok(renderer.socketDetailHtml(socketMap, "socket:10.0.0.20").includes("Central Gateway"));
  assert.ok(renderer.socketDetailHtml(socketMap, "socket:10.0.0.20").includes("activation packet"));
  assert.ok(renderer.socketDetailHtml(socketMap, "socket:10.0.0.20|route:0x2222").includes("Routed logical address"));
  assert.ok(renderer.socketDetailHtml(socketMap, "socket:10.0.0.20|route:0x2222").includes("2 packets observed"));
  assert.equal(renderer.socketDetailHtml(socketMap, "socket:10.0.0.20|route:0x2222").includes("<dt>Packets</dt>"), false);
  assert.ok(renderer.socketDetailHtml(socketMap, "socket:10.0.0.20|rejected:0x4444").includes("Rejected target"));
  const socketTables = renderer.socketTableHtml(socketMap);
  assert.ok(socketTables.sockets.includes("0x1001"));
  assert.ok(socketTables.mappings.includes("rejected"));
}

function assertDiagnosticsRendererContracts() {
  const renderer = loadDiagnosticsRenderer();
  const transfers = [{
    id: 1,
    direction: "download",
    request: { memoryAddress: "0x1000", memorySize: 4 },
    expectedBlocks: 2,
    blocks: 2,
    acknowledgedBlocks: 1,
    reconstructedBytes: 4,
    pending: 0,
    negatives: 0,
    missingSequences: ["0x02"],
    status: "completed with gaps"
  }];
  const routineEvents = [
    {
      id: 1,
      timestamp: 1,
      packet: 10,
      responseKind: "request",
      service: "0x31",
      serviceName: "Routine Control",
      subFunction: "0x01",
      direction: "request",
      routineId: "0x0203",
      raw: "31 01 02 03 aa bb"
    },
    {
      id: 2,
      timestamp: 1.1,
      packet: 11,
      responseKind: "positive",
      service: "0x71",
      serviceName: "Routine Control Response",
      subFunction: "0x01",
      direction: "response",
      routineId: "0x0203",
      raw: "71 01 02 03"
    }
  ];

  assert.equal(renderer.routineControlLabel("0x01"), "Start routine");
  assert.equal(renderer.routineOptionBytes("31 01 02 03 aa bb"), "aa bb");
  assert.ok(renderer.transferExpectationHtml(transfers[0]).includes("Expected 2"));
  assert.equal(renderer.transferStatusClass(transfers[0]), "warn");
  assert.ok(renderer.renderEcuTransfers(transfers).includes("completed with gaps"));
  assert.ok(renderer.renderEcuOverview({
    address: "0x1001",
    requests: 2,
    responses: 1,
    pending: 0,
    negatives: 0,
    didCount: 1,
    transferCount: 1,
    serviceStats: { "0x22 Read": 1 },
    nrcStats: {},
    firstTimestamp: 1,
    lastTimestamp: 2
  }, {
    events: routineEvents,
    didReads: [{ did: "0xf190" }],
    transfers,
    barsHtml: (object) => Object.keys(object || {}).join(",")
  }).includes("Service Distribution"));
  assert.ok(renderer.renderEcuOverview({
    address: "0x1001",
    requests: 1,
    responses: 1,
    pending: 0,
    negatives: 0,
    didCount: 0,
    transferCount: 0,
    serviceStats: {},
    nrcStats: {},
    firstTimestamp: 0,
    lastTimestamp: 65
  }, {
    events: [],
    didReads: [],
    transfers: [],
    barsHtml: () => ""
  }).includes("1m 5.0s"));
  assert.deepEqual(plain(renderer.baseServiceDistribution([
    { service: "0x36", serviceName: "Transfer Data" },
    { service: "0x76", serviceName: "Transfer Data Response", originalService: "0x36", originalServiceName: "Transfer Data" },
    { service: "0x67", serviceName: "Security Access Response", originalService: "0x27", originalServiceName: "Security Access" },
    { service: "0x7f", serviceName: "Negative Response", originalService: "0x27", originalServiceName: "Security Access" }
  ])), {
    "0x36 Transfer Data": 2,
    "0x27 Security Access": 2
  });
  assert.equal(renderer.baseServiceKey({ service: "0x76", serviceName: "Transfer Data Response" }), "0x36 Transfer Data");
  assert.deepEqual(plain(renderer.serviceBreakdown([
    { service: "0x36", serviceName: "Transfer Data", responseKind: "request", timestamp: 1, packet: 10 },
    { service: "0x76", serviceName: "Transfer Data Response", responseKind: "positive", timestamp: 2, packet: 11 },
    { service: "0x7f", serviceName: "Negative Response", originalService: "0x36", originalServiceName: "Transfer Data", responseKind: "negative", timestamp: 3, packet: 12 }
  ])[0]), {
    key: "0x36 Transfer Data",
    service: "0x36",
    name: "Transfer Data",
    total: 3,
    requests: 1,
    positives: 1,
    pending: 0,
    negatives: 1,
    firstTimestamp: 1,
    lastTimestamp: 3,
    packets: [10, 11, 12]
  });
  assert.ok(renderer.renderEcuServices({ serviceStats: {} }, {
    events: [
      { service: "0x36", serviceName: "Transfer Data", responseKind: "request", timestamp: 1, packet: 10 },
      { service: "0x76", serviceName: "Transfer Data Response", responseKind: "positive", timestamp: 2, packet: 11 }
    ],
    formatTimeDelta: () => "+1.000s"
  }).includes("Positive responses"));
  assert.equal(renderer.renderEcuTimeline(routineEvents, { renderCompactTimeline: (events) => `timeline ${events.length}` }), "timeline 2");
  assert.ok(renderer.renderEcuDids([{
    did: "0xf190",
    name: "VIN",
    reads: 1,
    responses: 1,
    negatives: 0,
    latestValueAscii: "VIN123",
    latestValueHex: "56 49 4e",
    firstTimestamp: 1,
    lastTimestamp: 2,
    events: [{ service: "0x62", responseKind: "positive", timestamp: 2, packet: 20, source: "0x1001", target: "0x0e80", valueAscii: "VIN123", valueHex: "56 49 4e", raw: "62 f1 90 56" }]
  }], {
    ecuAddress: "0x1001",
    expandedDidGroups: new Set(["0x1001|0xf190"]),
    didPlotStatus: () => ({ plottable: true, reason: "single byte" }),
    truncateMiddle: (value) => value,
    formatTimeDelta: () => "+1.000s",
    ecuLabel: (address) => address
  }).includes("Plot value"));
  assert.ok(renderer.renderEcuDids([{
    did: "0xf191",
    name: "Long",
    reads: 1,
    responses: 1,
    negatives: 0,
    latestValueAscii: "",
    latestValueHex: "aa ".repeat(120),
    firstTimestamp: 1,
    lastTimestamp: 2,
    events: []
  }], {
    ecuAddress: "0x1001",
    expandedDidGroups: new Set(),
    didPlotStatus: () => ({ plottable: false, reason: "" }),
    truncateMiddle: (value, limit) => value.length > limit ? `${value.slice(0, limit)}...` : value,
    formatTimeDelta: () => "+1.000s",
    ecuLabel: (address) => address
  }).includes("did-hex-preview"));
  assert.ok(renderer.renderEcuDtcs({ address: "0x1001" }, {
    rows: [
      { ecuAddress: "0x1001", recordType: "dtcRecord", responseKind: "positive", dtc: "P0001", service: "0x59", serviceName: "DTC response", timestamp: 1, packet: 30, source: "0x1001", target: "0x0e80", raw: "59 02" },
      { ecuAddress: "0x1001", recordType: "snapshot", responseKind: "positive", dtc: "P0001", snapshotRecordNumber: "0x01", dataLength: 80, payloadAscii: "", payloadHex: "aa ".repeat(120), service: "0x59", serviceName: "DTC response", timestamp: 1.2, packet: 31, source: "0x1001", target: "0x0e80", raw: "59 04" }
    ],
    summary: [{ ecuAddress: "0x1001", dtc: "P0001", status: "0x01", statusLabels: "test failed", responses: 1, firstTimestamp: 1, lastTimestamp: 2, latestPacket: 30, persistentAfterClear: true, clearGroup: "FFFFFF", clearPacket: 10, clearTimestamp: 0.5 }]
  }, {
    formatTimeDelta: () => "+1.000s",
    ecuLabel: (address) => address,
    truncateMiddle: (value, limit) => value.length > limit ? `${value.slice(0, limit)}...` : value
  }).includes("Persisted after clear"));
  assert.ok(renderer.renderEcuRoutines(routineEvents, {
    ecuAddress: "0x1001",
    routineName: () => "Erase memory",
    formatTimeDelta: () => "+1.000s"
  }).includes("Erase memory"));
  assert.ok(renderer.renderEcuServices({ serviceStats: { "0x22 Read Data": 1 } }, { events: [], formatTimeDelta: () => "" }).includes("Read Data"));
  assert.equal(renderer.renderEcuErrors({ nrcStats: { B: 1 } }, { barsHtml: (object) => Object.keys(object).join("") }), "B");
  assert.ok(renderer.renderEcuRaw(routineEvents, {
    formatTimeDelta: () => "+1.000s",
    ecuLabel: (address) => `ECU ${address}`
  }).includes("Routine Control"));
  assert.ok(renderer.renderEcuRaw([{ ...routineEvents[0], raw: "31 ".repeat(80) }], {
    formatTimeDelta: () => "+1.000s",
    ecuLabel: (address) => `ECU ${address}`
  }).includes("raw-uds-cell"));
  assert.ok(renderer.renderEcuRaw([{ ...routineEvents[0], raw: "31 ".repeat(80) }], {
    formatTimeDelta: () => "+1.000s",
    ecuLabel: (address) => `ECU ${address}`
  }).includes("<details"));
}

function assertTraceRendererContracts() {
  const trace = loadTraceRenderer();
  const events = [
    { id: 1, category: "arp", type: "request", label: "ARP request", laneKey: "arp:1", timestamp: 2 },
    { id: 2, category: "uds", type: "request", label: "UDS request", laneKey: "ecu:1", timestamp: 1 },
    { id: 3, category: "transport", type: "Slow ACK", label: "Slow ACK", laneKey: "ecu:1", timestamp: 3 }
  ];
  const history = {
    events: [
      { id: 10, service: "0x62", responseKind: "positive", valueHex: "0a", timestamp: 1, packet: 10 },
      { id: 11, service: "0x62", responseKind: "positive", valueHex: "0b", timestamp: 2, packet: 11 }
    ]
  };
  const state = {};
  const grouped = trace.advancedGroups(events, state);

  assert.equal(trace.traceTypeKey(events[1]), "uds:request");
  assert.equal(trace.traceCategoryLabel("ack"), "DoIP ACK/NAK");
  assert.equal(trace.traceCategoryRank("doip") < trace.traceCategoryRank("uds"), true);
  assert.deepEqual(plain(trace.removeArpOnlyTraceLanes(events)), { events: [events[1], events[2]], hiddenLanes: 1, hiddenEvents: 1 });
  assert.deepEqual(plain(trace.layerCounts(events)), { arp: 1, uds: 1, transport: 1 });
  assert.ok(trace.renderLayerCounts(events).includes("UDS"));
  assert.equal(grouped.get("uds").get("uds:request").count, 1);
  assert.equal(state["uds:request"], true);
  assert.ok(trace.renderAdvancedPanel(events, state).includes("trace-type-toggle"));
  assert.equal(trace.traceLayerEnabled(events[1], { uds: true }, state), true);
  const viewport = trace.buildTraceViewport(events, {
    traceLayerState: { uds: true, doip: true, dhcp: true, arp: true, ack: true, transport: true },
    traceTypeState: state,
    ecuFilter: "all",
    kindFilter: "all",
    traceCompareSelection: [2],
    traceLinkedEventIds: { primary: 2, pair: new Set(), pending: new Set() },
    formatTimeDelta: (value) => `+${value}s`,
    formatBytes: (value) => `${value} B`,
    ecuLabel: (address) => address
  });
  assert.equal(viewport.visibleEvents.length, 2);
  assert.ok(viewport.html.includes("trace-slice"));
  assert.ok(viewport.summaryText.includes("visible"));
  assert.equal(trace.traceTransferSummary({ type: "Transfer Data", blockCounter: 2, dataLength: 4 }), "Transfer Data - block 2 - 4 B");
  assert.equal(trace.traceLatencyLabel({ timestamp: 1 }, { timestamp: 1.25 }), "250.000 ms");
  assert.ok(trace.renderTraceTooltipContent({
    category: "uds",
    label: "UDS request",
    timestamp: 1,
    laneLabel: "ECU 0x1001",
    responseKind: "request",
    service: "0x22",
    serviceName: "Read Data",
    packet: 10,
    raw: "22 f1 90"
  }, {
    formatTimeDelta: () => "+1.000s",
    relation: { udsEvent: { id: 1, direction: "request" }, request: { id: 1, packet: 10 }, finalResponse: null, pendingResponses: [] }
  }).includes("No paired response observed"));
  assert.deepEqual(plain(trace.didPlotSamples(history)), [
    { eventId: 10, timestamp: 1, packet: 10, hex: "0x0a", value: 10 },
    { eventId: 11, timestamp: 2, packet: 11, hex: "0x0b", value: 11 }
  ]);
  assert.equal(trace.didPlotStatus(history).plottable, true);
  assert.equal(trace.truncateMiddle("abcdefghijklmnopqrstuvwxyz", 12), "abcd ... xyz");
  assert.ok(trace.renderCompactTimeline([{ responseKind: "positive", timestamp: 1, source: "0x01", target: "0x02", service: "0x62", serviceName: "Read", raw: "62" }], {
    formatTimeDelta: () => "+1.000s",
    ecuLabel: (address) => address
  }).includes("timeline-item"));
}

function assertDownloadRendererContracts() {
  const renderer = loadDownloadRenderer();
  const session = {
    id: 7,
    ecuAddress: "0x1001",
    testerAddress: "0x0e80",
    sessionType: "download",
    progress: 0.5,
    reconstructedBytes: 128,
    requestedBytes: 256,
    hexExportable: true,
    expectedBlocks: 3,
    blocks: 2,
    acknowledgedBlocks: 1,
    pending: 0,
    negatives: 0,
    status: "completed",
    startTimestamp: 1,
    endTimestamp: 2,
    dataBlocks: [
      { eventId: 1, counter: "0x01", direction: "request", packet: 10, timestamp: 1, payloadBytes: 64, payloadHex: "aa".repeat(64) },
      { eventId: 2, counter: "0x02", direction: "request", packet: 11, timestamp: 1.5, payloadBytes: 64, payloadHex: "bb" }
    ],
    ackBlocks: [{ requestEventId: 1, counter: "0x01", packet: 12, timestamp: 1.1 }],
    ackObservedEvents: [{ counter: "0x02", packet: 13, timestamp: 1.6 }],
    duplicateCounters: ["0x02"],
    events: [
      { id: 1, timestamp: 1, packet: 10, responseKind: "request", serviceName: "Transfer Data", raw: "36 01 aa" }
    ],
    validation: []
  };

  assert.equal(renderer.downloadSeverityClass("error"), "danger");
  assert.equal(renderer.downloadSeverityClass("warning"), "warn");
  assert.equal(renderer.formatTimelineDuration(0.25), "250 ms");
  assert.equal(renderer.formatTimelineDuration(12), "12.0 s");
  assert.deepEqual(plain(renderer.layoutCampaignSessions([
    { id: "a", startTimestamp: 0, endTimestamp: 5 },
    { id: "b", startTimestamp: 2, endTimestamp: 3 },
    { id: "c", startTimestamp: 5, endTimestamp: 6 }
  ])).items.map((item) => [item.session.id, item.row]), [["a", 0], ["b", 1], ["c", 0]]);
  assert.deepEqual(plain(renderer.campaignTimelineDomain([
    { startTimestamp: 0, endTimestamp: 5 },
    { startTimestamp: 10, endTimestamp: 10 }
  ])), { start: 0, end: 10, duration: 10 });
  assert.deepEqual(plain(renderer.timelineSessionBounds(
    { startTimestamp: 10, endTimestamp: 10 },
    { start: 0, end: 10 }
  )), {
    rawStart: 10,
    rawEnd: 10,
    start: 10,
    end: 10,
    leftPercent: 100,
    widthPercent: 0,
    durationSeconds: 0,
    clipped: false
  });
  assert.equal(renderer.niceAxisMax(240), 500);
  assert.deepEqual(plain(renderer.compactRateBuckets([
    { start: 0, end: 1, seconds: 1, bytes: 100 },
    { start: 1, end: 2, seconds: 1, bytes: 200 },
    { start: 2, end: 3, seconds: 1, bytes: 300 }
  ], 2)), [
    { index: 0, start: 0, end: 2, seconds: 2, bytes: 300, rateBps: 150 },
    { index: 1, start: 2, end: 3, seconds: 1, bytes: 300, rateBps: 300 }
  ]);
  assert.deepEqual(plain(renderer.didValueDomain(10, 10)), { min: 8, max: 12 });
  assert.deepEqual(plain(renderer.numericTicks(0, 10, 5)), [0, 5, 10]);
  assert.deepEqual(plain(renderer.timeSampleTicks([{ id: 1 }, { id: 2 }, { id: 3 }, { id: 4 }], 3).map((item) => item.id)), [1, 3, 4]);
  assert.equal(renderer.compactTimeAxisLabel("+123.000s"), "+2m03s");
  assert.equal(renderer.compactTimeAxisLabel("+12.500s"), "+12s");
  assert.ok(renderer.didAxisTickCount(760, ["+123.000s", "+124.000s", "+125.000s"]) <= 6);
  assert.ok(renderer.renderDidLineChart([{ timestamp: 1, value: 10, packet: 1, hex: "0x0a" }, { timestamp: 2, value: 11, packet: 2, hex: "0x0b" }], { formatTimeDelta: () => "+1.000s" }).includes("did-line-chart"));
  const longLabelChart = renderer.renderDidLineChart(
    Array.from({ length: 8 }, (_, index) => ({ timestamp: index * 60, value: 10 + index, packet: index + 1, hex: "0x0a" })),
    { formatTimeDelta: (timestamp) => `+${Number(timestamp).toFixed(3)}s` }
  );
  assert.ok(longLabelChart.includes("<title>+180.000s</title>+3m00s"));
  assert.equal(longLabelChart.includes(">+180.000s</text>"), false);
  assert.ok(renderer.renderDidPlotModal({}, [{ timestamp: 1, value: 10, packet: 1, hex: "0x0a" }, { timestamp: 2, value: 11, packet: 2, hex: "0x0b" }], { formatTimeDelta: () => "+1.000s" }).includes("Samples"));
  assert.ok(renderer.renderDirectionDiagram(session, { ecuCode: (address) => `ECU ${address}` }).includes("Tester payload via 0x36"));
  assert.ok(renderer.renderPayloadProgress(session).includes("128 of 256 bytes (50%)"));
  assert.ok(renderer.renderBlockStrip(session).includes("block-slot observed duplicate"));
  const wrappedSlots = renderer.blockStripSlots({
    expectedBlocks: 256,
    blocks: 256,
    dataBlocks: Array.from({ length: 256 }, (_, index) => {
      const counter = (index + 1) & 0xff;
      return { counter: `0x${counter.toString(16).padStart(2, "0")}`, packet: index + 1, timestamp: index };
    })
  });
  assert.equal(wrappedSlots.length, 256);
  assert.deepEqual(plain(wrappedSlots[0]), { ordinal: 1, counter: "0x01", state: "observed", classes: "observed", repeatCount: 0, observations: 1, required: true });
  assert.deepEqual(plain(wrappedSlots[254]), { ordinal: 255, counter: "0xff", state: "observed", classes: "observed", repeatCount: 0, observations: 1, required: true });
  assert.deepEqual(plain(wrappedSlots[255]), { ordinal: 256, counter: "0x00", state: "observed", classes: "observed", repeatCount: 0, observations: 1, required: true });
  assert.ok(renderer.renderBlockStrip({ expectedBlocks: 256, blocks: 256, dataBlocks: wrappedSlots.map((slot) => ({ counter: slot.counter })) }).includes("Block 0x00: observed"));
  const gapSlots = renderer.blockStripSlots({
    expectedBlocks: 3,
    blocks: 2,
    dataBlocks: [
      { counter: "0x01", packet: 1, timestamp: 1 },
      { counter: "0x03", packet: 2, timestamp: 2 }
    ]
  });
  assert.equal(gapSlots.length, 256);
  assert.deepEqual(plain([gapSlots[0].state, gapSlots[1].state, gapSlots[2].state, gapSlots[3].state]), ["observed", "missing", "observed", "not-required"]);
  assert.equal(gapSlots[3].classes, "unused");
  const repeatedSlots = renderer.blockStripSlots({
    expectedBlocks: 3,
    blocks: 4,
    dataBlocks: [
      { counter: "0x01", packet: 1, timestamp: 1 },
      { counter: "0x02", packet: 2, timestamp: 2 },
      { counter: "0x02", packet: 3, timestamp: 3 },
      { counter: "0x03", packet: 4, timestamp: 4 }
    ]
  });
  assert.equal(repeatedSlots.length, 256);
  assert.deepEqual(plain([repeatedSlots[0].state, repeatedSlots[1].state, repeatedSlots[2].state]), ["observed", "repeated", "observed"]);
  assert.equal(repeatedSlots[1].repeatCount, 1);
  assert.equal(repeatedSlots[1].observations, 2);
  assert.equal(repeatedSlots[1].classes, "observed repeat");
  assert.equal(renderer.blockSlotTitle(repeatedSlots[1]), "Block 0x02: repeated, 1 repeated observation");
  assert.ok(renderer.renderBlockStrip({ dataBlocks: repeatedSlots.filter((slot) => slot.observations).flatMap((slot) => Array.from({ length: slot.observations }, () => ({ counter: slot.counter }))) }).includes(">2</span>"));
  const duplicateSlots = renderer.blockStripSlots({
    dataBlocks: [{ counter: "0x02", packet: 2, timestamp: 2 }],
    duplicateCounters: ["0x02"]
  });
  assert.equal(duplicateSlots[0].state, "duplicate");
  assert.equal(duplicateSlots[0].classes, "observed duplicate");
  assert.ok(renderer.renderGroupedDownloadRows([{ key: "gw", label: "Gateway", sessions: [session] }], [session], { ecuCode: (address) => address, selectedDownloadSessionId: 7 }).includes("download-group-row"));
  assert.ok(renderer.renderDownloadOverview(session, { ecuCode: (address) => address }).includes("Payload Progress"));
  assert.ok(renderer.renderDownloadOverview({ ...session, status: "open" }, { ecuCode: (address) => address }).includes("TransferExit missing"));
  assert.equal(renderer.campaignPeakParallelism([{ startTimestamp: 1, endTimestamp: 3 }, { startTimestamp: 2, endTimestamp: 4 }]), 2);
  assert.ok(renderer.renderDownloadCampaignSummary([session], { ecuLabel: (address) => address, ecuCode: (address) => address }).includes("Gateway/IP Rollup"));
  assert.ok(renderer.renderDownloadMatrix([{
    groupLabel: "Gateway",
    ecuAddress: "0x1001",
    sessionIds: [7],
    sessions: 1,
    downloads: 1,
    uploads: 0,
    fileTransfers: 0,
    payloadBytes: 128,
    blockAgreement: "pass",
    nrcs: 0,
    captureWarnings: 0,
    exportable: 1,
    severity: "ok"
  }], { selectedDownloadSessionId: 7, ecuCode: (address) => address }).includes("download-matrix"));
  assert.deepEqual(plain(renderer.buildRateTimingRows(session)).map((row) => [row.counter, row.ackStatus]), [["0x01", "paired"], ["0x02", "observed"]]);
  assert.ok(renderer.renderRateChart([{ start: 1, end: 2, seconds: 1, bytes: 64, rateBps: 64 }], session, { formatTimeDelta: () => "+1.000s" }).includes("rate-line-chart"));
  assert.ok(renderer.renderDownloadRate({ ...session, rate: { rateBuckets: [{ start: 1, end: 2, seconds: 1, bytes: 64, rateBps: 64 }] } }, { formatTimeDelta: () => "+1.000s" }).includes("Campaign comparison"));
  assert.ok(renderer.renderDownloadBlocks(session).includes("ACK packet 12"));
  const mappedTimeline = renderer.renderDownloadTimeline([session], { selectedDownloadSessionId: 7, ecuLabel: (address) => `Gateway (${address})` });
  assert.ok(mappedTimeline.includes("campaign-bar"));
  assert.ok(mappedTimeline.includes("Gateway (0x1001)"));
  const failedAtBoundary = { ...session, id: 8, startTimestamp: 10, endTimestamp: 10, severity: "error", status: "open" };
  const boundaryTimeline = renderer.renderDownloadTimeline([
    { ...session, id: 9, startTimestamp: 0, endTimestamp: 5 },
    failedAtBoundary
  ], { selectedDownloadSessionId: 8, ecuLabel: (address) => address });
  assert.ok(boundaryTimeline.includes('data-download-session="8"'));
  assert.ok(boundaryTimeline.includes("left:99.3%;width:0.7%"));
  const exportModel = renderer.buildDownloadTimelineExportModel([session], { ecuLabel: (address) => `Gateway (${address})` });
  assert.equal(exportModel.laidOut.length, 1);
  assert.equal(exportModel.laidOut[0].ecu, "Gateway (0x1001)");
  assert.equal(exportModel.width, 1400);
  assert.equal(renderer.timelineExportColours({ getPropertyValue: (name) => name === "--warning" ? "#abc" : "" }).warning, "#abc");
  const drawOps = [];
  const fakeCtx = {
    set fillStyle(value) { drawOps.push(["fillStyle", value]); },
    set strokeStyle(value) { drawOps.push(["strokeStyle", value]); },
    set font(value) { drawOps.push(["font", value]); },
    set textBaseline(value) { drawOps.push(["textBaseline", value]); },
    fillRect(...args) { drawOps.push(["fillRect", ...args]); },
    strokeRect(...args) { drawOps.push(["strokeRect", ...args]); },
    beginPath() { drawOps.push(["beginPath"]); },
    moveTo(...args) { drawOps.push(["moveTo", ...args]); },
    lineTo(...args) { drawOps.push(["lineTo", ...args]); },
    stroke() { drawOps.push(["stroke"]); },
    fillText(...args) { drawOps.push(["fillText", ...args]); },
    measureText(text) { return { width: String(text).length * 6 }; }
  };
  renderer.drawDownloadTimelineExport(fakeCtx, exportModel, renderer.timelineExportColours(), { formatTimeDelta: () => "+1.000s", firstTimestamp: 1 });
  assert.ok(drawOps.some((op) => op[0] === "fillText" && String(op[1]).includes("Harness Software Download")));
  assert.ok(drawOps.some((op) => op[0] === "fillText" && String(op[1]).includes("Gateway (0x1001)")));
  const boundaryModel = renderer.buildDownloadTimelineExportModel([
    { ...session, id: 9, startTimestamp: 0, endTimestamp: 5 },
    failedAtBoundary
  ]);
  const boundaryOps = [];
  const boundaryCtx = {
    set fillStyle(value) { boundaryOps.push(["fillStyle", value]); },
    set strokeStyle(value) { boundaryOps.push(["strokeStyle", value]); },
    set font(value) { boundaryOps.push(["font", value]); },
    set textBaseline(value) { boundaryOps.push(["textBaseline", value]); },
    fillRect(...args) { boundaryOps.push(["fillRect", ...args]); },
    strokeRect(...args) { boundaryOps.push(["strokeRect", ...args]); },
    beginPath() { boundaryOps.push(["beginPath"]); },
    moveTo(...args) { boundaryOps.push(["moveTo", ...args]); },
    lineTo(...args) { boundaryOps.push(["lineTo", ...args]); },
    stroke() { boundaryOps.push(["stroke"]); },
    fillText(...args) { boundaryOps.push(["fillText", ...args]); },
    measureText(text) { return { width: String(text).length * 6 }; }
  };
  renderer.drawDownloadTimelineExport(boundaryCtx, boundaryModel, renderer.timelineExportColours(), { firstTimestamp: 0 });
  const plotRight = boundaryModel.laneLabelWidth + 24 + boundaryModel.plotWidth;
  const boundaryBars = boundaryOps.filter((op) => op[0] === "fillRect" && op[4] === 22);
  assert.ok(boundaryBars.length >= 2);
  assert.ok(boundaryBars.every((op) => op[1] + op[3] <= plotRight));
  assert.equal(renderer.conditionServiceGroup({ service: "0x27" }), "Security access");
  assert.equal(renderer.conditionDetail({ subFunction: "0x01", routineId: "0x0203", nrc: "0x78", nrcName: "Response pending" }), "sub 0x01 | routine 0x0203 | NRC 0x78 Response pending");
  assert.equal(renderer.downloadConditionEvents(session, [{ ecuAddress: "0x1001", testerAddress: "0x0e80", service: "0x10", timestamp: 0.5 }])[0].phase, "Pre");
  assert.ok(renderer.renderDownloadConditions(session, [{ ecuAddress: "0x1001", testerAddress: "0x0e80", service: "0x10", serviceName: "Session", responseKind: "request", timestamp: 0.5, packet: 1, raw: "10 03" }], { formatTimeDelta: () => "+0.500s" }).includes("Diagnostic session"));
  assert.ok(renderer.renderDownloadConditions(session, [{ ecuAddress: "0x1001", testerAddress: "0x0e80", service: "0x10", serviceName: "Session", responseKind: "request", timestamp: 0.5, packet: 1, raw: "10 ".repeat(80) }], { formatTimeDelta: () => "+0.500s" }).includes("raw-uds-cell"));
  assert.ok(renderer.renderSequenceHealth(session).includes("Assigned 0x76 responses"));
  assert.ok(renderer.renderDownloadValidation(session).includes("No validation issues found"));
  assert.ok(renderer.renderDownloadValidation({
    ...session,
    validation: [{ severity: "warning", category: "Completeness", title: "Gap", detail: "Missing block", packet: 99 }]
  }).includes("Missing block"));
  assert.ok(renderer.renderDownloadRaw(session, { formatTimeDelta: () => "+1.000s" }).includes("Transfer Data"));
  assert.ok(renderer.renderDownloadRaw({ ...session, events: [{ ...session.events[0], raw: "36 ".repeat(80) }] }, { formatTimeDelta: () => "+1.000s" }).includes("<details"));
}

function assertDownloadControllerContracts() {
  const controllerApi = loadDownloadController();
  const elements = {
    downloadGatewayFilter: fakeElement(),
    downloadGatewaySummary: fakeElement(),
    downloadGatewayOptions: fakeElement(),
    downloadTypeFilter: fakeElement(),
    downloadSeverityFilter: fakeElement(),
    downloadExportableOnly: fakeElement(),
    downloadEcuSummary: fakeElement(),
    downloadEcuOptions: fakeElement(),
    downloadSummary: fakeElement(),
    downloadMetrics: fakeElement(),
    downloadSessionTable: fakeElement(),
    downloadDetailHead: fakeElement(),
    downloadTabContent: fakeElement({ dataset: {} })
  };
  const report = {
    summary: { firstTimestamp: 1 },
    diagnostics: { udsEvents: [] },
    downloadAnalysis: {
      metrics: { exportable: 1, warnings: 0, errors: 0, downloads: 1 },
      groups: [{ key: "gw", label: "Gateway", sessions: [] }],
      matrixRows: [{
        groupKey: "gw",
        groupLabel: "Gateway",
        ecuAddress: "0x1001",
        sessionIds: [7],
        sessions: 1,
        downloads: 1,
        uploads: 0,
        fileTransfers: 0,
        payloadBytes: 128,
        blockAgreement: "pass",
        nrcs: 0,
        captureWarnings: 0,
        exportable: 1,
        severity: "ok"
      }],
      sessions: [{
        id: 7,
        ecuAddress: "0x1001",
        testerAddress: "0x0e80",
        gatewayIp: "gw",
        typeLabel: "RequestDownload",
        sessionType: "download",
        severity: "ok",
        startTimestamp: 1,
        endTimestamp: 2,
        hexExportable: true
      }]
    }
  };
  const controller = controllerApi.createDownloadController({
    $: (id) => elements[id] || null,
    getReport: () => report,
    buildDownloadAnalysis: () => report.downloadAnalysis,
    ecuCode: (address) => `ECU ${address}`,
    ecuLabel: (address) => address,
    ecuName: () => "",
    formatTimeDelta: (value) => `+${value}s`,
    didHistoryForEcu: () => [],
    downloadText() {},
    downloadHexText: () => ""
  });

  controller.state.selectedEcus.add("0xdead");
  controller.state.selectedGateways.add("stale-gateway");
  controller.render(report);

  assert.equal(controller.state.selectedEcus.size, 0, "stale ECU filters should be pruned before filtering sessions");
  assert.equal(controller.state.selectedGateways.size, 0, "stale gateway/IP filters should be pruned before filtering sessions");
  assert.equal(controller.state.selectedSessionId, 7);
  assert.ok(elements.downloadSummary.textContent.includes("1 transfer segments"));
  assert.ok(elements.downloadDetailHead.innerHTML.includes("RequestDownload"));
}

function assertTraceControllerContracts() {
  const controllerApi = loadTraceController();
  const elements = {
    traceEcuFilter: fakeElement(),
    traceViewport: fakeElement(),
    traceKindFilter: fakeElement(),
    traceAdvancedToggle: fakeElement(),
    traceAdvancedPanel: fakeElement(),
    traceSummary: fakeElement(),
    traceWindow: fakeElement(),
    traceZoomReset: fakeElement(),
    traceZoomBack: fakeElement(),
    traceLayerCounts: fakeElement(),
    traceCompareDelta: fakeElement(),
    traceCompareClear: fakeElement(),
    traceMeasureToggle: fakeElement()
  };
  const report = {
    diagnostics: {
      ecus: { "0x1001": { address: "0x1001", requests: 1, responses: 1 } },
      udsEvents: [
        { id: 1, direction: "request", responseEventId: 2, packet: 10, timestamp: 1 },
        { id: 2, direction: "response", requestEventId: 1, responseKind: "positive", packet: 11, timestamp: 1.1 }
      ]
    }
  };
  const traceEvent = { id: "t1", category: "uds", udsEventId: 1, timestamp: 1, laneKey: "ecu:0x1001" };
  const controller = controllerApi.createTraceController({
    $: (id) => elements[id] || null,
    getReport: () => report,
    traceEventsForReport: () => [traceEvent],
    formatTimeDelta: (value) => `+${value}s`,
    escapeHtml: (value) => String(value ?? ""),
    ecuLabel: (address) => address,
    openEcuTimeline() {}
  });

  controller.render(report);
  assert.ok(elements.traceSummary.textContent.includes("visible"));
  assert.equal(controller.relationshipForEvent(traceEvent).finalResponse.id, 2);

  controller.bindControls();
  elements.traceMeasureToggle.dispatch("click");
  assert.equal(controller.state.measureMode, true);
  assert.equal(elements.traceCompareDelta.textContent, "Select first marker");
}

async function assertPersistenceContracts() {
  const persistence = loadPersistence();
  const config = { dbName: "harness-test", storeName: "captures", key: "last-report", version: 1 };
  await assert.rejects(() => persistence.openPersistDb(config), /IndexedDB unavailable/);
  assert.equal(await persistence.loadPersistedReport(config), null);
  let warning = "";
  await persistence.persistReport({ summary: {} }, config, { warn: (message) => { warning = message; } });
  assert.equal(warning, "Harness could not retain the loaded pcap report.");
  warning = "";
  await persistence.clearPersistedReport(config, { warn: (message) => { warning = message; } });
  assert.equal(warning, "Harness could not clear the retained pcap report.");
}

function assertExporterContracts() {
  const exporters = loadExporters();
  const report = {
    diagnostics: {
      didReads: [{ ecuAddress: "0x1001", did: "0xf190", name: "VIN" }],
      dtcReads: { rows: [{ ecuAddress: "0x1001", dtc: "P0001" }] },
      transfers: [{ id: 1, ecuAddress: "0x1001" }]
    },
    downloadAnalysis: {
      sessions: [{
        id: 2,
        ecuAddress: "0x1001",
        ecuName: "ECU",
        sessionType: "download",
        validation: [{ severity: "warning", category: "Completeness", title: "Gap", detail: "Missing", packet: 12 }]
      }]
    },
    validationCentre: { findings: [] },
    tcpAnalysis: {
      flows: [{ key: "a:1 <-> b:2", flowControl: { status: { label: "OK", severity: "ok" }, directions: [] } }],
      events: [{ id: 1, flowKey: "a:1 <-> b:2", type: "Handshake" }],
      ackTimings: [{ id: 2, flowKey: "a:1 <-> b:2", direction: "a>b" }]
    }
  };
  const topology = {
    nodes: [{ id: "n1", role: "ecu", label: "ECU", ips: ["1.1.1.1"], macs: [], eids: [], vins: [], evidence: [] }],
    edges: [{ id: "e1", kind: "diagnostic", source: "n1", target: "n2", evidence: [] }]
  };
  const socketTopology = {
    socketMap: {
      sockets: [{
        id: "socket:10.0.0.20",
        ip: "10.0.0.20",
        label: "Central Gateway",
        directLogicalAddress: "0x1001",
        directName: "Central Gateway",
        macs: ["aa"],
        eids: ["eid"],
        vins: ["vin"],
        packets: [1],
        evidence: ["announcement"],
        routed: [{ id: "route", logicalAddress: "0x2222", name: "Body ECU", requests: 2, testers: ["0x0e00"], services: ["0x22 Read"], packets: [2], evidence: ["request"] }],
        rejected: [{ id: "rejected", logicalAddress: "0x4444", name: "Rejected ECU", packets: [3], evidence: ["NACK 0x03"] }]
      }]
    }
  };

  assert.equal(exporters.exportSelected("allDids", report, null).filename, "uds-dids-all-ecus.csv");
  assert.ok(exporters.exportSelected("events", report, "0x1001", { ecuEvents: () => [{ id: 1, ecuAddress: "0x1001" }] }).text.includes("ecuAddress"));
  assert.equal(exporters.exportDownload("sessions", report).filename, "software-download-segments.csv");
  assert.ok(exporters.exportDownload("validation", report, { ecuName: () => "ECU" }).text.includes("Completeness"));
  assert.ok(exporters.exportDownload("rateCampaign", report, { ecuName: () => "ECU", rateCampaignRows: () => [{ ecuAddress: "0x1001", sessions: 1, payloadBytes: 10 }] }).text.includes("activeTimeSeconds"));
  assert.equal(exporters.exportValidationCentre([{ id: 1, severity: "warning" }]).filename, "harness-validation-centre.csv");
  assert.equal(exporters.exportTcp("events", report, "a:1 <-> b:2", { transportFlowIdentity: () => ({ tester: { label: "Tester" } }) }).filename, "tcp-events-a-1-b-2.csv");
  assert.equal(exporters.exportTopology("nodes", topology).filename, "topology-nodes.csv");
  assert.equal(exporters.exportTopology("nodes", socketTopology).filename, "topology-sockets.csv");
  assert.equal(exporters.exportTopology("edges", socketTopology).filename, "topology-socket-mappings.csv");
  assert.ok(exporters.exportTopology("edges", socketTopology).text.includes("rejected"));
  assert.ok(exporters.downloadHexText({ ecuAddress: "0x1001", typeLabel: "Download", id: 2, reconstructedBytes: 1, dataBlocks: [{ counter: "0x01", packet: 3, timestamp: 4, payloadBytes: 1, payloadHex: "aa" }] }).includes("block=0x01"));
}

assertJavaScriptParses("src/js/protocol-reference.js");
assertJavaScriptParses("src/js/formatters.js");
assertJavaScriptParses("src/js/ui-renderer.js");
assertJavaScriptParses("src/js/mapping-utils.js");
assertJavaScriptParses("src/js/uds-decoder.js");
assertJavaScriptParses("src/js/tcp-doip-reassembly.js");
assertJavaScriptParses("src/js/pcap-parser.js");
assertJavaScriptParses("src/js/tcp-analysis.js");
assertJavaScriptParses("src/js/diagnostic-analysis.js");
assertJavaScriptParses("src/js/identity-analysis.js");
assertJavaScriptParses("src/js/topology-analysis.js");
assertJavaScriptParses("src/js/download-analysis.js");
assertJavaScriptParses("src/js/validation-analysis.js");
assertJavaScriptParses("src/js/doip-lifecycle-analysis.js");
assertJavaScriptParses("src/js/discovery-renderer.js");
assertJavaScriptParses("src/js/validation-renderer.js");
assertJavaScriptParses("src/js/identity-renderer.js");
assertJavaScriptParses("src/js/transport-renderer.js");
assertJavaScriptParses("src/js/topology-renderer.js");
assertJavaScriptParses("src/js/diagnostics-renderer.js");
assertJavaScriptParses("src/js/trace-renderer.js");
assertJavaScriptParses("src/js/download-renderer.js");
assertJavaScriptParses("src/js/download-controller.js");
assertJavaScriptParses("src/js/trace-controller.js");
assertJavaScriptParses("src/js/exporters.js");
assertJavaScriptParses("src/js/persistence.js");
assertJavaScriptParses("app.js");
assertJavaScriptParses("mappings.js");
assertHtmlLoadsScriptBeforeApp();
assertScrollPaneCssContracts();
assertProtocolReferenceContracts();
assertFormatterContracts();
assertUiRendererContracts();
assertMappingUtilityContracts();
assertUdsDecoderContracts();
assertTcpDoipReassemblyContracts();
assertPcapParserContracts();
assertTcpAnalysisContracts();
assertDiagnosticAnalysisContracts();
assertIdentityAnalysisContracts();
assertTopologyAnalysisContracts();
assertDownloadAnalysisContracts();
assertValidationAnalysisContracts();
assertDoipLifecycleAnalysisContracts();
assertDiscoveryRendererContracts();
assertValidationRendererContracts();
assertIdentityRendererContracts();
assertTransportRendererContracts();
assertTopologyRendererContracts();
assertDiagnosticsRendererContracts();
assertTraceRendererContracts();
assertDownloadRendererContracts();
assertDownloadControllerContracts();
assertTraceControllerContracts();
assertExporterContracts();
assertPersistenceContracts().then(() => {
  assertPythonToolingRemoved();
  console.log("Smoke tests passed");
}).catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
