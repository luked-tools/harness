# Harness Architecture

Harness is a static browser app for classic Ethernet PCAP analysis. Parsing, analysis, rendering, export, and persistence run locally in the browser.

## Structure

- `index.html` defines the panels and application shell.
- `styles.css` contains the visual system.
- `mappings.js` contains user-editable ECU, DID, routine, service, and NRC names.
- `app.js` owns app state, cross-tool navigation, report orchestration, and compatibility adapters.
- `tests/smoke.test.js` checks syntax, script order, removed Python tooling, and module contracts.

Core modules:

- `src/js/protocol-reference.js`: protocol constants and lookup tables.
- `src/js/formatters.js`: display, byte, CSV, and HTML escaping helpers.
- `src/js/ui-renderer.js`: shared HTML snippets for metrics, badges, empty rows, and simple tables.
- `src/js/mapping-utils.js`: ECU-map CSV parsing and friendly-name lookup.
- `src/js/uds-decoder.js`: UDS service, DTC, transfer, and NRC decoding.
- `src/js/tcp-doip-reassembly.js`: TCP DoIP stream coalescing and gap reporting.
- `src/js/pcap-parser.js`: classic PCAP, Ethernet, ARP, DHCP, UDP/TCP, and DoIP parsing.

Analysis modules:

- `src/js/tcp-analysis.js`: TCP timing, ACK, retransmission, and flow-control analysis.
- `src/js/diagnostic-analysis.js`: UDS pairing, DID/DTC aggregation, and transfer sessions.
- `src/js/identity-analysis.js`: DHCP, ARP, DoIP, and UDS identity findings.
- `src/js/topology-analysis.js`: diagnostic topology nodes and links.
- `src/js/download-analysis.js`: software download/session analysis, rates, grouping, and validation.
- `src/js/validation-analysis.js`: cross-tool validation aggregation.

Rendering and workflow modules:

- `src/js/discovery-renderer.js`: home, discovery, and raw-sample views.
- `src/js/validation-renderer.js`: validation filtering and HTML rendering.
- `src/js/identity-renderer.js`: address-identity findings and host map.
- `src/js/transport-renderer.js`: transport identity, health, filtering, and helper views.
- `src/js/topology-renderer.js`: topology filtering, geometry, details, and tables.
- `src/js/diagnostics-renderer.js`: ECU diagnostic subpanels.
- `src/js/trace-renderer.js`: trace metadata, viewport model, tooltips, and compact timeline.
- `src/js/download-renderer.js`: software-download tables, charts, timeline, validation, and raw views.
- `src/js/download-controller.js`: download filters, selected session, modals, and renderer orchestration.
- `src/js/trace-controller.js`: trace filters, layers, zoom, measure mode, and tooltip wiring.
- `src/js/exporters.js`: CSV/text export shaping.
- `src/js/persistence.js`: IndexedDB report cache.

## Smoke Tests

```powershell
npm test
```
