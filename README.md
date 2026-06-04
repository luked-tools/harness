# Harness

Static browser app for inspecting classic Ethernet `.pcap` captures with automotive diagnostic traffic.

It decodes:

- ARP requests and replies
- DHCP clients, servers, hostnames, and requested/offered IPs
- DoIP traffic on TCP/UDP port `13400`
- DoIP vehicle announcements, VIN, logical address, EID, and GID
- UDS messages carried over DoIP
- DID reads, negative responses, sessions, security access, routines, and transfer/download activity

## Use

Open the local app:

```powershell
python -m http.server 8765 --bind 127.0.0.1
```

Then visit:

```text
http://127.0.0.1:8765/index.html
```

Drag a `.pcap` onto the page or use **Open pcap**. Parsing stays in the browser.

## Tools

The home view groups the main tools: **Validation Centre**, **UDS Analyser**, **DID Explorer**, **Software Download**, **Protocol Trace**, **Transport Timing**, **Discovery Console**, **Address Identity**, **Node Map**, and **Packet Samples**.

Use **Protocol Trace** for a split timeline of UDS and setup traffic. Toggle UDS, DoIP, DHCP, ARP, ACK/NAK, and TCP layers; hover or focus a marker for details; drag to zoom.

Use **Transport Timing** for DoIP TCP flows, ACK timing, retransmissions, duplicate ACKs, zero-window events, and handshake timing.

Use **Address Identity** for MAC/IP consistency, DHCP gaps, ARP conflicts, and logical-address drift across EIDs or IPs.

Use the **UDS Analyser** to select a logical address such as `0x1001`. The detail view includes:

- Overview metrics and service mix
- Chronological UDS timeline
- Service `0x22/0x62` DID read table
- RequestDownload / TransferData / TransferExit summaries
- Negative response grouping
- Raw decoded UDS messages

CSV exports are available for ECU events, DID reads, DTCs, transfers, validation findings, TCP data, and topology data.

Friendly ECU, DID, routine, service, and NRC names can be edited in `mappings.js`. Shared protocol tables live in `src/js/protocol-reference.js`.

Use **Import ECU map** to load a local CSV of logical addresses and ECU names. Supported columns include `logicalAddress,name`, `address,name`, or two-column rows such as `0x1001,Gateway`.

## Development

```powershell
npm test
```

The smoke tests check JavaScript syntax, script order, Python-tooling removal, and module contracts.

See `docs/architecture.md` for the current structure.

## Notes

This is intentionally dependency-free at runtime and supports classic pcap with Ethernet link type. It does not parse pcapng.
