/**
 * Shared protocol lookup tables used by the browser parser and renderers.
 *
 * Keeping these values outside the main application file makes it easier to
 * review standards updates without digging through UI and parsing code.
 */
(function registerProtocolReference(global) {
  "use strict";

  const reference = {
    DOIP_PORT: 13400,
    DHCP_PORTS: new Set([67, 68]),
    ETH_IPV4: 0x0800,
    ETH_ARP: 0x0806,
    VLAN_TYPES: new Set([0x8100, 0x88a8, 0x9100]),

    DHCP_TYPES: Object.freeze({
      1: "Discover",
      2: "Offer",
      3: "Request",
      4: "Decline",
      5: "Ack",
      6: "Nak",
      7: "Release",
      8: "Inform"
    }),

    DOIP_TYPES: Object.freeze({
      0x0000: "Generic DoIP header negative acknowledgement",
      0x0001: "Vehicle identification request",
      0x0002: "Vehicle identification request with EID",
      0x0003: "Vehicle identification request with VIN",
      0x0004: "Vehicle announcement / identification response",
      0x0005: "Routing activation request",
      0x0006: "Routing activation response",
      0x0007: "Alive check request",
      0x0008: "Alive check response",
      0x4001: "DoIP entity status request",
      0x4002: "DoIP entity status response",
      0x4003: "Diagnostic power mode information request",
      0x4004: "Diagnostic power mode information response",
      0x8001: "Diagnostic message",
      0x8002: "Diagnostic message positive acknowledgement",
      0x8003: "Diagnostic message negative acknowledgement"
    }),

    DOIP_DIAGNOSTIC_NACK_CODES: Object.freeze({
      0x02: "Invalid source address",
      0x03: "Unknown target address",
      0x04: "Diagnostic message too large",
      0x05: "Out of memory",
      0x06: "Target unreachable",
      0x07: "Unknown network",
      0x08: "Transport protocol error"
    }),

    DOIP_GENERIC_NACK_CODES: Object.freeze({
      0x00: "Incorrect pattern format",
      0x01: "Unknown payload type",
      0x02: "Message too large",
      0x03: "Out of memory",
      0x04: "Invalid payload length"
    }),

    DOIP_ROUTING_ACTIVATION_RESPONSE_CODES: Object.freeze({
      0x00: "Routing denied due to unknown source address",
      0x01: "Routing denied because all sockets are registered and active",
      0x02: "Routing denied because source address is already registered",
      0x03: "Routing denied because source address is already registered on another socket",
      0x04: "Routing denied due to missing authentication",
      0x05: "Routing denied due to rejected confirmation",
      0x06: "Routing denied due to unsupported activation type",
      0x10: "Routing successfully activated"
    }),

    UDS_SERVICE_NAMES: Object.freeze({
      0x10: "Diagnostic Session Control",
      0x11: "ECU Reset",
      0x14: "Clear Diagnostic Information",
      0x19: "Read DTC Information",
      0x22: "Read Data By Identifier",
      0x23: "Read Memory By Address",
      0x24: "Read Scaling Data By Identifier",
      0x27: "Security Access",
      0x28: "Communication Control",
      0x2e: "Write Data By Identifier",
      0x2f: "Input Output Control By Identifier",
      0x31: "Routine Control",
      0x34: "Request Download",
      0x35: "Request Upload",
      0x36: "Transfer Data",
      0x37: "Request Transfer Exit",
      0x38: "Request File Transfer",
      0x3d: "Write Memory By Address",
      0x3e: "Tester Present",
      0x50: "Diagnostic Session Control Response",
      0x51: "ECU Reset Response",
      0x59: "Read DTC Information Response",
      0x62: "Read Data By Identifier Response",
      0x63: "Read Memory By Address Response",
      0x67: "Security Access Response",
      0x6e: "Write Data By Identifier Response",
      0x6f: "Input Output Control By Identifier Response",
      0x71: "Routine Control Response",
      0x74: "Request Download Response",
      0x75: "Request Upload Response",
      0x76: "Transfer Data Response",
      0x77: "Request Transfer Exit Response",
      0x78: "Request File Transfer Response",
      0x7e: "Tester Present Response",
      0x7f: "Negative Response",
      0x83: "Access Timing Parameter",
      0x84: "Secured Data Transmission",
      0x85: "Control DTC Setting",
      0x86: "Response On Event",
      0x87: "Link Control"
    }),

    UDS_NRC_NAMES: Object.freeze({
      0x10: "General reject",
      0x11: "Service not supported",
      0x12: "Sub-function not supported",
      0x13: "Incorrect message length or invalid format",
      0x21: "Busy repeat request",
      0x22: "Conditions not correct",
      0x24: "Request sequence error",
      0x31: "Request out of range",
      0x33: "Security access denied",
      0x35: "Invalid key",
      0x36: "Exceeded number of attempts",
      0x37: "Required time delay not expired",
      0x70: "Upload/download not accepted",
      0x71: "Transfer data suspended",
      0x72: "General programming failure",
      0x73: "Wrong block sequence counter",
      0x78: "Response pending",
      0x7e: "Sub-function not supported in active session",
      0x7f: "Service not supported in active session",
      0x81: "RPM too high",
      0x82: "RPM too low",
      0x83: "Engine is running",
      0x84: "Engine is not running",
      0x85: "Engine run time too low",
      0x90: "Vehicle speed too high"
    }),

    DTC_SUBFUNCTION_NAMES: Object.freeze({
      0x01: "Report number of DTC by status mask",
      0x02: "Report DTC by status mask",
      0x03: "Report DTC snapshot identification",
      0x04: "Report DTC snapshot record by DTC number",
      0x05: "Report DTC snapshot record by record number",
      0x06: "Report DTC extended data by DTC number",
      0x07: "Report number of DTC by severity mask",
      0x08: "Report DTC by severity mask",
      0x09: "Report severity information of DTC",
      0x0a: "Report supported DTC",
      0x0b: "Report first test failed DTC",
      0x0c: "Report first confirmed DTC",
      0x0d: "Report most recent test failed DTC",
      0x0e: "Report most recent confirmed DTC",
      0x0f: "Report mirror memory DTC by status mask",
      0x10: "Report mirror memory DTC extended data",
      0x11: "Report number of mirror memory DTC",
      0x12: "Report number of emissions-related OBD DTC",
      0x13: "Report emissions-related OBD DTC",
      0x14: "Report DTC fault detection counter",
      0x15: "Report DTC with permanent status",
      0x17: "Report user-defined memory DTC by status mask",
      0x18: "Report user-defined memory DTC snapshot record",
      0x19: "Report user-defined memory DTC extended data",
      0x1a: "Report supported DTC in user-defined memory"
    }),

    DTC_STATUS_BITS: Object.freeze([
      "testFailed",
      "testFailedThisOperationCycle",
      "pendingDTC",
      "confirmedDTC",
      "testNotCompletedSinceLastClear",
      "testFailedSinceLastClear",
      "testNotCompletedThisOperationCycle",
      "warningIndicatorRequested"
    ])
  };

  global.HarnessProtocol = Object.freeze(reference);
})(window);
