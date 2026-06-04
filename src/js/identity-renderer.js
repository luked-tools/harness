/**
 * Rendering helpers for address-identity findings and host role maps.
 */
(function registerIdentityRenderer(global) {
  "use strict";

  const formatters = global.HarnessFormatters || {};
  const escapeHtml = formatters.escapeHtml || ((value) => String(value ?? ""));
  const formatNumber = formatters.formatNumber || ((value) => String(value ?? ""));
  const { badge, metrics: metricsList } = global.HarnessUi;

  function summaryText(identity) {
    return `${formatNumber(identity.findings.length)} findings across ${formatNumber(identity.groups.length)} diagnostic or DHCP identities.`;
  }

  function metricsHtml(metrics = {}) {
    return metricsList([
      ["High", metrics.high],
      ["Medium", metrics.medium],
      ["Known roles", metrics.hosts],
      ["IP addresses", metrics.ipAddresses],
      ["DHCP clients", metrics.dhcpClients],
      ["Logical addresses", metrics.logicalAddresses]
    ]);
  }

  function findingsHtml(groups = [], severity = "all") {
    const visibleGroups = groups
      .map((group) => ({ ...group, findings: group.findings.filter((finding) => severity === "all" || finding.severity === severity) }))
      .filter((group) => group.findings.length);
    return visibleGroups.map((group) => {
      const topSeverity = group.findings[0]?.severity || "info";
      return `
      <tr>
        <td>${badge(topSeverity, topSeverity === "high" ? "warn" : topSeverity === "medium" ? "" : "ok")}</td>
        <td>
          <code>${escapeHtml(group.entityId)}</code>
          <span class="identity-entity">${escapeHtml(group.entityType)}${group.role ? ` - ${escapeHtml(group.role)}` : ""}</span>
        </td>
        <td>${group.findings.map((finding) => `
          <div class="finding-line">
            <strong>${escapeHtml(finding.title)}</strong>
            <span>${escapeHtml(finding.source)}</span>
            <code>${escapeHtml(finding.evidence)}</code>
          </div>
        `).join("")}</td>
      </tr>
    `;
    }).join("") || `<tr><td colspan="3">No findings for this filter.</td></tr>`;
  }

  function hostMapHtml(hostMap = [], options = {}) {
    const ecuCode = options.ecuCode || ((address) => `<code>${escapeHtml(address)}</code>`);
    return hostMap.map((host) => `
    <tr>
      <td><code>${escapeHtml(host.mac)}</code></td>
      <td>${host.roles.map((role) => badge(role)).join(" ")}</td>
      <td>${host.ips.map((ipAddress) => `<code>${escapeHtml(ipAddress)}</code>`).join("<br>") || ""}</td>
      <td>${host.dhcp ? escapeHtml(Object.entries(host.dhcp.messages || {}).map(([key, value]) => `${key}: ${value}`).join(", ")) : ""}</td>
      <td>${host.logicalAddresses.map((address) => ecuCode(address)).join("<br>")}</td>
    </tr>
  `).join("") || `<tr><td colspan="5">No DHCP, tester, or ECU identities decoded.</td></tr>`;
  }

  global.HarnessIdentityRenderer = Object.freeze({
    summaryText,
    metricsHtml,
    findingsHtml,
    hostMapHtml
  });
})(window);
