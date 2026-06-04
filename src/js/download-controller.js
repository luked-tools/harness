(function attachDownloadController(global) {
  "use strict";

  const { escapeHtml, formatNumber, formatBytes, formatRate, formatDurationValue } = global.HarnessFormatters;
  const { badge, metrics: metricsHtml } = global.HarnessUi;
  const DownloadRenderer = global.HarnessDownloadRenderer;

  /**
   * Coordinates the software download workflow: filters, selected session state,
   * modal wiring, and renderer calls. The HTML generation stays in
   * HarnessDownloadRenderer; this module owns browser interaction only.
   */
  function createDownloadController(deps) {
    const state = {
      selectedSessionId: null,
      selectedTab: "matrix",
      selectedEcus: new Set(),
      selectedGateways: new Set(),
      collapsedGroups: new Set(),
      collapsedEcuGroups: new Set()
    };

    const $ = deps.$;

    function currentReport() {
      return deps.getReport();
    }

    function filteredSessions(sessions) {
      const type = $("downloadTypeFilter")?.value || "all";
      const severity = $("downloadSeverityFilter")?.value || "all";
      const exportableOnly = $("downloadExportableOnly")?.checked || false;
      return (sessions || []).filter((session) =>
        (!state.selectedEcus.size || state.selectedEcus.has(session.ecuAddress)) &&
        (!state.selectedGateways.size || state.selectedGateways.has(session.gatewayIp || "unknown")) &&
        (type === "all" || session.sessionType === type) &&
        (severity === "all" || session.severity === severity) &&
        (!exportableOnly || session.hexExportable)
      );
    }

    function populateFilters(analysis) {
      const sessions = analysis.sessions || [];
      const ecus = Array.from(new Set(sessions.map((session) => session.ecuAddress))).sort();
      state.selectedEcus = new Set(Array.from(state.selectedEcus).filter((ecu) => ecus.includes(ecu)));
      $("downloadEcuSummary").textContent = state.selectedEcus.size ? `${state.selectedEcus.size} ECUs selected` : "All ECUs";
      $("downloadEcuOptions").innerHTML = `
        <label><input type="checkbox" data-download-ecu="all" ${state.selectedEcus.size ? "" : "checked"}> All ECUs</label>
        ${ecus.map((ecu) => `<label><input type="checkbox" data-download-ecu="${escapeHtml(ecu)}" ${state.selectedEcus.has(ecu) ? "checked" : ""}> ${deps.ecuCode(ecu)}</label>`).join("")}
      `;
      const groups = analysis.groups || [];
      const gatewayKeys = new Set(groups.map((group) => group.key));
      state.selectedGateways = new Set(Array.from(state.selectedGateways).filter((gateway) => gatewayKeys.has(gateway)));
      const selectedGatewayLabels = groups.filter((group) => state.selectedGateways.has(group.key)).map((group) => group.label);
      $("downloadGatewaySummary").textContent = selectedGatewayLabels.length === 1 ? selectedGatewayLabels[0] : selectedGatewayLabels.length ? `${selectedGatewayLabels.length} gateways/IPs` : "All gateways/IPs";
      $("downloadGatewayOptions").innerHTML = `
        <label><input type="checkbox" data-download-gateway="all" ${state.selectedGateways.size ? "" : "checked"}> All gateways/IPs</label>
        ${groups.map((group) => `<label><input type="checkbox" data-download-gateway="${escapeHtml(group.key)}" ${state.selectedGateways.has(group.key) ? "checked" : ""}> ${escapeHtml(group.label)}</label>`).join("")}
      `;
    }

    function render(report) {
      report.downloadAnalysis ||= deps.buildDownloadAnalysis(report);
      const analysis = report.downloadAnalysis;
      const allSessions = analysis.sessions || [];
      populateFilters(analysis);
      const sessions = filteredSessions(allSessions);
      if (!state.selectedSessionId || sessions.length && !sessions.some((session) => String(session.id) === String(state.selectedSessionId)) || !allSessions.some((session) => String(session.id) === String(state.selectedSessionId))) {
        state.selectedSessionId = sessions[0]?.id || allSessions[0]?.id || null;
      }
      $("downloadSummary").textContent = `${formatNumber(allSessions.length)} transfer segments, ${formatNumber(analysis.metrics?.exportable || 0)} exportable, ${formatNumber(analysis.metrics?.warnings || 0)} warnings, ${formatNumber(analysis.metrics?.errors || 0)} errors.`;
      $("downloadMetrics").innerHTML = metricsHtml([
        ["Transfer segments", allSessions.length],
        ["RequestDownload", analysis.metrics?.downloads || 0],
        ["RequestUpload", analysis.metrics?.uploads || 0],
        ["File transfer", analysis.metrics?.fileTransfers || 0],
        ["Hex exportable", analysis.metrics?.exportable || 0],
        ["Validation warnings", analysis.metrics?.warnings || 0],
        ["Validation errors", analysis.metrics?.errors || 0],
        ["Payload bytes", allSessions.reduce((sum, item) => sum + (item.reconstructedBytes || 0), 0)]
      ]);
      $("downloadSessionTable").innerHTML = DownloadRenderer.renderGroupedDownloadRows(analysis.groups || [], sessions, {
        ecuCode: deps.ecuCode,
        collapsedDownloadGroups: state.collapsedGroups,
        collapsedDownloadEcuGroups: state.collapsedEcuGroups,
        selectedDownloadSessionId: state.selectedSessionId
      });
      wireSessionTable();
      renderSelectedSession(allSessions.find((session) => String(session.id) === String(state.selectedSessionId)));
    }

    function rerender() {
      render(currentReport());
    }

    function wireSessionTable() {
      for (const row of $("downloadSessionTable").querySelectorAll("tr[data-download-session]")) {
        row.addEventListener("click", () => {
          state.selectedSessionId = row.dataset.downloadSession;
          rerender();
        });
      }
      for (const button of $("downloadSessionTable").querySelectorAll("[data-download-group-toggle]")) {
        button.addEventListener("click", () => {
          const key = button.dataset.downloadGroupToggle;
          if (state.collapsedGroups.has(key)) state.collapsedGroups.delete(key);
          else state.collapsedGroups.add(key);
          rerender();
        });
      }
      for (const button of $("downloadSessionTable").querySelectorAll("[data-download-ecu-toggle]")) {
        button.addEventListener("click", () => {
          const key = button.dataset.downloadEcuToggle;
          if (state.collapsedEcuGroups.has(key)) state.collapsedEcuGroups.delete(key);
          else state.collapsedEcuGroups.add(key);
          rerender();
        });
      }
    }

    function renderSelectedSession(session) {
      if (!session) {
        $("downloadDetailHead").innerHTML = `<div class="empty">No software transfer session selected.</div>`;
        $("downloadTabContent").dataset.downloadTab = "";
        $("downloadTabContent").innerHTML = "";
        return;
      }
      $("downloadDetailHead").innerHTML = `
        <div>
          <h3>${escapeHtml(session.typeLabel)} ${deps.ecuCode(session.ecuAddress)}</h3>
          <p class="subtle">${deps.formatTimeDelta(session.startTimestamp)} to ${deps.formatTimeDelta(session.endTimestamp)} | tester ${escapeHtml(session.testerAddress)}</p>
        </div>
        <div class="export-actions">
          ${badge(session.severity, DownloadRenderer.downloadSeverityClass(session.severity))}
          <button type="button" class="download-hex-export" data-download-session="${session.id}" ${session.hexExportable ? "" : "disabled"}>Export hex</button>
        </div>
      `;
      for (const button of document.querySelectorAll(".download-tab")) button.classList.toggle("active", button.dataset.downloadTab === state.selectedTab);
      const renderers = {
        matrix: renderDownloadMatrix,
        overview: (item) => DownloadRenderer.renderDownloadOverview(item, { ecuCode: deps.ecuCode }),
        conditions: (item) => DownloadRenderer.renderDownloadConditions(item, currentReport().diagnostics?.udsEvents || [], { formatTimeDelta: deps.formatTimeDelta }),
        blocks: DownloadRenderer.renderDownloadBlocks,
        rate: (item) => DownloadRenderer.renderDownloadRate(item, { formatTimeDelta: deps.formatTimeDelta }),
        timeline: renderDownloadTimeline,
        validation: DownloadRenderer.renderDownloadValidation,
        raw: (item) => DownloadRenderer.renderDownloadRaw(item, { formatTimeDelta: deps.formatTimeDelta })
      };
      const activeTab = renderers[state.selectedTab] ? state.selectedTab : "overview";
      $("downloadTabContent").dataset.downloadTab = activeTab;
      $("downloadTabContent").innerHTML = `<div class="download-tab-pane download-tab-pane-${activeTab}">${renderers[activeTab](session)}</div>`;
      wireSelectionButtons();
      wireHexExports();
      wireRateCampaignModal();
      wireRateChartTooltip();
    }

    function renderDownloadMatrix() {
      const rows = (currentReport().downloadAnalysis?.matrixRows || []).filter((row) =>
        (!state.selectedEcus.size || state.selectedEcus.has(row.ecuAddress)) && (!state.selectedGateways.size || state.selectedGateways.has(row.groupKey || "unknown"))
      );
      return DownloadRenderer.renderDownloadMatrix(rows, { selectedDownloadSessionId: state.selectedSessionId, ecuCode: deps.ecuCode });
    }

    function renderDownloadTimeline() {
      return DownloadRenderer.renderDownloadTimeline(filteredSessions(currentReport().downloadAnalysis?.sessions || []), {
        selectedDownloadSessionId: state.selectedSessionId,
        ecuLabel: timelineEcuLabel
      });
    }

    function timelineEcuLabel(address) {
      return deps.ecuLabel(address, { withAddress: Boolean(deps.ecuName(address)) });
    }

    function wireSelectionButtons() {
      for (const target of $("downloadTabContent").querySelectorAll("[data-download-session], [data-matrix-session]")) {
        target.addEventListener("click", () => {
          const id = target.dataset.downloadSession || target.dataset.matrixSession;
          if (!id) return;
          state.selectedSessionId = id;
          state.selectedTab = target.dataset.matrixSession ? "overview" : state.selectedTab;
          rerender();
        });
      }
    }

    function wireRateCampaignModal() {
      const button = $("openRateCampaignModal");
      if (!button) return;
      button.addEventListener("click", () => openRateCampaignModal());
    }

    function openRateCampaignModal() {
      $("rateCampaignModalBody").innerHTML = renderRateCampaignComparison();
      wireRateCampaignRows();
      $("rateCampaignModal").hidden = false;
    }

    function closeRateCampaignModal() {
      $("rateCampaignModal").hidden = true;
    }

    function openDownloadCampaignModal() {
      $("downloadCampaignModalBody").innerHTML = renderDownloadCampaignSummary();
      $("downloadCampaignModal").hidden = false;
    }

    function closeDownloadCampaignModal() {
      $("downloadCampaignModal").hidden = true;
    }

    function openDidPlotModal(key) {
      const [ecuAddress, did] = String(key || "").split("|");
      const history = deps.didHistoryForEcu(ecuAddress).find((item) => item.did === did);
      if (!history) return;
      const plot = global.HarnessTraceRenderer.didPlotStatus(history);
      if (!plot.plottable) return;
      $("didPlotTitle").textContent = `${did} ${history.name || "DID value"}`;
      $("didPlotSubtitle").textContent = `ECU ${deps.ecuLabel(ecuAddress, { withAddress: Boolean(deps.ecuName(ecuAddress)) })} - ${formatNumber(plot.samples.length)} unsigned byte samples.`;
      $("didPlotModalBody").innerHTML = DownloadRenderer.renderDidPlotModal(history, plot.samples, { formatTimeDelta: deps.formatTimeDelta });
      wireDidPlotTooltip();
      $("didPlotModal").hidden = false;
    }

    function closeDidPlotModal() {
      $("didPlotModal").hidden = true;
    }

    function wireRateCampaignRows() {
      for (const row of $("rateCampaignModalBody").querySelectorAll("tr[data-download-session]")) {
        row.addEventListener("click", () => {
          state.selectedSessionId = row.dataset.downloadSession;
          rerender();
          $("rateCampaignModalBody").innerHTML = renderRateCampaignComparison();
          wireRateCampaignRows();
        });
      }
    }

    function wireRateChartTooltip() {
      const chart = $("downloadTabContent").querySelector(".rate-line-chart");
      const tooltip = $("downloadTabContent").querySelector(".rate-tooltip");
      if (!chart || !tooltip) return;
      chart.addEventListener("pointermove", (event) => {
        const point = event.target.closest(".rate-point");
        if (!point) {
          tooltip.hidden = true;
          return;
        }
        tooltip.innerHTML = `
          <strong>${escapeHtml(point.dataset.rate || "")}</strong>
          <span>${escapeHtml(point.dataset.window || "")}</span>
          <span>${escapeHtml(point.dataset.bytes || "")}</span>
        `;
        tooltip.hidden = false;
        const host = chart.getBoundingClientRect();
        tooltip.style.left = `${Math.min(host.width - 180, Math.max(8, event.clientX - host.left + 12))}px`;
        tooltip.style.top = `${Math.max(8, event.clientY - host.top - 52)}px`;
      });
      chart.addEventListener("pointerleave", () => {
        tooltip.hidden = true;
      });
    }

    function wireDidPlotTooltip() {
      const body = $("didPlotModalBody");
      const chart = body.querySelector(".did-line-chart");
      const tooltip = body.querySelector(".did-chart-tooltip");
      if (!chart || !tooltip) return;
      const show = (target, clientX = null, clientY = null) => {
        tooltip.innerHTML = `
          <strong>${escapeHtml(target.dataset.value || "")}</strong>
          <span>${escapeHtml(target.dataset.hex || "")}</span>
          <span>packet ${escapeHtml(target.dataset.packet || "")}</span>
          <span>${escapeHtml(target.dataset.time || "")}</span>
        `;
        tooltip.hidden = false;
        const host = chart.getBoundingClientRect();
        const left = clientX === null ? Number(target.getAttribute("cx")) + 12 : clientX - host.left + 12;
        const top = clientY === null ? Number(target.getAttribute("cy")) - 58 : clientY - host.top - 58;
        tooltip.style.left = `${Math.min(host.width - 170, Math.max(8, left))}px`;
        tooltip.style.top = `${Math.max(8, top)}px`;
      };
      chart.addEventListener("pointermove", (event) => {
        const point = event.target.closest(".did-point");
        if (!point) {
          tooltip.hidden = true;
          return;
        }
        show(point, event.clientX, event.clientY);
      });
      chart.addEventListener("pointerleave", () => {
        tooltip.hidden = true;
      });
      for (const point of chart.querySelectorAll(".did-point")) {
        point.addEventListener("focus", () => show(point));
        point.addEventListener("blur", () => {
          tooltip.hidden = true;
        });
      }
    }

    function renderDownloadCampaignSummary() {
      return DownloadRenderer.renderDownloadCampaignSummary(filteredSessions(currentReport().downloadAnalysis?.sessions || []), {
        ecuLabel: deps.ecuLabel,
        ecuCode: deps.ecuCode
      });
    }

    function renderRateCampaignComparison() {
      const rows = rateCampaignRows();
      const body = rows.map((row) => `<tr data-download-session="${row.sessionId}" class="${String(row.sessionId) === String(state.selectedSessionId) ? "selected" : ""}"><td>${deps.ecuCode(row.ecuAddress)}</td><td>${formatNumber(row.sessions)}</td><td>${formatBytes(row.payloadBytes)}</td><td>${formatDurationValue(row.activeTime)}</td><td>${formatRate(row.averageRateBps)}</td><td>${formatRate(row.fastestRateBps)}</td><td>${formatRate(row.slowestRateBps)}</td><td>${formatNumber(row.captureInfo)}</td></tr>`).join("");
      return `<div class="table-wrap"><table><thead><tr><th>ECU</th><th>Segments</th><th>Payload</th><th>Active time</th><th>Average rate</th><th>Fastest</th><th>Slowest</th><th>Capture info</th></tr></thead><tbody>${body || `<tr><td colspan="8">No transfer segments match the filters.</td></tr>`}</tbody></table></div>`;
    }

    function rateCampaignRows() {
      const byEcu = new Map();
      for (const session of filteredSessions(currentReport().downloadAnalysis?.sessions || [])) {
        if (!byEcu.has(session.ecuAddress)) byEcu.set(session.ecuAddress, []);
        byEcu.get(session.ecuAddress).push(session);
      }
      return Array.from(byEcu.entries()).sort((a, b) => a[0].localeCompare(b[0])).map(([ecu, ecuSessions]) => {
        const totalPayload = ecuSessions.reduce((sum, item) => sum + (item.reconstructedBytes || 0), 0);
        const activeTime = ecuSessions.reduce((sum, item) => sum + (item.rate?.activePayloadDuration || 0), 0);
        const rates = ecuSessions.map((item) => item.rate?.averagePayloadRateBps).filter((value) => Number.isFinite(Number(value)));
        const fastest = rates.length ? Math.max(...rates) : null;
        const slowest = rates.length ? Math.min(...rates) : null;
        const captureInfo = ecuSessions.reduce((sum, item) => sum + (item.validation || []).filter((finding) => finding.category === "Capture quality").length, 0);
        return {
          ecuAddress: ecu,
          sessionId: ecuSessions[0].id,
          sessions: ecuSessions.length,
          payloadBytes: totalPayload,
          activeTime: activeTime || null,
          averageRateBps: activeTime > 0 ? totalPayload / activeTime : null,
          fastestRateBps: fastest,
          slowestRateBps: slowest,
          captureInfo
        };
      });
    }

    function wireHexExports() {
      for (const button of document.querySelectorAll(".download-hex-export")) {
        button.addEventListener("click", () => {
          const session = (currentReport().downloadAnalysis?.sessions || []).find((item) => String(item.id) === button.dataset.downloadSession);
          if (!session?.hexExportable) return;
          deps.downloadText(`software-download-${session.ecuAddress.replace(/[^a-z0-9]/gi, "")}-${session.id}.hex.txt`, deps.downloadHexText(session), "text/plain");
        });
      }
    }

    function exportTimelinePng() {
      const sessions = filteredSessions(currentReport().downloadAnalysis?.sessions || []);
      if (!sessions.length) return;
      const model = DownloadRenderer.buildDownloadTimelineExportModel(sessions, { ecuLabel: timelineEcuLabel });
      const scale = Math.min(2, Math.max(1, global.devicePixelRatio || 1));
      const canvas = document.createElement("canvas");
      canvas.width = Math.round(model.width * scale);
      canvas.height = Math.round(model.height * scale);
      const ctx = canvas.getContext("2d");
      ctx.scale(scale, scale);
      DownloadRenderer.drawDownloadTimelineExport(ctx, model, DownloadRenderer.timelineExportColours(getComputedStyle(document.documentElement)), {
        formatTimeDelta: deps.formatTimeDelta,
        firstTimestamp: currentReport().summary?.firstTimestamp || model.start
      });
      const link = document.createElement("a");
      link.download = `software-download-campaign-timeline-${new Date().toISOString().slice(0, 10)}.png`;
      link.href = canvas.toDataURL("image/png");
      link.click();
    }

    function bindControls() {
      $("openDownloadCampaignModal").addEventListener("click", openDownloadCampaignModal);
      $("closeRateCampaignModal").addEventListener("click", closeRateCampaignModal);
      $("rateCampaignModal").addEventListener("click", (event) => {
        if (event.target.id === "rateCampaignModal") closeRateCampaignModal();
      });
      $("closeDownloadCampaignModal").addEventListener("click", closeDownloadCampaignModal);
      $("downloadCampaignModal").addEventListener("click", (event) => {
        if (event.target.id === "downloadCampaignModal") closeDownloadCampaignModal();
      });
      $("closeDidPlotModal").addEventListener("click", closeDidPlotModal);
      $("didPlotModal").addEventListener("click", (event) => {
        if (event.target.id === "didPlotModal") closeDidPlotModal();
      });
      $("downloadEcuFilter").addEventListener("change", (event) => {
        const input = event.target;
        if (!input.matches("[data-download-ecu]")) return;
        const value = input.dataset.downloadEcu;
        if (value === "all") {
          state.selectedEcus.clear();
        } else if (input.checked) {
          state.selectedEcus.add(value);
        } else {
          state.selectedEcus.delete(value);
        }
        rerender();
      });
      $("downloadGatewayFilter").addEventListener("change", (event) => {
        const input = event.target;
        if (!input.matches("[data-download-gateway]")) return;
        const value = input.dataset.downloadGateway;
        if (value === "all") {
          state.selectedGateways.clear();
        } else if (input.checked) {
          state.selectedGateways.add(value);
        } else {
          state.selectedGateways.delete(value);
        }
        rerender();
      });
      $("downloadTypeFilter").addEventListener("change", rerender);
      $("downloadSeverityFilter").addEventListener("change", rerender);
      $("downloadExportableOnly").addEventListener("change", rerender);
      for (const button of document.querySelectorAll(".download-tab")) {
        button.addEventListener("click", () => {
          state.selectedTab = button.dataset.downloadTab;
          rerender();
        });
      }
    }

    function resetFilters() {
      state.selectedEcus.clear();
      state.selectedGateways.clear();
      if ($("downloadTypeFilter")) $("downloadTypeFilter").value = "all";
      if ($("downloadSeverityFilter")) $("downloadSeverityFilter").value = "all";
      if ($("downloadExportableOnly")) $("downloadExportableOnly").checked = false;
    }

    return {
      bindControls,
      render,
      filteredSessions,
      rateCampaignRows,
      exportTimelinePng,
      openDidPlotModal,
      setSelectedSession(id) {
        state.selectedSessionId = id;
      },
      setSelectedTab(tab) {
        state.selectedTab = tab || state.selectedTab;
      },
      resetFilters,
      wireHexExports,
      state
    };
  }

  global.HarnessDownloadController = Object.freeze({ createDownloadController });
})(window);
