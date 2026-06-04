(function attachTraceController(global) {
  "use strict";

  const TraceRenderer = global.HarnessTraceRenderer;
  const { formatBytes, formatMs } = global.HarnessFormatters;

  /**
   * Coordinates the protocol trace workflow: filters, layer state, zoom/measure
   * interactions, tooltip wiring, and relationship highlighting.
   */
  function createTraceController(deps) {
    const state = {
      fullRange: null,
      zoomRange: null,
      zoomHistory: [],
      dragState: null,
      compareSelection: [],
      measureMode: false,
      linkedEventIds: { primary: null, pair: new Set(), pending: new Set() },
      layerState: { uds: true, doip: true, dhcp: true, arp: true, ack: true, transport: false },
      typeState: {}
    };

    const $ = deps.$;

    function currentReport() {
      return deps.getReport();
    }

    function render(report, preserveSelection = false, resetZoom = false) {
      const select = $("traceEcuFilter");
      const viewport = $("traceViewport");
      hideTooltip();
      viewport.onpointerdown = null;
      viewport.onpointermove = null;
      viewport.onpointerup = null;
      viewport.onpointercancel = null;
      const previous = preserveSelection ? select.value : "all";
      const ecus = Object.values(report.diagnostics?.ecus || {}).sort((a, b) => (b.requests + b.responses) - (a.requests + a.responses));
      select.innerHTML = `<option value="all">All ECUs</option>${ecus.map((ecu) => `<option value="${deps.escapeHtml(ecu.address)}">${deps.escapeHtml(deps.ecuLabel(ecu.address, { withAddress: Boolean(ecu.name) }))}</option>`).join("")}`;
      select.value = previous && (previous === "all" || ecus.some((ecu) => ecu.address === previous)) ? previous : "all";
      if (resetZoom || !preserveSelection) resetZoomState();

      const traceEvents = deps.traceEventsForReport(report);
      $("traceAdvancedPanel").innerHTML = TraceRenderer.renderAdvancedPanel(traceEvents, state.typeState);
      const view = TraceRenderer.buildTraceViewport(traceEvents, {
        traceLayerState: state.layerState,
        traceTypeState: state.typeState,
        ecuFilter: select.value,
        kindFilter: $("traceKindFilter").value,
        traceZoomRange: state.zoomRange,
        traceCompareSelection: state.compareSelection,
        traceLinkedEventIds: state.linkedEventIds,
        traceZoomHistory: state.zoomHistory,
        formatTimeDelta: deps.formatTimeDelta,
        formatBytes,
        ecuLabel: deps.ecuLabel
      });
      state.fullRange = view.traceFullRange;
      state.compareSelection = view.compareSelection;
      $("traceSummary").textContent = view.summaryText;
      $("traceWindow").textContent = view.windowText;
      $("traceZoomReset").disabled = view.zoomResetDisabled;
      $("traceZoomBack").disabled = view.zoomBackDisabled;
      $("traceLayerCounts").innerHTML = view.layerCountsHtml;
      updateCompareDisplay();
      viewport.innerHTML = view.html;
      if (!view.allEvents.length || !view.visibleEvents.length) return;
      for (const button of viewport.querySelectorAll("[data-trace-ecu]")) {
        button.addEventListener("click", () => deps.openEcuTimeline(button.dataset.traceEcu));
      }
      wireTooltips();
      wireZoomDrag(view.dragStart, view.dragEnd);
    }

    function traceEventById(id) {
      return deps.traceEventsForReport(currentReport()).find((event) => String(event.id) === String(id));
    }

    function udsEventForTraceEvent(traceEvent) {
      if (!traceEvent?.udsEventId) return null;
      return (currentReport().diagnostics?.udsEvents || []).find((event) => String(event.id) === String(traceEvent.udsEventId)) || null;
    }

    function traceEventForUdsId(udsId) {
      if (!udsId) return null;
      return deps.traceEventsForReport(currentReport()).find((event) => String(event.udsEventId) === String(udsId)) || null;
    }

    function relationshipForEvent(traceEvent) {
      const udsEvent = udsEventForTraceEvent(traceEvent);
      if (!udsEvent) return { traceEvent, udsEvent: null, request: null, finalResponse: null, pendingResponses: [] };
      const udsEvents = currentReport().diagnostics?.udsEvents || [];
      const request = udsEvent.direction === "request"
        ? udsEvent
        : udsEvents.find((event) => String(event.id) === String(udsEvent.requestEventId)) || null;
      const finalResponse = request?.responseEventId
        ? udsEvents.find((event) => String(event.id) === String(request.responseEventId)) || null
        : (udsEvent.direction === "response" && udsEvent.responseKind !== "pending" ? udsEvent : null);
      const pendingResponses = request
        ? udsEvents.filter((event) => String(event.requestEventId) === String(request.id) && event.responseKind === "pending")
        : [];
      return { traceEvent, udsEvent, request, finalResponse, pendingResponses };
    }

    function setRelationshipClasses(eventId) {
      const relation = relationshipForEvent(traceEventById(eventId));
      const traceIds = (events) => events
        .map((event) => String(traceEventForUdsId(event?.id)?.id || ""))
        .filter((id) => id && String(id) !== String(eventId));
      state.linkedEventIds = {
        primary: eventId,
        pair: new Set(traceIds([relation.request, relation.finalResponse].filter(Boolean))),
        pending: new Set(traceIds(relation.pendingResponses))
      };
    }

    function clearRelationship() {
      state.linkedEventIds = { primary: null, pair: new Set(), pending: new Set() };
    }

    function applyRelationshipClasses() {
      for (const marker of $("traceViewport").querySelectorAll("[data-trace-event]")) {
        const id = String(marker.dataset.traceEvent);
        const primary = String(state.linkedEventIds.primary || "") === id;
        const pair = state.linkedEventIds.pair?.has(id);
        const pending = state.linkedEventIds.pending?.has(id);
        marker.classList.toggle("linked-primary", primary);
        marker.classList.toggle("linked-pair", Boolean(pair));
        marker.classList.toggle("linked-pending", Boolean(pending));
        marker.classList.toggle("linked-muted", Boolean(state.linkedEventIds.primary && marker.classList.contains("uds") && !primary && !pair && !pending));
      }
    }

    function tooltipContent(event) {
      return TraceRenderer.renderTraceTooltipContent(event, {
        relation: event.category === "uds" ? relationshipForEvent(event) : null,
        formatTimeDelta: deps.formatTimeDelta
      });
    }

    function positionTooltip(clientX, clientY) {
      const tooltip = $("traceTooltip");
      if (!tooltip || tooltip.hidden) return;
      const margin = 12;
      const rect = tooltip.getBoundingClientRect();
      let left = clientX + 14;
      let top = clientY + 14;
      if (left + rect.width + margin > global.innerWidth) left = clientX - rect.width - 14;
      if (top + rect.height + margin > global.innerHeight) top = clientY - rect.height - 14;
      tooltip.style.left = `${Math.max(margin, left)}px`;
      tooltip.style.top = `${Math.max(margin, top)}px`;
    }

    function showTooltip(eventId, clientX, clientY) {
      if (state.dragState) return;
      const event = traceEventById(eventId);
      const tooltip = $("traceTooltip");
      if (!event || !tooltip) return;
      setRelationshipClasses(eventId);
      applyRelationshipClasses();
      tooltip.innerHTML = tooltipContent(event);
      tooltip.hidden = false;
      positionTooltip(clientX, clientY);
    }

    function hideTooltip() {
      const tooltip = $("traceTooltip");
      if (!tooltip) return;
      tooltip.hidden = true;
      if (state.linkedEventIds.primary) {
        clearRelationship();
        applyRelationshipClasses();
      }
    }

    function wireTooltips() {
      for (const marker of $("traceViewport").querySelectorAll("[data-trace-event]")) {
        marker.addEventListener("pointerenter", (event) => showTooltip(marker.dataset.traceEvent, event.clientX, event.clientY));
        marker.addEventListener("pointermove", (event) => positionTooltip(event.clientX, event.clientY));
        marker.addEventListener("pointerleave", hideTooltip);
        marker.addEventListener("focus", () => {
          const rect = marker.getBoundingClientRect();
          showTooltip(marker.dataset.traceEvent, rect.left + rect.width / 2, rect.bottom);
        });
        marker.addEventListener("blur", hideTooltip);
      }
    }

    function selectCompareEvent(id) {
      if (!id) return;
      if (state.compareSelection.length === 1 && String(state.compareSelection[0]) === String(id)) {
        state.compareSelection = [];
      } else if (state.compareSelection.length >= 2) {
        state.compareSelection = [id];
      } else {
        state.compareSelection = [...state.compareSelection.filter((item) => String(item) !== String(id)), id];
      }
      render(currentReport(), true);
    }

    function updateCompareDisplay() {
      const output = $("traceCompareDelta");
      const clear = $("traceCompareClear");
      const toggle = $("traceMeasureToggle");
      if (!output || !clear) return;
      if (toggle) {
        toggle.classList.toggle("active", state.measureMode);
        toggle.setAttribute("aria-pressed", state.measureMode ? "true" : "false");
      }
      clear.disabled = !state.compareSelection.length;
      if (!state.measureMode) {
        output.textContent = "Measure off";
        return;
      }
      if (state.compareSelection.length < 2) {
        output.textContent = state.compareSelection.length ? "Select second marker" : "Select first marker";
        return;
      }
      const [first, second] = state.compareSelection.map((id) => traceEventById(id));
      if (!first || !second) {
        output.textContent = "Selection unavailable";
        return;
      }
      const delta = Math.abs(Number(second.timestamp || 0) - Number(first.timestamp || 0));
      output.textContent = `Delta ${formatMs(delta)} (${deps.formatTimeDelta(first.timestamp)} to ${deps.formatTimeDelta(second.timestamp)})`;
    }

    function resetZoomState() {
      state.zoomRange = null;
      state.zoomHistory = [];
      state.dragState = null;
    }

    function setZoomRange(start, end) {
      if (!state.fullRange) return;
      const nextStart = Math.max(state.fullRange.start, Math.min(start, end));
      const nextEnd = Math.min(state.fullRange.end, Math.max(start, end));
      if (nextEnd - nextStart < 0.0005) return;
      state.zoomHistory.push(state.zoomRange || { ...state.fullRange });
      state.zoomRange = { start: nextStart, end: nextEnd };
      render(currentReport(), true);
    }

    function clearSelection() {
      for (const track of $("traceViewport").querySelectorAll(".trace-track.selecting")) {
        track.classList.remove("selecting");
        track.style.removeProperty("--selection-left");
        track.style.removeProperty("--selection-width");
      }
    }

    function updateSelection(left, width) {
      for (const track of $("traceViewport").querySelectorAll(".trace-track")) {
        track.classList.add("selecting");
        track.style.setProperty("--selection-left", `${left}px`);
        track.style.setProperty("--selection-width", `${width}px`);
      }
    }

    function wireZoomDrag(start, end) {
      const viewport = $("traceViewport");
      viewport.onpointerdown = (event) => {
        if (event.button !== 0) return;
        const track = event.target.closest(".trace-track");
        if (!track) return;
        hideTooltip();
        const rect = track.getBoundingClientRect();
        const x = Math.max(0, Math.min(rect.width, event.clientX - rect.left));
        const marker = event.target.closest("[data-trace-event]");
        state.dragState = { startX: x, currentX: x, rectWidth: rect.width, domainStart: start, domainEnd: end, eventId: marker?.dataset.traceEvent || null };
        viewport.setPointerCapture?.(event.pointerId);
        updateSelection(x, 0);
        event.preventDefault();
      };
      viewport.onpointermove = (event) => {
        if (!state.dragState) return;
        const track = event.target.closest(".trace-track") || viewport.querySelector(".trace-track");
        if (!track) return;
        const rect = track.getBoundingClientRect();
        const x = Math.max(0, Math.min(state.dragState.rectWidth, event.clientX - rect.left));
        state.dragState.currentX = x;
        updateSelection(Math.min(state.dragState.startX, x), Math.abs(x - state.dragState.startX));
      };
      viewport.onpointerup = (event) => {
        if (!state.dragState) return;
        const { startX, currentX, rectWidth, domainStart, domainEnd, eventId } = state.dragState;
        state.dragState = null;
        clearSelection();
        viewport.releasePointerCapture?.(event.pointerId);
        if (Math.abs(currentX - startX) < 8 || rectWidth <= 0) {
          if (eventId && state.measureMode) selectCompareEvent(eventId);
          return;
        }
        const duration = domainEnd - domainStart;
        const selectedStart = domainStart + (Math.min(startX, currentX) / rectWidth) * duration;
        const selectedEnd = domainStart + (Math.max(startX, currentX) / rectWidth) * duration;
        setZoomRange(selectedStart, selectedEnd);
      };
      viewport.onpointercancel = () => {
        state.dragState = null;
        clearSelection();
      };
    }

    function bindControls() {
      $("traceEcuFilter").addEventListener("change", () => render(currentReport(), true, true));
      $("traceKindFilter").addEventListener("change", () => render(currentReport(), true, true));
      $("traceAdvancedToggle").addEventListener("click", () => {
        $("traceAdvancedPanel").hidden = !$("traceAdvancedPanel").hidden;
      });
      for (const input of document.querySelectorAll(".trace-layer-toggle")) {
        input.addEventListener("change", () => {
          state.layerState[input.dataset.traceLayer] = input.checked;
          render(currentReport(), true, true);
        });
      }
      $("traceAdvancedPanel").addEventListener("change", (event) => {
        if (!event.target.matches(".trace-type-toggle")) return;
        state.typeState[event.target.dataset.traceType] = event.target.checked;
        render(currentReport(), true, true);
      });
      $("traceZoomReset").addEventListener("click", () => {
        resetZoomState();
        render(currentReport(), true);
      });
      $("traceZoomBack").addEventListener("click", () => {
        if (!state.zoomHistory.length) return;
        const previous = state.zoomHistory.pop();
        state.zoomRange = state.fullRange && previous.start === state.fullRange.start && previous.end === state.fullRange.end ? null : previous;
        render(currentReport(), true);
      });
      $("traceMeasureToggle").addEventListener("click", () => {
        state.measureMode = !state.measureMode;
        if (!state.measureMode) state.compareSelection = [];
        updateCompareDisplay();
        render(currentReport(), true);
      });
      $("traceCompareClear").addEventListener("click", () => {
        state.compareSelection = [];
        render(currentReport(), true);
      });
    }

    return {
      bindControls,
      render,
      relationshipForEvent,
      tooltipContent,
      state
    };
  }

  global.HarnessTraceController = Object.freeze({ createTraceController });
})(window);
