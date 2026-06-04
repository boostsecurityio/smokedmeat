/*
Copyright (C) 2026 boostsecurity.io
SPDX-License-Identifier: AGPL-3.0-or-later
*/

(() => {
  const text = (node, value) => {
    if (node) node.textContent = value || "";
  };

  const isTypingTarget = (target) => {
    if (!target) return false;
    const tag = target.tagName ? target.tagName.toLowerCase() : "";
    return tag === "input" || tag === "textarea" || tag === "select" || target.isContentEditable;
  };

  const identityWidget = document.querySelector("[data-identity-widget]");
  if (identityWidget) {
    const button = identityWidget.querySelector("[data-identity-button]");
    const popover = identityWidget.querySelector("[data-identity-popover]");
    const label = identityWidget.querySelector("[data-identity-label]");
    const avatar = identityWidget.querySelector("[data-identity-avatar]");
    const popoverAvatar = identityWidget.querySelector("[data-identity-popover-avatar]");
    const name = identityWidget.querySelector("[data-identity-name]");
    const summary = identityWidget.querySelector("[data-identity-summary]");
    const badges = identityWidget.querySelector("[data-identity-badges]");
    const details = identityWidget.querySelector("[data-identity-details]");
    const rates = identityWidget.querySelector("[data-identity-rates]");
    const link = identityWidget.querySelector("[data-identity-link]");

    const renderAvatar = (target, data) => {
      target.replaceChildren();
      if (data.avatar_url) {
        const img = document.createElement("img");
        img.src = data.avatar_url;
        img.alt = "";
        img.referrerPolicy = "no-referrer";
        target.append(img);
        return;
      }
      target.textContent = (data.label || data.kind || "?").trim().slice(0, 1).toUpperCase();
    };

    const renderIdentity = (data) => {
      text(label, data.label || "GitHub identity");
      renderAvatar(avatar, data);
      renderAvatar(popoverAvatar, data);
      text(name, data.name || data.login || data.label || "GitHub identity");
      text(summary, data.summary || "");
      badges.replaceChildren();
      for (const badge of data.badges || []) {
        const item = document.createElement("span");
        item.className = "identity-badge";
        item.textContent = badge;
        badges.append(item);
      }
      details.replaceChildren();
      for (const detail of data.details || []) {
        const term = document.createElement("dt");
        const value = document.createElement("dd");
        term.textContent = detail.label;
        value.textContent = detail.value;
        details.append(term, value);
      }
      rates.replaceChildren();
      if ((data.rates || []).length > 0) {
        const title = document.createElement("div");
        title.className = "identity-rates-title";
        title.textContent = "Rate limits";
        rates.append(title);
      }
      for (const rate of data.rates || []) {
        const row = document.createElement("div");
        row.className = "identity-rate-row";
        const label = document.createElement("span");
        label.className = "identity-rate-label";
        label.textContent = rate.label;
        const value = document.createElement("span");
        value.className = "identity-rate-value";
        value.textContent = `${rate.remaining}/${rate.limit}`;
        const meter = document.createElement("span");
        meter.className = "identity-rate-meter";
        const fill = document.createElement("span");
        fill.style.width = `${Math.max(0, Math.min(100, rate.percent || 0))}%`;
        meter.append(fill);
        const reset = document.createElement("span");
        reset.className = "identity-rate-reset";
        reset.textContent = rate.reset ? `resets ${rate.reset}` : "";
        row.append(label, value, meter, reset);
        rates.append(row);
      }
      if (data.html_url) {
        link.hidden = false;
        link.href = data.html_url;
        link.textContent = data.kind === "app" || data.kind === "installation" ? "Open public GitHub App page" : "Open public GitHub profile";
      } else {
        link.hidden = true;
      }
    };

    fetch("/viewer/identity", { credentials: "same-origin" })
      .then((response) => response.ok ? response.json() : null)
      .then((data) => {
        if (data) renderIdentity(data);
      })
      .catch(() => {});

    button.addEventListener("click", () => {
      const open = popover.hidden;
      popover.hidden = !open;
      button.setAttribute("aria-expanded", open ? "true" : "false");
    });
    document.addEventListener("click", (event) => {
      if (popover.hidden || identityWidget.contains(event.target)) return;
      popover.hidden = true;
      button.setAttribute("aria-expanded", "false");
    });
    document.addEventListener("keydown", (event) => {
      if (event.key !== "Escape" || popover.hidden) return;
      popover.hidden = true;
      button.setAttribute("aria-expanded", "false");
    });
  }

  const toggles = document.querySelectorAll(".collapse-toggle");
  for (const toggle of toggles) {
    toggle.addEventListener("click", () => {
      const item = toggle.closest(".collapsible-item");
      if (!item) {
        return;
      }
      const collapsed = item.classList.toggle("collapsed");
      toggle.setAttribute("aria-expanded", collapsed ? "false" : "true");
    });
  }

  const linkedLine = (link) => {
    const href = link.getAttribute("href") || "";
    if (!href.startsWith("#L")) {
      return null;
    }
    return document.getElementById(href.slice(1));
  };

  const pulseLine = (line) => {
    line.classList.remove("line-audit-pulse");
    void line.offsetWidth;
    line.classList.add("line-audit-pulse");
  };

  for (const link of document.querySelectorAll(".risk-link[href^='#L'], .line-risk-chip[href^='#L']")) {
    link.addEventListener("mouseenter", () => {
      const line = linkedLine(link);
      if (line) {
        line.classList.add("line-audit-hover");
      }
    });
    link.addEventListener("mouseleave", () => {
      const line = linkedLine(link);
      if (line) {
        line.classList.remove("line-audit-hover");
      }
    });
    link.addEventListener("click", (event) => {
      const line = linkedLine(link);
      if (!line) {
        return;
      }
      event.preventDefault();
      pulseLine(line);
      line.scrollIntoView({ behavior: "smooth", block: "center", inline: "nearest" });
      history.replaceState(null, "", link.getAttribute("href"));
      window.setTimeout(() => pulseLine(line), 260);
    });
  }

  let tableFilterInput = null;
  for (const panel of document.querySelectorAll("[data-filter-panel]")) {
    const input = panel.querySelector("[data-filter-input]");
    const view = panel.nextElementSibling;
    const rows = view ? Array.from(view.querySelectorAll(".directory-row")) : [];
    if (!input || rows.length === 0) continue;
    if (!tableFilterInput) {
      tableFilterInput = input;
    }

    const applyFilter = () => {
      const query = input.value.trim().toLowerCase();
      for (const row of rows) {
        const matched = query === "" || row.textContent.toLowerCase().includes(query);
        row.classList.toggle("is-filtered-out", !matched);
      }
    };

    input.addEventListener("input", applyFilter);
    applyFilter();
  }

  if (tableFilterInput) {
    document.addEventListener("keydown", (event) => {
      if (event.key.toLowerCase() !== "t" || event.metaKey || event.ctrlKey || event.altKey || isTypingTarget(event.target)) {
        return;
      }
      event.preventDefault();
      tableFilterInput.focus();
      tableFilterInput.select();
    });
  }

  const lineRows = document.querySelectorAll(".line-row[id^='L']");
  if (lineRows.length > 0) {
    let overlay = null;
    const closeOverlay = () => {
      if (overlay) {
        overlay.remove();
        overlay = null;
      }
    };

    const jumpToLine = (value) => {
      const lineNumber = Number.parseInt(value, 10);
      if (!Number.isFinite(lineNumber) || lineNumber <= 0) return false;
      const line = document.getElementById(`L${lineNumber}`);
      if (!line) return false;
      closeOverlay();
      pulseLine(line);
      line.scrollIntoView({ behavior: "smooth", block: "center", inline: "nearest" });
      history.replaceState(null, "", `#L${lineNumber}`);
      return true;
    };

    const openOverlay = () => {
      closeOverlay();
      overlay = document.createElement("div");
      overlay.className = "line-jump-overlay";
      const dialog = document.createElement("form");
      dialog.className = "line-jump-dialog";
      const label = document.createElement("label");
      label.textContent = "Jump to line";
      const input = document.createElement("input");
      input.type = "number";
      input.min = "1";
      input.inputMode = "numeric";
      input.autocomplete = "off";
      input.placeholder = "Line number";
      const buttons = document.createElement("div");
      buttons.className = "line-jump-actions";
      const go = document.createElement("button");
      go.className = "button";
      go.type = "submit";
      go.textContent = "Go";
      const cancel = document.createElement("button");
      cancel.className = "button";
      cancel.type = "button";
      cancel.textContent = "Cancel";
      buttons.append(go, cancel);
      label.append(input);
      dialog.append(label, buttons);
      overlay.append(dialog);
      document.body.append(overlay);
      input.focus();

      cancel.addEventListener("click", closeOverlay);
      overlay.addEventListener("click", (event) => {
        if (event.target === overlay) closeOverlay();
      });
      dialog.addEventListener("submit", (event) => {
        event.preventDefault();
        jumpToLine(input.value);
      });
    };

    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape" && overlay) {
        closeOverlay();
        return;
      }
      if (event.key.toLowerCase() !== "l" || event.metaKey || event.ctrlKey || event.altKey || isTypingTarget(event.target)) {
        return;
      }
      event.preventDefault();
      openOverlay();
    });
  }
})();
