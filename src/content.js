/*
 * PhishGuard content script. Runs on every page.
 *
 *   1. Analyze the URL and every password/card form; send findings to the background.
 *   2. Show a warning banner if the background says the page is risky.
 *   3. Intercept submission of a risky credential form and ask the user first.
 *
 * Security notes:
 *   - All UI lives in a *closed* shadow root, so page scripts can't read or click it.
 *   - Button handlers require event.isTrusted, so a page can't fake a user click.
 *   - Text is set with textContent, never innerHTML. Hostnames are attacker-controlled
 *     input, and innerHTML would let a malicious page inject markup into our warning.
 *   - Form actions are read with getAttribute("action"). form.action can be
 *     "clobbered" by an <input name="action">, which a phishing kit could use to hide
 *     where the form really posts.
 */
(() => {
  "use strict";

  const PG = globalThis.PhishGuard;
  const CARD_FIELD = 'input[autocomplete^="cc-"], input[name*="cardnumber" i], input[name*="card_number" i], input[id*="cardnumber" i]';
  const RISKY_FORM_WEIGHT = 30;

  let trusted = false;
  let lastReportKey = "";
  const confirmedForms = new WeakSet();

  // ---------------------------------------------------------------------------
  // Analysis
  // ---------------------------------------------------------------------------

  function describeForm(form) {
    return {
      action: form.getAttribute("action") || "",
      method: form.getAttribute("method") || "get",
      hasPassword: !!form.querySelector('input[type="password"]'),
      hasCardField: !!form.querySelector(CARD_FIELD),
    };
  }

  function analyzeFormElement(form) {
    return PG.analyzeForm(describeForm(form), location.href, document.baseURI);
  }

  function collectFindings() {
    const findings = PG.analyzeUrl(location.href);
    for (const form of document.forms) findings.push(...analyzeFormElement(form));
    return findings;
  }

  async function report() {
    const findings = collectFindings();
    const key = JSON.stringify(findings.map((f) => f.id + f.message));
    if (key === lastReportKey) return;
    lastReportKey = key;

    let verdict;
    try {
      verdict = await chrome.runtime.sendMessage({ type: "pg:report", findings });
    } catch {
      return; // extension was reloaded or updated; this page's script is orphaned
    }
    if (!verdict) return;
    trusted = verdict.trusted;
    if (!trusted && verdict.level !== "safe") showBanner(verdict);
    else removeBanner();
  }

  // ---------------------------------------------------------------------------
  // UI (closed shadow DOM, styled with a constructable stylesheet so page CSP
  // rules for inline <style> don't block it)
  // ---------------------------------------------------------------------------

  const CSS = `
    :host { all: initial; }
    .banner {
      position: fixed; top: 0; left: 0; right: 0; z-index: 2147483647;
      font: 14px/1.4 system-ui, -apple-system, "Segoe UI", sans-serif; color: #fff;
      padding: 12px 16px; display: flex; gap: 16px; align-items: flex-start;
      box-shadow: 0 2px 12px rgba(0,0,0,.35);
    }
    .banner.danger { background: #b3261e; }
    .banner.suspicious { background: #8a5a00; }
    .body { flex: 1; min-width: 0; }
    .title { font-weight: 700; font-size: 15px; margin-bottom: 4px; }
    ul { margin: 4px 0 0; padding-left: 18px; }
    li { margin: 2px 0; overflow-wrap: anywhere; }
    .actions { display: flex; gap: 8px; flex-wrap: wrap; }
    button {
      font: inherit; border: 1px solid rgba(255,255,255,.7); border-radius: 6px;
      padding: 6px 12px; cursor: pointer; background: transparent; color: #fff;
    }
    button.primary { background: #fff; color: #b3261e; border-color: #fff; font-weight: 600; }
    .overlay {
      position: fixed; inset: 0; z-index: 2147483647; background: rgba(0,0,0,.55);
      display: flex; align-items: center; justify-content: center; padding: 16px;
      font: 14px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif;
    }
    .dialog {
      background: #fff; color: #1f1f1f; border-radius: 12px; max-width: 460px; width: 100%;
      padding: 20px 22px; box-shadow: 0 10px 40px rgba(0,0,0,.4); border-top: 6px solid #b3261e;
    }
    .dialog h2 { margin: 0 0 8px; font-size: 18px; color: #b3261e; }
    .dialog li { margin: 4px 0; }
    .dialog .actions { justify-content: flex-end; margin-top: 16px; }
    .dialog button { color: #1f1f1f; border-color: #c4c4c4; }
    .dialog button.primary { background: #b3261e; color: #fff; border-color: #b3261e; }
  `;

  let host = null;
  let shadow = null;

  function getShadow() {
    if (shadow && host.isConnected) return shadow;
    host = document.createElement("phishguard-ui");
    shadow = host.attachShadow({ mode: "closed" });
    const sheet = new CSSStyleSheet();
    sheet.replaceSync(CSS);
    shadow.adoptedStyleSheets = [sheet];
    document.documentElement.appendChild(host);
    return shadow;
  }

  function el(tag, props = {}, children = []) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(props)) {
      if (k === "text") node.textContent = v;
      else if (k === "onClick") node.addEventListener("click", (e) => e.isTrusted && v(e));
      else node.setAttribute(k, v);
    }
    for (const c of children) node.appendChild(c);
    return node;
  }

  function findingList(findings, max) {
    return el("ul", {}, findings.slice(0, max).map((f) => el("li", { text: f.message })));
  }

  function removeBanner() {
    shadow?.querySelector(".banner")?.remove();
  }

  function leaveSite() {
    if (history.length > 1) history.back();
    else location.replace("about:blank");
  }

  function showBanner(verdict) {
    const root = getShadow();
    removeBanner();
    const title = verdict.level === "danger"
      ? `PhishGuard: this page looks like a phishing site (risk ${verdict.score}/100)`
      : `PhishGuard: be careful on this page (risk ${verdict.score}/100)`;

    root.appendChild(
      el("div", { class: `banner ${verdict.level}`, role: "alert" }, [
        el("div", { class: "body" }, [el("div", { class: "title", text: title }), findingList(verdict.findings, 4)]),
        el("div", { class: "actions" }, [
          el("button", { class: "primary", text: "Get me out of here", onClick: leaveSite }),
          el("button", {
            text: "I trust this site",
            onClick: () => chrome.runtime.sendMessage({ type: "pg:set-trust", trusted: true }),
          }),
          el("button", { text: "Dismiss", onClick: removeBanner }),
        ]),
      ])
    );
  }

  function confirmSubmit(findings) {
    return new Promise((resolve) => {
      const root = getShadow();
      const close = (answer) => {
        overlay.remove();
        resolve(answer);
      };
      const cancel = el("button", { class: "primary", text: "Don't send", onClick: () => close(false) });
      const overlay = el("div", { class: "overlay" }, [
        el("div", { class: "dialog", role: "alertdialog", "aria-modal": "true" }, [
          el("h2", { text: "Stop: this form looks unsafe" }),
          el("div", { text: "PhishGuard paused this form before anything was sent:" }),
          findingList(findings, 5),
          el("div", { class: "actions" }, [el("button", { text: "Send anyway", onClick: () => close(true) }), cancel]),
        ]),
      ]);
      root.appendChild(overlay);
      cancel.focus();
    });
  }

  // ---------------------------------------------------------------------------
  // Form submit interception. Capture phase, so we run before the page's own handlers.
  // The action is re-checked at submit time because phishing kits often swap it
  // in with JavaScript after the page has loaded.
  // ---------------------------------------------------------------------------

  document.addEventListener(
    "submit",
    async (event) => {
      const form = event.target;
      if (trusted || !(form instanceof HTMLFormElement) || confirmedForms.has(form)) return;
      const risky = analyzeFormElement(form).filter((f) => f.weight >= RISKY_FORM_WEIGHT);
      if (!risky.length) return;

      event.preventDefault();
      event.stopImmediatePropagation();
      const submitter = event.submitter;
      if (await confirmSubmit(risky)) {
        confirmedForms.add(form);
        if (submitter && submitter.form === form) form.requestSubmit(submitter);
        else form.requestSubmit();
      }
    },
    true
  );

  // ---------------------------------------------------------------------------
  // Wiring
  // ---------------------------------------------------------------------------

  chrome.runtime.onMessage.addListener((msg) => {
    if (msg?.type !== "pg:trust-changed") return;
    trusted = msg.trusted;
    lastReportKey = "";
    if (trusted) removeBanner();
    else report();
  });

  // Single-page apps and phishing kits add login forms (or rewrite their action) after load.
  // Re-scan, debounced.
  let timer = null;
  new MutationObserver(() => {
    clearTimeout(timer);
    timer = setTimeout(report, 500);
  }).observe(document.documentElement, { childList: true, subtree: true, attributes: true, attributeFilter: ["action"] });

  report();
})();
