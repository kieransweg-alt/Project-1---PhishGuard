/*
 * PhishGuard background service worker.
 *
 * Jobs:
 *   1. Record the redirect chain that led to each tab's page (server + client redirects).
 *   2. Receive page reports from the content script, add redirect findings, score them.
 *   3. Show the verdict on the toolbar badge and keep it for the popup.
 *   4. Own the "trusted sites" allowlist.
 */
importScripts("lib/detectors.js");

const PG = self.PhishGuard;
const BADGE = {
  danger: { text: "!", color: "#d93025" },
  suspicious: { text: "?", color: "#f29900" },
};

// tabId -> { requestId, chain } for the main-frame request currently loading.
// In memory only: these events arrive within milliseconds of each other.
const serverHops = new Map();

// ---------------------------------------------------------------------------
// Storage helpers. Per-tab state lives in storage.session because MV3 service
// workers are shut down when idle and lose their globals.
// ---------------------------------------------------------------------------

const tabKey = (tabId) => `tab:${tabId}`;

async function getTabState(tabId) {
  const key = tabKey(tabId);
  return (await chrome.storage.session.get(key))[key] || null;
}

async function setTabState(tabId, state) {
  await chrome.storage.session.set({ [tabKey(tabId)]: state });
}

async function getAllowlist() {
  return (await chrome.storage.local.get("allowlist")).allowlist || [];
}

async function isTrusted(url) {
  try {
    const domain = PG.getRegistrableDomain(new URL(url).hostname);
    return (await getAllowlist()).includes(domain);
  } catch {
    return false;
  }
}

async function setTrusted(url, trusted) {
  const domain = PG.getRegistrableDomain(new URL(url).hostname);
  const list = new Set(await getAllowlist());
  if (trusted) list.add(domain);
  else list.delete(domain);
  await chrome.storage.local.set({ allowlist: [...list] });
}

function updateBadge(tabId, verdict) {
  const style = verdict && BADGE[verdict.level];
  chrome.action.setBadgeText({ tabId, text: style ? style.text : "" });
  if (style) chrome.action.setBadgeBackgroundColor({ tabId, color: style.color });
  chrome.action.setTitle({
    tabId,
    title: verdict ? `PhishGuard: ${verdict.level} (risk ${verdict.score}/100)` : "PhishGuard",
  });
}

// ---------------------------------------------------------------------------
// Redirect tracking
// ---------------------------------------------------------------------------

const MAIN_FRAME = { urls: ["<all_urls>"], types: ["main_frame"] };

chrome.webRequest.onBeforeRequest.addListener((d) => {
  if (d.tabId < 0) return;
  const current = serverHops.get(d.tabId);
  if (!current || current.requestId !== d.requestId) {
    serverHops.set(d.tabId, { requestId: d.requestId, chain: [d.url] });
  }
}, MAIN_FRAME);

chrome.webRequest.onBeforeRedirect.addListener((d) => {
  const current = serverHops.get(d.tabId);
  if (current && current.requestId === d.requestId) current.chain.push(d.redirectUrl);
}, MAIN_FRAME);

chrome.webNavigation.onCommitted.addListener(async (d) => {
  if (d.frameId !== 0) return;
  const hops = serverHops.get(d.tabId)?.chain;
  serverHops.delete(d.tabId);

  // Only trust the recorded chain if it actually ends at the page that committed.
  let chain = hops && hops[hops.length - 1] === d.url ? hops : [d.url];

  // A meta-refresh / JS redirect continues the previous page's chain.
  if (d.transitionQualifiers.includes("client_redirect")) {
    const previous = await getTabState(d.tabId);
    if (previous?.chain) chain = [...previous.chain, ...chain];
  }
  chain = chain.filter((u, i) => u !== chain[i - 1]).slice(-10);

  await setTabState(d.tabId, { url: d.url, documentId: d.documentId, chain, verdict: null, findings: [], trusted: false });
  updateBadge(d.tabId, null);
});

chrome.tabs.onRemoved.addListener((tabId) => {
  serverHops.delete(tabId);
  chrome.storage.session.remove(tabKey(tabId));
});

// ---------------------------------------------------------------------------
// Messages from the content script and popup
// ---------------------------------------------------------------------------

async function handleReport(msg, sender) {
  const tabId = sender.tab.id;
  const url = sender.url; // set by Chrome, so the page can't lie about it
  const trusted = await isTrusted(url);
  const state = (await getTabState(tabId)) || { chain: [url] };

  const verdict = PG.scoreFindings([...msg.findings, ...PG.analyzeRedirects(state.chain)]);

  // A page that redirects away (meta refresh, JS) can report a moment after the next page
  // committed. Don't let that late report overwrite the new page's state.
  if (state.documentId && sender.documentId && state.documentId !== sender.documentId) {
    return { ...verdict, trusted };
  }
  await setTabState(tabId, { ...state, url, verdict: { score: verdict.score, level: verdict.level }, findings: verdict.findings, trusted });
  updateBadge(tabId, trusted ? null : verdict);
  return { ...verdict, trusted };
}

async function handleTrust(msg, sender) {
  const tabId = sender.tab ? sender.tab.id : msg.tabId;
  const state = await getTabState(tabId);
  if (!state) return { ok: false };

  await setTrusted(state.url, msg.trusted);
  await setTabState(tabId, { ...state, trusted: msg.trusted });
  updateBadge(tabId, msg.trusted ? null : state.verdict);
  chrome.tabs.sendMessage(tabId, { type: "pg:trust-changed", trusted: msg.trusted }).catch(() => {});
  return { ok: true };
}

async function handleMessage(msg, sender) {
  switch (msg?.type) {
    case "pg:report":
      return sender.tab ? handleReport(msg, sender) : null;
    case "pg:set-trust":
      return handleTrust(msg, sender);
    case "pg:get-tab":
      return getTabState(msg.tabId);
    default:
      return null;
  }
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id) return false;
  handleMessage(msg, sender).then(sendResponse, (err) => {
    console.error("PhishGuard:", err);
    sendResponse(null);
  });
  return true; // keep the channel open for the async response
});
