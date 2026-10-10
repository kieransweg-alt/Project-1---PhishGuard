// Popup: shows the stored verdict for the active tab. Everything is rendered with
// textContent because URLs and findings come from untrusted pages.

const $ = (id) => document.getElementById(id);

function li(text, extra) {
  const item = document.createElement("li");
  item.textContent = text;
  if (extra) {
    const span = document.createElement("span");
    span.className = "weight";
    span.textContent = extra;
    item.appendChild(span);
  }
  return item;
}

function render(tabId, state) {
  if (!state || !state.verdict) {
    $("unsupported").hidden = false;
    return;
  }
  const { verdict, findings, chain, url, trusted } = state;
  const level = trusted ? "safe" : verdict.level;

  $("report").hidden = false;
  $("host").textContent = new URL(url).hostname;
  $("score").textContent = verdict.score;
  $("score").className = `score ${level}`;
  $("level").textContent = trusted ? "Trusted by you" : verdict.level;
  $("level").className = `level ${level}`;
  $("summary").textContent = `Risk score ${verdict.score}/100`;

  const list = $("findings");
  list.replaceChildren();
  if (!findings.length) list.appendChild(li("No phishing signals found."));
  for (const f of findings) list.appendChild(li(f.message, `+${f.weight}`));

  if (chain && chain.length > 1) {
    $("chain-section").hidden = false;
    $("chain").replaceChildren(...chain.map((u) => li(u)));
  }

  const button = $("trust");
  button.textContent = trusted ? "Stop trusting this site" : "Trust this site";
  button.onclick = async () => {
    await chrome.runtime.sendMessage({ type: "pg:set-trust", tabId, trusted: !trusted });
    render(tabId, await chrome.runtime.sendMessage({ type: "pg:get-tab", tabId }));
  };
}

(async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab) return;
  render(tab.id, await chrome.runtime.sendMessage({ type: "pg:get-tab", tabId: tab.id }));
})();
