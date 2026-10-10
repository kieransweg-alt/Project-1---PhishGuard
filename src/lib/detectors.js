/*
 * PhishGuard detection engine.
 *
 * Pure functions only: no chrome.* or DOM APIs. That lets the exact same file run in
 * the content script, the background service worker, and the Node unit tests.
 *
 * Every detector returns an array of "findings":
 *   { id, category, weight, message }
 * scoreFindings() adds the weights up into a 0-100 risk score.
 */
(function (root) {
  "use strict";

  // ---------------------------------------------------------------------------
  // Reference data
  // ---------------------------------------------------------------------------

  // Brands that phishers love to impersonate.
  //   domains:  official domains (and their subdomains) that are always trusted
  //   keywords: the name an attacker would imitate in a fake domain
  const BRANDS = [
    { name: "PayPal", domains: ["paypal.com", "paypal.me", "paypalobjects.com"], keywords: ["paypal"] },
    {
      name: "Google",
      domains: ["google.com", "gmail.com", "youtube.com", "gstatic.com", "googleusercontent.com", "googleapis.com"],
      keywords: ["google", "gmail", "youtube"],
    },
    { name: "Apple", domains: ["apple.com", "icloud.com"], keywords: ["apple", "icloud"] },
    {
      name: "Microsoft",
      domains: ["microsoft.com", "live.com", "outlook.com", "office.com", "microsoftonline.com", "office365.com", "bing.com"],
      keywords: ["microsoft", "outlook", "office365", "microsoftonline"],
    },
    {
      name: "Amazon",
      domains: ["amazon.com", "amazonaws.com", "amazon.co.uk", "amazon.ca", "amazon.de"],
      keywords: ["amazon"],
    },
    { name: "Facebook", domains: ["facebook.com", "fb.com", "messenger.com"], keywords: ["facebook"] },
    { name: "Instagram", domains: ["instagram.com"], keywords: ["instagram"] },
    { name: "Netflix", domains: ["netflix.com"], keywords: ["netflix"] },
    { name: "LinkedIn", domains: ["linkedin.com"], keywords: ["linkedin"] },
    { name: "GitHub", domains: ["github.com", "githubusercontent.com"], keywords: ["github"] },
    { name: "Dropbox", domains: ["dropbox.com"], keywords: ["dropbox"] },
    { name: "Coinbase", domains: ["coinbase.com"], keywords: ["coinbase"] },
    { name: "Binance", domains: ["binance.com"], keywords: ["binance"] },
    { name: "Chase", domains: ["chase.com"], keywords: ["chase"] },
    { name: "Bank of America", domains: ["bankofamerica.com"], keywords: ["bankofamerica"] },
    { name: "Wells Fargo", domains: ["wellsfargo.com"], keywords: ["wellsfargo"] },
    { name: "Yahoo", domains: ["yahoo.com"], keywords: ["yahoo"] },
    { name: "eBay", domains: ["ebay.com"], keywords: ["ebay"] },
    { name: "Steam", domains: ["steampowered.com", "steamcommunity.com"], keywords: ["steampowered", "steamcommunity"] },
    { name: "DHL", domains: ["dhl.com"], keywords: ["dhl"] },
    { name: "FedEx", domains: ["fedex.com"], keywords: ["fedex"] },
    { name: "USPS", domains: ["usps.com"], keywords: ["usps"] },
    { name: "WhatsApp", domains: ["whatsapp.com"], keywords: ["whatsapp"] },
  ];

  // Characters that look like ASCII letters. Attackers swap them in: paypa1.com, g00gle.com,
  // or Cyrillic "а" (U+0430) instead of Latin "a".
  const CONFUSABLES = {
    0: "o", 3: "e", 4: "a", 5: "s", 7: "t", 8: "b", 9: "g", "@": "a", $: "s", "|": "l",
    // Cyrillic
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i",
    "ј": "j", "ѕ": "s", "ԁ": "d", "һ": "h", "ӏ": "l", "ԛ": "q", "ԝ": "w", "ɡ": "g",
    // Greek
    "α": "a", "ο": "o", "ν": "v", "ρ": "p", "τ": "t", "ι": "i", "κ": "k",
    // Latin lookalikes
    "ı": "i", "ł": "l",
  };

  const SUSPICIOUS_TLDS = new Set([
    "zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "country", "kim", "work",
    "rest", "fit", "loan", "cam", "icu", "buzz", "monster", "cyou", "sbs",
  ]);

  const LURE_WORDS = [
    "login", "signin", "sign-in", "verify", "verification", "secure", "account", "update",
    "wallet", "banking", "confirm", "unlock", "suspended", "recover",
  ];

  const URL_SHORTENERS = new Set([
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
    "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc",
  ]);

  // Public suffixes with two labels. A real implementation would use the full Public Suffix
  // List (https://publicsuffix.org); this short list covers the common cases.
  const MULTI_PART_SUFFIXES = new Set([
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz", "co.jp",
    "co.in", "com.br", "com.mx", "co.za", "com.sg", "com.cn", "com.tr",
  ]);

  const LEVELS = { DANGER: 60, SUSPICIOUS: 30 };

  // ---------------------------------------------------------------------------
  // Domain helpers
  // ---------------------------------------------------------------------------

  function isIpAddress(hostname) {
    return /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) || hostname.startsWith("[") || hostname.includes(":");
  }

  function isLocalHost(hostname) {
    const h = hostname.toLowerCase();
    return (
      h === "localhost" ||
      h.endsWith(".localhost") ||
      h.endsWith(".test") ||
      h === "[::1]" ||
      /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h)
    );
  }

  /** "login.secure.paypal.com" -> "paypal.com", "shop.amazon.co.uk" -> "amazon.co.uk" */
  function getRegistrableDomain(hostname) {
    const h = hostname.toLowerCase().replace(/\.$/, "");
    if (isIpAddress(h)) return h;
    const parts = h.split(".");
    if (parts.length <= 2) return h;
    const lastTwo = parts.slice(-2).join(".");
    return MULTI_PART_SUFFIXES.has(lastTwo) ? parts.slice(-3).join(".") : lastTwo;
  }

  function findOfficialBrand(hostname) {
    const h = hostname.toLowerCase();
    return BRANDS.find((b) => b.domains.some((d) => h === d || h.endsWith("." + d))) || null;
  }

  // RFC 3492 Punycode decoder. Browsers hand us "xn--pypal-4ve.com"; we need the Unicode
  // form ("pаypal") to see which letters were swapped.
  const PUNY = { base: 36, tMin: 1, tMax: 26, skew: 38, damp: 700, bias: 72, n: 128 };

  function punyAdapt(delta, numPoints, firstTime) {
    const { base, tMin, tMax, skew, damp } = PUNY;
    delta = firstTime ? Math.floor(delta / damp) : delta >> 1;
    delta += Math.floor(delta / numPoints);
    let k = 0;
    while (delta > ((base - tMin) * tMax) >> 1) {
      delta = Math.floor(delta / (base - tMin));
      k += base;
    }
    return k + Math.floor(((base - tMin + 1) * delta) / (delta + skew));
  }

  function punyDigit(cp) {
    if (cp >= 48 && cp <= 57) return cp - 22; // 0-9 -> 26-35
    if (cp >= 65 && cp <= 90) return cp - 65; // A-Z -> 0-25
    if (cp >= 97 && cp <= 122) return cp - 97; // a-z -> 0-25
    return PUNY.base;
  }

  function punycodeDecode(input) {
    const { base, tMin, tMax } = PUNY;
    const output = [];
    let n = PUNY.n;
    let bias = PUNY.bias;
    let i = 0;
    const basic = Math.max(input.lastIndexOf("-"), 0);
    for (let j = 0; j < basic; j++) output.push(input.charCodeAt(j));

    for (let index = basic > 0 ? basic + 1 : 0; index < input.length; ) {
      const oldi = i;
      let w = 1;
      for (let k = base; ; k += base) {
        if (index >= input.length) throw new Error("Invalid punycode");
        const digit = punyDigit(input.charCodeAt(index++));
        if (digit >= base) throw new Error("Invalid punycode");
        i += digit * w;
        const t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;
        if (digit < t) break;
        w *= base - t;
      }
      const len = output.length + 1;
      bias = punyAdapt(i - oldi, len, oldi === 0);
      n += Math.floor(i / len);
      i %= len;
      output.splice(i++, 0, n);
    }
    return String.fromCodePoint(...output);
  }

  function toUnicodeLabel(label) {
    if (!label.startsWith("xn--")) return label;
    try {
      return punycodeDecode(label.slice(4));
    } catch {
      return label;
    }
  }

  function toUnicodeHost(hostname) {
    return hostname.split(".").map(toUnicodeLabel).join(".");
  }

  /**
   * Every plausible "what the attacker wants you to read" version of a label.
   * "paypa1" -> {"paypa1", "paypal", "paypai"}, "arnazon" -> {..., "amazon"}
   */
  function normalizeVariants(label) {
    const stripped = label.normalize("NFKD").replace(/[̀-ͯ]/g, "").toLowerCase();
    const mapped = [...stripped].map((ch) => CONFUSABLES[ch] || ch).join("");
    const bases = [mapped, mapped.replace(/rn/g, "m").replace(/vv/g, "w")];
    const variants = new Set([label]);
    for (const b of bases) {
      variants.add(b.replace(/1/g, "l"));
      variants.add(b.replace(/1/g, "i"));
    }
    return variants;
  }

  /** Optimal-string-alignment distance: insert, delete, substitute, or swap neighbours. */
  function editDistance(a, b) {
    const d = Array.from({ length: a.length + 1 }, (_, i) => [i]);
    for (let j = 1; j <= b.length; j++) d[0][j] = j;
    for (let i = 1; i <= a.length; i++) {
      for (let j = 1; j <= b.length; j++) {
        const cost = a[i - 1] === b[j - 1] ? 0 : 1;
        d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
        if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
          d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
        }
      }
    }
    return d[a.length][b.length];
  }

  function finding(category, id, weight, message) {
    return { id, category, weight, message };
  }

  // ---------------------------------------------------------------------------
  // Detectors
  // ---------------------------------------------------------------------------

  /** Lookalike / typosquat / brand-abuse detection for one hostname. */
  function detectLookalike(hostname) {
    const host = hostname.toLowerCase();
    if (isIpAddress(host) || isLocalHost(host) || findOfficialBrand(host)) return [];

    const reg = getRegistrableDomain(host);
    const regLabel = toUnicodeLabel(reg.split(".")[0]);
    const variants = normalizeVariants(regLabel);
    const tokens = regLabel.split(/[-_]/);
    const subLabels = host.split(".").slice(0, -reg.split(".").length);
    const findings = [];

    for (const brand of BRANDS) {
      const hit = (() => {
        for (const kw of brand.keywords) {
          if (regLabel === kw) {
            return finding("url", "brand-other-domain", 15,
              `Uses the name "${brand.name}" but ${reg} is not an official ${brand.name} domain`);
          }
          if (variants.has(kw)) {
            return finding("url", "homoglyph", 45,
              `"${toUnicodeHost(reg)}" imitates ${brand.name} using lookalike characters`);
          }
          if (kw.length >= 6 && [...variants].some((v) => editDistance(v, kw) === 1)) {
            return finding("url", "typosquat", 40,
              `"${reg}" is one typo away from ${brand.name} (${kw})`);
          }
          if (subLabels.some((l) => normalizeVariants(toUnicodeLabel(l)).has(kw))) {
            return finding("url", "brand-in-subdomain", 30,
              `"${brand.name}" appears in the subdomain, but the real site is ${reg}`);
          }
          if (tokens.includes(kw)) {
            return finding("url", "combosquat", 20,
              `Domain contains "${brand.name}" but isn't an official ${brand.name} domain`);
          }
        }
        return null;
      })();
      if (hit) findings.push(hit);
    }
    return findings;
  }

  /** Signals that come from the page URL alone. */
  function analyzeUrl(urlString) {
    let url;
    try {
      url = new URL(urlString);
    } catch {
      return [];
    }
    if (url.protocol !== "http:" && url.protocol !== "https:") return [];
    const host = url.hostname.toLowerCase();
    if (isLocalHost(host)) return [];

    const findings = [];
    const add = (id, weight, message) => findings.push(finding("url", id, weight, message));
    const official = findOfficialBrand(host);
    const reg = getRegistrableDomain(host);

    if (isIpAddress(host)) add("ip-host", 25, `Site is a raw IP address (${host}) instead of a domain name`);
    if (url.username || url.password) {
      add("userinfo", 30, `The URL uses an "@" trick: everything before it is ignored, the real site is ${host}`);
    }
    if (host.split(".").some((l) => l.startsWith("xn--"))) {
      add("punycode", 15, `Domain uses international characters: ${toUnicodeHost(host)}`);
    }
    findings.push(...detectLookalike(host));

    if (!isIpAddress(host)) {
      const labels = host.split(".");
      if (labels.length > 4) add("deep-subdomain", 10, `Unusually deep subdomain (${labels.length} levels)`);
      if (host.length > 50) add("long-host", 10, `Very long domain name (${host.length} characters)`);
      if (SUSPICIOUS_TLDS.has(labels[labels.length - 1])) {
        add("risky-tld", 10, `.${labels[labels.length - 1]} is a top-level domain frequently used for phishing`);
      }
      if ((reg.split(".")[0].match(/-/g) || []).length >= 3) add("hyphens", 5, "Domain has many hyphens");
    }
    if (url.protocol === "http:") add("no-https", 10, "Connection is not encrypted (HTTP, not HTTPS)");
    if (!official) {
      const lures = LURE_WORDS.filter((w) => host.includes(w));
      if (lures.length) add("lure-words", 10, `Domain contains bait words: ${lures.join(", ")}`);
    }

    for (const value of url.searchParams.values()) {
      if (!/^https?:\/\//i.test(value)) continue;
      try {
        const target = new URL(value);
        if (getRegistrableDomain(target.hostname) !== reg) {
          add("embedded-redirect", 10, `URL carries a link to another site (${target.hostname}), a common open-redirect trick`);
          break;
        }
      } catch {
        // not a URL after all
      }
    }
    return findings;
  }

  /**
   * Signals from a form on the page.
   * @param form    { action, method, hasPassword, hasCardField } (action may be relative or "")
   * @param pageUrl the page the form lives on
   * @param baseUrl document.baseURI, used to resolve a relative action (defaults to pageUrl)
   */
  function analyzeForm(form, pageUrl, baseUrl) {
    if (!form.hasPassword && !form.hasCardField) return [];
    const findings = [];
    const add = (id, weight, message) => findings.push(finding("form", id, weight, message));
    const what = form.hasPassword ? "your password" : "card details";

    let page;
    let target;
    try {
      page = new URL(pageUrl);
      target = new URL(form.action || pageUrl, baseUrl || pageUrl);
    } catch {
      return [];
    }

    if (target.protocol === "mailto:") {
      add("form-mailto", 40, `This form emails ${what} to ${decodeURIComponent(target.pathname)}`);
      return findings;
    }
    // javascript: and friends mean the page submits with its own script; nothing to inspect.
    if (target.protocol !== "http:" && target.protocol !== "https:") return findings;

    if (target.protocol === "http:" && !isLocalHost(target.hostname)) {
      add("form-insecure", 30, `This form sends ${what} over unencrypted HTTP`);
    }
    if (getRegistrableDomain(target.hostname) !== getRegistrableDomain(page.hostname)) {
      add("form-external", 35, `This form sends ${what} to a different site: ${target.hostname}`);
    }
    if (form.hasPassword && (form.method || "get").toLowerCase() === "get") {
      add("form-get", 15, "This form would put your password in the URL (GET request)");
    }
    return findings;
  }

  /** Signals from the redirect chain that led to the page. chain = [firstUrl, ..., finalUrl] */
  function analyzeRedirects(chain) {
    if (!Array.isArray(chain) || chain.length < 2) return [];
    const findings = [];
    const add = (id, weight, message) => findings.push(finding("redirect", id, weight, message));

    const domains = [];
    for (const u of chain) {
      try {
        const d = getRegistrableDomain(new URL(u).hostname);
        if (domains[domains.length - 1] !== d) domains.push(d);
      } catch {
        // skip unparsable hop
      }
    }
    const distinct = [...new Set(domains)];
    const hops = chain.length - 1;

    if (hops >= 3) add("redirect-chain", 10, `Arrived here through ${hops} redirects`);
    if (distinct.length >= 3) add("redirect-domains", 15, `Redirects crossed ${distinct.length} sites: ${domains.join(" → ")}`);
    if (URL_SHORTENERS.has(domains[0]) && distinct.length > 1) {
      add("shortener", 10, `Started from a link shortener (${domains[0]}) that hid the real destination`);
    }
    return findings;
  }

  /** Combine findings into a verdict. */
  function scoreFindings(findings) {
    const seen = new Set();
    const unique = [];
    for (const f of findings) {
      const key = f.id + "|" + f.message;
      if (!seen.has(key)) {
        seen.add(key);
        unique.push(f);
      }
    }
    unique.sort((a, b) => b.weight - a.weight);
    const score = Math.min(100, unique.reduce((sum, f) => sum + f.weight, 0));
    const level = score >= LEVELS.DANGER ? "danger" : score >= LEVELS.SUSPICIOUS ? "suspicious" : "safe";
    return { score, level, findings: unique };
  }

  const api = {
    BRANDS,
    LEVELS,
    isIpAddress,
    isLocalHost,
    getRegistrableDomain,
    findOfficialBrand,
    punycodeDecode,
    toUnicodeHost,
    normalizeVariants,
    editDistance,
    detectLookalike,
    analyzeUrl,
    analyzeForm,
    analyzeRedirects,
    scoreFindings,
  };

  root.PhishGuard = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof globalThis !== "undefined" ? globalThis : self);
