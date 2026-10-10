const test = require("node:test");
const assert = require("node:assert/strict");
const { domainToASCII } = require("node:url");
const PG = require("../src/lib/detectors.js");

const ids = (findings) => findings.map((f) => f.id);

test("getRegistrableDomain strips subdomains and respects two-part suffixes", () => {
  assert.equal(PG.getRegistrableDomain("login.secure.paypal.com"), "paypal.com");
  assert.equal(PG.getRegistrableDomain("shop.amazon.co.uk"), "amazon.co.uk");
  assert.equal(PG.getRegistrableDomain("example.com"), "example.com");
  assert.equal(PG.getRegistrableDomain("10.0.0.5"), "10.0.0.5");
});

test("punycodeDecode reverses the browser's xn-- encoding", () => {
  const cyrillicA = "а";
  const ascii = domainToASCII(`p${cyrillicA}ypal.com`); // what Chrome puts in location.hostname
  assert.match(ascii, /^xn--/);
  const label = ascii.split(".")[0].slice(4);
  assert.equal(PG.punycodeDecode(label), `p${cyrillicA}ypal`);
  assert.equal(PG.punycodeDecode(domainToASCII("münchen.de").slice(4, -3)), "münchen");
});

test("editDistance counts swaps as one edit", () => {
  assert.equal(PG.editDistance("google", "google"), 0);
  assert.equal(PG.editDistance("gooogle", "google"), 1);
  assert.equal(PG.editDistance("googel", "google"), 1);
  assert.equal(PG.editDistance("kitten", "sitting"), 3);
});

test("official brand domains are never flagged", () => {
  for (const host of ["paypal.com", "www.paypal.com", "accounts.google.com", "github.com", "login.microsoftonline.com"]) {
    assert.deepEqual(PG.detectLookalike(host), [], host);
    assert.deepEqual(PG.analyzeUrl(`https://${host}/login`), [], host);
  }
});

test("detectLookalike catches character swaps", () => {
  assert.deepEqual(ids(PG.detectLookalike("paypa1.com")), ["homoglyph"]);
  assert.deepEqual(ids(PG.detectLookalike("g00gle.com")), ["homoglyph"]);
  assert.deepEqual(ids(PG.detectLookalike("arnazon.com")), ["homoglyph"]); // rn -> m
  assert.deepEqual(ids(PG.detectLookalike(domainToASCII("pаypal.com"))), ["homoglyph"]);
});

test("detectLookalike catches typos, subdomain tricks and combosquats", () => {
  assert.deepEqual(ids(PG.detectLookalike("microsofft.com")), ["typosquat"]);
  assert.deepEqual(ids(PG.detectLookalike("linkdein.com")), ["typosquat"]);
  assert.deepEqual(ids(PG.detectLookalike("paypal.com.secure-check.xyz")), ["brand-in-subdomain"]);
  assert.deepEqual(ids(PG.detectLookalike("paypal-account-verify.com")), ["combosquat"]);
  assert.deepEqual(ids(PG.detectLookalike("paypal.net")), ["brand-other-domain"]);
});

test("detectLookalike leaves ordinary domains alone", () => {
  for (const host of ["example.com", "pineapple.com", "chaser.org", "wikipedia.org", "news.ycombinator.com"]) {
    assert.deepEqual(PG.detectLookalike(host), [], host);
  }
});

test("analyzeUrl flags classic URL tricks", () => {
  assert.deepEqual(ids(PG.analyzeUrl("http://192.168.1.10/login")).sort(), ["ip-host", "no-https"]);
  assert.ok(ids(PG.analyzeUrl("https://paypal.com@evil.example/")).includes("userinfo"));
  assert.ok(ids(PG.analyzeUrl("https://example.com/out?next=https://evil.xyz/")).includes("embedded-redirect"));
  assert.ok(ids(PG.analyzeUrl("https://secure-login.zip/")).includes("risky-tld"));
  assert.ok(ids(PG.analyzeUrl("https://account-verify-login.example.com/")).includes("lure-words"));
});

test("analyzeUrl ignores local development hosts and non-web schemes", () => {
  assert.deepEqual(PG.analyzeUrl("http://localhost:8000/login"), []);
  assert.deepEqual(PG.analyzeUrl("http://127.0.0.1/"), []);
  assert.deepEqual(PG.analyzeUrl("chrome://settings"), []);
  assert.deepEqual(PG.analyzeUrl("not a url"), []);
});

test("analyzeForm flags credentials leaving the site", () => {
  const page = "https://paypa1.com/signin";
  const external = { action: "https://collector.example.net/grab.php", method: "post", hasPassword: true };
  assert.deepEqual(ids(PG.analyzeForm(external, page)), ["form-external"]);

  const insecure = { action: "http://paypa1.com/post", method: "post", hasPassword: true };
  assert.deepEqual(ids(PG.analyzeForm(insecure, page)), ["form-insecure"]);

  const mailto = { action: "mailto:thief@example.com", method: "post", hasPassword: true };
  assert.deepEqual(ids(PG.analyzeForm(mailto, page)), ["form-mailto"]);

  const get = { action: "/login", method: "get", hasPassword: true };
  assert.deepEqual(ids(PG.analyzeForm(get, page)), ["form-get"]);

  const card = { action: "https://other.example/pay", method: "post", hasCardField: true };
  assert.match(PG.analyzeForm(card, page)[0].message, /card details/);
});

test("analyzeForm stays quiet for normal forms", () => {
  const page = "https://example.com/login";
  assert.deepEqual(PG.analyzeForm({ action: "/session", method: "post", hasPassword: true }, page), []);
  assert.deepEqual(PG.analyzeForm({ action: "", method: "post", hasPassword: true }, page), []);
  assert.deepEqual(PG.analyzeForm({ action: "https://auth.example.com/x", method: "post", hasPassword: true }, page), []);
  assert.deepEqual(PG.analyzeForm({ action: "https://evil.example/", method: "post", hasPassword: false }, page), []);
  assert.deepEqual(PG.analyzeForm({ action: "javascript:void(0)", method: "post", hasPassword: true }, page), []);
});

test("analyzeRedirects scores long, multi-site chains", () => {
  const chain = ["https://bit.ly/abc", "https://track.adnet.example/c", "https://login.evil.xyz/", "https://paypa1.com/"];
  assert.deepEqual(ids(PG.analyzeRedirects(chain)).sort(), ["redirect-chain", "redirect-domains", "shortener"]);
  assert.deepEqual(PG.analyzeRedirects(["https://example.com/"]), []);
  assert.deepEqual(PG.analyzeRedirects(["http://example.com/", "https://example.com/"]), []);
});

test("scoreFindings caps at 100, dedupes and picks a level", () => {
  const f = (id, weight) => ({ id, weight, message: id, category: "url" });
  assert.equal(PG.scoreFindings([]).level, "safe");
  assert.equal(PG.scoreFindings([f("a", 30)]).level, "suspicious");
  assert.equal(PG.scoreFindings([f("a", 30), f("a", 30)]).score, 30);
  const big = PG.scoreFindings([f("a", 45), f("b", 35), f("c", 40)]);
  assert.equal(big.score, 100);
  assert.equal(big.level, "danger");
  assert.equal(big.findings[0].id, "a");
});

test("end to end: a fake PayPal login posting off-site is dangerous", () => {
  const page = "https://paypa1.com/signin";
  const findings = [
    ...PG.analyzeUrl(page),
    ...PG.analyzeForm({ action: "https://collector.example.net/", method: "post", hasPassword: true }, page),
  ];
  assert.equal(PG.scoreFindings(findings).level, "danger");
});
