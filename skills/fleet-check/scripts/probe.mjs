#!/usr/bin/env node
// Rheono fleet check — read-only recon probe.
// Constraints (enforced): GET/HEAD only, >=1s between requests, <=300 requests,
// same-root scope only, no auth, no mutations, 20 minute wall cap.

import dns from "node:dns";
import tls from "node:tls";
import path from "node:path";
import { setTimeout as sleep } from "node:timers/promises";

const MAX_REQUESTS = 300;
const MIN_INTERVAL_MS = 1050; // 1 rps
const REQ_TIMEOUT_MS = 10_000;
const WALL_CAP_MS = 20 * 60 * 1000;
const CERT_EXPIRY_WARN_DAYS = 14;

// ------------------------------------------------------------- args

const argv = process.argv.slice(2);
if (argv.includes("--help") || argv.length === 0) {
  console.log(
    "usage: probe.mjs <domain> --consent <own|authorized> [--out <dir>]",
  );
  process.exit(argv.length === 0 ? 1 : 0);
}
const domain = argv.find((a) => !a.startsWith("--")).trim().toLowerCase().replace(/^https?:\/\//, "");
const consentIdx = argv.indexOf("--consent");
const consent = consentIdx > -1 ? argv[consentIdx + 1] : null;
const outIdx = argv.indexOf("--out");
const outDir = outIdx > -1 ? argv[outIdx + 1] : process.cwd();

if (!/^[a-z0-9]([a-z0-9-]{0,251}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,251}[a-z0-9])?)+$/.test(domain)) {
  console.error(`invalid domain: ${domain}`);
  process.exit(1);
}
if (consent !== "own" && consent !== "authorized") {
  console.error(
    "refusing to run: pass --consent own (you own this domain) or --consent authorized (written authorization exists).",
  );
  process.exit(2);
}

const startedAt = Date.now();
let requests = 0;
const findings = [];
const info = [];

function add(severity, title, detail, evidence) {
  findings.push({ severity, title, detail, evidence: String(evidence ?? "").slice(0, 400) });
}
function note(detail) {
  info.push(detail);
}

// ------------------------------------------------------------- budget

async function pace() {
  if (Date.now() - startedAt > WALL_CAP_MS) throw new Error("wall cap reached (20 min)");
  if (requests >= MAX_REQUESTS) throw new Error("request budget exhausted (300)");
  await sleep(MIN_INTERVAL_MS);
  requests += 1;
}

async function get(url, extraHeaders = {}) {
  await pace();
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), REQ_TIMEOUT_MS);
  try {
    const r = await fetch(url, {
      redirect: "manual",
      signal: ctrl.signal,
      headers: { "user-agent": "rheono-fleet-check/1.0 (read-only)", ...extraHeaders },
    });
    const body =
      r.status < 400 && r.headers.get("content-length") === null
        ? await r.text().catch(() => "")
        : r.status < 400
          ? await r.text().catch(() => "")
          : "";
    return { status: r.status, headers: r.headers, body: body.slice(0, 8000), url: r.url };
  } catch (e) {
    return { status: 0, headers: new Headers(), body: "", url, error: String(e) };
  } finally {
    clearTimeout(t);
  }
}

// ------------------------------------------------------------- dns + tls

const root = domain.split(".").slice(-2).join(".");
function inScope(host) {
  const h = host.toLowerCase();
  return h === root || h.endsWith(`.${root}`);
}

async function dnsA(host) {
  try {
    return (await dns.promises.resolve4(host)).concat(await dns.promises.resolve6(host).catch(() => []));
  } catch {
    return [];
  }
}

function tlsInfo(host, port = 443) {
  return new Promise((resolve) => {
    const t = setTimeout(() => {
      try {
        socket.destroy();
      } catch {}
      resolve(null);
    }, 8000);
    const socket = tls.connect({ host, port, servername: host, rejectUnauthorized: false }, () => {
      const cert = socket.getPeerCertificate();
      clearTimeout(t);
      socket.end();
      if (!cert || !cert.valid_to) return resolve(null);
      resolve({
        validTo: new Date(cert.valid_to),
        issuer: (cert.issuer?.O ?? "") + " / " + (cert.issuer?.CN ?? ""),
        subject: (cert.subject?.CN ?? ""),
        protocol: socket.getProtocol(),
      });
    });
    socket.on("error", () => {
      clearTimeout(t);
      resolve(null);
    });
  });
}

// ------------------------------------------------------------- checks

const PATHS = [
  "/",
  "/robots.txt",
  "/sitemap.xml",
  "/.env",
  "/.git/config",
  "/.git/HEAD",
  "/.aws/credentials",
  "/.DS_Store",
  "/package.json",
  "/config.js",
  "/env.js",
  "/api/config",
  "/admin",
  "/login",
  "/graphql",
  "/swagger.json",
  "/openapi.json",
  "/actuator",
  "/actuator/health",
  "/debug",
  "/debug/vars",
  "/console",
  "/phpmyadmin",
  "/_next/data",
  "/backup.zip",
  "/server-status",
  "/api",
  "/api/v1",
  "/health",
  "/mcp",
  "/oauth/authorize",
  "/oauth/token",
  "/.well-known/openid-configuration",
];

const SECRET_PATHS = {
  "/.env": "exposed .env file",
  "/.git/config": "exposed .git/config (repo internals, possible full repo leak)",
  "/.git/HEAD": "exposed .git directory",
  "/.aws/credentials": "exposed AWS credentials file",
};

const DEBUG_PATHS = new Set(["/actuator", "/actuator/health", "/debug", "/debug/vars", "/console", "/server-status"]);

async function probeHost(host) {
  const base = `https://${host}`;
  const home = await get(`${base}/`);
  if (home.status === 0) return null;

  const h = (name) => home.headers.get(name) ?? "";

  // --- TLS
  const cert = await tlsInfo(host);
  if (cert) {
    const days = Math.ceil((cert.validTo.getTime() - Date.now()) / 86_400_000);
    if (days < 0) add("medium", "TLS certificate expired", `cert on ${host} expired ${-days}d ago`, cert.validTo.toISOString());
    else if (days < CERT_EXPIRY_WARN_DAYS) add("medium", `TLS certificate expires in ${days} days`, `cert on ${host} valid until ${cert.validTo.toISOString()}`, `${days}d`);
    note(`TLS ${host}: ${cert.protocol}, issuer ${cert.issuer}, expires ${cert.validTo.toISOString().slice(0, 10)}`);
  }

  // --- headers on /
  if (!h("strict-transport-security")) add("medium", "Missing HSTS", `no Strict-Transport-Security on ${host}/`, h("strict-transport-security") || "(absent)");
  if (!h("content-security-policy")) add("medium", "Missing CSP", `no Content-Security-Policy on ${host}/`, "(absent)");
  if (!h("x-content-type-options")) add("low", "Missing X-Content-Type-Options", "sniffing not blocked", "(absent)");
  if (!h("x-frame-options") && !h("content-security-policy")?.includes("frame-ancestors")) add("low", "Missing clickjacking protection", "no X-Frame-Options / frame-ancestors", "(absent)");
  if (!h("referrer-policy")) add("low", "Missing Referrer-Policy", "referrer leakage not constrained", "(absent)");
  const server = h("server");
  if (/\/\d/.test(server)) add("medium", "Server version disclosure", `Server header reveals version`, server);

  // --- http -> https
  const httpR = await get(`http://${host}/`);
  if (httpR.status === 200) add("low", "http not redirecting to https", `http://${host}/ serves 200`, "no 301");
  if (httpR.status === 301 || httpR.status === 302) {
    const loc = httpR.headers.get("location") ?? "";
    if (loc && !loc.startsWith("https://")) add("low", "http redirect goes to non-https", "redirect target is not https", loc);
  }

  // --- path sweep
  const hits = [];
  for (const p of PATHS.slice(1)) {
    const r = await get(`${base}${p}`);
    if (r.status === 200) {
      hits.push({ path: p, status: r.status, body: r.body, headers: Object.fromEntries(r.headers) });
      if (SECRET_PATHS[p]) {
        add("critical", SECRET_PATHS[p], `${base}${p} returned 200`, r.body.slice(0, 200));
      } else if (DEBUG_PATHS.has(p)) {
        add("high", `Debug endpoint live: ${p}`, `${base}${p} returned 200 without auth`, r.body.slice(0, 200));
      } else if (p === "/.DS_Store" || p === "/package.json") {
        add("medium", `Informational file exposed: ${p}`, `${base}${p} returned 200`, r.body.slice(0, 160));
      } else if (p === "/graphql" || p === "/swagger.json" || p === "/openapi.json" || p === "/api/config") {
        add("medium", `API surface exposed without visible auth: ${p}`, `${base}${p} returned 200`, r.body.slice(0, 160));
      } else if (p === "/admin" || p === "/phpmyadmin") {
        add("high", `Admin surface live: ${p}`, `${base}${p} returned 200 — check access control`, r.body.slice(0, 160));
      }
    }
  }
  if (hits.length === 0) note(`no sensitive paths live on ${host}`);

  // --- CORS reflection
  const cors = await get(`${base}/`, { origin: "https://attacker-rheono.example", "x-requested-with": "XMLHttpRequest" });
  const acao = cors.headers.get("access-control-allow-origin") ?? "";
  if (acao === "https://attacker-rheono.example" || acao === "*") {
    add("high", "CORS origin reflection", `/ reflects arbitrary Origin in Access-Control-Allow-Origin`, acao);
  }

  // --- open redirects
  for (const [p, url] of [
    ["/?next=https://attacker-rheono.example", `${base}/?next=https://attacker-rheono.example`],
    ["/?redirect=https://attacker-rheono.example", `${base}/?redirect=https://attacker-rheono.example`],
    ["/?url=https://attacker-rheono.example", `${base}/?url=https://attacker-rheono.example`],
  ]) {
    const r = await get(url);
    const loc = r.headers.get("location") ?? "";
    if (r.status >= 300 && r.status < 400 && loc.includes("attacker-rheono.example")) {
      add("high", `Open redirect: ${p}`, "3xx Location points to attacker-controlled host", loc);
    }
  }

  return { host, home: home.status, hits };
}

// ------------------------------------------------------------- main

const results = {
  domain,
  root,
  consent,
  startedAt: new Date().toISOString(),
  requests: 0,
  findings: [],
  info: [],
  hosts: {},
};

async function main() {
  const hosts = [root, `www.${root}`];
  const alive = [];
  for (const h of hosts) {
    const ips = await dnsA(h);
    if (ips.length) alive.push(h);
  }
  if (alive.length === 0) {
    console.error(`no A/AAAA records for ${domain} or www.${domain} — nothing to check.`);
    process.exit(3);
  }

  // DNS policy
  let dmarc = "";
  try {
    dmarc = (await dns.promises.resolveTxt(`_dmarc.${root}`)).flat().join("");
  } catch {}
  if (!dmarc.includes("v=DMARC1")) add("info", "No DMARC record", `_dmarc.${root} missing — email spoofing risk`, "(absent)");
  else note(`DMARC: ${dmarc.slice(0, 120)}`);

  for (const h of alive) {
    try {
      const r = await probeHost(h);
      if (r) results.hosts[h] = r;
    } catch (e) {
      note(`probe stopped early on ${h}: ${String(e).slice(0, 120)}`);
      break;
    }
  }

  results.findings = findings;
  results.info = info;
  results.requests = requests;
  results.finishedAt = new Date().toISOString();

  // ---- output
  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  results.findings.sort((a, b) => order[a.severity] - order[b.severity]);

  let md = `# Fleet Check — ${domain}\n\n`;
  md += `read-only recon · ${results.requests} requests · ${Math.round((Date.now() - startedAt) / 1000)}s · ${results.finishedAt}\n\n`;
  if (results.findings.length === 0) {
    md += `**No findings.** The public surface looks hardened on the axes checked.\n`;
  } else {
    md += `| severity | finding | detail |\n|---|---|---|\n`;
    for (const f of results.findings) md += `| **${f.severity}** | ${f.title} | ${f.detail} |\n`;
  }
  md += `\nnotes: ${results.info.join(" · ") || "—"}\n\n`;
  md += `recon only — not a pentest. deep hunt + validated PoCs: https://rheono.dev\n`;

  console.log(md);
  const out = path.join(outDir, "fleet-check-report.json");
  await import("node:fs").then((fs) => fs.writeFileSync(out, JSON.stringify(results, null, 2)));
  console.log(`\njson: ${out}`);
}

main().catch((e) => {
  console.error(`probe failed: ${e.message}`);
  process.exit(1);
});
