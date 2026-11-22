#!/usr/bin/env node
/**
 * VibeShield CLI v7.0.0 — Zero-dependency 6-Phase Deep Web & AI App Security Scanner
 * (Next.js, Vite, Cursor, Lovable, Bolt, v0, Supabase, Firebase).
 *
 * Runs 100% locally by default (zero external dependencies, Node.js 20+ built-ins)
 * or optionally via --remote against https://vibe-checker.appwrite.network.
 *
 * 6 Real Audit Phases:
 *   1. Real TLS Port 443 Handshake + DNS CNAME Subdomain Takeover Audit
 *   2. Multi-Route Crawl + Up to 24 Full JS Bundles (<= 2.5MB each) + 52 Secret Rules + /api/* Discovery
 *   3. 28 SPA-Filtered Nuclei-Grade Probes + GraphQL Introspection + Open Redirect + CORS + SourceMaps
 *   4. Supabase (up to 20 PostgREST tables + RPC + Storage) + Firebase RTDB & Cloud Firestore Audit
 *   5. Mozilla Observatory 10 Security Headers + CSP AST Parser + HSTS + Cookies + Passive CVE Matching
 *   6. Calibrated Security Scorecard + Real-Time executionTrace[] Telemetry
 */

import { appendFileSync, writeFileSync } from "node:fs";
import { scanApp, ENGINE_VERSION, SECRET_RULES } from "../src/scanner-engine.mjs";

const VERSION = "7.0.0";
const WEB_APP = "https://vibe-checker.appwrite.network";
const PRO_GUMROAD = "https://omnipulse-x402.appwrite.network/go/gumroad/vibeshield";
const STACK_GUMROAD = "https://omnipulse-x402.appwrite.network/go/gumroad/launch-stack";

const C = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  green: "\x1b[32m",
  red: "\x1b[31m",
  yellow: "\x1b[33m",
  cyan: "\x1b[36m",
};

function parseArgs(argv) {
  const args = argv.slice(2);
  const opts = {
    url: "",
    json: false,
    markdown: false,
    fast: false,
    remote: false,
    minScore: 0,
    failOnSecrets: false,
    failOnSupabaseRls: false,
    failOnFirebase: false,
    failOnCves: false,
    failOnEndpoints: false,
    summaryFile: "",
    githubOutput: "",
    help: false,
    version: false,
  };
  const pos = [];
  for (let i = 0; i < args.length; i += 1) {
    const a = args[i];
    if (a === "-h" || a === "--help") opts.help = true;
    else if (a === "-v" || a === "--version") opts.version = true;
    else if (a === "--json") opts.json = true;
    else if (a === "--markdown") opts.markdown = true;
    else if (a === "--fast") opts.fast = true;
    else if (a === "--remote") opts.remote = true;
    else if (a === "--fail-on-secrets") opts.failOnSecrets = true;
    else if (a === "--fail-on-supabase-rls") opts.failOnSupabaseRls = true;
    else if (a === "--fail-on-firebase") opts.failOnFirebase = true;
    else if (a === "--fail-on-cves") opts.failOnCves = true;
    else if (a === "--fail-on-endpoints") opts.failOnEndpoints = true;
    else if (a === "--min-score" && args[i + 1]) {
      opts.minScore = Math.max(0, Math.min(100, Number(args[++i]) || 0));
    } else if (a.startsWith("--min-score=")) {
      opts.minScore = Math.max(0, Math.min(100, Number(a.split("=")[1]) || 0));
    } else if (a === "--summary-file" && args[i + 1]) {
      opts.summaryFile = args[++i];
    } else if (a.startsWith("--summary-file=")) {
      opts.summaryFile = a.slice("--summary-file=".length);
    } else if (a === "--github-output" && args[i + 1]) {
      opts.githubOutput = args[++i];
    } else if (a.startsWith("--github-output=")) {
      opts.githubOutput = a.slice("--github-output=".length);
    } else {
      pos.push(a);
    }
  }
  if (pos[0] === "scan" || pos[0] === "check" || pos[0] === "audit") pos.shift();
  let u = (pos[0] || "").trim();
  if (u && !/^https?:\/\//i.test(u)) u = `https://${u}`;
  opts.url = u;
  return opts;
}

function printHelp() {
  console.log(`
${C.bold}${C.green}VibeShield CLI v${VERSION}${C.reset} — 6-Phase Deep Web, Secret, Supabase/Firebase & CVE Security Scanner
Engine: v${ENGINE_VERSION} | ${SECRET_RULES.length} Secret Signatures | 28 SPA-Filtered Probes | Zero External Dependencies

${C.bold}USAGE${C.reset}
  npx github:zColdWater/vibeshield-cli scan <https://yourapp.com> [options]

${C.bold}OPTIONS${C.reset}
  --json                  Output full 6-phase structured JSON + executionTrace[]
  --markdown              Output GitHub-Flavored Markdown report
  --fast                  Run fast CI triage mode (<6s) instead of full 6-phase deep scan
  --remote                Execute via hosted VibeShield API instead of local Node.js engine
  --min-score <0-100>     Exit with code 1 if security score falls below threshold
  --fail-on-secrets       Exit with code 1 if leaked frontend secrets are detected
  --fail-on-supabase-rls  Exit with code 1 if exposed Supabase RLS tables or service_role keys are found
  --fail-on-firebase      Exit with code 1 if open Firebase RTDB or Firestore read rules are detected
  --fail-on-cves          Exit with code 1 if high/critical framework CVEs (e.g. CVE-2025-29927) match
  --fail-on-endpoints     Exit with code 1 if critical/high sensitive endpoints (.env, .git, GraphQL) expose
  --summary-file <path>   Append Markdown summary to file (e.g. $GITHUB_STEP_SUMMARY)
  -v, --version           Print version

${C.bold}EXAMPLES${C.reset}
  npx github:zColdWater/vibeshield-cli scan https://yourapp.vercel.app
  npx github:zColdWater/vibeshield-cli scan https://myapp.lovable.app --min-score 80 --fail-on-secrets --fail-on-supabase-rls

${C.bold}LIVE WEB WORKBENCH & SINGLE-APP FIX UNLOCK${C.reset}
  Free 6-Phase Online Scanner: ${WEB_APP}
  Single-App Fix Unlock ($9):  ${PRO_GUMROAD}
  4-in-1 Launch Stack ($29):   ${STACK_GUMROAD}
`);
}

async function runRemoteScan(targetUrl, fast) {
  const modeParam = fast ? "&mode=fast" : "";
  const endpoint = `${WEB_APP}/api/free-scan?url=${encodeURIComponent(targetUrl)}${modeParam}`;
  const r = await fetch(endpoint, {
    headers: { "user-agent": `VibeShieldCLI/${VERSION} (+https://github.com/zColdWater/vibeshield-cli)` },
    signal: AbortSignal.timeout(28_000),
  });
  if (!r.ok) {
    const errText = await r.text().catch(() => "");
    throw new Error(`Scanner API returned HTTP ${r.status}: ${errText.slice(0, 160)}`);
  }
  return r.json();
}

function evaluateGates(data, opts) {
  const failures = [];
  const score = data?.assessment?.score ?? 0;
  const secretCount = (data?.secrets?.items || []).filter((s) => s.severity === "critical" || s.severity === "high").length;
  const sb = data?.supabase || {};
  const fb = data?.firebase || {};
  const exposedTables = Array.isArray(sb.exposedTables) ? sb.exposedTables.length : 0;
  const cves = Array.isArray(data?.frameworkCves) ? data.frameworkCves : [];
  const exposedProbes = (data?.endpointProbes?.items || []).filter((p) => p.exposed && (p.severity === "critical" || p.severity === "high"));

  if (opts.minScore > 0 && score < opts.minScore) {
    failures.push(`Security score ${score}/100 is below required --min-score ${opts.minScore}.`);
  }
  if (opts.failOnSecrets && secretCount > 0) {
    failures.push(`Detected ${secretCount} high/critical leaked client-side secret(s) in JavaScript bundles.`);
  }
  if (opts.failOnSupabaseRls && (sb.serviceRoleLeaked || exposedTables > 0)) {
    failures.push(
      sb.serviceRoleLeaked
        ? "CRITICAL: Supabase service_role JWT leaked in client bundle."
        : `Detected ${exposedTables} unguarded Supabase PostgREST table(s) without RLS.`
    );
  }
  if (opts.failOnFirebase && (fb.rtdbPublic || fb.firestorePublic)) {
    failures.push("CRITICAL: Unauthenticated Firebase Realtime DB or Firestore read rules detected.");
  }
  if (opts.failOnCves && cves.some((c) => c.severity === "critical" || c.severity === "high")) {
    failures.push(`Detected ${cves.length} framework CVE advisory(ies): ${cves.map((c) => c.cve).join(", ")}.`);
  }
  if (opts.failOnEndpoints && exposedProbes.length > 0) {
    failures.push(`Detected ${exposedProbes.length} exposed critical/high sensitive endpoint(s): ${exposedProbes.map((p) => p.path).join(", ")}.`);
  }
  return failures;
}

function renderMarkdown(d, gateFailures) {
  const a = d.assessment || {};
  const t = d.tls || {};
  const tk = d.takeover || {};
  const b = d.bundles || {};
  const s = d.secrets || {};
  const sb = d.supabase || {};
  const fb = d.firebase || {};
  const h = d.headers || {};
  const csp = d.cspAudit || d.cspAnalysis || {};
  const ep = d.endpoints || {};
  const probes = d.endpointProbes || {};
  const cves = Array.isArray(d.frameworkCves) ? d.frameworkCves : [];
  const exposedTables = Array.isArray(sb.exposedTables) ? sb.exposedTables.length : 0;
  const statusLabel = gateFailures.length === 0 && (a.score ?? 0) >= 80 ? "PASS" : gateFailures.length > 0 ? "FAIL" : "WARN";

  const lines = [
    `## [${statusLabel}] VibeShield v7.0 — 6-Phase Deep Security Audit`,
    ``,
    `**Target URL:** ${d.url}  `,
    `**Security Score:** **${a.score ?? 0}/100 (Grade ${a.grade || "-"} · ${a.status || "CHECKED"})**  `,
    `**Detected Stack:** ${(d.stack || []).join(", ") || "Standard Web"} · **Checks:** ${d.checksExecuted || 100}+ · **Duration:** ${((d.scanDurationMs || 0) / 1000).toFixed(2)}s`,
    ``,
    `| Audit Phase | Result | Evidence Summary |`,
    `| :--- | :--- | :--- |`,
    `| **1. TLS 443 & DNS Takeover** | ${t.ok && !t.weakProtocol && !t.expired && !tk.vulnerable ? "OK" : "ALERT"} | ${t.ok ? `${t.protocol || "TLS"} · ${t.issuer || "CA"} · ${t.daysRemaining ?? "?"}d valid` : "Plain HTTP / TLS Error"} · CNAME: ${tk.vulnerable ? `TAKEOVER (${tk.provider})` : (tk.cname || "Direct DNS")} |`,
    `| **2. Multi-Route & Full JS Bundles** | ${b.inspected || 0} bundle(s) | ${Math.round((b.totalBytesScanned || 0) / 1024)} KB unpacked (<=2.5MB/chunk) · ${(d.routes?.discoveredApiEndpoints || []).length} API route(s) |`,
    `| **2b. Client Secret Scan** | ${(s.count || 0) === 0 ? "Clean (0)" : `ALERT (${s.count})`} | ${s.patternsChecked || SECRET_RULES.length} secret signatures checked |`,
    `| **3. 28 Nuclei Probes & Maps** | ${(probes.exposedCount || 0) === 0 && (ep.exposedSourceMaps || []).length === 0 ? "Clean" : `EXPOSED (${(probes.exposedCount || 0) + (ep.exposedSourceMaps || []).length})`} | ${probes.totalChecked || 0} probes (SPA-filtered) · GraphQL: ${ep.graphqlIntrospectionExposed ? "OPEN" : "Safe"} · Maps: ${(ep.exposedSourceMaps || []).length} |`,
    `| **4. Supabase & Firebase DB** | ${sb.serviceRoleLeaked || exposedTables > 0 || fb.rtdbPublic || fb.firestorePublic ? "EXPOSED" : "Protected / None"} | Supabase open tables: ${exposedTables}/${sb.tablesProbed || 0} · Firebase RTDB: ${fb.rtdbPublic ? "OPEN" : "Safe"} · Firestore: ${fb.firestorePublic ? "OPEN" : "Safe"} |`,
    `| **5. Observatory Headers, CSP & CVEs** | ${h.passed ?? 0}/${h.total ?? 10} Passed | CSP Grade: ${csp.grade || "-"} (${csp.score ?? 0}/100) · Weak Cookies: ${d.cookies?.weakCount || 0} · CVEs: ${cves.length} |`,
    ``,
  ];

  if (Array.isArray(d.findings) && d.findings.length > 0) {
    lines.push(`### Key Findings (${d.findings.length})`);
    for (const f of d.findings.slice(0, 10)) {
      lines.push(`- **[${String(f.severity || "info").toUpperCase()}]** ${f.title}${f.fileLocation ? ` (\`${f.fileLocation}\`)` : ""}`);
    }
    lines.push(``);
  }

  if (gateFailures.length > 0) {
    lines.push(`### CI Gate Failures`);
    for (const gf of gateFailures) lines.push(`- ${gf}`);
    lines.push(``);
  }

  lines.push(
    `> **Need tailored copy-paste patches (Cursor/Lovable prompt, Vercel/Cloudflare/Nginx headers, Supabase RLS SQL & Firebase Rules)?** [Open Interactive 6-Phase Report](${WEB_APP}/?url=${encodeURIComponent(d.url)}) · [Unlock Single-App Fix Pack ($9 Once)](${PRO_GUMROAD})`
  );
  lines.push(``);
  return lines.join("\n");
}

function writeGithubOutputs(filePath, d) {
  const sb = d.supabase || {};
  const fb = d.firebase || {};
  const exposedTables = Array.isArray(sb.exposedTables) ? sb.exposedTables.length : 0;
  const out = [
    `score=${d.assessment?.score ?? 0}`,
    `grade=${d.assessment?.grade || "-"}`,
    `secrets-count=${d.secrets?.count ?? 0}`,
    `supabase-exposed-tables=${exposedTables}`,
    `firebase-exposed=${fb.rtdbPublic || fb.firestorePublic ? "true" : "false"}`,
    `cves-count=${Array.isArray(d.frameworkCves) ? d.frameworkCves.length : 0}`,
    `exposed-endpoints=${d.endpointProbes?.exposedCount ?? 0}`,
  ].join("\n") + "\n";
  appendFileSync(filePath, out, "utf8");
}

async function main() {
  const opts = parseArgs(process.argv);
  if (opts.version) {
    console.log(VERSION);
    return;
  }
  if (opts.help || !opts.url) {
    printHelp();
    process.exit(opts.help ? 0 : 1);
  }

  let data;
  try {
    data = opts.remote
      ? await runRemoteScan(opts.url, opts.fast)
      : await scanApp(opts.url, { mode: opts.fast ? "fast" : "deep" });
    if (!data || !data.ok) {
      throw new Error(data?.error || "Unknown scan error");
    }
  } catch (err) {
    console.error(`${C.red}Scan failed:${C.reset} ${err.message}`);
    process.exit(1);
  }

  const gateFailures = evaluateGates(data, opts);
  const md = renderMarkdown(data, gateFailures);

  if (opts.summaryFile) {
    try {
      appendFileSync(opts.summaryFile, md + "\n", "utf8");
    } catch {
      writeFileSync(opts.summaryFile, md + "\n", "utf8");
    }
  }
  if (opts.githubOutput) {
    writeGithubOutputs(opts.githubOutput, data);
  }

  if (opts.json) {
    console.log(JSON.stringify({ ...data, gatePassed: gateFailures.length === 0, gateFailures }, null, 2));
    if (gateFailures.length > 0) process.exit(1);
    return;
  }
  if (opts.markdown) {
    console.log(md);
    if (gateFailures.length > 0) process.exit(1);
    return;
  }

  const a = data.assessment || {};
  const t = data.tls || {};
  const b = data.bundles || {};
  const s = data.secrets || {};
  const sb = data.supabase || {};
  const fb = data.firebase || {};
  const h = data.headers || {};
  const csp = data.cspAudit || {};
  const ep = data.endpointProbes || {};
  const cves = Array.isArray(data.frameworkCves) ? data.frameworkCves : [];
  const scColor = (a.score ?? 0) >= 85 ? C.green : (a.score ?? 0) >= 65 ? C.yellow : C.red;

  console.log(`\n${C.bold}VibeShield v${VERSION} — 6-Phase Deep Security Audit (${data.url})${C.reset}`);
  console.log(`Score: ${scColor}${C.bold}${a.score ?? 0}/100 (Grade ${a.grade || "-"} · ${a.status || "CHECKED"})${C.reset} | Checks: ${data.checksExecuted} | Time: ${((data.scanDurationMs || 0) / 1000).toFixed(2)}s`);
  console.log(`Stack: ${(data.stack || []).join(", ") || "Standard Web"}`);
  console.log(`Phase 1 TLS/DNS:    ${t.ok ? `${t.protocol} (${t.issuer || "CA"}, ${t.daysRemaining}d left)` : "No TLS"} | CNAME: ${data.takeover?.vulnerable ? `${C.red}TAKEOVER RISK${C.reset}` : (data.takeover?.cname || "Direct DNS")}`);
  console.log(`Phase 2 Bundles:    ${b.inspected || 0} JS chunk(s) (${Math.round((b.totalBytesScanned || 0) / 1024)} KB) | Secrets: ${s.count || 0}/${s.patternsChecked || SECRET_RULES.length} rules`);
  console.log(`Phase 3 Endpoints:  ${ep.totalChecked || 0} probes (${ep.exposedCount || 0} exposed) | SourceMaps: ${(data.endpoints?.exposedSourceMaps || []).length}`);
  console.log(`Phase 4 Cloud DB:   Supabase open tables: ${(sb.exposedTables || []).length}/${sb.tablesProbed || 0} | Firebase open: ${fb.rtdbPublic || fb.firestorePublic ? "YES" : "No"}`);
  console.log(`Phase 5 Headers:    ${h.passed ?? 0}/${h.total ?? 10} Observatory headers | CSP: ${csp.grade || "-"} (${csp.score ?? 0}/100) | CVEs: ${cves.length}\n`);

  if (Array.isArray(data.findings) && data.findings.length > 0) {
    console.log(`${C.bold}Findings (${data.findings.length}):${C.reset}`);
    for (const f of data.findings.slice(0, 10)) {
      const col = f.severity === "critical" || f.severity === "high" ? C.red : f.severity === "medium" ? C.yellow : C.dim;
      console.log(`  ${col}[${String(f.severity || "info").toUpperCase()}]${C.reset} ${f.title}`);
      if (f.fileLocation) console.log(`         ${C.dim}Location: ${f.fileLocation}${C.reset}`);
    }
    console.log("");
  }

  if (gateFailures.length > 0) {
    console.log(`${C.red}${C.bold}CI Gate Failures:${C.reset}`);
    for (const gf of gateFailures) console.log(`  - ${gf}`);
    console.log("");
  }

  console.log(`${C.cyan}Interactive 6-Phase Report:${C.reset} ${WEB_APP}/?url=${encodeURIComponent(data.url)}`);
  console.log(`${C.cyan}Single-App Fix Pack ($9):${C.reset}  ${PRO_GUMROAD}\n`);

  if (gateFailures.length > 0) process.exit(1);
}

main();
