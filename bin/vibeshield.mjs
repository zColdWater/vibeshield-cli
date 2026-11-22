#!/usr/bin/env node
/**
 * VibeShield CLI (v1.0.0) — Zero-dependency security scanner for AI-built web apps
 * (Next.js, Vite, Cursor, Lovable, Bolt, v0, Supabase).
 *
 * Unpacks frontend JavaScript chunks to detect 38 secret patterns, leaked Supabase
 * URLs & service_role JWTs, unguarded PostgREST RLS tables, exposed .env / source maps,
 * cookie security flags, and HTTP security headers.
 */

import { appendFileSync, writeFileSync } from "node:fs";

const VERSION = "1.0.0";
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
    minScore: 0,
    failOnSecrets: false,
    failOnSupabaseRls: false,
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
    else if (a === "--fail-on-secrets") opts.failOnSecrets = true;
    else if (a === "--fail-on-supabase-rls") opts.failOnSupabaseRls = true;
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
${C.bold}${C.green}VibeShield CLI v${VERSION}${C.reset} — Frontend JS Secret, Supabase RLS & Web Security Scanner

${C.bold}USAGE${C.reset}
  npx github:zColdWater/vibeshield-cli scan <https://yourapp.com> [options]

${C.bold}OPTIONS${C.reset}
  --json                  Output structured JSON report
  --markdown              Output GitHub-Flavored Markdown table
  --min-score <0-100>     Exit with code 1 if security score falls below threshold
  --fail-on-secrets       Exit with code 1 if leaked frontend secrets are detected
  --fail-on-supabase-rls  Exit with code 1 if exposed Supabase RLS tables or service_role keys are found
  --summary-file <path>   Append Markdown summary to file (e.g. $GITHUB_STEP_SUMMARY)
  -v, --version           Print version

${C.bold}EXAMPLES${C.reset}
  npx github:zColdWater/vibeshield-cli scan https://supabase.com
  npx github:zColdWater/vibeshield-cli scan https://myapp.vercel.app --min-score 80 --fail-on-secrets

${C.bold}LIVE WEB WORKBENCH & REMEDIATION WIZARD${C.reset}
  Free Interactive Scanner: ${WEB_APP}
  VibeShield Web Pro ($9):  ${PRO_GUMROAD}
  4-in-1 Launch Stack ($29): ${STACK_GUMROAD}
`);
}

async function runRemoteScan(targetUrl) {
  const endpoint = `${WEB_APP}/api/free-scan?url=${encodeURIComponent(targetUrl)}`;
  const r = await fetch(endpoint, {
    headers: { "user-agent": `VibeShieldCLI/${VERSION} (+https://github.com/zColdWater/vibeshield-cli)` },
    signal: AbortSignal.timeout(20_000),
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
  const secretCount = data?.secrets?.count ?? 0;
  const sb = data?.supabase || {};
  const exposedTables = Array.isArray(sb.exposedTables) ? sb.exposedTables.length : 0;

  if (opts.minScore > 0 && score < opts.minScore) {
    failures.push(`Security score ${score}/100 is below required --min-score ${opts.minScore}.`);
  }
  if (opts.failOnSecrets && secretCount > 0) {
    failures.push(`Detected ${secretCount} leaked client-side secret(s) in JavaScript bundles.`);
  }
  if (opts.failOnSupabaseRls && (sb.serviceRoleLeaked || exposedTables > 0)) {
    failures.push(
      sb.serviceRoleLeaked
        ? "CRITICAL: Supabase service_role JWT leaked in client bundle."
        : `Detected ${exposedTables} unguarded Supabase PostgREST table(s) without RLS.`
    );
  }
  return failures;
}

function renderMarkdown(d, gateFailures) {
  const a = d.assessment || {};
  const b = d.bundles || {};
  const s = d.secrets || {};
  const sb = d.supabase || {};
  const h = d.headers || {};
  const ep = d.endpoints || {};
  const exposedTables = Array.isArray(sb.exposedTables) ? sb.exposedTables.length : 0;
  const statusLabel = gateFailures.length === 0 && (a.score ?? 0) >= 80 ? "PASS" : gateFailures.length > 0 ? "FAIL" : "WARN";

  const lines = [
    `## [${statusLabel}] VibeShield Web & Supabase Security Audit`,
    ``,
    `**Target URL:** ${d.url}  `,
    `**Security Score:** **${a.score ?? 0}/100 (Grade ${a.grade || "-"} · ${a.status || "CHECKED"})**  `,
    `**Detected Stack:** ${(d.stack || []).join(", ") || "Standard Web"}`,
    ``,
    `| Security Vector | Result | Details |`,
    `| :--- | :--- | :--- |`,
    `| **JS Bundle Inspection** | ${b.inspected || 0} chunk(s) | ${Math.round((b.totalBytesScanned || 0) / 1024)} KB unpacked & scanned |`,
    `| **Leaked Client Secrets** | ${(s.count || 0) === 0 ? "Clean (0)" : `ALERT (${s.count})`} | ${s.patternsChecked || 38} API key & token signatures checked |`,
    `| **Supabase & PostgREST RLS** | ${sb.serviceRoleLeaked || exposedTables > 0 ? "EXPOSED" : sb.detected ? "Detected (Protected)" : "None exposed"} | ${sb.detected ? `Project: \`${sb.projectUrl || "detected"}\` · Open tables: ${exposedTables}` : "No public Supabase project leak"} |`,
    `| **Sensitive Endpoints** | ${ep.envExposed || ep.gitExposed ? "EXPOSED" : "Clean"} | \`.env\`: ${ep.envExposed ? "EXPOSED" : "Safe"} · \`.git\`: ${ep.gitExposed ? "EXPOSED" : "Safe"} · Source maps: ${(ep.exposedSourceMaps || []).length} |`,
    `| **HTTP Security Headers** | ${h.passed ?? 0}/${h.total ?? 7} Passed | HSTS, CSP, X-Frame-Options, Referrer-Policy, Permissions-Policy |`,
    ``,
  ];

  if (Array.isArray(d.findings) && d.findings.length > 0) {
    lines.push(`### Key Findings`);
    for (const f of d.findings.slice(0, 6)) {
      lines.push(`- **[${String(f.severity || "info").toUpperCase()}]** ${f.title}`);
    }
    lines.push(``);
  }

  if (gateFailures.length > 0) {
    lines.push(`### CI Gate Failures`);
    for (const gf of gateFailures) lines.push(`- ${gf}`);
    lines.push(``);
  }

  lines.push(
    `> **Unlock platform remediation prompts (Cursor / Lovable / Supabase RLS SQL), 50-site batch CSV audits & client PDF reports:** [Interactive Web Scanner](${WEB_APP}/?url=${encodeURIComponent(d.url)}) · [VibeShield Web Pro ($9)](${PRO_GUMROAD})`
  );
  lines.push(``);
  return lines.join("\n");
}

function writeGithubOutputs(filePath, d) {
  const sb = d.supabase || {};
  const exposedTables = Array.isArray(sb.exposedTables) ? sb.exposedTables.length : 0;
  const out = [
    `score=${d.assessment?.score ?? 0}`,
    `grade=${d.assessment?.grade || "-"}`,
    `secrets-count=${d.secrets?.count ?? 0}`,
    `supabase-exposed-tables=${exposedTables}`,
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
    data = await runRemoteScan(opts.url);
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
  const b = data.bundles || {};
  const s = data.secrets || {};
  const sb = data.supabase || {};
  const h = data.headers || {};
  const scColor = (a.score ?? 0) >= 80 ? C.green : (a.score ?? 0) >= 55 ? C.yellow : C.red;

  console.log(`\n${C.bold}VibeShield Security Audit — ${data.url}${C.reset}`);
  console.log(`Security Score: ${scColor}${C.bold}${a.score ?? 0}/100 (Grade ${a.grade || "-"} · ${a.status || "CHECKED"})${C.reset}`);
  console.log(`Detected Stack: ${(data.stack || []).join(", ") || "Web"} · Scan Time: ${data.scanDurationMs || 0}ms\n`);

  console.log(`  JS Chunks Unpacked          ${b.inspected || 0} file(s) (${Math.round((b.totalBytesScanned || 0) / 1024)} KB)`);
  console.log(`  Client Secret Leaks         ${(s.count || 0) === 0 ? `${C.green}0 leaks across ${s.patternsChecked || 38} patterns${C.reset}` : `${C.red}${s.count} LEAKED${C.reset}`}`);
  console.log(`  Supabase / PostgREST RLS    ${sb.serviceRoleLeaked ? `${C.red}CRITICAL service_role LEAK${C.reset}` : sb.detected ? `${C.green}Detected (${(sb.exposedTables || []).length} open tables)${C.reset}` : "Not detected"}`);
  console.log(`  HTTP Security Headers       ${h.passed ?? 0}/${h.total ?? 7} passed`);

  if (Array.isArray(data.findings) && data.findings.length > 0) {
    console.log(`\n  ${C.bold}Findings:${C.reset}`);
    for (const f of data.findings.slice(0, 5)) {
      console.log(`    - [${String(f.severity || "info").toUpperCase()}] ${f.title}`);
    }
  }

  if (gateFailures.length > 0) {
    console.log(`\n  ${C.bold}${C.red}CI Gate Failures:${C.reset}`);
    for (const gf of gateFailures) console.log(`    - ${gf}`);
  }

  console.log(
    `\n--------------------------------------------------------------------------------\n` +
      `Interactive Remediation Wizard (Cursor / Lovable / Supabase RLS SQL) & PDF Export:\n` +
      `  Live Web App:         ${C.cyan}${WEB_APP}/?url=${encodeURIComponent(data.url)}${C.reset}\n` +
      `  VibeShield Web Pro:   ${C.cyan}${PRO_GUMROAD}${C.reset} ($9 one-time)\n` +
      `  4-in-1 Launch Stack:  ${C.cyan}${STACK_GUMROAD}${C.reset} ($29 one-time)\n` +
      `--------------------------------------------------------------------------------\n`
  );

  if (gateFailures.length > 0) process.exit(1);
}

main();
