# VibeShield v7.0 — 6-Phase Deep Security Scanner CLI & GitHub Action

**Zero-dependency, read-only 6-phase security auditor built for AI-coded web apps (Lovable, Bolt.new, Cursor, v0, Next.js, Vite, Supabase & Firebase).**

[![Live VibeShield Score](https://vibe-checker.appwrite.network/api/badge.svg?url=zcoldwater.github.io)](https://vibe-checker.appwrite.network/?url=https://zcoldwater.github.io/vibeshield-cli/)
[![AI Search Readiness](https://citeready-checker.appwrite.network/api/badge?url=zcoldwater.github.io/vibeshield-cli)](https://citeready-checker.appwrite.network/?url=https://zcoldwater.github.io/vibeshield-cli/)
[![GitHub Action](https://img.shields.io/badge/GitHub%20Action-zColdWater%2Fvibeshield--cli%40v7-16a34a?logo=githubactions&logoColor=white)](./action.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![Node.js >= 20](https://img.shields.io/badge/node-%3E%3D20.0.0-brightgreen.svg)](https://nodejs.org)
[![Dependencies: 0](https://img.shields.io/badge/dependencies-0-success.svg)](./package.json)

- **Free 6-Phase Online Deep Scanner (Live Console, Zero Signup):** [https://vibe-checker.appwrite.network](https://vibe-checker.appwrite.network)
- **Single-App Fix Unlock ($2 Launch Special, reg. $9 — One-Time — Exact File/Line Evidence + 5-Platform Copy-Paste Patches):** [Gumroad Checkout](https://omnipulse-x402.appwrite.network/go/gumroad/vibeshield) · [Direct Checkout](https://omnipulse-x402.appwrite.network/checkout/vibeshield)
- **Feature & TCO Comparison (VibeAppScanner $348/yr vs. VibeShield $2 Launch Special):** [https://zcoldwater.github.io/launch-audit-reports/compare/vibeappscanner-vs-vibeshield.html](https://zcoldwater.github.io/launch-audit-reports/compare/vibeappscanner-vs-vibeshield.html)
- **2026 Empirical Benchmark (N=60 Indie SaaS Security Headers & TLS Study — 46.7% No CSP, 31.7% No Clickjacking Defense, 28.3% Grade F):** [https://zcoldwater.github.io/vibeshield-cli/web-security-headers-benchmark-2026.html](https://zcoldwater.github.io/vibeshield-cli/web-security-headers-benchmark-2026.html) · [JSON Dataset](./docs/web-security-headers-benchmark-2026.json)
- **40 Zero-Dependency AI Agent Skills (`skills.sh`):** `npx skills add zColdWater/omniforge-skills` ([Registry](https://www.skills.sh/zColdWater/omniforge-skills))
- **Companion Free Tools:** [BrandShield v6.2 (100% Free 78-TLD & Aftermarket Check)](https://brand-checker.appwrite.network) · [InboxShield v7.0 (Email Deliverability & DMARC Linter)](https://inbox-checker.appwrite.network) · [CiteReady (AI Search / llms.txt)](https://citeready-checker.appwrite.network)

---

## 6-Phase Deep Security Architecture (`v7.0.0`)

Runs **100% locally in Node.js 20+** using native `node:tls`, `node:dns/promises`, and `fetch` — zero npm sub-dependencies, strictly read-only, non-destructive, and SSRF-safe:

| Phase | Deep Checks Executed |
| :--- | :--- |
| **Phase 1: TLS 443 & DNS Takeover** | Direct `node:tls` socket handshake on port 443 (TLSv1.3 vs weak TLS 1.0/1.1, cipher suite, CA issuer, expiry countdown, SAN list, self-signed/mismatch checks) + DNS `CNAME` dangling subdomain takeover checks across 12 cloud providers (GitHub Pages, Heroku, AWS S3, Vercel, Netlify, Azure, Shopify, Fastly, Surge, Fly.io, Ghost, Pantheon). |
| **Phase 2: Multi-Route Crawl & Uncapped JS Bundles** | Crawls `/`, `/robots.txt`, `/sitemap.xml`, Next.js `_buildManifest.js`, and up to 5 core app routes; unpacks up to **24 complete JS bundles (up to 2.5 MB per chunk — no 260 KB truncation!)**; extracts exposed `/api/*`, `/trpc/*`, `/graphql` endpoints; runs **52 high-precision secret rules** (OpenAI, Anthropic, Stripe, AWS, Supabase `service_role`, Firebase Service Account JSON, JWT secrets, DB URIs, DeepSeek, Groq, Clerk, Resend, SendGrid, GitHub, npm, PyPI, Slack, Discord, PayPal, Razorpay). |
| **Phase 3: 28 SPA-Filtered Nuclei Probes & SourceMaps** | Probes 28 sensitive paths (`/.env*`, `/.git/HEAD`, `/.git/config`, `/.DS_Store`, `/swagger.json`, `/openapi.json`, `/api-docs`, `/graphql` & `/api/graphql` Introspection, `/wp-json/wp/v2/users`, `/actuator/health`, `/actuator/env`, `/phpinfo.php`, `/server-status`, `/.well-known/security.txt`, `/firebase.json`, `/next.config.js`, `/package.json`, `/backup.sql`, `/dump.sql`, `/debug/vars`, `/metrics`, Open Redirect, CORS credential reflection) + up to 6 `.js.map` SourceMaps with strict SPA fake-200 HTML rejection. |
| **Phase 4: Supabase (20 Tables) & Firebase DB Probes** | Probes up to **20 Supabase PostgREST tables** (strictly read-only `HEAD Prefer: count=exact` — zero user PII downloaded), RPC inventory, and Storage buckets (`CVE-2025-48757`); detects Firebase `projectId`/`databaseURL` and performs read-only `GET /.json?shallow=true` (RTDB) and `documents?pageSize=1` (Cloud Firestore) rule checks. |
| **Phase 5: Mozilla Observatory Headers, CSP AST & CVEs** | Directive-by-directive `Content-Security-Policy` parser (`'unsafe-inline'`, `'unsafe-eval'`, wildcard `*`, missing `frame-ancestors`, `object-src 'none'`, `base-uri`), HSTS `max-age >= 31536000` + `includeSubDomains` + `preload`, COOP, CORP, `security.txt`, Cookie flags (`Secure`, `HttpOnly`, `SameSite`), and passive framework version matching (`CVE-2025-29927` Next.js middleware bypass, `CVE-2025-48757` Supabase RLS, legacy jQuery/Apache/Nginx/WordPress/PHP advisories). |
| **Phase 6: Live Telemetry & Calibrated Score** | Emits full `executionTrace[]` telemetry (exact URL, HTTP status, bytes, ms latency per probe) and calibrated `0-100` (`A+` to `F`) score. |

---

## Quick Start (`npx` — Zero Install, Runs Locally)

```bash
# Run full 6-phase local deep scan on your own deployment
npx github:zColdWater/vibeshield-cli scan https://yourapp.vercel.app

# Enforce strict CI gates before shipping
npx github:zColdWater/vibeshield-cli scan https://yourapp.vercel.app \
  --min-score 80 \
  --fail-on-secrets \
  --fail-on-supabase-rls \
  --fail-on-firebase \
  --fail-on-endpoints

# Output full JSON + executionTrace[] or GitHub-Flavored Markdown
npx github:zColdWater/vibeshield-cli scan https://yourapp.vercel.app --json
npx github:zColdWater/vibeshield-cli scan https://yourapp.vercel.app --markdown
```

---

## Use as a GitHub Action (`uses: zColdWater/vibeshield-cli@v7`)

```yaml
name: VibeShield v7.0 Security Gate
on: [push, pull_request]

jobs:
  security-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-node@v4
        with:
          node-version: "20"

      - name: Run 6-Phase Security Scan
        uses: zColdWater/vibeshield-cli@v7
        with:
          url: "https://yourapp.example.com"
          min-score: "80"
          fail-on-secrets: "true"
          fail-on-supabase-rls: "true"
          fail-on-firebase: "true"
          fail-on-endpoints: "true"
```

---

## Embed Your Live Security Badge

Show users your app passed a live 6-phase pre-launch security check:

```markdown
[![Audited by VibeShield](https://vibe-checker.appwrite.network/api/badge.svg?domain=yourapp.com&score=95&grade=A%2B)](https://vibe-checker.appwrite.network/?url=https://yourapp.com)
```

---

## Free Online Scanner vs. Single-App Fix Unlock ($2 Launch Special, reg. $9 — One-Time)

| Capability | Free Online Scanner | Single-App Fix Unlock ($2 Launch, ~~$9~~) | 3-in-1 Complete Suite ($5 Launch, ~~$29~~) |
| :--- | :---: | :---: | :---: |
| **Full 6-Phase Deep Scan (100+ Checks + Live Trace)** | Included | **Included + 50-URL Batch CSV** | **All 4 OmniForge Web Tools** |
| **Score, Grade, TLS Cert & Finding Summaries** | Full transparency | **Exact Leaked File / Line & Evidence** | **VibeShield + InboxShield + CiteReady** |
| **5-Platform Copy-Paste Fix Wizard** | Preview only | **Cursor/Lovable Prompt, Vercel, Cloudflare, Nginx, Supabase RLS SQL & Firebase Rules** | **Full Fix Wizards Across All Suites** |
| **Printable Client A4 PDF Audit Report** | Summary only | **Branded A4 PDF Export** | **Included Across All Suites** |

- **Run Free Deep Scan:** [https://vibe-checker.appwrite.network](https://vibe-checker.appwrite.network)
- **Unlock Single-App Fix Pack ($2 Launch Special, ~~$9~~, One-Time, $0/mo, 14-Day Refund):** [https://omnipulse-x402.appwrite.network/go/gumroad/vibeshield](https://omnipulse-x402.appwrite.network/go/gumroad/vibeshield)
- **Need a Clean Domain or Email DNS Check?** [BrandShield v6.2 (100% Free)](https://brand-checker.appwrite.network) · [InboxShield v7.0 ($2 Launch Special)](https://inbox-checker.appwrite.network)

## Ethical Scope

Only scan applications and domains that you own or have explicit authorization to audit. VibeShield is strictly read-only and non-destructive — it never exploits vulnerabilities, writes to databases, or exfiltrates user records.

## License

MIT (c) OmniForge · Agent Arena Studio (`agentarenastudio@proton.me` · [@agentarenastudi](https://x.com/agentarenastudi))
