# VibeShield CLI & GitHub Action (`vibeshield-cli`)

**Zero-dependency frontend JavaScript secret, Supabase Row-Level Security (RLS), and HTTP header auditor for AI-built web applications (Next.js, Vite, Cursor, Lovable, Bolt, v0).**

[![GitHub Action](https://img.shields.io/badge/GitHub%20Action-zColdWater%2Fvibeshield--cli%40v1-16a34a?logo=githubactions&logoColor=white)](./action.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![Node.js >= 18](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen.svg)](https://nodejs.org)
[![Dependencies: 0](https://img.shields.io/badge/dependencies-0-success.svg)](./package.json)

- **Free Online Scanner (2-Second Live Audit):** [https://vibe-checker.appwrite.network](https://vibe-checker.appwrite.network)
- **Documentation & Live Demo:** [https://zcoldwater.github.io/vibeshield-cli/](https://zcoldwater.github.io/vibeshield-cli/)
- **Feature & TCO Comparison (VibeAppScanner vs. VibeShield):** [https://zcoldwater.github.io/launch-audit-reports/compare/vibeappscanner-vs-vibeshield.html](https://zcoldwater.github.io/launch-audit-reports/compare/vibeappscanner-vs-vibeshield.html)
- **VibeShield Web Pro ($9 One-Time — 5-Platform Fix Wizard, 50-Site Batch CSV & Client A4 PDF Reports):** [https://omnipulse-x402.appwrite.network/go/gumroad/vibeshield](https://omnipulse-x402.appwrite.network/go/gumroad/vibeshield)
- **OmniForge 4-in-1 Launch Stack ($29 One-Time):** [https://omnipulse-x402.appwrite.network/go/gumroad/launch-stack](https://omnipulse-x402.appwrite.network/go/gumroad/launch-stack)

---

## What VibeShield Detects

1. **Leaked Client-Side API Keys (38 Signatures):** Unpacks live `/_next/static/chunks/*.js` and `/assets/*.js` bundles to catch accidentally bundled `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `STRIPE_SECRET_KEY`, AWS credentials, GitHub tokens, and private webhook URLs.
2. **Supabase `service_role` & PostgREST RLS Exposure:** Extracts exposed `SUPABASE_URL` and JWT tokens, flags leaked `service_role` keys, and performs read-only checks for unguarded PostgREST tables missing Row-Level Security policies.
3. **Exposed `.env`, `.git`, Source Maps & Security Headers:** Verifies `.env`, `.git/config`, `.js.map` exposure, `Set-Cookie` flags (`HttpOnly`, `Secure`, `SameSite`), CORS wildcards, and 7 core browser security headers (`HSTS`, `CSP`, `X-Frame-Options`).

---

## Quick Start (`npx` — Zero Install)

```bash
# Audit any live deployment in under 2 seconds
npx github:zColdWater/vibeshield-cli scan https://supabase.com

# Enforce CI thresholds (exit code 1 on leaked secrets, exposed RLS, or score < 80)
npx github:zColdWater/vibeshield-cli scan https://yourapp.vercel.app --min-score 80 --fail-on-secrets --fail-on-supabase-rls

# Output structured JSON or GitHub-Flavored Markdown
npx github:zColdWater/vibeshield-cli scan https://yourapp.vercel.app --json
```

---

## Use as a GitHub Action (`uses: zColdWater/vibeshield-cli@v1`)

Block deployments that leak secrets into client JavaScript bundles or leave Supabase tables open without RLS, and write a structured security scorecard to `$GITHUB_STEP_SUMMARY`:

```yaml
name: VibeShield Security Gate
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-node@v4
        with:
          node-version: "20"

      - name: Audit Production or Preview URL
        uses: zColdWater/vibeshield-cli@v1
        with:
          url: "https://yourapp.example.com"
          min-score: "80"
          fail-on-secrets: "true"
          fail-on-supabase-rls: "true"
```

---

## Free Scanner vs. VibeShield Web Pro ($9 One-Time)

| Capability | Free CLI & Online Check | VibeShield Web Pro ($9 Once) | 4-in-1 Launch Stack ($29 Once) |
| :--- | :---: | :---: | :---: |
| **Live JS Chunk & 38-Pattern Secret Scan** | 1 URL / run | **Included + 50-URL Batch Table** | **All 4 Web Pro Suites** |
| **Supabase RLS & Header Posture Audit** | Summary score | **Full Cursor / Lovable / RLS SQL Fix Wizard** | **VibeShield + InboxShield + CiteReady + BrandShield** |
| **Batch CSV / Excel Export** | — | **Up to 50 domains / batch** | **Included across all 4 suites** |
| **Printable Client A4 PDF Audit Report** | — | **Custom-branded PDF report** | **Included across all 4 suites** |

- **Unlock VibeShield Web Pro ($9 One-Time, $0/mo):** [https://omnipulse-x402.appwrite.network/go/gumroad/vibeshield](https://omnipulse-x402.appwrite.network/go/gumroad/vibeshield)

## License

MIT © OmniForge · Agent Arena Studio
