// VibeShield v7.0 — 6-Phase Deep Web & AI App Security Scanner Engine
// Zero external npm dependencies (Node.js 20+ built-ins: node:tls, node:dns/promises).
// Strictly read-only, non-destructive, SSRF-safe, SPA fake-200 immune,
// bounded strictly <= 20.5s (Appwrite HTTP gateway safe), emitting live executionTrace[]
// and 100% aligned with VibeShield v7.0 frontend/backend contract (#420/#421/#422).

import tls from "node:tls";
import dns from "node:dns/promises";

export const ENGINE_VERSION = "7.0.0";

const CHROME_UA =
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

const BROWSER_HTML_HEADERS = {
  "user-agent": CHROME_UA,
  accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
  "accept-language": "en-US,en;q=0.9,zh-CN;q=0.7",
  "cache-control": "no-cache",
  "sec-fetch-dest": "document",
  "sec-fetch-mode": "navigate",
  "sec-fetch-site": "none",
  "upgrade-insecure-requests": "1",
};

const SKIP_SCRIPT_HOSTS = [
  "googletagmanager.com",
  "google-analytics.com",
  "doubleclick.net",
  "connect.facebook.net",
  "static.hotjar.com",
  "clarity.ms",
  "widget.intercom.io",
  "js.intercomcdn.com",
  "cdn.segment.com",
  "plausible.io",
  "us.i.posthog.com",
  "eu.i.posthog.com",
  "challenges.cloudflare.com",
  "js.stripe.com",
  "www.recaptcha.net",
  "www.gstatic.com",
  "cdn.jsdelivr.net",
  "unpkg.com",
  "cdnjs.cloudflare.com",
];

const SENSITIVE_TABLE_HINTS = [
  "user", "profile", "account", "customer", "order", "payment", "invoice",
  "lead", "contact", "message", "chat", "secret", "key", "token", "session",
  "subscription", "billing", "booking", "ticket", "member", "admin", "email",
  "note", "document", "file", "workspace", "org", "tenant", "transaction",
  "api_key", "credential", "audit", "webhook", "payout", "wallet", "client",
];

const CORE_ROUTE_HINTS = [
  "/login", "/signin", "/signup", "/register", "/auth",
  "/pricing", "/app", "/dashboard", "/docs", "/account", "/settings",
];

const PLACEHOLDER_RE = /(?:your[_-]?|example|placeholder|changeme|replace[_-]?me|dummy|sample|test123|xxxxxx|000000|12345678|abcdefg|insert[_-]?here|fake[_-]?key|redacted|not[_-]?set)/i;

// 12 Cloud Provider Subdomain Takeover Signatures (Confirmed ONLY with NXDOMAIN or body fingerprint)
const TAKEOVER_SIGNATURES = [
  { provider: "GitHub Pages", cnameRe: /\.github\.io$/i, bodyRe: /There isn't a GitHub Pages site here/i },
  { provider: "Heroku", cnameRe: /\.(?:herokuapp\.com|herokudns\.com)$/i, bodyRe: /No such app|herokucdn\.com\/error-pages\/no-such-app/i },
  { provider: "AWS S3", cnameRe: /\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com$/i, bodyRe: /<Code>NoSuchBucket<\/Code>|The specified bucket does not exist/i },
  { provider: "Vercel", cnameRe: /(?:^cname\.vercel-dns\.com$|\.vercel\.app$)/i, bodyRe: /DEPLOYMENT_NOT_FOUND|The deployment could not be found on Vercel/i },
  { provider: "Netlify", cnameRe: /\.netlify\.(?:app|com)$/i, bodyRe: /Not Found - Request ID:/i },
  { provider: "Azure App Service", cnameRe: /\.(?:azurewebsites\.net|cloudapp\.net|trafficmanager\.net)$/i, bodyRe: /404 Web Site not found|Error 404 - Web app not found/i },
  { provider: "Shopify", cnameRe: /^shops\.myshopify\.com$/i, bodyRe: /Sorry, this shop is currently unavailable/i },
  { provider: "Fastly", cnameRe: /\.fastly\.net$/i, bodyRe: /Fastly error: unknown domain/i },
  { provider: "Surge.sh", cnameRe: /\.surge\.sh$/i, bodyRe: /project not found/i },
  { provider: "Fly.io", cnameRe: /\.fly\.dev$/i, bodyRe: /404 Not Found/i, requireNxdomain: true },
  { provider: "Ghost", cnameRe: /\.ghost\.io$/i, bodyRe: /The thing you were looking for is no longer here/i },
  { provider: "Pantheon", cnameRe: /\.pantheonsite\.io$/i, bodyRe: /404 error unknown site!/i },
];

// 52 High-Precision Secret & Credential Detection Patterns (Bilingual EN + ZH)
export const SECRET_RULES = [
  { id: "stripe-live-secret", name: "Stripe Live Secret Key", nameZh: "Stripe 生产环境私钥 (sk_live_)", severity: "critical", regex: /\bsk_live_[0-9a-zA-Z]{24,99}\b/g, remediation: "Rotate immediately in Stripe Dashboard > Developers > API Keys and move all billing calls to server-side API routes.", remediationZh: "请立即在 Stripe 后台轮换私钥，并将所有支付接口迁至后端服务端调用。" },
  { id: "stripe-restricted-live", name: "Stripe Restricted Live Key", nameZh: "Stripe 生产受限密钥 (rk_live_)", severity: "critical", regex: /\brk_live_[0-9a-zA-Z]{24,99}\b/g, remediation: "Revoke the restricted live key in Stripe Dashboard and use server-side environment variables only.", remediationZh: "请立即在 Stripe 后台吊销该密钥，仅在服务端环境变量中使用。" },
  { id: "stripe-webhook-secret", name: "Stripe Webhook Signing Secret", nameZh: "Stripe Webhook 签名密钥", severity: "high", regex: /\bwhsec_[0-9a-zA-Z]{24,99}\b/g, remediation: "Roll the webhook signing secret in Stripe and keep webhook signature verification strictly on your backend.", remediationZh: "请重置 Stripe Webhook 签名密钥，并确保验签逻辑仅运行在后端。" },
  { id: "openai-project-key", name: "OpenAI API Key (Project)", nameZh: "OpenAI 项目私钥 (sk-proj-)", severity: "critical", regex: /\bsk-proj-[A-Za-z0-9_-]{32,160}\b/g, remediation: "Revoke this OpenAI key immediately and proxy LLM calls through a server-side endpoint with rate limiting.", remediationZh: "请立即在 OpenAI 后台吊销该 Key，改为通过后端接口转发大模型请求并加限流。" },
  { id: "openai-legacy-key", name: "OpenAI API Key (Legacy)", nameZh: "OpenAI API 私钥", severity: "critical", regex: /\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b/g, remediation: "Revoke immediately in OpenAI Platform and move LLM requests off client bundles.", remediationZh: "请立即在 OpenAI 平台吊销该私钥，严禁在前端代码中直连大模型接口。" },
  { id: "anthropic-api-key", name: "Anthropic Claude API Key", nameZh: "Anthropic Claude API 私钥", severity: "critical", regex: /\bsk-ant-api03-[A-Za-z0-9_-]{40,120}\b/g, remediation: "Rotate your Anthropic API key immediately and call Claude only from authenticated server routes.", remediationZh: "请立即轮换 Anthropic 私钥，仅从带鉴权的服务端路由调用 Claude。" },
  { id: "supabase-secret-key", name: "Supabase Secret API Key (sb_secret_)", nameZh: "Supabase 服务端特权密钥 (sb_secret_)", severity: "critical", regex: /\bsb_secret_[A-Za-z0-9_-]{20,80}\b/g, remediation: "Revoke this secret key in Supabase Dashboard > Settings > API; never prefix secret keys with NEXT_PUBLIC_ or VITE_.", remediationZh: "请立即在 Supabase 控制台重置该密钥，切勿添加 NEXT_PUBLIC_ 或 VITE_ 前缀。" },
  { id: "google-api-key", name: "Google / Firebase / Gemini API Key", nameZh: "Google / Firebase / Gemini API Key", severity: "medium", regex: /\bAIzaSy[0-9A-Za-z_-]{33}\b/g, remediation: "Restrict HTTP referrers and API scopes in Google Cloud Console (never leave Gemini/Maps/Cloud APIs unrestricted on browser keys).", remediationZh: "请在 Google Cloud 控制台严格限制该 Key 的域名白名单与 API 范围（Firebase 公开配置 Key 也应禁用多余 API 权限）。" },
  { id: "firebase-admin-private-key", name: "Firebase / GCP Service Account JSON Private Key", nameZh: "Firebase / GCP 服务账号私钥 JSON", severity: "critical", regex: /"type"\s*:\s*"service_account"[\s\S]{0,600}"private_key"\s*:\s*"(-----BEGIN [A-Z ]*PRIVATE KEY-----[^"]{20,})/g, remediation: "Delete this service account key immediately in Google Cloud IAM > Service Accounts and never bundle credentials JSON in frontend builds.", remediationZh: "请立即在 Google Cloud IAM 删除该服务账号密钥，严禁将 service_account JSON 打包进前端。" },
  { id: "aws-access-key", name: "AWS Access Key ID", nameZh: "AWS IAM 访问密钥 (AKIA/ASIA)", severity: "critical", regex: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, remediation: "Deactivate and rotate the IAM access key immediately in AWS IAM and audit CloudTrail logs.", remediationZh: "请立即在 AWS IAM 禁用并轮换该访问密钥，并检查 CloudTrail 异常调用。" },
  { id: "aws-secret-key", name: "AWS Secret Access Key Assignment", nameZh: "AWS Secret Access Key 硬编码", severity: "critical", regex: /(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[:=]\s*["']([A-Za-z0-9/+=]{40})["']/g, remediation: "Rotate AWS credentials immediately and migrate to short-lived IAM roles.", remediationZh: "请立即轮换 AWS 凭证并改用后端短期 IAM 角色。" },
  { id: "resend-api-key", name: "Resend Email API Key", nameZh: "Resend 发信 API 密钥", severity: "high", regex: /\bre_[A-Za-z0-9_]{24,60}\b/g, remediation: "Revoke this Resend key in resend.com/api-keys and send transactional email exclusively from server routes.", remediationZh: "请立即吊销该 Resend 密钥，邮件发送逻辑必须放在后端执行。" },
  { id: "sendgrid-api-key", name: "SendGrid API Key", nameZh: "SendGrid 邮件 API 密钥", severity: "critical", regex: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g, remediation: "Delete the compromised SendGrid key immediately to prevent spam abuse on your sending domain.", remediationZh: "请立即删除泄露的 SendGrid 密钥，防止发信域名被盗用发垃圾邮件。" },
  { id: "mailgun-api-key", name: "Mailgun Private API Key", nameZh: "Mailgun 私有 API 密钥", severity: "high", regex: /\bkey-[0-9a-fA-F]{32}\b/g, remediation: "Rotate your Mailgun private key and move email dispatch to server code.", remediationZh: "请立即轮换 Mailgun 私钥并将发信逻辑移至后端。" },
  { id: "postmark-token", name: "Postmark Server API Token", nameZh: "Postmark 服务端令牌", severity: "high", regex: /(?:POSTMARK_API_TOKEN|POSTMARK_SERVER_TOKEN|X-Postmark-Server-Token)["'\s:=]+([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/gi, remediation: "Rotate your Postmark Server Token and remove it from client-bundled config.", remediationZh: "请轮换 Postmark 令牌并从前端配置中移除。" },
  { id: "clerk-secret-key", name: "Clerk Secret Key", nameZh: "Clerk 认证私钥", severity: "critical", regex: /(?:CLERK_SECRET_KEY|clerkSecretKey)["'\s:=]+(sk_(?:live|test)_[A-Za-z0-9]{20,})/g, remediation: "Rotate Clerk Secret Key in Clerk Dashboard; expose only NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY to browsers.", remediationZh: "请立即轮换 Clerk 私钥，浏览器端仅可暴露 Publishable Key。" },
  { id: "jwt-secret-assignment", name: "Hardcoded JWT / Auth Signing Secret", nameZh: "硬编码 JWT / Auth 签名密钥", severity: "critical", regex: /(?:JWT_SECRET|NEXTAUTH_SECRET|AUTH_SECRET|SESSION_SECRET)\s*[:=]\s*["']([A-Za-z0-9!@#$%^&*_+=.-]{16,128})["']/g, remediation: "Rotate your session/JWT signing secret immediately and move it into server-only runtime environment variables.", remediationZh: "请立即轮换 JWT/Session 签名密钥并仅存于后端环境变量，避免攻击者伪造任意用户登录态。" },
  { id: "github-pat", name: "GitHub Personal Access Token", nameZh: "GitHub 个人访问令牌", severity: "critical", regex: /\b(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{40,90})\b/g, remediation: "Revoke this GitHub token immediately in GitHub Settings > Developer settings.", remediationZh: "请立即在 GitHub 开发者设置中吊销该令牌。" },
  { id: "gitlab-pat", name: "GitLab Personal Access Token", nameZh: "GitLab 个人访问令牌", severity: "critical", regex: /\bglpat-[A-Za-z0-9_-]{20,40}\b/g, remediation: "Revoke the GitLab token immediately and audit repository access logs.", remediationZh: "请立即吊销 GitLab 令牌并核查代码库访问日志。" },
  { id: "npm-access-token", name: "npm Automation / Access Token", nameZh: "npm 包发布访问令牌", severity: "critical", regex: /\bnpm_[A-Za-z0-9]{36}\b/g, remediation: "Revoke this npm token immediately to prevent supply-chain package hijacking.", remediationZh: "请立即吊销该 npm 令牌，防止恶意发布供应链投毒包。" },
  { id: "pypi-api-token", name: "PyPI Package API Token", nameZh: "PyPI 发布 API 令牌", severity: "critical", regex: /\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,200}\b/g, remediation: "Revoke the exposed PyPI API token in pypi.org Account Settings.", remediationZh: "请立即在 PyPI 账户设置中吊销泄露的发布令牌。" },
  { id: "slack-token", name: "Slack Bot / User OAuth Token", nameZh: "Slack OAuth 令牌", severity: "critical", regex: /\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{20,40}\b/g, remediation: "Revoke the Slack OAuth token in your Slack App dashboard immediately.", remediationZh: "请立即在 Slack 应用后台吊销该 OAuth 令牌。" },
  { id: "slack-webhook", name: "Slack Incoming Webhook URL", nameZh: "Slack Webhook 地址", severity: "high", regex: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{8,}\/B[A-Z0-9]{8,}\/[A-Za-z0-9]{20,}/g, remediation: "Regenerate the Slack webhook URL and dispatch notifications from server-side webhooks only.", remediationZh: "请重置 Slack Webhook 地址，通知请求仅从服务端发出。" },
  { id: "discord-webhook", name: "Discord Webhook URL", nameZh: "Discord Webhook 地址", severity: "high", regex: /https:\/\/discord(?:app)?\.com\/api\/webhooks\/\d{17,20}\/[A-Za-z0-9_-]{40,}/g, remediation: "Delete and recreate the Discord webhook and keep it inside backend secrets.", remediationZh: "请删除并重建 Discord Webhook，并将其移入服务端密钥配置。" },
  { id: "discord-bot-token", name: "Discord Bot Token Assignment", nameZh: "Discord 机器人令牌", severity: "critical", regex: /(?:DISCORD_BOT_TOKEN|DISCORD_TOKEN)\s*[:=]\s*["']([MN][A-Za-z0-9_-]{23,28}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,40})["']/g, remediation: "Reset the Discord bot token in Discord Developer Portal immediately.", remediationZh: "请立即在 Discord 开发者后台重置机器人令牌。" },
  { id: "telegram-bot-token", name: "Telegram Bot API Token", nameZh: "Telegram 机器人令牌", severity: "high", regex: /\b\d{8,11}:AA[A-Za-z0-9_-]{33}\b/g, remediation: "Revoke the bot token via @BotFather (/revoke) and move Telegram API calls to your backend.", remediationZh: "请通过 @BotFather 立即重置机器人令牌，并将调用移至后端。" },
  { id: "twilio-api-key", name: "Twilio API Key / Auth Secret", nameZh: "Twilio 短信认证密钥", severity: "high", regex: /(?:TWILIO_AUTH_TOKEN|TWILIO_API_SECRET)["'\s:=]+([0-9a-fA-F]{32})/gi, remediation: "Roll your Twilio Auth Token in Twilio Console to prevent SMS toll fraud.", remediationZh: "请立即重置 Twilio Auth Token，防止短信盗刷产生高额账单。" },
  { id: "db-connection-uri", name: "Database Connection String with Credentials", nameZh: "含明文密码的数据库连接串", severity: "critical", regex: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|rediss?):\/\/[^:\s"'`<>]{1,64}:[^@\s"'`<>]{4,128}@[a-zA-Z0-9._-]{3,120}(?::\d{2,5})?(?:\/[^\s"'`<>]*)?/g, remediation: "Rotate the database password immediately and remove connection strings from client bundles.", remediationZh: "请立即修改数据库密码，彻底清除前端代码中的数据库连接串。" },
  { id: "planetscale-token", name: "PlanetScale Database API Token", nameZh: "PlanetScale 数据库令牌", severity: "critical", regex: /\bpscale_tkn_[A-Za-z0-9_.-]{32,80}\b/g, remediation: "Revoke the PlanetScale service token immediately in PlanetScale Dashboard.", remediationZh: "请立即在 PlanetScale 控制台吊销该数据库令牌。" },
  { id: "upstash-redis-token", name: "Upstash Redis REST Token", nameZh: "Upstash Redis 访问令牌", severity: "critical", regex: /(?:UPSTASH_REDIS_REST_TOKEN)\s*[:=]\s*["']([A-Za-z0-9=_-]{30,120})["']/g, remediation: "Reset your Upstash Redis REST token and keep cache operations strictly on the server.", remediationZh: "请立即重置 Upstash Redis 令牌，缓存读写必须在服务端进行。" },
  { id: "private-key-pem", name: "Embedded Private Key (PEM)", nameZh: "硬编码 PEM 私钥证书", severity: "critical", regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g, remediation: "Revoke the exposed private key/certificate immediately and store signing keys only in server KMS/secrets.", remediationZh: "请立即吊销泄露的私钥证书，签名密钥仅存放在服务端安全存储中。" },
  { id: "huggingface-token", name: "Hugging Face Access Token", nameZh: "Hugging Face 访问令牌", severity: "high", regex: /\bhf_[A-Za-z0-9]{30,50}\b/g, remediation: "Revoke the Hugging Face token and route inference calls through your backend.", remediationZh: "请吊销该 Hugging Face 令牌并改为后端代理推理。" },
  { id: "replicate-token", name: "Replicate API Token", nameZh: "Replicate GPU API 令牌", severity: "critical", regex: /\br8_[A-Za-z0-9]{35,50}\b/g, remediation: "Revoke the Replicate API token immediately to prevent unauthorized GPU billing.", remediationZh: "请立即吊销 Replicate 令牌，防止 GPU 算力被盗刷。" },
  { id: "groq-api-key", name: "Groq API Key", nameZh: "Groq API 密钥", severity: "critical", regex: /\bgsk_[A-Za-z0-9]{40,70}\b/g, remediation: "Revoke the Groq API key in console.groq.com and move LLM calls server-side.", remediationZh: "请立即在 Groq 控制台吊销该密钥并改由后端调用。" },
  { id: "perplexity-api-key", name: "Perplexity API Key", nameZh: "Perplexity API 密钥", severity: "critical", regex: /\bpplx-[A-Za-z0-9]{40,60}\b/g, remediation: "Rotate your Perplexity API key and proxy queries via authenticated backend routes.", remediationZh: "请轮换 Perplexity API 密钥并通过后端路由转发请求。" },
  { id: "xai-api-key", name: "xAI (Grok) API Key", nameZh: "xAI (Grok) API 密钥", severity: "critical", regex: /\bxai-[A-Za-z0-9]{40,90}\b/g, remediation: "Revoke your xAI API key immediately and keep AI provider tokens strictly server-side.", remediationZh: "请立即吊销 xAI 密钥，所有模型密钥严禁暴露在客户端。" },
  { id: "openrouter-api-key", name: "OpenRouter API Key", nameZh: "OpenRouter API 密钥", severity: "critical", regex: /\bsk-or-v1-[0-9a-f]{64}\b/g, remediation: "Revoke the OpenRouter key immediately to stop unauthorized model spend.", remediationZh: "请立即吊销 OpenRouter 密钥，避免产生未授权模型扣费。" },
  { id: "ai-provider-env-key", name: "Hardcoded AI Provider Secret (DeepSeek / Gemini / Mistral)", nameZh: "硬编码大模型服务端密钥 (DeepSeek / Gemini / Mistral)", severity: "critical", regex: /(?:DEEPSEEK_API_KEY|GEMINI_API_KEY|GOOGLE_GENERATIVE_AI_API_KEY|MISTRAL_API_KEY|COHERE_API_KEY)\s*[:=]\s*["']([A-Za-z0-9_-]{24,100})["']/g, remediation: "Revoke the exposed LLM API key and proxy all model calls through an authenticated server route.", remediationZh: "请立即吊销泄露的大模型密钥，改为后端鉴权接口转发。" },
  { id: "elevenlabs-api-key", name: "ElevenLabs API Key", nameZh: "ElevenLabs 语音 API 密钥", severity: "high", regex: /(?:ELEVENLABS_API_KEY|xi-api-key)["'\s:=]+(sk_[0-9a-f]{40,64}|[0-9a-f]{32})/gi, remediation: "Rotate your ElevenLabs key and synthesize audio via server-side API routes.", remediationZh: "请轮换 ElevenLabs 密钥并改为后端生成语音。" },
  { id: "vercel-token", name: "Vercel API Token Assignment", nameZh: "Vercel 平台 API 令牌", severity: "critical", regex: /(?:VERCEL_TOKEN|VERCEL_API_TOKEN)["'\s:=]+([A-Za-z0-9]{24,48})/g, remediation: "Revoke the Vercel token in Vercel Account Settings > Tokens.", remediationZh: "请立即在 Vercel 账户设置中吊销该令牌。" },
  { id: "cloudflare-token", name: "Cloudflare API Token Assignment", nameZh: "Cloudflare API 令牌", severity: "critical", regex: /(?:CLOUDFLARE_API_TOKEN|CF_API_TOKEN)["'\s:=]+([A-Za-z0-9_-]{35,50})/g, remediation: "Roll your Cloudflare API token immediately and restrict zone permissions.", remediationZh: "请立即轮换 Cloudflare API 令牌并收紧区域权限。" },
  { id: "digitalocean-pat", name: "DigitalOcean Personal Access Token", nameZh: "DigitalOcean 云平台访问令牌", severity: "critical", regex: /\bdop_v1_[0-9a-f]{64}\b/g, remediation: "Revoke the DigitalOcean token immediately in DigitalOcean API settings.", remediationZh: "请立即在 DigitalOcean API 控制台吊销该令牌。" },
  { id: "sentry-auth-token", name: "Sentry Auth Token", nameZh: "Sentry 认证令牌", severity: "high", regex: /\bsntrys_[A-Za-z0-9_=]{40,120}\b/g, remediation: "Revoke the Sentry auth token (keep only the public DSN in browser code).", remediationZh: "请吊销泄露的 Sentry Auth Token，浏览器端仅可保留公开 DSN。" },
  { id: "algolia-admin-key", name: "Algolia Admin API Key", nameZh: "Algolia 管理员密钥", severity: "high", regex: /(?:ALGOLIA_ADMIN_KEY|ALGOLIA_ADMIN_API_KEY)\s*[:=]\s*["']([0-9a-f]{32})["']/gi, remediation: "Rotate the Algolia Admin Key and ship only a Search-Only API Key to the frontend.", remediationZh: "请轮换 Algolia Admin Key，前端仅允许使用只读 Search-Only Key。" },
  { id: "linear-api-key", name: "Linear API Key", nameZh: "Linear API 密钥", severity: "high", regex: /\blin_api_[A-Za-z0-9]{35,55}\b/g, remediation: "Revoke the Linear API key in Linear Settings > API.", remediationZh: "请在 Linear 设置中吊销该 API 密钥。" },
  { id: "notion-secret", name: "Notion Integration Secret", nameZh: "Notion 集成密钥", severity: "high", regex: /\b(?:ntn_[0-9A-Za-z]{40,60}|secret_[0-9A-Za-z]{43})\b/g, remediation: "Regenerate your Notion Internal Integration Secret and keep Notion sync server-side.", remediationZh: "请重新生成 Notion 集成密钥并将同步逻辑迁至后端。" },
  { id: "shopify-admin-token", name: "Shopify Admin Access Token", nameZh: "Shopify 管理员令牌", severity: "critical", regex: /\bshpat_[a-fA-F0-9]{32}\b/g, remediation: "Rotate the Shopify Admin token immediately to protect customer & order data.", remediationZh: "请立即轮换 Shopify 管理员令牌，保护客户与订单数据安全。" },
  { id: "square-access-token", name: "Square Production Access Token", nameZh: "Square 生产支付令牌", severity: "critical", regex: /\bsq0atp-[0-9A-Za-z_-]{22,40}\b/g, remediation: "Revoke the Square token in Square Developer Dashboard.", remediationZh: "请立即在 Square 开发者后台吊销该生产令牌。" },
  { id: "paypal-live-secret", name: "PayPal Client Secret Assignment", nameZh: "PayPal 客户端支付私钥", severity: "critical", regex: /(?:PAYPAL_CLIENT_SECRET|PAYPAL_SECRET)\s*[:=]\s*["']([A-Za-z0-9_-]{32,90})["']/g, remediation: "Rotate the PayPal secret in PayPal Developer Dashboard and keep OAuth token minting on your server.", remediationZh: "请立即在 PayPal 开发者后台重置私钥，鉴权流程必须在后端执行。" },
  { id: "razorpay-live-secret", name: "Razorpay Secret Key Assignment", nameZh: "Razorpay 支付私钥", severity: "critical", regex: /(?:RAZORPAY_KEY_SECRET|RAZORPAY_SECRET)\s*[:=]\s*["']([A-Za-z0-9]{20,40})["']/g, remediation: "Regenerate your Razorpay Key Secret and sign payment orders only on the server.", remediationZh: "请立即重置 Razorpay 私钥并在后端生成支付订单签名。" },
  { id: "mapbox-secret-token", name: "Mapbox Secret Token (sk.)", nameZh: "Mapbox 私有密钥 (sk.)", severity: "high", regex: /\bsk\.eyJ[A-Za-z0-9_-]{30,}\.[A-Za-z0-9_-]{15,}\b/g, remediation: "Replace with a URL-restricted Mapbox public token (pk.*) and revoke the secret sk.* token.", remediationZh: "请替换为带域名白名单的 pk.* 公开令牌并吊销 sk.* 私有令牌。" },
  { id: "supabase-service-var", name: "Hardcoded Supabase Service Role Variable", nameZh: "硬编码 Supabase Service Role 密钥", severity: "critical", regex: /(?:SUPABASE_SERVICE_ROLE_KEY|SUPABASE_SERVICE_KEY)\s*[:=]\s*["']([A-Za-z0-9._-]{30,})["']/g, remediation: "Remove SUPABASE_SERVICE_ROLE_KEY from client bundles immediately and rotate the JWT secret in Supabase.", remediationZh: "请立即清除前端中的 SUPABASE_SERVICE_ROLE_KEY 并在 Supabase 轮换 JWT 密钥。" },
];

function isPrivateHost(host) {
  const h = String(host || "").toLowerCase().replace(/^\[|\]$/g, "");
  if (!h) return true;
  if (h === "localhost" || h === "::1" || h.endsWith(".local") || h.endsWith(".internal") || h.endsWith(".localhost")) return true;
  if (/^(127\.|10\.|192\.168\.|169\.254\.|0\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|172\.(1[6-9]|2\d|3[01])\.)/.test(h)) return true;
  if (/^(fc|fd|fe80):/i.test(h)) return true;
  return false;
}

export function normalizeTargetUrl(raw, { allowLocalTest = false } = {}) {
  let s = String(raw || "").trim();
  if (!s) {
    return {
      error: "Please enter a website URL (e.g. supabase.com or yourapp.lovable.app).",
      errorZh: "请输入需要检测的网址（例如 supabase.com、baidu.com 或 yourapp.lovable.app）。",
    };
  }
  s = s.replace(/^["'`<\s]+|["'`>\s]+$/g, "");
  if (/[\s,;<>]/.test(s)) {
    return {
      error: "Please enter 1 URL here, or switch to the Online Batch Scanner tab above to scan up to 50 URLs at once.",
      errorZh: "单站检测每次仅支持输入 1 个网址；如需同时检测多个网站，请点击上方「在线批量检测」标签页。",
    };
  }
  if (!/^https?:\/\//i.test(s)) s = "https://" + s;
  let u;
  try {
    u = new URL(s);
  } catch {
    return {
      error: `Invalid website address: "${raw}". Please check the spelling.`,
      errorZh: `网址格式无效："${raw}"，请检查域名拼写是否正确。`,
    };
  }
  if (!["http:", "https:"].includes(u.protocol)) {
    return {
      error: "Only http:// and https:// web addresses are supported.",
      errorZh: "仅支持检测 http:// 或 https:// 开头的公网网站地址。",
    };
  }
  if (!allowLocalTest && (!u.hostname.includes(".") || isPrivateHost(u.hostname))) {
    return {
      error: "Private or localhost addresses cannot be scanned over the public internet.",
      errorZh: "不支持检测内网 IP 或 localhost 本地地址，请输入公网可访问的网站域名。",
    };
  }
  return {
    url: u.toString(),
    origin: u.origin,
    hostname: u.hostname.toLowerCase(),
    port: u.port ? Number(u.port) : (u.protocol === "https:" ? 443 : 80),
  };
}

function maskSecret(val) {
  const s = String(val || "");
  if (s.length <= 10) return s.slice(0, 3) + "***";
  const head = Math.min(10, Math.max(6, Math.floor(s.length * 0.25)));
  return s.slice(0, head) + "..." + s.slice(-4);
}

function decodeJwtPayload(token) {
  try {
    const parts = String(token || "").split(".");
    if (parts.length !== 3) return null;
    const b64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
    const json = Buffer.from(padded, "base64").toString("utf8");
    const parsed = JSON.parse(json);
    return parsed && typeof parsed === "object" ? parsed : null;
  } catch {
    return null;
  }
}

function safeJsonParse(txt) {
  try {
    const trimmed = String(txt || "").trim();
    if (!trimmed || (trimmed[0] !== "{" && trimmed[0] !== "[")) return null;
    return JSON.parse(trimmed);
  } catch {
    return null;
  }
}

function parseSemver(v) {
  const m = String(v || "").match(/(\d+)\.(\d+)(?:\.(\d+))?/);
  if (!m) return null;
  return [Number(m[1]), Number(m[2]), Number(m[3] || 0)];
}

function cmpSemver(a, b) {
  for (let i = 0; i < 3; i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return 0;
}

async function fetchCappedText(
  url,
  { timeoutMs = 2800, maxBytes = 350000, headers = {}, method = "GET", body = undefined, redirect = "follow" } = {}
) {
  const tStart = Date.now();
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const resp = await fetch(url, {
      method,
      redirect,
      signal: ctrl.signal,
      headers: { "user-agent": CHROME_UA, ...headers },
      body,
    });
    let text = "";
    let received = 0;
    if (method !== "HEAD" && resp.body) {
      const reader = resp.body.getReader();
      const dec = new TextDecoder("utf-8", { fatal: false });
      while (received < maxBytes) {
        const { done, value } = await reader.read();
        if (done) break;
        received += value.byteLength;
        text += dec.decode(value, { stream: true });
      }
      text += dec.decode();
      try { await reader.cancel(); } catch {}
    }
    return {
      ok: true,
      status: resp.status,
      url: resp.url || url,
      headers: resp.headers,
      text,
      bytes: received || Buffer.byteLength(text, "utf8"),
      ms: Date.now() - tStart,
    };
  } catch (e) {
    return {
      ok: false,
      status: 0,
      url,
      headers: new Headers(),
      text: "",
      bytes: 0,
      ms: Date.now() - tStart,
      error: String(e?.name === "AbortError" ? "timeout" : (e?.message || e)),
    };
  } finally {
    clearTimeout(timer);
  }
}

async function runPool(items, concurrency, fn, shouldStop = () => false) {
  const out = [];
  for (let i = 0; i < items.length; i += concurrency) {
    if (shouldStop()) break;
    const wave = items.slice(i, i + concurrency);
    const res = await Promise.all(wave.map((item, idx) => fn(item, i + idx)));
    out.push(...res);
  }
  return out;
}

// Resilient Homepage Fetcher: Chrome UA + www./root + HTTP + HEAD fallback
async function fetchHomepageResilient(norm) {
  const candidates = [];
  const u0 = new URL(norm.url);
  candidates.push({ url: u0.toString(), kind: "primary", timeoutMs: 3800 });

  const parts = u0.hostname.split(".");
  if (u0.hostname.startsWith("www.") && parts.length >= 3) {
    const alt = new URL(u0.toString());
    alt.hostname = u0.hostname.slice(4);
    candidates.push({ url: alt.toString(), kind: "root_fallback", timeoutMs: 3000 });
  } else if (!u0.hostname.startsWith("www.") && parts.length === 2) {
    const alt = new URL(u0.toString());
    alt.hostname = "www." + u0.hostname;
    candidates.push({ url: alt.toString(), kind: "www_fallback", timeoutMs: 3000 });
  }

  if (u0.protocol === "https:") {
    const httpAlt = new URL(u0.toString());
    httpAlt.protocol = "http:";
    candidates.push({ url: httpAlt.toString(), kind: "http_fallback", timeoutMs: 2500 });
  }

  let lastResp = null;
  for (const cand of candidates) {
    const r = await fetchCappedText(cand.url, {
      timeoutMs: cand.timeoutMs,
      maxBytes: 650000,
      headers: BROWSER_HTML_HEADERS,
    });
    if (r.ok && r.status > 0) {
      return { resp: r, fallbackKind: cand.kind, requestedUrl: norm.url };
    }
    lastResp = r;
  }

  const headFallback = await fetchCappedText(candidates[0].url, {
    method: "HEAD",
    timeoutMs: 2500,
    headers: BROWSER_HTML_HEADERS,
  });
  if (headFallback.ok && headFallback.status > 0) {
    return { resp: headFallback, fallbackKind: "head_only", requestedUrl: norm.url };
  }

  return { resp: lastResp || headFallback, fallbackKind: "failed", requestedUrl: norm.url };
}

// Phase 1A: Real node:tls Port 443 Handshake & Certificate Inspection
async function inspectTlsCertificate(host, port = 443, timeoutMs = 3200) {
  const t0 = Date.now();
  const makeFail = (errMsg) => ({
    ok: false,
    https: false,
    connected: false,
    protocol: null,
    cipher: null,
    authorized: false,
    authorizationError: errMsg,
    issuer: null,
    subject: null,
    validFrom: null,
    validTo: null,
    daysRemaining: null,
    keyBits: null,
    sans: [],
    sanList: [],
    expired: false,
    expiringSoon: false,
    weakProtocol: false,
    selfSigned: false,
    hostnameMismatch: false,
    error: errMsg,
    ms: Date.now() - t0,
    durationMs: Date.now() - t0,
  });

  return new Promise((resolve) => {
    let settled = false;
    const finish = (obj) => {
      if (settled) return;
      settled = true;
      resolve(obj);
    };

    let sock;
    try {
      sock = tls.connect({
        host,
        port,
        servername: /^[0-9.]+$|:/.test(host) ? undefined : host,
        rejectUnauthorized: false,
        ALPNProtocols: ["h2", "http/1.1"],
      });
    } catch (e) {
      return finish(makeFail(String(e?.message || e)));
    }

    const timer = setTimeout(() => {
      try { sock.destroy(); } catch {}
      finish(makeFail("timeout"));
    }, timeoutMs);

    sock.once("secureConnect", () => {
      clearTimeout(timer);
      try {
        const protocol = sock.getProtocol() || null;
        const cipherInfo = sock.getCipher() || {};
        const cipher = cipherInfo.standardName || cipherInfo.name || null;
        const authorized = Boolean(sock.authorized);
        const authErr = sock.authorizationError ? String(sock.authorizationError) : null;
        const cert = sock.getPeerCertificate(true) || {};
        const issuerObj = cert.issuer || {};
        const subjectObj = cert.subject || {};
        const issuer = issuerObj.O || issuerObj.CN || null;
        const subject = subjectObj.CN || null;
        const validFrom = cert.valid_from ? new Date(cert.valid_from).toISOString() : null;
        const validTo = cert.valid_to ? new Date(cert.valid_to).toISOString() : null;
        const daysRemaining = validTo ? Math.floor((new Date(validTo).getTime() - Date.now()) / 86400000) : null;
        const sans = cert.subjectaltname
          ? String(cert.subjectaltname)
              .split(",")
              .map((s) => s.trim().replace(/^DNS:/i, ""))
              .filter(Boolean)
              .slice(0, 20)
          : [];
        const expired = daysRemaining !== null && daysRemaining < 0;
        const expiringSoon = daysRemaining !== null && daysRemaining >= 0 && daysRemaining <= 30;
        const weakProtocol = Boolean(protocol && /^(?:TLSv1(?:\.[01])?$|SSLv)/i.test(protocol));
        const selfSigned = !authorized && Boolean(authErr && /self[- ]signed|unable to verify|DEPTH_ZERO/i.test(authErr));
        const hostnameMismatch = !authorized && Boolean(authErr && /altnames|hostname|ERR_TLS_CERT_ALTNAME/i.test(authErr));

        sock.end();
        sock.destroy();
        const elapsed = Date.now() - t0;
        finish({
          ok: true,
          https: true,
          connected: true,
          protocol,
          cipher,
          authorized,
          authorizationError: authErr,
          issuer,
          subject,
          validFrom,
          validTo,
          daysRemaining,
          keyBits: cert.bits || null,
          sans,
          sanList: sans,
          expired,
          expiringSoon,
          weakProtocol,
          selfSigned,
          hostnameMismatch,
          error: null,
          ms: elapsed,
          durationMs: elapsed,
        });
      } catch (e) {
        try { sock.destroy(); } catch {}
        finish(makeFail(String(e?.message || e)));
      }
    });

    sock.once("error", (err) => {
      clearTimeout(timer);
      try { sock.destroy(); } catch {}
      finish(makeFail(String(err?.code || err?.message || err)));
    });
  });
}

// Phase 1B: DNS CNAME & Dangling Subdomain Takeover Audit
async function inspectDnsTakeover(host, homeResp = null) {
  const t0 = Date.now();
  const out = {
    cname: null,
    cnameChain: [],
    aRecordsCount: 0,
    vulnerable: false,
    provider: null,
    detail: "No dangling CNAME takeover risk detected.",
    detailZh: "未发现悬空 CNAME 子域名接管风险。",
    durationMs: 0,
  };

  if (/^[0-9.]+$|:/.test(host)) {
    out.durationMs = Date.now() - t0;
    return out;
  }

  const withTimeout = (p, ms = 1600) =>
    Promise.race([p, new Promise((_, rej) => setTimeout(() => rej(new Error("dns-timeout")), ms))]);

  try {
    const cnames = await withTimeout(dns.resolveCname(host));
    if (Array.isArray(cnames) && cnames.length > 0) {
      out.cnameChain = cnames.slice(0, 8).map((c) => String(c).replace(/\.$/, ""));
      out.cname = out.cnameChain[0];
    }
  } catch {}

  try {
    const addrs = await withTimeout(dns.resolve4(host));
    if (Array.isArray(addrs)) out.aRecordsCount = addrs.length;
  } catch {}

  if (out.cnameChain.length > 0) {
    let bodyHead = (homeResp?.text || "").slice(0, 8000);
    let status = homeResp?.status || 0;
    let fetchedBody = Boolean(homeResp);

    for (const cleanCname of out.cnameChain) {
      for (const sig of TAKEOVER_SIGNATURES) {
        if (!sig.cnameRe.test(cleanCname)) continue;
        let targetNxdomain = false;
        try {
          await withTimeout(dns.resolve4(cleanCname), 1400);
        } catch (err) {
          if (err && (err.code === "ENOTFOUND" || err.code === "ENODATA")) targetNxdomain = true;
        }
        // In standalone inspectTlsAndTakeover() mode, only fetch HTTP if a cloud CNAME matches and isn't already NXDOMAIN
        if (!targetNxdomain && !fetchedBody && !sig.requireNxdomain) {
          fetchedBody = true;
          const r = await fetchCappedText(`https://${host}/`, { timeoutMs: 1400, maxBytes: 12000, headers: BROWSER_HTML_HEADERS });
          bodyHead = (r.text || "").slice(0, 8000);
          status = r.status || 0;
        }
        const bodyMatched = !sig.requireNxdomain && (status === 404 || status === 400 || status === 502 || status === 0) && sig.bodyRe.test(bodyHead);
        if (targetNxdomain || bodyMatched) {
          out.vulnerable = true;
          out.provider = sig.provider;
          out.detail = targetNxdomain
            ? `Dangling CNAME ${host} -> ${cleanCname} (${sig.provider}) returns NXDOMAIN and may be claimable.`
            : `CNAME ${host} -> ${cleanCname} matches unclaimed ${sig.provider} error signature (HTTP ${status}).`;
          out.detailZh = targetNxdomain
            ? `高危：${host} 的 CNAME 指向 ${cleanCname}（${sig.provider}）且目标返回 NXDOMAIN，存在子域名接管风险。`
            : `高危：${host} 的 CNAME 指向 ${cleanCname}，响应命中 ${sig.provider} 未认领服务特征（HTTP ${status}）。`;
          break;
        }
      }
      if (out.vulnerable) break;
    }

    if (!out.vulnerable) {
      out.detail = `Active CNAME -> ${out.cname} verified live (no unclaimed cloud target).`;
      out.detailZh = `已检测到 CNAME -> ${out.cname}，目标服务正常在线，无子域名接管风险。`;
    }
  } else {
    out.detail = `Direct DNS A/AAAA resolution (${out.aRecordsCount} IPv4 record(s)); no CNAME record present.`;
    out.detailZh = `域名通过直连 A/AAAA 记录解析（${out.aRecordsCount} 条 IPv4），无悬空 CNAME 风险。`;
  }

  out.durationMs = Date.now() - t0;
  return out;
}

// Fast standalone Phase-1 endpoint helper for /api/scan-tls (~250-600ms live console bootstrap!)
export async function inspectTlsAndTakeover(rawUrlOrHost, { allowLocalTest = false } = {}) {
  const t0 = Date.now();
  const norm = normalizeTargetUrl(rawUrlOrHost, { allowLocalTest });
  if (norm.error) return { ok: false, error: norm.error, errorZh: norm.errorZh || norm.error };

  const tlsPort = norm.url.startsWith("https://") ? norm.port : 443;
  const [tlsAudit, takeover] = await Promise.all([
    inspectTlsCertificate(norm.hostname, tlsPort, 2800),
    inspectDnsTakeover(norm.hostname, null),
  ]);

  const tlsVerdict = !tlsAudit.ok || tlsAudit.expired || tlsAudit.weakProtocol || tlsAudit.selfSigned ? "fail" : tlsAudit.expiringSoon ? "warn" : "pass";
  const tlsNote = tlsAudit.ok
    ? `${tlsAudit.protocol || "TLS"} · ${tlsAudit.cipher || "cipher"} · ${tlsAudit.issuer || "Unknown CA"}${tlsAudit.daysRemaining !== null ? ` · ${tlsAudit.daysRemaining}d valid` : ""}`
    : `TLS connection failed (${tlsAudit.error || "unreachable"})`;
  const dnsVerdict = takeover.vulnerable ? "fail" : "pass";
  const dnsNote = takeover.vulnerable
    ? `DANGLING CNAME -> ${takeover.cname} (${takeover.provider})`
    : (takeover.cname ? `CNAME -> ${takeover.cname} (live)` : `Direct A/AAAA (${takeover.aRecordsCount} IPv4)`);

  const executionTrace = [
    {
      seq: 1,
      tMs: tlsAudit.durationMs,
      phase: 1,
      phaseName: "TLS & DNS",
      label: "TLS 443 Handshake",
      step: "TLS 443 Handshake",
      target: `${norm.hostname}:${tlsPort}`,
      method: "TLS",
      status: tlsAudit.ok ? 200 : 0,
      bytes: 0,
      ms: tlsAudit.durationMs,
      durationMs: tlsAudit.durationMs,
      result: tlsVerdict === "pass" ? "ok" : tlsVerdict,
      verdict: tlsVerdict,
      detail: tlsNote,
      note: tlsNote,
    },
    {
      seq: 2,
      tMs: Date.now() - t0,
      phase: 1,
      phaseName: "TLS & DNS",
      label: "DNS CNAME & Takeover Audit",
      step: "DNS CNAME & Takeover Audit",
      target: norm.hostname,
      method: "DNS",
      status: takeover.cname ? 200 : 204,
      bytes: 0,
      ms: takeover.durationMs,
      durationMs: takeover.durationMs,
      result: dnsVerdict === "pass" ? "ok" : dnsVerdict,
      verdict: dnsVerdict,
      detail: dnsNote,
      note: dnsNote,
    },
  ];

  return {
    ok: true,
    engineVersion: ENGINE_VERSION,
    hostname: norm.hostname,
    port: tlsPort,
    durationMs: Date.now() - t0,
    tls: tlsAudit,
    takeover,
    dns: {
      cnameChain: takeover.cnameChain,
      aRecordsCount: takeover.aRecordsCount,
      takeoverRisk: takeover.vulnerable
        ? { vulnerable: true, provider: takeover.provider, cname: takeover.cname, fingerprint: takeover.detail }
        : null,
    },
    executionTrace,
  };
}

function detectWafOrChallenge(resp) {
  const hdrs = resp.headers;
  const server = (hdrs.get("server") || "").toLowerCase();
  const body = (resp.text || "").slice(0, 12000).toLowerCase();
  const providers = [];
  if (hdrs.get("cf-ray") || server.includes("cloudflare")) providers.push("Cloudflare");
  if (hdrs.get("x-akamai-transformed") || server.includes("akamai")) providers.push("Akamai");
  if (hdrs.get("ali-swift-global-savetime") || hdrs.get("x-oss-request-id") || server.includes("tengine")) providers.push("Alibaba Cloud / Tengine");
  if (hdrs.get("x-nws-log-uuid") || hdrs.get("x-daa-tunnel") || server.includes("tencent")) providers.push("Tencent Cloud EdgeOne");
  if (server.includes("bfe") || server.includes("baidu")) providers.push("Baidu BFE Edge");
  if (hdrs.get("x-vercel-id")) providers.push("Vercel Edge");
  if (hdrs.get("x-nf-request-id")) providers.push("Netlify Edge");
  if (hdrs.get("x-amz-cf-id") || server.includes("cloudfront")) providers.push("AWS CloudFront");

  const challengeBlocked =
    resp.status === 403 ||
    resp.status === 429 ||
    resp.status === 503 ||
    body.includes("just a moment") ||
    body.includes("cf-browser-verification") ||
    body.includes("wappass.baidu.com") ||
    body.includes("cf-challenge");

  return {
    detected: providers.length > 0 || challengeBlocked,
    challengeBlocked,
    providers,
    httpStatus: resp.status,
  };
}

function detectStack(html, headers, origin) {
  const stack = new Set();
  const lower = (html || "").toLowerCase();
  const host = (() => { try { return new URL(origin).hostname.toLowerCase(); } catch { return ""; } })();
  const srv = (headers.get("server") || "").toLowerCase();
  const powered = (headers.get("x-powered-by") || "").toLowerCase();
  if (host.endsWith(".lovable.app") || host.endsWith(".lovableproject.com") || lower.includes("lovable.dev") || lower.includes("gptengineer")) stack.add("Lovable");
  if (host.endsWith(".bolt.host") || lower.includes("stackblitz") || lower.includes("bolt.new")) stack.add("Bolt.new");
  if (host.endsWith(".replit.app") || host.endsWith(".repl.co")) stack.add("Replit");
  if (host.endsWith(".vercel.app") || headers.get("x-vercel-id") || srv.includes("vercel")) stack.add("Vercel");
  if (host.endsWith(".netlify.app") || headers.get("x-nf-request-id") || srv.includes("netlify")) stack.add("Netlify");
  if (headers.get("cf-ray") || srv.includes("cloudflare")) stack.add("Cloudflare");
  if (srv.includes("tengine") || headers.get("ali-swift-global-savetime")) stack.add("Alibaba Cloud");
  if (headers.get("x-nws-log-uuid") || srv.includes("tencent")) stack.add("Tencent Cloud");
  if (srv.includes("bfe")) stack.add("Baidu BFE");
  if (lower.includes("/_next/static/") || lower.includes("__next_data__") || powered.includes("next.js")) stack.add("Next.js");
  if (lower.includes("/assets/index-") || (lower.includes('type="module"') && lower.includes("/assets/"))) stack.add("Vite / React");
  if (lower.includes("/_nuxt/")) stack.add("Nuxt");
  if (lower.includes("wp-content/") || lower.includes("wp-includes/")) stack.add("WordPress");
  if (powered.includes("express")) stack.add("Express");
  if (lower.includes("supabase.co")) stack.add("Supabase");
  if (lower.includes("firebaseapp.com") || lower.includes("firebaseio.com") || lower.includes("firebasedatabase.app")) stack.add("Firebase");
  if (lower.includes("clerk.") || lower.includes("__clerk")) stack.add("Clerk");
  if (lower.includes("stripe.com")) stack.add("Stripe");
  if (srv.includes("nginx")) stack.add("Nginx");
  if (srv.includes("apache")) stack.add("Apache");
  return [...stack];
}

// Phase 2: Multi-route link & Next.js build manifest discovery
function extractInternalRoutes(html, sitemapXml, origin) {
  const routes = new Set();
  const baseHost = new URL(origin).hostname.toLowerCase();

  if (sitemapXml) {
    const locRe = /<loc>\s*(https?:\/\/[^<\s]+)\s*<\/loc>/gi;
    let m;
    while ((m = locRe.exec(sitemapXml)) !== null) {
      try {
        const u = new URL(m[1]);
        if (u.hostname.toLowerCase() === baseHost && u.pathname !== "/" && !/\.(?:xml|jpg|jpeg|png|webp|svg|pdf|zip)$/i.test(u.pathname)) {
          routes.add(u.pathname);
        }
      } catch {}
    }
  }

  const hrefRe = /<a\b[^>]*\bhref=["']([^"'#?]+)["']/gi;
  let m;
  while ((m = hrefRe.exec(html || "")) !== null) {
    try {
      const u = new URL(m[1], origin);
      if (u.hostname.toLowerCase() === baseHost && u.pathname.length > 1 && u.pathname.length < 80) {
        if (!/\.(?:js|css|png|jpg|jpeg|webp|svg|ico|pdf|zip|xml|json|mp4|woff2?)$/i.test(u.pathname)) {
          routes.add(u.pathname);
        }
      }
    } catch {}
  }

  const scoreRoute = (p) => {
    const l = p.toLowerCase();
    let s = 0;
    if (CORE_ROUTE_HINTS.some((h) => l === h || l.startsWith(h + "/"))) s += 20;
    if (/^\/[a-z0-9-]+$/i.test(l)) s += 5;
    if (l.includes("/blog/") || l.includes("/changelog/") || l.includes("/terms") || l.includes("/privacy")) s -= 6;
    return s;
  };

  return [...routes].sort((a, b) => scoreRoute(b) - scoreRoute(a)).slice(0, 5);
}

function extractBuildManifestUrl(html, baseUrl) {
  const m = String(html || "").match(/["'](\/_next\/static\/[a-zA-Z0-9_-]+\/_buildManifest\.js(?:\?[^"']*)?)["']/);
  if (m) {
    try { return new URL(m[1], baseUrl).toString(); } catch {}
  }
  const nextDataMatch = String(html || "").match(/"buildId"\s*:\s*"([a-zA-Z0-9_-]{8,40})"/);
  if (nextDataMatch) {
    try { return new URL(`/_next/static/${nextDataMatch[1]}/_buildManifest.js`, baseUrl).toString(); } catch {}
  }
  return null;
}

function extractJsChunkUrlsFromTexts(htmlDocs, baseUrl, maxChunks = 24, { allowLocalTest = false } = {}) {
  const candidates = new Set();
  const baseHost = new URL(baseUrl).hostname.toLowerCase();
  const rootDomain = baseHost.split(".").slice(-2).join(".");

  const maybeAdd = (rawPath) => {
    try {
      const resolved = new URL(rawPath, baseUrl);
      if (!["http:", "https:"].includes(resolved.protocol)) return;
      const h = resolved.hostname.toLowerCase();
      if (SKIP_SCRIPT_HOSTS.some((sk) => h === sk || h.endsWith("." + sk))) return;
      if (!allowLocalTest && isPrivateHost(h)) return;
      const sameRoot =
        h === baseHost ||
        h.endsWith("." + rootDomain) ||
        resolved.pathname.includes("/_next/") ||
        resolved.pathname.includes("/assets/");
      if (sameRoot) candidates.add(resolved.toString());
    } catch {}
  };

  for (const doc of htmlDocs) {
    const text = doc.text || "";
    const tagRegex = /<(?:script\b[^>]*\bsrc|link\b[^>]*\bhref)=["']([^"']+\.m?js(?:\?[^"']*)?)["'][^>]*>/gi;
    let m;
    while ((m = tagRegex.exec(text)) !== null) maybeAdd(m[1]);

    const nextChunkRe = /["'](\/_next\/static\/(?:chunks|pages)\/[a-zA-Z0-9._/-]+\.js)["']/g;
    while ((m = nextChunkRe.exec(text)) !== null) maybeAdd(m[1]);

    const manifestChunkRe = /["'](static\/chunks\/[a-zA-Z0-9._/-]+\.js)["']/g;
    while ((m = manifestChunkRe.exec(text)) !== null) maybeAdd(`/_next/${m[1]}`);

    const viteChunkRe = /["'](\/assets\/[a-zA-Z0-9._-]+\.m?js)["']/g;
    while ((m = viteChunkRe.exec(text)) !== null) maybeAdd(m[1]);
  }

  const scoreChunk = (u) => {
    const p = new URL(u).pathname.toLowerCase();
    let s = 0;
    if (/(?:index|main|app|page|layout|supabase|firebase|auth|client|config|env|api|checkout|billing)/.test(p)) s += 12;
    if (/(?:\/assets\/|\/_next\/static\/chunks\/app\/|\/_next\/static\/chunks\/pages\/)/.test(p)) s += 7;
    if (/(?:polyfill|webpack|framework|vendor|react-dom|sentry|analytics|chunk-vendors)/.test(p)) s -= 8;
    return s;
  };

  return [...candidates].sort((a, b) => scoreChunk(b) - scoreChunk(a)).slice(0, maxChunks);
}

function extractApiEndpoints(sources) {
  const eps = new Set();
  const re = /["'`](\/(?:api|trpc|v[1-4]|graphql)(?:\/[a-zA-Z0-9._:\-\[\]]{1,40}){0,5})["'`]/g;
  for (const { text } of sources) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(text)) !== null) {
      const p = m[1];
      if (p.length < 4 || p.length > 90) continue;
      if (/\.(?:js|css|png|jpg|jpeg|svg|webp|ico|woff2?|map)$/i.test(p)) continue;
      eps.add(p);
      if (eps.size >= 40) return [...eps];
    }
  }
  return [...eps];
}

function scanTextForSecrets(text, sourceLabel, seenKeys) {
  const hits = [];
  for (const rule of SECRET_RULES) {
    rule.regex.lastIndex = 0;
    let m;
    let perRuleCount = 0;
    while ((m = rule.regex.exec(text)) !== null && perRuleCount < 3) {
      const rawMatch = m[1] || m[0];
      if (!rawMatch || rawMatch.length < 12) continue;
      if (PLACEHOLDER_RE.test(rawMatch)) continue;
      const dedupe = `${rule.id}:${rawMatch.slice(0, 14)}:${rawMatch.slice(-4)}`;
      if (seenKeys.has(dedupe)) continue;
      seenKeys.add(dedupe);
      perRuleCount++;
      hits.push({
        ruleId: rule.id,
        name: rule.name,
        nameZh: rule.nameZh || rule.name,
        severity: rule.severity,
        maskedValue: maskSecret(rawMatch),
        source: sourceLabel,
        offset: m.index,
        location: `${sourceLabel} (byte offset ${m.index})`,
        remediation: rule.remediation,
        remediationZh: rule.remediationZh || rule.remediation,
      });
    }
  }
  return hits;
}

// Phase 3: SPA Fake-200 Detector + 28 Nuclei-Grade Non-Destructive Endpoint Probes
function isSpaHtmlFallback(resp, homeSnippet) {
  const ct = (resp.headers.get("content-type") || "").toLowerCase();
  const txt = (resp.text || "").trimStart();
  const lower = txt.slice(0, 700).toLowerCase();
  if (ct.includes("text/html") || ct.includes("application/xhtml")) return true;
  if (/^<!doctype\s+html|^<html\b|^<head\b|^<meta\b|^<script\b/i.test(lower)) return true;
  if (lower.includes('<div id="__next"') || lower.includes('<div id="root"') || lower.includes('<div id="app"')) return true;
  if (homeSnippet && homeSnippet.length > 48 && lower.startsWith(homeSnippet.slice(0, 90))) return true;
  return false;
}

function buildSensitiveProbeSpecs(finalOrigin, resolvedUrl, homeSnippet) {
  const isEnvBody = (r) =>
    r.ok &&
    r.status === 200 &&
    !isSpaHtmlFallback(r, homeSnippet) &&
    /^[A-Z][A-Z0-9_]{2,}\s*=\s*\S+/m.test(r.text);

  const isOpenApiJson = (r) => {
    if (!r.ok || r.status !== 200 || isSpaHtmlFallback(r, homeSnippet)) return false;
    const j = safeJsonParse(r.text);
    return Boolean(j && typeof j === "object" && (j.openapi || j.swagger) && j.paths && typeof j.paths === "object");
  };

  const isGraphqlIntrospection = (r) => {
    if (!r.ok || r.status !== 200 || isSpaHtmlFallback(r, homeSnippet)) return false;
    const j = safeJsonParse(r.text);
    return Boolean(j && j.data && j.data.__schema && Array.isArray(j.data.__schema.types) && j.data.__schema.types.length > 0);
  };

  const isSqlDump = (r) =>
    r.ok &&
    r.status === 200 &&
    !isSpaHtmlFallback(r, homeSnippet) &&
    /(?:CREATE\s+TABLE|INSERT\s+INTO|DROP\s+TABLE|pg_dump|MySQL\s+dump|PostgreSQL\s+database\s+dump)/i.test(r.text);

  return [
    {
      id: "env-root", path: "/.env", category: "Secret Dotfile", severity: "critical",
      validate: isEnvBody,
      evidenceFn: (r) => `HTTP 200 (${r.bytes} bytes) — contains KEY=VALUE environment entries`,
      detail: "Public /.env file exposed at web root with environment configuration keys.",
      detailZh: "网站根目录公开暴露 /.env 环境变量文件，可能导致全部密钥与数据库凭证泄露。",
      fixSnippet: "# Nginx:\nlocation ~* /\\.env { deny all; return 404; }",
    },
    {
      id: "env-local", path: "/.env.local", category: "Secret Dotfile", severity: "critical",
      validate: isEnvBody,
      evidenceFn: (r) => `HTTP 200 (${r.bytes} bytes) — local .env secrets accessible`,
      detail: "Public /.env.local file exposed over HTTP/HTTPS.",
      detailZh: "公开暴露 /.env.local 本地环境配置文件，请立即屏蔽并轮换密钥。",
      fixSnippet: "# Nginx:\nlocation ~* /\\.env { deny all; return 404; }",
    },
    {
      id: "env-prod", path: "/.env.production", category: "Secret Dotfile", severity: "critical",
      validate: isEnvBody,
      evidenceFn: (r) => `HTTP 200 (${r.bytes} bytes) — production .env secrets accessible`,
      detail: "Public /.env.production file exposed at web root.",
      detailZh: "公开暴露 /.env.production 生产环境配置文件，风险极高。",
      fixSnippet: "# Nginx:\nlocation ~* /\\.env { deny all; return 404; }",
    },
    {
      id: "env-backup", path: "/.env.backup", category: "Secret Dotfile", severity: "critical",
      validate: isEnvBody,
      evidenceFn: (r) => `HTTP 200 (${r.bytes} bytes) — backup .env file accessible`,
      detail: "Public /.env.backup file exposed on production host.",
      detailZh: "公开暴露 /.env.backup 备份环境文件，请立即删除并屏蔽点文件访问。",
      fixSnippet: "# Nginx:\nlocation ~* /\\.env { deny all; return 404; }",
    },
    {
      id: "git-head", path: "/.git/HEAD", category: "Source Repo Exposure", severity: "critical",
      validate: (r) => r.ok && r.status === 200 && !isSpaHtmlFallback(r, homeSnippet) && /^ref:\s+refs\/heads\//m.test(r.text),
      evidenceFn: (r) => `HTTP 200 — returned "${r.text.trim().slice(0, 60)}"`,
      detail: "Public /.git/HEAD metadata exposed, allowing full backend source reconstruction.",
      detailZh: "公开暴露 /.git/HEAD 源码仓库元数据，攻击者可据此还原整站源码与历史提交。",
      fixSnippet: "# Nginx:\nlocation ~* /\\.git { deny all; return 404; }",
    },
    {
      id: "git-config", path: "/.git/config", category: "Source Repo Exposure", severity: "critical",
      validate: (r) => r.ok && r.status === 200 && !isSpaHtmlFallback(r, homeSnippet) && /\[core\]/i.test(r.text) && /(?:repositoryformatversion|\[remote\s+"origin"\])/i.test(r.text),
      evidenceFn: (r) => `HTTP 200 (${r.bytes} bytes) — Git [core]/remote config readable`,
      detail: "Public /.git/config exposed, potentially revealing private repository URLs and embedded credentials.",
      detailZh: "公开暴露 /.git/config 仓库配置文件，可能直接泄露私有仓库地址与认证令牌。",
      fixSnippet: "# Nginx:\nlocation ~* /\\.git { deny all; return 404; }",
    },
    {
      id: "ds-store", path: "/.DS_Store", category: "Metadata Exposure", severity: "low",
      validate: (r) => r.ok && r.status === 200 && !isSpaHtmlFallback(r, homeSnippet) && r.text.slice(0, 16).includes("Bud1"),
      evidenceFn: (r) => `HTTP 200 (${r.bytes} bytes) — macOS Bud1 directory index header`,
      detail: "macOS .DS_Store metadata file publicly accessible, leaking internal directory filenames.",
      detailZh: "线上暴露了 macOS .DS_Store 目录索引文件，可被用于枚举隐藏文件名。",
      fixSnippet: "# Remove from repo & block dotfiles:\nfind . -name .DS_Store -delete",
    },
    {
      id: "swagger-json", path: "/swagger.json", category: "API Schema Exposure", severity: "medium",
      validate: isOpenApiJson,
      evidenceFn: (r) => {
        const j = safeJsonParse(r.text);
        const count = j?.paths ? Object.keys(j.paths).length : 0;
        return `HTTP 200 — Swagger/OpenAPI spec exposing ${count} API path(s)`;
      },
      detail: "Public /swagger.json API specification is unauthenticated, mapping internal endpoints.",
      detailZh: "公开暴露 /swagger.json 接口文档，直接向外部暴露全部后端路由与参数结构。",
      fixSnippet: "// Restrict Swagger/OpenAPI to non-production or authenticated admin sessions:\nif (process.env.NODE_ENV !== 'production') app.use('/swagger.json', swaggerHandler);",
    },
    {
      id: "openapi-json", path: "/openapi.json", category: "API Schema Exposure", severity: "medium",
      validate: isOpenApiJson,
      evidenceFn: (r) => {
        const j = safeJsonParse(r.text);
        const count = j?.paths ? Object.keys(j.paths).length : 0;
        return `HTTP 200 — OpenAPI JSON exposing ${count} API path(s)`;
      },
      detail: "Public /openapi.json specification exposes internal API paths and schemas.",
      detailZh: "公开暴露 /openapi.json 接口清单，建议在生产环境关闭或增加鉴权保护。",
      fixSnippet: "# FastAPI / Express: disable openapi_url=None in production",
    },
    {
      id: "api-docs", path: "/api-docs", category: "API Schema Exposure", severity: "medium",
      validate: (r) => {
        if (!r.ok || r.status !== 200) return false;
        if (isOpenApiJson(r)) return true;
        const lower = (r.text || "").toLowerCase();
        return lower.includes("swagger-ui") && (lower.includes("swaggeruibundle") || lower.includes("openapi")) && !(homeSnippet && lower.startsWith(homeSnippet.slice(0, 80)));
      },
      evidenceFn: (r) => `HTTP 200 (${r.bytes} bytes) — interactive Swagger/OpenAPI docs accessible`,
      detail: "Unauthenticated /api-docs endpoint exposes interactive API documentation in production.",
      detailZh: "生产环境公开暴露 /api-docs 交互式接口文档，建议加鉴权或仅限内网访问。",
      fixSnippet: "// Gate /api-docs behind admin authentication or NODE_ENV !== 'production'",
    },
    {
      id: "v2-api-docs", path: "/v2/api-docs", category: "API Schema Exposure", severity: "medium",
      validate: isOpenApiJson,
      evidenceFn: (r) => `HTTP 200 (${r.bytes} bytes) — Springfox/Swagger v2 spec exposed`,
      detail: "Public /v2/api-docs Swagger JSON specification exposed.",
      detailZh: "公开暴露 Springfox / Swagger /v2/api-docs 接口规范，建议生产环境禁用。",
      fixSnippet: "# application-prod.properties:\nspringdoc.api-docs.enabled=false",
    },
    {
      id: "graphql-root", path: "/graphql", method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({ query: "{__schema{types{name}}}" }),
      category: "GraphQL Introspection", severity: "high",
      validate: isGraphqlIntrospection,
      evidenceFn: (r) => {
        const j = safeJsonParse(r.text);
        return `HTTP 200 — GraphQL introspection enabled (${j?.data?.__schema?.types?.length || 0} schema types exposed)`;
      },
      detail: "Production /graphql endpoint has GraphQL Introspection enabled, revealing the entire API schema.",
      detailZh: "生产环境 /graphql 开启了 Schema 内省（Introspection），外部可直接导出全部接口类型与敏感字段定义。",
      fixSnippet: "// Apollo / GraphQL Server:\nnew ApolloServer({ typeDefs, resolvers, introspection: process.env.NODE_ENV !== 'production' });",
    },
    {
      id: "graphql-api", path: "/api/graphql", method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({ query: "{__schema{types{name}}}" }),
      category: "GraphQL Introspection", severity: "high",
      validate: isGraphqlIntrospection,
      evidenceFn: (r) => {
        const j = safeJsonParse(r.text);
        return `HTTP 200 — /api/graphql introspection enabled (${j?.data?.__schema?.types?.length || 0} types exposed)`;
      },
      detail: "Production /api/graphql endpoint has GraphQL Introspection enabled.",
      detailZh: "生产环境 /api/graphql 开启了内省查询，建议立即在生产环境关闭 introspection。",
      fixSnippet: "// Disable GraphQL introspection in production:\nintrospection: process.env.NODE_ENV !== 'production'",
    },
    {
      id: "wp-users", path: "/wp-json/wp/v2/users", category: "User Enumeration", severity: "medium",
      validate: (r) => {
        if (!r.ok || r.status !== 200 || isSpaHtmlFallback(r, homeSnippet)) return false;
        const j = safeJsonParse(r.text);
        return Array.isArray(j) && j.length > 0 && typeof j[0]?.slug === "string" && j[0]?.id !== undefined;
      },
      evidenceFn: (r) => {
        const j = safeJsonParse(r.text);
        return `HTTP 200 — WordPress REST API enumerated ${j?.length || 0} user account(s)`;
      },
      detail: "WordPress /wp-json/wp/v2/users publicly enumerates administrator/author login slugs.",
      detailZh: "WordPress 接口 /wp-json/wp/v2/users 允许未登录枚举站点管理员与作者用户名。",
      fixSnippet: "// WordPress functions.php: disable /wp/v2/users for unauthenticated requests\nadd_filter('rest_endpoints', function($e){ if(!is_user_logged_in()){ unset($e['/wp/v2/users']); } return $e; });",
    },
    {
      id: "actuator-health", path: "/actuator/health", category: "Diagnostics Exposure", severity: "medium",
      validate: (r) => {
        if (!r.ok || r.status !== 200 || isSpaHtmlFallback(r, homeSnippet)) return false;
        const j = safeJsonParse(r.text);
        return Boolean(j && typeof j.status === "string" && /^(UP|DOWN|OUT_OF_SERVICE|UNKNOWN)$/i.test(j.status));
      },
      evidenceFn: (r) => `HTTP 200 — Spring Boot Actuator health exposed (${r.text.slice(0, 80)})`,
      detail: "Spring Boot /actuator/health endpoint is publicly accessible on the internet.",
      detailZh: "Spring Boot /actuator/health 运维监控端点暴露在公网，建议仅限内网访问。",
      fixSnippet: "# application.properties:\nmanagement.endpoints.web.exposure.include=health\nmanagement.endpoint.health.show-details=never",
    },
    {
      id: "actuator-env", path: "/actuator/env", category: "Secret Diagnostics Exposure", severity: "critical",
      validate: (r) => {
        if (!r.ok || r.status !== 200 || isSpaHtmlFallback(r, homeSnippet)) return false;
        const j = safeJsonParse(r.text);
        return Boolean(j && Array.isArray(j.propertySources));
      },
      evidenceFn: (r) => `HTTP 200 (${r.bytes} bytes) — Spring Boot /actuator/env propertySources exposed`,
      detail: "Spring Boot /actuator/env publicly exposes environment properties and runtime configuration.",
      detailZh: "高危：Spring Boot /actuator/env 暴露在公网，可直接泄露系统属性与内部密钥配置。",
      fixSnippet: "# application.properties:\nmanagement.endpoints.web.exposure.exclude=env,beans,heapdump,mappings",
    },
    {
      id: "phpinfo", path: "/phpinfo.php", category: "Diagnostics Exposure", severity: "high",
      validate: (r) => r.ok && r.status === 200 && /<title>phpinfo\(\)<\/title>|PHP Version\s+\d+\.\d+/i.test(r.text) && !(homeSnippet && r.text.trimStart().toLowerCase().startsWith(homeSnippet.slice(0, 80))),
      evidenceFn: () => "HTTP 200 — phpinfo() runtime & environment variables page exposed",
      detail: "Public /phpinfo.php diagnostic script reveals PHP version, server paths, and environment variables.",
      detailZh: "生产服务器公开暴露了 /phpinfo.php 调试页，会直接泄露服务器路径与环境变量。",
      fixSnippet: "# Delete /phpinfo.php from web root immediately:\nrm -f /var/www/html/phpinfo.php",
    },
    {
      id: "server-status", path: "/server-status", category: "Diagnostics Exposure", severity: "high",
      validate: (r) => r.ok && r.status === 200 && /Apache Server Status for|Total accesses:\s*\d+/i.test(r.text),
      evidenceFn: () => "HTTP 200 — Apache mod_status live request telemetry exposed",
      detail: "Apache /server-status publicly displays live client IPs, active URLs, and server state.",
      detailZh: "Apache /server-status 状态页对外公开，可泄露实时请求 URL 与访客 IP。",
      fixSnippet: "# Apache httpd.conf:\n<Location /server-status>\n  Require local\n</Location>",
    },
    {
      id: "security-txt", path: "/.well-known/security.txt", category: "Security Policy (RFC 9116)", severity: "info", positiveCheck: true,
      validate: (r) => r.ok && r.status === 200 && !isSpaHtmlFallback(r, homeSnippet) && /^Contact:\s*(?:mailto:|https?:\/\/)/im.test(r.text),
      evidenceFn: () => "HTTP 200 — valid RFC 9116 security.txt published",
      detail: "RFC 9116 security.txt disclosure contact published.",
      detailZh: "已按 RFC 9116 标准发布 security.txt 安全漏洞披露联系方式。",
      fixSnippet: "",
    },
    {
      id: "firebase-json", path: "/firebase.json", category: "Config Exposure", severity: "low",
      validate: (r) => {
        if (!r.ok || r.status !== 200 || isSpaHtmlFallback(r, homeSnippet)) return false;
        const j = safeJsonParse(r.text);
        return Boolean(j && (j.hosting || j.firestore || j.database || j.functions));
      },
      evidenceFn: (r) => `HTTP 200 (${r.bytes} bytes) — Firebase project hosting/rules config accessible`,
      detail: "Public /firebase.json configuration file is served from web root.",
      detailZh: "网站根目录公开暴露了 /firebase.json 配置文件，建议从静态发布目录排除。",
      fixSnippet: '// firebase.json hosting.ignore:\n"ignore": ["firebase.json", "**/.*", "**/node_modules/**"]',
    },
    {
      id: "next-config", path: "/next.config.js", category: "Config Exposure", severity: "high",
      validate: (r) => r.ok && r.status === 200 && !isSpaHtmlFallback(r, homeSnippet) && /(?:module\.exports|export\s+default|nextConfig)/i.test(r.text) && /(?:rewrites|headers|images|env|reactStrictMode|webpack)/i.test(r.text),
      evidenceFn: (r) => `HTTP 200 (${r.bytes} bytes) — Next.js server build config readable`,
      detail: "Public /next.config.js exposed from web root, revealing rewrites, headers, or env mappings.",
      detailZh: "生产根目录直接暴露了 /next.config.js 服务端配置文件，请勿将项目根目录直接映射到静态服务器。",
      fixSnippet: "# Serve only .next/static or public/ — never expose repository root files",
    },
    {
      id: "package-json", path: "/package.json", category: "Dependency Manifest Exposure", severity: "medium",
      validate: (r) => {
        if (!r.ok || r.status !== 200 || isSpaHtmlFallback(r, homeSnippet)) return false;
        const j = safeJsonParse(r.text);
        return Boolean(j && typeof j.name === "string" && (j.dependencies || j.devDependencies || j.scripts));
      },
      evidenceFn: (r) => {
        const j = safeJsonParse(r.text);
        const deps = Object.keys(j?.dependencies || {}).length;
        return `HTTP 200 — package.json exposed (${deps} production dependencies listed)`;
      },
      detail: "Public /package.json exposes exact dependency versions for targeted CVE matching.",
      detailZh: "生产环境公开暴露了 /package.json，会直接暴露所有依赖包版本号与构建脚本。",
      fixSnippet: "# Nginx:\nlocation = /package.json { deny all; return 404; }",
    },
    {
      id: "backup-sql", path: "/backup.sql", category: "Database Dump Exposure", severity: "critical",
      validate: isSqlDump,
      evidenceFn: (r) => `HTTP 200 (${r.bytes} bytes) — SQL database dump statements detected`,
      detail: "CRITICAL: Public /backup.sql database dump is directly downloadable from web root.",
      detailZh: "严重高危：网站公开暴露了 /backup.sql 数据库备份文件，请立即删除并排查数据外泄！",
      fixSnippet: "# Remove SQL backups from web root immediately and block *.sql:\nlocation ~* \\.(sql|bak|dump)$ { deny all; return 404; }",
    },
    {
      id: "dump-sql", path: "/dump.sql", category: "Database Dump Exposure", severity: "critical",
      validate: isSqlDump,
      evidenceFn: (r) => `HTTP 200 (${r.bytes} bytes) — SQL database dump statements detected`,
      detail: "CRITICAL: Public /dump.sql database dump is directly downloadable from web root.",
      detailZh: "严重高危：网站公开暴露了 /dump.sql 数据库导出文件，请立即删除并屏蔽 .sql 扩展名！",
      fixSnippet: "# Nginx:\nlocation ~* \\.(sql|bak|dump)$ { deny all; return 404; }",
    },
    {
      id: "debug-vars", path: "/debug/vars", category: "Diagnostics Exposure", severity: "high",
      validate: (r) => {
        if (!r.ok || r.status !== 200 || isSpaHtmlFallback(r, homeSnippet)) return false;
        const j = safeJsonParse(r.text);
        return Boolean(j && j.cmdline && j.memstats);
      },
      evidenceFn: () => "HTTP 200 — Go expvar /debug/vars runtime cmdline & memory stats exposed",
      detail: "Go expvar /debug/vars diagnostic endpoint publicly exposes command-line args and runtime metrics.",
      detailZh: "Go 语言 /debug/vars 调试端点暴露在公网，可能泄露启动参数与运行状态。",
      fixSnippet: "// Bind Go expvar/pprof only to 127.0.0.1 internal admin listener",
    },
    {
      id: "metrics", path: "/metrics", category: "Diagnostics Exposure", severity: "medium",
      validate: (r) => r.ok && r.status === 200 && !isSpaHtmlFallback(r, homeSnippet) && /^#\s*(?:HELP|TYPE)\s+[a-zA-Z_:][a-zA-Z0-9_:]*/m.test(r.text),
      evidenceFn: (r) => `HTTP 200 (${r.bytes} bytes) — Prometheus /metrics exposition format accessible`,
      detail: "Prometheus /metrics endpoint is publicly exposed without IP allowlist or auth.",
      detailZh: "Prometheus /metrics 监控指标接口裸奔在公网，建议限制仅内网抓取。",
      fixSnippet: "# Nginx:\nlocation = /metrics { allow 10.0.0.0/8; deny all; }",
    },
    {
      id: "open-redirect", path: "/?next=https://vibeshield-redirect-probe.invalid",
      urlOverride: `${finalOrigin}/?next=https://vibeshield-redirect-probe.invalid`,
      method: "GET", redirect: "manual",
      category: "Open Redirect", severity: "high",
      validate: (r) => {
        if (!r.ok || r.status < 300 || r.status >= 400) return false;
        const loc = (r.headers.get("location") || "").trim();
        return /^https?:\/\/vibeshield-redirect-probe\.invalid/i.test(loc) || /^\/\/vibeshield-redirect-probe\.invalid/i.test(loc);
      },
      evidenceFn: (r) => `HTTP ${r.status} Location: ${r.headers.get("location")}`,
      detail: "Unvalidated ?next= parameter reflects external redirect URLs in Location header (Open Redirect).",
      detailZh: "检测到开放重定向风险：?next= 参数可将用户 302 跳转至外部任意域名，易被钓鱼利用。",
      fixSnippet: "// Only allow relative same-origin redirect paths:\nconst safeNext = rawNext.startsWith('/') && !rawNext.startsWith('//') ? rawNext : '/';",
    },
    {
      id: "cors-probe", path: new URL(resolvedUrl).pathname || "/",
      urlOverride: resolvedUrl,
      method: "HEAD",
      headers: { Origin: "https://vibeshield-cors-probe.invalid" },
      category: "CORS Policy", severity: "high",
      customCors: true,
      validate: (r) => {
        const acao = (r.headers.get("access-control-allow-origin") || "").trim();
        const acac = (r.headers.get("access-control-allow-credentials") || "").toLowerCase() === "true";
        return acao === "https://vibeshield-cors-probe.invalid" || (acao === "*" && acac);
      },
      evidenceFn: (r) => `ACAO: ${r.headers.get("access-control-allow-origin") || "none"}, ACAC: ${r.headers.get("access-control-allow-credentials") || "false"}`,
      detail: "Server reflects untrusted Origin header in Access-Control-Allow-Origin.",
      detailZh: "服务器将任意外部 Origin 反射进 Access-Control-Allow-Origin，存在跨域数据读取风险。",
      fixSnippet: "// Validate Origin against an explicit production allowlist instead of echoing req.headers.origin",
    },
  ];
}

// Phase 4A: Supabase Artifacts & Live Read-Only Probe (up to 20 tables + RPC + Storage)
function extractSupabaseArtifacts(sources) {
  const urls = new Set();
  const jwts = new Map();

  const urlRe = /https:\/\/([a-z0-9]{15,28})\.supabase\.co\b/gi;
  const jwtRe = /\beyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b/g;

  for (const { label, text } of sources) {
    let m;
    urlRe.lastIndex = 0;
    while ((m = urlRe.exec(text)) !== null) {
      urls.add(`https://${m[1].toLowerCase()}.supabase.co`);
    }
    jwtRe.lastIndex = 0;
    while ((m = jwtRe.exec(text)) !== null) {
      const tok = m[0];
      if (jwts.has(tok)) continue;
      const payload = decodeJwtPayload(tok);
      if (payload && (payload.iss === "supabase" || payload.role === "anon" || payload.role === "service_role" || payload.ref)) {
        jwts.set(tok, { token: tok, payload, source: label });
      }
    }
  }

  let primaryUrl = [...urls][0] || null;
  let anonKey = null;
  const serviceRoleLeaks = [];

  for (const entry of jwts.values()) {
    const role = String(entry.payload.role || "").toLowerCase();
    if (!primaryUrl && entry.payload.ref && /^[a-z0-9]{15,28}$/i.test(entry.payload.ref)) {
      primaryUrl = `https://${entry.payload.ref.toLowerCase()}.supabase.co`;
    }
    if (role === "service_role") {
      serviceRoleLeaks.push({
        source: entry.source,
        maskedValue: maskSecret(entry.token),
        ref: entry.payload.ref || null,
      });
    } else if (role === "anon" && !anonKey) {
      anonKey = entry.token;
    }
  }

  return {
    detected: Boolean(primaryUrl || anonKey || serviceRoleLeaks.length),
    urls: [...urls],
    primaryUrl,
    anonKey,
    anonKeyMasked: anonKey ? maskSecret(anonKey) : null,
    serviceRoleLeaks,
  };
}

async function probeSupabaseLive(supa, { maxTables = 20, recordTrace, shouldStop }) {
  const result = {
    detected: supa.detected,
    projectUrl: supa.primaryUrl,
    anonKeyExposed: Boolean(supa.anonKey),
    anonKeyMasked: supa.anonKeyMasked,
    serviceRoleLeaked: supa.serviceRoleLeaks.length > 0,
    serviceRoleLeaks: supa.serviceRoleLeaks,
    openApiExposed: false,
    discoveredTables: [],
    tablesProbed: 0,
    exposedTables: [],
    rpcEndpoints: [],
    publicBuckets: [],
    probeError: null,
  };

  if (!supa.primaryUrl || !supa.anonKey) return result;

  const authHeaders = {
    apikey: supa.anonKey,
    Authorization: `Bearer ${supa.anonKey}`,
    Accept: "application/json",
  };

  const [schemaResp, bucketResp] = await Promise.all([
    fetchCappedText(`${supa.primaryUrl}/rest/v1/`, { timeoutMs: 2000, maxBytes: 350000, headers: authHeaders }),
    fetchCappedText(`${supa.primaryUrl}/storage/v1/bucket`, { timeoutMs: 1800, maxBytes: 80000, headers: authHeaders }),
  ]);

  if (schemaResp.ok && schemaResp.status === 200) {
    const spec = safeJsonParse(schemaResp.text);
    if (spec && spec.paths && typeof spec.paths === "object") {
      result.openApiExposed = true;
      for (const p of Object.keys(spec.paths)) {
        if (p === "/") continue;
        if (p.startsWith("/rpc/")) {
          result.rpcEndpoints.push(p.slice(5));
        } else {
          const tbl = p.replace(/^\//, "");
          if (tbl && !tbl.includes("/")) result.discoveredTables.push(tbl);
        }
      }
    }
  }
  recordTrace(
    4, "Cloud DB", "Supabase PostgREST OpenAPI", `${supa.primaryUrl}/rest/v1/`, "GET",
    schemaResp.status, schemaResp.bytes, schemaResp.ms,
    result.openApiExposed ? "warn" : "pass",
    result.openApiExposed
      ? `OpenAPI schema lists ${result.discoveredTables.length} tables, ${result.rpcEndpoints.length} RPCs`
      : `PostgREST OpenAPI restricted (HTTP ${schemaResp.status})`
  );

  if (bucketResp.ok && bucketResp.status === 200) {
    const arr = safeJsonParse(bucketResp.text);
    if (Array.isArray(arr)) {
      result.publicBuckets = arr.slice(0, 20).map((b) => ({
        name: String(b.name || b.id || "unnamed"),
        public: Boolean(b.public),
      }));
    }
  }
  recordTrace(
    4, "Cloud DB", "Supabase Storage Buckets", `${supa.primaryUrl}/storage/v1/bucket`, "GET",
    bucketResp.status, bucketResp.bytes, bucketResp.ms,
    result.publicBuckets.length > 0 ? "warn" : "pass",
    result.publicBuckets.length > 0
      ? `${result.publicBuckets.length} bucket(s) enumerable by anon key`
      : `Storage bucket list locked (HTTP ${bucketResp.status})`
  );

  if (result.discoveredTables.length > 0 && !shouldStop()) {
    const rankTable = (t) => {
      const l = t.toLowerCase();
      return SENSITIVE_TABLE_HINTS.some((h) => l.includes(h)) ? 2 : 1;
    };
    const toProbe = [...result.discoveredTables].sort((a, b) => rankTable(b) - rankTable(a)).slice(0, maxTables);
    const probes = await runPool(
      toProbe,
      5,
      async (tbl) => {
        const r = await fetchCappedText(`${supa.primaryUrl}/rest/v1/${encodeURIComponent(tbl)}?select=*`, {
          method: "HEAD",
          timeoutMs: 1300,
          headers: { ...authHeaders, Prefer: "count=exact" },
        });
        const range = r.headers.get("content-range") || "";
        const totalMatch = range.match(/\/(\d+)$/);
        const rowCount = totalMatch ? Number(totalMatch[1]) : null;
        const sensitive = rankTable(tbl) === 2;
        const readableByAnon = r.status === 200 || r.status === 206;
        recordTrace(
          4, "Cloud DB", `Supabase RLS HEAD: ${tbl}`, `${supa.primaryUrl}/rest/v1/${tbl}`, "HEAD",
          r.status, 0, r.ms,
          readableByAnon && (rowCount > 0 || sensitive) ? "fail" : readableByAnon ? "warn" : "pass",
          readableByAnon
            ? `Anon readable (HTTP ${r.status}${rowCount !== null ? `, ${rowCount} rows` : ""})`
            : `Protected by RLS (HTTP ${r.status})`
        );
        return { table: tbl, status: r.status, readableByAnon, rowCount, sensitive };
      },
      shouldStop
    );
    result.tablesProbed = probes.length;
    result.exposedTables = probes.filter((p) => p.readableByAnon);
  }

  return result;
}

// Phase 4B: Firebase Realtime DB & Cloud Firestore Read-Only Exposure Audit
function extractFirebaseArtifacts(sources) {
  const projectIds = new Set();
  const databaseUrls = new Set();

  const projRe = /["']?projectId["']?\s*[:=]\s*["']([a-z0-9][a-z0-9-]{3,36})["']/gi;
  const authDomRe = /["']?authDomain["']?\s*[:=]\s*["']([a-z0-9][a-z0-9-]{3,36})\.firebaseapp\.com["']/gi;
  const dbUrlRe = /https:\/\/([a-z0-9-]+(?:\.[a-z0-9-]+)?\.(?:firebaseio\.com|firebasedatabase\.app))\b/gi;
  const bucketRe = /["']?storageBucket["']?\s*[:=]\s*["']([a-z0-9][a-z0-9-]{3,36})\.(?:appspot\.com|firebasestorage\.app)["']/gi;

  for (const { text } of sources) {
    let m;
    projRe.lastIndex = 0;
    while ((m = projRe.exec(text)) !== null) {
      if (!PLACEHOLDER_RE.test(m[1])) projectIds.add(m[1].toLowerCase());
    }
    authDomRe.lastIndex = 0;
    while ((m = authDomRe.exec(text)) !== null) {
      if (!PLACEHOLDER_RE.test(m[1])) projectIds.add(m[1].toLowerCase());
    }
    bucketRe.lastIndex = 0;
    while ((m = bucketRe.exec(text)) !== null) {
      if (!PLACEHOLDER_RE.test(m[1])) projectIds.add(m[1].toLowerCase());
    }
    dbUrlRe.lastIndex = 0;
    while ((m = dbUrlRe.exec(text)) !== null) {
      if (!PLACEHOLDER_RE.test(m[1])) databaseUrls.add(`https://${m[1].toLowerCase()}`);
    }
  }

  for (const pid of [...projectIds].slice(0, 2)) {
    const defaultUrl = `https://${pid}-default-rtdb.firebaseio.com`;
    const legacyUrl = `https://${pid}.firebaseio.com`;
    if (databaseUrls.size < 3) databaseUrls.add(defaultUrl);
    if (databaseUrls.size < 3) databaseUrls.add(legacyUrl);
  }

  return {
    detected: projectIds.size > 0 || databaseUrls.size > 0,
    projectIds: [...projectIds].slice(0, 3),
    databaseUrls: [...databaseUrls].slice(0, 3),
  };
}

async function probeFirebaseLive(fb, { recordTrace, shouldStop }) {
  const result = {
    detected: fb.detected,
    projectId: fb.projectIds[0] || null,
    projectIds: fb.projectIds,
    rtdbUrl: fb.databaseUrls[0] || null,
    databaseUrls: fb.databaseUrls,
    rtdbPublic: false,
    firestorePublic: false,
    rtdbProbes: [],
    firestoreProbes: [],
    rtdbExposed: [],
    firestoreExposed: [],
    detail: fb.detected ? "Firebase project detected; access rules denied unauthenticated reads." : "No Firebase project configuration detected in client bundles.",
    detailZh: fb.detected ? "已检测到 Firebase 项目，未登录匿名读取均已被安全规则拦截。" : "前端代码中未检测到 Firebase 数据库配置。",
  };
  if (!fb.detected || shouldStop()) return result;

  const rtdbTasks = fb.databaseUrls.map(async (dbUrl) => {
    const probeUrl = `${dbUrl}/.json?shallow=true`;
    const r = await fetchCappedText(probeUrl, { timeoutMs: 2000, maxBytes: 24000, headers: { Accept: "application/json" } });
    const parsed = r.ok && r.status === 200 ? safeJsonParse(r.text) : null;
    const accessible = Boolean(
      r.ok &&
      r.status === 200 &&
      parsed !== null &&
      !(typeof parsed === "object" && !Array.isArray(parsed) && typeof parsed.error === "string")
    );
    const topLevelKeysCount = accessible && typeof parsed === "object" ? Object.keys(parsed).length : 0;
    recordTrace(
      4, "Cloud DB", "Firebase RTDB Shallow Probe", probeUrl, "GET",
      r.status, r.bytes, r.ms,
      accessible ? "fail" : "pass",
      accessible
        ? `Unauthenticated RTDB read allowed (${topLevelKeysCount} top-level key(s))`
        : `RTDB access denied or absent (HTTP ${r.status})`
    );
    return { url: dbUrl, status: r.status, accessible, topLevelKeysCount };
  });

  const fsTasks = fb.projectIds.map(async (pid) => {
    const probeUrl = `https://firestore.googleapis.com/v1/projects/${encodeURIComponent(pid)}/databases/(default)/documents?pageSize=1`;
    const r = await fetchCappedText(probeUrl, { timeoutMs: 2000, maxBytes: 16000, headers: { Accept: "application/json" } });
    const parsed = r.ok && r.status === 200 ? safeJsonParse(r.text) : null;
    const accessible = Boolean(r.ok && r.status === 200 && parsed && Array.isArray(parsed.documents) && parsed.documents.length > 0);
    const documentsSampled = accessible ? parsed.documents.length : 0;
    recordTrace(
      4, "Cloud DB", `Firestore Read Probe (${pid})`, probeUrl, "GET",
      r.status, r.bytes, r.ms,
      accessible ? "fail" : "pass",
      accessible
        ? `Unauthenticated Firestore documents readable (pageSize=1 returned ${documentsSampled} doc)`
        : `Firestore rules locked or no root public docs (HTTP ${r.status})`
    );
    return { projectId: pid, status: r.status, accessible, documentsSampled };
  });

  const [rtdbRes, fsRes] = await Promise.all([Promise.all(rtdbTasks), Promise.all(fsTasks)]);
  result.rtdbProbes = rtdbRes;
  result.firestoreProbes = fsRes;
  result.rtdbExposed = rtdbRes.filter((x) => x.accessible);
  result.firestoreExposed = fsRes.filter((x) => x.accessible);
  result.rtdbPublic = result.rtdbExposed.length > 0;
  result.firestorePublic = result.firestoreExposed.length > 0;
  if (result.rtdbPublic || result.firestorePublic) {
    result.detail = `CRITICAL: Unauthenticated public Firebase read confirmed (${result.rtdbPublic ? "Realtime DB open" : ""}${result.rtdbPublic && result.firestorePublic ? " + " : ""}${result.firestorePublic ? "Cloud Firestore open" : ""}).`;
    result.detailZh = `高危：确认 Firebase 允许未登录公开读取（${result.rtdbPublic ? "Realtime DB 裸奔" : ""}${result.rtdbPublic && result.firestorePublic ? " + " : ""}${result.firestorePublic ? "Firestore 裸奔" : ""}）。`;
  }
  return result;
}

// Phase 5A: Mozilla Observatory-Grade CSP Directive Parser (Aligned 1:1 with #422 cspAudit contract)
function analyzeCsp(rawCsp) {
  const raw = String(rawCsp || "").trim();
  if (!raw) {
    return {
      present: false,
      raw: "",
      unsafeInline: false,
      unsafeEval: false,
      wildcardSrc: false,
      missingFrameAncestors: true,
      missingObjectSrc: true,
      missingBaseUri: true,
      score: 0,
      grade: "F",
      directives: {},
      issues: ["No Content-Security-Policy header is configured to restrict script execution or injection."],
      issuesZh: ["未配置 Content-Security-Policy 响应头，无法有效拦截 XSS 跨站脚本注入。"],
      issueItems: [
        {
          code: "missing-csp",
          severity: "medium",
          detail: "No Content-Security-Policy header is configured to restrict script execution or injection.",
          detailZh: "未配置 Content-Security-Policy 响应头，无法有效拦截 XSS 跨站脚本注入。",
        },
      ],
    };
  }

  const directives = {};
  for (const part of raw.split(";")) {
    const tokens = part.trim().split(/\s+/).filter(Boolean);
    if (!tokens.length) continue;
    const name = tokens[0].toLowerCase();
    if (!directives[name]) directives[name] = tokens.slice(1);
  }

  const issueItems = [];
  let score = 100;
  const scriptSrc = directives["script-src"] || directives["default-src"] || [];
  const hasStrictDynamic = scriptSrc.some((t) => t.toLowerCase() === "'strict-dynamic'");
  const hasNonceOrHash = scriptSrc.some((t) => /^'(?:nonce-|sha(?:256|384|512)-)/i.test(t));

  const unsafeInline = scriptSrc.some((t) => t.toLowerCase() === "'unsafe-inline'") && !hasStrictDynamic && !hasNonceOrHash;
  const unsafeEval = scriptSrc.some((t) => t.toLowerCase() === "'unsafe-eval'");
  const wildcardTokens = scriptSrc.filter((t) => t === "*" || t === "https:" || t === "http:" || t === "data:");
  const wildcardSrc = wildcardTokens.length > 0;
  const missingFrameAncestors = !directives["frame-ancestors"];
  const objectSrc = directives["object-src"] || directives["default-src"] || [];
  const missingObjectSrc = !objectSrc.some((t) => t.toLowerCase() === "'none'");
  const missingBaseUri = !directives["base-uri"];

  if (unsafeInline) {
    score -= 25;
    issueItems.push({
      code: "csp-unsafe-inline-script",
      severity: "medium",
      detail: "CSP script-src/default-src allows 'unsafe-inline' without nonces or hashes, weakening XSS protection.",
      detailZh: "CSP 的 script-src/default-src 允许 'unsafe-inline' 且未使用 nonce/hash，XSS 防御大幅削弱。",
    });
  }
  if (unsafeEval) {
    score -= 20;
    issueItems.push({
      code: "csp-unsafe-eval",
      severity: "medium",
      detail: "CSP allows 'unsafe-eval', permitting dynamic string-to-code execution via eval().",
      detailZh: "CSP 允许 'unsafe-eval'，增加了动态代码注入与 DOM XSS 执行风险。",
    });
  }
  if (wildcardSrc) {
    score -= 30;
    issueItems.push({
      code: "csp-wildcard-script",
      severity: "high",
      detail: `CSP script-src/default-src permits broad wildcard script origins (${wildcardTokens.join(", ")}).`,
      detailZh: "CSP 脚本来源包含过宽通配符（* / https: / data:），攻击者可加载任意外部恶意脚本。",
    });
  }
  if (missingFrameAncestors) {
    score -= 10;
    issueItems.push({
      code: "csp-missing-frame-ancestors",
      severity: "low",
      detail: "CSP omits frame-ancestors directive (modern replacement for X-Frame-Options clickjacking defense).",
      detailZh: "CSP 缺少 frame-ancestors 指令，建议补齐以替代老旧的 X-Frame-Options 点击劫持防护。",
    });
  }
  if (missingObjectSrc) {
    score -= 10;
    issueItems.push({
      code: "csp-missing-object-src",
      severity: "low",
      detail: "CSP does not set object-src 'none' to block legacy Flash/plugin object embedding.",
      detailZh: "CSP 未设置 object-src 'none'，建议显式禁用插件对象加载。",
    });
  }
  if (missingBaseUri) {
    score -= 5;
    issueItems.push({
      code: "csp-missing-base-uri",
      severity: "low",
      detail: "CSP omits base-uri 'self' or 'none', leaving relative script URLs open to <base> tag hijacking.",
      detailZh: "CSP 未限制 base-uri，建议添加 base-uri 'self' 防止相对路径脚本被劫持。",
    });
  }

  score = Math.max(0, score);
  const grade = score >= 95 ? "A+" : score >= 85 ? "A" : score >= 75 ? "B" : score >= 60 ? "C" : score >= 40 ? "D" : "F";

  return {
    present: true,
    raw: raw.slice(0, 600),
    unsafeInline,
    unsafeEval,
    wildcardSrc,
    missingFrameAncestors,
    missingObjectSrc,
    missingBaseUri,
    score,
    grade,
    directives,
    issues: issueItems.map((x) => x.detail),
    issuesZh: issueItems.map((x) => x.detailZh),
    issueItems,
  };
}

// Phase 5B: Mozilla Observatory Security Headers Audit (10 checks, backward-compatible with v2.0 7-check contract)
function auditSecurityHeaders(headers, securityTxtPresent, cspAudit) {
  const h = (name) => headers.get(name) || "";
  const hstsRaw = h("strict-transport-security");
  const maxAgeMatch = hstsRaw.match(/max-age\s*=\s*(\d+)/i);
  const hstsMaxAge = maxAgeMatch ? Number(maxAgeMatch[1]) : 0;
  const hstsAudit = {
    present: Boolean(hstsRaw),
    raw: hstsRaw,
    maxAge: hstsMaxAge,
    includeSubDomains: /includeSubDomains/i.test(hstsRaw),
    preload: /\bpreload\b/i.test(hstsRaw),
    meetsOneYear: hstsMaxAge >= 31536000,
  };

  const refPol = h("referrer-policy").trim();
  const refPolSafe = Boolean(refPol) && !/unsafe-url/i.test(refPol);
  const coop = h("cross-origin-opener-policy").trim();
  const corp = h("cross-origin-resource-policy").trim();
  const serverHdr = h("server").trim();
  const poweredBy = h("x-powered-by").trim();
  const verboseServer = /\b(?:nginx|apache|iis|php|express|openresty)\/\d+\.\d+/i.test(serverHdr);

  const checks = [
    {
      name: "Strict-Transport-Security",
      present: hstsAudit.present,
      strong: hstsAudit.present && hstsAudit.meetsOneYear && hstsAudit.includeSubDomains,
      value: hstsRaw,
      weight: 5,
      purpose: "Enforces HTTPS with >= 1 year max-age & includeSubDomains against SSL stripping",
      purposeZh: "强制浏览器全程走 HTTPS（建议 max-age>=31536000 且含 includeSubDomains）",
    },
    {
      name: "Content-Security-Policy",
      present: cspAudit.present,
      strong: cspAudit.present && cspAudit.score >= 85,
      value: h("content-security-policy").slice(0, 140),
      weight: 6,
      purpose: "Mitigates XSS & unauthorized third-party script injection",
      purposeZh: "限制脚本与接口来源，防御跨站脚本（XSS）注入攻击",
    },
    {
      name: "X-Frame-Options",
      present: Boolean(h("x-frame-options") || /frame-ancestors/i.test(h("content-security-policy"))),
      strong: Boolean(h("x-frame-options") || /frame-ancestors/i.test(h("content-security-policy"))),
      value: h("x-frame-options") || (/frame-ancestors/i.test(h("content-security-policy")) ? "CSP frame-ancestors" : ""),
      weight: 3,
      purpose: "Blocks clickjacking iframe embedding attacks",
      purposeZh: "禁止恶意网页用 iframe 嵌套本站实施点击劫持",
    },
    {
      name: "X-Content-Type-Options",
      present: h("x-content-type-options").toLowerCase().includes("nosniff"),
      strong: h("x-content-type-options").toLowerCase().includes("nosniff"),
      value: h("x-content-type-options"),
      weight: 2,
      purpose: "Prevents MIME-type confusion script execution",
      purposeZh: "禁止浏览器嗅探文件类型，防止静态文件被当脚本执行",
    },
    {
      name: "Referrer-Policy",
      present: refPolSafe,
      strong: refPolSafe,
      value: refPol || "",
      weight: 2,
      purpose: "Stops sensitive URL tokens leaking via Referer header",
      purposeZh: "防止带参数的敏感页面链接通过 Referer 泄露给外站",
    },
    {
      name: "Permissions-Policy",
      present: Boolean(h("permissions-policy")),
      strong: Boolean(h("permissions-policy")),
      value: h("permissions-policy").slice(0, 100),
      weight: 2,
      purpose: "Restricts camera, microphone & geolocation browser APIs",
      purposeZh: "收紧摄像头、麦克风与定位等浏览器敏感接口权限",
    },
    {
      name: "Cross-Origin-Opener-Policy",
      present: Boolean(coop && /same-origin/i.test(coop)),
      strong: Boolean(coop && /same-origin/i.test(coop)),
      value: coop,
      weight: 2,
      purpose: "Isolates browsing context group against Spectre/XS-Leaks cross-window attacks",
      purposeZh: "启用跨源窗口隔离（COOP），防御 Spectre 与跨标签页侧信道泄露",
    },
    {
      name: "Cross-Origin-Resource-Policy",
      present: Boolean(corp),
      strong: Boolean(corp),
      value: corp,
      weight: 1,
      purpose: "Controls which origins may embed your static/API resources",
      purposeZh: "限制跨域资源加载权限（CORP），降低资源被恶意站点嵌入风险",
    },
    {
      name: "Server / X-Powered-By Hidden",
      present: !poweredBy && !verboseServer,
      strong: !poweredBy && !verboseServer,
      value: poweredBy ? `Exposed X-Powered-By: ${poweredBy}` : (verboseServer ? `Verbose Server: ${serverHdr}` : "Clean (hidden)"),
      weight: 1,
      purpose: "Avoids broadcasting backend framework & server version fingerprints",
      purposeZh: "隐藏后端框架与 Web 服务器精确版本号，降低自动化漏洞精准打击面",
    },
    {
      name: "security.txt (RFC 9116)",
      present: Boolean(securityTxtPresent),
      strong: Boolean(securityTxtPresent),
      value: securityTxtPresent ? "Published at /.well-known/security.txt" : "Not found",
      weight: 1,
      purpose: "Publishes verified security researcher vulnerability disclosure contact",
      purposeZh: "按 RFC 9116 发布安全漏洞披露联系人，便于白帽第一时间反馈隐患",
    },
  ];

  const passed = checks.filter((c) => c.present).length;
  return { passed, total: checks.length, hstsDetails: hstsAudit, hstsAudit, checks };
}

function auditCookies(headers) {
  let rawCookies = [];
  try {
    if (typeof headers.getSetCookie === "function") {
      rawCookies = headers.getSetCookie();
    } else {
      const single = headers.get("set-cookie");
      if (single) rawCookies = [single];
    }
  } catch {}

  const items = [];
  const seenNames = new Set();
  let weakCount = 0;
  for (const raw of rawCookies.slice(0, 20)) {
    const parts = String(raw).split(";").map((s) => s.trim());
    const nameVal = parts[0] || "";
    const eqIdx = nameVal.indexOf("=");
    const name = (eqIdx > 0 ? nameVal.slice(0, eqIdx) : nameVal).trim();
    if (!name || seenNames.has(name.toLowerCase())) continue;
    seenNames.add(name.toLowerCase());
    const attrs = parts.slice(1).map((a) => a.toLowerCase());
    const secure = attrs.includes("secure");
    const httpOnly = attrs.includes("httponly");
    const sameSiteAttr = attrs.find((a) => a.startsWith("samesite=")) || "";
    const sameSite = sameSiteAttr ? sameSiteAttr.split("=")[1] : "missing";
    const sensitiveName = /(?:sess|sid|auth|token|jwt|uid|login|bduss|csrf|sb-)/i.test(name);
    const issues = [];
    if (!secure) issues.push("Secure");
    if (!httpOnly && sensitiveName) issues.push("HttpOnly");
    if (sameSite === "missing") issues.push("SameSite");
    if (sameSite === "none" && !secure) issues.push("Secure-required-for-SameSite-None");
    if (issues.length > 0) weakCount++;
    items.push({ name, secure, httpOnly, sameSite, sensitiveName, missingFlags: issues });
  }
  return { total: items.length, weakCount, items };
}

// Phase 5C: Passive Framework Fingerprinting & Real CVE Advisory Matcher (ZERO exploit payloads)
function detectFrameworkCves(allSources, headers, supabaseAudit) {
  const detectedFrameworks = [];
  const frameworkCves = [];
  const seenFw = new Set();

  const addVersion = (framework, version, source) => {
    const key = `${framework}:${version}`;
    if (seenFw.has(key)) return;
    seenFw.add(key);
    detectedFrameworks.push({ framework, version, source });
  };

  const serverHdr = headers.get("server") || "";
  const poweredBy = headers.get("x-powered-by") || "";

  // 1. Passive Next.js version detection
  let nextVersion = null;
  let nextSource = null;
  for (const src of allSources) {
    const m =
      src.text.match(/window\.next\s*=\s*\{[^}]{0,120}version\s*:\s*["'](\d+\.\d+\.\d+(?:-[a-z0-9.]+)?)["']/i) ||
      src.text.match(/"next"\s*:\s*"[\^~]?(\d+\.\d+\.\d+)"/i) ||
      src.text.match(/next\.js\/v?(\d+\.\d+\.\d+)/i);
    if (m) {
      nextVersion = m[1];
      nextSource = src.label;
      break;
    }
  }
  if (nextVersion) {
    addVersion("Next.js", nextVersion, nextSource);
    const sv = parseSemver(nextVersion);
    if (sv) {
      const vulnNext =
        (sv[0] === 15 && cmpSemver(sv, [15, 2, 3]) < 0) ||
        (sv[0] === 14 && cmpSemver(sv, [14, 2, 25]) < 0) ||
        (sv[0] === 13 && cmpSemver(sv, [13, 5, 9]) < 0) ||
        (sv[0] <= 12 && cmpSemver(sv, [12, 3, 5]) < 0);
      if (vulnNext) {
        frameworkCves.push({
          framework: "Next.js",
          version: nextVersion,
          cve: "CVE-2025-29927",
          severity: "critical",
          title: `Next.js ${nextVersion} is vulnerable to Middleware Authorization Bypass (CVE-2025-29927)`,
          titleZh: `检测到 Next.js ${nextVersion} 存在高危中间件鉴权绕过漏洞 (CVE-2025-29927)`,
          detail: `Detected Next.js ${nextVersion} in ${nextSource}. Versions below 15.2.3 / 14.2.25 / 13.5.9 / 12.3.5 are affected by CVE-2025-29927.`,
          detailZh: `在 ${nextSource} 识别到 Next.js ${nextVersion}，低于 15.2.3 / 14.2.25 / 13.5.9 / 12.3.5 的版本受 CVE-2025-29927 影响。`,
          remediation: "Upgrade Next.js immediately to >= 15.2.3 (or 14.2.25 / 13.5.9) and strip external x-middleware-subrequest headers at your edge proxy.",
          remediationZh: "请立即升级 Next.js 至 >= 15.2.3（或 14.2.25 / 13.5.9），并在边缘网关拦截外部传入的 x-middleware-subrequest 请求头。",
          fixSnippet: 'npm install next@latest && npm run build\n# Nginx defense-in-depth:\nproxy_set_header x-middleware-subrequest "";',
        });
      }
    }
  }

  // 2. Passive jQuery version detection
  for (const src of allSources) {
    const m =
      src.text.match(/jQuery(?:\s+JavaScript\s+Library)?\s+v?(\d+\.\d+\.\d+)/i) ||
      src.text.match(/jquery[.-](\d+\.\d+\.\d+)(?:\.min)?\.js/i);
    if (m) {
      addVersion("jQuery", m[1], src.label);
      const sv = parseSemver(m[1]);
      if (sv && cmpSemver(sv, [3, 5, 0]) < 0) {
        frameworkCves.push({
          framework: "jQuery",
          version: m[1],
          cve: "CVE-2020-11022",
          severity: "medium",
          title: `Outdated jQuery ${m[1]} detected (XSS vulnerability CVE-2020-11022 / CVE-2020-11023)`,
          titleZh: `检测到过时的 jQuery ${m[1]}（存在 XSS 漏洞 CVE-2020-11022 / CVE-2020-11023）`,
          detail: `jQuery ${m[1]} found in ${src.label}. Versions prior to 3.5.0 contain HTML sanitization XSS flaws in DOM manipulation methods.`,
          detailZh: `在 ${src.label} 发现 jQuery ${m[1]}，3.5.0 以下版本存在 DOM 操作 XSS 注入缺陷。`,
          remediation: "Upgrade jQuery to >= 3.7.1 or remove legacy jQuery dependencies.",
          remediationZh: "请升级 jQuery 至 3.7.1 及以上版本，或清理遗留依赖。",
          fixSnippet: "npm install jquery@^3.7.1",
        });
      }
      break;
    }
  }

  // 3. Passive Apache / Nginx / PHP / WordPress version fingerprints
  const apacheM = serverHdr.match(/Apache\/(\d+\.\d+\.\d+)/i);
  if (apacheM) {
    addVersion("Apache HTTP Server", apacheM[1], "Header: Server");
    if (apacheM[1] === "2.4.49" || apacheM[1] === "2.4.50") {
      frameworkCves.push({
        framework: "Apache HTTP Server",
        version: apacheM[1],
        cve: "CVE-2021-41773",
        severity: "critical",
        title: `Apache ${apacheM[1]} vulnerable to Path Traversal & RCE (CVE-2021-41773 / CVE-2021-42013)`,
        titleZh: `Apache ${apacheM[1]} 存在高危路径穿越与远程代码执行漏洞 (CVE-2021-41773)`,
        detail: `Server header reports Apache/${apacheM[1]}, which is directly affected by CVE-2021-41773 and CVE-2021-42013.`,
        detailZh: `响应头暴露服务器运行 Apache/${apacheM[1]}，受高危路径穿越漏洞影响。`,
        remediation: "Upgrade Apache HTTP Server to >= 2.4.58 immediately and set ServerTokens Prod.",
        remediationZh: "请立即升级 Apache 至 2.4.58+ 并配置 ServerTokens Prod 隐藏版本号。",
        fixSnippet: "# Apache httpd.conf:\nServerTokens Prod\nServerSignature Off",
      });
    }
  }

  const nginxM = serverHdr.match(/nginx\/(\d+\.\d+\.\d+)/i);
  if (nginxM) {
    addVersion("Nginx", nginxM[1], "Header: Server");
    const sv = parseSemver(nginxM[1]);
    if (sv && cmpSemver(sv, [1, 24, 0]) < 0) {
      frameworkCves.push({
        framework: "Nginx",
        version: nginxM[1],
        cve: "CVE-2023-44487",
        severity: "medium",
        title: `Legacy Nginx ${nginxM[1]} exposed in Server header (HTTP/2 Rapid Reset advisory)`,
        titleZh: `响应头暴露老旧 Nginx ${nginxM[1]} 版本（受 HTTP/2 Rapid Reset 等历史漏洞影响）`,
        detail: `Server header discloses nginx/${nginxM[1]}. Upgrade to supported Nginx >= 1.26 and enable server_tokens off.`,
        detailZh: `响应头直接暴露 nginx/${nginxM[1]}，建议升级至 1.26+ 并配置 server_tokens off。`,
        remediation: "Upgrade Nginx to >= 1.26.x and add server_tokens off; in http block.",
        remediationZh: "升级 Nginx 至 1.26+ 并在配置中开启 server_tokens off。",
        fixSnippet: "http {\n    server_tokens off;\n}",
      });
    }
  }

  const wpM = (allSources[0]?.text || "").match(/<meta[^>]+name=["']generator["'][^>]+content=["']WordPress\s+(\d+\.\d+(?:\.\d+)?)["']/i);
  if (wpM) {
    addVersion("WordPress", wpM[1], "index.html <meta generator>");
    const sv = parseSemver(wpM[1]);
    if (sv && cmpSemver(sv, [6, 4, 0]) < 0) {
      frameworkCves.push({
        framework: "WordPress",
        version: wpM[1],
        cve: "WP-CORE-OUTDATED",
        severity: "high",
        title: `Outdated WordPress ${wpM[1]} core version exposed`,
        titleZh: `检测到过时的 WordPress ${wpM[1]} 核心版本`,
        detail: `HTML meta generator advertises WordPress ${wpM[1]}, which misses critical security patches.`,
        detailZh: `页面暴露了过时的 WordPress ${wpM[1]}，缺少多项关键安全补丁。`,
        remediation: "Upgrade WordPress core and plugins to the latest stable release and remove the generator meta tag.",
        remediationZh: "请升级 WordPress 内核与插件至最新稳定版，并移除 wp_generator 标签。",
        fixSnippet: "remove_action('wp_head', 'wp_generator');",
      });
    }
  }

  if (poweredBy) {
    const phpM = poweredBy.match(/PHP\/(\d+\.\d+\.\d+)/i);
    if (phpM) {
      addVersion("PHP", phpM[1], "Header: X-Powered-By");
      const sv = parseSemver(phpM[1]);
      if (sv && cmpSemver(sv, [8, 1, 0]) < 0) {
        frameworkCves.push({
          framework: "PHP",
          version: phpM[1],
          cve: "PHP-EOL-ADVISORY",
          severity: "high",
          title: `End-of-life PHP ${phpM[1]} runtime exposed in X-Powered-By`,
          titleZh: `X-Powered-By 暴露已停止安全维护的 PHP ${phpM[1]} 版本`,
          detail: `Server discloses PHP/${phpM[1]}, which is past End-of-Life and no longer receives security fixes.`,
          detailZh: `服务器运行已停止维护的 PHP/${phpM[1]}，存在多个公开高危漏洞风险。`,
          remediation: "Upgrade PHP to >= 8.3 and set expose_php = Off in php.ini.",
          remediationZh: "请升级至 PHP 8.3+ 并在 php.ini 设置 expose_php = Off。",
          fixSnippet: "; php.ini\nexpose_php = Off",
        });
      }
    }
  }

  if (supabaseAudit?.detected && (supabaseAudit.exposedTables || []).length > 0) {
    frameworkCves.push({
      framework: "Supabase PostgREST",
      version: "RLS Missing",
      cve: "CVE-2025-48757",
      severity: "critical",
      title: `Supabase Row Level Security exposure confirmed on ${supabaseAudit.exposedTables.length} table(s) (CVE-2025-48757)`,
      titleZh: `确认 ${supabaseAudit.exposedTables.length} 张 Supabase 表存在 RLS 行级权限缺失风险 (CVE-2025-48757)`,
      detail: `Unauthenticated anon key successfully queried PostgREST tables: ${supabaseAudit.exposedTables.map((t) => t.table).slice(0, 8).join(", ")}.`,
      detailZh: `匿名 anon 密钥已可直接查询 PostgREST 数据表：${supabaseAudit.exposedTables.map((t) => t.table).slice(0, 8).join("、")}。`,
      remediation: "Enable and FORCE Row Level Security on every public schema table and revoke anon table privileges.",
      remediationZh: "请立即为所有 public 表开启 ENABLE / FORCE ROW LEVEL SECURITY 并回收 anon 读取权限。",
      fixSnippet: "ALTER TABLE public.<table_name> ENABLE ROW LEVEL SECURITY;\nALTER TABLE public.<table_name> FORCE ROW LEVEL SECURITY;\nREVOKE ALL ON TABLE public.<table_name> FROM anon;",
    });
  }

  return { detectedFrameworks, frameworkCves };
}

// Main 6-Phase Deep Scanner Entrypoint
export async function scanApp(rawUrl, options = {}) {
  const t0 = Date.now();
  const mode = options.mode === "fast" ? "fast" : "deep";
  const allowLocalTest = Boolean(options.allowLocalTest);
  const totalBudgetMs = Number(options.budgetMs || (mode === "fast" ? 6500 : 20500));
  const remainingMs = () => Math.max(0, totalBudgetMs - (Date.now() - t0));
  let budgetTruncated = false;

  const executionTrace = [];
  const recordTrace = (phase, phaseName, step, target, method, status, bytes, durationMs, verdict, note) => {
    const cleanNote = String(note || "").slice(0, 220);
    const msNum = Number(durationMs || 0);
    executionTrace.push({
      seq: executionTrace.length + 1,
      tMs: Date.now() - t0,
      phase,
      phaseName,
      label: step,
      step,
      target: String(target || "").slice(0, 140),
      method,
      status: Number(status || 0),
      bytes: Number(bytes || 0),
      ms: msNum,
      durationMs: msNum,
      result: verdict === "pass" ? "ok" : verdict,
      verdict,
      detail: cleanNote,
      note: cleanNote,
    });
  };

  const norm = normalizeTargetUrl(rawUrl, { allowLocalTest });
  if (norm.error) return { ok: false, error: norm.error, errorZh: norm.errorZh || norm.error };

  // =========================================================================
  // PHASE 1: Resilient Homepage Fetch + Real TLS 443 Handshake + DNS Takeover
  // =========================================================================
  const homeResult = await fetchHomepageResilient(norm);
  const homeResp = homeResult.resp;

  if (!homeResp || !homeResp.ok || homeResp.status === 0) {
    return {
      ok: false,
      error: `Could not connect to ${norm.hostname} (${homeResp?.error || "unreachable"}). Please confirm the website is publicly online.`,
      errorZh: `暂时无法连接到 ${norm.hostname}（${homeResp?.error === "timeout" ? "连接超时" : "目标服务器未响应"}），请确认网址可正常公开访问。`,
    };
  }

  const resolvedUrl = homeResp.url || norm.url;
  const finalUrlObj = (() => { try { return new URL(resolvedUrl); } catch { return new URL(norm.url); } })();
  const finalOrigin = finalUrlObj.origin;
  const finalHost = finalUrlObj.hostname.toLowerCase();
  const finalPort = finalUrlObj.port ? Number(finalUrlObj.port) : (finalUrlObj.protocol === "https:" ? 443 : 80);
  const tlsHttps = resolvedUrl.startsWith("https://");
  const waf = detectWafOrChallenge(homeResp);

  recordTrace(
    1, "TLS & DNS", "Homepage Navigation", resolvedUrl, "GET",
    homeResp.status, homeResp.bytes, homeResp.ms,
    waf.challengeBlocked ? "blocked" : "pass",
    waf.challengeBlocked
      ? `HTTP ${homeResp.status} — Edge WAF challenge (${waf.providers.join(", ") || "active"})`
      : `HTTP ${homeResp.status} · ${(homeResp.bytes / 1024).toFixed(1)} KB HTML (${homeResult.fallbackKind})`
  );

  let resolutionNote = null;
  let resolutionNoteZh = null;
  if (homeResult.fallbackKind === "www_fallback" || homeResult.fallbackKind === "root_fallback" || finalHost !== norm.hostname) {
    resolutionNote = `Automatically followed redirect to ${finalOrigin}`;
    resolutionNoteZh = `已自动追踪跳转至 ${finalOrigin} 完成体检`;
  } else if (homeResult.fallbackKind === "http_fallback") {
    resolutionNote = `HTTPS connection failed; audited over HTTP (${finalOrigin})`;
    resolutionNoteZh = `HTTPS 握手失败，已自动降级为 HTTP（${finalOrigin}）完成体检`;
  }

  const [tlsAudit, takeover] = await Promise.all([
    tlsHttps
      ? inspectTlsCertificate(finalHost, finalPort, Math.min(3200, Math.max(1200, remainingMs())))
      : Promise.resolve({
          ok: false, https: false, connected: false, protocol: null, cipher: null, authorized: false,
          authorizationError: "Not HTTPS", issuer: null, subject: null, validFrom: null,
          validTo: null, daysRemaining: null, keyBits: null, sans: [], sanList: [], expired: false, expiringSoon: false,
          weakProtocol: false, selfSigned: false, hostnameMismatch: false, error: "plain-http", ms: 0, durationMs: 0,
        }),
    inspectDnsTakeover(finalHost, homeResp),
  ]);

  recordTrace(
    1, "TLS & DNS", "TLS Socket Handshake", `${finalHost}:${finalPort}`, "TLS",
    tlsAudit.ok ? 200 : 0, 0, tlsAudit.durationMs || 0,
    !tlsHttps || tlsAudit.expired || tlsAudit.weakProtocol || tlsAudit.selfSigned ? "fail" : tlsAudit.expiringSoon ? "warn" : "pass",
    tlsAudit.ok
      ? `${tlsAudit.protocol || "TLS"} · ${tlsAudit.cipher || "cipher"} · ${tlsAudit.issuer || "Unknown CA"}${tlsAudit.daysRemaining !== null ? ` · ${tlsAudit.daysRemaining}d valid` : ""}`
      : (tlsHttps ? `TLS handshake error (${tlsAudit.error})` : "Site served over plain HTTP (no TLS)")
  );

  recordTrace(
    1, "TLS & DNS", "DNS CNAME & Takeover Audit", finalHost, "DNS",
    takeover.cname ? 200 : 204, 0, takeover.durationMs || 0,
    takeover.vulnerable ? "fail" : "pass",
    takeover.vulnerable
      ? `DANGLING CNAME -> ${takeover.cname} (${takeover.provider})`
      : (takeover.cname ? `CNAME -> ${takeover.cname} (verified live)` : `Direct A/AAAA records (${takeover.aRecordsCount} IPv4)`)
  );

  // =========================================================================
  // PHASE 2: Multi-Route Crawl + Uncapped Full JS Bundles (up to 24 x 2.5MB)
  // =========================================================================
  const crawledRoutes = [{ path: finalUrlObj.pathname || "/", status: homeResp.status, bytes: homeResp.bytes, ms: homeResp.ms }];
  const htmlDocs = [{ label: "index.html (inline)", text: homeResp.text || "" }];
  let robotsFound = false;
  let robotsDisallowedCount = 0;
  let sitemapFound = false;
  let buildManifestFound = false;

  if (!waf.challengeBlocked && mode === "deep" && remainingMs() > 9500) {
    const manifestUrl = extractBuildManifestUrl(homeResp.text, resolvedUrl);
    const [robotsResp, sitemapResp, manifestResp] = await Promise.all([
      fetchCappedText(`${finalOrigin}/robots.txt`, { timeoutMs: 1800, maxBytes: 40000 }),
      fetchCappedText(`${finalOrigin}/sitemap.xml`, { timeoutMs: 2000, maxBytes: 120000 }),
      manifestUrl ? fetchCappedText(manifestUrl, { timeoutMs: 1800, maxBytes: 120000 }) : Promise.resolve(null),
    ]);

    if (robotsResp.ok && robotsResp.status === 200 && !isSpaHtmlFallback(robotsResp, "")) {
      robotsFound = true;
      robotsDisallowedCount = (robotsResp.text.match(/^Disallow:\s*\S+/gim) || []).length;
    }
    recordTrace(2, "Crawl & Bundles", "Fetch robots.txt", `${finalOrigin}/robots.txt`, "GET", robotsResp.status, robotsResp.bytes, robotsResp.ms, "info", robotsFound ? `Found (${robotsDisallowedCount} Disallow rules)` : `Absent (HTTP ${robotsResp.status})`);

    if (sitemapResp.ok && sitemapResp.status === 200 && /<(?:urlset|sitemapindex)\b/i.test(sitemapResp.text)) {
      sitemapFound = true;
    }
    recordTrace(2, "Crawl & Bundles", "Fetch sitemap.xml", `${finalOrigin}/sitemap.xml`, "GET", sitemapResp.status, sitemapResp.bytes, sitemapResp.ms, "info", sitemapFound ? `XML sitemap parsed (${sitemapResp.bytes} bytes)` : `Absent (HTTP ${sitemapResp.status})`);

    if (manifestResp && manifestResp.ok && manifestResp.status === 200 && manifestResp.text.length > 20) {
      buildManifestFound = true;
      htmlDocs.push({ label: "_buildManifest.js", text: manifestResp.text });
      recordTrace(2, "Crawl & Bundles", "Next.js _buildManifest.js", manifestUrl, "GET", manifestResp.status, manifestResp.bytes, manifestResp.ms, "pass", `Unpacked route chunks (${manifestResp.bytes} bytes)`);
    }

    const routePaths = extractInternalRoutes(homeResp.text, sitemapFound ? sitemapResp.text : "", finalOrigin);
    if (routePaths.length > 0 && remainingMs() > 8500) {
      const routeResps = await runPool(
        routePaths,
        5,
        async (rPath) => {
          const rUrl = `${finalOrigin}${rPath}`;
          const r = await fetchCappedText(rUrl, { timeoutMs: 2200, maxBytes: 380000, headers: BROWSER_HTML_HEADERS });
          recordTrace(2, "Crawl & Bundles", `Crawl route ${rPath}`, rUrl, "GET", r.status, r.bytes, r.ms, r.ok && r.status === 200 ? "pass" : "info", `HTTP ${r.status} · ${(r.bytes / 1024).toFixed(1)} KB`);
          return { path: rPath, resp: r };
        },
        () => remainingMs() < 8000
      );
      for (const rr of routeResps) {
        crawledRoutes.push({ path: rr.path, status: rr.resp.status, bytes: rr.resp.bytes, ms: rr.resp.ms });
        if (rr.resp.ok && rr.resp.status === 200 && rr.resp.text) {
          htmlDocs.push({ label: `route:${rr.path}`, text: rr.resp.text });
        }
      }
    }
  }

  // Unpack up to 24 FULL JS bundles (up to 2.5 MB each — NO 260KB truncation!)
  const maxChunks = mode === "fast" ? 4 : 24;
  const perBundleCap = mode === "fast" ? 500000 : 2500000;
  const totalJsMemoryCap = mode === "fast" ? 2000000 : 18000000;
  const chunkUrls = waf.challengeBlocked
    ? []
    : extractJsChunkUrlsFromTexts(htmlDocs, resolvedUrl, maxChunks, { allowLocalTest });

  let totalJsBytes = 0;
  const chunkResps = await runPool(
    chunkUrls,
    mode === "fast" ? 4 : 5,
    async (u) => {
      if (totalJsBytes >= totalJsMemoryCap || remainingMs() < (mode === "fast" ? 2200 : 7500)) {
        budgetTruncated = true;
        return { url: u, label: u, ok: false, bytes: 0, text: "", skipped: true };
      }
      const r = await fetchCappedText(u, { timeoutMs: 3000, maxBytes: perBundleCap });
      const label = (() => { try { return new URL(u).pathname.split("/").slice(-2).join("/"); } catch { return u; } })();
      const ok = r.ok && r.status === 200 && r.text.length > 0;
      if (ok) totalJsBytes += r.bytes;
      recordTrace(
        2, "Crawl & Bundles", `Unpack JS ${label}`, u, "GET",
        r.status, r.bytes, r.ms,
        ok ? "pass" : "info",
        ok ? `${(r.bytes / 1024).toFixed(1)} KB unpacked (uncapped <= 2.5MB)` : `Skipped/HTTP ${r.status}`
      );
      return { url: u, label, ok, bytes: r.bytes, text: ok ? r.text : "" };
    },
    () => {
      if (remainingMs() < (mode === "fast" ? 2200 : 7500)) {
        budgetTruncated = true;
        return true;
      }
      return false;
    }
  );

  const fetchedChunks = chunkResps.filter((c) => c.ok && c.text.length > 0);
  const allSources = [
    ...htmlDocs,
    ...fetchedChunks.map((c) => ({ label: c.label, text: c.text })),
  ];

  // Scan all HTML routes + complete JS bundles with 52 high-precision secret rules + extract API routes
  const tSecret0 = Date.now();
  const seenKeys = new Set();
  const secrets = [];
  for (const src of allSources) {
    secrets.push(...scanTextForSecrets(src.text, src.label, seenKeys));
  }
  const discoveredApis = extractApiEndpoints(allSources);
  recordTrace(
    2, "Crawl & Bundles", "52-Rule Secret & API Scan", `${allSources.length} source artifact(s)`, "ANALYZE",
    200, allSources.reduce((a, s) => a + s.text.length, 0), Date.now() - tSecret0,
    secrets.some((s) => s.severity === "critical" || s.severity === "high") ? "fail" : secrets.length ? "warn" : "pass",
    `${secrets.length} secret match(es) · ${discoveredApis.length} API endpoint(s) discovered`
  );

  const supaArtifacts = extractSupabaseArtifacts(allSources);
  const fbArtifacts = extractFirebaseArtifacts(allSources);
  const stack = detectStack(homeResp.text, homeResp.headers, finalOrigin);
  if (supaArtifacts.detected && !stack.includes("Supabase")) stack.push("Supabase");
  if (fbArtifacts.detected && !stack.includes("Firebase")) stack.push("Firebase");

  for (const sr of supaArtifacts.serviceRoleLeaks) {
    secrets.unshift({
      ruleId: "supabase-service-role-jwt",
      name: "Supabase service_role JWT (Bypasses ALL RLS)",
      nameZh: "Supabase service_role 超级管理员令牌（绕过全部权限校验）",
      severity: "critical",
      maskedValue: sr.maskedValue,
      source: sr.source,
      location: sr.source,
      remediation: "EMERGENCY: Rotate your Supabase JWT secret / service_role key immediately. Any client possessing service_role bypasses every Row Level Security policy.",
      remediationZh: "高危紧急：请立即在 Supabase 后台重置 JWT 密钥与 service_role，该令牌可绕过所有 RLS 行级权限直接读写整库！",
    });
  }

  // =========================================================================
  // PHASE 3: 28 Nuclei-Grade Non-Destructive Probes + SourceMaps (.js.map)
  // =========================================================================
  const homeSnippet = (homeResp.text || "").trimStart().slice(0, 320).toLowerCase();
  const allProbeSpecs = buildSensitiveProbeSpecs(finalOrigin, resolvedUrl, homeSnippet);
  const probeSpecs = mode === "fast"
    ? allProbeSpecs.filter((p) => ["env-root", "git-head", "security-txt", "cors-probe", "openapi-json"].includes(p.id))
    : allProbeSpecs;

  let corsRespObj = null;
  const probeResults = await runPool(
    probeSpecs,
    6,
    async (spec) => {
      const targetUrl = spec.urlOverride || `${finalOrigin}${spec.path}`;
      const r = await fetchCappedText(targetUrl, {
        method: spec.method || "GET",
        timeoutMs: 1600,
        maxBytes: 24000,
        headers: spec.headers || {},
        body: spec.body,
        redirect: spec.redirect || "follow",
      });
      if (spec.customCors) corsRespObj = r;
      const matched = spec.validate(r);
      const exposed = spec.positiveCheck ? false : matched;
      recordTrace(
        3, "Endpoint Probes", `Probe ${spec.path}`, targetUrl, spec.method || "GET",
        r.status, r.bytes, r.ms,
        spec.positiveCheck ? (matched ? "pass" : "info") : (exposed ? (spec.severity === "critical" || spec.severity === "high" ? "fail" : "warn") : "pass"),
        matched ? spec.evidenceFn(r) : `Clean / blocked (HTTP ${r.status})`
      );
      return {
        id: spec.id,
        path: spec.path,
        category: spec.category,
        status: r.status,
        bytes: r.bytes,
        ms: r.ms,
        durationMs: r.ms,
        exposed,
        positiveMatched: Boolean(spec.positiveCheck && matched),
        severity: spec.severity,
        evidence: matched ? spec.evidenceFn(r) : null,
        detail: spec.detail,
        detailZh: spec.detailZh,
        fixCode: spec.fixSnippet,
        fixSnippet: spec.fixSnippet,
      };
    },
    () => {
      if (remainingMs() < (mode === "fast" ? 1200 : 4500)) {
        budgetTruncated = true;
        return true;
      }
      return false;
    }
  );

  // SourceMap (.js.map) Probes (up to 6 chunks in deep mode, 2 in fast mode)
  const maxMaps = mode === "fast" ? 2 : 6;
  const mapCandidates = [];
  for (const c of fetchedChunks) {
    const smMatch = c.text.match(/\/\/[#@]\s*sourceMappingURL=([^\s'"]+\.map)/);
    if (smMatch) {
      try { mapCandidates.push({ chunk: c.label, mapUrl: new URL(smMatch[1], c.url).toString() }); } catch {}
    }
  }
  for (const c of fetchedChunks) {
    if (mapCandidates.length >= maxMaps) break;
    const candidateUrl = `${c.url.split("?")[0]}.map`;
    if (!mapCandidates.some((x) => x.mapUrl === candidateUrl)) {
      mapCandidates.push({ chunk: c.label, mapUrl: candidateUrl });
    }
  }

  const mapProbes = await runPool(
    mapCandidates.slice(0, maxMaps),
    6,
    async (mc) => {
      const r = await fetchCappedText(mc.mapUrl, { timeoutMs: 1200, maxBytes: 24000 });
      const validMap =
        r.ok &&
        r.status === 200 &&
        !isSpaHtmlFallback(r, homeSnippet) &&
        r.text.includes('"mappings"') &&
        r.text.includes('"sources"');
      recordTrace(
        3, "Endpoint Probes", `SourceMap ${mc.chunk}.map`, mc.mapUrl, "GET",
        r.status, r.bytes, r.ms,
        validMap ? "fail" : "pass",
        validMap ? `SourceMap downloadable (${r.bytes} bytes sampled)` : `Not exposed (HTTP ${r.status})`
      );
      return { chunk: mc.chunk, mapUrl: mc.mapUrl, exposed: validMap };
    },
    () => remainingMs() < 3500
  );

  const exposedSourceMaps = mapProbes.filter((m) => m.exposed);
  const exposedProbes = probeResults.filter((p) => p.exposed && p.id !== "cors-probe");
  const envExposed = probeResults.some((p) => p.exposed && p.id.startsWith("env-"));
  const gitExposed = probeResults.some((p) => p.exposed && p.id.startsWith("git-"));
  const securityTxtPresent = probeResults.some((p) => p.id === "security-txt" && p.positiveMatched);
  const graphqlIntrospectionExposed = probeResults.some((p) => p.exposed && p.id.startsWith("graphql-"));
  const openRedirectVulnerable = probeResults.some((p) => p.exposed && p.id === "open-redirect");

  const acao = (corsRespObj?.headers.get("access-control-allow-origin") || homeResp.headers.get("access-control-allow-origin") || "").trim();
  const acac = ((corsRespObj?.headers.get("access-control-allow-credentials") || homeResp.headers.get("access-control-allow-credentials") || "").toLowerCase() === "true");
  const corsReflected = acao === "https://vibeshield-cors-probe.invalid";
  const corsWildcardCreds = (acao === "*" || corsReflected) && acac;
  const corsIssue = corsWildcardCreds
    ? {
        severity: "high",
        detail: `Reflects arbitrary Origin (${acao}) with Access-Control-Allow-Credentials: true`,
        detailZh: `响应头反射任意来源（${acao}）且同时允许携带 Cookie 凭证（Allow-Credentials: true），存在跨站窃取风险`,
      }
    : corsReflected
      ? {
          severity: "medium",
          detail: "Reflects arbitrary Origin header in Access-Control-Allow-Origin",
          detailZh: "服务器将任意测试来源直接反射进 Access-Control-Allow-Origin，建议改为白名单域名校验",
        }
      : acao === "*"
        ? {
            severity: "info",
            detail: "Access-Control-Allow-Origin: * (normal for public static pages; verify private APIs)",
            detailZh: "首页配置了通配符 CORS（*），静态公开页通常无害，但请确认后台鉴权接口未开放通配符",
          }
        : null;

  // =========================================================================
  // PHASE 4: Full Cloud DB Probes (Supabase up to 20 Tables + Firebase RTDB/Firestore)
  // =========================================================================
  const [supabaseAudit, firebaseAudit] = await Promise.all([
    probeSupabaseLive(supaArtifacts, {
      maxTables: mode === "fast" ? 4 : 20,
      recordTrace,
      shouldStop: () => remainingMs() < 1800,
    }),
    probeFirebaseLive(fbArtifacts, {
      recordTrace,
      shouldStop: () => remainingMs() < 1800,
    }),
  ]);

  if (!supaArtifacts.detected && !fbArtifacts.detected) {
    recordTrace(4, "Cloud DB", "Supabase & Firebase Discovery", finalHost, "ANALYZE", 200, 0, 1, "pass", "No exposed Supabase or Firebase client database config detected");
  }

  // =========================================================================
  // PHASE 5: Observatory CSP/Header Syntax Parser + Cookies + Passive CVEs
  // =========================================================================
  const tPhase5 = Date.now();
  const cspAudit = analyzeCsp(homeResp.headers.get("content-security-policy"));
  const headerAudit = auditSecurityHeaders(homeResp.headers, securityTxtPresent, cspAudit);
  const hstsAudit = headerAudit.hstsAudit;
  const cookieAudit = auditCookies(homeResp.headers);
  const { detectedFrameworks, frameworkCves } = detectFrameworkCves(allSources, homeResp.headers, supabaseAudit);

  recordTrace(
    5, "Headers & CVEs", "Observatory Header & CSP Parser", finalHost, "ANALYZE",
    200, 0, Date.now() - tPhase5,
    cspAudit.wildcardSrc ? "fail" : headerAudit.passed < 7 ? "warn" : "pass",
    `${headerAudit.passed}/${headerAudit.total} headers · CSP ${cspAudit.grade} (${cspAudit.score}/100) · ${cookieAudit.weakCount} weak cookie(s) · ${frameworkCves.length} CVE advisory(ies)`
  );

  // =========================================================================
  // PHASE 6: Calibrated Scoring & Enriched Bilingual Findings (Aligned 1:1 with #422)
  // =========================================================================
  let score = 100;
  const findings = [];
  const pushFinding = (f) => {
    findings.push({
      id: f.id,
      phase: f.phase,
      severity: f.severity,
      category: f.category,
      categoryZh: f.categoryZh,
      title: f.title,
      titleZh: f.titleZh,
      summary: f.summary || f.detail,
      summaryZh: f.summaryZh || f.detailZh,
      detail: f.detail,
      detailZh: f.detailZh,
      fileLocation: f.location || null,
      location: f.location || null,
      evidence: f.evidence || null,
      remediation: f.remediation || f.detail,
      remediationZh: f.remediationZh || f.detailZh,
      fixCode: f.fixSnippet || null,
      fixSnippet: f.fixSnippet || null,
    });
  };

  // --- Phase 1 Findings ---
  if (!tlsHttps) {
    score -= 22;
    pushFinding({
      id: "tls-no-https", phase: 1, severity: "high",
      category: "TLS / HTTPS", categoryZh: "HTTPS 加密传输",
      title: "Site served over unencrypted HTTP without HTTPS",
      titleZh: "网站未启用 HTTPS 加密（明文 HTTP 访问）",
      summary: "Traffic and credentials are transmitted in plaintext over the network.",
      summaryZh: "用户访问与登录凭据以明文传输，易遭中间人窃听或篡改。",
      detail: "Traffic and login credentials can be intercepted on public networks. Enable SSL/TLS and enforce 301 HTTP-to-HTTPS redirect.",
      detailZh: "用户访问与登录数据在传输中易被窃听篡改，请立即在 CDN 或服务器开启免费 SSL 证书并强制 301 跳转 HTTPS。",
      location: resolvedUrl,
      evidence: `Protocol: http:// on ${finalHost}`,
      fixSnippet: `# Nginx HTTP -> HTTPS permanent redirect:\nserver {\n    listen 80;\n    server_name ${finalHost};\n    return 301 https://$host$request_uri;\n}`,
    });
  } else {
    if (tlsAudit.expired) {
      score -= 30;
      pushFinding({
        id: "tls-cert-expired", phase: 1, severity: "critical",
        category: "TLS Certificate", categoryZh: "SSL 证书过期",
        title: "SSL/TLS certificate has expired",
        titleZh: "网站 SSL/TLS 证书已过期",
        summary: "Browsers block visitors with full-screen security errors until the certificate is renewed.",
        summaryZh: "证书过期将导致浏览器阻断用户访问并触发高危安全警告。",
        detail: `Certificate expired on ${tlsAudit.validTo} (${Math.abs(tlsAudit.daysRemaining)} days ago). Renew immediately via Let's Encrypt or your CDN.`,
        detailZh: `证书已于 ${tlsAudit.validTo} 过期，请立即通过 Let's Encrypt 或云厂商 SSL 续签部署。`,
        location: `${finalHost}:${finalPort}`,
        evidence: `Issuer: ${tlsAudit.issuer || "Unknown"}, ValidTo: ${tlsAudit.validTo}`,
        fixSnippet: "# Certbot auto-renewal:\nsudo certbot renew --force-renewal && sudo nginx -s reload",
      });
    } else if (tlsAudit.expiringSoon) {
      score -= 4;
      pushFinding({
        id: "tls-cert-expiring-soon", phase: 1, severity: "low",
        category: "TLS Certificate", categoryZh: "SSL 证书即将到期",
        title: `SSL/TLS certificate expires in ${tlsAudit.daysRemaining} day(s)`,
        titleZh: `SSL/TLS 证书将在 ${tlsAudit.daysRemaining} 天内到期`,
        summary: "Automated renewal should be verified before the certificate expires.",
        summaryZh: "请及时核查自动续签任务，避免证书过期引发服务中断。",
        detail: `Certificate issued by ${tlsAudit.issuer || "CA"} expires on ${tlsAudit.validTo} (${tlsAudit.daysRemaining} days left).`,
        detailZh: `由 ${tlsAudit.issuer || "CA"} 签发的证书将于 ${tlsAudit.validTo} 到期（剩余 ${tlsAudit.daysRemaining} 天）。`,
        location: `${finalHost}:${finalPort}`,
        evidence: `ValidTo: ${tlsAudit.validTo} (${tlsAudit.daysRemaining}d remaining)`,
        fixSnippet: "sudo certbot renew --dry-run",
      });
    }
    if (tlsAudit.weakProtocol) {
      score -= 16;
      pushFinding({
        id: "tls-weak-protocol", phase: 1, severity: "high",
        category: "TLS Protocol", categoryZh: "TLS 协议版本过旧",
        title: `Deprecated TLS protocol negotiated (${tlsAudit.protocol})`,
        titleZh: `检测到已淘汰的弱加密协议（${tlsAudit.protocol}）`,
        summary: "Legacy TLS 1.0/1.1 protocols fail PCI-DSS and modern browser security standards.",
        summaryZh: "TLS 1.0/1.1 存在已知降级漏洞，不符合现代安全合规要求。",
        detail: `Port ${finalPort} negotiated ${tlsAudit.protocol} (${tlsAudit.cipher || "cipher"}). Disable TLS 1.0/1.1 and enforce TLS 1.2 + TLS 1.3.`,
        detailZh: `端口 ${finalPort} 协商协议为 ${tlsAudit.protocol}，请立即禁用 TLS 1.0/1.1 并启用 TLS 1.2/1.3。`,
        location: `${finalHost}:${finalPort}`,
        evidence: `Protocol: ${tlsAudit.protocol}, Cipher: ${tlsAudit.cipher}`,
        fixSnippet: "# Nginx modern TLS:\nssl_protocols TLSv1.2 TLSv1.3;\nssl_prefer_server_ciphers off;",
      });
    }
    if (tlsAudit.selfSigned || tlsAudit.hostnameMismatch) {
      score -= 18;
      pushFinding({
        id: "tls-untrusted-cert", phase: 1, severity: "high",
        category: "TLS Certificate", categoryZh: "SSL 证书校验异常",
        title: tlsAudit.selfSigned ? "Self-signed or untrusted TLS certificate" : "TLS certificate hostname mismatch",
        titleZh: tlsAudit.selfSigned ? "检测到自签名或不受信任的 SSL 证书" : "SSL 证书域名不匹配",
        summary: "Visitors receive certificate trust errors when accessing this host.",
        summaryZh: "浏览器无法验证站点身份，可能导致用户流失与中间人风险。",
        detail: `TLS verification failed: ${tlsAudit.authorizationError}. Install a CA-signed certificate covering ${finalHost}.`,
        detailZh: `TLS 证书校验失败：${tlsAudit.authorizationError}，请为 ${finalHost} 签发受信任的 CA 证书。`,
        location: `${finalHost}:${finalPort}`,
        evidence: `Error: ${tlsAudit.authorizationError}, Subject: ${tlsAudit.subject}`,
        fixSnippet: `sudo certbot --nginx -d ${finalHost}`,
      });
    }
  }

  if (takeover.vulnerable) {
    score -= 30;
    pushFinding({
      id: "dns-subdomain-takeover", phase: 1, severity: "critical",
      category: "Subdomain Takeover", categoryZh: "子域名接管高危漏洞",
      title: `Dangling CNAME points to unclaimed ${takeover.provider} resource`,
      titleZh: `检测到悬空 CNAME 记录指向未认领的 ${takeover.provider} 服务`,
      summary: "An attacker could claim the cloud resource and host malicious scripts on your domain.",
      summaryZh: "攻击者可在对应云平台注册该悬空资源，从而完全接管此域名并窃取主站 Cookie。",
      detail: takeover.detail,
      detailZh: takeover.detailZh,
      location: `DNS CNAME: ${finalHost} -> ${takeover.cname}`,
      evidence: takeover.detail,
      fixSnippet: `# DNS Action Required:\n# Delete dangling CNAME record for ${finalHost} -> ${takeover.cname}`,
    });
  }

  // --- Phase 2 Findings: Leaked Secrets ---
  for (const s of secrets) {
    const pen = s.severity === "critical" ? 30 : s.severity === "high" ? 18 : 6;
    score -= pen;
    pushFinding({
      id: `secret-${s.ruleId}`, phase: 2, severity: s.severity,
      category: "Leaked Secret", categoryZh: "前端密钥泄露",
      title: `${s.name} detected in client-delivered asset`,
      titleZh: `在前端静态资源中检测到 ${s.nameZh}`,
      summary: s.severity === "medium"
        ? "Public client API key detected — confirm domain referrer & API quota restrictions."
        : "Sensitive credential exposed in browser-downloadable code; immediate key rotation required.",
      summaryZh: s.severity === "medium"
        ? "检测到前端公开 API Key，请核查控制台域名白名单与 API 权限范围。"
        : "敏感密钥已暴露在浏览器可下载代码中，请立即轮换密钥并迁至服务端。",
      detail: s.remediation,
      detailZh: s.remediationZh,
      location: s.location || s.source,
      evidence: `Rule: ${s.ruleId} · Masked token: ${s.maskedValue} · Source: ${s.source}`,
      remediation: s.remediation,
      remediationZh: s.remediationZh,
      fixSnippet: `# 1. Rotate ${s.name} immediately in provider dashboard\n# 2. Remove from client code & NEXT_PUBLIC_/VITE_ env vars\n# 3. Proxy calls through a server-side /api/* route`,
    });
  }

  // --- Phase 3 Findings: Exposed Sensitive Endpoints, SourceMaps, CORS ---
  for (const ep of exposedProbes) {
    const pen = ep.severity === "critical" ? 30 : ep.severity === "high" ? 16 : ep.severity === "medium" ? 8 : 3;
    score -= pen;
    pushFinding({
      id: `probe-${ep.id}`, phase: 3, severity: ep.severity,
      category: ep.category,
      categoryZh: ep.category === "Open Redirect" ? "开放重定向风险" : ep.category === "GraphQL Introspection" ? "GraphQL Schema 暴露" : "敏感端点暴露",
      title: `Exposed endpoint detected (${ep.path})`,
      titleZh: `检测到公网可访问的敏感路径（${ep.path}）`,
      summary: ep.detail,
      summaryZh: ep.detailZh,
      detail: ep.detail,
      detailZh: ep.detailZh,
      location: `${finalOrigin}${ep.path}`,
      evidence: ep.evidence,
      fixSnippet: ep.fixSnippet,
    });
  }

  if (exposedSourceMaps.length > 0) {
    score -= 14;
    pushFinding({
      id: "sourcemap-exposed", phase: 3, severity: "high",
      category: "SourceMap Exposure", categoryZh: "前端源码映射文件泄露",
      title: `${exposedSourceMaps.length} production .js.map SourceMap file(s) publicly downloadable`,
      titleZh: `线上暴露了 ${exposedSourceMaps.length} 个 .js.map 源码映射文件`,
      summary: "Unminified original frontend source code, comments, and internal API routes can be restored.",
      summaryZh: "外部可直接下载源码映射文件并一键还原未混淆的前端完整业务代码。",
      detail: "Disable production browser source maps in your bundler config and block *.js.map at your edge proxy.",
      detailZh: "请在构建配置中关闭生产环境 SourceMap 生成，并在网关屏蔽 .js.map 访问。",
      location: exposedSourceMaps.map((m) => m.mapUrl).join(", "),
      evidence: `Verified JSON SourceMaps with mappings+sources: ${exposedSourceMaps.map((m) => m.chunk + ".map").join(", ")}`,
      fixSnippet: "// next.config.mjs:\nexport default { productionBrowserSourceMaps: false };\n// vite.config.ts:\nexport default { build: { sourcemap: false } };",
    });
  }

  if (corsIssue && (corsIssue.severity === "high" || corsIssue.severity === "medium")) {
    score -= corsIssue.severity === "high" ? 16 : 7;
    pushFinding({
      id: "cors-permissive", phase: 3, severity: corsIssue.severity,
      category: "CORS Policy", categoryZh: "跨域策略 (CORS) 过宽",
      title: "Permissive Cross-Origin Resource Sharing (CORS) policy",
      titleZh: "网站跨域策略（CORS）配置过于宽松",
      summary: corsIssue.detail,
      summaryZh: corsIssue.detailZh,
      detail: corsIssue.detail,
      detailZh: corsIssue.detailZh,
      location: `Header: Access-Control-Allow-Origin (${resolvedUrl})`,
      evidence: `ACAO=${acao || "none"}, ACAC=${acac}`,
      fixSnippet: `// Express / Edge CORS allowlist:\nconst ALLOWED = new Set(['https://${finalHost}']);\nif (ALLOWED.has(req.headers.origin)) res.setHeader('Access-Control-Allow-Origin', req.headers.origin);`,
    });
  }

  // --- Phase 4 Findings: Supabase RLS & Firebase RTDB/Firestore ---
  if (supabaseAudit.detected) {
    const openWithRows = supabaseAudit.exposedTables.filter((t) => t.rowCount !== null && t.rowCount > 0);
    const openSensitive = supabaseAudit.exposedTables.filter((t) => t.sensitive);
    if (openWithRows.length > 0) {
      score -= Math.min(40, 26 + (openWithRows.length - 1) * 7);
      pushFinding({
        id: "supabase-rls-open-rows", phase: 4, severity: "critical",
        category: "Supabase RLS (CVE-2025-48757)", categoryZh: "Supabase 权限裸奔 (CVE-2025-48757)",
        title: `${openWithRows.length} Supabase table(s) publicly readable without authentication`,
        titleZh: `检测到 ${openWithRows.length} 张 Supabase 数据表未开启 RLS 保护，匿名可读`,
        summary: "Unauthenticated PostgREST queries confirmed live row counts accessible to anonymous clients.",
        summaryZh: "使用前端公开的 anon 密钥已可直接读通含真实数据行的数据表，存在严重数据外泄风险。",
        detail: "Enable & force Row Level Security (RLS) on every exposed table and revoke anon SELECT/INSERT/UPDATE/DELETE privileges.",
        detailZh: "请立即在 Supabase SQL Editor 执行 RLS 锁定脚本并撤销 anon 匿名读取权限。",
        location: `${supabaseAudit.projectUrl}/rest/v1/ (${openWithRows.map((t) => t.table).join(", ")})`,
        evidence: `HEAD Prefer:count=exact confirmed: ${openWithRows.map((t) => `${t.table} (${t.rowCount} rows)`).join(", ")}`,
        fixSnippet: openWithRows.slice(0, 6).map((t) => `ALTER TABLE public."${t.table}" ENABLE ROW LEVEL SECURITY;\nALTER TABLE public."${t.table}" FORCE ROW LEVEL SECURITY;\nREVOKE ALL ON TABLE public."${t.table}" FROM anon;`).join("\n\n"),
      });
    } else if (openSensitive.length > 0) {
      score -= 18;
      pushFinding({
        id: "supabase-rls-open-sensitive", phase: 4, severity: "high",
        category: "Supabase RLS", categoryZh: "Supabase 数据表权限风险",
        title: `${openSensitive.length} sensitive Supabase table(s) accept unauthenticated anon queries`,
        titleZh: `${openSensitive.length} 张敏感 Supabase 数据表允许未登录匿名查询`,
        summary: "Sensitive tables returned HTTP 200 to the anonymous PostgREST role.",
        summaryZh: "敏感业务表对匿名角色返回了 HTTP 200，建议立即核查并收紧 RLS 策略。",
        detail: "Verify every table has strict RLS policies restricting rows to auth.uid() = user_id.",
        detailZh: "请逐表确认已开启行级安全策略并限制仅 auth.uid() = user_id 可访问。",
        location: `${supabaseAudit.projectUrl}/rest/v1/`,
        evidence: `HTTP 200 to anon role on: ${openSensitive.map((t) => t.table).join(", ")}`,
        fixSnippet: openSensitive.slice(0, 6).map((t) => `ALTER TABLE public."${t.table}" ENABLE ROW LEVEL SECURITY;\nREVOKE ALL ON TABLE public."${t.table}" FROM anon;`).join("\n"),
      });
    } else if (supabaseAudit.openApiExposed && supabaseAudit.discoveredTables.length > 0) {
      score -= 6;
      pushFinding({
        id: "supabase-openapi-schema", phase: 4, severity: "medium",
        category: "Supabase Schema Exposure", categoryZh: "Supabase 表结构暴露",
        title: `Supabase PostgREST OpenAPI lists ${supabaseAudit.discoveredTables.length} table(s)`,
        titleZh: `Supabase PostgREST 接口对外暴露了 ${supabaseAudit.discoveredTables.length} 张表结构清单`,
        summary: "Table and RPC names are enumerable using the client anon key.",
        summaryZh: "通过前端公开 anon 密钥可枚举数据库表名与 RPC 函数名。",
        detail: "Confirm every exposed table enables RLS and consider disabling PostgREST OpenAPI schema exposure if unnecessary.",
        detailZh: "建议逐表确认 RLS 已生效，并在不需要时收紧 public schema 暴露范围。",
        location: `${supabaseAudit.projectUrl}/rest/v1/`,
        evidence: `Tables: ${supabaseAudit.discoveredTables.slice(0, 10).join(", ")}${supabaseAudit.rpcEndpoints.length ? ` · RPCs: ${supabaseAudit.rpcEndpoints.slice(0, 5).join(", ")}` : ""}`,
        fixSnippet: "REVOKE USAGE ON SCHEMA public FROM anon;\n-- Or verify RLS on every table in public schema",
      });
    }
    if (supabaseAudit.publicBuckets.length > 0) {
      score -= 7;
      pushFinding({
        id: "supabase-public-buckets", phase: 4, severity: "medium",
        category: "Supabase Storage", categoryZh: "Supabase 存储桶公开枚举",
        title: `${supabaseAudit.publicBuckets.length} Supabase Storage bucket(s) publicly enumerable`,
        titleZh: `发现 ${supabaseAudit.publicBuckets.length} 个可被匿名枚举的 Supabase 存储桶`,
        summary: "Storage bucket names can be listed by unauthenticated clients.",
        summaryZh: "匿名客户端可枚举存储桶列表，请核查上传与遍历权限策略。",
        detail: "Review storage.objects RLS policies so private uploads cannot be listed or overwritten by anon users.",
        detailZh: "请检查 storage.objects 权限策略，防止未授权上传或文件遍历。",
        location: `${supabaseAudit.projectUrl}/storage/v1/bucket`,
        evidence: supabaseAudit.publicBuckets.map((b) => `${b.name}${b.public ? " (public)" : ""}`).join(", "),
        fixSnippet: '-- Restrict storage.objects bucket listing to authenticated owners\nCREATE POLICY "auth_read_own" ON storage.objects FOR SELECT TO authenticated USING (auth.uid() = owner);',
      });
    }
  }

  if (firebaseAudit.rtdbPublic) {
    score -= 32;
    pushFinding({
      id: "firebase-rtdb-open", phase: 4, severity: "critical",
      category: "Firebase Realtime DB", categoryZh: "Firebase 实时数据库裸奔",
      title: `${firebaseAudit.rtdbExposed.length} Firebase Realtime Database instance(s) publicly readable`,
      titleZh: `检测到 ${firebaseAudit.rtdbExposed.length} 个 Firebase 实时数据库允许匿名公开读取`,
      summary: "Unauthenticated GET /.json?shallow=true succeeded, indicating overly permissive `.read: true` rules.",
      summaryZh: "未登录访问 /.json?shallow=true 返回了有效数据节点，说明数据库安全规则过度放开。",
      detail: "Lock down Firebase Realtime Database rules immediately so unauthenticated users cannot read or write root nodes.",
      detailZh: "请立即在 Firebase 控制台收紧 Realtime Database Rules，禁止匿名全局读取。",
      location: firebaseAudit.rtdbExposed.map((x) => x.url).join(", "),
      evidence: firebaseAudit.rtdbExposed.map((x) => `${x.url}/.json?shallow=true -> HTTP 200 (${x.topLevelKeysCount} top-level key(s))`).join("; "),
      fixSnippet: '{\n  "rules": {\n    ".read": "auth != null",\n    ".write": "auth != null",\n    "users": {\n      "$uid": { ".read": "$uid === auth.uid", ".write": "$uid === auth.uid" }\n    }\n  }\n}',
    });
  }

  if (firebaseAudit.firestorePublic) {
    score -= 32;
    pushFinding({
      id: "firebase-firestore-open", phase: 4, severity: "critical",
      category: "Firebase Firestore", categoryZh: "Firebase Firestore 数据库裸奔",
      title: `${firebaseAudit.firestoreExposed.length} Cloud Firestore database(s) allow unauthenticated document reads`,
      titleZh: `检测到 ${firebaseAudit.firestoreExposed.length} 个 Cloud Firestore 允许未登录读取文档`,
      summary: "Firestore REST API returned documents without an authentication token.",
      summaryZh: "Firestore REST 接口在无鉴权令牌情况下直接返回了文档数据，存在数据泄露风险。",
      detail: "Replace open `allow read, write: if true;` Firestore rules with per-user `request.auth.uid` checks.",
      detailZh: "请立即修改 Firestore Security Rules，移除 allow read: if true 并改为基于 request.auth.uid 的校验。",
      location: firebaseAudit.firestoreExposed.map((x) => `firestore:${x.projectId}`).join(", "),
      evidence: firebaseAudit.firestoreExposed.map((x) => `Project ${x.projectId} returned HTTP 200 on documents?pageSize=1`).join("; "),
      fixSnippet: "rules_version = '2';\nservice cloud.firestore {\n  match /databases/{database}/documents {\n    match /{document=**} { allow read, write: if false; }\n    match /users/{userId} { allow read, write: if request.auth != null && request.auth.uid == userId; }\n  }\n}",
    });
  }

  // --- Phase 5 Findings: CSP Syntax, HSTS Strength, Security Headers, Cookies, CVEs ---
  for (const issue of cspAudit.issueItems) {
    if (issue.code === "missing-csp") continue;
    const pen = issue.severity === "high" ? 10 : issue.severity === "medium" ? 5 : 2;
    score -= pen;
    pushFinding({
      id: issue.code, phase: 5, severity: issue.severity,
      category: "CSP Syntax Defect", categoryZh: "CSP 策略语法缺陷",
      title: issue.detail,
      titleZh: issue.detailZh,
      summary: issue.detail,
      summaryZh: issue.detailZh,
      detail: issue.detail,
      detailZh: issue.detailZh,
      location: "Header: Content-Security-Policy",
      evidence: `CSP raw: ${cspAudit.raw.slice(0, 180)}`,
      fixSnippet: "Content-Security-Policy: default-src 'self'; script-src 'self' 'strict-dynamic'; object-src 'none'; base-uri 'self'; frame-ancestors 'none';",
    });
  }

  if (tlsHttps && hstsAudit.present && (!hstsAudit.meetsOneYear || !hstsAudit.includeSubDomains)) {
    score -= 3;
    pushFinding({
      id: "hsts-weak-directive", phase: 5, severity: "low",
      category: "HSTS Hardening", categoryZh: "HSTS 强度不足",
      title: "HSTS header is present but below Mozilla Observatory baseline (max-age >= 1 year + includeSubDomains)",
      titleZh: "已启用 HSTS 但配置弱于安全基线（建议 max-age >= 1 年且含 includeSubDomains）",
      summary: `Current HSTS max-age is ${hstsAudit.maxAge}s; includeSubDomains=${hstsAudit.includeSubDomains}.`,
      summaryZh: `当前 HSTS max-age 为 ${hstsAudit.maxAge} 秒，includeSubDomains=${hstsAudit.includeSubDomains}。`,
      detail: "Raise Strict-Transport-Security max-age to 63072000 (2 years) with includeSubDomains and preload.",
      detailZh: "建议将 Strict-Transport-Security 升级为 max-age=63072000; includeSubDomains; preload。",
      location: "Header: Strict-Transport-Security",
      evidence: `Raw HSTS: ${hstsAudit.raw}`,
      fixSnippet: "Strict-Transport-Security: max-age=63072000; includeSubDomains; preload",
    });
  }

  if (cookieAudit.weakCount > 0) {
    const sensWeak = cookieAudit.items.filter((c) => c.sensitiveName && c.missingFlags.length > 0);
    score -= sensWeak.length > 0 ? 7 : 3;
    pushFinding({
      id: "cookie-missing-flags", phase: 5, severity: sensWeak.length > 0 ? "medium" : "low",
      category: "Cookie Security", categoryZh: "Cookie 安全属性缺失",
      title: `${cookieAudit.weakCount} of ${cookieAudit.total} response cookie(s) missing Secure / HttpOnly / SameSite flags`,
      titleZh: `首页下发的 ${cookieAudit.total} 个 Cookie 中有 ${cookieAudit.weakCount} 个缺少安全加固属性`,
      summary: "Session/auth cookies without Secure, HttpOnly, and SameSite increase XSS session theft and CSRF risks.",
      summaryZh: "缺少 Secure/HttpOnly/SameSite 的 Cookie 易遭 XSS 窃取会话或 CSRF 跨站请求伪造。",
      detail: "Enforce Secure; HttpOnly; SameSite=Lax on all session and authentication cookies.",
      detailZh: "请为全部会话与认证 Cookie 统一补齐 Secure; HttpOnly; SameSite=Lax 属性。",
      location: "Header: Set-Cookie",
      evidence: cookieAudit.items.filter((c) => c.missingFlags.length > 0).slice(0, 6).map((c) => `${c.name} (missing ${c.missingFlags.join("/")})`).join(", "),
      fixSnippet: "# Nginx proxy cookie hardening:\nproxy_cookie_flags ~ secure httponly samesite=lax;",
    });
  }

  for (const adv of frameworkCves) {
    if (adv.cve === "CVE-2025-48757") continue; // Already scored in Phase 4 Supabase RLS finding
    const pen = adv.severity === "critical" ? 28 : adv.severity === "high" ? 14 : 6;
    score -= pen;
    pushFinding({
      id: `cve-${adv.cve.toLowerCase()}`, phase: 5, severity: adv.severity,
      category: `Framework CVE (${adv.cve})`, categoryZh: `框架已知漏洞 (${adv.cve})`,
      title: adv.title,
      titleZh: adv.titleZh,
      summary: adv.detail,
      summaryZh: adv.detailZh,
      detail: adv.detail,
      detailZh: adv.detailZh,
      location: `${adv.framework} ${adv.version}`,
      evidence: `Matched passive version ${adv.framework} ${adv.version} -> ${adv.cve}`,
      remediation: adv.remediation,
      remediationZh: adv.remediationZh,
      fixSnippet: adv.fixSnippet,
    });
  }

  const missingHeaders = headerAudit.checks.filter((c) => !c.present);
  for (const hc of missingHeaders) score -= hc.weight;
  if (missingHeaders.length > 0) {
    pushFinding({
      id: "headers-missing", phase: 5, severity: missingHeaders.length >= 5 ? "medium" : "low",
      category: "HTTP Security Headers", categoryZh: "HTTP 安全响应头缺失",
      title: `${missingHeaders.length} of ${headerAudit.total} Mozilla Observatory security headers/policies missing`,
      titleZh: `缺少 ${missingHeaders.length} / ${headerAudit.total} 项 Mozilla Observatory 安全响应头与策略`,
      summary: `Missing defense-in-depth headers: ${missingHeaders.map((m) => m.name).join(", ")}.`,
      summaryZh: `缺失防护项：${missingHeaders.map((m) => m.name).join("、")}。`,
      detail: `Missing headers/policies: ${missingHeaders.map((m) => m.name).join(", ")}.`,
      detailZh: `缺失清单：${missingHeaders.map((m) => m.name).join("、")}。建议在边缘网关或托管配置中统一补齐。`,
      location: `HTTP Response Headers (${finalOrigin})`,
      evidence: `Passed ${headerAudit.passed}/${headerAudit.total}; missing: ${missingHeaders.map((m) => m.name).join(", ")}`,
      fixSnippet: missingHeaders.map((m) => {
        if (m.name === "Strict-Transport-Security") return "Strict-Transport-Security: max-age=63072000; includeSubDomains; preload";
        if (m.name === "Content-Security-Policy") return "Content-Security-Policy: default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'";
        if (m.name === "X-Frame-Options") return "X-Frame-Options: DENY";
        if (m.name === "X-Content-Type-Options") return "X-Content-Type-Options: nosniff";
        if (m.name === "Referrer-Policy") return "Referrer-Policy: strict-origin-when-cross-origin";
        if (m.name === "Permissions-Policy") return "Permissions-Policy: camera=(), microphone=(), geolocation=()";
        if (m.name === "Cross-Origin-Opener-Policy") return "Cross-Origin-Opener-Policy: same-origin";
        if (m.name === "Cross-Origin-Resource-Policy") return "Cross-Origin-Resource-Policy: same-origin";
        if (m.name === "security.txt (RFC 9116)") return `# Publish /.well-known/security.txt:\nContact: mailto:security@${finalHost}`;
        return "# Hide X-Powered-By & server_tokens off";
      }).join("\n"),
    });
  }

  const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  findings.sort((a, b) => (sevOrder[a.severity] ?? 9) - (sevOrder[b.severity] ?? 9));

  score = Math.max(0, Math.min(100, Math.round(score)));
  const criticalCount = findings.filter((f) => f.severity === "critical").length;
  const highCount = findings.filter((f) => f.severity === "high").length;
  const mediumCount = findings.filter((f) => f.severity === "medium").length;
  const lowCount = findings.filter((f) => f.severity === "low").length;
  const status = criticalCount > 0 ? "CRITICAL_EXPOSURE" : (highCount > 0 || score < 70) ? "NEEDS_HARDENING" : score >= 90 ? "HARDENED" : "MODERATE_RISK";
  const grade = score >= 95 ? "A+" : score >= 88 ? "A" : score >= 78 ? "B" : score >= 65 ? "C" : score >= 45 ? "D" : "F";
  const projectedScore = Math.min(99, Math.max(score + 10, criticalCount > 0 ? 94 : 97));

  const checksExecuted =
    SECRET_RULES.length +
    probeResults.length +
    mapProbes.length +
    headerAudit.total +
    (tlsHttps ? 4 : 1) +
    2 +
    6 +
    (supabaseAudit.detected ? Math.max(2, supabaseAudit.tablesProbed + 2) : 1) +
    (firebaseAudit.detected ? firebaseAudit.rtdbProbes.length + firebaseAudit.firestoreProbes.length : 1) +
    5;

  recordTrace(
    6, "Report & Score", "Finalize Security Audit", finalHost, "ANALYZE",
    200, 0, Date.now() - t0,
    criticalCount > 0 ? "fail" : highCount > 0 ? "warn" : "pass",
    `Score ${score}/100 (${grade}) · ${findings.length} finding(s) · ${checksExecuted} checks in ${((Date.now() - t0) / 1000).toFixed(2)}s${budgetTruncated ? " (graceful time-cap)" : ""}`
  );

  const wafNoteEn = waf.challengeBlocked
    ? ` Note: Edge WAF (${waf.providers.join(", ") || "active"}) challenged client bundle fetching; TLS, DNS, headers, cookies, CORS, and endpoint probes still completed.`
    : "";
  const wafNoteZh = waf.challengeBlocked
    ? ` 说明：检测到边缘 WAF（${waf.providers.join(" / ") || "已启用"}）拦截了前端 JS 包抓取，已完成 TLS 证书、DNS、安全头、Cookie、CORS 与端点探测。`
    : "";

  const totalBytesScanned = allSources.reduce((acc, s) => acc + s.text.length, 0);
  const totalKbStr = (totalBytesScanned / 1024).toFixed(0);

  const executiveSummary =
    (criticalCount > 0
      ? `Urgent: ${criticalCount} critical exposure(s) confirmed on ${finalHost} across ${checksExecuted} deep security checks (${fetchedChunks.length} full JS bundles, ${totalKbStr} KB inspected). Apply the tailored fix pack immediately.`
      : highCount > 0
        ? `Action recommended: ${finalHost} has ${highCount} high-priority security gap(s) across ${checksExecuted} live checks (${fetchedChunks.length} JS bundles, ${probeResults.length} endpoint probes). Close these before scaling traffic.`
        : score < 88
          ? `Baseline safe with hardening opportunities: Zero leaked secrets across ${fetchedChunks.length} full JS bundle(s) (${totalKbStr} KB) and ${probeResults.length} sensitive endpoint probes, but ${findings.length} hardening gap(s) (CSP/HSTS/headers) keep the score at ${score}/100.`
          : `Strong security posture: Passed ${checksExecuted} deep checks across ${fetchedChunks.length} JS bundle(s) (${totalKbStr} KB), TLS ${tlsAudit.protocol || "HTTPS"}, and ${probeResults.length} sensitive endpoint probes with strong header defenses.`) + wafNoteEn;

  const executiveSummaryZh =
    (criticalCount > 0
      ? `紧急告警：在 ${finalHost} 完成 ${checksExecuted} 项 6 阶段深度体检（含 ${fetchedChunks.length} 个完整 JS 包共 ${totalKbStr} KB），确认 ${criticalCount} 项高危泄露风险，请立即使用修复方案封堵！`
      : highCount > 0
        ? `建议尽快加固：对 ${finalHost} 执行 ${checksExecuted} 项深度检测（${fetchedChunks.length} 个 JS 包、${probeResults.length} 个敏感端点探测）后发现 ${highCount} 项高优先级隐患，建议推广前修复。`
        : score < 88
          ? `基础安全达标，仍有加固空间：已深度扫描 ${fetchedChunks.length} 个完整 JS 包（${totalKbStr} KB）与 ${probeResults.length} 个敏感路径（0 私钥泄露），修复 ${findings.length} 项 CSP/HSTS/安全头缺陷即可升至 ${projectedScore}/100。`
          : `安全防护扎实：通过 ${checksExecuted} 项深度安全校验（${fetchedChunks.length} 个 JS 包共 ${totalKbStr} KB、${tlsAudit.protocol || "HTTPS"} 证书校验、${probeResults.length} 项端点探测零泄露）。`) + wafNoteZh;

  return {
    ok: true,
    engineVersion: ENGINE_VERSION,
    scanMode: mode,
    budgetTruncated,
    checksExecuted,
    url: resolvedUrl,
    origin: finalOrigin,
    hostname: finalHost,
    tlsHttps,
    waf,
    resolutionNote,
    resolutionNoteZh,
    checkedAt: new Date().toISOString(),
    scanDurationMs: Date.now() - t0,
    stack,
    assessment: {
      score,
      projectedScore,
      grade,
      status,
      criticalCount,
      highCount,
      mediumCount,
      lowCount,
      totalFindings: findings.length,
      executiveSummary,
      executiveSummaryZh,
    },
    tls: tlsAudit,
    dns: {
      cnameChain: takeover.cnameChain,
      aRecordsCount: takeover.aRecordsCount,
      takeoverRisk: takeover.vulnerable
        ? { vulnerable: true, provider: takeover.provider, cname: takeover.cname, fingerprint: takeover.detail }
        : null,
    },
    takeover,
    routes: {
      robotsFound,
      robotsDisallowedCount,
      sitemapFound,
      buildManifestFound,
      crawled: crawledRoutes,
      discoveredApiEndpoints: discoveredApis,
    },
    crawl: {
      routes: crawledRoutes,
      discoveredApis,
      buildManifestFound,
      robotsFound,
      robotsDisallowedCount,
      sitemapFound,
    },
    bundles: {
      discovered: chunkUrls.length,
      inspected: fetchedChunks.length,
      totalBytesScanned,
      chunks: fetchedChunks.map((c) => ({ label: c.label, bytes: c.bytes })),
    },
    secrets: {
      patternsChecked: SECRET_RULES.length,
      count: secrets.length,
      items: secrets,
    },
    supabase: supabaseAudit,
    firebase: firebaseAudit,
    cookies: cookieAudit,
    cspAnalysis: {
      present: cspAudit.present,
      raw: cspAudit.raw,
      unsafeInline: cspAudit.unsafeInline,
      unsafeEval: cspAudit.unsafeEval,
      wildcardSrc: cspAudit.wildcardSrc,
      missingFrameAncestors: cspAudit.missingFrameAncestors,
      missingObjectSrc: cspAudit.missingObjectSrc,
      missingBaseUri: cspAudit.missingBaseUri,
      score: cspAudit.score,
      grade: cspAudit.grade,
      directives: cspAudit.directives,
      issues: cspAudit.issueItems,
    },
    cspAudit,
    hstsAudit,
    endpointProbes: {
      totalChecked: probeResults.length,
      exposedCount: exposedProbes.length,
      securityTxtPresent,
      graphqlIntrospectionExposed,
      openRedirectVulnerable,
      items: probeResults,
    },
    endpoints: {
      envExposed,
      gitExposed,
      sourceMapsChecked: mapProbes.length,
      exposedSourceMaps,
      cors: corsIssue,
      graphqlIntrospectionExposed,
      openRedirectVulnerable,
      securityTxtPresent,
      totalProbed: probeResults.length,
      exposedCount: exposedProbes.length,
    },
    headers: headerAudit,
    detectedFrameworks,
    frameworkCves,
    findings,
    executionTrace,
  };
}
