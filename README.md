# VibeCode Security Gate
 
> Find the mistakes vibe coding introduces — before attackers do.
 
A CI-integrated security gate (CLI + dashboard) that scans Lovable / Bolt / v0 / Cursor projects before deploy and blocks releases that contain high-risk security patterns.
 
## Why This Exists
 
CVE-2025-48757 affected 170+ Lovable-generated applications due to missing RLS policies, and one data leak exposed 13,000 users. Lovable's own scanner only flags whether RLS *exists*, not whether it *actually works*. That gap is this product.
 
## 4 Security Modules
 
### 1. Secret Scanner
Wraps **Gitleaks** + **TruffleHog** with custom rules for vibe-coding patterns:
- Detects `VITE_*`, `NEXT_PUBLIC_*` prefixes wrapping secret keys
- Identifies Supabase `service_role` key leaks
- Custom patterns for OpenAI, Anthropic, Stripe, AWS, Firebase credentials
### 2. Frontend/API Architecture Checker
- Detects `fetch('https://api.openai.com/...')` directly from React/Vue components
- Scans production bundles for leaked secrets
- Checks Firebase rules for `allow read, write: if true`
- Integrates with **Semgrep** for deep analysis
### 3. Database Exposure Checker (The Killer Feature)
Goes beyond checking if RLS is "enabled" — actively **tests** whether policies work:
- Probes every table with the `anon` key and reports what data comes back
- Tests INSERT/UPDATE/DELETE access with anonymous credentials
- Checks Supabase migrations for tables created without RLS
- Detects `service_role` key exposure in client code
### 4. AI Agent Risk Checker
- Detects `eval()` with LLM outputs, `dangerouslySetInnerHTML` with AI content
- Scans MCP configurations for overly permissive servers
- Finds auto-approval of agent actions without human-in-the-loop
- Checks for prompt injection vectors (user input concatenated with system prompts)
- Integration points for **Garak** and **Promptfoo**
## Quick Start
 
### CLI
 
```bash
# Install
pnpm install
pnpm build
 
# Scan a project
npx vibecode-scan scan /path/to/project
 
# With Supabase active probing
npx vibecode-scan scan /path/to/project \
  --supabase-url https://xyz.supabase.co \
  --supabase-anon-key eyJhbGci...
 
# CI mode (exit code 1 if score < threshold)
npx vibecode-scan scan . --ci --threshold 70
 
# HTML report
npx vibecode-scan scan . --format html --output report.html
 
# JSON output
npx vibecode-scan scan . --format json --output results.json
```
 
### API Server
 
```bash
pnpm --filter @vibecode/api start
 
# POST /api/scan
curl -X POST http://localhost:3001/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target": {"type": "directory", "path": "/path/to/project"}}'
```
 
### Dashboard
 
```bash
pnpm --filter @vibecode/dashboard dev
# Open http://localhost:3000
```
 
### GitHub Action
 
```yaml
- name: VibeCode Security Gate
  uses: ./packages/github-action
  with:
    path: "."
    threshold: "70"
    supabase-url: ${{ secrets.SUPABASE_URL }}
    supabase-anon-key: ${{ secrets.SUPABASE_ANON_KEY }}
```
 
## Project Structure
 
```
packages/
  shared/         # Shared types, constants, patterns
  scanner/        # Core scanning engine (4 modules + risk scoring)
  cli/            # CLI tool (Commander.js)
  api/            # REST API (Express)
  dashboard/      # Web dashboard (Next.js + Tailwind)
  github-action/  # GitHub Action wrapper
```
 
## Risk Scoring
 
Scores are 0-100, weighted by:
- **Severity**: Critical (25pts), High (15pts), Medium (8pts), Low (3pts)
- **Module weights**: Secrets (30%), Frontend (25%), Database (30%), Agents (15%)
- **Exploitability**: Verified findings get 1.5x weight
- **Data sensitivity**: PII-related findings get 1.3x weight
Grades: A (90+), B (75+), C (60+), D (40+), F (<40)
 
## Differentiators
 
| Feature | VibeCode | Lovable Scanner | Generic SAST |
|---------|----------|-----------------|--------------|
| Active RLS testing | Yes | No | No |
| Multi-platform | Lovable+Bolt+v0+Cursor | Lovable only | Generic |
| Agent security | Yes | No | No |
| Public env prefix detection | Yes | No | No |
| Proof-of-risk evidence | Yes | No | No |
| PDF/HTML reports | Yes | No | Varies |
 
## License
 
MIT
