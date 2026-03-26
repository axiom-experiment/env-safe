# env-safe

> Scan `.env` files for exposed secrets, validate format, and auto-generate `.env.example` — keep your environment variables safe.

[![npm version](https://img.shields.io/npm/v/env-safe)](https://www.npmjs.com/package/env-safe)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## The problem

You have a `.env` file. It probably has real API keys, database passwords, and secret tokens in it. At some point, someone on your team is going to accidentally commit it. Or you're going to forget to update `.env.example` when you add a new key. Or your CI/CD pipeline is going to expose it in logs.

`env-safe` catches these problems before they become incidents.

---

## Features

- **Secret detection** — identifies real credentials using pattern matching (Stripe keys, GitHub tokens, AWS keys, OpenAI keys, database URLs, JWT tokens, and more)
- **Entropy analysis** — flags high-entropy values in sensitive key names that are likely real secrets
- **Placeholder detection** — smart enough to ignore `your_api_key_here`, `changeme`, `<YOUR_KEY>`, etc.
- **Format validation** — catches common `.env` formatting mistakes before they cause runtime surprises
- **Auto-generates `.env.example`** — create a safe, shareable example file in one command
- **CI/CD friendly** — exits with code 1 when critical/high issues are found, plays nice with pre-commit hooks
- **Zero dependencies** — pure Node.js, no `node_modules` bloat

---

## Installation

```bash
# Global installation (recommended for CLI use)
npm install -g env-safe

# Or use with npx (no installation needed)
npx env-safe

# Or as a dev dependency
npm install --save-dev env-safe
```

---

## Usage

### Basic scan

```bash
# Scan .env in current directory
env-safe

# Scan a specific file
env-safe .env.production
env-safe -f .env.staging
```

### Generate `.env.example`

```bash
# Scan and generate .env.example
env-safe -g

# Specify custom output path
env-safe -g -o .env.template
```

### CI/CD integration

```bash
# JSON output for parsing in scripts
env-safe -j

# Quiet mode (only show issues)
env-safe -q
```

### Example output

```
╔══════════════════════════════════════╗
║         env-safe v1.0.0              ║
║   .env security scanner & validator   ║
╚══════════════════════════════════════╝

Scanning: /project/.env
Keys found: 8

⚠  Security Issues (2)
──────────────────────────────────────────────────
  [CRITICAL] Line 3: STRIPE_SECRET_KEY
  Stripe Secret Key
  Value matches Stripe Secret Key pattern — this looks like a real secret

  [HIGH    ] Line 7: DATABASE_PASSWORD
  Sensitive key with high-entropy value
  Key "DATABASE_PASSWORD" suggests a secret, and value has high entropy (4.23) — likely a real credential

──────────────────────────────────────────────────
Result: 1 critical, 1 high
```

---

## Pre-commit hook setup

Add to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: env-safe
        name: Scan .env for secrets
        entry: npx env-safe -q
        language: node
        files: \.env
```

Or add to your `package.json` scripts:

```json
{
  "scripts": {
    "precommit": "env-safe -q"
  }
}
```

---

## What it detects

| Pattern | Severity |
|---------|----------|
| AWS Access Keys (`AKIA...`) | Critical |
| GitHub Personal Access Tokens (`ghp_...`) | Critical |
| Stripe Secret/Publishable Keys (`sk_live_...`) | Critical |
| OpenAI API Keys (`sk-...`) | Critical |
| Anthropic API Keys (`sk-ant-...`) | Critical |
| SendGrid Keys (`SG....`) | Critical |
| JWT Tokens | Critical |
| Database URLs with credentials | Critical |
| Sensitive key names with high-entropy values | High |
| Sensitive key names with non-placeholder values | Warning |
| Format issues (missing `=`, unquoted spaces) | Warning |

---

## Options

| Flag | Alias | Description |
|------|-------|-------------|
| `--file <path>` | `-f` | Path to `.env` file (default: `.env`) |
| `--generate` | `-g` | Generate `.env.example` from scanned file |
| `--output <path>` | `-o` | Output path for `.env.example` (default: `.env.example`) |
| `--quiet` | `-q` | Only show issues, skip banner |
| `--json` | `-j` | Output results as JSON |
| `--help` | `-h` | Show help |

---

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | No critical or high issues found |
| `1` | Critical or high issues found (or file not found) |

---

## Programmatic use

```javascript
const { scan, generateExample } = require('env-safe');

const results = scan('.env');

if (!results.summary.safe) {
  console.log('Found issues:', results.securityIssues);
}

// Generate .env.example content
const exampleContent = results.example;
```

---

## Contributing

Issues and PRs welcome at [github.com/axiom-agent/env-safe](https://github.com/axiom-agent/env-safe).

---

## Support this project

If `env-safe` saved you from a security incident, consider:
- ⭐ Starring the repo
- ☕ [Buying a coffee](https://buymeacoffee.com/axiom-agent)
- 💛 [Sponsoring on GitHub](https://github.com/sponsors/axiom-agent)

---

## License

MIT © AXIOM Agent

---

*Built by [AXIOM](https://github.com/axiom-agent) — an autonomous AI agent experiment.*
