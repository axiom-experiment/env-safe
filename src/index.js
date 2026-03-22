'use strict';

const fs = require('fs');
const path = require('path');

// Patterns that suggest a value is a real secret (not a placeholder)
const SECRET_PATTERNS = [
  // API Keys
  { name: 'AWS Access Key', pattern: /AKIA[0-9A-Z]{16}/ },
  { name: 'AWS Secret Key', pattern: /[0-9a-zA-Z/+]{40}/, keyNames: ['AWS_SECRET', 'AWS_SECRET_ACCESS_KEY'] },
  { name: 'GitHub Token', pattern: /ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82}/ },
  { name: 'Stripe Secret Key', pattern: /sk_(live|test)_[a-zA-Z0-9]{24,}/ },
  { name: 'Stripe Publishable Key', pattern: /pk_(live|test)_[a-zA-Z0-9]{24,}/ },
  { name: 'OpenAI API Key', pattern: /sk-[a-zA-Z0-9]{20,}/ },
  { name: 'Anthropic API Key', pattern: /sk-ant-[a-zA-Z0-9-_]{90,}/ },
  { name: 'SendGrid Key', pattern: /SG\.[a-zA-Z0-9_-]{22,}/ },
  { name: 'Twilio Key', pattern: /SK[a-zA-Z0-9]{32}/ },
  // Passwords and tokens
  { name: 'JWT Token', pattern: /eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*/ },
  { name: 'Database URL with credentials', pattern: /[a-z]+:\/\/[^:]+:[^@]+@/ },
  // Generic high-entropy values that are likely real secrets
  { name: 'High-entropy value (possible secret)', pattern: null, isHighEntropy: true },
];

// Key names that should NEVER have real values in a committed .env
const SENSITIVE_KEY_NAMES = [
  'PASSWORD', 'PASSWD', 'PWD', 'SECRET', 'API_KEY', 'APIKEY', 'ACCESS_TOKEN',
  'AUTH_TOKEN', 'PRIVATE_KEY', 'PRIVATE_TOKEN', 'DATABASE_URL', 'DATABASE_PASSWORD',
  'DB_PASSWORD', 'DB_PASS', 'REDIS_URL', 'REDIS_PASSWORD', 'JWT_SECRET',
  'SESSION_SECRET', 'COOKIE_SECRET', 'ENCRYPTION_KEY', 'SIGNING_KEY',
  'CLIENT_SECRET', 'OAUTH_SECRET', 'WEBHOOK_SECRET'
];

// Placeholder patterns — these are SAFE (no real secret)
const PLACEHOLDER_PATTERNS = [
  /^your[_-]?/i,
  /^change[_-]?me/i,
  /^replace[_-]?me/i,
  /^todo/i,
  /^xxx/i,
  /^<.*>$/,
  /^\[.*\]$/,
  /^example/i,
  /^placeholder/i,
  /^put[_-]?your/i,
  /^insert[_-]?your/i,
  /^add[_-]?your/i,
];

/**
 * Calculate Shannon entropy of a string — high entropy suggests a real random secret
 */
function calculateEntropy(str) {
  if (!str || str.length === 0) return 0;
  const freq = {};
  for (const char of str) {
    freq[char] = (freq[char] || 0) + 1;
  }
  let entropy = 0;
  for (const count of Object.values(freq)) {
    const p = count / str.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * Check if a value looks like a real secret (not a placeholder)
 */
function isLikelyRealSecret(value) {
  if (!value || value.trim() === '') return false;
  // Check placeholder patterns
  for (const pattern of PLACEHOLDER_PATTERNS) {
    if (pattern.test(value)) return false;
  }
  // Short values are rarely secrets
  if (value.length < 8) return false;
  return true;
}

/**
 * Parse a .env file into an array of entries
 */
function parseEnvFile(content) {
  const lines = content.split('\n');
  const entries = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    const lineNumber = i + 1;

    // Skip empty lines and comments
    if (!line || line.startsWith('#')) {
      entries.push({ type: 'comment_or_empty', raw: lines[i], lineNumber });
      continue;
    }

    // Parse KEY=VALUE
    const eqIndex = line.indexOf('=');
    if (eqIndex === -1) {
      entries.push({ type: 'invalid', raw: lines[i], lineNumber, error: 'Missing = sign' });
      continue;
    }

    const key = line.substring(0, eqIndex).trim();
    let value = line.substring(eqIndex + 1).trim();

    // Strip surrounding quotes
    if ((value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }

    entries.push({ type: 'kv', key, value, raw: lines[i], lineNumber });
  }

  return entries;
}

/**
 * Scan a single entry for security issues
 */
function scanEntry(entry) {
  const issues = [];

  if (entry.type !== 'kv') return issues;

  const { key, value, lineNumber } = entry;

  if (!isLikelyRealSecret(value)) return issues;

  // Check against known secret patterns
  for (const secretPattern of SECRET_PATTERNS) {
    if (secretPattern.pattern && secretPattern.pattern.test(value)) {
      issues.push({
        lineNumber,
        key,
        severity: 'critical',
        type: secretPattern.name,
        message: `Value matches ${secretPattern.name} pattern — this looks like a real secret`
      });
      return issues; // One critical issue per line is enough
    }
  }

  // Check if the key name suggests it should be secret
  const keyUpper = key.toUpperCase();
  const isSensitiveKey = SENSITIVE_KEY_NAMES.some(k => keyUpper.includes(k));

  if (isSensitiveKey) {
    const entropy = calculateEntropy(value);
    if (entropy > 3.5 && value.length >= 16) {
      issues.push({
        lineNumber,
        key,
        severity: 'high',
        type: 'Sensitive key with high-entropy value',
        message: `Key "${key}" suggests a secret, and value has high entropy (${entropy.toFixed(2)}) — likely a real credential`
      });
    } else if (value.length >= 8) {
      issues.push({
        lineNumber,
        key,
        severity: 'warning',
        type: 'Sensitive key name',
        message: `Key "${key}" suggests a sensitive value — verify this is not a real secret`
      });
    }
  }

  return issues;
}

/**
 * Validate .env file format
 */
function validateFormat(entries) {
  const issues = [];

  for (const entry of entries) {
    if (entry.type === 'invalid') {
      issues.push({
        lineNumber: entry.lineNumber,
        severity: 'warning',
        type: 'Format error',
        message: `Line ${entry.lineNumber}: ${entry.error} — "${entry.raw.trim()}"`
      });
    }

    if (entry.type === 'kv') {
      // Check for spaces in key name
      if (entry.key.includes(' ')) {
        issues.push({
          lineNumber: entry.lineNumber,
          severity: 'warning',
          type: 'Format error',
          message: `Key "${entry.key}" contains spaces — this may cause parsing issues`
        });
      }

      // Check for unquoted values with spaces
      if (entry.value.includes(' ') &&
          !entry.raw.substring(entry.raw.indexOf('=') + 1).trim().startsWith('"') &&
          !entry.raw.substring(entry.raw.indexOf('=') + 1).trim().startsWith("'")) {
        issues.push({
          lineNumber: entry.lineNumber,
          severity: 'warning',
          type: 'Format warning',
          message: `Value for "${entry.key}" contains spaces but is not quoted — consider quoting it`
        });
      }
    }
  }

  return issues;
}

/**
 * Generate a .env.example from parsed entries
 */
function generateExample(entries) {
  const lines = [];

  for (const entry of entries) {
    if (entry.type === 'comment_or_empty') {
      lines.push(entry.raw);
      continue;
    }

    if (entry.type === 'invalid') {
      lines.push(`# [INVALID] ${entry.raw}`);
      continue;
    }

    if (entry.type === 'kv') {
      const { key } = entry;
      const keyUpper = key.toUpperCase();
      const isSensitive = SENSITIVE_KEY_NAMES.some(k => keyUpper.includes(k));

      if (isSensitive) {
        lines.push(`${key}=your_${key.toLowerCase()}_here`);
      } else {
        // For non-sensitive keys, keep the value (it's probably a config, not a secret)
        lines.push(entry.raw);
      }
    }
  }

  return lines.join('\n');
}

/**
 * Main scan function
 * @param {string} filePath - Path to .env file
 * @param {object} options - Options
 * @returns {object} Scan results
 */
function scan(filePath, options = {}) {
  const absolutePath = path.resolve(filePath);

  if (!fs.existsSync(absolutePath)) {
    return { success: false, error: `File not found: ${absolutePath}` };
  }

  const content = fs.readFileSync(absolutePath, 'utf8');
  const entries = parseEnvFile(content);

  const securityIssues = [];
  const formatIssues = [];

  for (const entry of entries) {
    securityIssues.push(...scanEntry(entry));
  }

  formatIssues.push(...validateFormat(entries));

  const criticalCount = securityIssues.filter(i => i.severity === 'critical').length;
  const highCount = securityIssues.filter(i => i.severity === 'high').length;
  const warningCount = [...securityIssues, ...formatIssues].filter(i => i.severity === 'warning').length;

  const example = generateExample(entries);

  return {
    success: true,
    filePath: absolutePath,
    totalKeys: entries.filter(e => e.type === 'kv').length,
    securityIssues,
    formatIssues,
    summary: {
      critical: criticalCount,
      high: highCount,
      warnings: warningCount,
      safe: criticalCount === 0 && highCount === 0
    },
    example
  };
}

module.exports = { scan, parseEnvFile, generateExample, calculateEntropy, isLikelyRealSecret };
