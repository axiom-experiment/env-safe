'use strict';

const { scan, parseEnvFile, generateExample, calculateEntropy, isLikelyRealSecret } = require('../src/index.js');
const fs = require('fs');
const path = require('path');
const os = require('os');

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (err) {
    console.log(`  ✗ ${name}`);
    console.log(`    ${err.message}`);
    failed++;
  }
}

function assert(condition, message) {
  if (!condition) throw new Error(message || 'Assertion failed');
}

function assertEqual(actual, expected, message) {
  if (actual !== expected) {
    throw new Error(message || `Expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
  }
}

// Helper: write a temp .env file
function writeTempEnv(content) {
  const tmpPath = path.join(os.tmpdir(), `env-safe-test-${Date.now()}.env`);
  fs.writeFileSync(tmpPath, content, 'utf8');
  return tmpPath;
}

console.log('\nenv-safe test suite\n');

// --- calculateEntropy ---
console.log('calculateEntropy:');
test('empty string returns 0', () => assertEqual(calculateEntropy(''), 0));
test('single char returns 0', () => assertEqual(calculateEntropy('a'), 0));
test('high-entropy string has entropy > 3', () => assert(calculateEntropy('xK92!mP@4vQr8nZs') > 3));
test('low-entropy string has entropy < 2', () => assert(calculateEntropy('aaaaaaa') < 2));

// --- isLikelyRealSecret ---
console.log('\nisLikelyRealSecret:');
test('empty string is not a secret', () => assert(!isLikelyRealSecret('')));
test('"your_api_key_here" is not a secret (placeholder)', () => assert(!isLikelyRealSecret('your_api_key_here')));
test('"changeme" is not a secret (placeholder)', () => assert(!isLikelyRealSecret('changeme')));
test('"<YOUR_KEY>" is not a secret (placeholder)', () => assert(!isLikelyRealSecret('<YOUR_KEY>')));
test('real-looking key IS a secret', () => assert(isLikelyRealSecret('sk-ant-api03-xK92mP4vQr8nZs')));
test('short values are not secrets', () => assert(!isLikelyRealSecret('abc')));

// --- parseEnvFile ---
console.log('\nparseEnvFile:');
test('parses simple key=value', () => {
  const entries = parseEnvFile('FOO=bar\nBAZ=qux');
  assert(entries.length === 2);
  assertEqual(entries[0].key, 'FOO');
  assertEqual(entries[0].value, 'bar');
});

test('strips quoted values', () => {
  const entries = parseEnvFile('FOO="bar baz"');
  assertEqual(entries[0].value, 'bar baz');
});

test('ignores comment lines', () => {
  const entries = parseEnvFile('# this is a comment\nFOO=bar');
  assertEqual(entries[0].type, 'comment_or_empty');
  assertEqual(entries[1].key, 'FOO');
});

test('marks invalid lines', () => {
  const entries = parseEnvFile('this is not valid');
  assertEqual(entries[0].type, 'invalid');
});

test('handles empty values', () => {
  const entries = parseEnvFile('FOO=');
  assertEqual(entries[0].value, '');
});

// --- scan ---
console.log('\nscan:');
test('returns error for non-existent file', () => {
  const result = scan('/tmp/does-not-exist-99999.env');
  assert(!result.success);
  assert(result.error.includes('not found'));
});

test('detects Stripe secret key', () => {
  const tmpFile = writeTempEnv('STRIPE_SECRET_KEY=' + 'sk_live_' + 'XXXX_FAKE_TEST_KEY_DO_NOT_USE');
  const result = scan(tmpFile);
  fs.unlinkSync(tmpFile);
  assert(result.success);
  assert(result.securityIssues.length > 0);
  assert(result.securityIssues.some(i => i.severity === 'critical'));
});

test('detects GitHub token', () => {
  const tmpFile = writeTempEnv('GITHUB_TOKEN=ghp_' + 'a'.repeat(36));
  const result = scan(tmpFile);
  fs.unlinkSync(tmpFile);
  assert(result.success);
  assert(result.securityIssues.length > 0);
  assert(result.securityIssues.some(i => i.severity === 'critical'));
});

test('does not flag placeholder values', () => {
  const tmpFile = writeTempEnv('STRIPE_SECRET_KEY=your_stripe_key_here\nAPI_KEY=change_me');
  const result = scan(tmpFile);
  fs.unlinkSync(tmpFile);
  assert(result.success);
  assertEqual(result.securityIssues.filter(i => i.severity === 'critical').length, 0);
});

test('reports safe when no real secrets found', () => {
  const tmpFile = writeTempEnv('PORT=3000\nNODE_ENV=development\nDEBUG=true');
  const result = scan(tmpFile);
  fs.unlinkSync(tmpFile);
  assert(result.success);
  assert(result.summary.safe);
});

test('counts total keys correctly', () => {
  const tmpFile = writeTempEnv('FOO=1\nBAR=2\n# comment\nBAZ=3');
  const result = scan(tmpFile);
  fs.unlinkSync(tmpFile);
  assertEqual(result.totalKeys, 3);
});

// --- generateExample ---
console.log('\ngenerateExample:');
test('replaces sensitive key values with placeholders', () => {
  const entries = parseEnvFile('DATABASE_PASSWORD=realpassword123\nPORT=3000');
  const example = generateExample(entries);
  assert(!example.includes('realpassword123'));
  assert(example.includes('your_database_password_here'));
  assert(example.includes('PORT=3000'));
});

// --- Summary ---
console.log(`\n${'─'.repeat(40)}`);
console.log(`Tests: ${passed + failed} total, ${passed} passed, ${failed} failed`);

if (failed > 0) {
  console.log('\n✗ Test suite FAILED');
  process.exit(1);
} else {
  console.log('\n✓ All tests passed');
  process.exit(0);
}
