#!/usr/bin/env node
'use strict';

const path = require('path');
const fs = require('fs');
const { scan } = require('../src/index.js');

// ANSI color codes
const RED = '\x1b[31m';
const YELLOW = '\x1b[33m';
const GREEN = '\x1b[32m';
const CYAN = '\x1b[36m';
const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';
const RESET = '\x1b[0m';

function printBanner() {
  console.log(`\n${BOLD}${CYAN}╔══════════════════════════════════════╗`);
  console.log(`║         env-safe v1.0.0              ║`);
  console.log(`║   .env security scanner & validator   ║`);
  console.log(`╚══════════════════════════════════════╝${RESET}\n`);
}

function printHelp() {
  console.log(`${BOLD}Usage:${RESET}
  env-safe [options] [file]

${BOLD}Options:${RESET}
  -f, --file <path>     Path to .env file (default: .env)
  -g, --generate        Generate .env.example from scanned file
  -o, --output <path>   Output path for .env.example (default: .env.example)
  -q, --quiet           Only show issues, no banner
  -j, --json            Output results as JSON
  -h, --help            Show this help

${BOLD}Examples:${RESET}
  env-safe                     Scan .env in current directory
  env-safe .env.production      Scan a specific file
  env-safe -g                  Scan + generate .env.example
  env-safe -g -o .env.sample   Scan + generate to custom output path
  env-safe -j                  Output results as JSON (for CI/CD)
`);
}

function printIssue(issue) {
  const severityColor = issue.severity === 'critical' ? RED : issue.severity === 'high' ? YELLOW : DIM;
  const severityLabel = issue.severity.toUpperCase().padEnd(8);
  console.log(`  ${severityColor}${BOLD}[${severityLabel}]${RESET} Line ${issue.lineNumber}: ${issue.key}`);
  console.log(`  ${DIM}${issue.type}${RESET}`);
  console.log(`  ${issue.message}\n`);
}

function printResults(results, options = {}) {
  if (!options.quiet) {
    printBanner();
  }

  if (!results.success) {
    console.error(`${RED}Error: ${results.error}${RESET}`);
    process.exit(1);
  }

  console.log(`${BOLD}Scanning:${RESET} ${results.filePath}`);
  console.log(`${BOLD}Keys found:${RESET} ${results.totalKeys}\n`);

  // Security issues
  if (results.securityIssues.length > 0) {
    console.log(`${BOLD}${RED}⚠  Security Issues (${results.securityIssues.length})${RESET}`);
    console.log(`${'─'.repeat(50)}`);
    for (const issue of results.securityIssues) {
      printIssue(issue);
    }
  }

  // Format issues
  if (results.formatIssues.length > 0) {
    console.log(`${BOLD}${YELLOW}⚠  Format Issues (${results.formatIssues.length})${RESET}`);
    console.log(`${'─'.repeat(50)}`);
    for (const issue of results.formatIssues) {
      printIssue(issue);
    }
  }

  // Summary
  console.log(`${'─'.repeat(50)}`);
  if (results.summary.safe && results.formatIssues.length === 0) {
    console.log(`${GREEN}${BOLD}✓ All clear — no secrets or format issues detected${RESET}`);
  } else {
    const parts = [];
    if (results.summary.critical > 0) parts.push(`${RED}${results.summary.critical} critical${RESET}`);
    if (results.summary.high > 0) parts.push(`${YELLOW}${results.summary.high} high${RESET}`);
    if (results.summary.warnings > 0) parts.push(`${DIM}${results.summary.warnings} warnings${RESET}`);
    console.log(`${BOLD}Result:${RESET} ${parts.join(', ')}`);
  }
  console.log('');
}

// Parse CLI args
const args = process.argv.slice(2);
const options = {
  file: '.env',
  generate: false,
  output: '.env.example',
  quiet: false,
  json: false
};

let i = 0;
while (i < args.length) {
  const arg = args[i];
  if (arg === '-h' || arg === '--help') {
    printHelp();
    process.exit(0);
  } else if (arg === '-f' || arg === '--file') {
    options.file = args[++i];
  } else if (arg === '-g' || arg === '--generate') {
    options.generate = true;
  } else if (arg === '-o' || arg === '--output') {
    options.output = args[++i];
  } else if (arg === '-q' || arg === '--quiet') {
    options.quiet = true;
  } else if (arg === '-j' || arg === '--json') {
    options.json = true;
  } else if (!arg.startsWith('-')) {
    options.file = arg;
  }
  i++;
}

// Run scan
const results = scan(options.file, options);

if (options.json) {
  console.log(JSON.stringify(results, null, 2));
} else {
  printResults(results, options);
}

// Generate .env.example if requested
if (options.generate && results.success) {
  const outputPath = path.resolve(options.output);
  fs.writeFileSync(outputPath, results.example, 'utf8');
  if (!options.json) {
    console.log(`${GREEN}✓ Generated ${options.output}${RESET}\n`);
  }
}

// Exit with error code if critical or high issues found
if (results.success && (results.summary.critical > 0 || results.summary.high > 0)) {
  process.exit(1);
}
