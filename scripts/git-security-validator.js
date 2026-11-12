#!/usr/bin/env node

/**
 * ==============================================================================
 * Connect App Backoffice - Git Security & Push Protection Validator
 * ==============================================================================
 * Comprehensive security gate that prevents sensitive credentials, environment
 * variables, private keys, database dumps, customer documents, and debug scripts
 * from being staged, committed, or pushed to GitHub.
 *
 * Usage:
 *   node scripts/git-security-validator.js --pre-commit
 *   node scripts/git-security-validator.js --pre-push
 *   node scripts/git-security-validator.js --ci
 * ==============================================================================
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

// ANSI Color Helpers
const RED = '\x1b[31m';
const GREEN = '\x1b[32m';
const YELLOW = '\x1b[33m';
const CYAN = '\x1b[36m';
const BOLD = '\x1b[1m';
const RESET = '\x1b[0m';

// Configuration: Forbidden File Patterns
const FORBIDDEN_FILE_PATTERNS = [
  // 1. Environment Secrets (Excluding .env.example)
  {
    pattern: /(^|[/\\])\.env(\.[^/\\]+)?$/i,
    exception: /(^|[/\\])\.env\.example$/i,
    description: 'Actual environment file containing secrets'
  },
  {
    pattern: /(^|[/\\])[^/\\]+\.env$/i,
    exception: /(^|[/\\])\.env\.example$/i,
    description: 'Custom environment file containing secrets'
  },
  // 2. Private Project Instructions
  {
    pattern: /(^|[/\\])(AGENT|AGENTS|CHANGELOG)\.md$/i,
    description: 'Confidential project instruction or changelog file'
  },
  // 3. Private Keys and Certificates
  {
    pattern: /\.(pem|key|p12|pfx|jks|keystore|crt|cer)$/i,
    description: 'Private key, keystore, or security certificate'
  },
  // 4. Database Files and Backups
  {
    pattern: /\.(dump|bson|backup|sqlite|sqlite3)$/i,
    description: 'Database dump, export, or backup file'
  },
  {
    pattern: /(^|[/\\])(database-backup|db-backup|backups|mongodb-dumps)([/\\]|$)/i,
    description: 'Database backup directory'
  },
  // 5. Private Documents and Uploads
  {
    pattern: /(^|[/\\])(uploads|private-uploads|secure-uploads|customer-documents|vendor-documents|kyc-documents|aadhaar-documents|pan-documents|private-storage|sent_emails)([/\\]|$)/i,
    description: 'Private customer/vendor document or runtime upload directory'
  },
  // 6. Scratch / Debug Scripts
  {
    pattern: /(^|[/\\])backend[/\\](call_api|check_kathir|debug_vendors|query_orders|recreate_users|test_public_products|test_user)\.js$/i,
    description: 'Backend scratch/debug script containing direct database operations'
  },
  {
    pattern: /(^|[/\\])backend[/\\]utils[/\\]sync_customer_and_business_data\.js$/i,
    description: 'Backend scratch data synchronization script'
  },
  // 7. Dependencies & Build Artifacts
  {
    pattern: /(^|[/\\])(node_modules|dist|build|coverage|\.cache|\.tmp|\.temp)([/\\]|$)/i,
    description: 'Dependency, build artifact, or temporary directory'
  }
];

// Configuration: Sensitive Secret Regexes (Scanned in added lines of diff)
const SECRET_PATTERNS = [
  {
    name: 'Private Key Header',
    regex: /-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/,
    description: 'Unencrypted private key detected'
  },
  {
    name: 'AWS Access Key ID',
    regex: /\bAKIA[0-9A-Z]{16}\b/,
    description: 'AWS access key identifier detected'
  },
  {
    name: 'MongoDB Connection String with Password',
    regex: /mongodb(\+srv)?:\/\/[^:\s'"]+:(?!<[^>]+>)[^@\s'"]+@[a-zA-Z0-9\.-]+/,
    // Exclude placeholders like username:password, user:pass, etc.
    filter: (match) => !match.includes(':<') && !match.includes(':password@') && !match.includes(':pass@'),
    description: 'Live MongoDB URI with embedded credentials'
  },
  {
    name: 'Cloudinary Live URL with Secret',
    regex: /cloudinary:\/\/[0-9]+:(?!<[^>]+>)[a-zA-Z0-9_-]+@[a-zA-Z0-9_-]+/,
    filter: (match) => !match.includes(':<') && !match.includes('your_'),
    description: 'Live Cloudinary connection URL containing API secret'
  },
  {
    name: 'Live Cloudinary API Secret',
    regex: /CLOUDINARY_API_SECRET\s*=\s*['"]?(?!your_|<)[a-zA-Z0-9_-]{20,}['"]?/i,
    description: 'Raw Cloudinary API secret assigned'
  },
  {
    name: 'GitHub Personal Access Token',
    regex: /\bgh[pousr]_[a-zA-Z0-9]{36,255}\b/,
    description: 'GitHub personal access token detected'
  },
  {
    name: 'Slack Token',
    regex: /\bxox[baprs]-[0-9a-zA-Z]{10,48}\b/,
    description: 'Slack token or webhook credentials detected'
  }
];

function runGit(command) {
  try {
    return execSync(command, { encoding: 'utf8', stdio: ['pipe', 'pipe', 'ignore'] }).trim();
  } catch (err) {
    return '';
  }
}

/**
 * Validates a list of file paths against forbidden file patterns.
 */
function checkForbiddenFiles(fileList) {
  const violations = [];
  for (const file of fileList) {
    const normalized = file.replace(/\\/g, '/');
    for (const rule of FORBIDDEN_FILE_PATTERNS) {
      if (rule.pattern.test(normalized)) {
        if (rule.exception && rule.exception.test(normalized)) {
          continue;
        }
        violations.push({
          file: normalized,
          reason: rule.description
        });
        break;
      }
    }
  }
  return violations;
}

/**
 * Validates git diff content for raw secrets.
 */
function checkDiffContent(diffText) {
  const violations = [];
  const lines = diffText.split('\n');
  let currentFile = 'unknown';

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    if (line.startsWith('diff --git a/')) {
      const match = line.match(/^diff --git a\/(.+?) b\/(.+?)$/);
      if (match) {
        currentFile = match[2];
      }
      continue;
    }

    // Only inspect added lines (starting with '+', not '+++')
    if (line.startsWith('+') && !line.startsWith('+++')) {
      const content = line.substring(1);

      for (const secretRule of SECRET_PATTERNS) {
        if (secretRule.regex.test(content)) {
          if (secretRule.filter && !secretRule.filter(content)) {
            continue;
          }
          // Redact the match for secure reporting
          violations.push({
            file: currentFile,
            line: i + 1,
            secretType: secretRule.name,
            reason: secretRule.description
          });
        }
      }
    }
  }
  return violations;
}

/**
 * Prints violation report and remediation steps.
 */
function reportViolations(fileViolations, contentViolations, hookType) {
  console.error(`\n${RED}${BOLD}================================================================================${RESET}`);
  console.error(`${RED}${BOLD}🚨 [GIT SECURITY PROTECTION] ${hookType.toUpperCase()} REJECTED${RESET}`);
  console.error(`${RED}${BOLD}================================================================================${RESET}`);
  console.error(`\n${YELLOW}Antigravity Push Protection detected sensitive assets in your changeset.${RESET}\n`);

  if (fileViolations.length > 0) {
    console.error(`${BOLD}${RED}[FORBIDDEN FILES DETECTED]${RESET}`);
    fileViolations.forEach((v, index) => {
      console.error(`  ${index + 1}. ${CYAN}${v.file}${RESET}`);
      console.error(`     ↳ ${YELLOW}${v.reason}${RESET}`);
    });
    console.error('');
  }

  if (contentViolations.length > 0) {
    console.error(`${BOLD}${RED}[SENSITIVE SECRETS / CREDENTIALS DETECTED IN DIFF]${RESET}`);
    contentViolations.forEach((v, index) => {
      console.error(`  ${index + 1}. In ${CYAN}${v.file}${RESET} (near line ${v.line}):`);
      console.error(`     ↳ Type: ${BOLD}${v.secretType}${RESET} - ${YELLOW}${v.reason}${RESET}`);
    });
    console.error('');
  }

  console.error(`${BOLD}[REMEDIATION INSTRUCTIONS]${RESET}`);
  console.error(`  1. To unstage forbidden files:`);
  console.error(`     ${GREEN}git reset HEAD <file>${RESET}`);
  console.error(`  2. To remove a tracked sensitive file while keeping it on local disk:`);
  console.error(`     ${GREEN}git rm --cached <file>${RESET}`);
  console.error(`  3. Ensure credentials use environment variables or safe placeholders in .env.example.`);
  console.error(`  4. Check that .gitignore contains the required rule.`);
  console.error(`\n${RED}${BOLD}================================================================================${RESET}\n`);
}

// -----------------------------------------------------------------------------
// Mode Handlers
// -----------------------------------------------------------------------------

function runPreCommit() {
  // Check staged files
  const stagedFilesOutput = runGit('git diff --cached --name-only --diff-filter=ACM');
  if (!stagedFilesOutput) {
    process.exit(0);
  }
  const stagedFiles = stagedFilesOutput.split(/\r?\n/).filter(Boolean);

  const fileViolations = checkForbiddenFiles(stagedFiles);

  // Check staged diff content
  const stagedDiff = runGit('git diff --cached -U0');
  const contentViolations = checkDiffContent(stagedDiff);

  if (fileViolations.length > 0 || contentViolations.length > 0) {
    reportViolations(fileViolations, contentViolations, 'Pre-Commit Check');
    process.exit(1);
  }

  console.log(`${GREEN}✔ [Git Security] Pre-commit security verification passed.${RESET}`);
  process.exit(0);
}

function runPrePush() {
  // Determine range of commits to be pushed
  let commitRange = 'HEAD';
  const upstream = runGit('git rev-parse --abbrev-ref --symbolic-full-name @{u}');
  if (upstream) {
    commitRange = `${upstream}..HEAD`;
  }

  const pushedFilesOutput = runGit(`git diff --name-only --diff-filter=ACM ${commitRange}`);
  const pushedFiles = pushedFilesOutput ? pushedFilesOutput.split(/\r?\n/).filter(Boolean) : [];

  const fileViolations = checkForbiddenFiles(pushedFiles);

  const pushedDiff = runGit(`git diff -U0 ${commitRange}`);
  const contentViolations = checkDiffContent(pushedDiff);

  if (fileViolations.length > 0 || contentViolations.length > 0) {
    reportViolations(fileViolations, contentViolations, 'Pre-Push Check');
    process.exit(1);
  }

  console.log(`${GREEN}✔ [Git Security] Pre-push security verification passed.${RESET}`);
  process.exit(0);
}

function runCI() {
  // Check all tracked files in tree
  const trackedFilesOutput = runGit('git ls-files');
  const trackedFiles = trackedFilesOutput ? trackedFilesOutput.split(/\r?\n/).filter(Boolean) : [];

  const fileViolations = checkForbiddenFiles(trackedFiles);

  // Check latest commit diff
  const commitDiff = runGit('git diff HEAD~1..HEAD -U0');
  const contentViolations = commitDiff ? checkDiffContent(commitDiff) : [];

  if (fileViolations.length > 0 || contentViolations.length > 0) {
    reportViolations(fileViolations, contentViolations, 'CI Push Protection Check');
    process.exit(1);
  }

  console.log(`${GREEN}✔ [Git Security] CI repository security verification passed.${RESET}`);
  process.exit(0);
}

// Main execution
const mode = process.argv[2] || '--pre-commit';
if (mode === '--pre-push') {
  runPrePush();
} else if (mode === '--ci') {
  runCI();
} else {
  runPreCommit();
}

