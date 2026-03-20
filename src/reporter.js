import chalk from 'chalk';

const SEP = chalk.gray('━'.repeat(60));

const SEVERITY_CONFIG = {
  critical: {
    emoji: '🔴',
    label: 'CRITICAL',
    note: 'Fix before deploying',
    color: chalk.red.bold,
    tag: (t) => chalk.bgRed.white.bold(` ${t} `),
  },
  high: {
    emoji: '🟠',
    label: 'HIGH',
    note: 'Fix this week',
    color: chalk.yellow.bold,
    tag: (t) => chalk.bgYellow.black.bold(` ${t} `),
  },
  medium: {
    emoji: '🟡',
    label: 'MEDIUM',
    note: 'Schedule soon',
    color: chalk.yellow,
    tag: (t) => chalk.bgYellow.black(` ${t} `),
  },
  low: {
    emoji: '🔵',
    label: 'LOW',
    note: 'Nice to have',
    color: chalk.blue,
    tag: (t) => chalk.bgBlue.white(` ${t} `),
  },
};

const ORDER = ['critical', 'high', 'medium', 'low'];

export function report(findings, scanPath, stackStr, fileCount, duration) {
  const TITLE = 'PagePatcher.com — Vibe-Security — Audit';
  const WIDTH = 60;
  const inner = WIDTH - 2;

  const pad = (str) => str.padEnd(inner);

  // ── Header ──────────────────────────────────────────────────
  console.log('\n' + chalk.cyan('╔' + '═'.repeat(inner) + '╗'));
  console.log(chalk.cyan('║') + chalk.bold.white('  ' + pad(TITLE)) + chalk.cyan('║'));
  const scanLine = `  Scanning: ${scanPath}`;
  console.log(chalk.cyan('║') + chalk.gray(pad(scanLine.length > inner ? scanLine.slice(0, inner - 3) + '...' : scanLine)) + chalk.cyan('║'));
  console.log(chalk.cyan('╚' + '═'.repeat(inner) + '╝') + '\n');

  // ── Detected stack ───────────────────────────────────────────
  if (stackStr && stackStr !== 'Unknown') {
    console.log(chalk.gray('Detected stack: ') + chalk.cyan(stackStr));
  }
  console.log();

  // ── Group findings by severity ───────────────────────────────
  const bySeverity = { critical: [], high: [], medium: [], low: [] };
  for (const f of findings) {
    const sev = f.severity?.toLowerCase();
    if (bySeverity[sev]) bySeverity[sev].push(f);
  }

  const counters = ORDER.map((s) => ({
    ...SEVERITY_CONFIG[s],
    severity: s,
    count: bySeverity[s].length,
  }));

  // ── Summary (top) ────────────────────────────────────────────
  console.log(SEP);
  console.log(chalk.bold.white('📋  SUMMARY'));
  console.log(SEP);
  console.log();

  for (const { emoji, label, note, color, count } of counters) {
    const countStr = String(count).padStart(2);
    console.log(`  ${emoji}  ${color(label.padEnd(10))} ${countStr}    ${chalk.gray(note)}`);
  }

  console.log();
  console.log(chalk.gray(`  Checked ${fileCount} files in ${duration}s`));
  console.log();

  // ── No issues ────────────────────────────────────────────────
  if (findings.length === 0) {
    console.log(chalk.green.bold('✅  No security issues found. Nice work!'));
    console.log();
    return 0;
  }

  // ── Detailed findings, grouped by severity ───────────────────
  for (const sev of ORDER) {
    const items = bySeverity[sev];
    if (!items.length) continue;

    const cfg = SEVERITY_CONFIG[sev];
    console.log(SEP);
    console.log(
      `${cfg.emoji}  ${cfg.color(`${cfg.label} (${items.length} ${items.length === 1 ? 'issue' : 'issues'})`)}`
    );
    console.log(SEP);
    console.log();

    items.forEach((item, idx) => {
      const prefix = `${sev[0].toUpperCase()}${idx + 1}`;
      console.log(cfg.tag(prefix) + ' ' + chalk.bold(item.title));

      if (item.file) {
        const loc = item.line && item.line > 0 ? `${item.file}:${item.line}` : item.file;
        console.log(chalk.gray('  File: ') + chalk.white(loc));
      }
      if (item.code && item.code.trim()) {
        console.log(chalk.gray('  Code: ') + chalk.red(item.code.slice(0, 90)));
      }
      if (item.risk) {
        console.log(chalk.gray('  Risk: ') + item.risk);
      }
      if (item.fix) {
        console.log(chalk.gray('  Fix:  ') + chalk.green(item.fix));
      }
      console.log();
    });
  }

  // ── Footer ───────────────────────────────────────────────────
  const hasBlockers = bySeverity.critical.length > 0 || bySeverity.high.length > 0;

  if (hasBlockers) {
    console.log(chalk.red.bold('  ⚠  Exiting with code 1 — critical/high issues must be resolved before shipping.'));
  }
  console.log(
    chalk.gray('  Tip: run ') + chalk.cyan('npm audit') + chalk.gray(' to check for vulnerable dependencies too.')
  );
  console.log();

  return hasBlockers ? 1 : 0;
}
