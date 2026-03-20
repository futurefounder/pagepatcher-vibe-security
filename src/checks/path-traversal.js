const JS_EXT = /\.(js|ts|jsx|tsx|mjs|cjs)$/;

export function check(files) {
  const findings = [];

  for (const { path, lines } of files) {
    if (!JS_EXT.test(path)) continue;

    lines.forEach((line, i) => {
      const trimmed = line.trim();
      if (trimmed.startsWith('//') || trimmed.startsWith('*')) return;

      // fs.readFile/readFileSync/writeFile/unlink with user-supplied path
      if (
        /fs\s*\.\s*(?:readFile|readFileSync|writeFile|writeFileSync|unlink|unlinkSync|access|accessSync|createReadStream)\s*\(/.test(
          line
        ) &&
        /(?:req|request)\.(?:query|params|body)/.test(line)
      ) {
        findings.push({
          severity: 'critical',
          title: 'Path traversal — user-controlled filename passed to fs',
          file: path,
          line: i + 1,
          code: trimmed.substring(0, 90),
          risk: 'An attacker can read any file on the server by sending filename=../../../etc/passwd.',
          fix: 'Validate against an allowlist, or use path.basename(filename) inside a fixed root: path.join(SAFE_DIR, path.basename(filename)).',
        });
      }
    });
  }

  return findings;
}
