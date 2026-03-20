import { readdirSync, readFileSync, statSync } from 'fs';
import { join, extname } from 'path';

const SKIP_DIRS = new Set([
  'node_modules', '.git', '.next', 'dist', 'build', '.cache',
  'coverage', '.vibe-security', '.turbo', 'out', '.vercel', '__pycache__',
]);

const CODE_EXTENSIONS = new Set([
  '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs',
  '.sql', '.json', '.yaml', '.yml',
  '.gitignore', '.env',
]);

export function walkFiles(dir) {
  const results = [];

  function walk(current) {
    let entries;
    try {
      entries = readdirSync(current, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      if (SKIP_DIRS.has(entry.name)) continue;

      // Skip hidden dirs (except .gitignore files)
      if (entry.name.startsWith('.') && entry.isDirectory()) continue;

      const fullPath = join(current, entry.name);

      if (entry.isDirectory()) {
        walk(fullPath);
      } else if (entry.isFile()) {
        const ext = extname(entry.name);
        const base = entry.name;

        // Include files by extension or special filenames
        const include =
          CODE_EXTENSIONS.has(ext) ||
          base === '.gitignore' ||
          base.startsWith('.env') ||
          base.startsWith('next.config') ||
          base.startsWith('vite.config') ||
          base.startsWith('firebase');

        if (!include) continue;

        try {
          const content = readFileSync(fullPath, 'utf-8');
          results.push({ path: fullPath, lines: content.split('\n') });
        } catch {
          // skip unreadable files
        }
      }
    }
  }

  walk(dir);
  return results;
}
