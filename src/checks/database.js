export function check(files, rootDir, stacks) {
  if (!stacks.has('supabase') && !stacks.has('firebase')) return [];

  const findings = [];

  for (const { path, lines } of files) {
    lines.forEach((line, i) => {
      const trimmed = line.trim();
      if (trimmed.startsWith('--') || trimmed.startsWith('#')) return;

      // ── Supabase ──────────────────────────────────────────────
      if (stacks.has('supabase')) {
        // USING (true) — open policy
        if (/USING\s*\(\s*true\s*\)/i.test(line)) {
          findings.push({
            severity: 'critical',
            title: 'Supabase RLS policy USING (true) — all rows exposed',
            file: path,
            line: i + 1,
            code: trimmed.substring(0, 90),
            risk: 'Any authenticated user can read or modify every row in this table.',
            fix: 'Scope to row owner: USING ((SELECT auth.uid()) = user_id)',
          });
        }

        // auth.uid() IS NOT NULL — authenticated-only open policy
        if (/USING\s*\(\s*auth\.uid\(\)\s*IS\s*NOT\s*NULL\s*\)/i.test(line)) {
          findings.push({
            severity: 'high',
            title: 'Supabase RLS USING (auth.uid() IS NOT NULL) — any user sees all rows',
            file: path,
            line: i + 1,
            code: trimmed.substring(0, 90),
            risk: 'Any logged-in user can access every row — no ownership validation.',
            fix: 'Use: USING ((SELECT auth.uid()) = user_id)',
          });
        }

        // INSERT/UPDATE without WITH CHECK (look ahead a few lines)
        if (/FOR\s+(INSERT|UPDATE)/i.test(line)) {
          const block = lines.slice(i, i + 6).join(' ');
          if (!/WITH\s+CHECK/i.test(block)) {
            findings.push({
              severity: 'high',
              title: 'Supabase RLS INSERT/UPDATE policy missing WITH CHECK',
              file: path,
              line: i + 1,
              code: trimmed.substring(0, 90),
              risk: 'Without WITH CHECK, a user can INSERT/UPDATE a row setting user_id to someone else\'s ID.',
              fix: 'Add WITH CHECK ((SELECT auth.uid()) = user_id) matching your USING clause.',
            });
          }
        }

        // service_role exposed via public prefix
        if (/(?:NEXT_PUBLIC_|VITE_|EXPO_PUBLIC_|REACT_APP_).*SERVICE_ROLE/i.test(line)) {
          findings.push({
            severity: 'critical',
            title: 'Supabase service_role key exposed to browser',
            file: path,
            line: i + 1,
            code: trimmed.substring(0, 90),
            risk: 'service_role bypasses ALL Row-Level Security. Anyone with DevTools can read/write/delete your entire database.',
            fix: 'Rename to SUPABASE_SERVICE_ROLE_KEY (no public prefix). Use only in server-side code.',
          });
        }
      }

      // ── Firebase ──────────────────────────────────────────────
      if (stacks.has('firebase')) {
        // allow read/write: if true;
        if (/allow\s+(?:read|write|read\s*,\s*write)\s*:\s*if\s+true\s*;/.test(line)) {
          findings.push({
            severity: 'critical',
            title: 'Firebase rules allow unrestricted access (if true)',
            file: path,
            line: i + 1,
            code: trimmed.substring(0, 90),
            risk: 'Anyone — including unauthenticated users — can read and write all data.',
            fix: 'Add ownership check: if request.auth.uid == userId',
          });
        }

        // allow if request.auth != null (no ownership check)
        if (/allow\s+(?:read|write|read\s*,\s*write)\s*:\s*if\s+request\.auth\s*!=\s*null/.test(line)) {
          findings.push({
            severity: 'high',
            title: 'Firebase rules allow any authenticated user to access all data',
            file: path,
            line: i + 1,
            code: trimmed.substring(0, 90),
            risk: 'Any logged-in user can read or modify every document. No ownership validation.',
            fix: 'Scope to owner: allow read, write: if request.auth.uid == resource.data.userId',
          });
        }
      }
    });
  }

  return findings;
}
