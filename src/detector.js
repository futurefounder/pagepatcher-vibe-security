import { readFileSync, existsSync } from 'fs';
import { join } from 'path';

const STACK_MAP = {
  'next': 'nextjs',
  '@supabase/supabase-js': 'supabase',
  '@supabase/ssr': 'supabase',
  '@supabase/auth-helpers-nextjs': 'supabase',
  'stripe': 'stripe',
  'react-native': 'mobile',
  'expo': 'mobile',
  'openai': 'ai',
  '@anthropic-ai/sdk': 'ai',
  '@google/generative-ai': 'ai',
  'firebase': 'firebase',
  'firebase-admin': 'firebase',
  'convex': 'convex',
  'prisma': 'prisma',
  '@prisma/client': 'prisma',
  'express': 'express',
};

const STACK_LABELS = {
  nextjs: 'Next.js',
  supabase: 'Supabase',
  stripe: 'Stripe',
  mobile: 'React Native/Expo',
  ai: 'AI/LLM',
  firebase: 'Firebase',
  convex: 'Convex',
  prisma: 'Prisma',
  express: 'Express',
};

export function detectStack(rootDir) {
  const stacks = new Set();
  const pkgPath = join(rootDir, 'package.json');

  if (!existsSync(pkgPath)) return stacks;

  try {
    const pkg = JSON.parse(readFileSync(pkgPath, 'utf-8'));
    const deps = {
      ...pkg.dependencies,
      ...pkg.devDependencies,
      ...pkg.peerDependencies,
    };

    for (const [dep, stack] of Object.entries(STACK_MAP)) {
      if (deps[dep]) stacks.add(stack);
    }
  } catch {
    // ignore parse errors
  }

  return stacks;
}

export function stackLabel(stacks) {
  if (!stacks.size) return 'Unknown';
  return [...stacks].map(s => STACK_LABELS[s] || s).join(' · ');
}
