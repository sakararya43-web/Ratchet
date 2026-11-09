// Picks live or demo before the console renders. A reachable RATCHET core means live;
// anything else (GitHub Pages, a dev server without the core) means demo.
// ?mode=demo or ?mode=live overrides and is remembered on this browser.
import { installBackend } from '../lib/api';

const KEY = 'ratchet-mode';
export let demoMode = false;

function remembered(): string | null {
  const asked = new URLSearchParams(location.search).get('mode');
  try {
    if (asked === 'demo' || asked === 'live') localStorage.setItem(KEY, asked);
    if (asked === 'auto') localStorage.removeItem(KEY);
    return asked === 'demo' || asked === 'live' ? asked : localStorage.getItem(KEY);
  } catch { return asked === 'demo' || asked === 'live' ? asked : null; }
}

async function coreReachable(): Promise<boolean> {
  try {
    const r = await fetch('/api/setup', { credentials: 'same-origin', signal: AbortSignal.timeout(3000) });
    if (!r.ok) return false;
    const body = await r.json() as { mode?: unknown };
    return typeof body.mode === 'string';
  } catch { return false; }
}

export async function chooseMode(): Promise<boolean> {
  const choice = remembered();
  demoMode = choice === 'demo' || (choice !== 'live' && !await coreReachable());
  if (demoMode) {
    const [backend, { demoCredentials }] = await Promise.all([import('./backend'), import('./passkey')]);
    await backend.initDemo();
    installBackend(backend.demoTransport, demoCredentials);
  }
  return demoMode;
}

export function switchMode(mode: 'demo' | 'live' | 'auto'): void {
  try { if (mode === 'auto') localStorage.removeItem(KEY); else localStorage.setItem(KEY, mode); } catch { /* The choice applies to this load only. */ }
  location.replace(`${location.pathname}${location.hash}`);
}

// Demo deep link: #/console?as=alice&tab=incidents opens that persona on that workspace,
// so a shared link or a recorded clip starts on the right screen. Live mode ignores it.
export function demoDeepLink(): { actor: string; tab: string } | null {
  if (!demoMode || !location.hash.startsWith('#/console')) return null;
  const query = new URLSearchParams(location.hash.split('?')[1] ?? '');
  const as = query.get('as');
  if (!as) return null;
  return { actor: as.startsWith('user:') ? as : `user:${as}`, tab: (query.get('tab') ?? '').toLowerCase().replace(/[-_]/g, ' ') };
}
