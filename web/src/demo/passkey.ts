// Demo stand-in for the browser's passkey prompt. It never touches a real authenticator:
// it asks the viewer to confirm, then returns a credential-shaped object for the demo backend.
import { personas } from './personas';
import { demoPersona } from './backend';

type Purpose = 'sign' | 'register';

function confirm(purpose: Purpose): Promise<boolean> {
  return new Promise(resolve => {
    const who = personas.find(p => p.id === demoPersona())?.name ?? 'this persona';
    const backdrop = document.createElement('div');
    backdrop.className = 'demo-passkey-backdrop';
    const dialog = document.createElement('div');
    dialog.className = 'demo-passkey'; dialog.setAttribute('role', 'dialog'); dialog.setAttribute('aria-modal', 'true'); dialog.setAttribute('aria-labelledby', 'demo-passkey-title');
    const eyebrow = document.createElement('p'); eyebrow.className = 'eyebrow'; eyebrow.textContent = 'SIMULATED PASSKEY';
    const title = document.createElement('h2'); title.id = 'demo-passkey-title';
    title.textContent = purpose === 'sign' ? `Confirm as ${who}` : `Register a passkey for ${who}`;
    const body = document.createElement('p');
    body.textContent = purpose === 'sign'
      ? 'In the live system your security key or fingerprint signs the exact digest shown on screen. Here the prompt is simulated; the digest checks before it are real.'
      : 'In the live system your browser creates a new key pair on your authenticator. Here the enrolment is simulated.';
    const actions = document.createElement('div'); actions.className = 'demo-passkey-actions';
    const cancel = document.createElement('button'); cancel.type = 'button'; cancel.textContent = 'Cancel';
    const ok = document.createElement('button'); ok.type = 'button'; ok.className = 'button-primary'; ok.textContent = purpose === 'sign' ? 'Use passkey' : 'Create passkey';
    actions.append(cancel, ok);
    dialog.append(eyebrow, title, body, actions);
    backdrop.append(dialog);
    const previous = document.activeElement as HTMLElement | null;
    const close = (value: boolean) => { backdrop.remove(); document.removeEventListener('keydown', key); previous?.focus(); resolve(value); };
    const key = (e: KeyboardEvent) => { if (e.key === 'Escape') close(false); };
    cancel.onclick = () => close(false); ok.onclick = () => close(true);
    document.addEventListener('keydown', key);
    document.body.append(backdrop);
    ok.focus();
  });
}

const bytes = (text: string) => new TextEncoder().encode(text).buffer as ArrayBuffer;
function credential(rawId: ArrayBuffer): Credential {
  const id = btoa(String.fromCharCode(...new Uint8Array(rawId))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return {
    id, rawId, type: 'public-key', authenticatorAttachment: 'platform', getClientExtensionResults: () => ({}),
    response: { clientDataJSON: bytes('{"type":"demo"}'), authenticatorData: bytes('demo'), signature: bytes('demo'), attestationObject: bytes('demo'), getTransports: () => ['internal'] },
  } as unknown as Credential;
}

export const demoCredentials = {
  async get(options?: CredentialRequestOptions): Promise<Credential | null> {
    if (!await confirm('sign')) return null;
    const allowed = options?.publicKey?.allowCredentials?.[0]?.id;
    if (!allowed) throw new Error('No enrolled passkey for this persona');
    return credential(allowed instanceof ArrayBuffer ? allowed : (allowed as Uint8Array).slice().buffer as ArrayBuffer);
  },
  async create(): Promise<Credential | null> {
    if (!await confirm('register')) return null;
    return credential(crypto.getRandomValues(new Uint8Array(32)).buffer);
  },
};
