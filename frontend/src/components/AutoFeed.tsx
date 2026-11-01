import { useEffect, useState } from 'react';

// Demo-mode auto mode: a scripted replay (same every time) of what live auto mode would do.
// Pull the CVE delta, triage each new CVE, pick the one worth a decoy, hand it to the build pipeline.

interface FeedItem {
  id: string;
  product: string;
  flaw: string;
  cvss: number;
  kev?: boolean;
  verdict: string;
  pick?: boolean;
}

const FEED: FeedItem[] = [
  { id: 'CVE-2024-6767', product: 'WordSurvey (WordPress plugin)', flaw: 'Stored XSS', cvss: 5.5, verdict: 'Needs an admin login. No mass exploitation.' },
  { id: 'CVE-2025-6767', product: 'hosp_order', flaw: 'SQL injection', cvss: 6.3, verdict: 'Hobby project, almost no internet exposure.' },
  {
    id: 'CVE-2024-3400',
    product: 'Palo Alto PAN-OS GlobalProtect',
    flaw: 'Unauthenticated command injection',
    cvss: 10.0,
    kev: true,
    verdict: 'Unauthenticated RCE · in CISA KEV · internet-facing VPN · mass-scanned. Building a decoy.',
    pick: true,
  },
  { id: 'CVE-2024-6387', product: 'OpenSSH (regreSSHion)', flaw: 'Race-condition RCE', cvss: 8.1, verdict: 'SSH, not HTTP, and takes hours per target. Watchlist.' },
  { id: 'CVE-2024-3094', product: 'xz Utils', flaw: 'Supply-chain backdoor', cvss: 10.0, verdict: 'Nothing reachable to scan for. Not decoy-able.' },
  { id: 'CVE-2024-38063', product: 'Windows TCP/IP (IPv6)', flaw: 'Kernel RCE', cvss: 9.8, verdict: 'Kernel network stack; cannot be impersonated safely.' },
  { id: 'CVE-2024-23897', product: 'Jenkins', flaw: 'CLI arbitrary file read', cvss: 9.8, kev: true, verdict: 'KEV, but mostly patched. Queued next.' },
];

type Phase = 'idle' | 'pulling' | 'triage' | 'picked';

export function AutoFeed({ onPick }: { onPick: (cveId: string) => void }) {
  const [phase, setPhase] = useState<Phase>('idle');
  const [shown, setShown] = useState(0);
  const [judged, setJudged] = useState(0);

  useEffect(() => {
    if (phase === 'pulling') {
      if (shown < FEED.length) {
        const t = setTimeout(() => setShown((n) => n + 1), 260);
        return () => clearTimeout(t);
      }
      const t = setTimeout(() => setPhase('triage'), 600);
      return () => clearTimeout(t);
    }
    if (phase === 'triage') {
      if (judged < FEED.length) {
        const t = setTimeout(() => setJudged((n) => n + 1), 650);
        return () => clearTimeout(t);
      }
      setPhase('picked');
    }
    if (phase === 'picked') {
      const t = setTimeout(() => onPick(FEED.find((f) => f.pick)!.id), 1400);
      return () => clearTimeout(t);
    }
  }, [phase, shown, judged, onPick]);

  if (phase === 'idle') {
    return (
      <div className="auto-feed">
        <button type="button" className="flow-btn auto-btn" onClick={() => setPhase('pulling')}>
          Auto mode <span aria-hidden>⟳</span>
        </button>
        <span className="auto-hint">Watch the CVE feed, pick what attackers will go after, build it automatically.</span>
      </div>
    );
  }

  return (
    <div className="auto-feed is-running">
      <p className="auto-status">
        {phase === 'pulling'
          ? `Pulling cvelistV5 delta… ${shown} new CVEs`
          : phase === 'triage'
            ? 'Triage: exploitable remotely? internet-facing? in KEV? decoy-able?'
            : 'Selected 1 of 7. Starting the build pipeline…'}
      </p>
      <ul className="auto-list">
        {FEED.slice(0, shown).map((f, i) => {
          const done = i < judged;
          const state = done ? (f.pick ? 'is-pick' : 'is-drop') : '';
          return (
            <li key={f.id} className={`auto-row ${state}`}>
              <div className="auto-row-top">
                <span className="mono">{f.id}</span>
                <span className="auto-cvss">CVSS {f.cvss.toFixed(1)}</span>
                {f.kev && <span className="auto-kev">KEV</span>}
                <span className="auto-mark">{done ? (f.pick ? '✓ build' : '✕ skip') : 'new'}</span>
              </div>
              <div className="auto-row-sub">
                {f.product} · {f.flaw}
              </div>
              {done && <div className="auto-verdict">{f.verdict}</div>}
            </li>
          );
        })}
      </ul>
    </div>
  );
}
