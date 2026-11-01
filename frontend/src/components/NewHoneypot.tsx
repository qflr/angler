import { useEffect, useRef, useState } from 'react';
import { CVE_PATTERN, createHoneypot, getHoneypot, publishHoneypot } from '../data/honeypot';
import type { HoneypotJob, HoneypotStatus } from '../data/types';
import { SiteFooter } from './SiteFooter';

// Profiles the decoy already answers. Same set as backend classify.DECOY_CVES.
const PREBUILT = [
  { id: 'CVE-2023-1389', name: 'TP-Link Archer command injection' },
  { id: 'CVE-2017-9841', name: 'PHPUnit eval-stdin.php RCE' },
  { id: 'CVE-2021-41773', name: 'Apache path traversal' },
  { id: 'CVE-2024-4577', name: 'PHP-CGI argument injection' },
] as const;

const PREBUILT_IDS = new Set<string>(PREBUILT.map((cve) => cve.id));

const POLL_MS = 800;
// Lets the button's press animation play before the view changes.
const PRESS_MS = 350;

// Order of the pipeline; a step is done once the job's status is past it.
const ORDER: HoneypotStatus[] = ['researching', 'building', 'containing', 'ready', 'published'];

interface Step {
  key: string;
  title: string;
  blurb: string;
  activeAt: HoneypotStatus;
  working: string;
  done: (job: HoneypotJob) => string;
}

const STEPS: Step[] = [
  {
    key: 'research',
    title: 'Research',
    blurb: 'Pulls verified advisories and PoCs',
    activeAt: 'researching',
    working: 'Researching',
    done: (j) =>
      j.advisory
        ? [j.advisory.product, j.advisory.description, j.advisory.cvss != null && `CVSS ${j.advisory.cvss.toFixed(1)}`, j.advisory.kev && 'KEV']
            .filter(Boolean)
            .join(' · ')
        : 'Advisory and PoC verified',
  },
  {
    key: 'build',
    title: 'Build',
    blurb: 'Generates the vulnerable app',
    activeAt: 'building',
    working: 'Building',
    done: () => 'Decoy app generated',
  },
  {
    key: 'contain',
    title: 'Contain',
    blurb: 'Isolated, hollow, no egress, disposable',
    activeAt: 'containing',
    working: 'Containing',
    done: () => 'Sandboxed · egress blocked · nothing real behind it',
  },
  {
    key: 'exploit',
    title: 'Exploit & track',
    blurb: 'Fires the PoC, then tracks every attacker',
    activeAt: 'published',
    working: 'Firing PoC',
    done: () => 'PoC confirmed · tracking attackers live',
  },
];

function stepState(step: Step, job: HoneypotJob) {
  if (job.status === 'failed') {
    if (step.key === 'research') return job.advisory ? 'done' : 'pending';
    if (step.key === 'build') return 'failed';
    return 'pending';
  }
  const at = ORDER.indexOf(job.status);
  const mine = ORDER.indexOf(step.activeAt);
  // The exploit step only runs after publishing, and resolves immediately in this view.
  if (step.key === 'exploit') return job.status === 'published' ? 'done' : 'pending';
  return at > mine ? 'done' : at === mine ? 'active' : 'pending';
}

export function NewHoneypot({ onViewDashboard }: { onViewDashboard: () => void }) {
  const [cve, setCve] = useState('');
  const [picked, setPicked] = useState<Set<string>>(() => new Set());
  const [error, setError] = useState<string | null>(null);
  const [job, setJob] = useState<HoneypotJob | null>(null);
  const [publishing, setPublishing] = useState(false);
  const [starting, setStarting] = useState(false);
  const [leaving, setLeaving] = useState(false);
  const selectAllRef = useRef<HTMLInputElement>(null);

  const running = job && !['ready', 'published', 'failed'].includes(job.status);
  const locked = !!job || starting;
  const allPicked = picked.size === PREBUILT.length;

  useEffect(() => {
    if (selectAllRef.current) selectAllRef.current.indeterminate = picked.size > 0 && !allPicked;
  }, [picked, allPicked]);

  const applyPick = (next: Set<string>) => {
    setPicked(next);
    if (next.size === 1) {
      setCve([...next][0]);
      setError(null);
      return;
    }
    setCve((current) => (PREBUILT_IDS.has(current.trim().toUpperCase()) ? '' : current));
  };

  const toggleCve = (id: string) => {
    const next = new Set(picked);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    applyPick(next);
  };

  const toggleAll = () => {
    applyPick(allPicked ? new Set() : new Set(PREBUILT_IDS));
  };

  useEffect(() => {
    if (!job || !running) return;
    const id = setTimeout(async () => {
      try {
        setJob(await getHoneypot(job.id));
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      }
    }, POLL_MS);
    return () => clearTimeout(id);
  }, [job, running]);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    const id = cve.trim().toUpperCase();
    if (!CVE_PATTERN.test(id)) {
      setError('Enter a CVE ID like CVE-2024-3400.');
      return;
    }
    setError(null);
    setCve(id);
    setStarting(true);
    await new Promise((r) => setTimeout(r, PRESS_MS));
    try {
      setJob(await createHoneypot(id));
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setStarting(false);
    }
  };

  const viewDashboard = () => {
    setLeaving(true);
    setTimeout(onViewDashboard, PRESS_MS);
  };

  const publish = async () => {
    if (!job) return;
    // Open the tab inside the click so popup blockers allow it, then point it at the decoy.
    const tab = window.open('', '_blank');
    setPublishing(true);
    try {
      const done = await publishHoneypot(job.id);
      setJob(done);
      if (tab && done.url) {
        tab.opener = null;
        tab.location.href = done.url;
      }
      // Ask the browser to keep the user here; most honor it for tabs opened from a click.
      window.focus();
    } catch (err) {
      tab?.close();
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setPublishing(false);
    }
  };

  const reset = () => {
    setJob(null);
    setCve('');
    setPicked(new Set());
    setError(null);
  };

  return (
    <main className="flow">
      <a className="flow-home" href="#">
        <img src="/angler-fish.png?v=4" alt="" />
        <span className="brand-name">Angler</span>
      </a>

      <div className="flow-stage">
      <aside className="prebuilt">
        <p className="flow-step-label">Prebuilt</p>
        <div className="prebuilt-card">
          <label className={`prebuilt-row prebuilt-all${allPicked ? ' is-selected' : ''}`}>
            <input
              ref={selectAllRef}
              type="checkbox"
              checked={allPicked}
              onChange={toggleAll}
              disabled={locked}
            />
            <span className={`prebuilt-mark${allPicked ? ' is-on' : picked.size > 0 ? ' is-some' : ''}`} aria-hidden />
            <span className="prebuilt-copy">
              <span className="prebuilt-id">Select all</span>
              <span className="prebuilt-name">
                {picked.size === 0 ? 'Profiles the decoy already answers' : `${picked.size} of ${PREBUILT.length} selected`}
              </span>
            </span>
          </label>
          {PREBUILT.map((item) => {
            const on = picked.has(item.id);
            return (
              <label key={item.id} className={`prebuilt-row${on ? ' is-selected' : ''}`}>
                <input type="checkbox" checked={on} onChange={() => toggleCve(item.id)} disabled={locked} />
                <span className={`prebuilt-mark${on ? ' is-on' : ''}`} aria-hidden />
                <span className="prebuilt-copy">
                  <span className="prebuilt-id">{item.id}</span>
                  <span className="prebuilt-name">{item.name}</span>
                </span>
              </label>
            );
          })}
        </div>
      </aside>

      <section className="flow-panel">
        <p className="flow-step-label">CVE in</p>
        <h1 className="flow-title">Which vulnerability should we impersonate?</h1>
        <form className="cve-form" onSubmit={submit}>
          <input
            className="cve-input"
            value={cve}
            onChange={(e) => {
              const value = e.target.value;
              setCve(value);
              const id = value.trim().toUpperCase();
              if (PREBUILT_IDS.has(id)) {
                setPicked(new Set([id]));
                setError(null);
              }
            }}
            placeholder="CVE-2024-3400"
            aria-label="CVE ID"
            spellCheck={false}
            autoComplete="off"
            disabled={!!job || starting}
            autoFocus
          />
          {!job && (
            <button className={`flow-btn${starting ? ' is-clicked' : ''}`} type="submit" disabled={starting}>
              Build honeypot <span aria-hidden>→</span>
            </button>
          )}
        </form>
        {error && <p className="flow-error">{error}</p>}

        {job && (
          <ol className="pipeline">
            {STEPS.map((step) => {
              const state = stepState(step, job);
              return (
                <li key={step.key} className={`pipe-step is-${state}`}>
                  <span className="pipe-node" aria-hidden>
                    {state === 'done' ? '✓' : state === 'failed' ? '!' : state === 'active' ? <span className="spinner" /> : null}
                  </span>
                  <div className="pipe-body">
                    <div className="pipe-head">
                      <span className="pipe-title">{step.title}</span>
                      <span className="pipe-status">
                        {state === 'failed' ? 'Failed' : state === 'done' ? 'Done' : state === 'active' ? `${step.working}…` : 'Waiting'}
                      </span>
                    </div>
                    <p className="pipe-detail">{state === 'failed' ? job.error || 'Failed' : state === 'done' ? step.done(job) : step.blurb}</p>
                  </div>
                </li>
              );
            })}
          </ol>
        )}

        {job && (job.status === 'ready' || job.status === 'published') && (
          <div className="flow-actions">
            <button
              type="button"
              className={`flow-btn publish-btn${job.status === 'published' ? ' is-published' : publishing ? ' is-clicked' : ''}`}
              onClick={publish}
              disabled={publishing || job.status === 'published'}
            >
              {job.status === 'published' ? 'Published ✓' : publishing ? 'Publishing…' : 'Ready to publish'}
            </button>
            {job.status === 'published' && (
              <button type="button" className={`flow-btn${leaving ? ' is-clicked' : ''}`} onClick={viewDashboard} disabled={leaving}>
                View dashboard <span aria-hidden>→</span>
              </button>
            )}
          </div>
        )}

        {job?.status === 'published' && (
          <p className="flow-note">
            Decoy for <span className="mono">{job.cve_id}</span> opened in a new tab.{' '}
            <button type="button" className="link-btn" onClick={reset}>
              Build another
            </button>
          </p>
        )}
      </section>
      </div>

      <SiteFooter tone="dark" />
    </main>
  );
}
