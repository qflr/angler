import { useEffect, useState } from 'react';
import { fetchActorDetail, usingMock, type ActorDetailData } from '../data/api';
import type { Actor, AttackEvent } from '../data/types';
import { ClassBadge } from './Tables';
import { ago, flag } from './format';

/** Simulated mode has no /api/actors/{id}; build the same view from the events already on screen. */
function fromEvents(actor: Actor, events: AttackEvent[]): ActorDetailData {
  const ips = new Set(actor.ips);
  const mine = events.filter((e) => ips.has(e.source_ip));
  const counts = new Map<string, number>();
  for (const e of mine) if (e.path) counts.set(e.path, (counts.get(e.path) ?? 0) + 1);
  return {
    ...actor,
    user_agents: [],
    download_urls: [],
    paths: [...counts].sort((a, b) => b[1] - a[1]).slice(0, 15).map(([path, count]) => ({ path, count })),
    hits: mine.slice(0, 200).map((e) => ({ ...e, body_preview: null, user_agent: null })),
  };
}

export function ActorDetail({ actor, events, now, onClose }: { actor: Actor; events: AttackEvent[]; now: number; onClose: () => void }) {
  const [detail, setDetail] = useState<ActorDetailData | null>(usingMock ? fromEvents(actor, events) : null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (usingMock) return;
    let alive = true;
    fetchActorDetail(actor.id)
      .then((d) => alive && setDetail(d))
      .catch((e) => alive && setError(e instanceof Error ? e.message : String(e)));
    return () => {
      alive = false;
    };
  }, [actor.id]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose();
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  const d = detail;
  return (
    <div className="actor-overlay" onClick={onClose} role="presentation">
      <aside className="actor-panel" onClick={(e) => e.stopPropagation()} role="dialog" aria-label={`Attacker ${actor.label}`}>
        <header className="actor-head">
          <div>
            <h2>
              <span className={`swatch swatch-${actor.classification}`} /> {actor.label} <ClassBadge cls={actor.classification} />
            </h2>
            <p>
              {actor.hit_count} hits · first seen {ago(actor.first_seen, now)} · last seen {ago(actor.last_seen, now)}
              {actor.countries?.length ? ` · ${actor.countries.map(flag).join(' ')}` : ''}
            </p>
          </div>
          <button type="button" className="actor-close" onClick={onClose} aria-label="Close">
            ×
          </button>
        </header>

        {error && <p className="actor-error">Could not load this attacker: {error}</p>}
        {!d && !error && <p className="actor-muted">Loading…</p>}
        {d && (
          <div className="actor-body">
            <section>
              <h3>Infrastructure</h3>
              <dl className="actor-facts">
                <dt>IPs</dt>
                <dd>{d.ips.join(', ')}</dd>
                <dt>ASNs</dt>
                <dd>{d.asns.length ? d.asns.map((a) => `AS${a}`).join(', ') : 'unresolved'}</dd>
                <dt>Tags</dt>
                <dd>{d.tags?.length ? d.tags.join(', ') : 'none'}</dd>
                {d.timezone && (
                  <>
                    <dt>Active</dt>
                    <dd>{d.timezone}</dd>
                  </>
                )}
                <dt>CVEs tried</dt>
                <dd>{d.cves?.length ? d.cves.join(', ') : 'none recognised'}</dd>
              </dl>
            </section>

            {d.download_urls.length > 0 && (
              <section>
                <h3>Malware download URLs (from payloads, not visited)</h3>
                <ul className="actor-mono">
                  {d.download_urls.map((u) => (
                    <li key={u}>{u}</li>
                  ))}
                </ul>
              </section>
            )}

            {d.user_agents.length > 0 && (
              <section>
                <h3>User agents</h3>
                <ul className="actor-mono">
                  {d.user_agents.map((u) => (
                    <li key={u}>{u}</li>
                  ))}
                </ul>
              </section>
            )}

            <section>
              <h3>What they tried</h3>
              <ul className="actor-mono">
                {d.paths.map((p) => (
                  <li key={p.path}>
                    <span className="actor-count">{p.count}×</span> {p.path}
                  </li>
                ))}
              </ul>
            </section>

            <section>
              <h3>Request log</h3>
              <ol className="actor-log">
                {d.hits.map((h) => (
                  <li key={h.id}>
                    <div className="actor-log-line">
                      <span className="actor-muted">{ago(h.timestamp, now)}</span>
                      <span className="actor-mono">
                        {h.method} {h.path}
                      </span>
                      {h.stage && <span className={`actor-stage stage-${h.stage}`}>{h.stage}</span>}
                      {h.cve_id && <span className="actor-cve">{h.cve_id}</span>}
                    </div>
                    {h.body_preview && <pre className="actor-payload">{h.body_preview}</pre>}
                  </li>
                ))}
              </ol>
            </section>
          </div>
        )}
      </aside>
    </div>
  );
}
