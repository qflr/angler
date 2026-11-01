import { useEffect, useMemo, useState, type CSSProperties } from 'react';
import { TAGLINE } from '../data/config';
import { minuteSeries } from '../data/derive';
import type { LiveData } from '../data/types';
import { AnglerFish } from './AnglerFish';
import { SiteFooter } from './SiteFooter';

const SLIDE_MS = 3200;
// Length of the bite animation on Get started; navigation waits for it.
const SNAP_MS = 1700;

interface Props {
  data: LiveData | null;
  now: number;
  onEnter: () => void;
}

export function Landing({ data, now, onEnter }: Props) {
  const slides = useMemo(() => {
    if (!data) return [];
    const series = minuteSeries(data.events, now);
    const noise = series.reduce((n, p) => n + p.noise, 0);
    const targeted = series.reduce((n, p) => n + p.targeted, 0);
    const window = data.stats.window ?? '24h';
    return [
      { value: data.stats.total_hits.toLocaleString(), label: `hits on our decoys · last ${window}` },
      { value: `${Math.round((targeted / (noise + targeted || 1)) * 100)}%`, label: 'aimed at a specific CVE' },
      { value: data.stats.new_cves.toLocaleString(), label: `new CVEs published · last ${window}` },
      { value: data.stats.newly_kev.toLocaleString(), label: 'newly confirmed exploited in the wild' },
      {
        value: data.actors.filter((a) => a.classification === 'targeted').length.toLocaleString(),
        label: 'targeted attackers fingerprinted',
      },
    ];
  }, [data, now]);

  const [active, setActive] = useState(0);
  const [snapping, setSnapping] = useState(false);

  const getStarted = () => {
    if (snapping) return;
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return onEnter();
    setSnapping(true);
    setTimeout(onEnter, SNAP_MS);
  };
  useEffect(() => {
    if (!slides.length) return;
    const id = setTimeout(() => setActive((i) => (i + 1) % slides.length), SLIDE_MS);
    return () => clearTimeout(id);
  }, [active, slides.length]);

  return (
    <main className="landing" style={{ '--slide-ms': `${SLIDE_MS}ms` } as CSSProperties}>
      <div className={`landing-mark${snapping ? ' is-snapping' : ''}`} style={{ '--snap-ms': `${SNAP_MS}ms` } as CSSProperties}>
        <AnglerFish className="landing-fish" />
        <h1 className="landing-title">Angler</h1>
        <p className="landing-tagline">{TAGLINE}</p>
      </div>

      <section className="ticker" aria-live="polite" aria-label="Live overview">
        <div className="ticker-stage">
          {slides.map((s, i) => (
            <div key={s.label} className={`ticker-slide${i === active ? ' is-active' : ''}`} aria-hidden={i !== active}>
              <span className="ticker-value">{s.value}</span>
              <span className="ticker-label">{s.label}</span>
            </div>
          ))}
        </div>
        <div className="ticker-dots">
          {slides.map((s, i) => (
            <button
              key={s.label}
              type="button"
              className={i === active ? 'is-active' : undefined}
              aria-label={`Show: ${s.label}`}
              onClick={() => setActive(i)}
            />
          ))}
        </div>
      </section>

      <button type="button" className={`landing-cta${snapping ? ' is-clicked' : ''}`} onClick={getStarted}>
        Get started <span aria-hidden>→</span>
      </button>

      <SiteFooter tone="dark" showTagline={false} />
    </main>
  );
}
