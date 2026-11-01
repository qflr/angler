import { useEffect, useMemo, useRef, useState } from 'react';
import { Badge, Banner, BlockStack, Button, Icon, InlineGrid, SkeletonBodyText, Card, Text, TextField, Tooltip } from '@shopify/polaris';
import { GlobeIcon, HideIcon, MaximizeIcon, SearchIcon, ViewIcon } from '@shopify/polaris-icons';
import { AttackGlobe, type AttackGlobeHandle } from './components/AttackGlobe';
import { Landing } from './components/Landing';
import { NewHoneypot } from './components/NewHoneypot';
import { SiteFooter } from './components/SiteFooter';
import { MetricCard } from './components/MetricCard';
import { BehaviorCard, LocationCard, NoiseCard } from './components/Panels';
import { ActorsCard, CveFocusCard, CveLeaderboard, EventStream } from './components/Tables';
import { ActorDetail } from './components/ActorDetail';
import { usingMock } from './data/api';
import { HONEYPOT } from './data/config';
import { hitsByCve, minuteSeries, stageBreakdown, topLocations } from './data/derive';
import { useLive } from './data/useLive';
import type { Actor, AttackEvent } from './data/types';

const matches = (e: AttackEvent, q: string) =>
  [e.source_ip, e.cve_id, e.city, e.country, e.region, e.org, `AS${e.asn}`, String(e.port)].some((f) =>
    f?.toLowerCase().includes(q),
  );

// "#/new" is CVE in (the honeypot pipeline), "#/live" the dashboard, anything else the landing page.
type View = 'landing' | 'new' | 'live';
const viewFromHash = (): View =>
  window.location.hash === '#/live' ? 'live' : window.location.hash === '#/new' ? 'new' : 'landing';

function useView() {
  const [view, setView] = useState(viewFromHash);
  useEffect(() => {
    const onHash = () => setView(viewFromHash());
    window.addEventListener('hashchange', onHash);
    return () => window.removeEventListener('hashchange', onHash);
  }, []);
  return view;
}

export default function App() {
  const { data, error, updatedAt } = useLive();
  const view = useView();
  const globe = useRef<AttackGlobeHandle>(null);
  const [query, setQuery] = useState('');
  const [showNoise, setShowNoise] = useState(true);
  const [autoRotate, setAutoRotate] = useState(true);
  // 'all' or the CVE ID of a published honeypot.
  const [tab, setTab] = useState<string>('all');
  const [openActor, setOpenActor] = useState<Actor | null>(null);

  const now = updatedAt ?? Date.now();
  const q = query.trim().toLowerCase();

  // One published honeypot = one tab; everything below reads `scoped` so the tab filters every panel.
  const tabs = data?.honeypots ?? [];
  const activeTab = tab !== 'all' && tabs.some((h) => h.cve_id === tab) ? tab : 'all';
  const scoped = useMemo(() => {
    if (!data || activeTab === 'all') return data;
    const events = data.events.filter((e) => e.cve_id === activeTab);
    return {
      ...data,
      events,
      actors: data.actors.filter((a) => a.cves?.includes(activeTab)),
      cves: data.cves.filter((c) => c.id === activeTab),
      stats: { ...data.stats, total_hits: events.length },
    };
  }, [data, activeTab]);

  const events = useMemo(
    () => (scoped && q ? scoped.events.filter((h) => matches(h, q)) : scoped?.events ?? []),
    [scoped, q],
  );

  const onSearch = (e: React.FormEvent) => {
    e.preventDefault();
    const hit = events.find((e) => e.lat != null && e.lng != null);
    if (hit) {
      setAutoRotate(false);
      globe.current?.flyTo(hit.lat!, hit.lng!);
    }
  };

  const derived = useMemo(() => {
    if (!scoped) return null;
    const series = minuteSeries(scoped.events, now);
    return {
      series,
      hitSpark: series.map((p) => p.noise + p.targeted),
      stages: stageBreakdown(scoped.events, now),
      locations: topLocations(scoped.events),
      cveHits: hitsByCve(scoped.events),
    };
  }, [scoped, now]);

  if (view === 'landing') {
    return <Landing data={data} now={now} onEnter={() => (window.location.hash = '#/new')} />;
  }
  if (view === 'new') {
    return <NewHoneypot onViewDashboard={() => (window.location.hash = '#/live')} />;
  }

  return (
    <div className="shell">
      <header className="topbar">
        <button type="button" className="brand" onClick={() => (window.location.hash = '')} aria-label="Angler home">
          <img src="/angler-logo.png?v=6" alt="" />
          <span className="brand-name">Angler</span>
        </button>
        <span className="divider-dot" />
        <TitleGroup>
          <Icon source={GlobeIcon} tone="subdued" />
          <Text as="h1" variant="headingMd">
            Live View
          </Text>
          <span className="live-dot" />
          <Text as="span" variant="bodyMd" tone="subdued">
            {updatedAt && Date.now() - updatedAt < 10_000 ? 'Just now' : 'Connecting…'}
          </Text>
          {usingMock && (
            <Tooltip content="Demo mode: simulated traffic for presentation. Switch to Live on the home page for real decoy data.">
              <Badge tone="attention">Demo mode</Badge>
            </Tooltip>
          )}
        </TitleGroup>
        <div className="topbar-right">
          <form className="topbar-search" onSubmit={onSearch}>
            <TextField
              label="Search"
              labelHidden
              autoComplete="off"
              placeholder="Search IP, CVE, ASN or location"
              prefix={<Icon source={SearchIcon} />}
              value={query}
              onChange={setQuery}
              clearButton
              onClearButtonClick={() => setQuery('')}
            />
          </form>
          <Tooltip content={showNoise ? 'Hide background noise' : 'Show background noise'}>
            <Button icon={showNoise ? ViewIcon : HideIcon} variant="tertiary" onClick={() => setShowNoise((v) => !v)} accessibilityLabel="Toggle noise" />
          </Tooltip>
          <Tooltip content={autoRotate ? 'Stop rotation' : 'Rotate globe'}>
            <Button icon={GlobeIcon} variant="tertiary" pressed={autoRotate} onClick={() => setAutoRotate((v) => !v)} accessibilityLabel="Toggle rotation" />
          </Tooltip>
          <Tooltip content="Full screen">
            <Button
              icon={MaximizeIcon}
              variant="tertiary"
              onClick={() => (document.fullscreenElement ? document.exitFullscreen() : document.documentElement.requestFullscreen())}
              accessibilityLabel="Full screen"
            />
          </Tooltip>
        </div>
      </header>

      {tabs.length > 0 && (
        <nav className="cve-tabs" aria-label="Honeypots">
          <button type="button" className={`cve-tab${activeTab === 'all' ? ' is-active' : ''}`} onClick={() => setTab('all')}>
            All traffic
            <span className="cve-tab-count">{data?.events.length ?? 0}</span>
          </button>
          {tabs.map((h) => (
            <button
              key={h.cve_id}
              type="button"
              className={`cve-tab${activeTab === h.cve_id ? ' is-active' : ''}`}
              onClick={() => setTab(h.cve_id)}
              title={h.advisory?.description ?? undefined}
            >
              {h.cve_id}
              {h.advisory?.product && <span className="cve-tab-product">{h.advisory.product}</span>}
              <span className="cve-tab-count">{data?.events.filter((e) => e.cve_id === h.cve_id).length ?? 0}</span>
            </button>
          ))}
        </nav>
      )}

      <main className="main">
        <section className="rail">
          <BlockStack gap="300">
            {error && (
              <Banner tone="critical" title="Lost connection to the capture service">
                <p>{error}. Retrying every few seconds.</p>
              </Banner>
            )}
            {!data || !derived ? (
              <Card>
                <SkeletonBodyText lines={6} />
              </Card>
            ) : (
              <>
                <MetricCard
                  title="Total hits"
                  help={`Every request the honeypot received, noise included. Last ${scoped!.stats.window ?? '24h'}. Sparkline: last 30 minutes.`}
                  value={scoped!.stats.total_hits.toLocaleString()}
                  spark={derived.hitSpark}
                  wide
                />
                <InlineGrid columns={2} gap="300">
                  <MetricCard
                    title="New CVEs"
                    help={`CVEs first published in the last ${scoped!.stats.window ?? '24h'}.`}
                    value={scoped!.stats.new_cves.toLocaleString()}
                  />
                  <MetricCard
                    title="Updated CVEs"
                    help={`Existing CVE records that changed in the last ${scoped!.stats.window ?? '24h'}.`}
                    value={scoped!.stats.updated_cves.toLocaleString()}
                  />
                  <MetricCard
                    title="Newly patched"
                    help={`CVEs that got a vendor fix in the last ${scoped!.stats.window ?? '24h'}.`}
                    value={scoped!.stats.newly_patched.toLocaleString()}
                  />
                  <MetricCard
                    title="Newly KEV"
                    help={`CVEs added to CISA's Known Exploited Vulnerabilities catalog in the last ${scoped!.stats.window ?? '24h'}.`}
                    value={scoped!.stats.newly_kev.toLocaleString()}
                  />
                </InlineGrid>
                <NoiseCard series={derived.series} />
                <EventStream events={events} now={now} />
                {/* The leaderboard ranks every recognised CVE, so it only belongs on "All traffic". */}
                {activeTab === 'all' ? (
                  <CveLeaderboard cves={scoped!.cves} hits={derived.cveHits} />
                ) : (
                  <CveFocusCard
                    cveId={activeTab}
                    cve={scoped!.cves[0]}
                    fallback={tabs.find((h) => h.cve_id === activeTab)?.advisory}
                    hits={derived.cveHits.get(activeTab)}
                  />
                )}
                <ActorsCard actors={scoped!.actors} now={now} onSelect={setOpenActor} />
                {derived.stages.any && <BehaviorCard breakdown={derived.stages} />}
                {derived.locations.length > 0 && <LocationCard locations={derived.locations} />}
                <SiteFooter />
              </>
            )}
          </BlockStack>
        </section>

        <section className="globe-pane" aria-label="Attack map">
          {scoped && <AttackGlobe ref={globe} events={scoped.events} honeypot={HONEYPOT} showNoise={showNoise} autoRotate={autoRotate} />}
          <div className="globe-legend">
            <span className="legend-chip">
              <span className="swatch swatch-targeted" /> Targeted
            </span>
            {showNoise && (
              <span className="legend-chip">
                <span className="swatch swatch-noise" /> Background noise
              </span>
            )}
            <span className="legend-chip">
              <span className="swatch" style={{ background: '#fff', boxShadow: '0 0 0 3px #080505 inset' }} /> Honeypot
            </span>
          </div>
        </section>
      </main>
      {openActor && <ActorDetail actor={openActor} events={data?.events ?? []} now={now} onClose={() => setOpenActor(null)} />}
    </div>
  );
}

function TitleGroup({ children }: { children: React.ReactNode }) {
  return <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>{children}</div>;
}
