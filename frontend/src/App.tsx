import { useMemo, useRef, useState } from 'react';
import { Badge, Banner, BlockStack, Button, Icon, InlineGrid, SkeletonBodyText, Card, Text, TextField, Tooltip } from '@shopify/polaris';
import { GlobeIcon, HideIcon, MaximizeIcon, SearchIcon, ViewIcon } from '@shopify/polaris-icons';
import { AttackGlobe, type AttackGlobeHandle } from './components/AttackGlobe';
import { MetricCard } from './components/MetricCard';
import { BehaviorCard, LocationCard, NoiseCard } from './components/Panels';
import { ActorsCard, CveLeaderboard, EventStream } from './components/Tables';
import { usingMock } from './data/api';
import { HONEYPOT, TAGLINE } from './data/config';
import { hitsByCve, minuteSeries, stageBreakdown, topLocations } from './data/derive';
import { useLive } from './data/useLive';
import type { AttackEvent } from './data/types';

const matches = (e: AttackEvent, q: string) =>
  [e.source_ip, e.cve_id, e.city, e.country, e.region, e.org, `AS${e.asn}`, String(e.port)].some((f) =>
    f?.toLowerCase().includes(q),
  );

export default function App() {
  const { data, error, updatedAt } = useLive();
  const globe = useRef<AttackGlobeHandle>(null);
  const [query, setQuery] = useState('');
  const [showNoise, setShowNoise] = useState(true);
  const [autoRotate, setAutoRotate] = useState(true);

  const now = updatedAt ?? Date.now();
  const q = query.trim().toLowerCase();
  const events = useMemo(() => (data && q ? data.events.filter((h) => matches(h, q)) : data?.events ?? []), [data, q]);

  const onSearch = (e: React.FormEvent) => {
    e.preventDefault();
    const hit = events.find((e) => e.lat != null && e.lng != null);
    if (hit) {
      setAutoRotate(false);
      globe.current?.flyTo(hit.lat!, hit.lng!);
    }
  };

  const derived = useMemo(() => {
    if (!data) return null;
    const series = minuteSeries(data.events, now);
    return {
      series,
      hitSpark: series.map((p) => p.noise + p.targeted),
      stages: stageBreakdown(data.events, now),
      locations: topLocations(data.events),
      cveHits: hitsByCve(data.events),
    };
  }, [data, now]);

  return (
    <div className="shell">
      <header className="topbar">
        <div className="brand">
          <img src="/angler-logo.png" alt="" />
          <div className="brand-text">
            <span className="brand-name">Angler</span>
            <span className="brand-tagline">{TAGLINE}</span>
          </div>
        </div>
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
            <Tooltip content="No backend configured (VITE_API_URL). Showing simulated traffic.">
              <Badge>Simulated feed</Badge>
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
                  help={`Every request the honeypot received, noise included. Last ${data.stats.window ?? '24h'}. Sparkline: last 30 minutes.`}
                  value={data.stats.total_hits.toLocaleString()}
                  spark={derived.hitSpark}
                  wide
                />
                <InlineGrid columns={2} gap="300">
                  <MetricCard
                    title="New CVEs"
                    help={`CVEs first published in the last ${data.stats.window ?? '24h'}.`}
                    value={data.stats.new_cves.toLocaleString()}
                  />
                  <MetricCard
                    title="Updated CVEs"
                    help={`Existing CVE records that changed in the last ${data.stats.window ?? '24h'}.`}
                    value={data.stats.updated_cves.toLocaleString()}
                  />
                  <MetricCard
                    title="Newly patched"
                    help={`CVEs that got a vendor fix in the last ${data.stats.window ?? '24h'}.`}
                    value={data.stats.newly_patched.toLocaleString()}
                  />
                  <MetricCard
                    title="Newly KEV"
                    help={`CVEs added to CISA's Known Exploited Vulnerabilities catalog in the last ${data.stats.window ?? '24h'}.`}
                    value={data.stats.newly_kev.toLocaleString()}
                  />
                </InlineGrid>
                <NoiseCard series={derived.series} />
                <EventStream events={events} now={now} />
                <CveLeaderboard cves={data.cves} hits={derived.cveHits} />
                <ActorsCard actors={data.actors} now={now} />
                {derived.stages.any && <BehaviorCard breakdown={derived.stages} />}
                {derived.locations.length > 0 && <LocationCard locations={derived.locations} />}
              </>
            )}
          </BlockStack>
        </section>

        <section className="globe-pane" aria-label="Attack map">
          {data && <AttackGlobe ref={globe} events={data.events} honeypot={HONEYPOT} showNoise={showNoise} autoRotate={autoRotate} />}
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
              <span className="swatch" style={{ background: '#fff', boxShadow: '0 0 0 3px #4137cb inset' }} /> Honeypot
            </span>
          </div>
        </section>
      </main>
    </div>
  );
}

function TitleGroup({ children }: { children: React.ReactNode }) {
  return <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>{children}</div>;
}
