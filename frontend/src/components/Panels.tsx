import { BlockStack, Card, InlineStack, Text, Tooltip } from '@shopify/polaris';
import { Area, AreaChart, ResponsiveContainer, Tooltip as ChartTooltip, XAxis, YAxis } from 'recharts';
import type { SeriesPoint, stageBreakdown } from '../data/derive';
import type { Stage } from '../data/types';
import { clock } from './format';

function CardTitle({ children, help }: { children: string; help: string }) {
  return (
    <InlineStack>
      <Tooltip content={help}>
        <span className="metric-title">
          <Text as="h3" variant="headingSm">
            {children}
          </Text>
        </span>
      </Tooltip>
    </InlineStack>
  );
}

// --- Noise vs targeted: the signature view -------------------------------------

export function NoiseCard({ series }: { series: SeriesPoint[] }) {
  const noise = series.reduce((n, p) => n + p.noise, 0);
  const targeted = series.reduce((n, p) => n + p.targeted, 0);
  const total = noise + targeted || 1;
  const data = series.map((p) => ({ ...p, label: clock(new Date(p.t).toISOString()).slice(0, 5) }));

  return (
    <Card>
      <BlockStack gap="400">
        <CardTitle help="Background noise is untargeted internet scanning. Targeted hits carry a probe or exploit for a CVE our honeypot impersonates.">
          Noise vs targeted
        </CardTitle>
        <InlineStack gap="800">
          <BlockStack gap="100">
            <InlineStack gap="200" blockAlign="center">
              <span className="swatch swatch-noise" />
              <Text as="span" variant="bodyMd" tone="subdued">
                Background noise
              </Text>
            </InlineStack>
            <Text as="p" variant="headingLg">
              {Math.round((noise / total) * 100)}%
            </Text>
          </BlockStack>
          <BlockStack gap="100">
            <InlineStack gap="200" blockAlign="center">
              <span className="swatch swatch-targeted" />
              <Text as="span" variant="bodyMd" tone="subdued">
                Targeting our CVEs
              </Text>
            </InlineStack>
            <Text as="p" variant="headingLg">
              {Math.round((targeted / total) * 100)}%
            </Text>
          </BlockStack>
        </InlineStack>
        <div className="split-bar">
          <span style={{ width: `${(noise / total) * 100}%`, background: 'var(--angler-noise)' }} />
          <span style={{ width: `${(targeted / total) * 100}%`, background: 'var(--angler-bright-indigo)' }} />
        </div>
        <div style={{ height: 150 }}>
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={data} margin={{ top: 4, right: 4, bottom: 0, left: -28 }}>
              <defs>
                <linearGradient id="gTargeted" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#4137cb" stopOpacity={0.35} />
                  <stop offset="100%" stopColor="#4137cb" stopOpacity={0.02} />
                </linearGradient>
                <linearGradient id="gNoise" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#a3a8c3" stopOpacity={0.35} />
                  <stop offset="100%" stopColor="#a3a8c3" stopOpacity={0.02} />
                </linearGradient>
              </defs>
              <XAxis dataKey="label" tick={{ fontSize: 11, fill: '#5e5b74' }} tickLine={false} axisLine={false} interval={9} />
              <YAxis allowDecimals={false} tick={{ fontSize: 11, fill: '#5e5b74' }} tickLine={false} axisLine={false} />
              <ChartTooltip
                contentStyle={{ borderRadius: 10, border: '1px solid #e6e8f2', fontSize: 12 }}
                labelStyle={{ color: '#0e0c25', fontWeight: 600 }}
              />
              <Area type="monotone" dataKey="noise" name="Noise" stackId="1" stroke="#a3a8c3" fill="url(#gNoise)" strokeWidth={1.5} isAnimationActive={false} />
              <Area type="monotone" dataKey="targeted" name="Targeted" stackId="1" stroke="#4137cb" fill="url(#gTargeted)" strokeWidth={1.75} isAnimationActive={false} />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </BlockStack>
    </Card>
  );
}

// --- Attack behavior (kill-chain funnel) -------------------------------------

const STAGES: { key: Stage; label: string }[] = [
  { key: 'recon', label: 'Recon' },
  { key: 'probe', label: 'Probing' },
  { key: 'exploit', label: 'Exploit attempts' },
];

export function BehaviorCard({ breakdown }: { breakdown: ReturnType<typeof stageBreakdown> }) {
  const max = Math.max(1, ...STAGES.map((s) => breakdown.counts[s.key]));
  return (
    <Card>
      <BlockStack gap="400">
        <CardTitle help="How far each request got: crawling for anything, fingerprinting a product, or sending an exploit payload. Last 30 minutes.">
          Attack behavior
        </CardTitle>
        <div className="stage-grid">
          {STAGES.map((s) => (
            <div className="stage-col" key={s.key}>
              <Text as="p" variant="bodyMd">
                {s.label}
              </Text>
              <Text as="p" variant="headingLg">
                {breakdown.counts[s.key]}
              </Text>
              <div className="stage-meter">
                <span style={{ width: `${(breakdown.counts[s.key] / max) * 100}%` }} />
              </div>
              <BlockStack gap="100">
                {breakdown.topPaths[s.key].map((p) => (
                  <Tooltip content={p} key={p}>
                    <div className="mono truncate" style={{ color: 'var(--angler-dusty-grape)' }}>
                      {p}
                    </div>
                  </Tooltip>
                ))}
              </BlockStack>
            </div>
          ))}
        </div>
      </BlockStack>
    </Card>
  );
}

// --- Hits by location --------------------------------------------------------

export function LocationCard({ locations }: { locations: { label: string; count: number }[] }) {
  const max = Math.max(1, ...locations.map((l) => l.count));
  return (
    <Card>
      <BlockStack gap="400">
        <CardTitle help="Where recent requests originate, by IP geolocation.">Hits by location</CardTitle>
        <BlockStack gap="300">
          {locations.map((l) => (
            <BlockStack gap="100" key={l.label}>
              <Text as="p" variant="bodyMd" tone="subdued">
                {l.label}
              </Text>
              <div className="bar-row">
                <div className="bar-track">
                  <div className="bar-fill" style={{ width: `${(l.count / max) * 100}%` }} />
                </div>
                <Text as="span" variant="bodyMd" tone="subdued">
                  {l.count}
                </Text>
              </div>
            </BlockStack>
          ))}
        </BlockStack>
      </BlockStack>
    </Card>
  );
}

export { CardTitle };
