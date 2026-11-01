import { useRef } from 'react';
import { Badge, BlockStack, Box, Card, IndexTable, InlineStack, Text, Tooltip } from '@shopify/polaris';
import type { hitsByCve } from '../data/derive';
import type { Actor, AttackEvent, Classification, Cve, SourceTag } from '../data/types';
import { CardTitle } from './Panels';
import { ago, clock, flag } from './format';

const STATUS_TONE = { urgent: 'critical', high: 'warning', watch: 'info' } as const;
const SEVERITY_TONE = { critical: 'critical-strong', high: 'warning', medium: 'attention', low: undefined } as const;
const PATCH_TONE = { patched: 'success', partial: 'attention', unpatched: 'critical' } as const;
const STATUS_RANK = { urgent: 0, high: 1, watch: 2 } as const;
const TAG_LABEL: Record<SourceTag, string> = {
  tor: 'Tor',
  vpn: 'VPN',
  cloud: 'Cloud',
  residential: 'Residential',
  scanner: 'Known scanner',
};

const cap = (s: string) => s[0].toUpperCase() + s.slice(1);

export function ClassBadge({ cls }: { cls: Classification }) {
  return cls === 'targeted' ? <Badge tone="magic">Targeted</Badge> : <Badge>Noise</Badge>;
}

// --- Live event stream -------------------------------------------------------

export function EventStream({ events, now }: { events: AttackEvent[]; now: number }) {
  const seen = useRef<Set<string> | null>(null);
  const fresh = new Set<string>();
  if (seen.current) for (const e of events) if (!seen.current.has(e.id)) fresh.add(e.id);
  seen.current = new Set(events.map((e) => e.id));

  const rows = events.slice(0, 10);

  return (
    <Card padding="0">
      <Box padding="400" paddingBlockEnd="200">
        <CardTitle help="Every request the honeypot receives, newest first.">Live event stream</CardTitle>
      </Box>
      <IndexTable
        resourceName={{ singular: 'hit', plural: 'hits' }}
        itemCount={rows.length}
        selectable={false}
        headings={[{ title: 'Time' }, { title: 'Source' }, { title: 'Port' }, { title: 'Request' }, { title: 'Class' }]}
      >
        {rows.map((e, i) => {
          const cell = fresh.has(e.id) ? 'event-new' : undefined;
          return (
            <IndexTable.Row id={e.id} key={e.id} position={i}>
              <IndexTable.Cell className={cell}>
                <Tooltip content={clock(e.timestamp)}>
                  <Text as="span" variant="bodySm" tone="subdued">
                    {ago(e.timestamp, now)}
                  </Text>
                </Tooltip>
              </IndexTable.Cell>
              <IndexTable.Cell className={cell}>
                <BlockStack gap="050">
                  <span className="mono">{e.source_ip}</span>
                  <Text as="span" variant="bodySm" tone="subdued">
                    {e.country_code ? `${flag(e.country_code)} ` : ''}
                    {e.city ? `${e.city} · ` : ''}AS{e.asn}
                  </Text>
                </BlockStack>
              </IndexTable.Cell>
              <IndexTable.Cell className={cell}>
                <span className="mono">{e.port}</span>
              </IndexTable.Cell>
              <IndexTable.Cell className={cell}>
                <div style={{ maxWidth: 160 }}>
                  {e.path && (
                    <Tooltip content={`${e.method ?? ''} ${e.path}`}>
                      <div className="mono truncate">
                        {e.method && <span style={{ color: 'var(--angler-dusty-grape)' }}>{e.method}</span>} {e.path}
                      </div>
                    </Tooltip>
                  )}
                  {e.cve_id && (
                    <Text as="span" variant="bodySm" tone="magic">
                      {e.cve_id}
                    </Text>
                  )}
                </div>
              </IndexTable.Cell>
              <IndexTable.Cell className={cell}>
                <ClassBadge cls={e.classification} />
              </IndexTable.Cell>
            </IndexTable.Row>
          );
        })}
      </IndexTable>
    </Card>
  );
}

// --- CVE leaderboard ---------------------------------------------------------

export function CveLeaderboard({ cves, hits }: { cves: Cve[]; hits: ReturnType<typeof hitsByCve> }) {
  const rows = [...cves].sort(
    (a, b) =>
      (hits.get(b.id)?.targeted ?? 0) - (hits.get(a.id)?.targeted ?? 0) ||
      STATUS_RANK[a.status] - STATUS_RANK[b.status],
  );
  return (
    <Card padding="0">
      <Box padding="400" paddingBlockEnd="200">
        <CardTitle help="Tracked CVEs, ranked by targeted traffic against our decoys, then by triage status.">
          CVE leaderboard
        </CardTitle>
      </Box>
      <IndexTable
        resourceName={{ singular: 'CVE', plural: 'CVEs' }}
        itemCount={rows.length}
        selectable={false}
        headings={[
          { title: 'CVE' },
          { title: 'Status' },
          { title: 'Severity' },
          { title: 'Patch' },
          { title: 'Hits', alignment: 'end' },
        ]}
      >
        {rows.map((c, i) => {
          const h = hits.get(c.id);
          return (
            <IndexTable.Row id={c.id} key={c.id} position={i}>
              <IndexTable.Cell>
                <BlockStack gap="050">
                  <InlineStack gap="150" blockAlign="center" wrap={false}>
                    <span className="mono" style={{ fontSize: 13, fontWeight: 600 }}>
                      {c.id}
                    </span>
                    {c.kev && (
                      <Tooltip content="In CISA's Known Exploited Vulnerabilities catalog">
                        <Badge tone="critical" size="small">
                          KEV
                        </Badge>
                      </Tooltip>
                    )}
                  </InlineStack>
                  <div style={{ maxWidth: 190 }}>
                    <Tooltip content={c.description}>
                      <div className="truncate">
                        <Text as="span" variant="bodySm" tone="subdued">
                          {c.product ? `${c.product} · ` : ''}
                          {c.description}
                        </Text>
                      </div>
                    </Tooltip>
                  </div>
                </BlockStack>
              </IndexTable.Cell>
              <IndexTable.Cell>
                <Badge tone={STATUS_TONE[c.status]}>{cap(c.status)}</Badge>
              </IndexTable.Cell>
              <IndexTable.Cell>
                <Tooltip content={`${cap(c.severity)}${c.cvss != null ? ` · CVSS ${c.cvss.toFixed(1)}` : ''}`}>
                  <Badge tone={SEVERITY_TONE[c.severity]}>
                    {c.cvss != null ? c.cvss.toFixed(1) : cap(c.severity)}
                  </Badge>
                </Tooltip>
              </IndexTable.Cell>
              <IndexTable.Cell>
                <Badge tone={PATCH_TONE[c.patch_status]}>{cap(c.patch_status)}</Badge>
              </IndexTable.Cell>
              <IndexTable.Cell>
                <Text as="span" alignment="end" numeric>
                  {h ? (
                    <>
                      {h.targeted}
                      <Text as="span" tone="subdued">
                        {' '}/ {h.hits}
                      </Text>
                    </>
                  ) : (
                    <Text as="span" tone="subdued">
                      —
                    </Text>
                  )}
                </Text>
              </IndexTable.Cell>
            </IndexTable.Row>
          );
        })}
      </IndexTable>
    </Card>
  );
}

// --- Attacker dossiers -------------------------------------------------------

export function ActorsCard({ actors, now }: { actors: Actor[]; now: number }) {
  return (
    <Card>
      <BlockStack gap="400">
        <CardTitle help="Many IPs collapsed into one actor using shared fingerprints: user agent, request order, ASN mix and activity rhythm.">
          Attackers
        </CardTitle>
        <BlockStack gap="300">
          {actors.slice(0, 6).map((a, i) => (
            <Box
              key={a.id}
              paddingBlockStart={i ? '300' : '0'}
              borderBlockStartWidth={i ? '025' : undefined}
              borderColor="border-secondary"
            >
              <BlockStack gap="150">
                <InlineStack align="space-between" blockAlign="center">
                  <InlineStack gap="200" blockAlign="center">
                    <span className={`swatch swatch-${a.classification}`} />
                    <Text as="span" variant="headingSm">
                      {a.label}
                    </Text>
                    <ClassBadge cls={a.classification} />
                  </InlineStack>
                  <Text as="span" variant="bodySm" tone="subdued">
                    {ago(a.last_seen, now)}
                  </Text>
                </InlineStack>
                <Text as="p" variant="bodySm" tone="subdued">
                  {a.hit_count} hits from {a.ips.length} IP{a.ips.length === 1 ? '' : 's'} across{' '}
                  {a.asns.length} ASN{a.asns.length === 1 ? '' : 's'}
                  {a.countries?.length ? ` · ${a.countries.map(flag).join(' ')}` : ''}
                  {a.timezone ? ` · active ${a.timezone}` : ''}
                </Text>
                <InlineStack gap="100" wrap>
                  {(a.tags ?? []).map((t) => (
                    <Badge key={t} size="small">
                      {TAG_LABEL[t]}
                    </Badge>
                  ))}
                  {(a.cves ?? []).map((c) => (
                    <Badge key={c} size="small" tone="magic">
                      {c}
                    </Badge>
                  ))}
                </InlineStack>
              </BlockStack>
            </Box>
          ))}
        </BlockStack>
      </BlockStack>
    </Card>
  );
}
