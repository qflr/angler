import { useRef } from 'react';
import { BlockStack, Box, Card, IndexTable, InlineStack, Text, Tooltip } from '@shopify/polaris';
import type { hitsByCve } from '../data/derive';
import type { Actor, AttackEvent, Classification, Cve, SourceTag } from '../data/types';
import { CardTitle } from './Panels';
import { Pill, type PillTone } from './Pill';
import { ago, clock, flag } from './format';

// Severity reads as darkness: ink is most urgent, lilac tint least.
const STATUS_TONE: Record<Cve['status'], PillTone> = { urgent: 'strong', high: 'mid', watch: 'soft' };
const SEVERITY_TONE: Record<Cve['severity'], PillTone> = { critical: 'strong', high: 'mid', medium: 'soft', low: 'outline', unknown: 'outline' };
const PATCH_TONE: Record<Cve['patch_status'], PillTone> = { patched: 'soft', partial: 'mid', unpatched: 'strong', unknown: 'outline' };
const STATUS_RANK = { urgent: 0, high: 1, watch: 2 } as const;

// Same set as backend classify.SIGNATURES. These are the only CVEs we can attribute a request to.
const ANALYZABLE: { id: string; name: string; decoy: boolean }[] = [
  { id: 'CVE-2023-1389', name: 'TP-Link Archer command injection', decoy: true },
  { id: 'CVE-2017-9841', name: 'PHPUnit eval-stdin.php RCE', decoy: true },
  { id: 'CVE-2021-41773', name: 'Apache path traversal', decoy: true },
  { id: 'CVE-2024-4577', name: 'PHP-CGI argument injection', decoy: true },
  { id: 'CVE-2021-44228', name: 'Log4Shell JNDI injection', decoy: false },
  { id: 'CVE-2018-10561', name: 'GPON router auth bypass', decoy: false },
  { id: 'CVE-2017-17215', name: 'Huawei HG532 UPnP RCE', decoy: false },
  { id: 'CVE-2018-20062', name: 'ThinkPHP invokefunction RCE', decoy: false },
  { id: 'CVE-2022-1388', name: 'F5 BIG-IP iControl auth bypass', decoy: false },
  { id: 'CVE-2021-36260', name: 'Hikvision command injection', decoy: false },
  { id: 'CVE-2024-3400', name: 'PAN-OS GlobalProtect command injection', decoy: false },
  { id: 'CVE-2023-20198', name: 'Cisco IOS XE web UI privilege escalation', decoy: false },
  { id: 'CVE-2014-6271', name: 'Shellshock', decoy: false },
];
const TAG_LABEL: Record<SourceTag, string> = {
  tor: 'Tor',
  vpn: 'VPN',
  cloud: 'Cloud',
  residential: 'Residential',
  scanner: 'Known scanner',
};

const cap = (s: string) => (s ? s[0].toUpperCase() + s.slice(1) : '—');
// Values outside the contract (e.g. a backend sending patch_status "unknown") fall back to an outline pill.

export function ClassBadge({ cls }: { cls: Classification }) {
  return cls === 'targeted' ? <Pill tone="strong">Targeted</Pill> : <Pill tone="outline">Noise</Pill>;
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
  const byId = new Map(cves.map((c) => [c.id, c]));
  const rows = ANALYZABLE.map((known) => ({ ...known, cve: byId.get(known.id) })).sort(
    (a, b) =>
      (hits.get(b.id)?.targeted ?? 0) - (hits.get(a.id)?.targeted ?? 0) ||
      (a.cve ? STATUS_RANK[a.cve.status] : 9) - (b.cve ? STATUS_RANK[b.cve.status] : 9),
  );
  return (
    <Card padding="0">
      <Box padding="400" paddingBlockEnd="200">
        <CardTitle help="Only CVEs we can recognize in a request. Decoy means this VM answers as that vulnerability. Hits are targeted, then every request we attributed to that CVE.">
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
        {rows.map((row, i) => {
          const c = row.cve;
          const h = hits.get(row.id);
          const blurb = c ? `${c.product ? `${c.product} · ` : ''}${c.description}` : row.name;
          return (
            <IndexTable.Row id={row.id} key={row.id} position={i}>
              <IndexTable.Cell>
                <BlockStack gap="050">
                  <InlineStack gap="150" blockAlign="center" wrap={false}>
                    <span className="mono" style={{ fontSize: 13, fontWeight: 600 }}>
                      {row.id}
                    </span>
                    {row.decoy && (
                      <Tooltip content="The decoy answers this exploit. Other recognized CVEs are recorded, but the VM does not pretend to be that product.">
                        <Pill tone="mid">Decoy</Pill>
                      </Tooltip>
                    )}
                    {c?.kev && (
                      <Tooltip content="In CISA's Known Exploited Vulnerabilities catalog">
                        <Pill tone="strong">KEV</Pill>
                      </Tooltip>
                    )}
                  </InlineStack>
                  <div style={{ maxWidth: 220 }}>
                    <Tooltip content={blurb}>
                      <div className="truncate">
                        <Text as="span" variant="bodySm" tone="subdued">
                          {blurb}
                        </Text>
                      </div>
                    </Tooltip>
                  </div>
                </BlockStack>
              </IndexTable.Cell>
              <IndexTable.Cell>
                {c ? <Pill tone={STATUS_TONE[c.status] ?? 'outline'}>{cap(c.status)}</Pill> : <Text as="span" tone="subdued">—</Text>}
              </IndexTable.Cell>
              <IndexTable.Cell>
                {c ? (
                  <Tooltip content={`${cap(c.severity)}${c.cvss != null ? ` · CVSS ${c.cvss.toFixed(1)}` : ''}`}>
                    <Pill tone={SEVERITY_TONE[c.severity] ?? 'outline'}>
                      {c.cvss != null ? c.cvss.toFixed(1) : cap(c.severity)}
                    </Pill>
                  </Tooltip>
                ) : (
                  <Text as="span" tone="subdued">—</Text>
                )}
              </IndexTable.Cell>
              <IndexTable.Cell>
                {c ? <Pill tone={PATCH_TONE[c.patch_status] ?? 'outline'}>{cap(c.patch_status)}</Pill> : <Text as="span" tone="subdued">—</Text>}
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
                    <Pill key={t} tone="outline">
                      {TAG_LABEL[t]}
                    </Pill>
                  ))}
                  {(a.cves ?? []).map((c) => (
                    <Pill key={c} tone="soft">
                      {c}
                    </Pill>
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
