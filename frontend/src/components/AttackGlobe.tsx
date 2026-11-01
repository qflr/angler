import { forwardRef, useEffect, useImperativeHandle, useMemo, useRef, useState } from 'react';
import Globe, { type GlobeMethods } from 'react-globe.gl';
import { Color, MeshPhongMaterial } from 'three';
import { polygonToCells } from 'h3-js';
import { feature } from 'topojson-client';
import type { Topology } from 'topojson-specification';
import countries110 from 'world-atlas/countries-110m.json';
import type { HONEYPOT } from '../data/config';
import type { AttackEvent } from '../data/types';

const HEX_RES = 3;

// A few 110m country outlines (e.g. North Korea) are degenerate for H3 and abort the
// whole hex layer, so drop any polygon H3 can't tile.
const LAND = (
  feature(countries110 as unknown as Topology, (countries110 as any).objects.countries) as any
).features.flatMap((f: any) => {
  const polys: number[][][][] =
    f.geometry.type === 'Polygon' ? [f.geometry.coordinates] : f.geometry.coordinates;
  const ok = polys.filter((p) => {
    try {
      polygonToCells(p, HEX_RES, true);
      return true;
    } catch {
      return false;
    }
  });
  return ok.length ? [{ ...f, geometry: { type: 'MultiPolygon', coordinates: ok } }] : [];
});

const RECENT_MS = 2 * 60_000;
const INDIGO = '#4137cb';
const NOISE = '#8a90b8';

interface Marker {
  lat: number;
  lng: number;
  cls: 'noise' | 'targeted';
  ip: string;
  place: string;
  asn: string;
  cveId: string | null;
}

export interface AttackGlobeHandle {
  flyTo: (lat: number, lng: number) => void;
}

interface Props {
  events: AttackEvent[];
  honeypot: typeof HONEYPOT;
  showNoise: boolean;
  autoRotate: boolean;
}

export const AttackGlobe = forwardRef<AttackGlobeHandle, Props>(function AttackGlobe(
  { events, honeypot, showNoise, autoRotate },
  ref,
) {
  const wrap = useRef<HTMLDivElement>(null);
  const globe = useRef<GlobeMethods>();
  const [size, setSize] = useState({ w: 0, h: 0 });

  useEffect(() => {
    const el = wrap.current!;
    const ro = new ResizeObserver(([e]) => setSize({ w: e.contentRect.width, h: e.contentRect.height }));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  useImperativeHandle(ref, () => ({
    flyTo: (lat, lng) => globe.current?.pointOfView({ lat, lng, altitude: 1.6 }, 1200),
  }));

  useEffect(() => {
    const controls = globe.current?.controls();
    if (!controls) return;
    controls.autoRotate = autoRotate;
    controls.autoRotateSpeed = 0.35;
  }, [autoRotate, size.w]);

  const material = useMemo(
    () =>
      new MeshPhongMaterial({
        color: new Color('#bcd0f2'),
        emissive: new Color('#c4d4f4'),
        emissiveIntensity: 0.45,
        shininess: 14,
      }),
    [],
  );

  // One marker per source IP seen recently; targeted wins over noise for the same IP.
  // Events without lat/lng (optional in the contract) can't be placed and are skipped.
  const sources = useMemo(() => {
    const cutoff = Date.now() - RECENT_MS;
    const byIp = new Map<string, Marker>();
    for (const e of events) {
      if (e.lat == null || e.lng == null || Date.parse(e.timestamp) < cutoff) continue;
      if (!showNoise && e.classification === 'noise') continue;
      const prev = byIp.get(e.source_ip);
      if (!prev || (prev.cls === 'noise' && e.classification === 'targeted')) {
        byIp.set(e.source_ip, {
          lat: e.lat,
          lng: e.lng,
          cls: e.classification,
          ip: e.source_ip,
          place: [e.city, e.country].filter(Boolean).join(', '),
          asn: `AS${e.asn}${e.org ? ` ${e.org}` : ''}`,
          cveId: e.cve_id ?? null,
        });
      }
    }
    return [...byIp.values()];
  }, [events, showNoise]);

  const arcs = useMemo(
    () =>
      sources
        .filter((h) => h.cls === 'targeted')
        .map((h) => ({ startLat: h.lat, startLng: h.lng, endLat: honeypot.lat, endLng: honeypot.lng })),
    [sources, honeypot],
  );

  // The honeypot rides along in the point/ring layers (the HTML-element layer throws in this globe.gl build).
  const markers = useMemo(() => [...sources, { ...honeypot, cls: 'honeypot' }], [sources, honeypot]);

  return (
    // Oversized and offset so the globe bleeds off the bottom edge, like Shopify's Live View.
    <div ref={wrap} style={{ position: 'absolute', top: 0, left: 0, right: '-4%', bottom: '-18%' }}>
      {size.w > 0 && (
        <Globe
          ref={globe}
          width={size.w}
          height={size.h}
          backgroundColor="rgba(0,0,0,0)"
          globeMaterial={material}
          showAtmosphere
          atmosphereColor="#a9c4ff"
          atmosphereAltitude={0.22}
          onGlobeReady={() => {
            globe.current?.pointOfView({ lat: 34, lng: -70, altitude: 1.8 });
            const c = globe.current!.controls();
            c.autoRotate = autoRotate;
            c.autoRotateSpeed = 0.35;
          }}
          hexPolygonsData={LAND}
          hexPolygonResolution={HEX_RES}
          hexPolygonMargin={0.36}
          hexPolygonAltitude={0.004}
          hexPolygonColor={() => 'rgba(70, 88, 228, 0.7)'}
          ringsData={markers}
          ringLat={(d: any) => d.lat}
          ringLng={(d: any) => d.lng}
          ringColor={(d: any) => (t: number) =>
            d.cls === 'noise' ? `rgba(130,136,170,${0.8 * (1 - t)})` : `rgba(65,55,203,${1 - t})`}
          ringMaxRadius={(d: any) => (d.cls === 'honeypot' ? 6 : d.cls === 'targeted' ? 4 : 2.2)}
          ringPropagationSpeed={2}
          ringRepeatPeriod={(d: any) => (d.cls === 'honeypot' ? 2400 : d.cls === 'targeted' ? 900 : 1800)}
          pointsData={markers}
          pointLat={(d: any) => d.lat}
          pointLng={(d: any) => d.lng}
          pointColor={(d: any) => (d.cls === 'noise' ? NOISE : INDIGO)}
          pointAltitude={(d: any) => (d.cls === 'honeypot' ? 0.06 : 0.012)}
          pointRadius={(d: any) => (d.cls === 'honeypot' ? 0.9 : d.cls === 'targeted' ? 0.6 : 0.48)}
          pointLabel={(d: any) =>
            d.cls === 'honeypot'
              ? `<div style="font:12px Inter,sans-serif;padding:6px 8px;background:#fff;color:#0e0c25;border-radius:8px;box-shadow:0 4px 14px rgba(14,12,37,.15)"><b>${d.label}</b></div>`
              : `<div style="font:12px Inter,sans-serif;padding:6px 8px;background:#fff;color:#0e0c25;border-radius:8px;box-shadow:0 4px 14px rgba(14,12,37,.15)">
               <b>${d.ip}</b><br/>${d.place ? `${d.place}<br/>` : ''}${d.asn}${d.cveId ? `<br/><span style="color:${INDIGO}">${d.cveId}</span>` : ''}
             </div>`}
          arcsData={arcs}
          arcColor={() => ['rgba(65,55,203,0.15)', 'rgba(65,55,203,0.95)']}
          arcStroke={0.45}
          arcAltitudeAutoScale={0.35}
          arcDashLength={0.35}
          arcDashGap={1.2}
          arcDashAnimateTime={1800}
        />
      )}
    </div>
  );
});
