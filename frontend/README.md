# Angler dashboard

Live threat-intel view for the CVE honeypot. React + Vite + TypeScript, Shopify Polaris shell,
Recharts for charts, react-globe.gl for the hex globe. Modeled on Shopify's Live View.

## Run

```bash
npm install
npm run dev        # http://localhost:5173
npm run build      # static site in dist/ (Render: Static Site, publish dir = dist)
```

With no `VITE_API_URL` set, the dashboard runs on a built-in simulated feed (`src/data/mock.ts`)
and shows a "Simulated feed" badge. Point it at the FastAPI service to go live:

```bash
VITE_API_URL=https://angler-api.onrender.com npm run build
```

Optional: `VITE_HONEYPOT_LAT`, `VITE_HONEYPOT_LNG`, `VITE_HONEYPOT_LABEL` place the honeypot pin on the globe.

## Backend contract

The dashboard polls four endpoints every 3 s. Full spec with examples: [`docs/api-contract.md`](../docs/api-contract.md).
TypeScript types: `src/data/types.ts`.

| Endpoint | Feeds |
|---|---|
| `GET /api/stats` | Top metric cards |
| `GET /api/cves` | CVE leaderboard |
| `GET /api/events?limit=1000` | Live stream, globe, noise-vs-targeted chart, attack behavior, locations |
| `GET /api/actors` | Attackers card |

Charts are rolled up from raw events in the browser (`src/data/derive.ts`), so the backend only
serves records. Enable CORS on FastAPI for the static site's origin.

## Branding

- Name: Angler. Logo: `public/angler-logo.png`.
- Palette lives in `src/theme.css` as `--angler-*` tokens; Polaris `--p-color-*` tokens are
  re-pointed at them.
- Tagline and honeypot location: `src/data/config.ts`.
