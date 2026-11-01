# Angler

*Attackers need a target. We automate fake ones.*

CVE in, honeypot out: a new CVE goes public, Angler stands up a contained decoy that impersonates
the vulnerable software, and every hit lands on a live threat-intel dashboard, tagged as
background noise or targeting our CVE.

| Folder | Owner | Contents |
|---|---|---|
| [`frontend/`](frontend) | Frontend | React + Vite + TypeScript + Shopify Polaris dashboard |
| [`backend/`](backend) | Backend | FastAPI service and Render Workflows pipeline |
| [`docs/`](docs) | Shared | [API contract](docs/api-contract.md) and reference docs |

Frontend and backend never edit each other's folders. Changes to the API contract go through
`docs/api-contract.md` (and `frontend/src/data/types.ts`) so both sides stay in sync.

## Quick start (frontend)

```bash
cd frontend
npm install
npm run dev   # http://localhost:5173, runs on simulated data until VITE_API_URL is set
```
