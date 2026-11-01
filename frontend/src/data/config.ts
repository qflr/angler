// Where the decoy runs. Not part of the API contract; set per deploy.
export const HONEYPOT = {
  lat: Number(import.meta.env.VITE_HONEYPOT_LAT ?? 39.96),
  lng: Number(import.meta.env.VITE_HONEYPOT_LNG ?? -83.0),
  label: (import.meta.env.VITE_HONEYPOT_LABEL as string | undefined) ?? 'Honeypot · Render Ohio',
};

export const TAGLINE = 'Attackers need a target. We automate fake ones.';
