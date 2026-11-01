// Demo mode runs the whole app on the built-in simulator (clearly badged); live mode talks to the backend.
// Chosen on the landing page, remembered per browser. Switching reloads so every module re-reads it.

export type Mode = 'live' | 'demo';
const KEY = 'angler-mode';

export const MODE: Mode = (() => {
  try {
    return localStorage.getItem(KEY) === 'demo' ? 'demo' : 'live';
  } catch {
    return 'live';
  }
})();

export function setMode(mode: Mode) {
  try {
    localStorage.setItem(KEY, mode);
  } catch {
    // Storage blocked (private window): the app stays in live mode.
  }
  window.location.reload();
}
