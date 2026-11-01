import { usingMock } from '../data/api';
import { TAGLINE } from '../data/config';

// The landing page already shows the tagline above the fold, so it passes showTagline={false}.
export function SiteFooter({ tone = 'light', showTagline = true }: { tone?: 'light' | 'dark'; showTagline?: boolean }) {
  return (
    <footer className={`site-footer site-footer-${tone}`}>
      <img src="/angler-logo.png?v=6" alt="Angler" />
      <span className="site-footer-name">Angler</span>
      {showTagline && (
        <>
          <span className="site-footer-sep" />
          <span>{TAGLINE}</span>
        </>
      )}
      <span className="site-footer-live">
        <span className="live-dot" />
        {usingMock ? 'Simulated feed' : 'Live'}
      </span>
    </footer>
  );
}
