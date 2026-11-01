import type { ReactNode } from 'react';

/** Palette-only badge. strong = ink, mid = mauve, soft = lilac tint, outline = hairline. */
export type PillTone = 'strong' | 'mid' | 'soft' | 'outline';

export function Pill({ tone = 'soft', children }: { tone?: PillTone; children: ReactNode }) {
  return <span className={`pill pill-${tone}`}>{children}</span>;
}
