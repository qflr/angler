import { useState } from 'react';
import { BlockStack, Button, Card, InlineStack, Text } from '@shopify/polaris';
import { MODE } from '../data/mode';
import type { Actor, AttackEvent } from '../data/types';
import { CardTitle } from './Panels';

const API_URL = (import.meta.env.VITE_API_URL as string | undefined)?.replace(/\/$/, '');

/** "Explain this traffic": Gemini reads the current tab's numbers and says what they probably mean. */
export function InsightCard({ scope, events, actors }: { scope: string; events: AttackEvent[]; actors: Actor[] }) {
  const [text, setText] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const explain = async () => {
    if (!API_URL) {
      setError('The AI analyst needs the backend (VITE_API_URL).');
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API_URL}/api/insights`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scope: MODE === 'demo' ? `${scope} (simulated demo data)` : scope, events, actors }),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(body.detail ?? `HTTP ${res.status}`);
      setText(body.summary);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  };

  return (
    <Card>
      <BlockStack gap="300">
        <InlineStack align="space-between" blockAlign="center">
          <CardTitle help="Gemini reads the counts behind this view (paths, places, networks, stages, actors) and explains what the traffic most likely is. It only sees aggregates, never raw payloads.">
            AI analyst
          </CardTitle>
          <Button onClick={explain} loading={loading} disabled={!events.length} variant="primary">
            {text ? 'Explain again' : 'Explain this traffic'}
          </Button>
        </InlineStack>
        {!text && !error && (
          <Text as="p" variant="bodySm" tone="subdued">
            {events.length ? `Interpret the ${events.length} requests in "${scope}".` : 'No traffic in this view yet.'}
          </Text>
        )}
        {error && (
          <Text as="p" variant="bodySm" tone="critical">
            {error}
          </Text>
        )}
        {text && <div className="insight-text">{text}</div>}
      </BlockStack>
    </Card>
  );
}
