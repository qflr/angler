import { BlockStack, Card, InlineStack, Text, Tooltip } from '@shopify/polaris';
import { Sparkline } from './Sparkline';

interface Props {
  title: string;
  help: string;
  value: number | string;
  delta?: number;
  /** For metrics where going up is bad news (targeted hits), flip the tone. */
  upIsBad?: boolean;
  spark?: number[];
  sparkColor?: string;
  /** Full-width card: the sparkline gets more room. */
  wide?: boolean;
}

export function MetricCard({ title, help, value, delta, upIsBad, spark, sparkColor, wide }: Props) {
  const showDelta = delta !== undefined && delta !== 0 && Number.isFinite(delta);
  const tone = !showDelta ? 'subdued' : (delta! > 0) === !!upIsBad ? 'critical' : 'success';
  return (
    <Card>
      <BlockStack gap="200">
        <InlineStack>
          <Tooltip content={help}>
            <h3 className="eyebrow">{title}</h3>
          </Tooltip>
        </InlineStack>
        <div className="metric-row">
          <InlineStack gap="150" blockAlign="baseline">
            <p className="metric-value">{value}</p>
            {showDelta && (
              <span className="metric-delta">
                <Text as="span" tone={tone as any}>
                  {delta! > 0 ? '↗' : '↘'} {Math.abs(delta!)}%
                </Text>
              </span>
            )}
          </InlineStack>
          {spark && <Sparkline data={spark} color={sparkColor} wide={wide} />}
        </div>
      </BlockStack>
    </Card>
  );
}
