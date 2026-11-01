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
            <span className="metric-title">
              <Text as="h3" variant="headingSm">
                {title}
              </Text>
            </span>
          </Tooltip>
        </InlineStack>
        <div className="metric-row">
          <InlineStack gap="150" blockAlign="baseline">
            <Text as="p" variant="headingLg">
              {value}
            </Text>
            {showDelta && (
              <Text as="span" variant="bodySm" tone={tone as any}>
                {delta! > 0 ? '↗' : '↘'} {Math.abs(delta!)}%
              </Text>
            )}
          </InlineStack>
          {spark && <Sparkline data={spark} color={sparkColor} wide={wide} />}
        </div>
      </BlockStack>
    </Card>
  );
}
