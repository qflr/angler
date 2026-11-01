import { Line, LineChart, ResponsiveContainer, YAxis } from 'recharts';

interface Props {
  data: number[];
  color?: string;
  wide?: boolean;
}

export function Sparkline({ data, color = '#4137cb', wide }: Props) {
  const points = data.map((v, i) => ({ i, v }));
  return (
    <div className={wide ? 'spark spark-wide' : 'spark'}>
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={points} margin={{ top: 2, right: 2, bottom: 2, left: 2 }}>
          <YAxis hide domain={[0, 'dataMax + 1']} />
          <Line type="monotone" dataKey="v" stroke={color} strokeWidth={1.75} dot={false} isAnimationActive={false} />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
