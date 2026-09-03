import {
  PREPARATION_FRACTIONS,
  type LocalPreparationUsage,
} from "@/lib/local-preparation";

function compactBytes(bytes: number) {
  if (bytes < 1_000) return `${bytes} bytes`;
  if (bytes < 1_000_000) return `${Math.ceil(bytes / 1_000)} KB`;
  return `${(bytes / 1_000_000).toFixed(bytes >= 10_000_000 ? 0 : 1)} MB`;
}

export function UdjatSignal({ usage }: { usage?: LocalPreparationUsage }) {
  const visibleFractions = usage
    ? PREPARATION_FRACTIONS.filter((fraction) => usage.ratio >= fraction.threshold).length
    : 0;
  const label = usage
    ? `Local preparation load estimated at ${usage.percent} percent: ${usage.draftWords} draft words, ${usage.stagedItems} staged items, ${compactBytes(usage.selectedBytes)} selected. This is not model context or runner capacity.`
    : "Lil Tweak at rest";

  return (
    <span
      className="lil-tueeq-signal"
      data-pressure={usage?.pressure ?? "steady"}
      data-percent={usage?.percent ?? 0}
      data-tier={visibleFractions}
      role="img"
      aria-label={label}
      title={usage ? `Local preparation: ${usage.percent}%` : "Lil Tweak at rest"}
    >
      <span
        key={`${usage?.pressure ?? "steady"}:${visibleFractions}`}
        className="lil-tueeq-avatar"
        aria-hidden="true"
      />
      {usage && PREPARATION_FRACTIONS.map((fraction) => (
        <span
          key={fraction.id}
          className={`lil-tueeq-fraction fraction-${fraction.id}`}
          data-visible={usage.ratio >= fraction.threshold}
          aria-hidden="true"
        >
          {fraction.label}
        </span>
      ))}
    </span>
  );
}
