export const LOCAL_ITEM_LIMIT = 5;
export const LOCAL_FILE_TOTAL_BYTES = 2_000_000;
export const LOCAL_CAMERA_TOTAL_BYTES = 150_000_000;

export const PREPARATION_FRACTIONS = [
  { id: "half", label: "1/2", threshold: 1 / 2 },
  { id: "quarter", label: "1/4", threshold: 1 / 4 },
  { id: "eighth", label: "1/8", threshold: 1 / 8 },
  { id: "sixteenth", label: "1/16", threshold: 1 / 16 },
  { id: "thirty-second", label: "1/32", threshold: 1 / 32 },
  { id: "sixty-fourth", label: "1/64", threshold: 1 / 64 },
] as const;

export type PreparationPressure = "steady" | "elevated" | "high" | "limit";

export type PreparationItem = {
  size: number;
  source: "file" | "camera";
};

export type LocalPreparationUsage = {
  ratio: number;
  percent: number;
  pressure: PreparationPressure;
  draftCharacters: number;
  draftWords: number;
  stagedItems: number;
  fileBytes: number;
  cameraBytes: number;
  selectedBytes: number;
};

export function measureLocalPreparation(
  draft: string,
  items: readonly PreparationItem[],
): LocalPreparationUsage {
  const trimmed = draft.trim();
  const draftWords = trimmed ? trimmed.split(/\s+/).length : 0;
  const structureMarkers = trimmed
    ? (trimmed.match(/[\n,:;]|\b(and|then|after|before|if|unless)\b/gi) ?? []).length
    : 0;
  const draftPoints = draftWords + structureMarkers * 3;
  const draftRatio = trimmed
    ? Math.max(
        1 / 64,
        Math.min(1, Math.max(draftPoints / 140, trimmed.length / 840)),
      )
    : 0;
  const fileBytes = items
    .filter((item) => item.source === "file")
    .reduce((total, item) => total + Math.max(0, item.size), 0);
  const cameraBytes = items
    .filter((item) => item.source === "camera")
    .reduce((total, item) => total + Math.max(0, item.size), 0);
  const countRatio = Math.min(1, items.length / LOCAL_ITEM_LIMIT);
  const fileRatio = Math.min(1, fileBytes / LOCAL_FILE_TOTAL_BYTES);
  const cameraRatio = Math.min(1, cameraBytes / LOCAL_CAMERA_TOTAL_BYTES);
  const ratio = Math.max(draftRatio, countRatio, fileRatio, cameraRatio);
  const hardLimit =
    items.length >= LOCAL_ITEM_LIMIT ||
    fileBytes >= LOCAL_FILE_TOTAL_BYTES ||
    cameraBytes >= LOCAL_CAMERA_TOTAL_BYTES;
  const pressure: PreparationPressure = hardLimit
    ? "limit"
    : ratio >= 0.8
      ? "high"
      : ratio >= 0.5
        ? "elevated"
        : "steady";

  return {
    ratio,
    percent: Math.round(ratio * 100),
    pressure,
    draftCharacters: draft.length,
    draftWords,
    stagedItems: items.length,
    fileBytes,
    cameraBytes,
    selectedBytes: fileBytes + cameraBytes,
  };
}
