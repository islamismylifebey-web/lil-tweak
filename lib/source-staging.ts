export type StagedSourceKind = "file" | "camera";

export interface StagedSourceSummary {
  name: string;
  size: number;
}

export interface StagedSourceCandidate extends StagedSourceSummary {
  type: string;
}

export const MAX_STAGED_FILES = 10;
export const MAX_STAGED_FILE_BYTES = 25_000_000;
export const MAX_STAGED_TOTAL_BYTES = 100_000_000;
export const MAX_CAMERA_IMAGE_BYTES = 25_000_000;
export const MAX_CAMERA_VIDEO_BYTES = 25_000_000;

export interface StagedSourceSelection<T extends StagedSourceCandidate> {
  accepted: T[];
  rejected: number;
  rejectionReason: string;
}

function normalizedFilename(value: string): string {
  return value.trim().toLocaleLowerCase();
}

export function selectStagedSourceCandidates<T extends StagedSourceCandidate>(
  existing: readonly StagedSourceSummary[],
  chosen: readonly T[],
  source: StagedSourceKind,
): StagedSourceSelection<T> {
  const accepted: T[] = [];
  const filenames = new Set(existing.map((item) => normalizedFilename(item.name)));
  let totalBytes = existing.reduce((total, item) => total + item.size, 0);
  let rejected = 0;
  let rejectionReason = "";

  for (const candidate of chosen) {
    const filename = normalizedFilename(candidate.name);
    const countExceeded = existing.length + accepted.length >= MAX_STAGED_FILES;
    const isImage = candidate.type.startsWith("image/");
    const isVideo = candidate.type.startsWith("video/");
    let reason = "";

    if (filenames.has(filename)) reason = "Source filenames must be unique.";
    else if (countExceeded) reason = `You can stage up to ${MAX_STAGED_FILES} items.`;
    else if (candidate.size === 0) reason = "Empty files cannot be selected.";
    else if (source === "camera" && !isImage && !isVideo) reason = "Camera capture accepts photos or video clips only.";
    else if (source === "camera" && isImage && candidate.size > MAX_CAMERA_IMAGE_BYTES) reason = "Photos must be 25 MB or smaller.";
    else if (source === "camera" && isVideo && candidate.size > MAX_CAMERA_VIDEO_BYTES) reason = "Video clips must be 25 MB or smaller.";
    else if (source === "file" && candidate.size > MAX_STAGED_FILE_BYTES) reason = "Files must be 25 MB or smaller.";
    else if (totalBytes + candidate.size > MAX_STAGED_TOTAL_BYTES) reason = "Sources selected here must total 100 MB or less.";

    if (reason) {
      rejected += 1;
      rejectionReason ||= reason;
      continue;
    }

    accepted.push(candidate);
    filenames.add(filename);
    totalBytes += candidate.size;
  }

  return { accepted, rejected, rejectionReason };
}
