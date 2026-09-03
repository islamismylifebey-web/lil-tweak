import type { JobState } from "./engineering";

export function decisionRecoveryMatches(
  decision: "approve" | "reject",
  state: JobState,
  approvalConsumed: boolean,
): boolean {
  return decision === "approve"
    ? state === "applying" && !approvalConsumed
    : state === "rejected";
}

export function exportRecoveryMatches(
  state: JobState,
  approvalConsumed: boolean,
): boolean {
  return state === "completed" && approvalConsumed;
}

export function cancelRecoveryMatches(state: JobState): boolean {
  return state === "cancelled";
}
