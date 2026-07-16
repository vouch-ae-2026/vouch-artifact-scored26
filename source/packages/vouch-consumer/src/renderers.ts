import {
  type AuthenticatedNativeDecision,
  type CheckedBridgeEvidence,
  requireBridgeSnapshot,
  requireNativeDecision,
} from './evidence.js';

export function renderNativeDecision(
  decision: AuthenticatedNativeDecision
): string {
  requireNativeDecision(decision);
  return 'Authenticated native decision';
}

export function renderBridgeEvidence(evidence: CheckedBridgeEvidence): string {
  requireBridgeSnapshot(evidence);
  return 'External evidence checked';
}
