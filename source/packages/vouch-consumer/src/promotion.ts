import {
  type AuthenticatedNativeDecision,
  type AuthenticatedNativeEvidence,
  mintNativeDecision,
  requireNativeSnapshot,
  type CanonicalDecision,
} from './evidence.js';
import type { PromotionError, Result } from './types.js';

const decisions = new Set<CanonicalDecision>([
  'approve',
  'deny',
  'review',
  'invalid-input',
]);

export function promoteNativeDecision(
  evidence: AuthenticatedNativeEvidence
): Result<AuthenticatedNativeDecision, PromotionError> {
  let snapshot;
  try {
    snapshot = requireNativeSnapshot(evidence);
  } catch {
    return Object.freeze({
      ok: false as const,
      error: Object.freeze({ code: 'wrong-evidence-capability' as const }),
    });
  }

  const receipt = snapshot.receipt as Record<string, any>;
  if (receipt.comparison?.status !== 'agree')
    return ineligible('comparison-not-agree');
  if (
    receipt.reference?.terminal?.kind !== 'completed' ||
    receipt.meaning_env?.terminal?.kind !== 'completed'
  ) {
    return ineligible('terminal-not-completed');
  }
  const events = receipt.reference?.transcript?.events;
  const finalValue = Array.isArray(events) ? events.at(-1)?.value : undefined;
  if (
    finalValue?.t !== 'decision' ||
    typeof finalValue.v !== 'string' ||
    !decisions.has(finalValue.v as CanonicalDecision)
  ) {
    return ineligible('final-value-not-decision');
  }
  if (!Array.isArray(receipt.diagnostics) || receipt.diagnostics.length !== 0) {
    return ineligible('diagnostics-present');
  }
  if (snapshot.build_variant !== 'release' || snapshot.mutant_id !== null) {
    return ineligible('mutant-build');
  }
  return Object.freeze({
    ok: true as const,
    value: mintNativeDecision(finalValue.v as CanonicalDecision),
  });
}

function ineligible(
  reason: Exclude<
    PromotionError,
    { code: 'wrong-evidence-capability' }
  >['reason']
): Result<never, PromotionError> {
  return Object.freeze({
    ok: false as const,
    error: Object.freeze({
      code: 'native-decision-promotion-ineligible' as const,
      reason,
    }),
  });
}
