import {
  type AuthenticatedNativeEvidence,
  type CheckedBridgeEvidence,
  renderNativeDecision,
} from '../dist/index.js';

declare const bridge: CheckedBridgeEvidence;
declare const evidence: AuthenticatedNativeEvidence;

renderNativeDecision(bridge);
renderNativeDecision(evidence);
