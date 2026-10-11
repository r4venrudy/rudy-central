import type {
  Asset as UiAsset,
  Engagement,
  Finding,
  Run,
  Evidence,
  Control,
  Audit,
} from '../src/types.ts';
import type { KernelSensor, KernelPermitRecord, KernelCaptureRecord } from './kernel.mts';
export type ScopePermit = {
  assetId: string;
  origin: string;
  engagementId: string;
  issuedAt: number;
  expiresAt: number;
  capabilities: string[];
  requestBudget: number;
};
export type Asset = Omit<UiAsset, 'permit'> & {
  permit: ScopePermit | null;
  signature?: string | null;
  challenge: string;
  challengeExpiresAt: number;
  authorized: boolean;
  authorizedBy: string;
};
export type FindingRecord = Finding & { runId?: string; ruleId?: string; updatedAt?: string };
export type EvidenceRecord = Evidence & { raw: string; runId?: string };
export type Records = {
  asset: Asset;
  engagement: Engagement;
  finding: FindingRecord;
  evidence: EvidenceRecord;
  run: Run;
  control: Control & { createdAt: string };
  sensor: KernelSensor;
  kernelPermit: KernelPermitRecord;
  kernelCapture: KernelCaptureRecord;
};
export type RecordKind = keyof Records;
export type FindingInput = Omit<FindingRecord, 'id' | 'createdAt' | 'engagementId'>;
export type AuditEntry = Audit & { previous: string; hash: string };
export type Integrity = { valid: boolean; count: number; head?: string };
declare global {
  namespace Express {
    interface Request {
      actor: 'operator' | 'viewer';
      sessionId: string;
    }
  }
}
