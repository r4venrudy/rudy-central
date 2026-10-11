export type Finding = {
  id: string;
  engagementId: string;
  title: string;
  severity: string;
  category: string;
  source: string;
  asset: string;
  remediation: string;
  status: string;
  description: string;
  evidence: string;
  confidence: string;
  createdAt: string;
  notes?: string;
  owner?: string;
  evidenceId?: string;
};
export type Asset = {
  id: string;
  engagementId: string;
  name: string;
  origin: string;
  method: string;
  state: string;
  createdAt: string;
  challenge?: string;
  challengeExpiresAt?: number;
  permit?: { expiresAt: number; capabilities: string[] };
  verifiedAt?: string;
};
export type Engagement = {
  id: string;
  name: string;
  client: string;
  objective: string;
  createdAt: string;
  status: string;
};
export type Run = {
  id: string;
  engagementId: string;
  assetId?: string;
  name: string;
  target: string;
  state: string;
  createdAt: string;
  finishedAt?: string;
  findingCount: number;
  error?: string;
  steps?: string[];
};
export type Evidence = {
  id: string;
  engagementId: string;
  name: string;
  format: string;
  findingCount: number;
  sha256: string;
  createdAt: string;
};
export type Tool = {
  id: string;
  name: string;
  description: string;
  domain: string;
  adapter: string;
  status: string;
  execution: string;
  requirements: string;
};
export type Control = {
  id: string;
  engagementId?: string;
  name: string;
  description: string;
  status: string;
  notes?: string;
};
export type Audit = {
  seq: number;
  time: string;
  actor: string;
  action: string;
  detail: string;
  hash?: string;
};
export type State = {
  demo: boolean;
  role: string;
  engagements: Engagement[];
  assets: Asset[];
  findings: Finding[];
  runs: Run[];
  evidence: Evidence[];
  catalog: Tool[];
  domains: { id: string; name: string; description: string; count: number }[];
  nativeChecks: {
    id: string;
    name: string;
    description: string;
    requests: number;
    status: string;
  }[];
  audit: Audit[];
  integrity: { valid: boolean; count: number; head?: string };
  controls: Control[];
  policy: {
    version: string;
    capabilities: string[];
    maxConcurrentRuns: number;
    maxRequestsPerRun: number;
    permitHours: number;
    publicHttpsOnly: boolean;
    kernel: string;
  };
};
