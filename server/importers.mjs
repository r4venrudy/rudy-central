import { PolicyError } from './security.mts';
const severity = (value) =>
  ({
    critical: 'critical',
    high: 'high',
    medium: 'medium',
    moderate: 'medium',
    low: 'low',
    info: 'info',
    informational: 'info',
    warning: 'medium',
    error: 'high',
    note: 'low',
    none: 'info',
  })[String(value || 'info').toLowerCase()] || 'info';
const text = (value, max = 8000) =>
  typeof value === 'string' ? value.slice(0, max) : JSON.stringify(value ?? '').slice(0, max);
const safeUrl = (value) => {
  try {
    const url = new URL(value);
    url.username = '';
    url.password = '';
    url.search = '';
    url.hash = '';
    return url.toString();
  } catch {
    return text(value, 512);
  }
};
export function parseEvidence(format, raw) {
  let data;
  try {
    data = JSON.parse(raw);
  } catch {
    if (format === 'nuclei') {
      try {
        data = raw
          .split(/\r?\n/)
          .filter(Boolean)
          .map((line) => JSON.parse(line));
      } catch {
        throw new PolicyError('Invalid JSON or Nuclei JSONL.');
      }
    } else throw new PolicyError('Invalid JSON evidence.');
  }
  let rows = [];
  if (format === 'sarif') {
    if (data.version !== '2.1.0' || !Array.isArray(data.runs))
      throw new PolicyError('Expected SARIF 2.1.0 with runs.');
    for (const run of data.runs) {
      const rules = run.tool?.driver?.rules || [];
      // CodeQL and other multi-pack tools keep their rules in tool.extensions[], and results
      // may point at a rule by index instead of ruleId
      const components = run.tool?.extensions || [];
      const findRule = (r) => {
        const ref = r.rule || {};
        const list =
          ref.toolComponent?.index !== undefined
            ? components[ref.toolComponent.index]?.rules || []
            : rules;
        const index = ref.index ?? r.ruleIndex;
        if (Number.isInteger(index) && list[index]) return list[index];
        const id = r.ruleId ?? ref.id;
        return (
          [rules, ...components.map((c) => c.rules || [])].flat().find((x) => x.id === id) || {}
        );
      };
      for (const r of run.results || []) {
        // "pass", "notApplicable" and "informational" results are not findings, and an accepted
        // suppression means someone already reviewed it
        if (r.kind && r.kind !== 'fail' && r.kind !== 'review' && r.kind !== 'open') continue;
        if ((r.suppressions || []).some((x) => !x.status || x.status === 'accepted')) continue;
        const rule = findRule(r);
        const score = Number(rule.properties?.['security-severity']);
        rows.push({
          title: rule.shortDescription?.text || r.ruleId || rule.id || 'SARIF finding',
          severity: Number.isFinite(score)
            ? score >= 9
              ? 'critical'
              : score >= 7
                ? 'high'
                : score >= 4
                  ? 'medium'
                  : score > 0
                    ? 'low'
                    : 'info'
            : // SARIF's default level is "warning" when neither the result nor the rule sets one
              r.level || rule.defaultConfiguration?.level || 'warning',
          description: r.message?.text || r.message?.markdown,
          remediation: rule.help?.text || 'Review the rule and validate the finding in context.',
          asset: r.locations?.[0]?.physicalLocation?.artifactLocation?.uri,
          evidence: r.locations,
          source: run.tool?.driver?.name || 'SARIF',
          ruleId: r.ruleId || rule.id,
        });
      }
    }
  } else if (format === 'semgrep') {
    if (!Array.isArray(data.results)) throw new PolicyError('Expected Semgrep results array.');
    rows = data.results.map((r) => ({
      title: r.check_id,
      severity: r.extra?.severity,
      description: r.extra?.message,
      asset: r.path,
      evidence: { path: r.path, start: r.start, end: r.end },
      remediation: r.extra?.fix || 'Review the Semgrep rule and affected source.',
      source: 'Semgrep',
      ruleId: r.check_id,
    }));
  } else if (format === 'nuclei') {
    if (!Array.isArray(data)) data = [data];
    if (data.some((r) => !r.info || !r['template-id']))
      throw new PolicyError('Expected Nuclei result objects with info and template-id.');
    rows = data.map((r) => ({
      title: r.info?.name,
      severity: r.info?.severity,
      description: r.info?.description,
      asset: safeUrl(r['matched-at'] || r.host),
      evidence: { template: r['template-id'], matcher: r['matcher-name'] },
      remediation:
        r.info?.remediation || 'Validate the template result and remediate the underlying issue.',
      source: 'Nuclei',
      ruleId: r['template-id'],
    }));
  } else if (format === 'trivy') {
    if (!Array.isArray(data.Results)) throw new PolicyError('Expected Trivy Results array.');
    rows = data.Results.flatMap((result) => [
      ...(result.Vulnerabilities || []).map((v) => ({
        title: `${v.VulnerabilityID} · ${v.PkgName}`,
        severity: v.Severity,
        description: v.Description || v.Title,
        asset: result.Target,
        evidence: { package: v.PkgName, installed: v.InstalledVersion, fixed: v.FixedVersion },
        remediation: v.FixedVersion
          ? `Upgrade ${v.PkgName} to a compatible fixed release (${v.FixedVersion}).`
          : 'No fixed version recorded. Evaluate mitigation and vendor guidance.',
        source: 'Trivy',
        ruleId: v.VulnerabilityID,
      })),
      // secret scanning: Match holds the secret itself, so only the rule and location are kept
      ...(result.Secrets || []).map((v) => ({
        title: v.Title || v.RuleID,
        severity: v.Severity,
        description: `${v.Title || v.RuleID} found in ${result.Target}${v.StartLine ? ` at line ${v.StartLine}` : ''}. The matched value is not imported.`,
        asset: result.Target,
        evidence: {
          rule: v.RuleID,
          category: v.Category,
          startLine: v.StartLine,
          endLine: v.EndLine,
        },
        remediation:
          'Revoke and rotate the credential, then remove it from the file and its version history.',
        source: 'Trivy',
        ruleId: v.RuleID,
      })),
      ...(result.Misconfigurations || [])
        .filter((v) => !v.Status || v.Status === 'FAIL')
        .map((v) => ({
          title: v.Title || v.ID,
          severity: v.Severity,
          description: v.Message,
          asset: result.Target,
          evidence: { id: v.ID, status: v.Status },
          remediation: v.Resolution,
          source: 'Trivy',
          ruleId: v.ID,
        })),
    ]);
  } else if (format === 'prowler') {
    if (!Array.isArray(data)) throw new PolicyError('Expected a Prowler OCSF JSON array.');
    rows = data
      .filter((r) => r.status_code === 'FAIL' || r.status === 'FAIL')
      .map((r) => ({
        title: r.finding_info?.title || r.check_id || 'Cloud posture finding',
        severity: r.severity,
        description: r.finding_info?.desc || r.status_detail,
        asset: r.resources?.[0]?.uid || r.cloud?.account?.uid,
        evidence: { status: r.status_code, uid: r.finding_info?.uid },
        remediation: r.remediation?.desc || 'Review the cloud control and remediation guidance.',
        source: 'Prowler',
        ruleId: r.finding_info?.uid,
      }));
  } else if (format === 'normalized') {
    rows = Array.isArray(data) ? data : data.findings;
    if (
      !Array.isArray(rows) ||
      rows.some((r) => !r || typeof r.title !== 'string' || typeof r.severity !== 'string')
    )
      throw new PolicyError('Expected findings with title and severity.');
  } else if (format === 'linux-snapshot') {
    if (data.schema !== 'rudy.linux-snapshot.v1' || !Array.isArray(data.checks))
      throw new PolicyError('Expected a Rudy Linux snapshot.');
    rows = data.checks
      .filter((r) => r.status === 'review')
      .map((r) => ({
        title: r.title,
        severity: r.severity || 'low',
        description: r.description,
        asset: data.host?.name,
        remediation: r.remediation,
        evidence: r.evidence,
        source: 'Linux snapshot',
        ruleId: r.id,
      }));
  } else throw new PolicyError('Unsupported evidence format.');
  if (rows.length > 500)
    throw new PolicyError('Evidence exceeds the 500-finding import limit. Split the export.');
  return rows.map((r) => ({
    title: text(r.title || 'Untitled finding', 240),
    severity: severity(r.severity),
    description: text(r.description),
    remediation: text(r.remediation || 'Validate the evidence and document remediation.'),
    asset: text(r.asset || 'Unspecified asset', 512),
    evidence: text(r.evidence || 'Imported observation; inspect the original artifact.'),
    source: text(r.source || format, 120),
    ruleId: text(r.ruleId || '', 200),
    category: text(r.category || 'Imported assessment', 120),
    confidence: 'Imported — requires validation',
    status: 'open',
  }));
}
