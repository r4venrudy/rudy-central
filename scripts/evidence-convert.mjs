import { spawnSync } from 'node:child_process';
import { open } from 'node:fs/promises';
import { isAbsolute } from 'node:path';
import { pathToFileURL } from 'node:url';

const limit = 4 * 1024 * 1024;

// Offline operator utility. The HTTP server never selects or launches this binary.
export function convertEvidence(format, scope, raw, executable = process.env.RUDY_EVIDENCE_CLI) {
  if (!executable || !isAbsolute(executable))
    throw new Error('Set RUDY_EVIDENCE_CLI to an absolute trusted SDK executable path.');
  if (Buffer.byteLength(raw) > limit) throw new Error('Input exceeds the 4 MiB conversion limit.');
  const operation =
    format === 'nuclei-lines' || format === 'sentinel-lines'
      ? 'normalize-lines'
      : format === 'bundle'
        ? 'validate'
        : 'normalize';
  const selected =
    format === 'nuclei-lines' ? 'nuclei' : format === 'sentinel-lines' ? 'rudy-sentinel' : format;
  const request =
    operation === 'normalize-lines'
      ? JSON.stringify({ operation, format: selected, scope, text: raw })
      : `{"operation":${JSON.stringify(operation)},"format":${JSON.stringify(selected)},"scope":${JSON.stringify(scope)},"document":${raw}}`;
  const result = spawnSync(executable, ['request'], {
    input: request,
    encoding: 'utf8',
    shell: false,
    windowsHide: true,
    timeout: 15000,
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.error || result.status !== 0)
    throw new Error('Native evidence conversion failed; inspect the input locally with the SDK.');
  const bundle = operation === 'validate' ? JSON.parse(raw) : JSON.parse(result.stdout);
  if (bundle.findings.length > 500)
    throw new Error('Central imports at most 500 findings. Split the report.');
  const findings = bundle.findings.map((f) => {
    const evidence = JSON.stringify({
      scope: f.scope,
      fingerprint: f.fingerprint,
      location: f.location,
      evidence: f.evidence,
      identifiers: f.identifiers,
    });
    if (
      f.title.length > 240 ||
      f.asset.id.length > 512 ||
      f.producer.length > 120 ||
      f.rule_id.length > 200 ||
      evidence.length > 8000
    )
      throw new Error(
        'A finding exceeds Central field limits. Review and split the source evidence.',
      );
    return {
      title: f.title,
      severity: f.severity,
      asset: f.asset.id,
      source: f.producer,
      ruleId: f.rule_id,
      category: 'SDK evidence import',
      description: f.title,
      evidence,
      remediation: 'Validate the imported observation and record remediation in context.',
    };
  });
  const converted = { findings };
  if (Buffer.byteLength(JSON.stringify(converted)) > limit)
    throw new Error('Converted report exceeds the Central import limit.');
  return converted;
}

async function readBounded(path) {
  const file = await open(path, 'r');
  try {
    const bytes = Buffer.alloc(limit + 1);
    let used = 0;
    while (used < bytes.length) {
      const { bytesRead } = await file.read(bytes, used, bytes.length - used, null);
      if (!bytesRead) break;
      used += bytesRead;
    }
    if (used > limit) throw new Error('Input exceeds the 4 MiB conversion limit.');
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, used));
  } finally {
    await file.close();
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const [format, scope, file, ...extra] = process.argv.slice(2);
    if (!format || !scope || !file || extra.length)
      throw new Error('Usage: node scripts/evidence-convert.mjs FORMAT SCOPE INPUT_FILE');
    const result = convertEvidence(format, scope, await readBounded(file));
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
