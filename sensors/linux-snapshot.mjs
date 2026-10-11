#!/usr/bin/env node
// Offline, read-only posture collection. No subprocesses, root, network, or kernel loading.
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
if (process.platform !== 'linux') {
  console.error('The posture collector requires Linux. Nothing was collected.');
  process.exit(1);
}
const args = process.argv.slice(2),
  outIndex = args.indexOf('--out');
if (args.length && !(args.length === 2 && outIndex === 0 && args[1])) {
  console.error('Usage: node sensors/linux-snapshot.mjs [--out snapshot.json]');
  process.exit(1);
}
const read = async (file) => {
  try {
    return (await fs.readFile(file, 'utf8')).trim();
  } catch {
    return null;
  }
};
const specs = [
  {
    id: 'kptr_restrict',
    path: '/proc/sys/kernel/kptr_restrict',
    min: 1,
    title: 'Kernel pointer exposure requires review',
    description: 'kptr_restrict controls exposure of kernel addresses in supported interfaces.',
    remediation:
      'Review the host hardening baseline and configure kptr_restrict according to workload requirements.',
  },
  {
    id: 'dmesg_restrict',
    path: '/proc/sys/kernel/dmesg_restrict',
    min: 1,
    title: 'Unprivileged kernel log access requires review',
    description: 'Unrestricted kernel log access may reveal sensitive system details.',
    remediation:
      'Review whether unprivileged users need kernel log access; consider dmesg_restrict=1.',
  },
  {
    id: 'ptrace_scope',
    path: '/proc/sys/kernel/yama/ptrace_scope',
    min: 1,
    title: 'Process tracing policy requires review',
    description: 'The Yama ptrace policy is permissive on this host.',
    remediation: 'Review debugging requirements before tightening ptrace_scope.',
  },
  {
    id: 'unprivileged_bpf_disabled',
    path: '/proc/sys/kernel/unprivileged_bpf_disabled',
    min: 1,
    title: 'Unprivileged BPF policy requires review',
    description: 'The host allows unprivileged BPF loading.',
    remediation:
      'Review application requirements and the distribution hardening guidance for unprivileged BPF.',
  },
  {
    id: 'randomize_va_space',
    path: '/proc/sys/kernel/randomize_va_space',
    min: 2,
    title: 'Address-space randomization requires review',
    description: 'Full supported address-space randomization is not enabled.',
    remediation:
      'Review compatibility and the distribution baseline before setting randomize_va_space=2.',
  },
];
const checks = [];
for (const spec of specs) {
  const value = await read(spec.path);
  checks.push({
    id: spec.id,
    title: spec.title,
    status: value === null ? 'unavailable' : Number(value) >= spec.min ? 'observed' : 'review',
    severity: 'low',
    description: spec.description,
    remediation: spec.remediation,
    evidence: `${spec.path}: ${value ?? 'not readable'}`,
  });
}
const snapshot = {
  schema: 'rudy.linux-snapshot.v1',
  collectedAt: new Date().toISOString(),
  host: {
    name: os.hostname(),
    platform: os.platform(),
    kernel: os.release(),
    architecture: os.arch(),
  },
  collector: { version: '0.1.0', privilege: 'current user', network: 'none' },
  checks,
  mounts:
    (await read('/proc/mounts'))
      ?.split('\n')
      .filter((line) => line.includes(' / ') || line.includes(' /tmp '))
      .map((line) => line.split(' ').slice(0, 4).join(' ')) || [],
};
const serialized = JSON.stringify(snapshot, null, 2) + '\n';
if (outIndex !== -1) {
  const output = path.resolve(args[outIndex + 1]);
  await fs.writeFile(output, serialized, { flag: 'wx', mode: 0o600 });
  console.log(
    `Snapshot saved: ${output}\nSHA-256: ${crypto.createHash('sha256').update(serialized).digest('hex')}`,
  );
} else process.stdout.write(serialized);
