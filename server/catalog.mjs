// Catalog entries are integration contracts, never arbitrary command templates.
const groups = [
  [
    'red-team',
    'Offensive security',
    'Reconnaissance, controlled validation, and evidence-led reporting.',
    [
      ['Kali Linux', 'Security testing environment', 'environment'],
      ['Nmap', 'Network discovery and service inventory', 'external'],
      ['Metasploit', 'Exploit validation in an isolated lab', 'restricted'],
      ['Burp Suite', 'Web application proxy and testing', 'external'],
      ['Nessus', 'Infrastructure vulnerability assessment', 'external'],
      ['OpenVAS / Greenbone', 'Infrastructure vulnerability assessment', 'external'],
      ['Cobalt Strike', 'Licensed adversary-emulation workspace', 'restricted'],
      ['BloodHound', 'Identity relationships and attack-path analysis', 'external'],
      ['Hydra', 'Online credential auditing in an isolated lab', 'restricted'],
      ['John the Ripper', 'Offline password-strength assessment', 'external'],
      ['Hashcat', 'Offline password-strength assessment', 'external'],
      ['Impacket', 'Windows protocol assessment in an isolated lab', 'restricted'],
    ],
  ],
  [
    'appsec',
    'Application security',
    'Source, dependencies, APIs, and running applications.',
    [
      ['OWASP ZAP', 'Web application assessment results', 'sarif'],
      ['sqlmap', 'SQL injection validation in an isolated lab', 'restricted'],
      ['Nuclei', 'Template-based vulnerability results', 'nuclei'],
      ['Semgrep', 'Static application security analysis', 'semgrep'],
      ['SonarQube', 'Code quality and security findings', 'external'],
      ['Snyk', 'Dependency and source findings', 'sarif'],
      ['Dependabot', 'Dependency vulnerability findings', 'external'],
      ['Postman', 'API collections and manual workflows', 'external'],
      ['OWASP Juice Shop', 'Intentionally vulnerable practice application', 'lab'],
      ['DVWA', 'Intentionally vulnerable practice application', 'lab'],
      ['PortSwigger Web Security Academy', 'Guided web-security practice', 'lab'],
      ['Trivy', 'Dependencies, containers, and configuration results', 'trivy'],
      ['Grype', 'Software composition analysis', 'external'],
      ['Gitleaks', 'Repository secret-detection findings', 'sarif'],
      ['Checkov', 'Infrastructure-as-code analysis', 'sarif'],
      ['Syft', 'Software bill of materials', 'external'],
    ],
  ],
  [
    'network',
    'Network security',
    'Exposure, segmentation, and packet evidence.',
    [
      ['Wireshark', 'Packet inspection and protocol analysis', 'external'],
      ['tcpdump', 'Packet capture workflow', 'external'],
      ['pfSense', 'Firewall and segmentation configuration review', 'external'],
      ['Snort', 'Network intrusion detection', 'external'],
      ['Suricata', 'Network detection and telemetry', 'external'],
      ['Zeek', 'Network security monitoring', 'external'],
      ['Aircrack-ng', 'Wireless assessment in a controlled lab', 'restricted'],
      ['Shodan', 'Public exposure intelligence', 'external'],
    ],
  ],
  [
    'cloud',
    'Cloud security',
    'Configuration, cloud identities, and delivery pipelines.',
    [
      ['ScoutSuite', 'Cloud configuration review', 'external'],
      ['Prowler', 'Cloud posture assessment results', 'prowler'],
      ['CloudSploit', 'Cloud configuration auditing', 'external'],
      ['Pacu', 'AWS attack simulation in an isolated lab', 'restricted'],
      ['AWS Security Hub', 'AWS security posture and findings', 'external'],
      ['Azure Defender', 'Microsoft Defender for Cloud findings', 'external'],
      ['GCP Security Command Center', 'Google Cloud posture and findings', 'external'],
      ['Terraform', 'Infrastructure configuration review', 'external'],
      ['tfsec', 'Terraform security analysis results', 'sarif'],
      ['Wiz', 'Commercial cloud security posture', 'external'],
      ['Orca', 'Commercial cloud security posture', 'external'],
      ['kube-bench', 'Kubernetes benchmark assessment', 'external'],
    ],
  ],
  [
    'defense',
    'Detection & response',
    'Detection engineering, hunting, and incident triage.',
    [
      ['Splunk', 'Security event search and correlation', 'external'],
      ['Elastic / ELK Stack', 'Search, analytics, and security events', 'external'],
      ['Microsoft Sentinel', 'Cloud SIEM incident workflow', 'external'],
      ['CrowdStrike', 'Endpoint security incident evidence', 'external'],
      ['SentinelOne', 'Endpoint security incident evidence', 'external'],
      ['Microsoft Defender', 'Endpoint security incident evidence', 'external'],
      ['Sigma', 'Portable detection rule workflow', 'reference'],
      ['Wazuh', 'Host security and detection events', 'external'],
      ['MITRE ATT&CK', 'Adversary technique reference', 'reference'],
      ['Falco', 'Runtime security event evidence', 'external'],
    ],
  ],
  [
    'dfir',
    'Forensics & incident response',
    'Evidence integrity, timelines, and reconstruction.',
    [
      ['Autopsy / The Sleuth Kit', 'Disk forensic analysis', 'external'],
      ['Volatility', 'Memory forensic analysis', 'external'],
      ['FTK', 'Commercial forensic analysis', 'external'],
      ['EnCase', 'Commercial forensic analysis', 'external'],
      ['Velociraptor', 'Endpoint hunting and forensic collection', 'external'],
      ['KAPE', 'Forensic artifact collection', 'external'],
      ['Timesketch', 'Collaborative timeline investigation', 'external'],
    ],
  ],
  [
    'malware',
    'Malware & reverse engineering',
    'Static analysis and isolated sandbox evidence.',
    [
      ['Ghidra', 'Binary reverse engineering', 'external'],
      ['IDA Pro', 'Commercial reverse engineering', 'external'],
      ['x64dbg', 'Windows debugging', 'external'],
      ['OllyDbg', 'Windows debugging', 'external'],
      ['Cuckoo Sandbox', 'Isolated dynamic analysis', 'external'],
      ['ANY.RUN', 'Commercial interactive sandbox', 'external'],
      ['PEStudio', 'Static Windows executable analysis', 'external'],
      ['YARA', 'Malware pattern-matching workflow', 'external'],
    ],
  ],
  [
    'crypto',
    'Cryptography',
    'Transport configuration, certificates, and key hygiene.',
    [
      ['OpenSSL', 'TLS and certificate inspection workflow', 'external'],
      ['TLS / AES / RSA / SHA / bcrypt', 'Cryptographic implementation review', 'reference'],
      ['testssl.sh', 'TLS configuration assessment', 'external'],
    ],
  ],
  [
    'grc',
    'Governance, risk & compliance',
    'Control evidence, risk ownership, and remediation.',
    [
      ['Vanta', 'Commercial compliance evidence workflow', 'external'],
      ['Drata', 'Commercial compliance evidence workflow', 'external'],
      ['Archer', 'Risk and compliance management', 'external'],
      ['NIST CSF', 'Cybersecurity risk management framework', 'reference'],
      ['CIS Controls', 'Prioritized security-control framework', 'reference'],
      ['SOC 2 / ISO 27001 / PCI-DSS', 'Assurance and compliance frameworks', 'reference'],
      ['HIPAA / GDPR', 'Privacy and security obligations', 'reference'],
    ],
  ],
  [
    'identity',
    'Identity & access',
    'Authentication, access reviews, and privileged identities.',
    [
      ['Okta', 'Identity configuration and event review', 'external'],
      ['Azure AD / Entra', 'Microsoft identity and access review', 'external'],
      ['Ping Identity', 'Identity federation review', 'external'],
      ['CyberArk', 'Privileged access review', 'external'],
      [
        'OAuth / SAML / OIDC / Kerberos',
        'Authentication and federation protocol review',
        'reference',
      ],
    ],
  ],
];
const importers = new Set(['sarif', 'nuclei', 'semgrep', 'trivy', 'prowler']);
export const domains = groups.map(([id, name, description, entries]) => ({
  id,
  name,
  description,
  count: entries.length,
}));
export const catalog = groups.flatMap(([domain, , , entries]) =>
  entries.map(([name, description, adapter]) => ({
    id: name
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/-$/, ''),
    name,
    description,
    domain,
    adapter,
    status: importers.has(adapter)
      ? 'Import ready'
      : adapter === 'restricted'
        ? 'Lab workflow only'
        : adapter === 'reference'
          ? 'Reference'
          : adapter === 'lab'
            ? 'Training target'
            : 'External workflow',
    execution: 'No executable bundled',
    requirements:
      adapter === 'restricted'
        ? 'Isolated lab, explicit written authorization, and separately installed/licensed tooling. No remote execution adapter is provided.'
        : importers.has(adapter)
          ? `Export ${adapter.toUpperCase()} findings from your authorized assessment. Import and normalize evidence locally.`
          : adapter === 'reference'
            ? 'Use as a reference in an assessment; inclusion does not certify compliance.'
            : 'Requires a separately installed or licensed product. Attach results using the normalized JSON evidence format. A direct connector is not implemented.',
  })),
);
export const nativeChecks = [
  {
    id: 'kernel-capture',
    name: 'Linux kernel telemetry',
    description:
      'Rust + eBPF process and connection-attempt metadata, host-bound permits, signed offline evidence.',
    requests: 0,
    status: 'Linux agent',
  },
  {
    id: 'web-baseline',
    name: 'Web security baseline',
    description: 'One HTTPS GET: response headers, cookie attributes, and negotiated TLS metadata.',
    requests: 1,
    status: 'Native',
  },
  {
    id: 'evidence-import',
    name: 'Evidence normalization',
    description:
      'SARIF 2.1, Semgrep JSON, Nuclei JSON/JSONL, Trivy JSON, Prowler OCSF JSON, and normalized JSON.',
    requests: 0,
    status: 'Native',
  },
  {
    id: 'linux-snapshot',
    name: 'Linux posture snapshot',
    description:
      'Unprivileged, local-only kernel/version, hardening settings, and mount configuration collection.',
    requests: 0,
    status: 'Native',
  },
];
