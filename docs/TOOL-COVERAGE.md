# Tool coverage

Every product and framework from the supplied scope is represented below. Similar or renamed products share a clearly named registry entry. Entries describe available evidence workflows; they do not mean an executable or licensed service is bundled.

Native runtime capabilities are the bounded web baseline, evidence normalization, and the unprivileged Linux posture collector. There is no arbitrary command runner.

## Offensive security

Reconnaissance, controlled validation, and evidence-led reporting.

| Product / reference | Release status    | Evidence adapter                    |
| ------------------- | ----------------- | ----------------------------------- |
| Kali Linux          | External workflow | Normalized JSON after manual review |
| Nmap                | External workflow | Normalized JSON after manual review |
| Metasploit          | Lab workflow only | Normalized JSON after manual review |
| Burp Suite          | External workflow | Normalized JSON after manual review |
| Nessus              | External workflow | Normalized JSON after manual review |
| OpenVAS / Greenbone | External workflow | Normalized JSON after manual review |
| Cobalt Strike       | Lab workflow only | Normalized JSON after manual review |
| BloodHound          | External workflow | Normalized JSON after manual review |
| Hydra               | Lab workflow only | Normalized JSON after manual review |
| John the Ripper     | External workflow | Normalized JSON after manual review |
| Hashcat             | External workflow | Normalized JSON after manual review |
| Impacket            | Lab workflow only | Normalized JSON after manual review |

## Application security

Source, dependencies, APIs, and running applications.

| Product / reference              | Release status    | Evidence adapter                    |
| -------------------------------- | ----------------- | ----------------------------------- |
| OWASP ZAP                        | Import ready      | SARIF                               |
| sqlmap                           | Lab workflow only | Normalized JSON after manual review |
| Nuclei                           | Import ready      | NUCLEI                              |
| Semgrep                          | Import ready      | SEMGREP                             |
| SonarQube                        | External workflow | Normalized JSON after manual review |
| Snyk                             | Import ready      | SARIF                               |
| Dependabot                       | External workflow | Normalized JSON after manual review |
| Postman                          | External workflow | Normalized JSON after manual review |
| OWASP Juice Shop                 | Training target   | Normalized JSON after manual review |
| DVWA                             | Training target   | Normalized JSON after manual review |
| PortSwigger Web Security Academy | Training target   | Normalized JSON after manual review |
| Trivy                            | Import ready      | TRIVY                               |
| Grype                            | External workflow | Normalized JSON after manual review |
| Gitleaks                         | Import ready      | SARIF                               |
| Checkov                          | Import ready      | SARIF                               |
| Syft                             | External workflow | Normalized JSON after manual review |

## Network security

Exposure, segmentation, and packet evidence.

| Product / reference | Release status    | Evidence adapter                    |
| ------------------- | ----------------- | ----------------------------------- |
| Wireshark           | External workflow | Normalized JSON after manual review |
| tcpdump             | External workflow | Normalized JSON after manual review |
| pfSense             | External workflow | Normalized JSON after manual review |
| Snort               | External workflow | Normalized JSON after manual review |
| Suricata            | External workflow | Normalized JSON after manual review |
| Zeek                | External workflow | Normalized JSON after manual review |
| Aircrack-ng         | Lab workflow only | Normalized JSON after manual review |
| Shodan              | External workflow | Normalized JSON after manual review |

## Cloud security

Configuration, cloud identities, and delivery pipelines.

| Product / reference         | Release status    | Evidence adapter                    |
| --------------------------- | ----------------- | ----------------------------------- |
| ScoutSuite                  | External workflow | Normalized JSON after manual review |
| Prowler                     | Import ready      | PROWLER                             |
| CloudSploit                 | External workflow | Normalized JSON after manual review |
| Pacu                        | Lab workflow only | Normalized JSON after manual review |
| AWS Security Hub            | External workflow | Normalized JSON after manual review |
| Azure Defender              | External workflow | Normalized JSON after manual review |
| GCP Security Command Center | External workflow | Normalized JSON after manual review |
| Terraform                   | External workflow | Normalized JSON after manual review |
| tfsec                       | Import ready      | SARIF                               |
| Wiz                         | External workflow | Normalized JSON after manual review |
| Orca                        | External workflow | Normalized JSON after manual review |
| kube-bench                  | External workflow | Normalized JSON after manual review |

## Detection & response

Detection engineering, hunting, and incident triage.

| Product / reference | Release status    | Evidence adapter                    |
| ------------------- | ----------------- | ----------------------------------- |
| Splunk              | External workflow | Normalized JSON after manual review |
| Elastic / ELK Stack | External workflow | Normalized JSON after manual review |
| Microsoft Sentinel  | External workflow | Normalized JSON after manual review |
| CrowdStrike         | External workflow | Normalized JSON after manual review |
| SentinelOne         | External workflow | Normalized JSON after manual review |
| Microsoft Defender  | External workflow | Normalized JSON after manual review |
| Sigma               | Reference         | Normalized JSON after manual review |
| Wazuh               | External workflow | Normalized JSON after manual review |
| MITRE ATT&CK        | Reference         | Normalized JSON after manual review |
| Falco               | External workflow | Normalized JSON after manual review |

## Forensics & incident response

Evidence integrity, timelines, and reconstruction.

| Product / reference      | Release status    | Evidence adapter                    |
| ------------------------ | ----------------- | ----------------------------------- |
| Autopsy / The Sleuth Kit | External workflow | Normalized JSON after manual review |
| Volatility               | External workflow | Normalized JSON after manual review |
| FTK                      | External workflow | Normalized JSON after manual review |
| EnCase                   | External workflow | Normalized JSON after manual review |
| Velociraptor             | External workflow | Normalized JSON after manual review |
| KAPE                     | External workflow | Normalized JSON after manual review |
| Timesketch               | External workflow | Normalized JSON after manual review |

## Malware & reverse engineering

Static analysis and isolated sandbox evidence.

| Product / reference | Release status    | Evidence adapter                    |
| ------------------- | ----------------- | ----------------------------------- |
| Ghidra              | External workflow | Normalized JSON after manual review |
| IDA Pro             | External workflow | Normalized JSON after manual review |
| x64dbg              | External workflow | Normalized JSON after manual review |
| OllyDbg             | External workflow | Normalized JSON after manual review |
| Cuckoo Sandbox      | External workflow | Normalized JSON after manual review |
| ANY.RUN             | External workflow | Normalized JSON after manual review |
| PEStudio            | External workflow | Normalized JSON after manual review |
| YARA                | External workflow | Normalized JSON after manual review |

## Cryptography

Transport configuration, certificates, and key hygiene.

| Product / reference            | Release status    | Evidence adapter                    |
| ------------------------------ | ----------------- | ----------------------------------- |
| OpenSSL                        | External workflow | Normalized JSON after manual review |
| TLS / AES / RSA / SHA / bcrypt | Reference         | Normalized JSON after manual review |
| testssl.sh                     | External workflow | Normalized JSON after manual review |

## Governance, risk & compliance

Control evidence, risk ownership, and remediation.

| Product / reference         | Release status    | Evidence adapter                    |
| --------------------------- | ----------------- | ----------------------------------- |
| Vanta                       | External workflow | Normalized JSON after manual review |
| Drata                       | External workflow | Normalized JSON after manual review |
| Archer                      | External workflow | Normalized JSON after manual review |
| NIST CSF                    | Reference         | Normalized JSON after manual review |
| CIS Controls                | Reference         | Normalized JSON after manual review |
| SOC 2 / ISO 27001 / PCI-DSS | Reference         | Normalized JSON after manual review |
| HIPAA / GDPR                | Reference         | Normalized JSON after manual review |

## Identity & access

Authentication, access reviews, and privileged identities.

| Product / reference            | Release status    | Evidence adapter                    |
| ------------------------------ | ----------------- | ----------------------------------- |
| Okta                           | External workflow | Normalized JSON after manual review |
| Azure AD / Entra               | External workflow | Normalized JSON after manual review |
| Ping Identity                  | External workflow | Normalized JSON after manual review |
| CyberArk                       | External workflow | Normalized JSON after manual review |
| OAuth / SAML / OIDC / Kerberos | Reference         | Normalized JSON after manual review |

## Adapter acceptance

Any future executable adapter requires pinned binaries, a license review, a declared target kind, exact authorization proof, a capability-specific signed permit, bounded arguments, an isolated process boundary, resource limits, restricted network egress, cancellation, audited result provenance, and tests against owned fixtures. No catalog field may be interpolated into a shell command.
