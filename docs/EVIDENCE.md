# Evidence imports

All imports require an engagement and an operator session. No imported file can execute a tool. Imports are limited to 4 MB of source text and 500 normalized findings; the HTTP envelope limit is 5 MB. The server deduplicates exact artifact hashes within an engagement. It does not yet deduplicate equivalent findings from different exports.

Kernel captures use a separate **Kernel telemetry → Import capture** flow, a registered sensor, and a issued permit. They are bounded to 10,000 events and a 4-million-character signed payload. Both signatures, scope and counters are validated. The persisted artifact preserves the exact signed payload/signature strings; outer JSON whitespace is normalized. Its evidence digest covers that persisted envelope. Kernel telemetry stays separate from vulnerability findings. See [kernel protocol and privacy](KERNEL.md).

| Format            | Supported subset                                                                                                                                   |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| SARIF             | Version 2.1.0, runs/results, driver/rules, rule security severity, message and first physical location                                             |
| Semgrep JSON      | `results`, check ID, path, start/end, message, severity, optional fix                                                                              |
| Nuclei            | JSON object/array or JSONL; template ID, info, matched location, matcher metadata; request/response bodies are not copied into normalized findings |
| Trivy JSON        | `Results[].Vulnerabilities` and `Misconfigurations`; installed/fixed versions                                                                      |
| Prowler OCSF JSON | Array of `FAIL` records; finding info, severity, resource/account ID, remediation description                                                      |
| Normalized JSON   | Array, or `{ "findings": [...] }`; each finding requires string title and severity                                                                 |
| Linux snapshot    | `rudy.linux-snapshot.v1`; checks marked `review` become findings                                                                                   |

Parsers accept documented subsets, not every schema variant or proprietary export. A product's SARIF adapter is usable only if that installed edition/version exports compatible SARIF, directly or through a trusted offline conversion. No vendor API is contacted.

## Shared native SDK conversion

The optional offline utility `scripts/evidence-convert.mjs` uses [Rudy Evidence](https://github.com/r4venrudy/rudy-evidence)'s native C++ core to normalize scanner reports or validate existing `rudy-evidence/v1` bundles. It produces Central's existing **Normalized JSON** import format, retaining scope, fingerprint, location, identifiers and evidence in the evidence field. It preserves the 4 MiB / 500-finding import bounds and rejects fields that would otherwise be truncated.

Build/install the SDK, then set `RUDY_EVIDENCE_CLI` to its absolute trusted executable path:

```sh
node scripts/evidence-convert.mjs semgrep repo:example semgrep.json > central-findings.json
node scripts/evidence-convert.mjs bundle imported:example findings.evidence.json > central-findings.json
```

Select **Normalized JSON** in the existing engagement import form. Other formats are the SDK's documented subsets; use `nuclei-lines` or `sentinel-lines` for NDJSON. Conversion happens locally with no shell and a 15-second deadline. The HTTP server does not launch the SDK or accept executable paths. Bundle integrity is unkeyed, not a signature; imported findings still require validation. Review output before sharing because redaction recognizes a limited pattern policy.

## Normalized finding

```json
{
  "findings": [
    {
      "title": "Observed configuration issue",
      "severity": "medium",
      "asset": "https://your-authorized-origin.example",
      "source": "Authorized manual review",
      "category": "Web configuration",
      "description": "What was observed, and the practical limits of that observation.",
      "evidence": "Reproduction details and evidence reference, without credentials.",
      "remediation": "Specific change and how to verify it."
    }
  ]
}
```

Severity normalization is a triage convenience, not a new CVSS computation. SARIF security-severity scores use standard severity bands where present. Imported confidence is always labeled as requiring validation. Finding statuses are open, in progress, resolved, accepted, or false positive. Owner and notes record the analyst's disposition.

Raw artifacts remain unchanged. They may contain secrets or unrelated personal data, even if normalized fields omit them. Review source exports before import. Evidence exports are downloadable inert files. No malware binaries or packet capture parsers are included.
