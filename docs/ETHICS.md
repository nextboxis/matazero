# Ethics & Governance Policy — imgint

## 1. Ethical Thesis

An image intelligence tool and a surveillance/stalking tool differ primarily in **governance and structural constraints**.

`imgint` builds ethics into code rather than documentation. The tool structurally enforces authorization scopes, tamper-evident audit trails, and refuses specific surveillance capabilities regardless of flags or configuration.

## 2. Binding Refused Capabilities (GR-3.1 – GR-3.8)

The following capabilities are **not implemented in this binary** and will not be added:

| Refused Capability | Rationale & Legal Basis |
|---|---|
| **Automated Face Recognition / Biometric Matching** | Special-category data under GDPR Art. 9; represents the clearest boundary between digital forensics and mass surveillance. |
| **Bulk Platform Scraping & Crawling** | Violates Terms of Service and computer misuse statutes (CFAA, IT Act); outside file analysis scope. |
| **Cross-Platform Identity Correlation** | Automated mass deanonymization of private individuals is harmful to civil liberties and source protection. |
| **Real-Time Location Tracking** | Surveillance and harassment infrastructure; unrelated to lawful forensic investigation. |
| **External Hash DB Querying (e.g. PhotoDNA)** | Centralized restricted-access programs have their own legal governance models and leak investigative inquiries. |
| **Boolean Manipulation Verdicts** | Emitting boolean `"manipulated": true/false` is irresponsible and contributes to false accusations and miscarriages of justice. |

## 3. Mandatory Uncertainty & Caveats (ADR-008, NFR-2.1)

- Every derived and indicative finding **must** carry a confidence rating (`observed`, `derived`, `indicative`, `inconclusive`) and a contextual caveat explaining common false-positive causes.
- Single authenticity scores are refused per FR-7.8.
- Reports explicitly lead with a **"What This Report Does NOT Establish"** section per FR-9.7.

## 4. Lawful Authorization Scope (GR-1.1 – GR-1.7)

- `imgint` will refuse extraction unless an unexpired, cryptographically signed authorization scope is loaded.
- A narrow `--self-audit` mode is available exclusively for privacy-conscious individuals auditing their own photos without creating a case record.
