# TawasolPay Cyber Risk Assistant

A lightweight cyber-risk prioritization system built for the Hive Pro AI Associate take-home assignment.

The system combines asset inventory, vulnerability data, business context, threat intelligence, CISA Known Exploited Vulnerabilities (KEV), NIST SP 800-53 Rev. 5, and an LLM explanation layer to produce a ranked Top 5 risk list with evidence and remediation guidance.

---

## Live Demo

**Public URL:** https://assignementhivepro.streamlit.app/

**GitHub Repository:** https://github.com/rizwan0110/assignement_hivepro

---

## What the system does

The system:

- ingests all five CSV files and the supplied MDR threat report;
- joins asset, vulnerability, threat-intelligence, and business-service data into one vulnerability-level master table;
- enriches CVEs with the official CISA KEV catalog;
- calculates a deterministic 0–100 risk score;
- ranks the Top 5 risks using business and threat context, not CVSS alone;
- retrieves relevant NIST SP 800-53 Rev. 5 controls using embeddings and FAISS;
- uses an LLM only to select and summarize from retrieved NIST controls;
- validates the LLM output so unsupported NIST controls are rejected;
- presents the final output in a Streamlit web application;
- includes automated pytest checks for the deterministic pipeline.

---

## Architecture

```text
Assignment data pack
  assets.csv
  vulnerabilities.csv
  threat_intelligence.csv
  business_services.csv
  remediation_guidance.csv
  synthetic_threat_report.md
        |
        v
Structured loading + contextual ingestion
        |
        v
Master vulnerability table
        |
        v
CISA KEV enrichment
        |
        v
Deterministic risk scoring
        |
        v
Ranked Top 5 risks
        |
        +-------------------------------+
        |                               |
        v                               v
Official NIST SP 800-53           Risk evidence
Rev. 5 OSCAL catalog                  |
        |                              |
        v                              |
Sentence-transformer embeddings       |
        |                              |
        v                              |
FAISS vector index                    |
        |                              |
        +-------------> retrieval <----+
                         |
                         v
                 Top NIST candidates
                         |
                         v
                 Grounded LLM selection
                         |
                         v
                 Validated JSON output
                         |
                         v
                    Streamlit UI
```

---

## Data pipeline

### 1. Assignment data ingestion

All supplied files are loaded by the pipeline.

The four core structured datasets used for ranking are:

- `assets.csv`
- `vulnerabilities.csv`
- `threat_intelligence.csv`
- `business_services.csv`

The additional supplied sources are also ingested:

- `remediation_guidance.csv` is retained as supporting remediation context only. It is not treated as the authoritative answer because the assignment requires final remediation guidance to come from NIST SP 800-53.
- `synthetic_threat_report.md` is loaded as contextual threat information. Its prioritization guidance informed the scoring design, while the actual ranking remains based on structured fields and external CISA evidence.

### 2. Master table

`vulnerabilities.csv` is used as the base table because each row represents one vulnerability.

It is enriched with:

- `assets.csv` via `asset_id`;
- `business_services.csv` via `business_service`;
- `threat_intelligence.csv` via CVE.

Threat-intelligence rows are aggregated by CVE before the join so that a vulnerability is not duplicated when the same CVE appears in more than one campaign.

The resulting table preserves one row per vulnerability.

### 3. CISA KEV enrichment

The system downloads the official CISA Known Exploited Vulnerabilities catalog and matches it to the vulnerability table by CVE.

For matched vulnerabilities, it adds:

- KEV match status;
- CISA ransomware association;
- date added;
- required action;
- vendor and product context.

CISA is used as an authoritative validation and fallback source. It does not receive a separate scoring category, which avoids double-counting exploitation or ransomware evidence.

### 4. NIST retrieval

The official NIST SP 800-53 Rev. 5 OSCAL catalog is downloaded and parsed into individual controls.

Each control is embedded with:

```text
sentence-transformers/all-MiniLM-L6-v2
```

The embeddings are stored in a FAISS index.

For each Top 5 risk, the system constructs a remediation-oriented query containing the vulnerability, asset, business service, exploit status, threat campaign, ransomware evidence, and CISA action. FAISS retrieves the most semantically relevant NIST controls.

### 5. Grounded LLM explanation

The LLM does **not** calculate risk scores and does **not** invent remediation controls.

It receives only:

- the selected risk evidence; and
- NIST controls already retrieved by FAISS.

The model returns structured JSON containing:

- a short risk explanation;
- one selected NIST control;
- the exact control title;
- a concise remediation explanation.

The application validates that the returned control ID is one of the retrieved candidates before accepting the output.

---

## Risk-scoring approach

The scoring engine is deterministic and uses a 0–100 scale.

| Factor | Max points | Rationale |
|---|---:|---|
| CVSS | 15 | Technical severity matters, but does not dominate |
| Internet exposure | 20 | Internet-facing assets are directly reachable |
| Active exploit signal | 15 | Exploit availability or CISA KEV evidence increases practical risk |
| Active threat-intelligence match | 15 | Indicates current campaign activity against the CVE |
| Ransomware association | 10 | Raises operational and business impact |
| Asset criticality | 10 | Critical assets receive greater priority |
| Business impact | 5 | Customer-facing, revenue-critical, and compliance-scoped services receive more weight |
| Missing EDR | 5 | Missing compensating controls increase exposure |
| Vulnerability age | 5 | Long-unresolved vulnerabilities receive a small additional penalty |
| **Total** | **100** | |

The main design principle is:

> **CVSS tells us how severe the vulnerability is technically; the contextual signals tell us how risky it is to TawasolPay right now.**

This prevents a CVSS 10 issue on an internal, low-impact development system from automatically outranking a lower-CVSS vulnerability on an internet-facing payment system with active exploitation and ransomware evidence.

Ties are resolved deterministically using risk score, CVSS, days open, and vulnerability ID.

---

## Example output

Each final risk entry contains:

- rank and risk score;
- asset;
- vulnerability and CVE;
- affected business service;
- matched threat actor and campaign;
- CISA KEV status;
- plain-English explanation of why it ranks highly;
- recommended NIST control;
- grounded remediation explanation.

---

## Project structure

```text
assignment/
├── app.py
├── data_loader.py
├── cisa_enrichment.py
├── risk_engine.py
├── nist_retriever.py
├── llm_explainer.py
├── requirements.txt
├── .gitignore
├── README.md
│
├── data/
│   ├── assets.csv
│   ├── vulnerabilities.csv
│   ├── threat_intelligence.csv
│   ├── business_services.csv
│   ├── remediation_guidance.csv
│   └── synthetic_threat_report.md
│
├── artifacts/
│   └── top_5_risks.json
│
└── tests/
    ├── conftest.py
    └── test_pipeline.py
```

---

## Running locally

### 1. Clone the repository

```bash
git clone <YOUR_REPO_URL>
cd <YOUR_REPO_FOLDER>
```

### 2. Create a virtual environment

Windows:

```bash
python -m venv .venv
.venv\Scripts\activate
```

macOS/Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Add the Groq API key

Create a `.env` file in the project root:

```env
GROQ_API_KEY=your_groq_api_key
```

Do not commit `.env`.

### 5. Run the pipeline

```bash
python data_loader.py
python cisa_enrichment.py
python risk_engine.py
python nist_retriever.py
python llm_explainer.py
```

This generates:

```text
artifacts/top_5_risks.json
```

### 6. Run the Streamlit application

```bash
streamlit run app.py
```

The app will be available locally at:

```text
http://localhost:8501
```

---

## Tests

Run:

```bash
python -m pytest -v
```

The current test suite checks:

- master-table row integrity;
- risk-score bounds;
- Top 5 output size;
- descending ranking order;
- exposure-mismatch detection;
- the known exposure inconsistency in the supplied dataset.

At the time of submission:

```text
6 tests passed
```

---

# Supporting questions

## 1. What data did you embed and why? What data did you query as structured records and why?

I kept the asset, vulnerability, business-service, threat-intelligence, CISA KEV, remediation-guidance, and threat-report inputs outside the vector store because they are either structured records or explicit contextual evidence. Exact joins, filters, and deterministic scoring are more reliable for fields such as `asset_id`, CVE, internet exposure, criticality, exploit availability, and ransomware status.

I embedded only the NIST SP 800-53 Rev. 5 control prose because remediation matching is a semantic-search problem. A risk description may not use the exact wording of a NIST control, so embeddings allow the system to retrieve controls that are conceptually relevant while keeping the structured risk calculation separate and reproducible.

---

## 2. Three specific ways the system can produce an incorrect or misleading output

### A. Missing or incomplete CISA KEV coverage

A CVE may not have a matching entry in CISA KEV even though exploitation is occurring, or a newly exploited vulnerability may not yet have been added to the catalog. In that case, the system could understate the strength of exploitation evidence.

**Mitigation:** CISA KEV is not used as the only exploitation source. The system combines it with the supplied `exploit_available` field and local threat intelligence. In a production version, I would also monitor KEV update timestamps and use additional trusted threat-intelligence feeds.

### B. Conflicting source data

The supplied dataset contains a case where the asset inventory marks `payment-api-prod-02` as internet-exposed while the vulnerability record labels it internal. If the system silently trusted the wrong field, the risk score could be misleading.

**Mitigation:** the implementation explicitly compares the two exposure fields and creates an `exposure_mismatch` warning. The asset inventory is currently treated as the primary exposure source, while the disagreement is surfaced for review rather than hidden.

### C. Semantic retrieval can return a relevant but suboptimal NIST control

Vector similarity may retrieve a broadly related control such as cyber resiliency or planning ahead of the most actionable control such as `SI-2 - Flaw Remediation`. A high semantic-similarity score does not guarantee that a control is the best operational recommendation.

**Mitigation:** the system retrieves multiple NIST candidates rather than trusting only the first result. The LLM is restricted to selecting from those retrieved candidates, and the selected control ID is validated in Python before the result is accepted. I would further improve this with a dedicated retrieval evaluation set and reranking.

---

## 3. If I had another day, what is the single most important thing I would improve?

The most important improvement would be to build a proper **retrieval and recommendation evaluation set for the NIST layer**. The current FAISS retrieval is semantically reasonable, but similarity alone can return controls that are related without being the most actionable remediation. I would create a small labeled set of representative vulnerability scenarios with expected NIST controls, measure metrics such as Recall@K and MRR, and then tune the query construction or add a reranker. This would directly improve the reliability of the remediation guidance, which is the least deterministic part of the current pipeline.

---

## Technology choices

- **Python / pandas** - structured data processing and joins
- **CISA KEV** - authoritative exploitation evidence
- **NIST SP 800-53 Rev. 5 OSCAL** - authoritative remediation source
- **sentence-transformers** - local embeddings
- **FAISS** - local vector retrieval
- **Groq + GPT-OSS 20B** - grounded explanation layer
- **Streamlit** - lightweight public interface
- **pytest** - deterministic pipeline checks

---

## Design decisions

### Why not let the LLM rank vulnerabilities?

The ranking needs to be repeatable and explainable. A deterministic scoring model guarantees that the same evidence produces the same ordering and makes it possible to show exactly which factors contributed to the score.

### Why not hardcode NIST controls?

The assignment requires remediation guidance to be retrieved from the actual NIST document. The system therefore retrieves controls from the official SP 800-53 Rev. 5 catalog instead of relying on model memory or hardcoded mappings.

### Why use an LLM at all?

The LLM is useful for turning structured evidence and retrieved NIST prose into concise, readable output. It is deliberately placed after scoring and retrieval so that it does not control the core risk decision or act as the source of remediation truth.

---

## Security and reproducibility notes

- API keys are loaded from environment variables and are not committed to source control.
- CISA and NIST data are downloaded from public authoritative sources and cached locally.
- The Streamlit UI reads the generated validated JSON artifact instead of invoking the LLM on every page load.
- The provided TawasolPay data and threat actors are synthetic and should not be used for real operational security decisions.

---

## Disclaimer

This project was created for a hiring assessment using synthetic data. It is not intended to replace a production vulnerability-management or security-operations platform.
