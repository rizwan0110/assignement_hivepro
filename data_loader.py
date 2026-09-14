from pathlib import Path

import pandas as pd


DATA_DIR = Path("data")

ASSETS_PATH = DATA_DIR / "assets.csv"
VULNERABILITIES_PATH = DATA_DIR / "vulnerabilities.csv"
THREAT_INTEL_PATH = DATA_DIR / "threat_intelligence.csv"
BUSINESS_SERVICES_PATH = DATA_DIR / "business_services.csv"
REMEDIATION_GUIDANCE_PATH = DATA_DIR / "remediation_guidance.csv"
THREAT_REPORT_PATH = DATA_DIR / "synthetic_threat_report.md"


# Load every file supplied in the assignment data pack.
assets = pd.read_csv(ASSETS_PATH)
vulnerabilities = pd.read_csv(VULNERABILITIES_PATH)
threat_intel = pd.read_csv(THREAT_INTEL_PATH)
business_services = pd.read_csv(BUSINESS_SERVICES_PATH)
remediation_guidance = pd.read_csv(REMEDIATION_GUIDANCE_PATH)

with open(THREAT_REPORT_PATH, "r", encoding="utf-8") as file:
    threat_report_text = file.read()


def _join_unique(values):
    """Join repeated text values without introducing duplicates."""
    cleaned = {
        str(value).strip()
        for value in values
        if pd.notna(value) and str(value).strip()
    }
    return ", ".join(sorted(cleaned))


def _aggregate_ransomware(values):
    """Preserve a positive ransomware signal if any matching campaign has one."""
    normalized = {
        str(value).strip().lower()
        for value in values
        if pd.notna(value)
    }
    return "Yes" if "yes" in normalized else "No"


# A CVE can appear in more than one campaign. Aggregate first so the join keeps
# one row per vulnerability.
threat_agg = (
    threat_intel
    .groupby("matched_cve_or_control", as_index=False)
    .agg(
        {
            "threat_actor": _join_unique,
            "campaign_name": _join_unique,
            "target_sector": _join_unique,
            "target_region": _join_unique,
            "exploit_maturity": _join_unique,
            "ransomware_association": _aggregate_ransomware,
            "confidence": _join_unique,
            "summary": lambda values: " | ".join(
                str(value).strip()
                for value in values
                if pd.notna(value) and str(value).strip()
            ),
        }
    )
)


# Start from vulnerabilities because the final ranking is vulnerability-level.
master = vulnerabilities.merge(
    assets,
    on="asset_id",
    how="left",
    suffixes=("_vuln", "_asset"),
)

master = master.merge(
    business_services,
    on="business_service",
    how="left",
)

master = master.merge(
    threat_agg,
    left_on="cve",
    right_on="matched_cve_or_control",
    how="left",
)

master["threat_match"] = master["matched_cve_or_control"].notna()


def validate_loaded_data():
    """Run a few inexpensive checks on the assignment inputs."""
    expected_files = {
        "assets.csv": assets,
        "vulnerabilities.csv": vulnerabilities,
        "threat_intelligence.csv": threat_intel,
        "business_services.csv": business_services,
        "remediation_guidance.csv": remediation_guidance,
    }

    for name, dataframe in expected_files.items():
        if dataframe.empty:
            raise ValueError(f"{name} was loaded but contains no rows.")

    if not threat_report_text.strip():
        raise ValueError("synthetic_threat_report.md is empty.")

    if len(master) != len(vulnerabilities):
        raise ValueError(
            "Master table row count changed during joins. "
            "Expected one row per vulnerability."
        )


validate_loaded_data()


if __name__ == "__main__":
    print("Assignment data loaded successfully.")
    print(f"Assets: {len(assets)}")
    print(f"Vulnerabilities: {len(vulnerabilities)}")
    print(f"Threat-intelligence records: {len(threat_intel)}")
    print(f"Business services: {len(business_services)}")
    print(f"Remediation guidance rows: {len(remediation_guidance)}")
    print(f"Threat report characters: {len(threat_report_text)}")
    print(f"Master table rows: {len(master)}")
    print(f"Threat-matched vulnerabilities: {int(master['threat_match'].sum())}")
