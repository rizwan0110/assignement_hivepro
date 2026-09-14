import pandas as pd

from cisa_enrichment import enriched_master


CRITICALITY_POINTS = {
    "critical": 10,
    "high": 7,
    "medium": 4,
    "low": 1,
}


def score_cvss(value):
    if pd.isna(value):
        return 0
    return (float(value) / 10) * 15


def score_yes_no(value, points):
    return points if str(value).strip().lower() == "yes" else 0


def score_flag(value, points):
    return points if bool(value) else 0


def score_asset_criticality(value):
    return CRITICALITY_POINTS.get(str(value).strip().lower(), 0)


def score_business_impact(row):
    """Small business-context boost, capped at five points."""
    points = 0

    if str(row["customer_facing"]).strip().lower() == "yes":
        points += 2

    if str(row["revenue_impact"]).strip().lower() == "critical":
        points += 2

    compliance = row["compliance_scope"]
    if pd.notna(compliance) and str(compliance).strip().lower() not in {"", "none", "nan"}:
        points += 1

    return min(points, 5)


def score_days_open(days):
    if pd.isna(days):
        return 0

    days = int(days)
    if days > 180:
        return 5
    if days > 90:
        return 3
    if days > 60:
        return 2
    if days > 30:
        return 1
    return 0


def exposure_mismatch(row):
    """Flag disagreements between asset inventory and scanner exposure data."""
    asset_exposed = str(row["internet_exposed"]).strip().lower() == "yes"
    scanner_exposed = str(row["asset_exposure"]).strip().lower() == "internet"
    return asset_exposed != scanner_exposed


def calculate_risk_score(row):
    total = (
        score_cvss(row["cvss"])
        + score_yes_no(row["internet_exposed"], 20)
        + score_flag(row["confirmed_active_exploit"], 15)
        + score_flag(row["threat_match"], 15)
        + score_flag(row["confirmed_ransomware"], 10)
        + score_asset_criticality(row["criticality"])
        + score_business_impact(row)
        + score_yes_no("Yes" if str(row["edr_installed"]).strip().lower() == "no" else "No", 5)
        + score_days_open(row["days_open"])
    )
    return round(total, 1)


def risk_level(score):
    if score >= 75:
        return "Critical"
    if score >= 55:
        return "High"
    if score >= 35:
        return "Medium"
    return "Low"


def score_risks(master_table):
    scored = master_table.copy()

    scored["cvss_points"] = scored["cvss"].apply(score_cvss)
    scored["internet_points"] = scored["internet_exposed"].apply(lambda value: score_yes_no(value, 20))
    scored["exploit_points"] = scored["confirmed_active_exploit"].apply(lambda value: score_flag(value, 15))
    scored["threat_points"] = scored["threat_match"].apply(lambda value: score_flag(value, 15))
    scored["ransomware_points"] = scored["confirmed_ransomware"].apply(lambda value: score_flag(value, 10))
    scored["criticality_points"] = scored["criticality"].apply(score_asset_criticality)
    scored["business_points"] = scored.apply(score_business_impact, axis=1)
    scored["edr_points"] = scored["edr_installed"].apply(
        lambda value: 5 if str(value).strip().lower() == "no" else 0
    )
    scored["age_points"] = scored["days_open"].apply(score_days_open)
    scored["exposure_mismatch"] = scored.apply(exposure_mismatch, axis=1)

    scored["risk_score"] = scored.apply(calculate_risk_score, axis=1)
    scored["risk_level"] = scored["risk_score"].apply(risk_level)

    scored = scored.sort_values(
        by=["risk_score", "cvss", "days_open", "vuln_id"],
        ascending=[False, False, False, True],
    ).reset_index(drop=True)
    scored["risk_rank"] = scored.index + 1

    return scored


scored = score_risks(enriched_master)
top_5 = scored.head(5).copy()


if __name__ == "__main__":
    columns = [
        "risk_rank",
        "vuln_id",
        "asset_name",
        "vulnerability_name",
        "cve",
        "risk_score",
        "risk_level",
    ]
    print(top_5[columns].to_string(index=False))

    mismatches = scored[scored["exposure_mismatch"]]
    print(f"\nExposure mismatches detected: {len(mismatches)}")
