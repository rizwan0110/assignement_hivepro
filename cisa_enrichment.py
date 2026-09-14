from pathlib import Path

import pandas as pd

from data_loader import master


CISA_KEV_URL = (
    "https://raw.githubusercontent.com/"
    "cisagov/kev-data/develop/known_exploited_vulnerabilities.csv"
)
CACHE_PATH = Path("data/cisa_kev.csv")


def load_cisa_kev(url=CISA_KEV_URL, cache_path=CACHE_PATH):
    """Load the latest KEV catalog, falling back to a local cache if needed."""
    try:
        kev = pd.read_csv(url)
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        kev.to_csv(cache_path, index=False)
        return kev
    except Exception as exc:
        if cache_path.exists():
            return pd.read_csv(cache_path)
        raise RuntimeError("CISA KEV could not be loaded and no cache is available.") from exc


def prepare_kev(kev):
    """Keep the CISA fields used by the risk pipeline and give them clear names."""
    selected = kev[
        [
            "cveID",
            "vendorProject",
            "product",
            "vulnerabilityName",
            "dateAdded",
            "requiredAction",
            "dueDate",
            "knownRansomwareCampaignUse",
        ]
    ].copy()

    return selected.rename(
        columns={
            "cveID": "cisa_cve",
            "vendorProject": "cisa_vendor",
            "product": "cisa_product",
            "vulnerabilityName": "cisa_vulnerability_name",
            "dateAdded": "cisa_date_added",
            "requiredAction": "cisa_required_action",
            "dueDate": "cisa_due_date",
            "knownRansomwareCampaignUse": "cisa_ransomware",
        }
    )


def add_cisa_context(master_table):
    """Join KEV data and derive the exploitation/ransomware signals used in scoring."""
    kev = prepare_kev(load_cisa_kev())

    enriched = master_table.merge(
        kev,
        left_on="cve",
        right_on="cisa_cve",
        how="left",
    )

    enriched["kev_match"] = enriched["cisa_cve"].notna()

    exploit_available = (
        enriched["exploit_available"].astype(str).str.strip().str.lower() == "yes"
    )
    enriched["confirmed_active_exploit"] = exploit_available | enriched["kev_match"]

    local_ransomware = (
        enriched["ransomware_association"].astype(str).str.strip().str.lower() == "yes"
    )
    cisa_ransomware = (
        enriched["cisa_ransomware"].astype(str).str.strip().str.lower() == "known"
    )
    enriched["confirmed_ransomware"] = local_ransomware | cisa_ransomware

    return enriched


enriched_master = add_cisa_context(master)


if __name__ == "__main__":
    print(f"Total vulnerabilities: {len(enriched_master)}")
    print(f"CISA KEV matches: {int(enriched_master['kev_match'].sum())}")
    print(
        "Confirmed active exploit:",
        int(enriched_master["confirmed_active_exploit"].sum()),
    )
