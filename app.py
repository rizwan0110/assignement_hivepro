import json
from pathlib import Path

import streamlit as st


RESULTS_PATH = Path("artifacts/top_5_risks.json")

st.set_page_config(
    page_title="TawasolPay Cyber Risk Assistant",
    page_icon="🛡️",
    layout="wide",
)


def load_results(path=RESULTS_PATH):
    if not path.exists():
        st.error("Risk results are missing. Run llm_explainer.py first.")
        st.stop()

    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


results = load_results()

st.title("🛡️ TawasolPay Cyber Risk Assistant")
st.caption(
    "Prioritized cyber risk analysis using asset context, threat intelligence, "
    "CISA KEV, and NIST SP 800-53."
)

st.subheader("Risk Overview")
metric_cols = st.columns(4)

metric_cols[0].metric("Top Risks", len(results))
metric_cols[1].metric(
    "Critical Risks",
    sum(risk["risk_level"] == "Critical" for risk in results),
)
metric_cols[2].metric(
    "CISA KEV Matches",
    sum(bool(risk["cisa_kev"]) for risk in results),
)
metric_cols[3].metric(
    "Threat-Matched Risks",
    sum(bool(risk.get("threat_actor")) for risk in results),
)

st.divider()
st.subheader("Top 5 Prioritized Risks")

for risk in results:
    with st.container(border=True):
        st.markdown(
            f"### #{risk['risk_rank']} — {risk['cve']} ({risk['risk_score']}/100)"
        )

        left, right = st.columns(2)

        with left:
            st.markdown(f"**Asset:** {risk['asset']}")
            st.markdown(f"**Vulnerability:** {risk['vulnerability']}")
            st.markdown(f"**Business Service:** {risk['business_service']}")
            st.markdown(f"**Risk Level:** {risk['risk_level']}")
            st.markdown(f"**CISA KEV:** {'Yes' if risk['cisa_kev'] else 'No'}")

        with right:
            st.markdown(f"**Threat Actor:** {risk.get('threat_actor') or 'No matched campaign'}")
            st.markdown(f"**Campaign:** {risk.get('campaign') or 'No matched campaign'}")
            st.markdown(
                f"**Recommended NIST Control:** {risk['nist_control_id']} — "
                f"{risk['nist_control_title']}"
            )

        st.markdown("#### Why this ranks highly")
        st.write(risk["risk_explanation"])

        st.markdown("#### Recommended NIST Remediation")
        st.write(risk["nist_explanation"])

st.divider()
st.subheader("How the prioritization works")
st.write(
    """
    Risks are ranked with a deterministic 0–100 score. CVSS is one input, but the
    ranking also considers internet exposure, exploit evidence, active threat campaigns,
    ransomware association, asset criticality, business impact, missing EDR, and age.

    CISA KEV is used as external evidence of real-world exploitation. NIST SP 800-53
    controls are retrieved with semantic search, and the language model is limited to
    summarizing the retrieved evidence rather than deciding the ranking.
    """
)

st.caption("Synthetic assessment data. Not intended for operational security decisions.")
