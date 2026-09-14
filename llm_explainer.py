import json
import os
from pathlib import Path

from dotenv import load_dotenv
from groq import Groq

from nist_retriever import create_risk_query, get_retriever, retrieve_controls
from risk_engine import top_5


MODEL = "openai/gpt-oss-20b"
OUTPUT_PATH = Path("artifacts/top_5_risks.json")
REQUIRED_FIELDS = {
    "risk_explanation",
    "nist_control_id",
    "nist_control_title",
    "nist_explanation",
}


def get_client():
    load_dotenv()
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        raise ValueError("GROQ_API_KEY is missing. Add it to your .env file.")
    return Groq(api_key=api_key)


def build_nist_context(matches):
    sections = []
    for match in matches:
        sections.append(
            "\n".join(
                [
                    f"CONTROL ID: {match['control_id']}",
                    f"TITLE: {match['title']}",
                    f"FAMILY: {match['family']}",
                    "OFFICIAL NIST TEXT:",
                    match["text"],
                ]
            )
        )
    return "\n\n".join(sections)


def build_risk_evidence(risk):
    """Build a compact evidence list from fields that actually affected prioritisation."""
    evidence = []

    if str(risk["internet_exposed"]).strip().lower() == "yes":
        evidence.append("The asset is internet-facing.")

    if risk["confirmed_active_exploit"]:
        evidence.append("Active exploitation is confirmed or an exploit is available.")

    if risk["threat_match"]:
        evidence.append(
            f"The CVE is linked to the {risk['campaign_name']} campaign by {risk['threat_actor']}."
        )

    if risk["confirmed_ransomware"]:
        evidence.append("The exploitation activity is associated with ransomware.")

    if str(risk["criticality"]).strip().lower() in {"critical", "high"}:
        evidence.append(f"The affected asset has {risk['criticality']} criticality.")

    if str(risk["edr_installed"]).strip().lower() == "no":
        evidence.append("EDR is not installed on the affected asset.")

    if risk["kev_match"]:
        evidence.append("The CVE is listed in CISA KEV.")

    return " ".join(evidence)


def validate_llm_output(data, nist_matches):
    missing = REQUIRED_FIELDS - data.keys()
    if missing:
        raise ValueError(f"LLM response is missing fields: {sorted(missing)}")

    allowed_ids = {match["control_id"] for match in nist_matches}
    if data["nist_control_id"] not in allowed_ids:
        raise ValueError(
            f"Unsupported NIST control {data['nist_control_id']}. "
            f"Retrieved controls were: {sorted(allowed_ids)}"
        )


def generate_risk_explanation(client, risk, nist_matches):
    prompt = f"""
Use only the risk evidence and retrieved NIST controls below.

Choose exactly one NIST control from the retrieved candidates. Do not invent controls,
vulnerability facts, remediation requirements, or timelines.

The risk explanation should mention two or three concrete reasons that drove the ranking.
Keep both explanations concise. Return only valid JSON, with no markdown.

Risk rank: {risk['risk_rank']}
Risk score: {risk['risk_score']}
Asset: {risk['asset_name']}
Vulnerability: {risk['vulnerability_name']}
CVE: {risk['cve']}
Business service: {risk['business_service']}
CVSS: {risk['cvss']}
CISA KEV: {risk['kev_match']}
CISA required action: {risk['cisa_required_action']}

Risk evidence:
{build_risk_evidence(risk)}

Retrieved NIST controls:
{build_nist_context(nist_matches)}

Return this JSON shape:
{{
  "risk_explanation": "one short sentence",
  "nist_control_id": "one retrieved control ID",
  "nist_control_title": "exact title of that control",
  "nist_explanation": "brief explanation of what the control recommends and why it applies"
}}
"""

    response = client.chat.completions.create(
        model=MODEL,
        messages=[
            {
                "role": "system",
                "content": "You write grounded cybersecurity summaries from supplied evidence only.",
            },
            {"role": "user", "content": prompt},
        ],
        temperature=0,
        response_format={"type": "json_object"},
    )

    data = json.loads(response.choices[0].message.content)
    validate_llm_output(data, nist_matches)
    return data


def build_result(risk, explanation):
    return {
        "risk_rank": int(risk["risk_rank"]),
        "risk_score": float(risk["risk_score"]),
        "risk_level": risk["risk_level"],
        "asset": risk["asset_name"],
        "vulnerability": risk["vulnerability_name"],
        "cve": risk["cve"],
        "business_service": risk["business_service"],
        "threat_actor": risk["threat_actor"] if risk["threat_match"] else None,
        "campaign": risk["campaign_name"] if risk["threat_match"] else None,
        "cisa_kev": bool(risk["kev_match"]),
        "risk_explanation": explanation["risk_explanation"],
        "nist_control_id": explanation["nist_control_id"],
        "nist_control_title": explanation["nist_control_title"],
        "nist_explanation": explanation["nist_explanation"],
    }


def generate_top_risk_output():
    client = get_client()
    controls, index = get_retriever()
    results = []

    for _, risk in top_5.iterrows():
        matches = retrieve_controls(
            create_risk_query(risk),
            controls,
            index,
            top_k=5,
        )
        explanation = generate_risk_explanation(client, risk, matches)
        results.append(build_result(risk, explanation))

    return results


def save_results(results, output_path=OUTPUT_PATH):
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as file:
        json.dump(results, file, indent=2)


if __name__ == "__main__":
    final_results = generate_top_risk_output()
    save_results(final_results)

    for result in final_results:
        print(
            f"#{result['risk_rank']} {result['cve']} - "
            f"{result['nist_control_id']} {result['nist_control_title']}"
        )

    print(f"Saved results to {OUTPUT_PATH}")
