import json
import re
from pathlib import Path

import faiss
import requests
from sentence_transformers import SentenceTransformer


NIST_URL = (
    "https://raw.githubusercontent.com/usnistgov/oscal-content/main/"
    "nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"
)
NIST_CACHE = Path("data/nist_sp800_53_rev5.json")
EMBEDDING_MODEL = "all-MiniLM-L6-v2"

_model = None
_controls = None
_index = None


def load_nist_catalog(url=NIST_URL, cache_path=NIST_CACHE):
    """Load NIST SP 800-53 Rev. 5 from cache or download the OSCAL JSON."""
    if cache_path.exists():
        with cache_path.open("r", encoding="utf-8") as file:
            return json.load(file)

    response = requests.get(url, timeout=60)
    response.raise_for_status()
    data = response.json()

    cache_path.parent.mkdir(parents=True, exist_ok=True)
    with cache_path.open("w", encoding="utf-8") as file:
        json.dump(data, file)

    return data


def clean_text(text):
    if not text:
        return ""
    text = re.sub(r"<[^>]+>", " ", str(text))
    return re.sub(r"\s+", " ", text).strip()


def extract_parts(parts):
    prose = []
    for part in parts or []:
        text = clean_text(part.get("prose", ""))
        if text:
            prose.append(text)
        prose.extend(extract_parts(part.get("parts", [])))
    return prose


def extract_controls(catalog_data):
    """Flatten OSCAL controls into small documents suitable for retrieval."""
    controls = []

    for group in catalog_data["catalog"].get("groups", []):
        family = group.get("title", "")

        for control in group.get("controls", []):
            control_id = control.get("id", "").upper()
            title = control.get("title", "")
            body = " ".join(extract_parts(control.get("parts", [])))

            controls.append(
                {
                    "control_id": control_id,
                    "title": title,
                    "family": family,
                    "text": clean_text(
                        f"{control_id}. {title}. Family: {family}. {body}"
                    ),
                }
            )

    return controls


def get_embedding_model():
    global _model
    if _model is None:
        _model = SentenceTransformer(EMBEDDING_MODEL)
    return _model


def build_index(controls):
    model = get_embedding_model()
    texts = [control["text"] for control in controls]
    embeddings = model.encode(texts, convert_to_numpy=True, show_progress_bar=False).astype("float32")

    faiss.normalize_L2(embeddings)
    index = faiss.IndexFlatIP(embeddings.shape[1])
    index.add(embeddings)
    return index


def get_retriever():
    """Create the NIST documents and FAISS index once per process."""
    global _controls, _index

    if _controls is None or _index is None:
        _controls = extract_controls(load_nist_catalog())
        _index = build_index(_controls)

    return _controls, _index


def create_risk_query(row):
    fields = [
        f"Vulnerability: {row['vulnerability_name']}",
        f"CVE: {row['cve']}",
        f"Asset: {row['asset_name']}",
        f"Business service: {row['business_service']}",
        f"Internet exposed: {row['internet_exposed']}",
        f"Active exploit: {row['confirmed_active_exploit']}",
        f"Threat campaign: {row['campaign_name']}",
        f"Ransomware: {row['confirmed_ransomware']}",
        f"CISA required action: {row['cisa_required_action']}",
    ]
    return "Cybersecurity remediation guidance. " + " ".join(fields)


def retrieve_controls(query, controls, index, top_k=3):
    model = get_embedding_model()
    query_embedding = model.encode([query], convert_to_numpy=True).astype("float32")
    faiss.normalize_L2(query_embedding)

    scores, indexes = index.search(query_embedding, top_k)
    results = []

    for score, idx in zip(scores[0], indexes[0]):
        control = controls[idx].copy()
        control["similarity_score"] = round(float(score), 4)
        results.append(control)

    return results


if __name__ == "__main__":
    from risk_engine import top_5

    controls, index = get_retriever()
    print(f"NIST controls indexed: {len(controls)}")

    for _, risk in top_5.iterrows():
        matches = retrieve_controls(create_risk_query(risk), controls, index, top_k=3)
        print(f"\nRisk #{risk['risk_rank']} - {risk['cve']}")
        for match in matches:
            print(
                f"{match['control_id']} - {match['title']} "
                f"({match['similarity_score']})"
            )
