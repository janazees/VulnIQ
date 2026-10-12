from pathlib import Path
import re
import os
import shap
import joblib
import requests
import pandas as pd
from typing import Any
from scipy.sparse import hstack
from fastapi import FastAPI, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="VulnIQ API")

# Allow the React development server to call this API.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:5174",
        "http://localhost:5175",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:5174",
        "http://127.0.0.1:5175",
        *[
            origin.strip()
            for origin in os.getenv("FRONTEND_URL", "").split(",")
            if origin.strip()
        ],
    ],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Locate project files.
PROJECT_DIR = Path(__file__).resolve().parent.parent
CSV_PATH = PROJECT_DIR / "combined_cve_vulnerabilities.csv"
ARTIFACT_DIR = PROJECT_DIR / "model_artifacts"

# Load the CVE dataset.
df = pd.read_csv(CSV_PATH)
df.columns = df.columns.str.strip()

print(f"Loaded {len(df):,} vulnerability records")

# Load the trained model and preprocessing artifacts.
xgb_nlp = joblib.load(ARTIFACT_DIR / "xgb_nlp.joblib")
tfidf = joblib.load(ARTIFACT_DIR / "tfidf.joblib")
shap_explainer = shap.TreeExplainer(xgb_nlp)
preprocessor = joblib.load(ARTIFACT_DIR / "preprocessor.joblib")
structured_features = joblib.load(
    ARTIFACT_DIR / "structured_features.joblib"
)

print("VulnIQ prediction model loaded!")


def clean_text(text):
    """Clean CVE descriptions using the training-time logic."""
    text = str(text).lower()
    text = re.sub(r"[^a-z0-9\s]", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def predict_cve_record(record):
    """Predict the probability that a CVE belongs to the CISA KEV class."""

    # Transform the description using the fitted TF-IDF vectorizer.
    description = clean_text(record.get("description", ""))
    text_matrix = tfidf.transform([description])

    # Reconstruct the structured features in the training-time order.
    date = pd.to_datetime(
        record.get("published_date"), errors="coerce"
    )

    feature_values = {}

    for feature in structured_features:
        if feature == "published_year":
            feature_values[feature] = (
                date.year if pd.notna(date) else float("nan")
            )
        elif feature == "published_month":
            feature_values[feature] = (
                date.month if pd.notna(date) else float("nan")
            )
        else:
            feature_values[feature] = record.get(feature)

    feature_frame = pd.DataFrame(
        [feature_values],
        columns=structured_features,
    )

    # Transform the structured data using the fitted preprocessor.
    structured_matrix = preprocessor.transform(feature_frame)

    # Combine text and structured features in the training-time order.
    combined_features = hstack(
        [text_matrix, structured_matrix]
    ).tocsr()

    probabilities = xgb_nlp.predict_proba(combined_features)[0]
    positive_index = list(xgb_nlp.classes_).index(1)
    kev_probability = float(probabilities[positive_index])

    return {
        "predicted_kev": kev_probability >= 0.5,
        "kev_probability": round(kev_probability, 4),
    }


def explain_cve_record(record, top_n=10):
    """Return real SHAP feature contributions for one CVE."""

    description = clean_text(record.get("description", ""))
    text_matrix = tfidf.transform([description])

    date = pd.to_datetime(
        record.get("published_date"), errors="coerce"
    )

    feature_values = {}
    for feature in structured_features:
        if feature == "published_year":
            feature_values[feature] = (
                date.year if pd.notna(date) else float("nan")
            )
        elif feature == "published_month":
            feature_values[feature] = (
                date.month if pd.notna(date) else float("nan")
            )
        else:
            feature_values[feature] = record.get(feature)

    feature_frame = pd.DataFrame(
        [feature_values],
        columns=structured_features,
    )
    structured_matrix = preprocessor.transform(feature_frame)

    combined_features = hstack(
        [text_matrix, structured_matrix]
    ).tocsr()

    shap_values = shap_explainer.shap_values(combined_features)

    # Handle the usual single-output binary XGBoost result.
    values = shap_values[0] if getattr(shap_values, "ndim", 0) == 2 else shap_values[0, :, 0]
    values = values.toarray().ravel() if hasattr(values, "toarray") else values.ravel()

    # Name the text features and structured features.
    text_names = tfidf.get_feature_names_out().tolist()
    structured_names = (
        preprocessor.get_feature_names_out().tolist()
    )
    feature_names = text_names + structured_names

    # Return the strongest positive and negative contributions.
    ranked_indices = sorted(
        range(len(values)),
        key=lambda i: abs(float(values[i])),
        reverse=True,
    )[:top_n]

    contributions = []
    for index in ranked_indices:
        value = float(values[index])
        contributions.append({
            "feature": str(feature_names[index]),
            "shap_value": round(value, 6),
            "direction": "positive" if value > 0 else "negative"
            if value < 0 else "neutral",
        })

    return {
        "cve_id": str(record["cve_id"]),
        "base_value": float(shap_explainer.expected_value),
        "contributions": contributions,
        "explanation_type": "SHAP contributions to the model output",
    }


@app.get("/")
def home():
    return {
        "message": "Welcome to the VulnIQ API",
        "docs": "/docs",
    }


@app.get("/api/health")
def health():
    return {
        "status": "healthy",
        "records_loaded": len(df),
        "model_loaded": True,
    }


@app.get("/api/model-info")
def get_model_info():
    """Return model metadata and global feature importance."""

    # Use the feature names from the saved preprocessing artifacts.
    text_names = tfidf.get_feature_names_out().tolist()
    structured_names = preprocessor.get_feature_names_out().tolist()
    feature_names = text_names + structured_names

    # XGBoost exposes the importance values learned during training.
    importance_values = xgb_nlp.feature_importances_

    # Do not return misleading feature names if the dimensions differ.
    if len(feature_names) != len(importance_values):
        feature_importance = []
        importance_note = (
            "Feature names do not match the model's feature count. "
            "Verify the feature order used during training."
        )
    else:
        ranked = sorted(
            zip(feature_names, importance_values),
            key=lambda item: float(item[1]),
            reverse=True,
        )[:10]

        feature_importance = [
            {
                "feature": str(name),
                "importance": round(float(value), 6),
            }
            for name, value in ranked
        ]
        importance_note = (
            "Global XGBoost feature importance. "
            "These values are not SHAP contributions."
        )

    return {
        "model_name": "VulnIQ XGBoost",
        "model_type": type(xgb_nlp).__name__,
        "feature_count": int(xgb_nlp.n_features_in_),
        "feature_importance": feature_importance,
        "importance_note": importance_note,
        "training_metrics_available": False,
        "metrics": {},
    }



@app.get("/api/stats")
def get_stats():
    severity_counts = (
        df["base_severity"]
        .fillna("UNKNOWN")
        .astype(str)
        .str.upper()
        .value_counts()
        .to_dict()
    )

    return {
        "total_records": len(df),
        "severity_counts": severity_counts,
        "duplicate_rows": int(df.duplicated().sum()),
    }


@app.get("/api/vulnerabilities")
def get_vulnerabilities(
    q: str = Query(default="", max_length=200),
    severity: str = Query(default="ALL"),
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
):
    results = df

    # Filter by severity.
    if severity.upper() != "ALL":
        results = results[
            results["base_severity"]
            .fillna("")
            .astype(str)
            .str.upper()
            == severity.upper()
        ]

    # Search CVE ID or description.
    if q.strip():
        term = q.strip()

        id_match = results["cve_id"].fillna("").astype(str).str.contains(
            term, case=False, regex=False
        )
        description_match = results["description"].fillna("").astype(
            str
        ).str.contains(term, case=False, regex=False)

        results = results[id_match | description_match]

    total = len(results)
    page = results.iloc[offset:offset + limit]

    # Convert pandas values to JSON-safe Python values.
    records = page.astype(object).where(pd.notna(page), None)
    items = records.to_dict(orient="records")

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "items": items,
    }



@app.get("/api/explain/{cve_id}")
def explain_cve(cve_id: str):
    """Return SHAP contributions for a dataset or live CVE."""

    cve_id = cve_id.strip().upper()

    # First, look for the CVE in the existing dataset.
    matches = df[
        df["cve_id"].fillna("").astype(str).str.upper() == cve_id
    ]

    try:
        if not matches.empty:
            # Preserve the existing behavior for dataset CVEs.
            record = matches.iloc[0]
        else:
            # If absent from the dataset, fetch its current source data.
            record = fetch_nvd_cve(cve_id)

        # Reuse the existing training-time feature pipeline and SHAP explainer.
        explanation = explain_cve_record(record)

        return {
            **explanation,
            "source": (
                "Dataset"
                if not matches.empty
                else "NVD + FIRST EPSS"
            ),
        }

    except HTTPException:
        raise

    except Exception as exc:
        print(f"SHAP explanation failed for {cve_id}: {exc}")
        raise HTTPException(
            status_code=500,
            detail="SHAP explanation failed. Check backend logs.",
        ) from exc


@app.get("/api/predict/{cve_id}")
def predict_cve(cve_id: str):
    """Predict CISA KEV inclusion for a CVE present in the dataset."""

    matches = df[
        df["cve_id"].fillna("").astype(str).str.upper()
        == cve_id.strip().upper()
    ]

    if matches.empty:
        raise HTTPException(
            status_code=404,
            detail="CVE ID not found in the dataset",
        )

    record = matches.iloc[0]

    try:
        prediction = predict_cve_record(record)
    except Exception as exc:
        # Keep detailed exception information in the server logs.
        print(f"Prediction failed for {cve_id}: {exc}")
        raise HTTPException(
            status_code=500,
            detail="Prediction failed. Check the backend logs.",
        ) from exc

    return {
        "cve_id": str(record["cve_id"]),
        "description": str(record["description"]),
        **prediction,
        "interpretation": (
            "Model-estimated probability of CISA KEV inclusion. "
            "This is not an official CVSS severity rating."
        ),
    }

def fetch_epss(cve_id):
    url = "https://api.first.org/data/v1/epss"

    response = requests.get(
        url,
        params={"cve": cve_id},
        timeout=15
    )
    response.raise_for_status()

    data = response.json().get("data", [])

    if not data:
        return {
            "epss_score": None,
            "epss_perc": None
        }

    return {
        "epss_score": float(data[0]["epss"]),
        "epss_perc": float(data[0]["percentile"])
    }


def fetch_nvd_cve(cve_id: str) -> dict:
    """Fetch the latest available CVE record from the NVD API."""

    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    try:
        response = requests.get(
            url,
            params={"cveId": cve_id},
            timeout=20,
        )
        response.raise_for_status()
        data = response.json()

    except requests.RequestException as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Could not retrieve CVE data from NVD: {exc}",
        ) from exc

    vulnerabilities = data.get("vulnerabilities", [])

    if not vulnerabilities:
        raise HTTPException(
            status_code=404,
            detail=f"{cve_id} was not found in NVD.",
        )

    cve = vulnerabilities[0]["cve"]

    descriptions = cve.get("descriptions", [])
    description = next(
        (
            item["value"]
            for item in descriptions
            if item.get("lang") == "en"
        ),
        "No English description available.",
    )

    published_date = (cve.get("published") or "")[:10]

    # Prefer CVSS 3.1, then 3.0, then 4.0, then 2.0.
    metrics = cve.get("metrics", {})
    metric = None
    cvss = None

    for metric_key in (
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV40",
        "cvssMetricV2",
    ):
        entries = metrics.get(metric_key, [])
        if entries:
            metric = entries[0]
            cvss = metric.get("cvssData", {})
            break

    if cvss is None:
        cvss = {}

    # Convert NVD fields into the names expected by the model.
    record = {
        "cve_id": cve_id,
        "description": description,
        "published_date": published_date,
        "base_score": cvss.get("baseScore"),
        "base_severity": (
            cvss.get("baseSeverity")
            or metric.get("baseSeverity")
            if metric
            else None
        ),
        "exploitability_score": (
            metric.get("exploitabilityScore") if metric else None
        ),
        "impact_score": metric.get("impactScore") if metric else None,
        "attack_vector": cvss.get("attackVector"),
        "attack_complexity": cvss.get("attackComplexity"),
        "privileges_required": cvss.get("privilegesRequired"),
        "user_interaction": cvss.get("userInteraction"),
        "scope": cvss.get("scope"),
        "confidentiality_impact": cvss.get("confidentialityImpact"),
        "integrity_impact": cvss.get("integrityImpact"),
        "availability_impact": cvss.get("availabilityImpact"),
    }

    # Fetch the latest EPSS score separately.
    try:
        epss = fetch_epss(cve_id)
    except requests.RequestException as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Could not retrieve EPSS data: {exc}",
        ) from exc

    record["epss_score"] = epss["epss_score"]
    record["epss_perc"] = epss["epss_perc"]

    return record


@app.get("/api/predict-live/{cve_id}")
def predict_live_by_id(cve_id: str):
    """Fetch current source data and predict KEV inclusion."""

    cve_id = cve_id.strip().upper()

    if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id):
        raise HTTPException(
            status_code=400,
            detail="Enter a valid CVE ID, such as CVE-2021-44228.",
        )

    # Retrieve the source data.
    record = fetch_nvd_cve(cve_id)

    try:
        # Use the existing trained model and preprocessing.
        prediction = predict_cve_record(record)

    except Exception as exc:
        print(f"Live prediction failed for {cve_id}: {exc}")
        raise HTTPException(
            status_code=500,
            detail="Prediction failed. Check backend logs and model features.",
        ) from exc

    return {
        **record,
        **prediction,
        "cvss_score": record["base_score"],
        "cvss_severity": record["base_severity"],
        "epss_percentile": record["epss_perc"],
        "source": "NVD + FIRST EPSS",
        "interpretation": (
            "Model-estimated probability of CISA KEV inclusion. "
            "This is not an official CVSS severity rating."
        ),
    }


@app.post("/api/predict-live")
def predict_live_cve(live_cve: dict[str, Any]):
    """
    Predict risk for a CVE record supplied by a live data source.
    Uses the same saved model and preprocessing as the existing API.
    """

    cve_id = live_cve.get("cve_id")
    description = live_cve.get("description")

    if not cve_id or not description:
        raise HTTPException(
            status_code=400,
            detail="Both cve_id and description are required."
        )

    try:
        # Reuse the existing prediction pipeline.
        prediction = predict_cve_record(live_cve)

        return {
            "cve_id": str(cve_id),
            "description": str(description),
            **prediction,
            "cvss_score": live_cve.get(
                "base_score",
                live_cve.get("cvss_score")
            ),
            "cvss_severity": live_cve.get(
                "base_severity",
                live_cve.get("baseSeverity")
            ),
            "epss_score": live_cve.get("epss_score"),
            "epss_percentile": live_cve.get("epss_perc"),
            "source": "live_record",
            "interpretation": (
                "Model-estimated probability of CISA KEV inclusion. "
                "This is not an official CVSS severity rating."
            ),
        }

    except Exception as exc:
        print(f"Live prediction failed for {cve_id}: {exc}")

        raise HTTPException(
            status_code=500,
            detail="Live prediction failed. Check backend logs."
        ) from exc
