from pathlib import Path
import re
import os
import joblib
import pandas as pd
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
