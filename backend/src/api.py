import logging
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .main import analyze_full
from .ml_model import get_dataset_stats, get_trained_model


BASE_DIR = Path(__file__).resolve().parents[1]
LOG_PATH = BASE_DIR / "analysis.log"

logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Phishing Email Analysis API",
    description="Backend API for phishing detection using ML and LLM-style analysis.",
    version="1.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8080",
        "http://127.0.0.1:8080",
        "http://localhost:8081",
        "http://127.0.0.1:8081",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_origin_regex=r"https://.*\.(lovable\.app|lovableproject\.com)$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class EmailRequest(BaseModel):
    email_text: str = Field(..., min_length=1, description="Raw email content to analyze.")


class Indicator(BaseModel):
    label: str
    detail: str
    severity: Literal["high", "medium", "low"]


class ModelDetails(BaseModel):
    raw_label: str
    phishing_probability: float
    safe_probability: float
    risk_adjustment: int


class AnalysisResponse(BaseModel):
    input_email: str
    ml_result: Literal["Phishing", "Safe"]
    confidence: float
    risk_score: int
    threat_level: Literal["HIGH", "MEDIUM", "LOW"]
    llm_result: str
    mitre_mapping: str
    timestamp: str
    indicators: list[Indicator]
    model_details: ModelDetails


@app.on_event("startup")
def warm_model() -> None:
    try:
        get_trained_model()
        logger.info("ML model trained and ready")
    except Exception:
        logger.exception("ML model failed during startup")


@app.get("/")
def root():
    return {"message": "Phishing Analysis API is running"}


@app.get("/health")
def health_check():
    return {"status": "ok", "service": "running"}


@app.get("/samples")
def get_sample_emails():
    return {
        "samples": [
            {
                "type": "Phishing",
                "text": "Dear user, your account has been suspended. Click here to verify your password immediately.",
            },
            {
                "type": "Phishing",
                "text": "Your bank account has unusual activity. Login now to confirm your identity.",
            },
            {
                "type": "Safe",
                "text": "Hello, please find attached the meeting agenda for tomorrow.",
            },
            {
                "type": "Safe",
                "text": "Hi team, the project update meeting is scheduled for Friday at 10 AM.",
            },
        ]
    }


@app.get("/dataset-stats")
def dataset_stats():
    try:
        return get_dataset_stats()
    except Exception as exc:
        logger.exception("Failed to load dataset statistics")
        raise HTTPException(status_code=500, detail="Dataset statistics are unavailable") from exc


@app.get("/model-info")
def model_info():
    try:
        stats = get_dataset_stats()
        return {
            "model": "TF-IDF word+character n-grams with Logistic Regression",
            "task": "Binary phishing email classification",
            "metrics": stats["model_metrics"],
        }
    except Exception as exc:
        logger.exception("Failed to load model information")
        raise HTTPException(status_code=500, detail="Model information is unavailable") from exc


@app.post("/analyze", response_model=AnalysisResponse)
def analyze_email(req: EmailRequest):
    email_text = req.email_text.strip()
    if not email_text:
        raise HTTPException(status_code=422, detail="email_text cannot be empty")

    try:
        result = analyze_full(email_text)
    except Exception as exc:
        logger.exception("Analysis failed")
        raise HTTPException(status_code=500, detail="Email analysis failed") from exc

    logger.info(
        "email_preview=%r ml_result=%s confidence=%.4f risk_score=%s threat_level=%s phishing_probability=%.4f",
        email_text[:120],
        result["ml_result"],
        result["confidence"],
        result["risk_score"],
        result["threat_level"],
        result["model_details"]["phishing_probability"],
    )
    return result
