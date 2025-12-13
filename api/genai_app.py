import os
import json
import re
from typing import Optional, Dict, Any, Tuple

from fastapi import FastAPI, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, HttpUrl

import tldextract
from dotenv import load_dotenv

# Groq is optional at runtime (we fallback if key/model fails)
try:
    from groq import Groq
except Exception:
    Groq = None


# ======================
# ENV + CONFIG
# ======================
load_dotenv()

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "").strip()
# ✅ Update default to a currently-used model (override via .env)
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.1-8b-instant").strip()

groq_client = None
if GROQ_API_KEY and Groq is not None:
    try:
        groq_client = Groq(api_key=GROQ_API_KEY)
    except Exception:
        groq_client = None


# ======================
# FASTAPI APP
# ======================
app = FastAPI(title="PhishGuard AI – GenAI + ML")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ======================
# PATHS + STATIC
# ======================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))          # .../api
STATIC_DIR = os.path.join(BASE_DIR, "static")                 # .../api/static

# Serve static assets at /static (safe; doesn't override /scan etc.)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


# ======================
# SCHEMAS
# ======================
class ScanRequest(BaseModel):
    url: HttpUrl
    page_title: Optional[str] = None
    page_text_snippet: Optional[str] = None
    brand_claimed: Optional[str] = None
    user_context: Optional[str] = None


class ScanResponse(BaseModel):
    url: str
    verdict: str
    risk_score: float
    ml_score: float
    genai_score: float
    reasons: list[str]
    signals: Dict[str, Any]
    genai_summary: Dict[str, Any]


# ======================
# UTILS
# ======================
SUSPICIOUS_TLDS = {"xyz", "zip", "click", "top", "tk", "ml", "ga", "cf"}

def is_ip(host: str) -> bool:
    return bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host))


def get_url_features(url: str) -> Dict[str, Any]:
    ext = tldextract.extract(url)
    host = ext.fqdn
    return {
        "host": host,
        "url_length": len(url),
        "num_dots": host.count("."),
        "num_hyphens": host.count("-"),
        "has_https": url.startswith("https"),
        "looks_like_ip": is_ip(host),
        "suspicious_tld": ext.suffix in SUSPICIOUS_TLDS,
    }


def ml_score_calc(features: Dict[str, Any]) -> Tuple[float, list[str]]:
    score = 0
    reasons = []

    if features["looks_like_ip"]:
        score += 20
        reasons.append("IP address used instead of domain")

    if features["suspicious_tld"]:
        score += 15
        reasons.append("Suspicious TLD detected")

    if features["url_length"] > 70:
        score += 10
        reasons.append("Unusually long URL")

    if features["num_hyphens"] >= 3:
        score += 10
        reasons.append("Too many hyphens in domain")

    if not features["has_https"]:
        score += 10
        reasons.append("HTTPS not used")

    return min(score, 100), reasons


GENAI_SYSTEM = """
You are a phishing detection expert.
Return ONLY valid JSON:

{
  "genai_score": number,
  "verdict": "SAFE" | "SUSPICIOUS" | "PHISHING",
  "top_reasons": [string],
  "notes": string
}
""".strip()


def genai_analysis(req: ScanRequest, features: Dict[str, Any]) -> Dict[str, Any]:
    """
    Always returns a dict (never raises) so /scan always returns JSON.
    Falls back if Groq is missing, key missing, model decommissioned, etc.
    """
    if groq_client is None:
        return {
            "genai_score": 50,
            "verdict": "SUSPICIOUS",
            "top_reasons": ["GenAI not configured (missing GROQ_API_KEY or Groq SDK)."],
            "notes": "Fallback used (GenAI unavailable)"
        }

    payload = {
        "url": str(req.url),
        "features": features,
        "title": req.page_title,
        "snippet": req.page_text_snippet,
        "brand": req.brand_claimed,
        "context": req.user_context,
    }

    try:
        res = groq_client.chat.completions.create(
            model=GROQ_MODEL,
            temperature=0.2,
            messages=[
                {"role": "system", "content": GENAI_SYSTEM},
                {"role": "user", "content": json.dumps(payload)},
            ],
        )

        content = res.choices[0].message.content

        # Some models may return extra text; try to recover JSON safely
        try:
            return json.loads(content)
        except Exception:
            # attempt to extract JSON block if any
            m = re.search(r"\{.*\}", content, flags=re.DOTALL)
            if m:
                return json.loads(m.group(0))
            raise

    except Exception as e:
        return {
            "genai_score": 50,
            "verdict": "SUSPICIOUS",
            "top_reasons": [f"GenAI fallback: {str(e)}"],
            "notes": "Fallback used (GenAI error)"
        }


# ======================
# ROUTES
# ======================
@app.get("/health")
def health():
    return {
        "status": "ok",
        "groq_enabled": groq_client is not None,
        "model": GROQ_MODEL
    }


@app.get("/", response_class=HTMLResponse)
def serve_ui():
    """
    Serves api/static/index.html as REAL HTML.
    Also fixes accidental escaped HTML content.
    """
    index_path = os.path.join(STATIC_DIR, "index.html")
    if not os.path.exists(index_path):
        return HTMLResponse("<h3>index.html not found in api/static</h3>", status_code=500)

    with open(index_path, encoding="utf-8") as f:
        html = f.read()

    # Fix: if saved like "'<html>\\n...'" convert to real HTML
    if (html.startswith("'") and html.endswith("'")) or (html.startswith('"') and html.endswith('"')):
        html = html[1:-1]
    html = html.replace("\\n", "\n")

    return HTMLResponse(content=html)


@app.post("/scan", response_model=ScanResponse)
def scan(req: ScanRequest):
    """
    JSON API:
    POST /scan
    body: {"url":"https://example.com"}
    """
    features = get_url_features(str(req.url))
    ml_score, ml_reasons = ml_score_calc(features)

    genai = genai_analysis(req, features)
    genai_score = float(genai.get("genai_score", 50))

    # weighted final score
    final_score = 0.45 * ml_score + 0.55 * genai_score

    if final_score >= 75:
        verdict = "PHISHING"
    elif final_score >= 45:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    reasons = (ml_reasons + genai.get("top_reasons", []))[:6]

    return ScanResponse(
        url=str(req.url),
        verdict=verdict,
        risk_score=round(final_score, 2),
        ml_score=ml_score,
        genai_score=genai_score,
        reasons=reasons,
        signals={"features": features},
        genai_summary=genai,
    )


@app.post("/scan_ui", response_model=ScanResponse)
def scan_ui(url: str = Form(...)):
    """
    Optional: HTML form post endpoint.
    """
    req = ScanRequest(url=url)
    return scan(req)
