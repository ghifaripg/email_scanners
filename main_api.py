from fastapi import FastAPI, File, UploadFile
from classify_eml import classify_eml
from attachment_analysis import (
    extract_attachments_and_urls,
    scan_file_virustotal,
    is_obfuscated_url
)
from email_analysis import analyze_email_headers

import shutil
import os
import uuid
import re
import requests

app = FastAPI()

@app.post("/scan-email/")
async def scan_email(file: UploadFile = File(...)):
    temp_filename = f"temp_{uuid.uuid4()}.eml"
    with open(temp_filename, "wb") as f:
        shutil.copyfileobj(file.file, f)

    try:
        # 1. Classify content
        label, confidence = classify_eml(temp_filename)

        # 2. Extract attachments & URLs
        attachments, urls = extract_attachments_and_urls(temp_filename)

        attachment_results = []
        for att in attachments:
            scan_result = scan_file_virustotal(att)
            parts = dict(re.findall(r'(\w+):\s*(\d+)', scan_result))
            attachment_results.append({
                "file": os.path.basename(att),
                "malicious": int(parts.get("Malicious", 0)),
                "suspicious": int(parts.get("Suspicious", 0)),
                "harmless": int(parts.get("Harmless", 0))
            })

        url_results = []
        for url in urls:
            try:
                response = requests.post("http://127.0.0.1:8002/predict/url", json={"url": url}, timeout=10)
                data = response.json()
                url_results.append({
                    "url": url,
                    "model_prediction": data.get("model_prediction", "Unknown"),
                    "confidence": data.get("confidence", "N/A"),
                    "result": data.get("result", "N/A")
                })
            except Exception as e:
                url_results.append({
                    "url": url,
                    "model_prediction": "Error",
                    "confidence": "N/A",
                    "result": str(e)
                })


        # 3. Header Analysis
        header_analysis = analyze_email_headers(temp_filename)

        # === Risk Scoring System ===

        # 1. Header Score (max 0.6)
        header_score_raw = 0
        auth = header_analysis["authentication"]

        if auth["SPF"] == "pass":
            header_score_raw += 0.15
        if auth["DKIM"] == "pass":
            header_score_raw += 0.15
        if auth["DMARC"] == "pass":
            header_score_raw += 0.10

        if not header_analysis["domain_check"]["mismatch_detected"]:
            header_score_raw += 0.05

        if header_analysis["ip_reputation"]["abuseConfidenceScore"] <= 10:
            header_score_raw += 0.05
        if header_analysis["ip_reputation"]["isWhitelisted"]:
            header_score_raw += 0.05

        # 2. Combined URL + Attachment Score (max 0.3)
        url_or_attachment_found = len(attachment_results) > 0 or len(url_results) > 0
        threat_found = (
            any(att["malicious"] > 0 for att in attachment_results) or
            any(url["result"] == "Not Safe" for url in url_results)
        )
        suspicious_found = (
            any(att["suspicious"] > 0 for att in attachment_results) or
            any(url["result"] == "Suspicious" for url in url_results)
        )

        attachment_score_raw = 0.3
        if threat_found:
            attachment_score_raw = 0.0
        elif suspicious_found:
            attachment_score_raw = 0.15
        elif not url_or_attachment_found:
            attachment_score_raw = 0.0

        # 3. Content Score (max 0.2)
        content_score_raw = 0.2 if label == 0 else 0.0  # 0 = Legitimate

        # === Dynamic Weighting ===
        if not url_or_attachment_found:
            # Only header + content
            total_score = round(
                (header_score_raw / 0.6) * 0.7 +
                (content_score_raw / 0.2) * 0.3,
                2
            )
        else:
            # Full system
            total_score = round(
                (header_score_raw / 0.6) * 0.5 +
                (attachment_score_raw / 0.3) * 0.3 +
                (content_score_raw / 0.2) * 0.2,
                2
            )

        # Risk Status
        if total_score >= 0.7:
            status = "Safe"
        elif total_score >= 0.4:
            status = "Suspicious"
        else:
            status = "Not Safe"

        # Final Output
        return {
            "classification": {
                "label": "Phishing/Spam" if label == 1 else "Legitimate",
                "confidence": round(confidence, 2)
            },
            "attachments": attachment_results,
            "urls": url_results,
            "header_analysis": header_analysis,
            "final_assessment": {
                "status": status,
                "score": total_score
            }
        }

    finally:
        if os.path.exists(temp_filename):
            os.remove(temp_filename)
