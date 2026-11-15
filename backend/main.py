from __future__ import annotations

import asyncio, uuid

from datetime import datetime, timezone
from typing import Any

from dotenv import load_dotenv
from fastapi import FastAPI, File, HTTPException, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware

from WorkFlow_1 import parse_engine as pe
from WorkFlow_2 import security_engine as se
from WorkFlow_3 import threat_engine as te

from WorkFlow_1.models import EmailModel
from WorkFlow_2.models import SecurityAnalysisModel
from WorkFlow_3.models import ThreatAnalysisModel

from integration_engine import post_to_ollama, post_to_logic

load_dotenv()

app = FastAPI(title="CypherX Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

analysis_store: dict[str, dict[str, Any]] = {}

processing_semaphore = asyncio.Semaphore(5)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


async def process_email(email_id: str, email_data: bytes):
    async with processing_semaphore:
        try:
            print(f"[{email_id}] Processing started.")

            parsed_email = await pe.parse_email(email_data)
            print(f"[{email_id}] Email parsed.")

            validated_email = EmailModel.model_validate(parsed_email)
            print(f"[{email_id}] Email validation completed.")

            security_analysis, threat_analysis = await asyncio.gather(
                se.analyze_security(validated_email, email_data),
                te.analyze_threat(validated_email)
            )

            print(f"[{email_id}] Security analysis completed.")
            print(f"[{email_id}] Threat analysis completed.")

            security_analysis = (SecurityAnalysisModel.model_validate(security_analysis).model_dump(by_alias=True, mode="json"))

            threat_analysis = (ThreatAnalysisModel.model_validate(threat_analysis).model_dump(mode="json"))

            analysis_store[email_id]["parsed_email"] = parsed_email
            analysis_store[email_id]["security_analysis"] = security_analysis
            analysis_store[email_id]["threat_analysis"] = threat_analysis

            print(f"[{email_id}] Sending analysis to Ollama and Logic.")

            ollama_result, logic_result = await asyncio.gather(
                asyncio.to_thread(post_to_ollama, email_id, parsed_email, security_analysis, threat_analysis),
                asyncio.to_thread(post_to_logic, email_id, security_analysis, threat_analysis)
            )

            analysis_store[email_id]["status"] = "completed"

            print(
                f"[{email_id}] Ollama sent: "
                f"{ollama_result is not None}, "
                f"Logic sent: "
                f"{logic_result is not None}"
            )

        except Exception as exc:
            print(
                f"[{email_id}] PROCESSING ERROR: "
                f"{type(exc).__name__}: {exc}"
            )

            analysis_store[email_id]["status"] = "failed"
            analysis_store[email_id]["error"] = str(exc)


@app.post("/receive-email", status_code=status.HTTP_202_ACCEPTED)
async def receive_email(email: UploadFile = File(...)):
    filename = email.filename or ""
    if not filename.lower().endswith(".eml"):
        raise HTTPException(
            status_code=415,
            detail="Please upload an .eml file."
        )
    
    email_data = await email.read()

    if not email_data:
        raise HTTPException(
            status_code=400,
            detail="Uploaded file is empty."
        )

    email_id = str(uuid.uuid4())

    analysis_store[email_id] = {
        "filename": filename,
        "size_bytes": len(email_data),
        "status": "processing",
        "parsed_email": None,
        "security_analysis": None,
        "threat_analysis": None,
        "logic_analysis": None,
        "created_at": utc_now()
    }

    print(
        f"[{email_id}] Received: "
        f"{filename} ({len(email_data)} bytes)"
    )

    asyncio.create_task(process_email(email_id, email_data))

    return {
        "status": "processing",
        "email_id": email_id,
        "case_id": email_id
    }