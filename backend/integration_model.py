from pydantic import BaseModel
from typing import Any

class OllamaRequestModel(BaseModel):
    email_id: str
    parsed_email: dict[str, Any]
    security_analysis: dict[str, Any]
    threat_analysis: dict[str, Any]

class LogicRequestModel(BaseModel):
    email_id: str
    security_analysis: dict[str, Any]
    threat_analysis: dict[str, Any]

class OllamaResultModel(BaseModel):
    email_id: str
    ollama_analysis: dict[str, Any]

class LogicResultModel(BaseModel):
    email_id: str
    logic_analysis: dict[str, Any]