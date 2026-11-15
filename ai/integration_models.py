from pydantic import BaseModel
from typing import Any


class OllamaRequestModel(BaseModel):
    email_id: str
    parsed_email: dict[str, Any]
    security_analysis: dict[str, Any]
    threat_analysis: dict[str, Any]
