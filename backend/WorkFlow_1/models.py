from pydantic import BaseModel, Field
from typing import Optional

class AttachmentModel(BaseModel):
    filename: list[str] = Field(default_factory=list)
    content_type: list[str] = Field(default_factory=list)
    size: list[int] = Field(default_factory=list)
    sha256: list[Optional[str]] = Field(default_factory=list)

class IOCModel(BaseModel):
    ip_address: list[str] = Field(default_factory=list)
    url: list[str] = Field(default_factory=list)
    domain: list[str] = Field(default_factory=list)

class EmailModel(BaseModel):
    from_: Optional[str] = Field(default=None, alias="from")
    to: Optional[str] = None
    subject: Optional[str] = None
    date: Optional[str] = None
    received: list[str] = Field(default_factory=list)
    originating_ip: Optional[str] = None
    reply_to: Optional[str] = None
    return_path: Optional[str] = None
    message_id: Optional[str] = None
    content: str
    content_type: list[str] = Field(default_factory=list)
    file_name: list[str] = Field(default_factory=list)
    attachments: AttachmentModel
    iocs: IOCModel
    dkim_signature: Optional[str] = None
    authentication_results: list[str] = Field(default_factory=list)