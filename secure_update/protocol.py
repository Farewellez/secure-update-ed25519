"""Model metadata dan serialisasi kanonis untuk protokol demo v1."""
import json
import re
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

SCHEMA = "edu.secure-update.v1"
APP_NAME = "CielApp"
MAX_METADATA_BYTES = 16 * 1024
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024


def canonical_bytes(value: dict) -> bytes:
    """UTF-8 JSON dengan key terurut, tanpa whitespace (aturan protokol demo)."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


class Manifest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    schema_id: Literal[SCHEMA]
    app: Literal[APP_NAME]
    version: int = Field(ge=1, le=2_147_483_647)
    artifact: str
    size: int = Field(ge=0, le=MAX_ARTIFACT_BYTES)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    key_id: str = Field(pattern=r"^[0-9a-f]{16}$")
    expires_at: str

    @model_validator(mode="after")
    def validate_semantics(self):
        if self.artifact != "package.bin":
            raise ValueError("artifact must be package.bin")
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", self.expires_at):
            raise ValueError("expires_at must be UTC YYYY-MM-DDTHH:MM:SSZ")
        try:
            datetime.fromisoformat(self.expires_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("invalid expires_at") from exc
        return self


class Envelope(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    signed: Manifest
    signature: str = Field(min_length=80, max_length=120)
