"""Engagement metadata — every report is scoped to one engagement."""

from __future__ import annotations

import re
from datetime import date
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, EmailStr, Field, field_validator

_MAX_YAML_BYTES = 1024 * 1024  # 1 MB — un engagement.yaml legítimo nunca se acerca
_ID_RE = re.compile(r"[\w-]{1,64}")


class Engagement(BaseModel):
    """Engagement / pentest scope metadata.

    Loaded from YAML so each engagement is reproducible:

        engagement.yaml:
        ----------------
        id: HK-2026-001
        client:
          name: Acme Corp
          contact: ciso@acme.example
        scope: "External perimeter + corp WLAN"
        methodology: PTES
        period:
          start: 2026-05-10
          end:   2026-05-20
        analyst: Alan Contreras
    """

    id: str = Field(min_length=1, max_length=64)
    client_name: str = Field(min_length=1, alias="client_name")
    client_contact: EmailStr | None = None
    scope: str
    methodology: Literal["PTES", "OWASP", "NIST-SP800-115", "MITRE-ATTACK", "Custom"] = "PTES"
    period_start: date | None = None
    period_end: date | None = None
    analyst: str = "Haak Cybersecurity Consulting"
    language: Literal["es-MX", "en-US", "pt-BR"] = "es-MX"

    @field_validator("id")
    @classmethod
    def _id_must_be_path_safe(cls, v: str) -> str:
        """`id` se usa como nombre de archivo de salida — sin separadores de ruta."""
        if not _ID_RE.fullmatch(v):
            raise ValueError(
                "id solo admite letras, dígitos, guion y guion bajo (1-64 caracteres)"
            )
        return v

    @classmethod
    def from_yaml(cls, path: Path | str) -> "Engagement":
        path = Path(path)
        size = path.stat().st_size
        if size > _MAX_YAML_BYTES:
            raise ValueError(
                f"engagement YAML demasiado grande ({size} bytes > {_MAX_YAML_BYTES})"
            )
        data = yaml.safe_load(path.read_text(encoding="utf-8"))

        # Flatten nested structure if present (client.name -> client_name)
        flat = dict(data)
        if isinstance(data.get("client"), dict):
            flat["client_name"] = data["client"].get("name")
            flat["client_contact"] = data["client"].get("contact")
            flat.pop("client", None)
        if isinstance(data.get("period"), dict):
            flat["period_start"] = data["period"].get("start")
            flat["period_end"] = data["period"].get("end")
            flat.pop("period", None)
        return cls.model_validate(flat)
