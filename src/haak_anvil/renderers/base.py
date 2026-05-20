"""Renderer base class — every output format inherits from this."""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from pathlib import Path

from haak_anvil.core.models import ReportBundle


class RendererBase(ABC):
    """Render a ReportBundle into a string and/or write to disk."""

    extension: str = ""

    @abstractmethod
    def render(self, bundle: ReportBundle) -> str:
        """Return the rendered report content."""
        ...

    def write(self, bundle: ReportBundle, path: Path | str) -> Path:
        """Render and write to disk. Returns the written path."""
        path = Path(path)
        if path.is_dir() or path.suffix == "":
            # engagement.id puede venir de un JSON bundle de terceros:
            # sanitizar evita path traversal al construir el archivo de salida.
            safe_id = re.sub(r"[^\w-]", "_", bundle.engagement.id) or "report"
            path = path / f"{safe_id}.{self.extension}"
        content = self.render(bundle)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path
