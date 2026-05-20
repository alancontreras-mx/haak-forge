"""Parser base class — every tool parser inherits from this."""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from pathlib import Path

from haak_anvil.core.engagement import Engagement
from haak_anvil.core.models import ReportBundle

_DEFAULT_MAX_XML_MB = 256


class ParserBase(ABC):
    """Common contract for input parsers.

    Subclass + register a `tool_name` and implement :meth:`parse`.
    """

    tool_name: str = ""

    def __init__(self, engagement: Engagement) -> None:
        if not self.tool_name:
            raise NotImplementedError("Subclass must set class attribute `tool_name`")
        self.engagement = engagement

    @abstractmethod
    def parse(self, path: Path) -> ReportBundle:
        """Parse one input file/dir into a ReportBundle scoped to the engagement."""
        ...

    def parse_many(self, paths: list[Path]) -> ReportBundle:
        """Parse multiple files and merge into a single bundle."""
        if not paths:
            raise ValueError("parse_many called with empty list")
        bundle = self.parse(paths[0])
        for p in paths[1:]:
            bundle = bundle.merge(self.parse(p))
        return bundle

    @staticmethod
    def _guard_file_size(path: Path) -> None:
        """Aborta antes de parsear si el archivo excede el limite de tamano.

        defusedxml protege contra XXE y billion-laughs, pero no contra un XML
        bien formado de varios GB que agota la memoria. Ajustable con la
        variable de entorno HAAK_ANVIL_MAX_XML_MB.
        """
        try:
            limit_mb = int(os.environ.get("HAAK_ANVIL_MAX_XML_MB", _DEFAULT_MAX_XML_MB))
        except ValueError:
            limit_mb = _DEFAULT_MAX_XML_MB
        limit = limit_mb * 1024 * 1024
        size = path.stat().st_size
        if size > limit:
            raise ValueError(
                f"Input file too large: {size} bytes (limit {limit}). "
                f"Override with HAAK_ANVIL_MAX_XML_MB."
            )
