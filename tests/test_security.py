"""Tests de regresión del secure code review 2026-05-20 (HAK-001..HAK-006).

Cada test fija una de las correcciones para que un cambio futuro que reintroduzca
la vulnerabilidad rompa la suite.
"""

import pytest
from pydantic import ValidationError

from haak_anvil.core.engagement import Engagement
from haak_anvil.core.models import Asset, Finding, ReportBundle
from haak_anvil.core.severity import Severity
from haak_anvil.renderers import HtmlRenderer, MarkdownRenderer


def _bundle_with_finding(engagement, **finding_kwargs) -> ReportBundle:
    base = {"id": "f-1", "title": "finding", "severity": Severity.HIGH, "tool": "nessus"}
    base.update(finding_kwargs)
    return ReportBundle(engagement=engagement, findings=[Finding(**base)])


# --- HAK-001: XSS almacenado en el HTML renderizado ------------------------

def test_hak001_html_escapes_script_in_evidence(engagement):
    """`evidence` proviene del banner del host escaneado: no debe inyectar HTML."""
    payload = "<script>alert(document.cookie)</script>"
    html = HtmlRenderer().render(_bundle_with_finding(engagement, evidence=payload))
    assert "<script>alert" not in html
    assert "&lt;script&gt;" in html


def test_hak001_html_escapes_event_handler_in_title(engagement):
    """El title de un finding tampoco debe inyectar HTML ejecutable."""
    html = HtmlRenderer().render(
        _bundle_with_finding(engagement, title="<img src=x onerror=alert(1)>")
    )
    assert "<img src=x onerror=" not in html


# --- HAK-002: path traversal vía engagement.id -----------------------------

def test_hak002_engagement_id_rejects_path_traversal():
    with pytest.raises(ValidationError):
        Engagement(id="../../../tmp/evil", client_name="Acme", scope="x")


def test_hak002_engagement_id_accepts_legitimate_id():
    eng = Engagement(id="HK-2026-001", client_name="Acme", scope="x")
    assert eng.id == "HK-2026-001"


# --- HAK-005: inyección de estructura en Markdown --------------------------

def test_hak005_markdown_escapes_pipe_in_hostname(engagement):
    """Un hostname con `|` no debe romper ni inyectar columnas en la tabla."""
    bundle = ReportBundle(
        engagement=engagement,
        assets=[Asset(address="10.0.0.1", hostname="evil | col | injected")],
    )
    md = MarkdownRenderer().render(bundle)
    assert "evil \\| col \\| injected" in md
