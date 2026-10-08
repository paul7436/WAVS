import json

from wavs.modules.base import Finding
from wavs.report.reporter import Reporter, ScanReport

_XSS_EVIDENCE = "GET http://t/x q=<script>alert(1)</script>"

_FINDINGS = [
    Finding("csrf", "http://t/transfer", "medium", "No token.", param="amount"),
    Finding("reflected-xss", "http://t/x", "high", "Reflected.", param="q",
            evidence=_XSS_EVIDENCE),
    Finding("missing-security-header", "http://t/", "low", "No Referrer-Policy."),
    Finding("sql-injection", "http://t/i", "high", "DB error.", param="id", evidence="id='"),
]


def _report():
    return ScanReport(target="http://t", findings=list(_FINDINGS))


def test_json_summary_and_severity_order():
    data = json.loads(Reporter().render_json(_report()))
    assert data["summary"] == {"info": 0, "low": 1, "medium": 1, "high": 2, "total": 4}
    assert [f["severity"] for f in data["findings"]] == ["high", "high", "medium", "low"]
    assert any(f["evidence"] == "id='" for f in data["findings"])


def test_html_escapes_payloads():
    page = Reporter().render_html(_report())
    assert "<!doctype html>" in page
    assert _XSS_EVIDENCE not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert "high: 2" in page


def test_empty_report():
    assert "No findings were reported." in Reporter().render_html(ScanReport("http://t", []))
    assert json.loads(Reporter().render_json(ScanReport("http://t", [])))["summary"]["total"] == 0


def test_save_writes_both_files(tmp_path):
    json_path, html_path = tmp_path / "r.json", tmp_path / "r.html"
    Reporter().save(_report(), json_path=json_path, html_path=html_path)
    assert json.loads(json_path.read_text())["summary"]["total"] == 4
    assert "<!doctype html>" in html_path.read_text()
