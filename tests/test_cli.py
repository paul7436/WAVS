import json

import pytest

from tests._util import serve
from wavs.main import main, parse_cookies, selected_modules

_LANDING = """<html><body>
<a href="/search?q=hi">search</a>
<a href="/item?id=1">item</a>
<form method="post" action="/transfer">
  <input name="to"><input name="amount">
</form>
</body></html>"""


def _bank(path, query):
    if path == "/":
        return (_LANDING, 200, None)
    if path == "/search":
        return (f"<html><body>Results for: {query.get('q', [''])[0]}</body></html>", 200, None)
    if path == "/item":
        value = query.get("id", [""])[0]
        if "'" in value or '"' in value:
            return ("<html><body>error in your SQL syntax; MySQL</body></html>", 200, None)
        return ("<html><body>Item</body></html>", 200, None)
    return ("<html><body>nope</body></html>", 404, None)


def test_parse_cookies():
    assert parse_cookies("PHPSESSID=abc; security=low") == {"PHPSESSID": "abc", "security": "low"}
    assert parse_cookies(None) == {}


def test_selected_modules():
    assert len(selected_modules("all")) == 5
    assert selected_modules("sqli,xss") == ["sqli", "xss"]
    with pytest.raises(SystemExit):
        selected_modules("bogus")


def test_cli_end_to_end_writes_report(tmp_path):
    json_path = tmp_path / "report.json"
    with serve(_bank) as base:
        code = main([
            base + "/",
            "--modules", "headers,sqli,xss,csrf",
            "--json", str(json_path),
        ])
    assert code == 0

    data = json.loads(json_path.read_text())
    assert data["summary"]["high"] >= 2
    findings = data["findings"]
    assert any(f["type"] == "reflected-xss" and f["severity"] == "high"
               and f["url"].endswith("/search") for f in findings)
    assert any(f["type"] == "sql-injection" and f["severity"] == "high"
               and f["url"].endswith("/item") for f in findings)
    assert any(f["type"] == "csrf" and f["url"].endswith("/transfer") for f in findings)
