import asyncio

from tests._util import crawl_result, serve
from wavs.core.http_client import HttpClient
from wavs.modules.csrf import CsrfModule

_FORMS = {
    "/vuln": '<form method="post" action="/transfer"><input name="amount"></form>',
    "/vuln-again": '<form method="post" action="/transfer"><input name="amount"></form>',
    "/safe": ('<form method="post" action="/update">'
              '<input type="hidden" name="csrf_token" value="x">'
              '<input name="email"></form>'),
    "/dvwa": ('<form method="POST" action="/pwd">'
              '<input type="hidden" name="user_token" value="x">'
              '<input name="pwd"></form>'),
    "/search": '<form method="get" action="/search"><input name="q"></form>',
}


def _responder(path, query):
    return (f"<html><body>{_FORMS.get(path, '')}</body></html>", 200, None)


def test_csrf_flags_tokenless_post_forms_once():
    async def run():
        with serve(_responder) as base:
            urls = [f"{base}{p}" for p in _FORMS]
            async with HttpClient(timeout=10) as client:
                return await CsrfModule(client).run(crawl_result(urls))

    findings = asyncio.run(run())
    actions = [f.url.rsplit("/", 1)[1] for f in findings]
    assert actions == ["transfer"]
    assert findings[0].severity == "medium" and findings[0].type == "csrf"
