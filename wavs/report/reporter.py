from __future__ import annotations

import html
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from wavs.modules.base import SEVERITIES, Finding

_SEVERITY_ORDER = {name: index for index, name in enumerate(reversed(SEVERITIES))}
_SEVERITY_COLORS = {
    "high": "#d7263d",
    "medium": "#f46036",
    "low": "#e8a600",
    "info": "#2e86ab",
}

_CSS = """
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body { margin: 0; padding: 2rem 1rem; font: 16px/1.5 system-ui, sans-serif;
       background: #f4f5f7; color: #1b1b1f; }
main { max-width: 860px; margin: 0 auto; }
h1 { margin: 0 0 .25rem; font-size: 1.6rem; }
.meta { margin: 0 0 1.25rem; color: #555; }
.meta code { word-break: break-all; }
.badges { display: flex; flex-wrap: wrap; gap: .5rem; margin-bottom: 1.5rem; }
.badge { padding: .25rem .7rem; border-radius: 999px; color: #fff;
         font-size: .85rem; font-weight: 600; }
.card { background: #fff; border: 1px solid #e3e5e8; border-left: 5px solid #777;
        border-radius: 8px; padding: 1rem 1.1rem; margin-bottom: 1rem; }
.card header { display: flex; align-items: center; gap: .6rem; margin-bottom: .6rem; }
.card h3 { margin: 0; font-size: 1.05rem; font-family: monospace; }
.sev { padding: .1rem .55rem; border-radius: 4px; color: #fff;
       font-size: .72rem; font-weight: 700; text-transform: uppercase; }
.row { margin: .3rem 0; }
.k { display: inline-block; min-width: 92px; color: #666; font-size: .85rem; }
code { background: #f0f1f3; padding: .1rem .35rem; border-radius: 4px;
       font-size: .9em; word-break: break-all; }
.desc { margin: .6rem 0 .3rem; }
.empty { background: #fff; border: 1px dashed #ccc; border-radius: 8px;
         padding: 2rem; text-align: center; color: #666; }
@media (prefers-color-scheme: dark) {
  body { background: #17181c; color: #e7e8ea; }
  .card { background: #212328; border-color: #30333a; }
  .meta { color: #a7a9ad; } .k { color: #9a9da3; }
  code { background: #2b2d33; } .empty { background: #212328; border-color: #3a3d44; }
}
"""


@dataclass
class ScanReport:
    target: str
    findings: list[Finding]
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")
    )

    def summary(self) -> dict[str, int]:
        counts = {severity: 0 for severity in SEVERITIES}
        for finding in self.findings:
            if finding.severity in counts:
                counts[finding.severity] += 1
        counts["total"] = len(self.findings)
        return counts

    def sorted_findings(self) -> list[Finding]:
        return sorted(
            self.findings,
            key=lambda f: (_SEVERITY_ORDER.get(f.severity, len(SEVERITIES)), f.type, f.url),
        )


class Reporter:
    def render_json(self, report: ScanReport) -> str:
        data = {
            "target": report.target,
            "generated_at": report.generated_at,
            "summary": report.summary(),
            "findings": [asdict(finding) for finding in report.sorted_findings()],
        }
        return json.dumps(data, indent=2)

    def render_html(self, report: ScanReport) -> str:
        summary = report.summary()
        badges = "".join(self._badge(sev, summary[sev]) for sev in reversed(SEVERITIES))
        if report.findings:
            body = "".join(self._card(finding) for finding in report.sorted_findings())
        else:
            body = '<p class="empty">No findings were reported.</p>'
        return (
            '<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width, initial-scale=1">'
            f"<title>WAVS report — {html.escape(report.target)}</title>"
            f"<style>{_CSS}</style></head><body><main>"
            "<h1>WAVS scan report</h1>"
            f'<p class="meta">Target: <code>{html.escape(report.target)}</code><br>'
            f"Generated: {html.escape(report.generated_at)} · "
            f'{summary["total"]} finding(s)</p>'
            f'<div class="badges">{badges}</div>'
            f"<section>{body}</section>"
            "</main></body></html>"
        )

    def save(
        self,
        report: ScanReport,
        *,
        json_path: str | Path | None = None,
        html_path: str | Path | None = None,
    ) -> None:
        if json_path is not None:
            Path(json_path).write_text(self.render_json(report), encoding="utf-8")
        if html_path is not None:
            Path(html_path).write_text(self.render_html(report), encoding="utf-8")

    @staticmethod
    def _badge(severity: str, count: int) -> str:
        color = _SEVERITY_COLORS.get(severity, "#777")
        return (
            f'<span class="badge" style="background:{color}">'
            f"{html.escape(severity)}: {count}</span>"
        )

    @staticmethod
    def _card(finding: Finding) -> str:
        color = _SEVERITY_COLORS.get(finding.severity, "#777")
        rows = [
            f'<div class="row"><span class="k">URL</span>'
            f"<code>{html.escape(finding.url)}</code></div>"
        ]
        if finding.param:
            rows.append(
                f'<div class="row"><span class="k">Parameter</span>'
                f"<code>{html.escape(finding.param)}</code></div>"
            )
        rows.append(f'<p class="desc">{html.escape(finding.description)}</p>')
        if finding.evidence:
            rows.append(
                f'<div class="row"><span class="k">Evidence</span>'
                f"<code>{html.escape(finding.evidence)}</code></div>"
            )
        return (
            f'<article class="card" style="border-left-color:{color}">'
            f'<header><span class="sev" style="background:{color}">'
            f"{html.escape(finding.severity)}</span>"
            f"<h3>{html.escape(finding.type)}</h3></header>"
            f'{"".join(rows)}</article>'
        )
