import json
from collections import Counter
from datetime import datetime
from html import escape
from pathlib import Path

from src.core import scoring
from src.core.models import ScanResult, utc_timestamp


def write_reports(base_dir: Path, results: list[ScanResult], report_stem: str = "report") -> tuple[Path, Path]:
    reports_dir = base_dir / "reports"
    reports_dir.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = reports_dir / f"{report_stem}_{timestamp}.json"
    md_path = reports_dir / f"{report_stem}_{timestamp}.md"

    write_json_report(json_path, results)
    write_markdown_report(md_path, results)
    return json_path, md_path


def write_json_report(path: Path, results: list[ScanResult]) -> None:
    path.write_text(json_report(results), encoding="utf-8")


def write_markdown_report(path: Path, results: list[ScanResult]) -> None:
    path.write_text(markdown_report(results), encoding="utf-8")


def write_html_report(path: Path, results: list[ScanResult]) -> None:
    path.write_text(html_report(results), encoding="utf-8")


def json_report(results: list[ScanResult]) -> str:
    return json.dumps([result.to_dict() for result in results], indent=2, ensure_ascii=False)


def markdown_report(results: list[ScanResult]) -> str:
    if not results:
        return "# OWASP LLM Top 10 Payload Tester Report\n\nNo results were recorded.\n"

    first = results[0]
    category_rollups = _category_rollups(results)
    counts = Counter(item["result"] for item in category_rollups)
    score = _security_score(category_rollups)
    lines = [
        "# OWASP LLM Top 10 Payload Tester Report",
        "",
        f"Target URL: {first.target_url}",
        f"Generated: {utc_timestamp()}",
        f"OWASP Security Score: {score.display}",
        f"Assessment: {score.assessment}",
        "",
        "## Final Summary",
        "",
        "| Result | Count |",
        "| --- | ---: |",
    ]
    for key in scoring.CATEGORY_STATUSES:
        lines.append(f"| {key} | {counts.get(key, 0)} |")

    lines.extend([
        "",
        "## Category Summary",
        "",
        "| Category | Name | Result | Reason |",
        "| --- | --- | --- | --- |",
    ])
    for item in category_rollups:
        lines.append(
            f"| {item['category_id']} | {item['category_name']} | "
            f"{item['result']} | {_escape_table(str(item['reason']))} |"
        )

    for result in results:
        lines.extend([
            "",
            f"## {result.category_id}: {result.category_name} - {result.payload_name}",
            "",
            f"- Payload file: `{result.payload_file}`",
            f"- Payload name: `{result.payload_name}`",
            f"- HTTP status: `{result.http_status}`",
            f"- Result: `{result.result}`",
            f"- Reason: {result.reason}",
            "",
            "### Payload",
            "",
            "```text",
            result.payload_text.strip(),
            "```",
            "",
            "### Raw Response",
            "",
            "```text",
            result.raw_response.strip() or "(empty response)",
            "```",
            "",
            "### Response Preview",
            "",
            "```text",
            result.response_preview.strip() or "(empty response)",
            "```",
        ])

    return "\n".join(lines) + "\n"


def html_report(results: list[ScanResult]) -> str:
    if not results:
        return _html_page("<h1>OWASP LLM Top 10 Payload Tester Report</h1><p>No results were recorded.</p>")

    first = results[0]
    category_rollups = _category_rollups(results)
    counts = Counter(item["result"] for item in category_rollups)
    score = _security_score(category_rollups)
    summary_rows = "".join(
        f"<tr><td>{key}</td><td>{counts.get(key, 0)}</td></tr>"
        for key in scoring.CATEGORY_STATUSES
    )
    result_rows = "".join(
        "<tr>"
        f"<td>{escape(str(item['category_id']))}</td>"
        f"<td>{escape(str(item['category_name']))}</td>"
        f"<td><span class='badge {escape(str(item['result']).lower())}'>{escape(str(item['result']))}</span></td>"
        f"<td>{escape(str(item['reason']))}</td>"
        "</tr>"
        for item in category_rollups
    )
    details = "\n".join(
        "<details>"
        f"<summary>{escape(result.category_id)}: {escape(result.category_name)} - {escape(result.payload_name)} - {escape(result.result)}</summary>"
        f"<p><strong>Payload file:</strong> {escape(result.payload_file)}</p>"
        f"<p><strong>Payload name:</strong> {escape(result.payload_name)}</p>"
        f"<p><strong>HTTP status:</strong> {escape(str(result.http_status))}</p>"
        f"<p><strong>Reason:</strong> {escape(result.reason)}</p>"
        "<h3>Payload</h3>"
        f"<pre>{escape(result.payload_text.strip())}</pre>"
        "<h3>Raw Response</h3>"
        f"<pre>{escape(result.raw_response.strip() or '(empty response)')}</pre>"
        "</details>"
        for result in results
    )
    body = f"""
    <h1>OWASP LLM Top 10 Payload Tester Report</h1>
    <section class="meta">
      <p><strong>Target URL:</strong> {escape(first.target_url)}</p>
      <p><strong>Generated:</strong> {escape(utc_timestamp())}</p>
      <p><strong>OWASP Security Score:</strong> {escape(score.display)}</p>
      <p><strong>Assessment:</strong> {escape(score.assessment)}</p>
    </section>
    <h2>Final Summary</h2>
    <table><thead><tr><th>Result</th><th>Count</th></tr></thead><tbody>{summary_rows}</tbody></table>
    <h2>Category Summary</h2>
    <table>
      <thead><tr><th>Category</th><th>Name</th><th>Result</th><th>Reason</th></tr></thead>
      <tbody>{result_rows}</tbody>
    </table>
    <h2>Details</h2>
    {details}
    """
    return _html_page(body)


def _category_rollups(results: list[ScanResult]) -> list[dict[str, object]]:
    grouped: dict[str, list[ScanResult]] = {}
    ordered_ids: list[str] = []
    for result in results:
        if result.category_id not in grouped:
            grouped[result.category_id] = []
            ordered_ids.append(result.category_id)
        grouped[result.category_id].append(result)

    rollups: list[dict[str, object]] = []
    for category_id in ordered_ids:
        items = grouped[category_id]
        first = items[0]
        rollups.append(
            {
                "category_id": category_id,
                "category_name": first.category_name,
                "result": scoring.category_status([item.result for item in items]),
                "reason": _aggregate_reason(items),
            }
        )
    return rollups


def _aggregate_reason(items: list[ScanResult]) -> str:
    status = scoring.category_status([item.result for item in items])
    count = len(items)
    if status == scoring.FAIL:
        return f"All {count} payload(s) in this category failed."
    if status == scoring.MIXED:
        passed = sum(1 for item in items if item.result == "PASS")
        return (
            f"{passed} of {count} payloads passed; the rest failed, warned, or errored. "
            "Manual review recommended."
        )
    if status == scoring.ERROR:
        return f"All {count} payload(s) in this category could not be evaluated."
    return f"All {count} payload(s) in this category passed."


def _security_score(category_rollups: list[dict[str, object]]) -> scoring.SecurityScore:
    return scoring.security_score([str(item["result"]) for item in category_rollups])


def _escape_table(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def _html_page(body: str) -> str:
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>OWASP LLM Top 10 Payload Tester Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 32px; color: #1f2933; line-height: 1.45; }}
    h1, h2, h3 {{ color: #102a43; }}
    table {{ border-collapse: collapse; width: 100%; margin: 16px 0 28px; }}
    th, td {{ border: 1px solid #d9e2ec; padding: 9px 10px; text-align: left; vertical-align: top; }}
    th {{ background: #f0f4f8; }}
    pre {{ background: #f5f7fa; border: 1px solid #d9e2ec; padding: 12px; overflow-x: auto; white-space: pre-wrap; }}
    details {{ border: 1px solid #d9e2ec; border-radius: 6px; padding: 12px; margin: 12px 0; }}
    summary {{ cursor: pointer; font-weight: 700; }}
    .meta {{ background: #f8fafc; border: 1px solid #d9e2ec; border-radius: 6px; padding: 12px 16px; }}
    .badge {{ color: white; border-radius: 4px; padding: 3px 7px; font-weight: 700; }}
    .pass {{ background: #198754; }}
    .fail {{ background: #dc3545; }}
    .mixed {{ background: #b7791f; }}
    .warning {{ background: #b7791f; }}
    .error {{ background: #6c757d; }}
  </style>
</head>
<body>
{body}
</body>
</html>
"""
