import asyncio
import json
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urljoin, urlparse

import httpx
from PySide6.QtCore import QThread, Signal

from src.core.evaluator import evaluate_response
from src.core.models import PayloadCase, ScanResult, utc_timestamp
from src.core.payload_loader import load_payload_cases


CHAT_FIELD_HINTS = ("chat", "message", "prompt", "query", "question", "ask", "text", "input")


def build_request_body(case: PayloadCase) -> dict[str, str]:
    """Customize this fallback if your target API expects another JSON schema."""
    return {
        "category_id": case.category_id,
        "category_name": case.category_name,
        "prompt": case.payload_text,
    }


@dataclass(frozen=True)
class BotTarget:
    page_url: str
    action_url: str
    method: str
    field_name: str
    fields: dict[str, str]


class FormCandidate:
    def __init__(self, page_url: str, attrs: dict[str, str]) -> None:
        self.page_url = page_url
        self.action = attrs.get("action", "")
        self.method = attrs.get("method", "post").lower()
        self.inputs: list[dict[str, str]] = []
        self.textareas: list[dict[str, str]] = []


class BotFormParser(HTMLParser):
    def __init__(self, page_url: str) -> None:
        super().__init__()
        self.page_url = page_url
        self.links: list[str] = []
        self.forms: list[FormCandidate] = []
        self._current_form: FormCandidate | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_map = {key.lower(): value or "" for key, value in attrs}
        if tag == "a" and attr_map.get("href"):
            self.links.append(urljoin(self.page_url, attr_map["href"]))
            return

        if tag == "form":
            self._current_form = FormCandidate(self.page_url, attr_map)
            self.forms.append(self._current_form)
            return

        if self._current_form and tag == "input":
            self._current_form.inputs.append(attr_map)
        elif self._current_form and tag == "textarea":
            self._current_form.textareas.append(attr_map)

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._current_form = None


class AsyncScanner:
    def __init__(
        self,
        base_dir: Path,
        target_url: str,
        timeout_seconds: int = 30,
        delay_seconds: int = 2,
        max_crawl_pages: int = 12,
        enable_browser_scan: bool = True,
        on_log: Callable[[str], None] | None = None,
        on_website_status: Callable[[str, bool], None] | None = None,
        on_progress: Callable[[int, int], None] | None = None,
        on_result: Callable[[ScanResult], None] | None = None,
    ) -> None:
        self.base_dir = base_dir
        self.target_url = target_url
        self.timeout_seconds = timeout_seconds
        self.delay_seconds = delay_seconds
        self.max_crawl_pages = max_crawl_pages
        self.enable_browser_scan = enable_browser_scan
        self.on_log = on_log or (lambda _: None)
        self.on_website_status = on_website_status or (lambda _message, _ok: None)
        self.on_progress = on_progress or (lambda _current, _total: None)
        self.on_result = on_result or (lambda _result: None)
        self._stop_requested = False

    def stop(self) -> None:
        self._stop_requested = True

    async def run(self) -> list[ScanResult]:
        cases = load_payload_cases(self.base_dir)
        results: list[ScanResult] = []

        async with httpx.AsyncClient(timeout=self.timeout_seconds, follow_redirects=True) as client:
            ok, message = await self._check_target(client)
            self.on_website_status(message, ok)
            self.on_log(message)
            if not ok:
                self.on_log("Scan stopped because the target website check failed.")
                return results

            browser_session: BrowserBotSession | None = None
            bot_target = await self._discover_bot_target(client)
            if bot_target:
                self.on_log(
                    "Bot input found. Payloads will be submitted to "
                    f"{bot_target.action_url} using field '{bot_target.field_name}'."
                )
            elif self.enable_browser_scan:
                browser_session = await BrowserBotSession.create(
                    self.target_url,
                    timeout_ms=self.timeout_seconds * 1000,
                    on_log=self.on_log,
                )
                if browser_session:
                    self.on_log("JavaScript-rendered bot input found. Browser scan mode is active.")
                else:
                    self.on_log("Browser scan did not find a visible bot input.")

            else:
                self.on_log("Browser scan is disabled.")

            if not bot_target and not browser_session:
                self.on_log("No AI bot or chat input was found. OWASP LLM tests cannot be evaluated for this website.")
                return self._results_for_missing_bot(cases)

            try:
                for index, case in enumerate(cases, start=1):
                    if self._stop_requested:
                        self.on_log("Stop requested. Ending scan before next payload.")
                        break

                    self.on_log(f"Testing {case.category_id}: {case.category_name}")
                    status_code: int | None = None
                    raw_response = ""

                    try:
                        if browser_session:
                            status_code, raw_response = await browser_session.submit(case.payload_text)
                        else:
                            response = await self._send_payload(client, case, bot_target)
                            status_code = response.status_code
                            raw_response = self._response_to_text(response)
                        result, reason = evaluate_response(case.category_id, raw_response, status_code)
                    except (httpx.TimeoutException, httpx.TransportError) as exc:
                        result, reason = "ERROR", f"HTTP request failed: {exc}"
                    except Exception as exc:
                        result, reason = "ERROR", f"Unexpected scanner error: {exc}"

                    scan_result = ScanResult(
                        target_url=self.target_url,
                        timestamp=utc_timestamp(),
                        category_id=case.category_id,
                        category_name=case.category_name,
                        payload_file=case.payload_file,
                        payload_name=case.payload_name,
                        payload_text=case.payload_text,
                        http_status=status_code,
                        raw_response=raw_response,
                        response_preview=raw_response[:700],
                        result=result,
                        reason=reason,
                    )
                    results.append(scan_result)
                    self.on_result(scan_result)
                    self.on_progress(index, len(cases))

                    if index < len(cases) and not self._stop_requested:
                        await asyncio.sleep(self.delay_seconds)
            finally:
                if browser_session:
                    await browser_session.close()

        return results

    def _results_for_missing_bot(self, cases: list[PayloadCase]) -> list[ScanResult]:
        reason = (
            "No AI bot, chat input, or LLM API endpoint was found. "
            "This website was not evaluated for OWASP LLM vulnerabilities."
        )
        results: list[ScanResult] = []
        for index, case in enumerate(cases, start=1):
            result = ScanResult(
                target_url=self.target_url,
                timestamp=utc_timestamp(),
                category_id=case.category_id,
                category_name=case.category_name,
                payload_file=case.payload_file,
                payload_name=case.payload_name,
                payload_text=case.payload_text,
                http_status=None,
                raw_response="No AI bot or chat input was detected on the target website.",
                response_preview="No AI bot or chat input was detected on the target website.",
                result="ERROR",
                reason=reason,
            )
            results.append(result)
            self.on_result(result)
            self.on_progress(index, len(cases))
        return results

    async def _send_payload(
        self,
        client: httpx.AsyncClient,
        case: PayloadCase,
        bot_target: BotTarget | None,
    ) -> httpx.Response:
        if bot_target:
            fields = dict(bot_target.fields)
            fields[bot_target.field_name] = case.payload_text
            if bot_target.method == "get":
                return await client.get(bot_target.action_url, params=fields)
            return await client.post(bot_target.action_url, data=fields)

        return await client.post(
            self.target_url,
            headers={"Content-Type": "application/json"},
            json=build_request_body(case),
        )

    async def _discover_bot_target(self, client: httpx.AsyncClient) -> BotTarget | None:
        start_origin = _origin(self.target_url)
        queue = [self.target_url]
        seen: set[str] = set()

        while queue and len(seen) < self.max_crawl_pages:
            page_url = queue.pop(0)
            if page_url in seen or _origin(page_url) != start_origin:
                continue

            seen.add(page_url)
            self.on_log(f"Crawling page {len(seen)}/{self.max_crawl_pages}: {page_url}")

            try:
                response = await client.get(page_url)
            except httpx.HTTPError as exc:
                self.on_log(f"Could not crawl {page_url}: {exc}")
                continue

            content_type = response.headers.get("content-type", "")
            if "html" not in content_type.lower() and "<html" not in response.text[:500].lower():
                continue

            parser = BotFormParser(str(response.url))
            parser.feed(response.text)

            for form in parser.forms:
                target = self._bot_target_from_form(form)
                if target:
                    return target

            for link in parser.links:
                normalized = _without_fragment(link)
                if (
                    normalized not in seen
                    and _origin(normalized) == start_origin
                    and normalized not in queue
                    and len(queue) + len(seen) < self.max_crawl_pages
                ):
                    queue.append(normalized)

        return None

    def _bot_target_from_form(self, form: FormCandidate) -> BotTarget | None:
        field_name = self._find_chat_field(form)
        if not field_name:
            return None

        action_url = urljoin(form.page_url, form.action or form.page_url)
        fields: dict[str, str] = {}
        for input_attrs in form.inputs:
            name = input_attrs.get("name")
            input_type = input_attrs.get("type", "text").lower()
            if not name or input_type in {"submit", "button", "reset", "file"}:
                continue
            fields[name] = input_attrs.get("value", "")

        return BotTarget(
            page_url=form.page_url,
            action_url=action_url,
            method=form.method if form.method in {"get", "post"} else "post",
            field_name=field_name,
            fields=fields,
        )

    @staticmethod
    def _find_chat_field(form: FormCandidate) -> str | None:
        for textarea in form.textareas:
            name = textarea.get("name")
            if name:
                return name

        text_inputs = [
            item
            for item in form.inputs
            if item.get("type", "text").lower() in {"text", "search", "email", "url", ""}
            and item.get("name")
        ]
        for item in text_inputs:
            haystack = " ".join(
                item.get(key, "").lower() for key in ("name", "id", "placeholder", "aria-label")
            )
            if any(hint in haystack for hint in CHAT_FIELD_HINTS):
                return item.get("name")

        if len(text_inputs) == 1:
            return text_inputs[0].get("name")
        return None

    async def _check_target(self, client: httpx.AsyncClient) -> tuple[bool, str]:
        try:
            response = await client.head(self.target_url)
            if response.status_code < 500 or response.status_code == 405:
                return True, f"Website check passed. Target responded with HTTP {response.status_code}."
        except httpx.HTTPError:
            pass

        try:
            response = await client.get(self.target_url)
            if response.status_code < 500 or response.status_code == 405:
                return True, f"Website check passed. Target responded with HTTP {response.status_code}."
            return False, f"Website check failed. Target responded with HTTP {response.status_code}."
        except httpx.HTTPError as exc:
            return False, f"Website check failed. Could not reach target: {exc}"

    @staticmethod
    def _response_to_text(response: httpx.Response) -> str:
        try:
            parsed = response.json()
            return json.dumps(parsed, indent=2, ensure_ascii=False)
        except ValueError:
            return response.text


class ScannerThread(QThread):
    log = Signal(str)
    website_status = Signal(str, bool)
    progress = Signal(int, int)
    result = Signal(object)
    finished_with_results = Signal(list)
    failed = Signal(str)

    def __init__(
        self,
        base_dir: Path,
        target_url: str,
        timeout_seconds: int,
        delay_seconds: int,
        max_crawl_pages: int,
        enable_browser_scan: bool,
    ) -> None:
        super().__init__()
        self.scanner = AsyncScanner(
            base_dir=base_dir,
            target_url=target_url,
            timeout_seconds=timeout_seconds,
            delay_seconds=delay_seconds,
            max_crawl_pages=max_crawl_pages,
            enable_browser_scan=enable_browser_scan,
            on_log=self.log.emit,
            on_website_status=self.website_status.emit,
            on_progress=self.progress.emit,
            on_result=self.result.emit,
        )

    def stop(self) -> None:
        self.scanner.stop()

    def run(self) -> None:
        try:
            results = asyncio.run(self.scanner.run())
            self.finished_with_results.emit(results)
        except Exception as exc:
            self.failed.emit(str(exc))


def _origin(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _without_fragment(url: str) -> str:
    parsed = urlparse(url)
    return parsed._replace(fragment="").geturl()


class BrowserBotSession:
    def __init__(self, playwright: Any, browser: Any, page: Any, input_locator: Any, on_log: Callable[[str], None]) -> None:
        self.playwright = playwright
        self.browser = browser
        self.page = page
        self.input_locator = input_locator
        self.on_log = on_log

    @classmethod
    async def create(
        cls,
        target_url: str,
        timeout_ms: int,
        on_log: Callable[[str], None],
    ) -> "BrowserBotSession | None":
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            on_log("Playwright is not installed. Install it to scan JavaScript-rendered chat boxes.")
            return None

        playwright = await async_playwright().start()
        try:
            browser = await playwright.chromium.launch(headless=True)
            page = await browser.new_page()
            page.set_default_timeout(timeout_ms)
            await page.goto(target_url, wait_until="networkidle")
            input_locator = await cls._find_input(page)
            if not input_locator:
                await browser.close()
                await playwright.stop()
                return None
            return cls(playwright, browser, page, input_locator, on_log)
        except Exception as exc:
            on_log(f"Browser scan unavailable: {exc}")
            await playwright.stop()
            return None

    @staticmethod
    async def _find_input(page: Any) -> Any | None:
        selectors = [
            "textarea[placeholder*='ask' i]:visible",
            "textarea[placeholder*='message' i]:visible",
            "textarea[placeholder*='prompt' i]:visible",
            "input[placeholder*='message' i]:visible",
            "input[placeholder*='prompt' i]:visible",
            "input[placeholder*='ask' i]:visible",
            "[contenteditable='true']:visible",
            "textarea:visible",
            "input[type='text']:visible",
            "input:not([type]):visible",
        ]
        for selector in selectors:
            locator_group = page.locator(selector)
            try:
                count = await locator_group.count()
                for index in range(count):
                    locator = locator_group.nth(index)
                    if await locator.is_visible() and await locator.is_enabled():
                        label_text = await locator.evaluate(
                            """el => [
                                el.getAttribute('name'),
                                el.getAttribute('id'),
                                el.getAttribute('placeholder'),
                                el.getAttribute('aria-label'),
                                el.getAttribute('type')
                            ].filter(Boolean).join(' ').toLowerCase()"""
                        )
                        if any(skip in label_text for skip in ("email", "name", "company", "institution")):
                            continue
                        return locator
            except Exception:
                continue
        return None

    async def submit(self, payload: str) -> tuple[int, str]:
        before_text = await self.page.locator("body").inner_text(timeout=5000)
        await self.input_locator.fill(payload)
        await self.input_locator.focus()
        await self._submit_current_input()
        try:
            await self.page.wait_for_load_state("networkidle", timeout=10000)
        except Exception:
            pass
        await self.page.wait_for_timeout(1500)
        after_text = await self.page.locator("body").inner_text(timeout=5000)
        response_text = after_text
        if after_text.startswith(before_text):
            response_text = after_text[len(before_text) :].strip()
        if not response_text or response_text == after_text:
            return 200, (
                "Browser automation response:\n\n"
                "No visible bot response was detected after submitting the payload. "
                "The page may require a custom selector or a non-standard submit action."
            )
        response_text = response_text.replace(payload, "[submitted payload omitted]")
        return 200, "Browser automation response:\n\n" + response_text

    async def _submit_current_input(self) -> None:
        try:
            await self.input_locator.press("Enter")
            return
        except Exception:
            pass

        button_selectors = [
            "button[type='submit']:visible",
            "button[aria-label*='send' i]:visible",
            "button[title*='send' i]:visible",
            "button:has-text('Send'):visible",
            "button:has-text('Submit'):visible",
            "button:has-text('Ask'):visible",
        ]
        for selector in button_selectors:
            button = self.page.locator(selector).last
            try:
                if await button.count() and await button.is_enabled():
                    await button.click()
                    return
            except Exception:
                continue
        raise RuntimeError("Could not submit the discovered bot input.")

    async def close(self) -> None:
        await self.browser.close()
        await self.playwright.stop()
