from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class PayloadCase:
    category_id: str
    category_name: str
    payload_file: str
    payload_path: str
    payload_name: str
    payload_text: str


@dataclass(frozen=True)
class ScanResult:
    target_url: str
    timestamp: str
    category_id: str
    category_name: str
    payload_file: str
    payload_name: str
    payload_text: str
    http_status: int | None
    raw_response: str
    response_preview: str
    result: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def utc_timestamp() -> str:
    """Current UTC time as an ISO-8601 string, e.g. '2026-06-15T12:00:00Z'."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
