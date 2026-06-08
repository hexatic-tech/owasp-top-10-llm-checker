from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class PayloadCase:
    category_id: str
    category_name: str
    payload_file: str
    payload_path: str
    payload_name: str
    payload_text: str


@dataclass
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
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
