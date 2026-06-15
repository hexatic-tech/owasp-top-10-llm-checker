from src.core.payload_loader import split_payload_entries


def test_single_entry_without_markers():
    assert split_payload_entries("hello world") == [("Payload 1", "hello world")]


def test_blank_text_yields_no_entries():
    assert split_payload_entries("   \n  ") == []


def test_multiple_payload_markers():
    text = "PAYLOAD 1:\nfoo\n\nPAYLOAD 2:\nbar\n"
    entries = split_payload_entries(text)
    assert [name for name, _ in entries] == ["Payload 1", "Payload 2"]
    assert [body for _, body in entries] == ["foo", "bar"]


def test_marker_with_empty_body_is_skipped():
    text = "PAYLOAD 1:\n\nPAYLOAD 2:\nbar\n"
    entries = split_payload_entries(text)
    assert [name for name, _ in entries] == ["Payload 2"]
