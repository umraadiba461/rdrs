from pathlib import Path

PAGE = Path(__file__).resolve().parent.parent / "app" / "dashboard" / "index.html"


def test_dashboard_page_exists():
    assert PAGE.exists()


def test_dashboard_calls_every_api_it_needs():
    html = PAGE.read_text(encoding="utf-8")
    for endpoint in ("/status", "/alerts", "/events", "/incidents", "/scores", "/scan"):
        assert endpoint in html


def test_dashboard_refreshes_every_three_seconds():
    assert "setInterval(refresh, 3000)" in PAGE.read_text(encoding="utf-8")


def test_dashboard_never_writes_data_with_innerhtml():
    # file names come from disk; innerHTML would let a malicious name run as code
    assert "innerHTML" not in PAGE.read_text(encoding="utf-8")