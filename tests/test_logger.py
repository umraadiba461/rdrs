import app.core.logger as lg
from app.core.config import LoggingConfig


def test_each_channel_gets_its_own_file(tmp_path):
    lg._configured = False                       # allow this test to configure logging
    folder = tmp_path / "logs"
    lg.setup_logging(LoggingConfig(dir=str(folder)))
    lg.get_logger("alerts").warning("alert-line")
    lg.get_logger("audit").info("audit-line")
    lg.get_logger("events").info("event-line")
    lg.get_logger("system").info("system-line")
    for name, text in [("alerts", "alert-line"), ("audit", "audit-line"),
                       ("events", "event-line"), ("system", "system-line")]:
        assert text in (folder / f"{name}.log").read_text(encoding="utf-8")
    # a message for one channel must not leak into another
    assert "alert-line" not in (folder / "audit.log").read_text(encoding="utf-8")
    lg._configured = False