from types import SimpleNamespace

from app.detectors.file_monitor import EventHandler


def ev(path, dest=None, is_dir=False):
    return SimpleNamespace(src_path=path, dest_path=dest, is_directory=is_dir)


def make():
    got = []
    return EventHandler(got.append, show_count=False), got


def test_created_modified_deleted():
    h, got = make()
    h.on_created(ev("a/file.txt"))
    h.on_modified(ev("a/file.txt"))
    h.on_deleted(ev("a/file.txt"))
    assert [e.event_type for e in got] == ["created", "modified", "deleted"]
    assert got[0].extension == ".txt"
    assert h.count == 3


def test_rename_records_new_extension():
    h, got = make()
    h.on_moved(ev("a/file.txt", "a/file.LOCKED"))
    e = got[0]
    assert e.event_type == "moved"
    assert e.extension == ".locked"
    assert e.dest_path == "a/file.LOCKED"


def test_directories_ignored():
    h, got = make()
    h.on_created(ev("a/folder", is_dir=True))
    assert got == [] and h.count == 0