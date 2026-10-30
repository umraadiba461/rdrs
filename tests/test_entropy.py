import os

from app.core.entropy import file_entropy, shannon_entropy


def test_empty_is_zero():
    assert shannon_entropy(b"") == 0.0


def test_single_byte_repeated_is_zero():
    assert shannon_entropy(b"A" * 1000) == 0.0


def test_text_is_low():
    text = b"The quick brown fox jumps over the lazy dog. " * 50
    assert 0 < shannon_entropy(text) < 5


def test_random_is_high():
    assert shannon_entropy(os.urandom(65536)) > 7.9


def test_file_entropy(tmp_path):
    f = tmp_path / "r.bin"
    f.write_bytes(os.urandom(20000))
    assert file_entropy(f) > 7.9
    assert file_entropy(tmp_path / "missing") == 0.0
