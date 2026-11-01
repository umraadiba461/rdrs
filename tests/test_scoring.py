from types import SimpleNamespace

from app.detectors.scoring import calculate_score, classify

W = SimpleNamespace(rapid_encryption=40, mass_rename=30, high_entropy=25, cpu_spike=15, unknown_program=10)
L = SimpleNamespace(warning=40, critical=70)


def test_no_signals_is_zero_and_normal():
    assert calculate_score(set(), W) == 0
    assert classify(0, L) == "Normal"


def test_two_signals_add_up():
    assert calculate_score({"rapid_encryption", "mass_rename"}, W) == 70
    assert classify(70, L) == "Critical"


def test_boundaries():
    assert classify(39, L) == "Normal"
    assert classify(40, L) == "Warning"
    assert classify(69, L) == "Warning"


def test_score_is_capped_at_100():
    allsig = {"rapid_encryption", "mass_rename", "high_entropy", "cpu_spike", "unknown_program"}
    assert calculate_score(allsig, W) == 100


def test_unknown_signal_counts_zero():
    assert calculate_score({"made_up"}, W) == 0