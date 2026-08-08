import time

from src.utils.known_list import load_known, prune_known, save_known


def test_round_trip_timestamps(tmp_path):
    f = tmp_path / "known.txt"
    now = time.time()
    save_known(f, {"aa:bb": now, "cc:dd": now - 100})
    loaded = load_known(f)
    assert set(loaded) == {"aa:bb", "cc:dd"}
    assert abs(loaded["aa:bb"] - now) < 1


def test_legacy_bare_addresses_load_as_recent(tmp_path):
    f = tmp_path / "legacy.txt"
    f.write_text("AA:BB\n# a comment\nCC:DD\n")
    loaded = load_known(f)
    assert set(loaded) == {"aa:bb", "cc:dd"}  # lower-cased, comment skipped
    assert all(time.time() - ts < 5 for ts in loaded.values())  # dated to now


def test_prune_drops_stale_entries():
    now = time.time()
    known = {"fresh": now, "stale": now - 40 * 86400}
    pruned = prune_known(known, max_age_days=30)
    assert set(pruned) == {"fresh"}


def test_prune_zero_disables_pruning():
    known = {"old": 0.0}
    assert prune_known(known, max_age_days=0) == known


def test_missing_file_returns_empty(tmp_path):
    assert load_known(tmp_path / "nope.txt") == {}
