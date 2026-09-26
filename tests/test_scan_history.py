from app.database.scan_history import get_recent_scans


def test_recent_scans_returns_scan_history():
    scans = get_recent_scans()

    assert isinstance(scans, list)
    assert len(scans) >= 1

    latest = scans[0]

    assert "id" in latest
    assert "target_name" in latest
    assert "base_url" in latest
    assert "status" in latest
    assert "started_at" in latest
    assert "scanner_version" in latest
