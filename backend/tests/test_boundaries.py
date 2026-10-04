from contextlib import contextmanager
import json
import uuid

from fastapi.testclient import TestClient

from backend.app import auth, integrity, main
from backend.app.db import connection, now


def test_request_body_limit_without_content_length():
    with TestClient(main.app) as client:
        small = client.post(
            "/api/v1/auth/login",
            content=iter([b'{"username":"missing","password":"wrong"}']),
            headers={"Content-Type": "application/json"},
        )
        assert small.status_code == 401

        large = client.post(
            "/api/v1/auth/login",
            content=iter([b"x" * 1048576, b"x" * (1048576 + 1)]),
            headers={"Content-Type": "application/json"},
        )
        assert large.status_code == 413
        exact_limit = client.post(
            "/api/v1/auth/login",
            content=iter([b"x" * 1048576, b"x" * 1048576]),
            headers={"Content-Type": "application/json"},
        )
        assert exact_limit.status_code == 422
        assert client.post("/api/v1/auth/login", content=b"{}", headers={"Content-Length": "invalid"}).status_code == 413
        assert client.post("/api/v1/auth/login", content=b"{}", headers={"Content-Length": "9" * 5000}).status_code == 413


def test_analysis_endpoints_use_verified_bundle(monkeypatch):
    bundle = {"run_id": "run", "investigation_id": "case", "streams": [],
              "analysis": {"timeline": [{"summary": "signed event", "time_kind": "event"}],
                           "edges": [{"reason": "signed relationship", "source": "a", "target": "b", "evidence_ids": ["a", "b"]}]}}
    calls = []

    def verified(id, user):
        calls.append((id, user))
        return bundle

    monkeypatch.setattr(main, "latest_bundle", verified)
    assert main.timeline("case", {"role": "reviewer"})[0]["summary"] == "signed event"
    assert main.timeline("case", {"role": "reviewer"})[0]["timestamp_meaning"] == "event"
    assert main.correlations("case", {"role": "reviewer"})[0]["reason"] == "signed relationship"
    assert main.correlations("case", {"role": "reviewer"})[0]["source_evidence_ids"] == ["a"]
    assert len(calls) == 4


def test_database_analysis_tampering_cannot_change_served_results():
    with TestClient(main.app) as client:
        username = f"analysis-{uuid.uuid4()}"
        auth.create_user(username, "Test-only-password-123")
        login = client.post("/api/v1/auth/login", json={"username": username, "password": "Test-only-password-123"})
        assert login.status_code == 200
        client.headers["X-CSRF-Token"] = login.json()["csrf"]
        case = client.post("/api/v1/investigations", json={"name": "Integrity regression", "source": ""}).json()
        run_id = str(uuid.uuid4())
        bundle = {"run_id": run_id, "investigation_id": case["id"], "mode": "lab", "source": "", "plan": {},
                  "plan_digest": "test-plan", "streams": [], "blobs": {}, "detections": [], "coverage": [],
                  "operations": [], "exports": {}, "analysis": {"timeline": [{"summary": "signed event", "endpoint_id": "lab",
                  "event_time": None, "observed_at": now(), "time_kind": "observation", "evidence_ids": [],
                  "detection_ids": [], "uncertainty": "fixture", "provenance_kind": "synthetic"}],
                  "edges": [{"source": "a", "target": "b", "evidence_ids": ["a", "b"], "reason": "signed link",
                             "profile": "triage-v1", "confidence": "high"}]}}
        bundle["checkpoint"] = integrity.checkpoint([], bundle["plan_digest"], integrity.analysis_digest(bundle))
        assert integrity.verify(bundle)["integrity"] == "valid"
        with connection() as db:
            db.execute("INSERT INTO jobs(id,investigation_id,status,created_at,completed_at,bundle) VALUES(?,?,?,?,?,?)",
                       (run_id, case["id"], "completed", now(), now(), json.dumps(bundle)))
            db.execute("INSERT INTO timeline_events VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                       (run_id+":timeline:0", case["id"], run_id, "lab", None, now(), now(), "observation",
                        "fixture", "observation", "[]", "[]", "synthetic", "forged event"))
            db.execute("INSERT INTO correlations VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                       (run_id+":corr:0", case["id"], run_id, "lab", '["a"]', '["b"]', "evidence", "evidence",
                        "related", "forged link", "high", "triage-v1", now(), '{}'))
        base = f"/api/v1/investigations/{case['id']}"
        assert client.get(base + "/timeline").json()[0]["summary"] == "signed event"
        assert client.get(base + "/correlations").json()[0]["reason"] == "signed link"
        bundle["analysis"]["timeline"][0]["summary"] = "forged bundle"
        with connection() as db:
            db.execute("UPDATE jobs SET bundle=? WHERE id=?", (json.dumps(bundle), run_id))
        assert client.get(base + "/timeline").status_code == 409
        assert client.get(base + "/correlations").status_code == 409


def test_first_login_file_is_created_exclusively(tmp_path, monkeypatch):
    class FakeDb:
        def execute(self, sql, *args):
            if sql.startswith("SELECT"):
                return self
            raise AssertionError("An existing credential file must block account creation")

        def fetchone(self):
            return None

    @contextmanager
    def fake_connection():
        yield FakeDb()

    monkeypatch.setattr(auth, "connection", fake_connection)
    monkeypatch.setattr(auth, "DATA", tmp_path)
    credential = tmp_path / "first-login.txt"
    credential.write_text("existing credential")
    try:
        auth.bootstrap()
    except FileExistsError:
        pass
    else:
        raise AssertionError("Existing credential file was replaced")
    assert credential.read_text() == "existing credential"


def test_bootstrap_removes_credential_if_database_commit_fails(tmp_path, monkeypatch):
    class FakeDb:
        def execute(self, sql, *args):
            return self

        def fetchone(self):
            return None

    @contextmanager
    def failing_connection():
        yield FakeDb()
        raise RuntimeError("commit failed")

    monkeypatch.setattr(auth, "connection", failing_connection)
    monkeypatch.setattr(auth, "DATA", tmp_path)
    try:
        auth.bootstrap()
    except RuntimeError as exc:
        assert str(exc) == "commit failed"
    else:
        raise AssertionError("Commit failure was ignored")
    assert not (tmp_path / "first-login.txt").exists()
