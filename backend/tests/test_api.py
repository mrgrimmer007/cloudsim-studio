import os
import tempfile

os.environ["DATA_DIR"] = tempfile.mkdtemp()

from fastapi.testclient import TestClient  # noqa: E402
from app.main import app  # noqa: E402

client = TestClient(app)


def node(i, t, name=None, **c):
    return {"id": i, "type": t, "name": name or i, "c": c}


INSECURE = {
    "nodes": [node("i", "internet"), node("v", "vm", public_ip=True, ssh_open=True, iam="admin"),
              node("d", "db", public=True, subnet="public")],
    "edges": [{"from": "i", "to": "v"}, {"from": "v", "to": "d"}],
}
SECURE = {
    "nodes": [node("i", "internet"), node("w", "waf"), node("g", "apigw", auth="jwt", logging=True), node("l", "lb", proto="HTTPS"),
              node("a", "vm", iam="least_privilege", logging=True), node("b", "vm", iam="least_privilege", logging=True),
              node("d", "db", encrypted=True, iam="least_privilege", logging=True)],
    "edges": [{"from": "i", "to": "w"}, {"from": "w", "to": "g"}, {"from": "g", "to": "l"}, {"from": "l", "to": "a"},
              {"from": "l", "to": "b"}, {"from": "a", "to": "d"}, {"from": "b", "to": "d"}],
}


def test_health():
    assert client.get("/api/health").json()["status"] == "ok"


def test_insecure_scores_zero_with_critical_finding():
    r = client.post("/api/analyze", json=INSECURE).json()
    assert r["score"] == 0
    assert r["findings"][0]["sev"] == "critical"


def test_secure_scores_100():
    r = client.post("/api/analyze", json=SECURE).json()
    assert r["score"] == 100 and not r["findings"]


def test_save_and_load_roundtrip():
    sid = client.post("/api/architectures", json={"name": "t", "model": SECURE}).json()["id"]
    assert any(a["id"] == sid for a in client.get("/api/architectures").json())
    assert len(client.get(f"/api/architectures/{sid}").json()["nodes"]) == 7
    assert client.get("/api/architectures/99999").status_code == 404
