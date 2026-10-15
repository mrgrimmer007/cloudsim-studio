import copy

from tests.test_api import INSECURE, SECURE, client
from app.engine import HITS


def test_latency_total():
    r = client.post("/api/simulate", json=INSECURE).json()
    assert r["routes"][0]["total"] == 40  # 5+10 (vm) + 5+20 (db)


def test_one_vm_failure_is_degraded_two_is_down():
    m = copy.deepcopy(SECURE)
    next(n for n in m["nodes"] if n["id"] == "a")["failed"] = True
    assert client.post("/api/simulate", json=m).json()["status"] == "degraded"
    next(n for n in m["nodes"] if n["id"] == "b")["failed"] = True
    assert client.post("/api/simulate", json=m).json()["status"] == "down"


def call(model, method="GET", token=True):
    return client.post("/api/request", json={"model": model, "method": method, "token": token}).json()


def test_api_codes():
    HITS.clear()
    assert call(SECURE)["code"] == 200
    assert call(SECURE, token=False)["code"] == 401
    assert call(SECURE, method="DELETE")["code"] == 405


def test_rate_limit_429():
    HITS.clear()
    codes = [call(SECURE)["code"] for _ in range(12)]
    assert codes[:10] == [200] * 10 and codes[10] == 429


def test_missing_waf_flagged_with_owasp_reference():
    m = copy.deepcopy(SECURE)
    m["nodes"] = [n for n in m["nodes"] if n["id"] != "w"]
    m["edges"] = [e for e in m["edges"] if "w" not in (e["from"], e["to"])] + [{"from": "i", "to": "g"}]
    f = client.post("/api/analyze", json=m).json()["findings"]
    assert any(x["id"] == "SEC-12" and "OWASP" in x["ref"] for x in f)
