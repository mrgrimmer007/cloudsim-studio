import time
from collections import defaultdict

LAT = {"mumbai": {"mumbai": 5, "singapore": 65, "frankfurt": 120, "virginia": 190},
       "singapore": {"singapore": 5, "frankfurt": 140, "virginia": 215},
       "frankfurt": {"frankfurt": 5, "virginia": 85}, "virginia": {"virginia": 5}}
PROC = {"waf": 1, "apigw": 3, "lb": 2, "vm": 10, "db": 20}
HITS = defaultdict(list)  # client key -> request timestamps (rate limiting)


def lat(a, b):
    return LAT[a].get(b, LAT[b].get(a, 100))


def routes(nodes, edges):
    by = {n["id"]: n for n in nodes}
    net = next((n for n in nodes if n["type"] == "internet"), None)
    if not net:
        return []
    found = []

    def go(i, tr):
        nxt = [e["to"] for e in edges if e["from"] == i and e["to"] not in tr and e["to"] in by]
        if not nxt and len(tr) > 1:
            found.append(tr)
        for t in nxt:
            go(t, tr + [t])

    go(net["id"], [net["id"]])
    out = []
    for tr in found:
        ns = [by[i] for i in tr]
        hops, total = [], 0
        for a, b in zip(ns, ns[1:]):
            ms = lat(a["c"].get("region", "mumbai"), b["c"].get("region", "mumbai")) + PROC[b["type"]]
            total += ms
            hops.append({"name": b["name"], "ms": ms, "failed": bool(b.get("failed"))})
        out.append({"nodes": tr, "hops": hops, "total": total, "alive": all(not n.get("failed") for n in ns),
                    "edges": [f"{a}>{b}" for a, b in zip(tr, tr[1:])]})
    return out


def simulate(nodes, edges):
    r = routes(nodes, edges)
    up = sum(1 for x in r if x["alive"])
    status = "none" if not r else "up" if up == len(r) else "degraded" if up else "down"
    return {"status": status, "routes": r}


def api_request(nodes, edges, method, token, key, now=None):
    now = now or time.time()
    hits = [t for t in HITS[key] if now - t < 60]
    g = next((n for n in nodes if n["type"] == "apigw"), None)
    ms = None
    if g and method not in ("GET", "POST"):
        code, text = 405, "Method not allowed"
    elif g and g["c"].get("auth", "none") != "none" and not token:
        code, text = 401, "Unauthorized"
    else:
        hits.append(now)
        alive = [r for r in routes(nodes, edges) if r["alive"]]
        if g and len(hits) > int(g["c"].get("rate") or 10):
            code, text = 429, "Rate limit exceeded"
        elif not alive:
            code, text = 503, "No working route"
        else:
            code, text, ms = 200, "OK", min(r["total"] for r in alive)
    HITS[key] = hits
    return {"code": code, "text": text, "ms": ms}
