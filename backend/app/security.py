from .engine import routes

REF = {
    "SEC-01": "OWASP A01:2021 Broken Access Control", "SEC-02": "OWASP A05:2021 Security Misconfiguration",
    "SEC-03": "OWASP A05:2021 Security Misconfiguration", "SEC-04": "OWASP A02:2021 Cryptographic Failures",
    "SEC-05": "OWASP A02:2021 Cryptographic Failures", "SEC-06": "OWASP API2:2023 Broken Authentication",
    "SEC-07": "OWASP A01:2021 Broken Access Control", "SEC-08": "OWASP A09:2021 Logging and Monitoring Failures",
    "SEC-09": "Availability / resilience", "SEC-10": "OWASP A05:2021 Security Misconfiguration",
    "SEC-11": "OWASP API4:2023 Unrestricted Resource Consumption", "SEC-12": "OWASP A03:2021 Injection (WAF mitigation)",
}
POINTS = {"critical": 30, "high": 20, "medium": 10, "low": 5}
ORDER = list(POINTS)


def analyze(nodes, edges):
    """Security rules SEC-01..SEC-10. nodes/edges are plain dicts."""
    F, G = [], []

    def add(i, sev, n, msg, fix):
        F.append({"id": i, "sev": sev, "node_id": n["id"], "msg": f"{n['name']} {msg}", "fix": fix, "ref": REF.get(i, "")})

    of = lambda t: [n for n in nodes if n["type"] == t]
    vms, net, has_lb = of("vm"), next(iter(of("internet")), None), bool(of("lb"))
    for d in of("db"):
        c = d["c"]
        direct = net and any(e["from"] == net["id"] and e["to"] == d["id"] for e in edges)
        if c.get("public") or direct:
            add("SEC-01", "critical", d, "is reachable from the internet", "Make it private and connect it only to application servers.")
        else:
            G.append(f"{d['name']} is not publicly reachable")
        if not c.get("encrypted"):
            add("SEC-05", "medium", d, "stores data without encryption", "Turn on encryption at rest.")
        else:
            G.append(f"{d['name']} is encrypted")
        if c.get("subnet") == "public":
            add("SEC-10", "medium", d, "sits in a public subnet", "Move it to a private subnet.")
    for v in vms:
        c = v["c"]
        if c.get("ssh_open"):
            add("SEC-02", "high", v, "allows SSH from anywhere", "Restrict port 22 to a trusted address.")
        if c.get("public_ip") and has_lb:
            add("SEC-03", "medium", v, "has a public IP behind a load balancer", "Remove the public IP so traffic goes through the load balancer.")
        if c.get("subnet") == "public":
            add("SEC-10", "medium", v, "sits in a public subnet", "Use a private subnet.")
    for g in of("apigw"):
        if g["c"].get("auth") == "none":
            add("SEC-06", "high", g, "accepts requests without authentication", "Require JWT or an API key.")
        else:
            G.append(f"{g['name']} requires {g['c'].get('auth')}")
    for l in of("lb"):
        if l["c"].get("proto") == "HTTP":
            add("SEC-04", "medium", l, "accepts unencrypted HTTP", "Switch the protocol to HTTPS.")
    for n in nodes:
        if n["c"].get("iam") == "admin":
            add("SEC-07", "high", n, "runs with an admin IAM role", "Use a least-privilege role.")
    for n in [n for n in nodes if "logging" in n["c"] and not n["c"]["logging"]][:2]:
        add("SEC-08", "low", n, "has logging turned off", "Enable logging.")
    if len(vms) == 1:
        add("SEC-09", "medium", vms[0], "is the only VM, a single point of failure", "Add a second VM behind a load balancer.")
    elif len(vms) > 1:
        G.append(f"{len(vms)} VMs remove the single point of failure")
    for g in of("apigw"):
        if int(g["c"].get("rate") or 0) > 1000:
            add("SEC-11", "low", g, "allows more than 1000 requests per minute", "Lower the rate limit to reduce abuse and cost.")
    by, exposed = {n["id"]: n for n in nodes}, {}
    for r in routes(nodes, edges):
        waf = False
        for i in r["nodes"][1:]:
            t = by[i]["type"]
            if t == "waf":
                waf = True
            elif t in ("apigw", "lb") and not waf:
                exposed[i] = by[i]
                break
    for n in exposed.values():
        add("SEC-12", "medium", n, "is exposed to the internet without a WAF in front", "Place a WAF between the internet and this component.")
    F.sort(key=lambda f: ORDER.index(f["sev"]))
    return {"score": max(0, 100 - sum(POINTS[f["sev"]] for f in F)), "findings": F, "good": G}
