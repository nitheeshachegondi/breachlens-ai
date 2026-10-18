"""BreachLens AI - attack-path analysis on FalkorDB. Discovery, scoring and what-if are deterministic Cypher."""
import os, uuid, httpx
from fastapi import FastAPI, HTTPException, Body
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
from falkordb import FalkorDB
try:
    from .agent import run_agent
except ImportError:  # loaded as a top-level module (e.g. by a serverless host)
    from agent import run_agent

BASE = "breachlens"
app = FastAPI(title="BreachLens AI")
@app.exception_handler(Exception)
async def boom(request, exc):
    return JSONResponse({"detail": f"{type(exc).__name__}: {exc}", "host": os.getenv("FALKORDB_HOST", "localhost"), "port": os.getenv("FALKORDB_PORT", "6379")}, status_code=500)
_db = None
LOG: list = []
def db():
    global _db
    if _db is None:
        _db = FalkorDB(host=os.getenv("FALKORDB_HOST", "localhost"), port=int(os.getenv("FALKORDB_PORT", 6379)),
                       username=os.getenv("FALKORDB_USERNAME") or None, password=os.getenv("FALKORDB_PASSWORD") or None, ssl=os.getenv("FALKORDB_SSL") == "1")
    return _db
def q(g, cypher, **p):
    LOG.append(" ".join(cypher.split())); return g.query(cypher, p).result_set

# Demo company (FICTIONAL / synthetic). CVE ids are public NVD records, SYN-* is invented.
ALLOWED = {"EXPOSES", "CONNECTS_TO", "CAN_ACCESS", "DEPENDS_ON", "HAS_VULNERABILITY"}
DEFAULT = {
    "company": {"name": "LedgerLoop", "desc": "Fictional 40-person B2B invoicing and payouts SaaS. Its scanner, dependency checker and cloud inventory produce three separate reports; BreachLens joins them into one graph."},
    "services": [["web-gateway", "Web App"], ["admin-portal", "Staff Admin"], ["api-service", "Invoice API"], ["auth-service", "Staff SSO"], ["billing-worker", "Payout Worker"]],
    "components": [["log4j-core", "log4j-core 2.14.1"], ["spring-framework", "Spring 5.3.17"], ["legacy-auth-lib", "legacy-auth-lib 0.9"]],
    "vulnerabilities": [["CVE-2021-44228", "Log4Shell", 10.0, "NVD (public record)"], ["CVE-2022-22965", "Spring4Shell", 9.8, "NVD (public record)"],
                        ["SYN-2026-001", "Hard-coded service token (synthetic)", 7.5, "synthetic"]],
    "sensitive": [["customer-db", "Customer DB", 9], ["payment-secrets", "Payout Keys", 10]],
    "edges": [["EXPOSES", "internet", "web-gateway"], ["EXPOSES", "internet", "admin-portal"],
              ["CONNECTS_TO", "web-gateway", "api-service"], ["CONNECTS_TO", "api-service", "billing-worker"], ["CONNECTS_TO", "admin-portal", "auth-service"],
              ["CAN_ACCESS", "api-service", "customer-db"], ["CAN_ACCESS", "billing-worker", "payment-secrets"], ["CAN_ACCESS", "auth-service", "payment-secrets"],
              ["DEPENDS_ON", "api-service", "log4j-core"], ["DEPENDS_ON", "admin-portal", "spring-framework"], ["DEPENDS_ON", "auth-service", "legacy-auth-lib"],
              ["HAS_VULNERABILITY", "log4j-core", "CVE-2021-44228"], ["HAS_VULNERABILITY", "spring-framework", "CVE-2022-22965"],
              ["HAS_VULNERABILITY", "legacy-auth-lib", "SYN-2026-001"]]}
LEN = {"services": 2, "components": 2, "vulnerabilities": 4, "sensitive": 3, "edges": 3}
def validate(d):
    try:
        for k, n in LEN.items():
            assert isinstance(d[k], list) and len(d[k]) <= 300 and all(isinstance(x, list) and len(x) == n for x in d[k])
        assert all(e[0] in ALLOWED for e in d["edges"])
        c = d.get("company") or {}
        return {"company": {"name": str(c.get("name", "Your company"))[:80], "desc": str(c.get("desc", ""))[:400]},
                "services": [[str(x[0]), str(x[1])] for x in d["services"]], "components": [[str(x[0]), str(x[1])] for x in d["components"]],
                "vulnerabilities": [[str(x[0]), str(x[1]), float(x[2]), str(x[3])] for x in d["vulnerabilities"]],
                "sensitive": [[str(x[0]), str(x[1]), int(x[2])] for x in d["sensitive"]], "edges": [[str(x) for x in e] for e in d["edges"]]}
    except Exception:
        raise HTTPException(400, "Invalid inventory JSON. Download /api/sample to see the format.")

_REC = None  # cache of fix ranking; cleared whenever the graph is re-seeded (saves round trips on a cloud DB)
def seed(name=BASE, data=None):
    global _REC; _REC = None
    d = data or DEFAULT
    try: db().select_graph(name).delete()
    except Exception: pass
    g = db().select_graph(name)
    q(g, "CREATE (:Internet {id:'internet', name:'Public Internet'})")
    q(g, "CREATE (:Company {name:$n, desc:$d})", n=d["company"]["name"], d=d["company"]["desc"])
    q(g, "UNWIND $r AS r CREATE (:Service {id:r[0], name:r[1]})", r=d["services"])
    q(g, "UNWIND $r AS r CREATE (:Component {id:r[0], name:r[1]})", r=d["components"])
    q(g, "UNWIND $r AS r CREATE (:Vulnerability {id:r[0], name:r[1], cvss:r[2], source:r[3]})", r=d["vulnerabilities"])
    q(g, "UNWIND $r AS r CREATE (:Sensitive {id:r[0], name:r[1], sensitivity:r[2]})", r=d["sensitive"])
    for t, a, b in d["edges"]:
        q(g, f"MATCH (a {{id:$a}}),(b {{id:$b}}) CREATE (a)-[:{t}]->(b)", a=a, b=b)
    return g

PATH_Q = ("MATCH p=(:Internet)-[:EXPOSES|CONNECTS_TO|CAN_ACCESS*1..6]->(s:Sensitive) "
          "RETURN [n IN nodes(p) | n.id], s.sensitivity, length(p)")
VULN_Q = ("MATCH (s:Service)-[:DEPENDS_ON]->(c:Component)-[:HAS_VULNERABILITY]->(v:Vulnerability) "
          "RETURN s.id, c.id, v.id, v.name, v.cvss, v.source")
def paths(g):
    vul = {}
    for s, c, v, vn, cv, src in q(g, VULN_Q):
        vul.setdefault(s, []).append({"service": s, "component": c, "id": v, "name": vn, "cvss": cv, "source": src})
    out = []
    for ids, sens, ln in q(g, PATH_Q):
        f = [x for n in ids for x in vul.get(n, [])]
        if not f: continue  # reachable but no known weakness: not a candidate
        score = round(0.6 * max(x["cvss"] for x in f) + 0.3 * sens + 0.1 * max(0, 10 - 2 * ln), 1)
        out.append({"id": "->".join(ids), "nodes": ids, "length": ln, "score": score, "findings": f,
                    "severity": "critical" if score >= 8.5 else "high" if score >= 7 else "medium",
                    "assumptions": ["Reachability + a known weakness makes this a candidate path, not proof of exploitability.",
                                    "Score = 0.6*max CVSS + 0.3*asset sensitivity + 0.1*(10-2*hops). Weights are configurable."]})
    return sorted(out, key=lambda p: -p["score"])

def apply(g, action):
    k, _, t = action.partition(":")
    if k == "patch": q(g, "MATCH (:Component {id:$t})-[r:HAS_VULNERABILITY]->() DELETE r", t=t)
    elif k == "isolate": q(g, "MATCH (:Service {id:$t})-[r:EXPOSES|CONNECTS_TO|CAN_ACCESS]-() DELETE r", t=t)
    else: raise HTTPException(400, "unknown action")
def simulate(action):  # runs on a COPY; the real graph is never modified
    before = paths(db().select_graph(BASE)); name = f"{BASE}_sim_{uuid.uuid4().hex[:8]}"
    db().select_graph(BASE).copy(name); sim = db().select_graph(name)
    try:
        apply(sim, action); after = paths(sim)
    finally:
        sim.delete()
    keep = {p["id"] for p in after}
    return {"action": action, "removed": [p for p in before if p["id"] not in keep], "remaining": after, "before": before,
            "risk_before": round(sum(p["score"] for p in before), 1), "risk_after": round(sum(p["score"] for p in after), 1)}
def candidates():
    g = db().select_graph(BASE)
    c = [r[0] for r in q(g, "MATCH (c:Component)-[:HAS_VULNERABILITY]->() RETURN DISTINCT c.id")]
    sv = [r[0] for r in q(g, "MATCH (s:Service) RETURN s.id")]
    return [f"patch:{x}" for x in c] + [f"isolate:{x}" for x in sv]
def recommend():
    global _REC
    if _REC is not None: return _REC
    r = [simulate(a) for a in candidates()]
    out = sorted([{"action": x["action"], "paths_removed": len(x["removed"]), "risk_reduction": round(x["risk_before"] - x["risk_after"], 1)} for x in r],
                 key=lambda x: (-x["risk_reduction"], 0 if x["action"].startswith("patch") else 1, x["action"]))
    if out: out[0]["recommended"] = True
    _REC = out
    return out

@app.get("/")
def home(): return FileResponse(os.path.join(os.path.dirname(__file__), "static", "index.html"))
@app.get("/api/health")
def health():
    try: db().connection.ping(); return {"status": "ok", "falkordb": True}
    except Exception as e: raise HTTPException(503, f"FalkorDB unreachable: {e}")
@app.post("/api/seed")
def do_seed(): seed(); return {"seeded": True, "environment": "synthetic"}
def ensure():
    g = db().select_graph(BASE)
    try: empty = q(g, "MATCH (n) RETURN count(n)")[0][0] == 0
    except Exception: empty = True
    return seed() if empty else g
@app.get("/api/graph")
def graph():
    g = ensure()
    n = q(g, "MATCH (n) WHERE n.id IS NOT NULL RETURN n.id, n.name, labels(n)[0], n.cvss, n.source, n.sensitivity")
    e = q(g, "MATCH (a)-[r]->(b) RETURN a.id, type(r), b.id")
    co = q(g, "MATCH (c:Company) RETURN c.name, c.desc")
    return {"company": ({"name": co[0][0], "desc": co[0][1]} if co else {"name": "Demo", "desc": ""}), "nodes": [dict(id=a, name=b, label=c, cvss=d, source=s, sensitivity=z) for a, b, c, d, s, z in n],
            "edges": [dict(a=a, type=t, b=b) for a, t, b in e]}
@app.get("/api/paths")
def get_paths():
    g = ensure(); LOG.clear(); p = paths(g); return {"paths": p, "queries": list(dict.fromkeys(LOG))}
class Sim(BaseModel): action: str
@app.post("/api/simulate")
def sim(b: Sim):
    ensure()
    if b.action not in candidates(): raise HTTPException(400, "unknown action")
    LOG.clear(); r = simulate(b.action); r["queries"] = list(dict.fromkeys(LOG)); return r
@app.get("/api/recommend")
def rec(): ensure(); return {"ranking": recommend()}
@app.get("/api/sample")
def sample(): return DEFAULT
@app.post("/api/import")
def do_import(d: dict = Body(...)):
    seed(data=validate(d)); return {"imported": True}
class Ask(BaseModel):
    question: str | None = None
    action: str | None = None
def _slim(ps): return [{"id": p["id"], "score": p["score"], "severity": p["severity"], "findings": p["findings"]} for p in ps]
def tool_impl():
    def find_attack_paths(): return _slim(paths(db().select_graph(BASE)))
    def simulate_fix(action):
        if action not in candidates(): raise ValueError("unknown action")
        r = simulate(action)
        return {"action": action, "removed": [p["id"] for p in r["removed"]], "remaining": _slim(r["remaining"]),
                "risk_before": r["risk_before"], "risk_after": r["risk_after"]}
    return {"find_attack_paths": find_attack_paths, "simulate_fix": simulate_fix, "recommend_fixes": recommend}
@app.post("/api/analyst")
async def analyst(b: Ask):
    ensure(); LOG.clear()
    q_ = b.question or "What is my riskiest attack path and what should I fix first?"
    if b.action: q_ += f" (The user is currently looking at the simulation of {b.action}.)"
    try: res = await run_agent(q_, tool_impl(), candidates())
    except Exception as e: res = {"answer": f"Agent error: {e}", "trace": []}
    if res is None:
        top = recommend()[0]
        return {"explanation": f"No GROQ_API_KEY set, so this is the deterministic summary. {len(paths(db().select_graph(BASE)))} candidate paths. "
                f"Best fix: {top['action']} (removes {top['paths_removed']} paths, risk -{top['risk_reduction']}). Candidate paths are not proof of exploitability; data is synthetic.",
                "llm": False, "trace": [], "queries": list(dict.fromkeys(LOG))}
    return {"explanation": res["answer"], "llm": True, "trace": res["trace"], "queries": list(dict.fromkeys(LOG))}
