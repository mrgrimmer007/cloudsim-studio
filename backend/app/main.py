import json
import os
import sqlite3
from contextlib import closing
from typing import Literal

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from .engine import api_request, simulate
from .security import analyze

app = FastAPI(title="CloudSim Studio API", version="0.3.0")


class Node(BaseModel):
    id: str
    type: Literal["internet", "waf", "apigw", "lb", "vm", "db"]
    name: str
    x: float = 0
    y: float = 0
    failed: bool = False
    c: dict = {}


class Edge(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    from_: str = Field(alias="from")
    to: str


class Arch(BaseModel):
    nodes: list[Node]
    edges: list[Edge]


class SaveReq(BaseModel):
    name: str = Field(max_length=100)
    model: Arch


def conn():
    d = os.getenv("DATA_DIR", ".")
    os.makedirs(d, exist_ok=True)
    c = sqlite3.connect(os.path.join(d, "cloudsim.db"))
    c.execute("CREATE TABLE IF NOT EXISTS arch(id INTEGER PRIMARY KEY, name TEXT, model TEXT, created TEXT DEFAULT CURRENT_TIMESTAMP)")
    return c


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.post("/api/analyze")
def analyze_ep(m: Arch):
    return analyze([n.model_dump() for n in m.nodes], [e.model_dump(by_alias=True) for e in m.edges])


@app.post("/api/architectures")
def save(r: SaveReq):
    with closing(conn()) as c:
        cur = c.execute("INSERT INTO arch(name, model) VALUES (?, ?)", (r.name, json.dumps(r.model.model_dump(by_alias=True))))
        c.commit()
        return {"id": cur.lastrowid}


@app.get("/api/architectures")
def list_all():
    with closing(conn()) as c:
        rows = c.execute("SELECT id, name, created FROM arch ORDER BY id DESC LIMIT 50").fetchall()
    return [{"id": i, "name": n, "created": t} for i, n, t in rows]


@app.get("/api/architectures/{aid}")
def get_one(aid: int):
    with closing(conn()) as c:
        row = c.execute("SELECT model FROM arch WHERE id=?", (aid,)).fetchone()
    if not row:
        raise HTTPException(404, "Not found")
    return json.loads(row[0])


class ReqBody(BaseModel):
    model: Arch
    method: str = "GET"
    token: bool = False


def plain(m: Arch):
    return [n.model_dump() for n in m.nodes], [e.model_dump(by_alias=True) for e in m.edges]


@app.post("/api/simulate")
def simulate_ep(m: Arch):
    return simulate(*plain(m))


@app.post("/api/request")
def request_ep(b: ReqBody, req: Request):
    key = req.headers.get("x-real-ip") or (req.client.host if req.client else "local")
    return api_request(*plain(b.model), b.method.upper(), b.token, key)
