# BreachLens AI

**See the road an attacker would take. Break it with one fix.**

BreachLens AI joins scanner, dependency and asset data into a **FalkorDB** graph, finds every route from the Internet to sensitive data, scores each route, simulates fixes on a copy of the graph, and lets an AI agent answer "what should we fix first?" using real graph queries.

Built for **FalkorDB Graph Hacks (WeMakeDevs)** · **Track 01: Agents That Act on Connected Data**

- Live demo: https://breachlens-ai.vercel.app/
- Demo video: https://youtu.be/LjgX5SUQB4g
- Blog post: https://nitheeshachegondi.substack.com/p/i-patched-the-scariest-bug-first?r=3yw0g6

> All data is **synthetic**. The demo company, LedgerLoop, is fictional. CVE-2021-44228 and CVE-2022-22965 are public NVD records; `SYN-2026-001` is invented.

## The problem

Security teams get separate lists: vulnerability scans, dependency alerts, asset inventories. None shows how findings connect, or which single fix would cut off an attacker. Teams patch the highest CVSS first, and sometimes nothing changes.

**Demo result:** patching the scariest-sounding bug (Spring4Shell, CVSS 9.8) leaves all 3 attack paths open. Patching log4j closes 2 of 3 and cuts total risk from 27.6 to 9.3 (about 66%).

## Features

- **Attack path explorer:** animated graph, internet to services to sensitive data, with known weaknesses marked and the selected path highlighted.
- **Transparent scoring:** `score = 0.6 × max CVSS + 0.3 × data sensitivity + 0.1 × (10 − 2 × hops)`. Weights are in code and easy to change.
- **What-if remediation:** patch a component or isolate a service. The change is applied to a **copy** of the graph, paths are recomputed, and before and after are compared. The real graph is never modified.
- **Fix ranking:** every candidate fix is simulated and ranked by risk removed.
- **AI analyst agent:** an LLM that can only call graph tools. Answers show the tool calls and the Cypher that ran.
- **Bring your own data:** import an inventory as JSON (`sample_inventory.json` shows the format).

## Graph data model

| Node label | Properties | Meaning |
|---|---|---|
| `Internet` | id, name | The public entry point |
| `Service` | id, name | A running service |
| `Component` | id, name | A software dependency |
| `Vulnerability` | id, name, cvss, source | A known weakness |
| `Sensitive` | id, name, sensitivity | Data or secrets worth protecting |
| `Company` | name, desc | Scenario metadata |

| Relationship | Meaning |
|---|---|
| `EXPOSES` | Internet can reach this service |
| `CONNECTS_TO` | One service can call another |
| `CAN_ACCESS` | A service can read sensitive data |
| `DEPENDS_ON` | A service uses a component |
| `HAS_VULNERABILITY` | A component has a known weakness |

Every edge has a defensible meaning. A path is only an attack-path **candidate** if it reaches sensitive data and has at least one known weakness along it.

## Key Cypher queries

Full source: [`app/main.py`](app/main.py).

```cypher
// 1. Discover every route from the Internet to sensitive data
MATCH p=(:Internet)-[:EXPOSES|CONNECTS_TO|CAN_ACCESS*1..6]->(s:Sensitive)
RETURN [n IN nodes(p) | n.id], s.sensitivity, length(p)

// 2. Attach weaknesses to services
MATCH (s:Service)-[:DEPENDS_ON]->(c:Component)-[:HAS_VULNERABILITY]->(v:Vulnerability)
RETURN s.id, c.id, v.id, v.name, v.cvss, v.source

// 3. Patch simulation (runs on a graph copy)
MATCH (:Component {id:$t})-[r:HAS_VULNERABILITY]->() DELETE r

// 4. Isolate simulation (runs on a graph copy)
MATCH (:Service {id:$t})-[r:EXPOSES|CONNECTS_TO|CAN_ACCESS]-() DELETE r
```

## How FalkorDB is used

1. **Multi-hop traversal** with variable-length relationships of several types finds all attack paths in one query.
2. **Graph copy** (`GRAPH.COPY`) creates a throwaway sandbox for each what-if. Changes are applied to the copy, the traversal is re-run, and the copy is deleted.
3. **Ranking** repeats the copy-and-recompute step for every candidate fix.
4. **The agent's tools** (`find_attack_paths`, `simulate_fix`, `recommend_fixes`) are thin wrappers over those queries.

Without FalkorDB there is no product: path discovery and fix simulation are both graph queries.

## Run locally

Requirements: Docker Desktop.

```bash
docker pull falkordb/falkordb:latest
cp .env.example .env        # Windows: copy .env.example .env
# optional: add GROQ_API_KEY to .env to enable the agent
docker compose up --build
```

- App: http://localhost:8000
- Health check: http://localhost:8000/api/health
- FalkorDB Browser: http://localhost:3000 (graph name `breachlens`)

`docker-compose.yml` forces local FalkorDB settings, so Cloud credentials in `.env` cannot break a local run. Without a `GROQ_API_KEY`, the analyst returns a deterministic evidence summary instead of an LLM answer.

Without Docker for the app:

```bash
docker run -p 6379:6379 -p 3000:3000 --rm falkordb/falkordb:latest
pip install -r requirements.txt
uvicorn app.main:app --port 8000
```

## Tests

```bash
pytest
```

The tests need FalkorDB on `localhost:6379` and skip if it isn't running. They check that 3 paths are found, that patching log4j closes 2 and leaves 1, that a simulation does not change the real graph, and that patching Spring alone leaves all 3 paths open.

## Environment variables

| Variable | Purpose |
|---|---|
| `GROQ_API_KEY` | Enables the LLM agent (optional) |
| `GROQ_MODEL` | Default `openai/gpt-oss-120b` |
| `FALKORDB_HOST`, `FALKORDB_PORT` | Database address |
| `FALKORDB_USERNAME`, `FALKORDB_PASSWORD` | Needed for FalkorDB Cloud |
| `FALKORDB_SSL` | `1` to prefer TLS. The app tries the other mode automatically if the first fails |

Never commit `.env`. It is listed in `.gitignore`.

## Deploy (Vercel + FalkorDB Cloud)

Vercel cannot run FalkorDB, so use a FalkorDB Cloud instance.

1. Create a free instance at app.falkordb.cloud and copy the endpoint (`host:port`), username and password from the Connectivity and Instance Details tabs.
2. Push this repo to GitHub and import it in Vercel. `pyproject.toml` sets the entrypoint to `app.main:app`.
3. Add the environment variables above in **Settings → Environment Variables** (Production), then redeploy.
4. Open `/api/health`. A good result is `{"status":"ok","falkordb":true}`. The first page load seeds the graph.

## API

| Endpoint | Purpose |
|---|---|
| `GET /api/health` | Database connectivity |
| `GET /api/graph` | Nodes, edges and company info |
| `GET /api/paths` | Attack paths with scores, evidence and queries run |
| `POST /api/simulate` | What-if for `{"action": "patch:log4j-core"}` |
| `GET /api/recommend` | Ranked fixes |
| `POST /api/analyst` | Agent answer with tool trace |
| `GET /api/sample`, `POST /api/import` | Sample inventory and import |
| `POST /api/seed` | Reset to the demo company |

## Project structure

```
app/main.py          FastAPI app, graph model, queries, scoring, simulation
app/agent.py         Tool-calling agent (Groq, OpenAI-compatible API)
app/static/index.html  Web UI
tests/               pytest tests
sample_inventory.json  Example import file
docker-compose.yml, Dockerfile, pyproject.toml, requirements.txt
```

## Limits and honesty

- A graph path plus a known weakness is a **candidate** attack path, not proof of exploitability. The UI, the agent and this README say so.
- The risk score is a transparent heuristic, not a prediction of attacks.
- Nothing is exploited, scanned or changed in a real environment. Simulations run only on a copy of the graph.
- The demo uses synthetic data and a fictional company.
- Not yet built: investigation history across snapshots, and importers for real scanner or SBOM formats.

## Hackathon criteria mapping

| Requirement | Where it is addressed |
|---|---|
| Meaningful FalkorDB use | Path discovery, graph copy for what-if, fix ranking |
| Agent acting on connected data | Tool-calling agent over graph queries, with visible trace |
| Explainable results | Evidence panel, scoring formula, Cypher shown in the UI |
| Setup instructions and data model | Sections above |
| Public repo, demo video, deployment | Links at the top |

## AI disclosure

This project was built with AI assistance: Claude (Anthropic) as a coding assistant, and a Groq-hosted open model (`gpt-oss-120b`) for the in-app agent. I reviewed the code and can explain the graph model and every query.
