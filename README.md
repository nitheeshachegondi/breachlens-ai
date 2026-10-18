# BreachLens AI
Attack-path analysis and what-if remediation for small SaaS companies, built on **FalkorDB**. Hackathon: Graph Hacks (WeMakeDevs x FalkorDB). **Track 01: Agents That Act on Connected Data.**
Data is a clearly labelled **synthetic** SaaS environment. CVE-2021-44228 and CVE-2022-22965 are public NVD records; `SYN-2026-001` is invented.

## Run
**Step 0, get FalkorDB (the graph database):**
```
docker pull falkordb/falkordb:latest
```
`docker-compose.yml` already uses this image (`falkordb` service), so `docker compose up` pulls it for you. To run FalkorDB alone and the app without Docker:
```
docker run -p 6379:6379 -p 3000:3000 --rm falkordb/falkordb:latest
pip install -r requirements.txt
uvicorn app.main:app --port 8000
```
**Full stack:**
```
cp .env.example .env       # set GROQ_API_KEY
docker compose up --build  # app: http://localhost:8000   FalkorDB Browser: http://localhost:3000
pip install -r requirements.txt && pytest   # needs FalkorDB on localhost:6379
```
## Graph model
Nodes: `Internet`, `Service`, `Component`, `Vulnerability`, `Sensitive`. Edges: `EXPOSES`, `CONNECTS_TO`, `CAN_ACCESS` (reachability), `DEPENDS_ON`, `HAS_VULNERABILITY`.
## Why FalkorDB is essential
Path discovery is one multi-hop traversal. What-if copies the graph, deletes edges, and re-runs the same traversal. Remove FalkorDB and there is no product.
## Key Cypher (see `app/main.py`)
```
MATCH p=(:Internet)-[:EXPOSES|CONNECTS_TO|CAN_ACCESS*1..6]->(s:Sensitive) RETURN [n IN nodes(p) | n.id], s.sensitivity, length(p)
MATCH (s:Service)-[:DEPENDS_ON]->(c:Component)-[:HAS_VULNERABILITY]->(v:Vulnerability) RETURN s.id, c.id, v.id, v.name, v.cvss, v.source
MATCH (:Component {id:$t})-[r:HAS_VULNERABILITY]->() DELETE r   // patch simulation, on a copy
```
Fix ranking = every candidate fix simulated on a graph copy, sorted by risk removed.
## Limits
Reachability + a known weakness = candidate path, not proof of exploitability. The agent (Groq, openai/gpt-oss-120b) can only call three graph tools: find_attack_paths, simulate_fix, recommend_fixes.
## AI disclosure
Built with Claude (Anthropic) as a coding assistant; the runtime agent uses Groq-hosted gpt-oss; the author reviews and is responsible for the code.

## Demo company and how it is used
The demo is **LedgerLoop**, a fictional invoicing/payouts SaaS. A security team normally gets separate reports (scanner, dependency alerts, asset inventory). BreachLens joins them into one FalkorDB graph, finds Internet-to-sensitive-data paths, ranks them, simulates fixes on a graph copy, and lets an agent answer "what should we fix first?".
To use it on another company, download `/api/sample` (also `sample_inventory.json`), replace the services, components, vulnerabilities, sensitive resources and edges, and click **Import JSON**. Allowed edge types: EXPOSES, CONNECTS_TO, CAN_ACCESS, DEPENDS_ON, HAS_VULNERABILITY.