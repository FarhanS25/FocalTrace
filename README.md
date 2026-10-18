# FocalTrace — Graph-Powered Security Investigation

**Track:** Agents That Act on Connected Data  
**Built for:** WeMakeDevs × FalkorDB Graph Hacks, October 2026

FocalTrace investigates synthetic infrastructure by traversing connected assets in FalkorDB. It surfaces multi-hop paths from a starting asset to high-criticality services, links findings to affected assets, and presents the evidence path behind each result. The graph is the operational source of truth: the traversal and exposure summary are Cypher queries executed against FalkorDB, not a static visualization or an LLM-generated guess.

> **Data notice:** All assets, findings, and relationships included here are synthetic demo data. Do not interpret the demo as a real security assessment.

## Features
- Interactive investigation by starting asset and traversal depth (1–4 hops).
- Multi-hop path traversal over deployment, authentication, credential, and service-dependency relationships.
- Exposure summary with connected findings and asset criticality.
- Synthetic finding cards with severity and affected asset.
- FalkorDB-backed health endpoint at `/health`.
- Browser UI designed for a quick live demo; no LLM/API key required for the deterministic investigation workflow.

## Architecture

`Browser → Flask UI → fixed parameterized Cypher queries → FalkorDB graph`

FalkorDB is not optional decoration: path discovery, connected exposure summary, asset records, findings, and relationship evidence are read from the graph. If FalkorDB is unavailable, the application displays a setup/error page instead of silently falling back to a local list.

## Graph data model

### Nodes
- `(:Asset {name, criticality, kind, description})`
- `(:Finding {id, title, severity, details})`

### Relationships
- `(:Asset)-[:CAN_DEPLOY_TO]->(:Asset)`
- `(:Asset)-[:CONNECTS_TO]->(:Asset)`
- `(:Asset)-[:CAN_AUTHENTICATE_TO]->(:Asset)`
- `(:Asset)-[:HAS_CREDENTIALS_FOR]->(:Asset)`
- `(:Asset)-[:CAN_ASSUME_ROLE_FOR]->(:Asset)`
- `(:Asset)-[:READS_SECRETS_FROM]->(:Asset)`
- `(:Finding)-[:AFFECTS]->(:Asset)`

The demo seeds six assets, four findings, and six infrastructure relationships. One important multi-hop chain is `docs-portal → build-runner → identity-gateway → payments-api → customer-db` (relationship directions can vary in the investigator because it searches connectivity in either direction).

## Run locally

Prerequisites: Python 3.10+ and Docker Desktop.

```bash
docker compose up -d
python -m venv .venv
# Windows PowerShell:
.venv\Scripts\Activate.ps1
# macOS/Linux:
source .venv/bin/activate
pip install -r requirements.txt
python -c "from app import initialize_graph; initialize_graph()"
python app.py
```

Open `http://127.0.0.1:5000`. FalkorDB Browser is available at `http://127.0.0.1:3000`.

If FalkorDB runs elsewhere, set `FALKORDB_HOST`, `FALKORDB_PORT`, and optionally `FALKORDB_GRAPH`. Do not expose the database port publicly without access controls.

## Important Cypher queries

### 1. Multi-hop connected-path discovery

```cypher
MATCH p=(start:Asset {name: $asset})-[:CAN_DEPLOY_TO|CONNECTS_TO|CAN_AUTHENTICATE_TO|HAS_CREDENTIALS_FOR|CAN_ASSUME_ROLE_FOR|READS_SECRETS_FROM*1..4]-(target:Asset)
WHERE start <> target
RETURN [n IN nodes(p) | n.name] AS path,
       length(p) AS hops,
       target.name AS target,
       target.criticality AS criticality,
       target.kind AS kind
ORDER BY criticality DESC, hops ASC
LIMIT 30
```

This is the core product query. Changing the traversal depth changes which connected assets are discoverable; the path returned is the evidence shown to the user.

### 2. Connected exposure summary

```cypher
MATCH (start:Asset {name: $asset})-[:CAN_DEPLOY_TO|CONNECTS_TO|CAN_AUTHENTICATE_TO|HAS_CREDENTIALS_FOR|CAN_ASSUME_ROLE_FOR|READS_SECRETS_FROM*0..4]-(a:Asset)
WITH DISTINCT a
OPTIONAL MATCH (f:Finding)-[:AFFECTS]->(a)
RETURN a.name AS asset, a.criticality AS criticality, a.kind AS kind,
       collect(DISTINCT f.title) AS findings
ORDER BY criticality DESC
```

### 3. Finding-to-asset evidence

```cypher
MATCH (f:Finding)-[:AFFECTS]->(a:Asset)
RETURN f.id, f.title, f.severity, a.name, f.details
```

## Demo script (60–90 seconds)
1. Open the dashboard and point out that assets and findings are loaded from FalkorDB.
2. Investigate `docs-portal` at depth 1, then at depth 4. Explain how deeper graph traversal exposes connected high-criticality infrastructure.
3. Select `build-runner` and show the path to `payments-api` and `customer-db`.
4. Show the exposure summary and the finding cards; explain that each finding is connected to its affected asset in the graph.
5. Open `/health` and, if possible, FalkorDB Browser on port 3000 to show the database is running.

## Limitations and next steps
- This is a deterministic graph investigator, not an autonomous remediation agent. It recommends containment and credential rotation but does not modify infrastructure.
- Demo graph and severities are synthetic and not validated against a real environment.
- A production version should add authenticated access, tenant isolation, audit logs, asset ingestion, edge provenance, severity calibration, and human approval for actions.
- The UI uses a simple graph-path list rather than a node-link canvas to keep the MVP robust under hackathon time constraints.

## AI assistance disclosure
AI coding assistance was used to accelerate scaffolding and documentation. The submitting participant should run the project, verify the behavior, understand the graph model and queries, and make meaningful edits before submission, consistent with the hackathon rules.

## License
MIT — see `LICENSE`.
