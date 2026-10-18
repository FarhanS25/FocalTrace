import os
from flask import Flask, render_template, request, redirect, url_for, flash
from falkordb import FalkorDB

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'local-demo-only-change-me')
GRAPH_NAME = os.getenv('FALKORDB_GRAPH', 'FocalTrace')

SEED = [
    ("Asset", "payments-api", {"criticality": 10, "kind": "Service", "description": "Handles payment authorization"}),
    ("Asset", "customer-db", {"criticality": 10, "kind": "Database", "description": "Stores customer and payment records"}),
    ("Asset", "identity-gateway", {"criticality": 9, "kind": "Service", "description": "Issues service identity tokens"}),
    ("Asset", "build-runner", {"criticality": 7, "kind": "Compute", "description": "Runs CI jobs and deployment scripts"}),
    ("Asset", "metrics-node", {"criticality": 3, "kind": "Compute", "description": "Internal metrics collector"}),
    ("Asset", "docs-portal", {"criticality": 2, "kind": "Web App", "description": "Internal documentation portal"}),
]

# Synthetic, illustrative data only. Relationships intentionally form multi-hop attack paths.
EDGES = [
    ("build-runner", "CAN_DEPLOY_TO", "payments-api"),
    ("payments-api", "CONNECTS_TO", "customer-db"),
    ("metrics-node", "HAS_CREDENTIALS_FOR", "identity-gateway"),
    ("identity-gateway", "CAN_AUTHENTICATE_TO", "payments-api"),
    ("docs-portal", "READS_SECRETS_FROM", "build-runner"),
    ("build-runner", "CAN_ASSUME_ROLE_FOR", "identity-gateway"),
]
FINDINGS = [
    ("F-101", "Exposed CI secret", "HIGH", "build-runner", "A synthetic CI token is readable by a documentation integration."),
    ("F-102", "Over-privileged service identity", "HIGH", "identity-gateway", "Service identity can authenticate to a critical payment service."),
    ("F-103", "Sensitive database reachable", "CRITICAL", "customer-db", "Customer database is reachable from the payment service."),
    ("F-104", "Weakly isolated telemetry host", "MEDIUM", "metrics-node", "Telemetry host retains credentials for an identity service."),
]


def connect():
    return FalkorDB(host=os.getenv('FALKORDB_HOST', 'localhost'), port=int(os.getenv('FALKORDB_PORT', '6379'))).select_graph(GRAPH_NAME)


def run_query(graph, query, params=None):
    result = graph.query(query, params or {})
    return result.result_set


def initialize_graph():
    graph = connect()
    # Idempotent seed: clear only this application's named graph, then create demo data.
    graph.query('MATCH (n) DETACH DELETE n')
    for label, name, props in SEED:
        graph.query(f'CREATE (n:{label} {{name: $name, criticality: $criticality, kind: $kind, description: $description}})', {
            'name': name, 'criticality': props['criticality'], 'kind': props['kind'], 'description': props['description']})
    for source, relation, target in EDGES:
        # Relationship types are constants from this source file, not user input.
        graph.query(f'MATCH (a:Asset {{name: $source}}), (b:Asset {{name: $target}}) CREATE (a)-[:{relation}]->(b)', {'source': source, 'target': target})
    for fid, title, severity, asset, details in FINDINGS:
        graph.query('MATCH (a:Asset {name: $asset}) CREATE (f:Finding {id: $id, title: $title, severity: $severity, details: $details})-[:AFFECTS]->(a)', {
            'asset': asset, 'id': fid, 'title': title, 'severity': severity, 'details': details})
    return graph


def get_dashboard(graph):
    counts = run_query(graph, 'MATCH (n) RETURN labels(n)[0] AS label, count(n) AS total')
    assets = run_query(graph, 'MATCH (a:Asset) RETURN a.name, a.kind, a.criticality, a.description ORDER BY a.criticality DESC')
    findings = run_query(graph, 'MATCH (f:Finding)-[:AFFECTS]->(a:Asset) RETURN f.id, f.title, f.severity, a.name, f.details ORDER BY CASE f.severity WHEN "CRITICAL" THEN 0 WHEN "HIGH" THEN 1 WHEN "MEDIUM" THEN 2 ELSE 3 END')
    return counts, assets, findings


def investigate(graph, asset_name, depth):
    # Variable-length traversal makes FalkorDB central: the app reports actual connected attack paths.
    rows = run_query(graph, '''MATCH p=(start:Asset {name: $asset})-[:CAN_DEPLOY_TO|CONNECTS_TO|CAN_AUTHENTICATE_TO|HAS_CREDENTIALS_FOR|CAN_ASSUME_ROLE_FOR|READS_SECRETS_FROM*1..4]-(target:Asset)
        WHERE start <> target
        RETURN [n IN nodes(p) | n.name] AS path, length(p) AS hops, target.name AS target,
               target.criticality AS criticality, target.kind AS kind
        ORDER BY criticality DESC, hops ASC LIMIT 30''', {'asset': asset_name})
    affected = run_query(graph, '''MATCH (start:Asset {name: $asset})-[:CAN_DEPLOY_TO|CONNECTS_TO|CAN_AUTHENTICATE_TO|HAS_CREDENTIALS_FOR|CAN_ASSUME_ROLE_FOR|READS_SECRETS_FROM*0..4]-(a:Asset)
        WITH DISTINCT a
        OPTIONAL MATCH (f:Finding)-[:AFFECTS]->(a)
        RETURN a.name AS asset, a.criticality AS criticality, a.kind AS kind,
               collect(DISTINCT f.title) AS findings
        ORDER BY criticality DESC''', {'asset': asset_name})
    return rows, affected

@app.route('/', methods=['GET'])
def index():
    try:
        graph = connect()
        counts, assets, findings = get_dashboard(graph)
        names = [row[0] for row in assets]
        selected = request.args.get('asset', names[0] if names else 'payments-api')
        depth = min(4, max(1, int(request.args.get('depth', '4'))))
        paths, affected = investigate(graph, selected, depth)
        # The traversal query uses a maximum depth of four; filter longer paths in the display.
        paths = [r for r in paths if r[1] <= depth]
        return render_template('index.html', counts=counts, assets=assets, findings=findings,
                               selected=selected, depth=depth, paths=paths, affected=affected, graph_name=GRAPH_NAME)
    except Exception as exc:
        return render_template('setup.html', error=str(exc), graph_name=GRAPH_NAME), 503

@app.route('/seed', methods=['POST'])
def seed():
    try:
        initialize_graph()
        flash('Synthetic demo graph seeded successfully.', 'success')
    except Exception as exc:
        flash(f'Could not seed graph: {exc}', 'error')
    return redirect(url_for('index'))

@app.route('/health')
def health():
    try:
        graph = connect()
        row = graph.query('RETURN 1 AS ok').result_set
        return {'status': 'ok', 'graph': GRAPH_NAME, 'database_check': row[0][0]}
    except Exception as exc:
        return {'status': 'error', 'detail': str(exc)}, 503

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', '5000')), debug=False)
