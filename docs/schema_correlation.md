# RedTeam V6 — Schema Correlation Audit

All four layers use consistent field names. This document records the verified mapping.

## Attack DAG Nodes

| Field | SQLite (causal_nodes) | Neo4j property | MCP /dag/session_data | DAG UI (dag_ui.html) |
|-------|-----------------------|----------------|----------------------|----------------------|
| node identifier | node_id | node_id | node_id | n.node_id → vis id |
| session scope | session_id | session_id | session_id | session_id param |
| node class | node_type | (Neo4j label) | node_type | n.node_type |
| display name | label | label | label | n.label |
| detail text | description | description | description | n.description |
| ml score | confidence | confidence | confidence | n.confidence |
| risk level | severity | — | severity | n.severity |

## Thinking DAG Nodes

| Field | SQLite (thinking_nodes) | Neo4j property | MCP /dag/session_data | DAG UI |
|-------|-------------------------|----------------|----------------------|--------|
| node identifier | node_id | node_id | node_id | n.node_id → vis id |
| session scope | session_id | session_id | session_id | — |
| reasoning text | thought_text | thought_text | thought_text | n.thought_text |
| bayesian score | confidence | confidence | confidence | n.confidence |
| uncertainty | entropy | entropy | entropy | n.entropy |
| mcts value | mcts_score | mcts_score | mcts_score | n.mcts_score |
| phase state | status | status | status | n.status |

## Edges

| Field | SQLite (causal_edges) | Neo4j | MCP output | DAG UI |
|-------|----------------------|-------|------------|--------|
| edge id | edge_id | — (relationship) | — | — |
| session scope | session_id | session_id on endpoints | session_id | — |
| origin node | source_id | MATCH (a {node_id: src}) | source_id | e.source_id |
| target node | target_id | MATCH (b {node_id: tgt}) | target_id | e.target_id |
| relationship | label | relationship type | label | e.label |

## MCTS State (via /dag/mcts_state)

| Field | BayesianMCTS.to_dict() | score_branches output | DAG UI mcts panel |
|-------|------------------------|----------------------|-------------------|
| branch | attack_type | attack_type | n.attack_type |
| times visited | visit_count | visit_count | n.visit_count |
| avg reward | confidence | confidence | n.confidence |
| uncertainty | entropy | entropy | n.entropy |
| bayesian prob | posterior_probability | posterior | n.posterior |

## Spec vs Implementation Notes

The build prompt spec used different column names for some tables. All layers were built
consistently using the names below — no cross-layer mismatches exist:

| Spec name | Actual name | Consistent across all layers? |
|-----------|-------------|-------------------------------|
| from_node | source_id | YES — all layers use source_id |
| to_node | target_id | YES — all layers use target_id |
| edge_type | label | YES — all layers use label |
| content (key_facts) | fact | YES — all layers use fact |
| scan_type | tool | YES — all layers use tool |

## Verification Status

- SQLite ↔ MCP output: VERIFIED (integration test Step 5, 8)
- Neo4j ↔ SQLite: VERIFIED (verify_sync.py, integration test Steps 1, 3, 4, 5)
- MCP output ↔ DAG UI: VERIFIED (integration test Step 8 — DAG UI reads nodes correctly)
- ThinkingNode Neo4j sync: FIXED (was missing, added in Phase 2)
