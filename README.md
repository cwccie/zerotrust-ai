# ZeroTrust-AI

**AI-Accelerated Zero Trust Architecture Platform**

[![CI](https://github.com/cwccie/zerotrust-ai/actions/workflows/ci.yml/badge.svg)](https://github.com/cwccie/zerotrust-ai/actions)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

ZeroTrust-AI brings machine learning to zero trust architecture — replacing static, rule-based security with continuous behavioral analytics, adaptive access control, and intelligent microsegmentation.

## The Problem

The zero trust security market is projected to reach **$22.6 billion** by 2027. The urgency is clear:

- **84%** of organizations experienced identity-related breaches in the past year
- **$4.45M** average cost of a data breach (IBM, 2023)
- **277 days** average time to identify and contain a breach
- **68%** of breaches involved a human element (Verizon DBIR)

Traditional perimeter security assumes internal traffic is trusted. **It is not.** Static access policies cannot adapt to the reality of compromised credentials, insider threats, and lateral movement.

## The AI Advantage

Static policies fail because threats are dynamic. ZeroTrust-AI uses behavioral analytics and graph neural networks to:

| Traditional Zero Trust | ZeroTrust-AI |
|----------------------|--------------|
| Binary allow/deny rules | Continuous risk-scored decisions |
| Authentication at login only | Continuous verification throughout session |
| Manual microsegmentation | AI-discovered communication clusters |
| Signature-based detection | Behavioral anomaly detection |
| Static privilege assignment | Dynamic, context-aware access |
| Manual policy tuning | Learned baselines + automated recommendations |

## Core Zero Trust Principles

ZeroTrust-AI implements all five pillars of zero trust:

1. **Never trust, always verify** — Every access request is evaluated against behavioral baselines, device health, network context, and threat intelligence
2. **Least privilege access** — The policy engine recommends minimum permissions based on observed access patterns
3. **Assume breach** — Lateral movement detection uses GNN analysis to find credential hopping, privilege escalation paths, and anomalous graph traversals
4. **Microsegmentation** — Flow analysis automatically discovers workload clusters and generates segment policies
5. **Continuous monitoring** — Trust scores degrade over time and are continuously re-evaluated

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        ZeroTrust-AI                             │
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │  Behavioral   │  │   Adaptive   │  │  Microsegmentation   │  │
│  │  Analytics    │  │   Access     │  │  Engine              │  │
│  │              │  │   Control    │  │                      │  │
│  │  • Baselines  │  │  • Risk-based│  │  • Flow analysis     │  │
│  │  • Anomaly    │──│    decisions │  │  • Cluster discovery  │  │
│  │  • Sessions   │  │  • Continuous│  │  • Policy recommend   │  │
│  │  • Patterns   │  │    verify   │  │  • Segment mgmt      │  │
│  └──────┬───────┘  └──────┬───────┘  └──────────┬───────────┘  │
│         │                 │                      │              │
│  ┌──────┴───────┐  ┌──────┴───────┐  ┌──────────┴───────────┐  │
│  │  Lateral      │  │    Risk      │  │  Policy Engine        │  │
│  │  Movement     │  │   Scoring    │  │                      │  │
│  │              │  │              │  │  • YAML policies      │  │
│  │  • GNN graph  │  │  • Composite │  │  • Simulation        │  │
│  │  • Cred hops  │──│    scoring  │──│  • Conflict detect    │  │
│  │  • Priv esc   │  │  • Threat    │  │  • Least privilege   │  │
│  │  • Embeddings │  │    intel    │  │    recommendations   │  │
│  └──────────────┘  └──────────────┘  └──────────────────────┘  │
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │  Identity     │  │  REST API    │  │  Web Dashboard        │  │
│  │  Registry     │  │  (Flask)     │  │  (Flask)             │  │
│  └──────────────┘  └──────────────┘  └──────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## Quickstart

### Install

```bash
pip install -e ".[dev]"
```

### Run the Demo

```bash
zerotrust-ai demo
```

This runs a complete scenario: identity setup, behavioral baseline learning, anomaly detection, risk scoring, access decisions, and lateral movement detection.

### Learn Baselines

```bash
zerotrust-ai baseline --events 1000 --entities 50
```

### Analyze an Event

```bash
zerotrust-ai analyze --entity user-001 --hour 3 --location unknown-region
```

### Detect Lateral Movement

```bash
zerotrust-ai detect --nodes 20 --edges 60
```

### Policy Management

```bash
# Interactive policy demo
zerotrust-ai policy

# Load from YAML
zerotrust-ai policy --file sample_data/policies.yaml
```

### Launch Dashboard

```bash
zerotrust-ai dashboard --host 127.0.0.1 --port 5000
```

### REST API

```bash
# Start API server
flask --app "zerotrust_ai.api.app:create_app()" run --port 8080

# Access decision
curl -X POST http://localhost:8080/api/v1/access/decide \
  -H "Content-Type: application/json" \
  -d '{"entity_id": "alice", "resource": "db-prod", "action": "read", "network_zone": "internal", "mfa_verified": true}'

# Risk score
curl -X POST http://localhost:8080/api/v1/risk/score \
  -H "Content-Type: application/json" \
  -d '{"entity_id": "bob", "behavior_score": 0.8, "device_health": 0.3}'
```

### Docker

```bash
docker-compose up -d
# API on :8080, Dashboard on :5000
```

## Module Overview

| Module | Description |
|--------|-------------|
| `behavioral/` | Behavioral analytics — baseline learning, anomaly detection, session analysis, pattern recognition |
| `access/` | Adaptive access control — risk-based decisions, continuous verification, context-aware policies |
| `microseg/` | Microsegmentation — flow analysis, cluster discovery, segment management, policy recommendations |
| `lateral/` | Lateral movement detection — GNN-based graph analysis, credential hopping, privilege escalation |
| `risk/` | Risk scoring — composite scores from behavior + device + network + threat intel + auth strength |
| `policy/` | Policy engine — YAML policies, simulation (what-if), conflict detection, least-privilege recommendations |
| `identity/` | Identity context — user/service/device registry, identity correlation, session tracking |
| `api/` | REST API — access decisions, risk queries, policy management, behavioral reports |
| `dashboard/` | Web dashboard — trust heatmap, risk timeline, lateral movement visualization, decision log |

## How It Works

### Behavioral Baselines

The behavioral engine learns per-entity statistical profiles using **online (streaming) algorithms** — no raw event storage required:

- **Time-of-day distributions** — When does this user normally work?
- **Resource access frequencies** — What does this user normally access?
- **Session duration statistics** — How long are normal sessions? (Welford's algorithm for running mean/variance)
- **Geographic patterns** — Where does this user normally connect from?
- **Entropy analysis** — How predictable is this user's behavior?

### GNN Lateral Movement Detection

The lateral movement detector uses a **two-layer graph neural network** (pure NumPy, no framework dependencies):

```
h_v' = ReLU(W_self · h_v + W_neigh · AGG(h_u : u ∈ N(v)) + b)
```

Node embeddings capture structural patterns. When access patterns change (new credential hops, new paths to high-value targets), embedding distances from the baseline reveal lateral movement.

### Composite Risk Scoring

Risk scores combine five weighted signals:

```
risk = w_b · behavior + w_d · (1 - device_health) + w_n · (1 - network_trust) + w_t · threat_intel + w_a · (1 - auth_strength)
```

Default weights: behavior=0.30, device=0.20, network=0.15, threat=0.20, auth=0.15

## Testing

```bash
# Run all tests
pytest

# With coverage
pytest --cov=zerotrust_ai --cov-report=term-missing

# Specific module
pytest tests/test_behavioral.py -v
```

## Project Structure

```
zerotrust-ai/
├── src/zerotrust_ai/
│   ├── behavioral/        # Behavioral analytics
│   ├── access/            # Adaptive access control
│   ├── microseg/          # Microsegmentation
│   ├── lateral/           # Lateral movement detection
│   ├── risk/              # Risk scoring
│   ├── policy/            # Policy engine
│   ├── identity/          # Identity registry
│   ├── api/               # REST API
│   ├── dashboard/         # Web dashboard
│   └── cli.py             # CLI interface
├── tests/                 # 50+ tests
├── sample_data/           # Synthetic data
├── pyproject.toml
├── Dockerfile
├── docker-compose.yml
└── README.md
```

## Author

**Corey A. Wade** — CISSP, CCIE #14124

- PhD candidate in AI + Security
- 20+ years in network security architecture
- Building at the intersection of AI and zero trust

## License

MIT — see [LICENSE](LICENSE)
