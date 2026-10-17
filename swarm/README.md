# PS5 Kernel Exploit Swarm

100-agent autonomous system for PS5 14.10 kernel exploit research.

## Quick Start

```bash
# Set your API key (or use OpenCode Zen free tier)
set ANTHROPIC_API_KEY=sk-ant-...

# Launch all 100 agents
swarm\launch.bat

# Or from Python directly
python swarm\swarm.py --agents 100

# Monitor in another terminal
python swarm\dashboard.py
```

## Architecture

```
100 AGENTS
├── Research Wing (40 agents)
│   ├── FreeBSD CVE Hunters (8) — search for applicable CVEs
│   ├── Kernel Source Readers (8) — analyze FreeBSD kernel code
│   ├── Exploit Technique Researchers (6) — study known techniques
│   ├── Syscall Analysts (6) — analyze syscall behavior
│   ├── Hardware Researchers (4) — GPU/memory controller angles
│   ├── Academic Paper Readers (4) — academic exploitation research
│   └── Sony Patch Diffing (4) — find incomplete patches
│
├── Probe Engineering Wing (25 agents)
│   ├── Syscall Probe Writers (5)
│   ├── Network Probe Writers (5)
│   ├── Memory Probe Writers (5)
│   ├── KASLR Probe Writers (5)
│   └── Creative Probe Writers (5)
│
├── Execution Wing (10 agents)
│   ├── Probe Runners (2) — serial queue to PS5
│   ├── Result Analyzers (4) — parse output for leads
│   ├── Crash Analysts (2) — analyze crashes
│   └── Regression Testers (2) — re-run promising probes
│
├── Strategy Wing (15 agents)
│   ├── Strategists (3) — high-level direction
│   ├── Dead End Validators (3) — re-examine dead ends
│   ├── Cross Pollinators (3) — combine findings
│   ├── Novelty Detectors (3) — deduplicate
│   └── Priority Rankers (3) — order the queue
│
└── Infrastructure Wing (10 agents)
    ├── Documentors (3) — update FINDINGS.md etc.
    ├── Git Manager (1) — auto-commit every 10 min
    ├── Health Monitors (2) — PS5 connectivity
    ├── PC Network Attackers (2) — scapy from PC
    └── Coordinators (2) — orchestration
```

## Scaling

```bash
# Run with fewer agents (proportionally scaled)
python swarm\swarm.py --agents 10   # 10% scale
python swarm\swarm.py --agents 50   # 50% scale

# Dry run (no probes sent to PS5)
python swarm\swarm.py --dry-run
```

## Files

- `swarm.py` — main orchestrator
- `config.py` — all configuration (models, timing, paths)
- `agents.py` — all 100 agent implementations
- `agent_base.py` — base agent class
- `task_queue.py` — thread-safe priority queue with persistence
- `ps5_connection.py` — PS5 probe sender with health monitoring
- `ai_client.py` — OpenCode Zen / Anthropic API wrapper
- `dashboard.py` — live terminal monitoring
- `launch.bat` — Windows launcher
