"""Swarm configuration — edit these values before launching."""

import os

# ── PS5 target ──
PS5_IP = "10.0.0.96"
PS5_PORT = 9026

# ── API Keys ──
# Option 1 (FREE): Get a free OpenRouter key at https://openrouter.ai/keys (no credit card)
#   Then: set OPENROUTER_API_KEY=sk-or-...
# Option 2 (PAID): Anthropic API key
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
OPENROUTER_API_KEY = os.environ.get("OPENROUTER_API_KEY", "")

# ── Models ──
# Using OpenCode Zen free tier models (zero cost, 24/7 viable)
# Best free: DeepSeek V4 Flash Free (smartest free option on Zen)
# Fallbacks: Big Pickle, Nemotron 3 Super Free
FAST_MODEL = "deepseek-v4-flash-free"
SMART_MODEL = "deepseek-v4-flash-free"
HAIKU_MODEL = "deepseek-v4-flash-free"

# If you have API keys and want to mix paid models in for critical roles:
# SMART_MODEL = "claude-opus-4-20250514"
# FAST_MODEL = "claude-sonnet-4-20250514"

# ── Agent allocation (100 total) ──
AGENT_COUNTS = {
    # ── Research wing (40 agents) ──
    "freebsd_cve_hunter": 8,        # search FreeBSD CVE databases, kernel changelogs
    "kernel_source_reader": 8,       # read FreeBSD kernel source for vuln patterns
    "exploit_technique_researcher": 6, # study known PS4/PS5/FreeBSD exploit techniques
    "syscall_analyst": 6,            # analyze syscall behavior, find untested patterns
    "hardware_researcher": 4,        # PS5 hardware, GPU, memory controller docs
    "academic_paper_reader": 4,      # academic papers on kernel exploitation
    "sony_patch_diffing": 4,         # compare firmware versions, find patched vulns

    # ── Probe engineering wing (25 agents) ──
    "probe_writer_syscall": 5,       # write probes targeting syscall attack surface
    "probe_writer_network": 5,       # write probes targeting network stack
    "probe_writer_memory": 5,        # write probes targeting memory/heap primitives
    "probe_writer_kaslr": 5,         # write probes specifically for KASLR defeat
    "probe_writer_creative": 5,      # creative/novel approaches, side channels, timing

    # ── Execution wing (10 agents) ──
    "probe_runner": 2,               # send probes to PS5, collect results (serial queue)
    "result_analyzer": 4,            # parse probe output, detect kernel ptrs, anomalies
    "crash_analyst": 2,              # analyze crashes, sandbox kills, interesting failures
    "regression_tester": 2,          # re-run probes that showed promise with variations

    # ── Strategy wing (15 agents) ──
    "strategist": 3,                 # high-level exploit strategy, attack tree maintenance
    "dead_end_validator": 3,         # re-examine dead ends with fresh eyes
    "cross_pollinator": 3,           # combine findings from different wings
    "novelty_detector": 3,           # identify genuinely new approaches vs repeats
    "priority_ranker": 3,            # rank all pending ideas by expected value

    # ── Infrastructure wing (10 agents) ──
    "documentor": 3,                 # keep FINDINGS.md, PROBE_INDEX.md, etc. current
    "git_manager": 1,                # commit, push, manage branches
    "health_monitor": 2,             # monitor PS5 connectivity, loader health
    "pc_network_attacker": 2,        # run scapy/network attacks from PC side
    "coordinator": 2,                # top-level orchestration, route tasks between wings
}

# Verify count
assert sum(AGENT_COUNTS.values()) == 100, f"Agent count is {sum(AGENT_COUNTS.values())}, expected 100"

# ── Model assignments per role ──
MODEL_MAP = {
    # Smart model for hard thinking
    "strategist": SMART_MODEL,
    "probe_writer_kaslr": SMART_MODEL,
    "probe_writer_creative": SMART_MODEL,
    "cross_pollinator": SMART_MODEL,
    "exploit_technique_researcher": SMART_MODEL,
    "coordinator": SMART_MODEL,

    # Fast model for bulk work
    "freebsd_cve_hunter": FAST_MODEL,
    "kernel_source_reader": FAST_MODEL,
    "syscall_analyst": FAST_MODEL,
    "probe_writer_syscall": FAST_MODEL,
    "probe_writer_network": FAST_MODEL,
    "probe_writer_memory": FAST_MODEL,
    "result_analyzer": FAST_MODEL,
    "crash_analyst": FAST_MODEL,
    "dead_end_validator": FAST_MODEL,
    "novelty_detector": FAST_MODEL,
    "priority_ranker": FAST_MODEL,
    "documentor": FAST_MODEL,
    "pc_network_attacker": FAST_MODEL,
    "sony_patch_diffing": FAST_MODEL,

    # Haiku for simple/fast tasks
    "probe_runner": HAIKU_MODEL,
    "regression_tester": HAIKU_MODEL,
    "health_monitor": HAIKU_MODEL,
    "git_manager": HAIKU_MODEL,
    "hardware_researcher": FAST_MODEL,
    "academic_paper_reader": FAST_MODEL,
}

# ── Timing ──
PROBE_SEND_INTERVAL = 5          # seconds between probe sends (PS5 needs breathing room)
HEALTH_CHECK_INTERVAL = 60       # seconds between PS5 health checks
STRATEGY_REVIEW_INTERVAL = 300   # seconds between strategy reviews
RESEARCH_CYCLE_INTERVAL = 120    # seconds between research agent cycles
COMMIT_INTERVAL = 600            # seconds between auto-commits

# ── Paths ──
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROBES_DIR = os.path.join(PROJECT_ROOT, "probes")
RESULTS_DIR = os.path.join(PROJECT_ROOT, "results")
DOCS_DIR = os.path.join(PROJECT_ROOT, "docs")
SWARM_DIR = os.path.join(PROJECT_ROOT, "swarm")
SWARM_STATE_DIR = os.path.join(SWARM_DIR, "state")
SWARM_LOGS_DIR = os.path.join(SWARM_DIR, "logs")
SWARM_QUEUE_DIR = os.path.join(SWARM_DIR, "queue")

# ── Concurrency ──
MAX_CONCURRENT_API_CALLS = 20    # max simultaneous API calls
PROBE_QUEUE_MAX = 50             # max probes waiting to be sent
