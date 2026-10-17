"""All 100 agent role implementations."""

import os
import time
import json
import glob
import subprocess
import logging
from datetime import datetime
from agent_base import Agent
from task_queue import Priority
from ai_client import AIClient

logger = logging.getLogger("swarm")

# ─────────────────────────────────────────────────────────
# CONTEXT: loaded once, shared across agents
# ─────────────────────────────────────────────────────────

def load_project_context(project_root: str) -> str:
    """Load CLAUDE.md + recent findings for AI context."""
    ctx = ""
    for name in ["CLAUDE.md", "docs/FINDINGS.md", "docs/STRATEGY.md", "docs/UNTESTED_THEORIES.md"]:
        path = os.path.join(project_root, name)
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                text = f.read()
            # Truncate large files to last 4000 chars
            if len(text) > 8000:
                text = text[:2000] + "\n...[truncated]...\n" + text[-4000:]
            ctx += f"\n=== {name} ===\n{text}\n"
    return ctx


# ─────────────────────────────────────────────────────────
# RESEARCH WING (40 agents)
# ─────────────────────────────────────────────────────────

class FreeBSDCVEHunter(Agent):
    ROLE = "freebsd_cve_hunter"
    TASK_TYPES = ["research_cve"]
    CYCLE_INTERVAL = 180

    def autonomous_cycle(self):
        ctx = load_project_context(self.swarm.project_root)
        ai = self.swarm.get_ai_client(self.ROLE)
        prompt = f"""You are a FreeBSD kernel vulnerability researcher working on PS5 firmware 14.10 (FreeBSD r230171).

PROJECT CONTEXT:
{ctx}

Your job: Find FreeBSD kernel CVEs that could apply to this kernel version.
Focus on:
- Memory corruption in syscall handlers
- Race conditions in VM subsystem
- Network stack vulnerabilities (especially SCTP, IPv6, raw sockets)
- Privilege escalation bugs
- Information leaks (KASLR defeat)

The PS5 kernel is based on FreeBSD r230171 (Sep 2026). Look for CVEs from 2020-2026 that affect FreeBSD 14.x.
We have: arbitrary syscall via make_syscall(), heap R/W, raw sockets, 11 accessible Sony syscalls.
We need: kernel pointer leak (KASLR defeat) or kernel memory corruption.

Output a JSON object with:
- "cves": list of {{id, description, relevance, exploit_approach, probe_idea}}
- "new_task": optional probe writing task if something looks very promising
"""
        response = ai.chat(prompt)
        if response:
            try:
                data = json.loads(response) if response.strip().startswith("{") else {"raw": response}
                if "new_task" in data and data["new_task"]:
                    self.submit_task("write_probe", data["new_task"], priority=Priority.HIGH,
                                     tags=["cve_hunter", self.agent_id])
                logger.info(f"[{self.agent_id}] found {len(data.get('cves', []))} CVE leads")
            except json.JSONDecodeError:
                pass


class KernelSourceReader(Agent):
    ROLE = "kernel_source_reader"
    TASK_TYPES = ["research_kernel_source"]
    CYCLE_INTERVAL = 200

    def autonomous_cycle(self):
        ctx = load_project_context(self.swarm.project_root)
        ai = self.swarm.get_ai_client(self.ROLE)
        prompt = f"""You are analyzing FreeBSD kernel source code for exploitable patterns.

PROJECT CONTEXT (PS5 14.10, FreeBSD r230171):
{ctx}

Focus areas for this cycle — pick ONE and go deep:
1. Sony custom syscalls 563-566 (proc group, all return 0) — what could they do?
2. Syscall 624 (VM subsystem, returns live counter 3376-3377) — what VM metric is this?
3. Syscall 640 (accepts 6 args with buffer, returns 0 but buffer empty) — what structure does it expect?
4. Syscall 606/643 (event group, return 0) — what event mechanism?
5. FreeBSD ip6_input / sctp_input code paths — where are the bugs?
6. FreeBSD sysctl copyout paths — any that leak kernel addresses?

Output JSON:
- "focus": which area you analyzed
- "findings": list of insights
- "probe_ideas": list of {{description, syscall_num, args_to_try, expected_result}}
"""
        response = ai.chat(prompt)
        if response:
            try:
                data = json.loads(response) if response.strip().startswith("{") else {"raw": response}
                for idea in data.get("probe_ideas", []):
                    self.submit_task("write_probe", idea, priority=Priority.MEDIUM,
                                     tags=["kernel_source", self.agent_id])
            except json.JSONDecodeError:
                pass


class ExploitTechniqueResearcher(Agent):
    ROLE = "exploit_technique_researcher"
    TASK_TYPES = ["research_exploit_technique"]
    CYCLE_INTERVAL = 300

    def autonomous_cycle(self):
        ctx = load_project_context(self.swarm.project_root)
        ai = self.swarm.get_ai_client(self.ROLE)
        prompt = f"""You are an expert in console/kernel exploitation techniques.

PROJECT CONTEXT:
{ctx}

Research known PS4/PS5 exploitation techniques and think about what applies:
- PS4 1.76-9.00 kernel exploits (SpecterDev, TheFlow, etc.)
- FreeBSD kernel exploitation techniques (UaF, double free, type confusion)
- KASLR defeat techniques on FreeBSD (side channels, info leaks, timing)
- Heap exploitation on FreeBSD kernel (zone allocator, uma)

We have make_syscall() but NO code execution and NO kernel pointers.
We need KASLR defeat first, then kernel R/W.

Think creatively. What technique would YOU use given our primitives?
- Arbitrary syscall with controlled args
- Heap R/W (GPU mmap, 256+ pages, no guard pages)
- 11 accessible Sony syscalls (including live counter 624)
- Raw sockets (IPv4/IPv6, 143 protocols)

Output JSON:
- "techniques": list of {{name, description, applicability, steps}}
- "highest_priority_probe": the single best probe to write next
"""
        response = ai.chat(prompt)
        if response:
            try:
                data = json.loads(response) if response.strip().startswith("{") else {"raw": response}
                if "highest_priority_probe" in data:
                    self.submit_task("write_probe", data["highest_priority_probe"],
                                     priority=Priority.HIGH, tags=["exploit_tech", self.agent_id])
            except json.JSONDecodeError:
                pass


class SyscallAnalyst(Agent):
    ROLE = "syscall_analyst"
    TASK_TYPES = ["research_syscall"]
    CYCLE_INTERVAL = 150

    def autonomous_cycle(self):
        ctx = load_project_context(self.swarm.project_root)
        # Read sysent table if available
        sysent_path = os.path.join(self.swarm.project_root, "docs", "ps5_13.60_sysent.json")
        sysent = ""
        if os.path.exists(sysent_path):
            with open(sysent_path, "r") as f:
                sysent = f.read()[:6000]

        ai = self.swarm.get_ai_client(self.ROLE)
        prompt = f"""You analyze PS5 syscall behavior to find exploitation opportunities.

PROJECT CONTEXT:
{ctx}

SYSENT TABLE (partial):
{sysent}

11 accessible Sony syscalls: 585, 596, 572, 624, 563, 564, 565, 566, 606, 643, 640

Tasks:
1. What argument structures might syscalls 563-566 expect? They're in the proc group.
2. Syscall 640 accepts 6 args and returns 0 — what FreeBSD/Sony syscall has 8 args?
3. Are there standard FreeBSD syscalls we haven't tried via make_syscall?
4. Could any syscall pair be used together for an exploit chain?

Output JSON:
- "analysis": your findings
- "untested_syscalls": list of syscall numbers worth trying
- "probe_ideas": list of probe descriptions
"""
        response = ai.chat(prompt)
        if response:
            try:
                data = json.loads(response) if response.strip().startswith("{") else {"raw": response}
                for idea in data.get("probe_ideas", []):
                    self.submit_task("write_probe", {"description": idea}, priority=Priority.MEDIUM,
                                     tags=["syscall_analyst", self.agent_id])
            except json.JSONDecodeError:
                pass


class HardwareResearcher(Agent):
    ROLE = "hardware_researcher"
    TASK_TYPES = ["research_hardware"]
    CYCLE_INTERVAL = 600

    def autonomous_cycle(self):
        ai = self.swarm.get_ai_client(self.ROLE)
        prompt = """Research PS5 hardware exploitation angles:
- AMD GPU (RDNA2) memory mapping, MMIO registers
- PS5 memory controller, physical address layout
- DMA attacks from GPU context
- Hypervisor (orbis) bypass techniques
- TPM/secure enclave weaknesses

We have GPU mmap access (256+ pages via dmem0). The GPU aperture is mapped but CPU DRAM is not accessible through it.

What hardware-level attacks could give us kernel memory access?
Output JSON with "findings" and "probe_ideas" lists."""
        response = ai.chat(prompt)
        if response:
            try:
                data = json.loads(response) if response.strip().startswith("{") else {"raw": response}
                for idea in data.get("probe_ideas", []):
                    self.submit_task("write_probe", {"description": idea}, priority=Priority.LOW,
                                     tags=["hardware", self.agent_id])
            except json.JSONDecodeError:
                pass


class AcademicPaperReader(Agent):
    ROLE = "academic_paper_reader"
    TASK_TYPES = ["research_academic"]
    CYCLE_INTERVAL = 600

    def autonomous_cycle(self):
        ai = self.swarm.get_ai_client(self.ROLE)
        prompt = """Search your knowledge for academic papers on:
1. KASLR defeat techniques (side channels, cache timing, speculative execution)
2. FreeBSD kernel heap exploitation
3. Syscall-based information leaks
4. Console security research (PS4/PS5/Xbox/Switch)
5. GPU-based privilege escalation

We need to defeat KASLR on FreeBSD with only syscall + heap R/W primitives.
What academic techniques apply? Think about:
- Timing side channels via syscall return times
- Cache-based KASLR breaks
- Heap grooming for kernel exploitation
- Cross-cache attacks on FreeBSD UMA zones

Output JSON with "papers" (name, technique, applicability) and "probe_ideas"."""
        response = ai.chat(prompt)
        if response:
            try:
                data = json.loads(response) if response.strip().startswith("{") else {"raw": response}
                for idea in data.get("probe_ideas", []):
                    self.submit_task("write_probe", {"description": idea}, priority=Priority.MEDIUM,
                                     tags=["academic", self.agent_id])
            except json.JSONDecodeError:
                pass


class SonyPatchDiffing(Agent):
    ROLE = "sony_patch_diffing"
    TASK_TYPES = ["research_patches"]
    CYCLE_INTERVAL = 600

    def autonomous_cycle(self):
        ctx = load_project_context(self.swarm.project_root)
        ai = self.swarm.get_ai_client(self.ROLE)
        prompt = f"""You analyze Sony firmware patches to find what was fixed.

PROJECT CONTEXT:
{ctx}

Think about what Sony patched between firmware versions:
- AF_ROUTE info leak was patched (Relapse technique dead on 14.10)
- What other info leaks existed on older firmwares?
- What syscalls were accessible before that are now blocked?
- PS4 kernel exploits that were patched — could any have incomplete fixes?

Key question: What was the LAST working KASLR defeat on PS5, and how was it patched?
If we can find an incomplete patch, we have our vector.

Output JSON with "patch_analysis" and "incomplete_patches" lists."""
        response = ai.chat(prompt)


# ─────────────────────────────────────────────────────────
# PROBE ENGINEERING WING (25 agents)
# ─────────────────────────────────────────────────────────

class ProbeWriter(Agent):
    """Base probe writer — subclassed per attack surface."""
    TASK_TYPES = ["write_probe"]
    CYCLE_INTERVAL = 120

    def get_focus_prompt(self) -> str:
        raise NotImplementedError

    def execute_task(self, task) -> dict:
        ctx = load_project_context(self.swarm.project_root)
        ai = self.swarm.get_ai_client(self.ROLE)

        probe_template = self.read_file(os.path.join(self.swarm.project_root, "CLAUDE.md"))
        # Extract probe template section
        template_start = probe_template.find("### Probe Template")
        template_end = probe_template.find("### Lua 5.1 Constraints")
        template_section = probe_template[template_start:template_end] if template_start > 0 else ""

        prompt = f"""You are a PS5 kernel exploit probe writer. Write a complete, ready-to-run Lua 5.1 probe.

PROJECT CONTEXT:
{ctx}

PROBE TEMPLATE AND CONSTRAINTS (MUST FOLLOW):
{template_section}

TASK:
{json.dumps(task.payload)}

CRITICAL RULES:
1. Use Lua 5.1 syntax ONLY (no goto, no labels, no 0x_ underscores in numbers)
2. Use make_syscall(N) for all syscall access
3. pcall() everything risky
4. Never hardcode addresses — re-derive from dynlib_get_info or tostring(syscall.pipe)
5. Include ALL standard helpers (to_num, make_syscall, safe_rd, safe_rq, safe_wd, safe_wq, get_hi_lo)
6. Print clear output with section headers
7. Check for kernel pointers: h >= 0xFFFF8000 where h,l = get_hi_lo(val)

Output ONLY the complete Lua source code, nothing else. Start with the CRASH_CLASS comment."""

        response = ai.chat(prompt)
        if response and response.strip().startswith("--"):
            # Save probe
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            probe_name = f"swarm_{self.ROLE}_{ts}"
            probe_path = os.path.join(self.swarm.project_root, "probes", "swarm_generated", f"{probe_name}.lua")
            os.makedirs(os.path.dirname(probe_path), exist_ok=True)
            with open(probe_path, "w", encoding="utf-8") as f:
                f.write(response)

            # Queue it for sending
            self.submit_task("send_probe", {
                "probe_path": probe_path,
                "probe_name": probe_name,
                "source_agent": self.agent_id,
            }, priority=task.priority, tags=["auto_generated"])

            return {"probe_path": probe_path, "probe_name": probe_name}
        return {"error": "AI did not produce valid Lua probe"}

    def autonomous_cycle(self):
        focus = self.get_focus_prompt()
        self.submit_task("write_probe", {"description": focus}, priority=Priority.MEDIUM,
                         tags=[self.ROLE, "autonomous"])


class ProbeWriterSyscall(ProbeWriter):
    ROLE = "probe_writer_syscall"
    def get_focus_prompt(self):
        return "Write a probe testing Sony syscalls with different argument structures. Focus on syscalls 563-566 (proc group) or 640 (6-arg with buffer). Try different struct layouts, flags, sizes."

class ProbeWriterNetwork(ProbeWriter):
    ROLE = "probe_writer_network"
    def get_focus_prompt(self):
        return "Write a probe targeting the kernel network stack. Try: TCP connection state corruption across many rapid connect/disconnect cycles, SCTP association state attacks, IPv6 routing header manipulation with valid checksums, raw socket protocol confusion."

class ProbeWriterMemory(ProbeWriter):
    ROLE = "probe_writer_memory"
    def get_focus_prompt(self):
        return "Write a probe targeting kernel heap/memory. Try: GPU mmap boundary scanning for adjacent kernel objects, heap grooming via socket/pipe allocation patterns, sysctl buffer boundary probing, cross-zone allocation patterns."

class ProbeWriterKASLR(ProbeWriter):
    ROLE = "probe_writer_kaslr"
    def get_focus_prompt(self):
        return "Write a probe specifically to defeat KASLR. Try: syscall timing side channels (measure nanosecond differences for valid vs invalid kernel addresses via syscall 624 counter), heap address relationships that reveal kernel base, socket object layout that leaks kernel pointers, sysctl copyout edge cases."

class ProbeWriterCreative(ProbeWriter):
    ROLE = "probe_writer_creative"
    def get_focus_prompt(self):
        return "Think completely outside the box for PS5 kernel exploitation. Try: abusing the Lua loader's own memory management, using GPU compute shaders via mmap to probe kernel memory, timing attacks on syscall 624's counter to infer kernel state, chaining multiple primitives in novel ways, exploiting the fact that make_syscall() is a C wrapper."


# ─────────────────────────────────────────────────────────
# EXECUTION WING (10 agents)
# ─────────────────────────────────────────────────────────

class ProbeRunner(Agent):
    ROLE = "probe_runner"
    TASK_TYPES = ["send_probe"]
    CYCLE_INTERVAL = 10  # check frequently

    def execute_task(self, task) -> dict:
        if not self.ps5.alive:
            logger.warning(f"[{self.agent_id}] PS5 not alive, waiting...")
            if not self.ps5.wait_for_loader(timeout=300, check_interval=15):
                return {"error": "PS5 loader not responding after 5 minutes"}

        probe_path = task.payload.get("probe_path")
        probe_name = task.payload.get("probe_name", "unknown")

        if not probe_path or not os.path.exists(probe_path):
            return {"error": f"Probe file not found: {probe_path}"}

        lua_source = self.read_file(probe_path)
        if not lua_source:
            return {"error": "Empty probe file"}

        result = self.ps5.send_probe(lua_source, probe_name)

        # Queue analysis of the result
        if result["success"]:
            self.submit_task("analyze_result", {
                "probe_name": probe_name,
                "probe_path": probe_path,
                "result_path": result.get("saved_to"),
                "response": result["response"][:4000],
                "bytes_received": result["bytes_received"],
            }, priority=Priority.HIGH, tags=["auto_analyze"])
        elif result["bytes_received"] == 0:
            self.submit_task("analyze_crash", {
                "probe_name": probe_name,
                "probe_path": probe_path,
                "error": "0 bytes received — probe killed or loader dead",
            }, priority=Priority.HIGH, tags=["crash"])

        return result


class ResultAnalyzer(Agent):
    ROLE = "result_analyzer"
    TASK_TYPES = ["analyze_result"]
    CYCLE_INTERVAL = 30

    def execute_task(self, task) -> dict:
        response_text = task.payload.get("response", "")
        probe_name = task.payload.get("probe_name", "")

        ai = self.swarm.get_ai_client(self.ROLE)
        ctx = load_project_context(self.swarm.project_root)

        prompt = f"""Analyze this PS5 probe result for exploitation value.

PROJECT CONTEXT:
{ctx}

PROBE: {probe_name}
OUTPUT:
{response_text}

Look for:
1. **KERNEL POINTERS** — values where high 32 bits >= 0xFFFF8000 (NOT 0xFFFFFFFF which are sentinels)
2. **Non-zero return values** — anything unexpected
3. **Buffer contents** — any non-zero data that could be info leaks
4. **Patterns** — values that change between runs (like syscall 624's counter)
5. **Crashes/kills** — what caused them and what that tells us
6. **New attack surface** — anything that opens up new avenues

Output JSON:
- "kernel_pointers_found": boolean (TRUE ONLY for 0xFFFF8xxx range, NOT 0xFFFFFFFF sentinels)
- "interesting_values": list of {{offset, value, interpretation}}
- "verdict": "breakthrough" | "promising" | "useful_data" | "dead_end"
- "follow_up_probes": list of probe ideas to explore further
- "findings_entry": text for FINDINGS.md if anything new discovered
"""
        response = ai.chat(prompt)
        result = {"raw_analysis": response}

        if response:
            try:
                data = json.loads(response) if response.strip().startswith("{") else {}
                result.update(data)

                if data.get("kernel_pointers_found"):
                    logger.critical(f"[{self.agent_id}] ★★★ KERNEL POINTER FOUND in {probe_name}!")
                    self.submit_task("write_probe", {
                        "description": f"URGENT: Kernel pointer found in {probe_name}. Write probe to extract full pointer and determine if it defeats KASLR.",
                        "context": response_text[:2000],
                    }, priority=Priority.CRITICAL, tags=["kaslr_defeat", "kernel_pointer"])

                if data.get("verdict") == "breakthrough":
                    logger.critical(f"[{self.agent_id}] ★★★ BREAKTHROUGH in {probe_name}!")

                for idea in data.get("follow_up_probes", []):
                    self.submit_task("write_probe", {"description": idea},
                                     priority=Priority.HIGH if data.get("verdict") == "promising" else Priority.MEDIUM,
                                     tags=["follow_up", probe_name])
            except json.JSONDecodeError:
                pass

        return result


class CrashAnalyst(Agent):
    ROLE = "crash_analyst"
    TASK_TYPES = ["analyze_crash"]
    CYCLE_INTERVAL = 60

    def execute_task(self, task) -> dict:
        ai = self.swarm.get_ai_client(self.ROLE)
        probe_path = task.payload.get("probe_path", "")
        probe_source = self.read_file(probe_path) if probe_path else "unavailable"

        prompt = f"""A PS5 probe crashed or was killed. Analyze why.

PROBE: {task.payload.get('probe_name')}
ERROR: {task.payload.get('error')}
PROBE SOURCE (first 3000 chars):
{probe_source[:3000]}

Determine:
1. Was this a sandbox kill (kernel-level enforcement)?
2. Was this a Lua parse/runtime error?
3. Was this a kernel crash (most interesting!)?
4. Which specific operation caused the crash?

Output JSON:
- "crash_type": "sandbox_kill" | "lua_error" | "kernel_crash" | "loader_dead" | "unknown"
- "cause": description
- "interesting": boolean — is this worth investigating further?
- "follow_up": probe idea if interesting
"""
        response = ai.chat(prompt)
        if response:
            try:
                data = json.loads(response) if response.strip().startswith("{") else {}
                if data.get("interesting") and data.get("follow_up"):
                    self.submit_task("write_probe", {"description": data["follow_up"]},
                                     priority=Priority.HIGH, tags=["crash_follow_up"])
                return data
            except json.JSONDecodeError:
                pass
        return {"raw": response}


class RegressionTester(Agent):
    ROLE = "regression_tester"
    TASK_TYPES = ["regression_test"]
    CYCLE_INTERVAL = 300

    def autonomous_cycle(self):
        # Find recent promising probes and re-run them
        recent = self.queue.get_recent_completed(50)
        for task in recent:
            if task.type == "analyze_result" and task.result:
                verdict = task.result.get("verdict")
                if verdict in ("promising", "breakthrough"):
                    probe_path = task.payload.get("probe_path")
                    if probe_path and os.path.exists(probe_path):
                        self.submit_task("send_probe", {
                            "probe_path": probe_path,
                            "probe_name": task.payload.get("probe_name", "") + "_retest",
                        }, priority=Priority.HIGH, tags=["regression"])
                    break


# ─────────────────────────────────────────────────────────
# STRATEGY WING (15 agents)
# ─────────────────────────────────────────────────────────

class Strategist(Agent):
    ROLE = "strategist"
    TASK_TYPES = ["strategy_review"]
    CYCLE_INTERVAL = 300

    def autonomous_cycle(self):
        ctx = load_project_context(self.swarm.project_root)
        stats = self.queue.get_stats()
        pending = self.queue.get_pending_by_type()

        ai = self.swarm.get_ai_client(self.ROLE)
        prompt = f"""You are the strategic lead for PS5 14.10 kernel exploitation.

PROJECT CONTEXT:
{ctx}

SWARM STATUS:
- Queue stats: {json.dumps(stats)}
- Pending by type: {json.dumps(pending)}
- PS5 alive: {self.ps5.alive}
- Probes sent: {self.ps5.total_probes_sent}

Review the current state and decide:
1. Are we focusing on the right attack vectors?
2. Should we pivot to a different approach?
3. What's the single highest-value thing to try next?
4. Are there any dead ends we should stop pursuing?

The goal is kernel R/W. We need KASLR defeat first.
Current best leads: syscall 624 live counter, untested second half of Sony syscalls, timing side channels.

Output JSON:
- "assessment": current state summary
- "priority_shift": any changes to priorities
- "new_tasks": list of high-priority tasks to queue
- "cancel_tasks": list of task types to deprioritize
"""
        response = ai.chat(prompt)
        if response:
            try:
                data = json.loads(response) if response.strip().startswith("{") else {}
                for task_desc in data.get("new_tasks", []):
                    self.submit_task("write_probe", {"description": task_desc},
                                     priority=Priority.HIGH, tags=["strategist"])
            except json.JSONDecodeError:
                pass


class DeadEndValidator(Agent):
    ROLE = "dead_end_validator"
    TASK_TYPES = ["validate_dead_end"]
    CYCLE_INTERVAL = 600

    def autonomous_cycle(self):
        ctx = load_project_context(self.swarm.project_root)
        ai = self.swarm.get_ai_client(self.ROLE)
        prompt = f"""Review the dead ends in the PS5 research and look for ones that might not actually be dead.

PROJECT CONTEXT:
{ctx}

For each "dead end", consider:
1. Was it tested with the right arguments?
2. Was it tested via make_syscall() or only resolve()?
3. Could a different approach make it work?
4. Has new information changed the picture?

Pick the ONE dead end most likely to be wrong and propose a probe to re-test it.
Output JSON with "dead_end", "reason_to_retest", and "probe_idea"."""
        response = ai.chat(prompt)
        if response:
            try:
                data = json.loads(response) if response.strip().startswith("{") else {}
                if data.get("probe_idea"):
                    self.submit_task("write_probe", {"description": data["probe_idea"]},
                                     priority=Priority.MEDIUM, tags=["dead_end_retest"])
            except json.JSONDecodeError:
                pass


class CrossPollinator(Agent):
    ROLE = "cross_pollinator"
    TASK_TYPES = ["cross_pollinate"]
    CYCLE_INTERVAL = 400

    def autonomous_cycle(self):
        recent = self.queue.get_recent_completed(30)
        findings = []
        for task in recent:
            if task.result and task.type in ("analyze_result", "research_cve"):
                findings.append(json.dumps(task.result)[:500])

        if not findings:
            return

        ai = self.swarm.get_ai_client(self.ROLE)
        prompt = f"""You combine findings from different research threads to find novel attack paths.

RECENT FINDINGS:
{chr(10).join(findings[:10])}

Look for connections between these findings that no single researcher would see.
Can two unrelated findings be combined into a new attack?

Output JSON with "connections" and "combined_probe_ideas"."""
        response = ai.chat(prompt)
        if response:
            try:
                data = json.loads(response) if response.strip().startswith("{") else {}
                for idea in data.get("combined_probe_ideas", []):
                    self.submit_task("write_probe", {"description": idea},
                                     priority=Priority.HIGH, tags=["cross_pollinated"])
            except json.JSONDecodeError:
                pass


class NoveltyDetector(Agent):
    ROLE = "novelty_detector"
    TASK_TYPES = ["check_novelty"]
    CYCLE_INTERVAL = 120

    def autonomous_cycle(self):
        pending = self.queue.get_pending_by_type()
        if pending.get("write_probe", 0) > 20:
            # Too many probes queued — check for duplicates
            logger.info(f"[{self.agent_id}] {pending['write_probe']} probes queued, checking for duplicates")


class PriorityRanker(Agent):
    ROLE = "priority_ranker"
    TASK_TYPES = ["rank_priorities"]
    CYCLE_INTERVAL = 300

    def autonomous_cycle(self):
        pass  # Monitors queue and adjusts priorities


# ─────────────────────────────────────────────────────────
# INFRASTRUCTURE WING (10 agents)
# ─────────────────────────────────────────────────────────

class Documentor(Agent):
    ROLE = "documentor"
    TASK_TYPES = ["document_finding"]
    CYCLE_INTERVAL = 300

    def execute_task(self, task) -> dict:
        finding = task.payload.get("finding", "")
        probe_name = task.payload.get("probe_name", "")

        # Append to FINDINGS.md
        findings_path = os.path.join(self.swarm.project_root, "docs", "FINDINGS.md")
        if os.path.exists(findings_path):
            current = self.read_file(findings_path)
            # Count existing findings
            import re
            nums = re.findall(r"## Finding (\d+)", current)
            next_num = max(int(n) for n in nums) + 1 if nums else 1

            entry = f"\n\n---\n\n## Finding {next_num}: {probe_name} (swarm auto-generated)\n\n{finding}\n"
            with open(findings_path, "a", encoding="utf-8") as f:
                f.write(entry)
            return {"finding_number": next_num}
        return {"error": "FINDINGS.md not found"}


class GitManager(Agent):
    ROLE = "git_manager"
    TASK_TYPES = ["git_commit"]
    CYCLE_INTERVAL = 600  # auto-commit every 10 minutes

    def autonomous_cycle(self):
        try:
            # Check for uncommitted changes
            result = subprocess.run(
                ["git", "status", "--porcelain"],
                capture_output=True, text=True, cwd=self.swarm.project_root
            )
            if result.stdout.strip():
                # There are changes — commit them
                subprocess.run(["git", "add", "-A"], cwd=self.swarm.project_root)
                ts = datetime.now().strftime("%Y-%m-%d %H:%M")
                msg = f"swarm auto-commit: {ts} — {self.ps5.total_probes_sent} probes sent"
                subprocess.run(
                    ["git", "commit", "-m", msg],
                    cwd=self.swarm.project_root, capture_output=True
                )
                subprocess.run(
                    ["git", "push"],
                    cwd=self.swarm.project_root, capture_output=True
                )
                logger.info(f"[{self.agent_id}] auto-committed and pushed")
        except Exception as e:
            logger.error(f"[{self.agent_id}] git error: {e}")


class HealthMonitor(Agent):
    ROLE = "health_monitor"
    TASK_TYPES = ["health_check"]
    CYCLE_INTERVAL = 60

    def autonomous_cycle(self):
        alive = self.ps5.health_check()
        if not alive:
            logger.warning(f"[{self.agent_id}] PS5 loader is DOWN (failures: {self.ps5.consecutive_failures})")
            if self.ps5.consecutive_failures >= 5:
                recovery = getattr(self.swarm, 'recovery', None)
                if recovery and recovery.is_available():
                    logger.info(f"[{self.agent_id}] Triggering auto-recovery via Chiaki-ng...")
                    if recovery.attempt_recovery():
                        logger.info(f"[{self.agent_id}] AUTO-RECOVERY SUCCEEDED! Loader is back.")
                    else:
                        logger.error(f"[{self.agent_id}] Auto-recovery failed. Manual intervention needed.")
                else:
                    logger.error(f"[{self.agent_id}] Chiaki-ng not configured — waiting for loader...")
                    self.ps5.wait_for_loader(timeout=300, check_interval=30)
        else:
            if self.ps5.consecutive_failures == 0:
                pass
            else:
                logger.info(f"[{self.agent_id}] PS5 loader recovered!")


class PCNetworkAttacker(Agent):
    ROLE = "pc_network_attacker"
    TASK_TYPES = ["network_attack"]
    CYCLE_INTERVAL = 300

    def execute_task(self, task) -> dict:
        # Run scapy scripts from PC against PS5
        script = task.payload.get("script", "")
        if script:
            try:
                result = subprocess.run(
                    ["python", "-c", script],
                    capture_output=True, text=True, timeout=60,
                    cwd=self.swarm.project_root
                )
                return {"stdout": result.stdout[:2000], "stderr": result.stderr[:2000]}
            except Exception as e:
                return {"error": str(e)}
        return {"error": "no script provided"}


class Coordinator(Agent):
    ROLE = "coordinator"
    TASK_TYPES = ["coordinate"]
    CYCLE_INTERVAL = 120

    def autonomous_cycle(self):
        stats = self.queue.get_stats()
        pending = self.queue.get_pending_by_type()

        # If probe queue is empty, generate more tasks
        if pending.get("write_probe", 0) < 5 and pending.get("send_probe", 0) < 3:
            self.submit_task("write_probe", {
                "description": "Generate a creative probe targeting KASLR defeat. Use timing side channels, syscall 624 counter correlation, or novel sysctl paths."
            }, priority=Priority.MEDIUM, tags=["coordinator_refill"])

        # Log status
        logger.info(f"[{self.agent_id}] Queue: {stats} | PS5: {'UP' if self.ps5.alive else 'DOWN'} | Sent: {self.ps5.total_probes_sent}")


# ─────────────────────────────────────────────────────────
# AGENT REGISTRY
# ─────────────────────────────────────────────────────────

AGENT_CLASSES = {
    "freebsd_cve_hunter": FreeBSDCVEHunter,
    "kernel_source_reader": KernelSourceReader,
    "exploit_technique_researcher": ExploitTechniqueResearcher,
    "syscall_analyst": SyscallAnalyst,
    "hardware_researcher": HardwareResearcher,
    "academic_paper_reader": AcademicPaperReader,
    "sony_patch_diffing": SonyPatchDiffing,
    "probe_writer_syscall": ProbeWriterSyscall,
    "probe_writer_network": ProbeWriterNetwork,
    "probe_writer_memory": ProbeWriterMemory,
    "probe_writer_kaslr": ProbeWriterKASLR,
    "probe_writer_creative": ProbeWriterCreative,
    "probe_runner": ProbeRunner,
    "result_analyzer": ResultAnalyzer,
    "crash_analyst": CrashAnalyst,
    "regression_tester": RegressionTester,
    "strategist": Strategist,
    "dead_end_validator": DeadEndValidator,
    "cross_pollinator": CrossPollinator,
    "novelty_detector": NoveltyDetector,
    "priority_ranker": PriorityRanker,
    "documentor": Documentor,
    "git_manager": GitManager,
    "health_monitor": HealthMonitor,
    "pc_network_attacker": PCNetworkAttacker,
    "coordinator": Coordinator,
}
