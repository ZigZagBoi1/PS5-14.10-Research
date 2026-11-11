"""Failure classification for PS5 experiments.

Seven outcome classes:
  SUCCESS           — probe ran to completion, data captured
  JS_EXCEPTION      — WebProcess JS error, page still alive
  WEBPROCESS_CRASH  — WebProcess died, page navigation can recover
  APP_FREEZE        — game/loader stopped responding
  RP_DISCONNECT     — Remote Play (Chiaki) lost connection
  SERVER_FAILURE    — our server/tooling failed, not the console
  CONSOLE_PANIC     — suspected kernel panic, requires power cycle
"""
from __future__ import annotations
from dataclasses import dataclass
from enum import Enum


class Outcome(str, Enum):
    SUCCESS = "SUCCESS"
    JS_EXCEPTION = "JS_EXCEPTION"
    WEBPROCESS_CRASH = "WEBPROCESS_CRASH"
    APP_FREEZE = "APP_FREEZE"
    RP_DISCONNECT = "RP_DISCONNECT"
    SERVER_FAILURE = "SERVER_FAILURE"
    CONSOLE_PANIC = "CONSOLE_PANIC"


@dataclass
class Classification:
    outcome: Outcome
    detail: str
    recoverable: bool
    crash_signature: str | None = None


def classify_lua_result(status: str, response: bytes, elapsed: float) -> Classification:
    if status == "COMPLETE" and response:
        return Classification(Outcome.SUCCESS, f"{len(response)}B in {elapsed:.1f}s", True)
    if status == "CONNECTION_REFUSED":
        return Classification(Outcome.APP_FREEZE, "loader port refused", True,
                              "lua_conn_refused")
    if status == "CONNECT_TIMEOUT":
        return Classification(Outcome.APP_FREEZE, "loader port unreachable", True,
                              "lua_conn_timeout")
    if status == "CONNECTION_RESET":
        return Classification(Outcome.WEBPROCESS_CRASH, "connection reset mid-probe", True,
                              "lua_conn_reset")
    if status == "CONNECTION_CLOSED" and not response:
        return Classification(Outcome.APP_FREEZE, "accepted but no response (dead thread)", True,
                              "lua_silent_close")
    if status in ("IDLE_TIMEOUT", "TOTAL_TIMEOUT"):
        return Classification(Outcome.APP_FREEZE, f"timeout after {elapsed:.1f}s", True,
                              "lua_timeout")
    if status == "ERROR":
        return Classification(Outcome.SERVER_FAILURE, "local socket error", True,
                              "local_error")
    return Classification(Outcome.APP_FREEZE, f"unknown status: {status}", True,
                          "unknown")


def classify_beacon_result(beacons: list[str], crashed: bool, elapsed: float) -> Classification:
    all_text = " ".join(beacons) if beacons else ""

    # Walk chain success patterns (FontFace UAF walk chain probes)
    if "WALK-ok=true" in all_text:
        return Classification(Outcome.SUCCESS,
                              f"walk chain complete, {len(beacons)} beacons, {elapsed:.1f}s", True)
    if "VP-0x" in all_text and "WALK-VT=" in all_text:
        return Classification(Outcome.SUCCESS,
                              f"VP+vtable leaked, {len(beacons)} beacons, {elapsed:.1f}s", True)

    if not crashed and beacons:
        last = beacons[-1] if beacons else ""
        if "DONE" in last or "COMPLETE" in last or "RESULT" in last:
            return Classification(Outcome.SUCCESS, f"{len(beacons)} beacons, {elapsed:.1f}s", True)
        # Walk chain partial: got beacons but no completion signal
        if "WALK-ok=false" in all_text:
            return Classification(Outcome.JS_EXCEPTION,
                                  f"walk chain validation failed, {len(beacons)} beacons", True,
                                  "walk_validation_fail")
        if any(p in all_text for p in ("FORGE-ERR", "W1-ERR", "W2-ERR", "W3-ERR", "W4-ERR")):
            return Classification(Outcome.WEBPROCESS_CRASH,
                                  f"forgeRead crash, {len(beacons)} beacons", True,
                                  "webkit_forgeread_crash")
        if any(p in all_text for p in ("NOLEAK", "NO-TRIGGER")):
            return Classification(Outcome.JS_EXCEPTION,
                                  "spray miss (no reclaim)", True, "spray_miss")
        return Classification(Outcome.SUCCESS, f"{len(beacons)} beacons (partial)", True)
    if crashed:
        has_beacons = len(beacons) > 0
        if has_beacons:
            return Classification(Outcome.WEBPROCESS_CRASH,
                                  f"crash after {len(beacons)} beacons", True,
                                  f"webkit_crash_{len(beacons)}b")
        return Classification(Outcome.WEBPROCESS_CRASH, "immediate crash", True,
                              "webkit_crash_0b")
    return Classification(Outcome.APP_FREEZE, "no beacons received", True, "no_beacons")


def is_recoverable(c: Classification) -> bool:
    return c.outcome not in (Outcome.CONSOLE_PANIC,)
