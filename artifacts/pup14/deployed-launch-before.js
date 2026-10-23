"use strict";

const etahenButton = document.getElementById("load-etahen");
const startButton = document.getElementById("start-relapse");
const pupButton = document.getElementById("send-pup");
const firmwareStatus = document.getElementById("firmware-status");
const consoleOutput = document.getElementById("console");
const dumpModeControl = document.getElementById("dump-mode");
const pupModeControl = document.getElementById("pup-mode");
window.__relapseMode = "relapse";
window.__relapseCleanupFailed = false;
let localRelapseCompleted = false;

async function refreshPupEligibility() {
  const response = await fetch("/ps5/api/pup/eligibility", { credentials: "same-origin", cache: "no-store" });
  if (!response.ok) throw new Error(`PUP eligibility HTTP ${response.status}`);
  const state = await response.json();
  pupButton.disabled = !state.relapse_ready && !localRelapseCompleted;
  return state;
}

async function sendPup() {
  pupButton.disabled = true;
  try {
    const diagnostics = window.__relapseDiagnostics;
    if (diagnostics && !(await diagnostics.drain()))
      throw new Error("Relapse messages have not reached the server yet. Wait a few seconds and retry this button.");
    const eligibility = await refreshPupEligibility();
    if (!eligibility.relapse_ready || !eligibility.relapse_session_id)
      throw new Error("The server has no completed Relapse session for this console. Do not rerun Relapse in the same boot.");
    firmwareStatus.textContent = "Sending the 14.10 PUP research ELF…";
    const response = await fetch("/ps5/api/pup/send", {
      method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ firmware: window.fw_str, elfldr_ready: true,
        relapse_session_id: eligibility.relapse_session_id }),
    });
    const delivery = await response.json();
    if (!response.ok || delivery.sent !== true)
      throw new Error(delivery.error || "PUP research ELF delivery failed");
    window.writeLog("Research ELF sent. Waiting for receiver status; this does not confirm decryption.", "info");
    firmwareStatus.textContent = "Research ELF sent. Waiting for server output…";
    pollPupStatus(eligibility.relapse_session_id);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    window.writeLog(`PUP delivery: ${message}`, "error");
    firmwareStatus.textContent = message;
    firmwareStatus.classList.add("error");
    try { await refreshPupEligibility(); } catch (_) { pupButton.disabled = true; }
  }
}

pupButton.addEventListener("click", sendPup);
if (window.fw_str === "13.60") void refreshPupEligibility().catch(() => {});

if (window.firmware) {
  const rejection = window.firmware.rejection();
  if (rejection) {
    firmwareStatus.textContent = `${rejection}. Confirm the installed system software in Settings before starting.`;
    firmwareStatus.classList.add("error");
  } else if (window.fw_str !== "13.60") {
    firmwareStatus.textContent = `This HV package is pinned to 13.60. The browser reports ${window.fw_str}; check Console Information in Settings before proceeding.`;
    firmwareStatus.classList.add("error");
  } else {
    firmwareStatus.textContent = "Browser reports PS5 firmware 13.60. Confirm Console Information in Settings, then choose a Relapse mode.";
    firmwareStatus.classList.add("ready");
    startButton.disabled = false;
  }
} else {
  const reported = (navigator.userAgent.match(/PlayStation 5\/(\d+\.\d+)/) || [])[1];
  if (reported === "13.60") {
    window.fw_str = reported;
    firmwareStatus.textContent = "Console reports firmware 13.60. The firmware check script did not load; reload this page before starting.";
  } else {
    firmwareStatus.textContent = "Could not verify firmware 13.60. Reload this page before starting.";
  }
  firmwareStatus.classList.add("error");
}

startButton.addEventListener("click", async () => {
  if (startButton.disabled) return;
  const rejection = window.firmware?.rejection();
  if (!window.firmware || rejection || window.fw_str !== "13.60") {
    firmwareStatus.textContent = !window.firmware
      ? "The upstream firmware check did not load. Check the page connection and reload before trying again."
      : rejection || `This page is for firmware 13.60; the browser reports ${window.fw_str || "an unknown version"}.`;
    firmwareStatus.classList.add("error");
    return;
  }
  const dumpMode = Boolean(dumpModeControl && dumpModeControl.checked);
  const pupMode = Boolean(pupModeControl && pupModeControl.checked && !dumpMode);
  window.__relapseMode = dumpMode ? "dump" : "relapse";
  if (dumpModeControl) dumpModeControl.disabled = true;
  if (pupModeControl) pupModeControl.disabled = true;
  startButton.disabled = true;
  consoleOutput.textContent = "Loading upstream Relapse…\n";
  window.__relapseDiagnostics?.log("Start Relapse selected", "info");
  try {
    if (window.__relapseOffsetsReady) {
      consoleOutput.textContent += "Waiting for firmware offsets…\n";
      await window.__relapseOffsetsReady;
      window.__relapseDiagnostics?.log("Firmware offsets loaded", "info");
    } else {
      throw new Error("Firmware offset loader did not initialize. Reload this page.");
    }
    const { runRelapse } = await import("./src/site.js");
    const result = await runRelapse();
    if (!result || !result.done || !result.payloads || window.__relapseCleanupFailed) {
      throw new Error("Relapse did not confirm payload loading and cleanup. Restart the console before another attempt.");
    }
    localRelapseCompleted = true;
    pupButton.disabled = false;
    const diagnostics = window.__relapseDiagnostics;
    if (!dumpMode && (!diagnostics || !diagnostics.log("Relapse cleanup complete; HV delivery ready.", "success"))) {
      throw new Error("Relapse finished, but the server did not acknowledge the completion message. Do not start another exploit in this boot.");
    }
    if (diagnostics && !(await diagnostics.drain())) {
      throw new Error("Completion could not reach the server. Restart before another attempt.");
    }
    if (pupMode) {
      await sendPup();
    } else if (!dumpMode) {
      etahenButton.disabled = false;
    }
    if (dumpMode) {
      firmwareStatus.textContent = "Relapse and selected dumps are complete; temporary exploit state was restored. Do not start another run in this boot.";
    } else if (!pupMode) {
      firmwareStatus.textContent = "Relapse complete. Select Load etaHEN when you are ready. Keep this page open; do not run Relapse again in this boot.";
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    consoleOutput.textContent += `\n[page] ${message}`;
    window.__relapseDiagnostics?.log(`[page] ${message}`, "error");
    firmwareStatus.textContent = message;
    firmwareStatus.classList.add("error");
  } finally {
    if (dumpModeControl) dumpModeControl.disabled = true;
    if (pupModeControl) pupModeControl.disabled = true;
  }
});

async function pollPupStatus(sessionId) {
  let lastStage = "";
  for (let attempt = 0; attempt < 720; attempt++) {
    try {
      const response = await fetch(`/ps5/api/pup/status?session_id=${encodeURIComponent(sessionId)}`,
        { credentials: "same-origin", cache: "no-store" });
      if (!response.ok) throw new Error(`status HTTP ${response.status}`);
      const { state } = await response.json();
      if (state.stage !== lastStage) {
        lastStage = state.stage;
        const detail = state.stage === "complete"
          ? `complete: ${state.component_count || 0} components, ${state.kernel_candidates || 0} kernel candidate(s) saved on server`
          : state.error ? `${state.stage}: ${state.error}` : state.stage;
        window.writeLog(`PUP receiver: ${detail}`,
          state.stage === "complete" ? "success" : state.stage.includes("failed") ? "error" : "info");
        firmwareStatus.textContent = `PUP receiver: ${detail}`;
      }
      if (["complete", "failed", "payload_failed", "unpack_failed"].includes(state.stage)) return;
    } catch (error) {
      window.writeLog(`PUP status unavailable: ${error.message || error}`, "error");
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 5000));
  }
  window.writeLog("PUP receiver still pending after one hour; check the server run folder.", "error");
}

if (pupModeControl && dumpModeControl) {
  pupModeControl.addEventListener("change", () => { if (pupModeControl.checked) dumpModeControl.checked = false; });
  dumpModeControl.addEventListener("change", () => { if (dumpModeControl.checked) pupModeControl.checked = false; });
}

etahenButton.addEventListener("click", async () => {
  if (etahenButton.disabled) return;
  etahenButton.disabled = true;

      firmwareStatus.textContent = "Relapse complete. Sending etaHEN… Keep this page open.";
      window.writeLog("Sending etaHEN to the console…", "info");
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 25000);
      try {
        const response = await fetch("/ps5/api/etahen/send", {
          method: "POST",
          credentials: "same-origin",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ firmware: window.fw_str, elfldr_ready: true, relapse_session_id: window.__relapseDiagnostics.sessionId }),
          signal: controller.signal,
        });
        const delivery = await response.json();
        if (!response.ok || delivery.sent !== true) throw new Error(delivery.error || "etaHEN delivery failed.");
        firmwareStatus.textContent = "etaHEN and ShadowMount sent. Wait for both notifications, then open your homebrew app.";
        window.writeLog("etaHEN and ShadowMount sent. Wait for both notifications before launching apps.", "success");
      } catch (error) {
        const message = `etaHEN: ${error.message || error}. Check the console; restart before trying again.`;
        firmwareStatus.textContent = message;
        firmwareStatus.classList.add("error");
        window.writeLog(message, "error");
      } finally {
        clearTimeout(timeout);
      }

});
