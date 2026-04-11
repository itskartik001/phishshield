/* =============================================================================
   PhishShield — Frontend Logic
   Handles scan requests, loading animation, and result rendering.
============================================================================= */

"use strict";

// ── Loading step sequence ─────────────────────────────────────────────────────
const LOAD_STEPS = ["ls1", "ls2", "ls3", "ls4", "ls5"];
let _loadTimer   = null;

function animateLoadingSteps() {
  let idx = 0;
  LOAD_STEPS.forEach(id => {
    const el = document.getElementById(id);
    if (el) { el.classList.remove("active", "done"); }
  });

  _loadTimer = setInterval(() => {
    if (idx < LOAD_STEPS.length) {
      if (idx > 0) {
        const prev = document.getElementById(LOAD_STEPS[idx - 1]);
        if (prev) { prev.classList.remove("active"); prev.classList.add("done"); }
      }
      const cur = document.getElementById(LOAD_STEPS[idx]);
      if (cur) cur.classList.add("active");
      idx++;
    } else {
      clearInterval(_loadTimer);
    }
  }, 1800);
}

function stopLoadingAnimation() {
  clearInterval(_loadTimer);
  LOAD_STEPS.forEach(id => {
    const el = document.getElementById(id);
    if (el) { el.classList.remove("active"); el.classList.add("done"); }
  });
}

// ── Fill example ─────────────────────────────────────────────────────────────
function fillExample(url) {
  const input = document.getElementById("urlInput");
  if (input) {
    input.value = url;
    input.focus();
  }
}

// ── Reset ─────────────────────────────────────────────────────────────────────
function resetScan() {
  document.getElementById("resultSection").classList.add("hidden");
  document.getElementById("loadingSection").classList.add("hidden");
  document.getElementById("urlInput").value = "";
  document.getElementById("errorMsg").textContent = "";
  document.getElementById("scanBtn").disabled = false;
  document.getElementById("urlInput").focus();
  window.scrollTo({ top: 0, behavior: "smooth" });
}

// ── Main scan ─────────────────────────────────────────────────────────────────
async function startScan() {
  const input   = document.getElementById("urlInput");
  const errMsg  = document.getElementById("errorMsg");
  const scanBtn = document.getElementById("scanBtn");

  errMsg.textContent = "";

  const rawUrl = input.value.trim();
  if (!rawUrl) {
    errMsg.textContent = "Please enter a URL to scan.";
    input.focus();
    return;
  }

  // Show loading
  scanBtn.disabled = true;
  document.getElementById("resultSection").classList.add("hidden");
  document.getElementById("loadingSection").classList.remove("hidden");
  animateLoadingSteps();

  // Smooth scroll to loading
  document.getElementById("loadingSection").scrollIntoView({ behavior: "smooth", block: "start" });

  try {
    const resp = await fetch("/api/scan", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ url: rawUrl }),
    });

    const data = await resp.json();

    stopLoadingAnimation();
    document.getElementById("loadingSection").classList.add("hidden");
    scanBtn.disabled = false;

    if (!resp.ok || data.error) {
      errMsg.textContent = data.error || `Server error (${resp.status})`;
      return;
    }

    renderResults(data);

  } catch (err) {
    stopLoadingAnimation();
    document.getElementById("loadingSection").classList.add("hidden");
    scanBtn.disabled = false;
    errMsg.textContent = "Network error — is the server running?";
    console.error("Scan error:", err);
  }
}

// ── Enter key ─────────────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  const input = document.getElementById("urlInput");
  if (input) {
    input.addEventListener("keydown", e => {
      if (e.key === "Enter") startScan();
    });
  }
});

// ── Render results ────────────────────────────────────────────────────────────
function renderResults(data) {
  const resultSection = document.getElementById("resultSection");
  const verdictClass  = data.verdict_class;  // "safe" | "suspicious" | "phishing"

  // ── Verdict banner ────────────────────────────────────────────────────────
  const banner = document.getElementById("verdictBanner");
  banner.className = `verdict-banner ${verdictClass}`;

  document.getElementById("verdictEmoji").textContent  = data.verdict_emoji;
  document.getElementById("verdictLabel").textContent  = data.verdict;
  document.getElementById("verdictUrl").textContent    = data.url;
  document.getElementById("verdictScore").textContent  = data.final_score;
  document.getElementById("verdictConfidence").textContent =
    `${data.confidence} confidence · ${data.scan_time_s}s`;

  // ── Score bar ─────────────────────────────────────────────────────────────
  const fill = document.getElementById("scoreBarFill");
  requestAnimationFrame(() => {
    fill.style.width = `${Math.min(data.final_score, 100)}%`;
  });

  // ── Modules ───────────────────────────────────────────────────────────────
  renderModule("Url",   data.url_analysis,  25);
  renderModule("Ssl",   data.ssl_status,    20);
  renderModule("Whois", data.whois,         20, renderWhoisDetails);
  renderModule("Api",   data.api_result,    25, renderApiDetails);
  renderModule("Ml",    data.ml_result,     10);

  // ── Breakdown bars ────────────────────────────────────────────────────────
  renderBreakdown(data.score_breakdown);

  // ── Scan meta ─────────────────────────────────────────────────────────────
  document.getElementById("scanMeta").innerHTML =
    `<span>⏱ ${data.scan_time_s}s scan time</span>` +
    `<span>📊 Total: ${data.final_score}/100</span>` +
    `<span>🏁 ${new Date().toLocaleTimeString()}</span>`;

  // Show
  resultSection.classList.remove("hidden");
  resultSection.scrollIntoView({ behavior: "smooth", block: "start" });
}

// ── Render a module card ──────────────────────────────────────────────────────
function renderModule(key, moduleData, maxScore, detailFn) {
  const scoreEl = document.getElementById(`score${key}`);
  const flagsEl = document.getElementById(`flags${key}`);
  if (!scoreEl || !flagsEl || !moduleData) return;

  const score = moduleData.score || 0;

  // Score colour
  const ratio = score / maxScore;
  let cls = "low";
  if (ratio > 0.65)      cls = "high";
  else if (ratio > 0.3)  cls = "medium";
  scoreEl.textContent  = score;
  scoreEl.className    = `mod-score ${cls}`;

  // Flags
  flagsEl.innerHTML = "";
  (moduleData.flags || []).forEach(flag => {
    const li  = document.createElement("li");
    li.textContent = flag;
    if      (/\+\d+\)/.test(flag) && parseInt(flag.match(/\+(\d+)/)?.[1] || 0) > 5) li.classList.add("flag-bad");
    else if (/\+\d+\)/.test(flag)) li.classList.add("flag-warn");
    else if (/✓/.test(flag))       li.classList.add("flag-ok");
    flagsEl.appendChild(li);
  });

  // Optional details renderer
  if (detailFn) detailFn(key, moduleData.details);
}

// ── WHOIS detail rows ─────────────────────────────────────────────────────────
function renderWhoisDetails(key, details) {
  const el = document.getElementById(`details${key}`);
  if (!el || !details) return;
  el.innerHTML = "";

  const rows = [
    ["Registrar",  details.registrar],
    ["Country",    details.country],
    ["Domain Age", details.domain_age_days != null ? `${details.domain_age_days} days` : null],
    ["Expires",    details.days_to_expiry  != null ? `in ${details.days_to_expiry} days` : null],
    ["DNSSEC",     details.dnssec],
  ];

  rows.forEach(([k, v]) => {
    if (!v || v === "undefined" || v === "null") return;
    el.innerHTML += `<div class="detail-row">
      <span class="detail-key">${k}</span>
      <span class="detail-value">${escHtml(String(v))}</span>
    </div>`;
  });
}

// ── API/VirusTotal detail rows ────────────────────────────────────────────────
function renderApiDetails(key, details) {
  const el = document.getElementById(`details${key}`);
  if (!el || !details || details.error) return;
  el.innerHTML = "";

  if (details.total_engines != null) {
    const rows = [
      ["Engines scanned", details.total_engines],
      ["Flagged malicious", details.malicious],
      ["Flagged suspicious", details.suspicious],
      ["Harmless",          details.harmless],
      ["Reputation score",  details.reputation],
    ];
    rows.forEach(([k, v]) => {
      if (v == null) return;
      el.innerHTML += `<div class="detail-row">
        <span class="detail-key">${k}</span>
        <span class="detail-value">${escHtml(String(v))}</span>
      </div>`;
    });

    if (details.flagging_engines && details.flagging_engines.length > 0) {
      el.innerHTML += `<div class="detail-row">
        <span class="detail-key">Flagged by</span>
        <span class="detail-value" style="font-size:10px">${details.flagging_engines.slice(0,5).map(escHtml).join(", ")}</span>
      </div>`;
    }
  }
}

// ── Breakdown mini-bars ───────────────────────────────────────────────────────
const MODULE_MAX = {
  url_analysis: 25,
  ssl_check:    20,
  whois:        20,
  threat_api:   25,
  ml_model:     10,
};
const MODULE_LABEL = {
  url_analysis: "URL Analysis",
  ssl_check:    "SSL Check",
  whois:        "WHOIS",
  threat_api:   "Threat API",
  ml_model:     "ML Model",
};
const BAR_COLOURS = {
  url_analysis: "#00e5ff",
  ssl_check:    "#00ff88",
  whois:        "#aa88ff",
  threat_api:   "#ff9944",
  ml_model:     "#ff66aa",
};

function renderBreakdown(breakdown) {
  const el = document.getElementById("breakdownBars");
  if (!el) return;
  el.innerHTML = "";

  Object.entries(breakdown).forEach(([key, val]) => {
    const max   = MODULE_MAX[key] || 10;
    const pct   = Math.min((val / max) * 100, 100);
    const color = BAR_COLOURS[key] || "var(--green)";
    el.innerHTML += `
      <div class="bar-row">
        <span class="bar-label">${MODULE_LABEL[key] || key}</span>
        <div class="bar-track">
          <div class="bar-inner" style="width:0%;background:${color}" data-pct="${pct}"></div>
        </div>
        <span class="bar-value">${val}/${max}</span>
      </div>`;
  });

  // Animate bars after paint
  requestAnimationFrame(() => {
    el.querySelectorAll(".bar-inner").forEach(bar => {
      bar.style.width = bar.dataset.pct + "%";
    });
  });
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function escHtml(str) {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
