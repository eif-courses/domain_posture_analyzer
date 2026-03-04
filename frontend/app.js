// Simple frontend for: GET /api/v1/{domain}/summary
// Assumptions about response:
// {
//   domain, generated_at_utc?,
//   score or score_0_100,
//   level,
//   checks: { key: {status, value, note?, confidence?} },
//   recommendations: [...]
// }

const $ = (id) => document.getElementById(id);

const domainInput = $("domainInput");
const apiBaseInput = $("apiBaseInput");
const runBtn = $("runBtn");
const shareBtn = $("shareBtn");

const statusCard = $("statusCard");
const grid = $("grid");
const errorCard = $("errorCard");

const targetDomain = $("targetDomain");
const generatedAt = $("generatedAt");
const scoreEl = $("score");
const levelEl = $("level");
const pillsEl = $("pills");
const recsEl = $("recs");
const checksTable = $("checksTable");
const rawEl = $("raw");
const errorText = $("errorText");
const apiInfo = $("apiInfo");

function normalizeDomain(d) {
  return (d || "").trim().replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/\.$/, "");
}

function normalizeApiBase(u) {
  return (u || "").trim().replace(/\/+$/, "");
}

function statusClass(status) {
  const s = (status || "").toLowerCase();
  if (["good", "pass", "ok"].includes(s)) return "good";
  if (["warn", "warning"].includes(s)) return "warn";
  if (["bad", "fail", "error"].includes(s)) return "bad";
  return "info";
}

function escapeHtml(str) {
  return String(str ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

function setLoading(isLoading) {
  runBtn.disabled = isLoading;
  runBtn.textContent = isLoading ? "Running…" : "Run checks";
  statusCard.classList.toggle("loading", isLoading);
}

function showError(msg) {
  errorCard.style.display = "block";
  errorText.textContent = msg;
}

function clearError() {
  errorCard.style.display = "none";
  errorText.textContent = "";
}

// Truncate for pill display — full value shown in the table
function truncate(str, max = 48) {
  if (!str) return "";
  return str.length > max ? str.slice(0, max) + "…" : str;
}

function render(data) {
  statusCard.style.display = "block";
  grid.style.display = "grid";

  const domain = data.domain || "—";
  targetDomain.textContent = domain;

  const generated =
    data.generated_at_utc ||
    data.generatedAt ||
    data.generated_at ||
    null;

  generatedAt.textContent = generated ? `Generated: ${generated}` : "";

  const score = data.score_0_100 ?? data.score ?? "—";
  scoreEl.textContent = score;

  const level = data.level || "—";
  levelEl.textContent = level;

  // Priority order: email auth first, then web, then extras
  const PRIORITY = [
    "spf","dmarc","dkim","email_provider",
    "https_tls","http_to_https","hsts","csp",
    "mta_sts","tls_rpt","caa","dnssec","cookies",
    "security_txt","robots_txt",
  ];

  const checks = data.checks || {};
  const orderedKeys = [
    ...PRIORITY.filter(k => k in checks),
    ...Object.keys(checks).filter(k => !PRIORITY.includes(k)),
  ];

  // Pills — email + web security checks shown prominently
  pillsEl.innerHTML = "";
  for (const k of orderedKeys) {
    const item = checks[k] || {};
    const cls = statusClass(item.status);
    const label = k.replace(/_/g, " ");
    const shortVal = truncate(item.value ?? "");
    const li = document.createElement("li");
    li.className = `pill ${cls}`;
    li.title = item.value ?? "";
    li.innerHTML = `<span class="dot"></span><span class="pill-text"><strong>${escapeHtml(label)}</strong>: ${escapeHtml(shortVal)}</span>`;
    pillsEl.appendChild(li);
  }

  // Recommendations
  recsEl.innerHTML = "";
  const recs = data.recommendations || [];
  if (recs.length === 0) {
    const li = document.createElement("li");
    li.textContent = "No recommendations.";
    recsEl.appendChild(li);
  } else {
    for (const r of recs) {
      const li = document.createElement("li");
      li.textContent = r;
      li.style.marginBottom = "6px";
      recsEl.appendChild(li);
    }
  }

  // Checks table — full values, with optional note row
  checksTable.innerHTML = "";
  for (const k of orderedKeys) {
    const v = checks[k];
    const cls = statusClass(v?.status);
    const label = k.replace(/_/g, " ");
    const tr = document.createElement("tr");

    // Build value cell: value + optional confidence badge + optional note
    let valueHtml = `<div class="check-val">${escapeHtml(v?.value ?? "")}</div>`;
    if (v?.confidence && v.confidence !== "high") {
      valueHtml += `<div class="note">confidence: ${escapeHtml(v.confidence)}</div>`;
    }
    if (v?.note) {
      valueHtml += `<div class="note">${escapeHtml(v.note)}</div>`;
    }

    tr.innerHTML = `
      <td><code>${escapeHtml(label)}</code></td>
      <td><span class="status-badge ${cls}">${escapeHtml(v?.status ?? "")}</span></td>
      <td>${valueHtml}</td>
    `;
    checksTable.appendChild(tr);
  }

  // Raw JSON
  rawEl.textContent = JSON.stringify(data, null, 2);
}

async function run(domain) {
  clearError();

  const apiBase = normalizeApiBase(apiBaseInput.value || window.APP_API_BASE || "");
  if (!apiBase) {
    showError("Set API Base URL (e.g., https://your-api.example.com).");
    return;
  }

  const d = normalizeDomain(domain);
  if (!d) {
    showError("Enter a domain (e.g., example.com).");
    return;
  }

  apiInfo.textContent = `API: ${apiBase}`;
  setLoading(true);

  try {
    const url = `${apiBase}/api/v1/${encodeURIComponent(d)}/summary`;
    const res = await fetch(url, { method: "GET" });

    if (!res.ok) {
      const text = await res.text().catch(() => "");
      throw new Error(`HTTP ${res.status} ${res.statusText}${text ? " — " + text : ""}`);
    }

    const data = await res.json();
    render(data);
  } catch (err) {
    showError(err?.message || String(err));
    statusCard.style.display = "none";
    grid.style.display = "none";
  } finally {
    setLoading(false);
  }
}

function copyShareLink() {
  const d = normalizeDomain(domainInput.value);
  const url = new URL(window.location.href);
  if (d) url.searchParams.set("domain", d);
  navigator.clipboard.writeText(url.toString());
  shareBtn.textContent = "Copied!";
  setTimeout(() => (shareBtn.textContent = "Copy link"), 1000);
}

// Wire up UI
runBtn.addEventListener("click", () => run(domainInput.value));
shareBtn.addEventListener("click", copyShareLink);

domainInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") run(domainInput.value);
});

// Load from query params
(function initFromUrl() {
  const url = new URL(window.location.href);
  const d = url.searchParams.get("domain");
  if (d) domainInput.value = d;

  const api = url.searchParams.get("api");
  if (api) apiBaseInput.value = api;

  // If domain was provided, auto-run
  if (d && apiBaseInput.value) run(d);
})();
