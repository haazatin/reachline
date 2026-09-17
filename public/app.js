const form = document.querySelector("#check-form");
const input = document.querySelector("#target");
const result = document.querySelector("#result");
const submit = form.querySelector("button[type='submit']");

document.querySelectorAll("[data-value]").forEach((button) => {
  button.addEventListener("click", () => {
    input.value = button.dataset.value;
    input.focus();
  });
});

function escapeHtml(value) {
  return String(value).replace(/[&<>'"]/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" })[character]);
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const target = input.value.trim();
  if (!target) return;
  submit.disabled = true;
  result.hidden = false;
  result.innerHTML = '<div class="loading">Tracing available signals</div>';
  result.scrollIntoView({ behavior: "smooth", block: "center" });
  try {
    const response = await fetch("/api/check", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ target }),
    });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || "The check failed.");
    const title = `${payload.target.host}${payload.target.path || ""}`;
    result.innerHTML = `
      <div class="result-head">
        <span class="verdict ${escapeHtml(payload.verdict)}">${escapeHtml(payload.verdict.replace("-", " "))}</span>
        <div><h2>${escapeHtml(title)}</h2><p>${escapeHtml(payload.summary)}</p></div>
        <span class="elapsed">${escapeHtml(payload.durationMs)} ms total</span>
      </div>
      <ol class="steps">${payload.steps.map((step) => `<li><span class="step-label">${escapeHtml(step.label)}</span><span class="step-detail">${escapeHtml(step.detail)}</span><span class="step-time">${step.durationMs == null ? "" : `${escapeHtml(step.durationMs)} ms`}</span></li>`).join("")}</ol>
      <div class="result-note">Perspective matters: checks run from this server's network, not from your browser. Silent probes may mean a firewall, ACL, VPN boundary, or routing issue—not necessarily a powered-off machine.</div>`;
  } catch (error) {
    result.innerHTML = `<div class="error-box"><strong>Check not completed</strong><br>${escapeHtml(error.message || "Unexpected error")}</div>`;
  } finally {
    submit.disabled = false;
  }
});
