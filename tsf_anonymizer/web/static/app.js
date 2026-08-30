/* TSF Anonymizer UI — vanilla JS, no build step. */
(() => {
  const $ = (s, el = document) => el.querySelector(s);
  const $$ = (s, el = document) => Array.from(el.querySelectorAll(s));
  const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  const fmtBytes = (b) => b < 1024 ? `${b} B` : b < 1048576 ? `${(b / 1024).toFixed(1)} KB` : b < 1073741824 ? `${(b / 1048576).toFixed(1)} MB` : `${(b / 1073741824).toFixed(2)} GB`;
  const fmtDate = (t) => new Date(t * 1000).toLocaleString("en-GB");
  const state = { jobId: null, pollTimer: null, filter: "error,warning", q: "" };

  // ---- tabs --------------------------------------------------------------
  $$("nav .tab").forEach((b) => b.addEventListener("click", () => showTab(b.dataset.tab)));
  function showTab(name) {
    $$("nav .tab").forEach((b) => b.classList.toggle("active", b.dataset.tab === name));
    $$(".tab-panel").forEach((p) => p.classList.toggle("active", p.id === `tab-${name}`));
    $("#job-view").hidden = true;
    if (name === "jobs") loadJobs();
  }

  // ---- uploads -----------------------------------------------------------
  function uploadForm(form, url) {
    form.addEventListener("submit", (ev) => {
      ev.preventDefault();
      const fd = new FormData(form);
      const prog = $(".upload-progress", form), bar = $(".bar", prog), label = $(".label", prog);
      const btn = $("button[type=submit]", form);
      prog.hidden = false; btn.disabled = true;
      const xhr = new XMLHttpRequest();
      xhr.open("POST", url);
      xhr.upload.onprogress = (e) => {
        if (!e.lengthComputable) return;
        const pct = Math.round((e.loaded / e.total) * 100);
        bar.style.width = pct + "%";
        label.textContent = `uploading ${fmtBytes(e.loaded)} / ${fmtBytes(e.total)} (${pct}%)`;
      };
      xhr.onload = () => {
        btn.disabled = false;
        if (xhr.status >= 200 && xhr.status < 300) {
          const job = JSON.parse(xhr.responseText);
          form.reset(); prog.hidden = true; bar.style.width = "0";
          openJob(job.id);
        } else {
          label.textContent = `upload failed: ${xhr.status} ${xhr.responseText.slice(0, 200)}`;
        }
      };
      xhr.onerror = () => { btn.disabled = false; label.textContent = "upload failed (network)"; };
      xhr.send(fd);
    });
  }
  uploadForm($("#form-anonymize"), "/api/jobs/anonymize");
  uploadForm($("#form-compare"), "/api/jobs/compare");

  // ---- jobs list ---------------------------------------------------------
  async function loadJobs() {
    const jobs = await (await fetch("/api/jobs")).json();
    const tb = $("#jobs-table tbody");
    tb.innerHTML = jobs.map((j) => {
      const s = j.compare_summary;
      const integ = s ? (s.errors ? `<span class="status status-error">${s.errors} error(s)</span>` :
        s.warnings ? `<span class="status status-warning">${s.warnings} warning(s)</span>` :
        `<span class="status status-done">OK</span>`) : "—";
      return `<tr class="clickable" data-id="${j.id}">
        <td>${fmtDate(j.created_at)}</td><td>${j.kind}</td>
        <td class="mono">${esc(j.input_name)}${j.anon_input_name ? " ↔ " + esc(j.anon_input_name) : ""}</td>
        <td><span class="status status-${j.status}">${j.status}</span></td><td>${integ}</td>
        <td><button class="secondary" data-open="${j.id}">open</button>
            <button class="danger" data-del="${j.id}">delete</button></td></tr>`;
    }).join("") || `<tr><td colspan="6" class="notes">no jobs yet</td></tr>`;
    $$("[data-open]", tb).forEach((b) => b.addEventListener("click", (e) => { e.stopPropagation(); openJob(b.dataset.open); }));
    $$("[data-del]", tb).forEach((b) => b.addEventListener("click", async (e) => {
      e.stopPropagation();
      if (!confirm("Delete this job and every file it holds (input, output, extracted trees)?")) return;
      await fetch(`/api/jobs/${b.dataset.del}`, { method: "DELETE" });
      loadJobs();
    }));
    $$("tr.clickable", tb).forEach((tr) => tr.addEventListener("click", () => openJob(tr.dataset.id)));
  }

  // ---- job view ----------------------------------------------------------
  async function openJob(id) {
    state.jobId = id;
    clearTimeout(state.pollTimer);
    $$(".tab-panel").forEach((p) => p.classList.remove("active"));
    $$("nav .tab").forEach((b) => b.classList.remove("active"));
    $("#job-view").hidden = false;
    $("#job-summary").hidden = true; $("#job-files").hidden = true; $("#diff-view").hidden = true;
    await pollJob();
  }

  async function pollJob() {
    const r = await fetch(`/api/jobs/${state.jobId}`);
    if (!r.ok) { $("#job-header").innerHTML = `<p>job not found</p>`; return; }
    const job = await r.json();
    renderHeader(job);
    if (job.status === "queued" || job.status === "running") {
      state.pollTimer = setTimeout(pollJob, 1000);
    } else if (job.status === "done") {
      renderSummary(job);
      await loadFiles();
    }
  }

  function renderHeader(job) {
    const pct = job.progress_total ? Math.round((job.progress_done / job.progress_total) * 100) : 0;
    const running = job.status === "queued" || job.status === "running";
    const dl = Object.entries(job.outputs || {}).map(([k, v]) =>
      `<a href="/api/jobs/${job.id}/download/${k}" download>${{ tgz: "⬇ anonymized TSF", mapping: "⬇ mapping.json", integrity_report: "⬇ integrity report", anonymize_report: "⬇ anonymize report" }[k] || k}</a>`).join("");
    $("#job-header").innerHTML = `
      <div class="toolbar"><h2>${job.kind} · <span class="mono">${esc(job.input_name)}${job.anon_input_name ? " ↔ " + esc(job.anon_input_name) : ""}</span></h2>
        <span class="status status-${job.status}">${job.status}</span>
        <span style="flex:1"></span>
        <button class="secondary" id="back-jobs">← jobs</button></div>
      ${running ? `<div class="upload-progress"><div class="bar" style="width:${pct}%"></div>
        <span class="label">${esc(job.phase)} ${job.progress_done}/${job.progress_total} ${esc(job.message)}</span></div>` : ""}
      ${job.error ? `<div class="verdict bad">${esc(job.error)}</div>` : ""}
      ${job.status === "done" ? `<div class="actions">${dl}
        ${job.trees_kept ? `<button class="secondary" id="purge-trees">free disk (purge extracted trees)</button>` : `<span class="notes">extracted trees purged — diff viewer unavailable</span>`}</div>` : ""}
      ${job.seed_mapping ? `<p class="notes">seeded from a previous mapping</p>` : ""}`;
    $("#back-jobs").addEventListener("click", () => showTab("jobs"));
    const purge = $("#purge-trees");
    if (purge) purge.addEventListener("click", async () => {
      if (!confirm("Purge the extracted trees? Downloads stay available; the diff viewer will not.")) return;
      await fetch(`/api/jobs/${job.id}/purge-trees`, { method: "POST" });
      pollJob();
    });
  }

  function kpi(label, v, cls = "") { return `<div class="kpi ${cls}"><div class="v">${v}</div><div class="k">${label}</div></div>`; }
  function renderSummary(job) {
    const s = job.compare_summary, a = job.anonymize_summary, arc = job.archive_check || {};
    let html = "";
    if (s) {
      const bad = s.errors > 0 || (arc.mismatches || []).length > 0;
      html += `<div class="verdict ${bad ? "bad" : s.warnings ? "warn" : "ok"}">
        ${bad ? "✗ Integrity problems found — review the errors below before sharing this archive."
              : s.warnings ? "⚠ Anonymization consistent, with warnings to review."
              : "✓ Every difference is explained by the mapping, nothing identifying survives, structure intact."}</div>`;
      html += `<div class="kpis">
        ${kpi("files compared", s.files_total)}
        ${kpi("identical", s.identical)}
        ${kpi("anonymized", s.anonymized, "ok")}
        ${kpi("warnings", s.warnings, s.warnings ? "warn" : "")}
        ${kpi("errors", s.errors, s.errors ? "err" : "ok")}
        ${kpi("changed lines", s.changed_lines)}
        ${kpi("explained by mapping", s.explained_lines, "ok")}
        ${kpi("unexplained", s.unexplained_lines, s.unexplained_lines ? "warn" : "ok")}
        ${kpi("surviving identifiers (text)", s.leaks_total, s.leaks_total ? "err" : "ok")}
        ${kpi("binaries w/ identifiers", s.binary_files_with_identifiers, s.binary_files_with_identifiers ? "warn" : "ok")}
        ${kpi("binary files identical", `${s.binary_identical}/${s.binary_files}`, s.binary_identical === s.binary_files ? "ok" : "err")}
        ${kpi("line-count mismatches", s.line_count_mismatches, s.line_count_mismatches ? "err" : "ok")}
        ${kpi("timestamp mismatches", s.timestamp_mismatches, s.timestamp_mismatches ? "warn" : "ok")}
        ${kpi("numeric-token mismatches", s.numeric_mismatches, s.numeric_mismatches ? "warn" : "ok")}
        ${kpi("XML structure preserved", `${s.xml_checked - s.xml_structure_changed}/${s.xml_checked}`, s.xml_structure_changed ? "err" : "ok")}
      </div>`;
      if (arc.members_orig !== undefined) {
        html += `<p class="notes">archive: ${arc.members_orig} → ${arc.members_anon} members, order ${arc.order_preserved ? "preserved" : "<b>changed</b>"}, ${arc.metadata_differences} metadata difference(s)${(arc.mismatches || []).length ? " — " + arc.mismatches.map(esc).join("; ") : ""}</p>`;
      }
    }
    if (a) {
      html += `<details><summary>anonymization stats</summary><div class="kpis">
        ${kpi("files", a.files_total)}${kpi("modified", a.modified)}${kpi("binary (untouched)", a.binary)}${kpi("errors", a.errors, a.errors ? "err" : "")}
        ${kpi("config files scanned", a.config_files_scanned)}${kpi("duration", `${a.duration_s.toFixed(1)}s`)}
        ${Object.entries(a.mapping_sizes || {}).map(([k, v]) => kpi(k.replace("_", " ") + " mapped", v)).join("")}
        ${Object.entries(a.replacements || {}).map(([k, v]) => kpi(k.replace("_", " ") + " replaced", v)).join("")}
      </div></details>`;
    }
    $("#job-summary").innerHTML = html; $("#job-summary").hidden = false;
  }

  // ---- file table --------------------------------------------------------
  $("#file-filter").addEventListener("change", (e) => { state.filter = e.target.value; loadFiles(); });
  $("#file-search").addEventListener("keydown", (e) => { if (e.key === "Enter") { state.q = e.target.value; loadFiles(); } });

  async function loadFiles() {
    const params = new URLSearchParams({ limit: 2000 });
    if (state.filter) params.set("status", state.filter);
    if (state.q) params.set("q", state.q);
    const r = await fetch(`/api/jobs/${state.jobId}/report?${params}`);
    if (!r.ok) return;
    const data = await r.json();
    $("#file-count").textContent = `${data.files.length} of ${data.total} shown`;
    const tb = $("#files-table tbody");
    tb.innerHTML = data.files.map((f) => `<tr class="clickable" data-path="${esc(f.path)}">
      <td class="mono">${esc(f.path)}</td><td>${f.kind}</td>
      <td><span class="status status-${f.status}">${f.status}</span></td>
      <td>${f.kind.includes("text") ? `${f.lines_orig}${f.lines_orig !== f.lines_anon ? " → <b>" + f.lines_anon + "</b>" : ""}` : fmtBytes(f.orig_size)}</td>
      <td>${f.changed_lines || ""}</td><td>${f.unexplained_lines || ""}</td>
      <td>${f.leak_count ? `<b>${f.leak_count}</b>` : ""}</td>
      <td class="notes">${(f.notes || []).map(esc).join("; ")}${f.leak_count ? `<details><summary>identifiers</summary><ul class="leaks">${Object.entries(f.leaks).map(([k, v]) => `<li class="mono">${esc(k)} ×${v}</li>`).join("")}</ul></details>` : ""}</td>
    </tr>`).join("") || `<tr><td colspan="8" class="notes">nothing matches this filter</td></tr>`;
    $$("tr.clickable", tb).forEach((tr) => tr.addEventListener("click", (e) => {
      if (e.target.closest("details")) return;
      openDiff(tr.dataset.path);
    }));
    $("#job-files").hidden = false;
  }

  // ---- diff viewer -------------------------------------------------------
  $("#diff-close").addEventListener("click", () => { $("#diff-view").hidden = true; });
  $("#diff-context").addEventListener("change", () => { if (state.diffPath) openDiff(state.diffPath); });

  function highlight(text, spans, side) {
    if (!spans || !spans.length) return esc(text);
    let out = "", pos = 0;
    for (const [i1, i2, j1, j2] of spans) {
      const s = side === "o" ? i1 : j1, e = side === "o" ? i2 : j2;
      out += esc(text.slice(pos, s)) + (e > s ? `<mark>${esc(text.slice(s, e))}</mark>` : "");
      pos = e;
    }
    return out + esc(text.slice(pos));
  }
  function rowHtml(r) {
    const cls = r.changed ? (r.explained === false ? "changed unexplained" : "changed") : "";
    return `<tr class="${cls}"><td class="n">${r.n}</td><td class="o">${highlight(r.orig ?? "", r.spans, "o")}</td>
      <td class="m">${r.changed ? (r.explained === false ? "✗" : "→") : ""}</td><td class="a">${highlight(r.anon ?? "", r.spans, "a")}</td></tr>`;
  }
  async function openDiff(path) {
    state.diffPath = path;
    const ctx = $("#diff-context").value || 3;
    const r = await fetch(`/api/jobs/${state.jobId}/diff?path=${encodeURIComponent(path)}&context=${ctx}`);
    const body = $("#diff-body");
    $("#diff-title").textContent = path;
    $("#diff-view").hidden = false;
    if (!r.ok) { body.innerHTML = `<p class="notes">${esc((await r.text()).slice(0, 300))}</p>`; return; }
    const d = await r.json();
    if (d.error) { body.innerHTML = `<p class="notes">${esc(d.error)}</p>`; return; }
    if (d.binary) {
      body.innerHTML = `<p>binary file (${d.kind}) — ${d.identical ? "byte-identical on both sides" : "<b>payload differs</b>"} · ${fmtBytes(d.orig_size)} / ${fmtBytes(d.anon_size)}</p>`;
      return;
    }
    if (!d.changed_lines) {
      body.innerHTML = `<p class="notes">no changed lines (${d.total_lines} lines). </p>
        <button class="secondary" id="browse">browse first 200 lines</button>`;
      $("#browse").addEventListener("click", () => browse(path, 1));
      return;
    }
    let html = `<p class="notes">${d.changed_lines} changed line(s) of ${d.total_lines}${d.truncated ? " — showing the first hunks only" : ""}. Red outline = change not explained by the mapping. <button class="secondary" id="browse">browse whole file</button></p>`;
    html += `<table class="diff"><colgroup><col class="n"><col><col class="m"><col></colgroup>`;
    for (const h of d.hunks) {
      html += `<tr class="hunk-sep"><td colspan="4">lines ${h.start}–${h.end}</td></tr>` + h.rows.map(rowHtml).join("");
    }
    body.innerHTML = html + "</table>";
    $("#browse").addEventListener("click", () => browse(path, 1));
    $("#diff-view").scrollIntoView({ behavior: "smooth", block: "start" });
  }
  async function browse(path, start) {
    const r = await fetch(`/api/jobs/${state.jobId}/diff?path=${encodeURIComponent(path)}&window=200&start_line=${start}`);
    const d = await r.json();
    const end = d.start_line + d.rows.length - 1;
    $("#diff-body").innerHTML = `<p class="notes">lines ${d.start_line}–${end} of ${d.total_lines}
      <button class="secondary" id="prev" ${d.start_line <= 1 ? "disabled" : ""}>← prev</button>
      <button class="secondary" id="next" ${end >= d.total_lines ? "disabled" : ""}>next →</button></p>
      <table class="diff"><colgroup><col class="n"><col><col class="m"><col></colgroup>${d.rows.map(rowHtml).join("")}</table>`;
    $("#prev").addEventListener("click", () => browse(path, Math.max(1, d.start_line - 200)));
    $("#next").addEventListener("click", () => browse(path, end + 1));
  }

  // ---- boot --------------------------------------------------------------
  const hash = location.hash.replace("#", "");
  if (hash.startsWith("job/")) openJob(hash.slice(4)); else loadJobs();
})();
