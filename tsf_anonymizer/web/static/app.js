/* TSF Anonymizer UI — vanilla JS, no build step. */
(() => {
  const $ = (s, el = document) => el.querySelector(s);
  const $$ = (s, el = document) => Array.from(el.querySelectorAll(s));
  const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  const fmtBytes = (b) => b < 1024 ? `${b} B` : b < 1048576 ? `${(b / 1024).toFixed(1)} KB` : b < 1073741824 ? `${(b / 1048576).toFixed(1)} MB` : `${(b / 1073741824).toFixed(2)} GB`;
  const fmtDate = (t) => new Date(t * 1000).toLocaleString("en-GB");
  const fmtDur = (s) => s < 60 ? `${Math.round(s)}s`
    : s < 3600 ? `${Math.floor(s / 60)}m${String(Math.round(s % 60)).padStart(2, "0")}s`
    : `${Math.floor(s / 3600)}h${String(Math.floor((s % 3600) / 60)).padStart(2, "0")}`;
  const state = { jobId: null, pollTimer: null, listTimer: null, filter: "error,warning", q: "" };

  // ---- tabs --------------------------------------------------------------
  $$("nav .tab").forEach((b) => b.addEventListener("click", () => showTab(b.dataset.tab)));
  function showTab(name) {
    $$("nav .tab").forEach((b) => b.classList.toggle("active", b.dataset.tab === name));
    $$(".tab-panel").forEach((p) => p.classList.toggle("active", p.id === `tab-${name}`));
    // Leaving a running job used to leave its 1 s poll alive, refreshing a
    // panel nobody can see.
    clearTimeout(state.pollTimer);
    clearTimeout(state.listTimer);
    $("#job-view").hidden = true;
    if (name === "jobs") loadJobs();
  }

  // ---- uploads -----------------------------------------------------------
  function uploadForm(form, url) {
    form.addEventListener("submit", (ev) => {
      ev.preventDefault();
      const fd = new FormData(form);
      // An unchecked checkbox is absent from FormData; the API needs an explicit false.
      const cb = form.querySelector("input[name=delete_original]");
      if (cb) fd.set("delete_original", cb.checked ? "true" : "false");
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
  uploadForm($("#form-compare"), "/api/jobs/compare");

  // ---- anonymize: drag & drop, one job per archive ------------------------
  // Archives are uploaded one after the other: a TSF is hundreds of MB, and the
  // worker runs them sequentially anyway.
  const TSF_NAME = /\.(tgz|tar\.gz|tar)$/i;
  // One entry per archive: the File, and the firewall it belongs to. Archives
  // sharing a firewall name share one growing mapping; different names never
  // link an identifier from one device to another.
  const picked = [];
  const form = $("#form-anonymize"), dz = $("#drop-zone"), fileInput = $("#tsf-files");
  const batchLog = $("#batch-log");

  // Without this a file dropped next to the zone replaces the page with it.
  ["dragover", "drop"].forEach((e) => document.addEventListener(e, (ev) => ev.preventDefault()));

  // PAN-OS names a TSF <date>_<time>_techsupport.tgz — no device in it. What a
  // human added around that generic part usually *is* the device, so strip the
  // generic part and keep the rest as a first guess. It is only a guess: the
  // field it fills is editable, and grouping is what the user decides.
  function guessDevice(name) {
    const s = name.replace(TSF_NAME, "")
      .replace(/\d{4}[-_.]?\d{2}[-_.]?\d{2}([-_.]?\d{2}[-_.:]?\d{2}([-_.:]?\d{2})?)?/g, " ")
      .replace(/tech[-_ ]?support|tsf|anon(ymized)?|\(\d+\)|\bcopy\b/gi, " ")
      .replace(/[^A-Za-z0-9.-]+/g, " ").trim()
      .replace(/\s+/g, "-").replace(/-{2,}/g, "-").replace(/^[-.]+|[-.]+$/g, "");
    return /[A-Za-z]/.test(s) ? s.toLowerCase().slice(0, 40) : "";
  }

  function seedPolicy() {
    return picked.length > 1 ? $("input[name=seed_policy]:checked").value : "shared";
  }

  // How many mappings a per-firewall batch will produce: one per name, plus one
  // for each file left unnamed (an unnamed file is nobody else's device).
  function deviceCount() {
    const named = new Set(picked.map((p) => p.device.trim()).filter(Boolean));
    return named.size + picked.filter((p) => !p.device.trim()).length;
  }

  function addFiles(files) {
    let ignored = 0;
    for (const f of files) {
      if (!TSF_NAME.test(f.name)) { ignored++; continue; }
      if (picked.some((p) => p.f.name === f.name && p.f.size === f.size)) continue;
      picked.push({ f, device: guessDevice(f.name) });
    }
    batchLog.textContent = ignored ? `${ignored} file(s) ignored — TSFs are .tgz archives` : "";
    renderPicked();
  }

  function pickedSummary() {
    const total = picked.reduce((s, p) => s + p.f.size, 0);
    const n = deviceCount();
    return `${picked.length} archives · ${fmtBytes(total)} total` +
      (seedPolicy() === "device" ? ` · ${n} firewall${n > 1 ? "s" : ""}, ${n} mapping${n > 1 ? "s" : ""}` : "");
  }

  function renderPicked() {
    const perDevice = seedPolicy() === "device";
    $("#file-list").innerHTML = picked.map((p, i) =>
      `<li><span class="mono">${esc(p.f.name)}</span>${perDevice ? `
       <input class="dev" type="text" data-dev="${i}" maxlength="40" placeholder="firewall"
              value="${esc(p.device)}" title="archives carrying the same name share one mapping">` : ""}
       <span class="opt">${fmtBytes(p.f.size)}</span>
       <button type="button" class="link" data-drop="${i}" title="remove">✕</button></li>`).join("")
      + (picked.length > 1 ? `<li class="notes" id="picked-summary">${esc(pickedSummary())}</li>` : "");
    $$("[data-drop]").forEach((b) => b.addEventListener("click", () => {
      picked.splice(Number(b.dataset.drop), 1); renderPicked();
    }));
    // Typing a name must not re-render the row under the caret, so the summary
    // is the only thing refreshed here.
    $$("[data-dev]").forEach((inp) => inp.addEventListener("input", () => {
      picked[Number(inp.dataset.dev)].device = inp.value;
      $("#picked-summary").textContent = pickedSummary();
    }));
    $("#batch-seed").hidden = picked.length === 0;
    $("#seed-policy").hidden = picked.length < 2;
    // One name for the whole drop only makes sense when the whole drop is one
    // mapping; per-firewall names live in the list, and "separate" names nothing.
    $("#device-one").hidden = picked.length > 1 && seedPolicy() !== "shared";
  }

  $$("input[name=seed_policy]").forEach((r) => r.addEventListener("change", renderPicked));

  dz.addEventListener("dragover", () => dz.classList.add("over"));
  dz.addEventListener("dragleave", () => dz.classList.remove("over"));
  dz.addEventListener("drop", (ev) => { dz.classList.remove("over"); addFiles(ev.dataTransfer.files); });
  $("#pick-files").addEventListener("click", () => fileInput.click());
  fileInput.addEventListener("change", () => { addFiles(fileInput.files); fileInput.value = ""; });

  function postJob(fd, label) {
    const prog = $(".upload-progress", form), bar = $(".bar", prog), lbl = $(".label", prog);
    prog.hidden = false;
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open("POST", "/api/jobs/anonymize");
      xhr.upload.onprogress = (e) => {
        if (!e.lengthComputable) return;
        const pct = Math.round((e.loaded / e.total) * 100);
        bar.style.width = pct + "%";
        lbl.textContent = `${label} — ${fmtBytes(e.loaded)} / ${fmtBytes(e.total)} (${pct}%)`;
      };
      xhr.onload = () => xhr.status >= 200 && xhr.status < 300
        ? resolve(JSON.parse(xhr.responseText))
        : reject(new Error(`${xhr.status} ${xhr.responseText.slice(0, 200)}`));
      xhr.onerror = () => reject(new Error("network error"));
      xhr.send(fd);
    });
  }

  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    if (!picked.length) { batchLog.textContent = "drop at least one TSF archive"; return; }
    const btn = $("button[type=submit]", form);
    const seedFile = $("input[name=seed_mapping]", form).files[0] || null;
    const del = $("input[name=delete_original]", form).checked;
    const redact = $("input[name=redact_binaries]", form).checked;
    // One shared mapping is only a question when there is more than one archive.
    const policy = seedPolicy();
    const batch = picked.length > 1 ? `b${Date.now().toString(36)}` : null;
    const oneName = $("#batch-device").value.trim();
    // The group is what the server chains on: same group → same growing
    // mapping. "shared" gives the whole drop one group (the firewall typed
    // above, or a one-off id that chains inside this batch only), "device"
    // gives each file its own firewall — unnamed files get a one-off id so
    // they never fall into the same group by accident — and "separate" gives
    // no group at all, which is how an archive starts from a fresh mapping.
    const groupOf = (i) =>
      policy === "separate" ? "" :
      policy === "device" ? (picked[i].device.trim() || `${batch}-${i + 1}`) :
      (oneName || batch || "");
    const outcome = policy === "device" ? `${deviceCount()} mapping(s), one per firewall`
      : policy === "separate" ? "a separate mapping each" : "one shared mapping";
    btn.disabled = true;
    const ids = [], seeded = new Set();
    try {
      for (let i = 0; i < picked.length; i++) {
        const group = groupOf(i);
        const fd = new FormData();
        fd.set("file", picked[i].f);
        fd.set("delete_original", del ? "true" : "false");
        fd.set("redact_binaries", redact ? "true" : "false");
        if (batch) fd.set("batch", batch);
        if (group) fd.set("group", group);
        // An uploaded seed starts every chain: the first archive of each group
        // gets it, the rest inherit it through their group's previous job, so
        // the mapping keeps growing instead of restarting.
        if (seedFile && !(group && seeded.has(group))) fd.set("seed_mapping", seedFile);
        seeded.add(group);
        batchLog.textContent = `queuing ${i + 1} of ${picked.length}…`;
        const job = await postJob(fd, `uploading ${i + 1}/${picked.length}: ${picked[i].f.name}`);
        ids.push(job.id);
      }
    } catch (e) {
      batchLog.textContent = `upload failed on ${picked[ids.length]?.f.name}: ${e.message}` +
        (ids.length ? ` — ${ids.length} archive(s) already queued` : "");
      btn.disabled = false;
      return;
    }
    btn.disabled = false;
    picked.length = 0; renderPicked();
    form.reset();
    $(".upload-progress", form).hidden = true; $(".bar", form).style.width = "0";
    batchLog.textContent = ids.length > 1 ? `${ids.length} archives queued — ${outcome}` : "";
    if (ids.length === 1) openJob(ids[0]); else showTab("jobs");
  });

  // ---- jobs list ---------------------------------------------------------
  // The list is where a batch is watched: one archive at a time, hours of it.
  // Without a refresh of its own it stays frozen on the state it had when the
  // tab was opened, which reads as "nothing is happening".
  async function loadJobs() {
    clearTimeout(state.listTimer);
    const jobs = await (await fetch("/api/jobs")).json();
    const now = Date.now() / 1000;
    const queue = jobs.filter((j) => j.status === "queued").sort((a, b) => a.created_at - b.created_at);
    const tb = $("#jobs-table tbody");
    tb.innerHTML = jobs.map((j) => {
      const s = j.compare_summary;
      const integ = s ? (s.errors ? `<span class="status status-error">${s.errors} error(s)</span>` :
        s.warnings ? `<span class="status status-warning">${s.warnings} warning(s)</span>` :
        `<span class="status status-done">OK</span>`) : "—";
      return `<tr class="clickable" data-id="${j.id}" title="${esc(j.error || "")}">
        <td>${fmtDate(j.created_at)}</td><td>${j.kind}</td>
        <td class="mono">${esc(j.input_name)}${j.anon_input_name ? " ↔ " + esc(j.anon_input_name) : ""}${j.group ? `<span class="opt"> · ${esc(j.group)}</span>` : ""}</td>
        <td><span class="status status-${j.status}">${j.status}</span>${liveDetail(j, now, queue)}</td><td>${integ}</td>
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
    if (jobs.some((j) => j.status === "queued" || j.status === "running")
        && $("#tab-jobs").classList.contains("active")) {
      state.listTimer = setTimeout(loadJobs, 2000);
    }
  }

  // Phase names are internal identifiers; what a human watches is a step with
  // a name. The order is the order the run actually goes through them.
  const PHASE_LABEL = {
    extract: "extracting", copy: "working copy", prescan: "config scan",
    "prescan-text": "identity scan", anonymize: "rewriting", repack: "repacking",
    compare: "comparing", verify: "archive check", finished: "finishing",
  };
  const PHASE_SEQ = {
    anonymize: ["extract", "copy", "prescan", "prescan-text", "anonymize", "repack", "compare", "verify"],
    compare: ["extract", "compare", "verify"],
  };
  const phaseLabel = (p) => PHASE_LABEL[p] || p;

  // What a row of the list can say about a job that has not finished: which
  // phase of how many it is in (a segmented bar — a plain bar restarts at 0 %
  // on every phase and reads as "it went backwards"), how far that phase is,
  // how long the job has been running, whether it has gone quiet — and, for
  // the ones still waiting, where they are in the queue.
  function liveDetail(job, now, queue) {
    if (job.status === "queued") {
      const i = queue.findIndex((q) => q.id === job.id);
      return `<span class="opt"> ${i === 0 ? "next" : `#${i + 1} in queue`}</span>`;
    }
    if (job.status !== "running") return "";
    const seq = PHASE_SEQ[job.kind] || [];
    const idx = seq.indexOf(job.phase);
    const pct = job.progress_total ? Math.round((job.progress_done / job.progress_total) * 100) : 0;
    const idle = job.updated_at ? Math.max(0, now - job.updated_at) : 0;
    const segs = seq.map((p, i) => {
      const fill = idx < 0 ? 0 : i < idx ? 100 : i === idx ? pct : 0;
      return `<div class="seg${i === idx ? " cur" : ""}" title="${esc(phaseLabel(p))}">
        <div class="fill" style="width:${fill}%"></div></div>`;
    }).join("");
    return `<div class="row-progress segs" title="${esc(phaseLabel(job.phase))} ${job.progress_done}/${job.progress_total}">${segs}</div>
      <span class="opt">${idx >= 0 ? `${idx + 1}/${seq.length} · ` : ""}${esc(phaseLabel(job.phase))} ${pct}% · ${
        fmtDur(Math.max(0, now - (job.started_at || now)))}${
        idle > 30 ? ` · <b>quiet for ${fmtDur(idle)}</b>` : ""}</span>`;
  }

  // ---- job view ----------------------------------------------------------
  async function openJob(id) {
    state.jobId = id;
    clearTimeout(state.pollTimer);
    clearTimeout(state.listTimer);
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

  // The verdict, computed once: the flow step and the banner must never be able
  // to disagree.
  function verdict(job) {
    const s = job.compare_summary, arc = job.archive_check || {};
    if (!s) return null;
    if (s.errors > 0 || (arc.mismatches || []).length > 0) {
      return { cls: "bad", short: "problems found",
               long: "✗ Integrity problems found — review the errors below before sharing this archive." };
    }
    if (s.warnings) {
      return { cls: "warn", short: `${s.warnings} to review`,
               long: "⚠ Anonymization consistent, with warnings to review." };
    }
    return { cls: "ok", short: "no loss, no leak",
             long: "✓ Every difference is explained by the mapping, nothing identifying survives, structure intact." };
  }

  // upload → anonymize → independent check → verdict. The check step is named
  // after the only thing that makes it worth anything: it re-derives what it
  // expects from the mapping, it never asks the anonymizer what it did.
  const ANON_PHASES = ["extract", "copy", "prescan", "prescan-text", "anonymize", "repack"];
  const CHECK_PHASES = ["compare", "verify"];

  function renderFlow(job) {
    const v = verdict(job);
    const pd = job.phase_durations || {};
    const stepDur = (phases) => phases.reduce((t, p) => t + (pd[p] || 0), 0);
    const steps = [{ label: "Upload", hint: job.input_name, phases: [] }];
    if (job.kind === "anonymize") {
      steps.push({ label: "Anonymize", hint: "identifiers → pseudonyms", phases: ANON_PHASES });
    }
    steps.push({ label: "Independent check", hint: "re-derived from the mapping alone",
                 phases: CHECK_PHASES });
    steps.push({ label: "Verdict", hint: v ? v.short : "problem or not", phases: [], verdict: v });

    const running = job.status === "queued" || job.status === "running";
    let active = steps.findIndex((s) => s.phases.includes(job.phase));
    // Queued, or between two phases: the upload is the only thing certainly done.
    if (active < 0) active = running ? (job.phase ? steps.length - 2 : 0) : steps.length - 1;

    return `<ol class="flow">` + steps.map((s, i) => {
      let cls = i < active ? "done" : i > active ? "todo" : "active";
      if (!running && i === steps.length - 1) cls = v ? `done ${v.cls}` : "todo";
      if (job.error && i === active) cls = "failed";
      // A step earns a better detail line the moment it has one: the active
      // step says which of its phases is running and how far, a step that ran
      // says how long it took, a failed one names the phase that broke.
      const took = stepDur(s.phases);
      const pct = job.progress_total ? Math.round((job.progress_done / job.progress_total) * 100) : 0;
      const inStep = s.phases.indexOf(job.phase);
      let detail = esc(s.hint || "");
      if (cls === "active" && inStep >= 0) {
        detail = `${esc(phaseLabel(job.phase))} ${inStep + 1}/${s.phases.length} · ${pct}%`;
      } else if (cls === "failed") {
        detail = `failed in ${esc(phaseLabel(job.phase))}`;
      } else if (cls.startsWith("done") && took > 0 && !s.verdict) {
        detail = fmtDur(took);
      }
      return `<li class="${cls}"><span class="n">${i + 1}</span>
        <span class="t">${esc(s.label)}</span><span class="d">${detail}</span></li>`;
    }).join("") + `</ol>` + phaseTimings(job, running);
  }

  // Where the minutes went, one line, in run order — the reason a run was
  // slow should be readable from its page, not reconstructed from the log.
  function phaseTimings(job, running) {
    const pd = job.phase_durations || {};
    const seq = (PHASE_SEQ[job.kind] || []).filter((p) => pd[p] >= 0.5);
    if (running || !seq.length) return "";
    const items = seq.map((p) => `${esc(phaseLabel(p))} <b>${fmtDur(pd[p])}</b>`).join(" · ");
    const total = job.started_at && job.finished_at ? ` — total ${fmtDur(job.finished_at - job.started_at)}` : "";
    return `<p class="notes timings">${items}${total}</p>`;
  }

  function renderHeader(job) {
    const pct = job.progress_total ? Math.round((job.progress_done / job.progress_total) * 100) : 0;
    const running = job.status === "queued" || job.status === "running";
    const now = Date.now() / 1000;
    // Server clocks and browser clocks are not the same clock; a negative age
    // would be nonsense, so it floors at 0.
    const idle = job.updated_at ? Math.max(0, now - job.updated_at) : null;
    // Which mapping this job continues, and why: the firewall it was filed
    // under is the reason it seeded from that particular job.
    const chain = [job.group ? `firewall <b>${esc(job.group)}</b>` : "",
                   job.batch ? `batch ${esc(job.batch)}` : "",
                   job.seed_source ? `seeded from ${esc(job.seed_source)}` : "own mapping",
                  ].filter(Boolean).join(" · ");
    // The log has its own panel below; it is not one of the result files.
    const dl = Object.entries(job.outputs || {}).filter(([k]) => k !== "log").map(([k, v]) =>
      `<a href="/api/jobs/${job.id}/download/${k}" download>${{ tgz: "⬇ anonymized TSF", mapping: "⬇ mapping.json", integrity_report: "⬇ integrity report", anonymize_report: "⬇ anonymize report" }[k] || k}</a>`).join("");
    $("#job-header").innerHTML = `
      <div class="toolbar"><h2>${job.kind} · <span class="mono">${esc(job.input_name)}${job.anon_input_name ? " ↔ " + esc(job.anon_input_name) : ""}</span></h2>
        <span class="status status-${job.status}">${job.status}</span>
        <span style="flex:1"></span>
        <button class="secondary" id="back-jobs">← jobs</button></div>
      ${renderFlow(job)}
      ${running ? `<div class="upload-progress"><div class="bar" style="width:${pct}%"></div>
        <span class="label">${esc(phaseLabel(job.phase))} — ${job.progress_done}/${job.progress_total} (${pct}%) ${esc(job.message)}</span></div>
        <p class="notes">${job.started_at ? fmtDur(Math.max(0, now - job.started_at)) + " elapsed" : "waiting for the worker"}${
          idle === null ? "" : idle > 30 ? ` · <b>no progress reported for ${fmtDur(idle)}</b>`
            : ` · last update ${fmtDur(idle)} ago`}</p>` : ""}
      ${job.error ? `<div class="verdict bad"><span>${esc(job.error)}</span></div>` : ""}
      ${running ? "" : `<div class="actions">${job.status === "done" ? dl : ""}
        ${job.status !== "done" ? `<button class="secondary" id="requeue">run again</button>` : ""}
        ${job.status === "done" && job.trees_kept ? `<button class="secondary" id="purge-trees">free disk (purge extracted trees)</button>` : ""}
        ${job.status === "done" && !job.trees_kept ? `<span class="notes">extracted trees purged — diff viewer unavailable</span>` : ""}
        <button class="secondary" id="show-log">${job.error ? "show the run log (traceback)" : "run log"}</button></div>`}
      <div id="log-box" hidden>
        <div class="log-head"><span id="log-meta"></span>
          <a href="/api/jobs/${job.id}/download/log" download>download the full log</a></div>
        <div class="logbox"><pre id="log-text"></pre></div>
      </div>
      ${chain ? `<p class="notes">${chain}</p>` : ""}
      ${job.status === "done" && job.original_deleted ? `<p class="notes">✓ original deleted after a clean verification</p>` : ""}
      ${job.status === "done" && !job.original_deleted && job.original_kept_reason ? `<div class="verdict warn">⚠ ${esc(job.original_kept_reason)} <button class="danger" id="delete-original">delete original now</button></div>` : ""}
      ${job.status === "done" && !job.original_deleted && !job.original_kept_reason ? `<p class="notes">original kept (not requested to delete) <button class="danger" id="delete-original">delete original</button></p>` : ""}`;
    $("#back-jobs").addEventListener("click", () => showTab("jobs"));
    const logBtn = $("#show-log");
    if (logBtn) logBtn.addEventListener("click", () => {
      const box = $("#log-box");
      box.hidden ? loadLog(job.id) : (box.hidden = true);
    });
    // A crash is the case where the log is the whole point: show it unasked.
    if (job.error) loadLog(job.id);
    const delOrig = $("#delete-original");
    if (delOrig) delOrig.addEventListener("click", async () => {
      if (!confirm("Delete the un-anonymized upload and the extracted trees? Outputs stay; the diff viewer will not.")) return;
      await fetch(`/api/jobs/${job.id}/delete-original`, { method: "POST" });
      pollJob();
    });
    const again = $("#requeue");
    if (again) again.addEventListener("click", async () => {
      const r = await fetch(`/api/jobs/${job.id}/requeue`, { method: "POST" });
      if (!r.ok) { alert((await r.json()).detail || "cannot requeue"); return; }
      pollJob();
    });
    const purge = $("#purge-trees");
    if (purge) purge.addEventListener("click", async () => {
      if (!confirm("Purge the extracted trees? Downloads stay available; the diff viewer will not.")) return;
      await fetch(`/api/jobs/${job.id}/purge-trees`, { method: "POST" });
      pollJob();
    });
  }

  // The run's log — the traceback of a failure and every file the anonymizer
  // had to skip. Without it the only copy is the container's stderr, which is
  // gone the next time the container is recreated.
  const LOG_LEVEL = /\s(WARNING|ERROR|CRITICAL)\s/;
  async function loadLog(id) {
    const box = $("#log-box"), pre = $("#log-text");
    if (!box) return;
    box.hidden = false;
    pre.textContent = "loading…";
    const r = await fetch(`/api/jobs/${id}/log?tail=400`);
    if (!r.ok) { pre.textContent = "no log kept for this job"; return; }
    const d = await r.json();
    $("#log-meta").textContent = d.truncated
      ? `last ${d.lines.length} of ${d.total} lines` : `${d.total} lines`;
    pre.innerHTML = d.lines.map((l) => {
      const m = LOG_LEVEL.exec(l);
      return m ? `<span class="lvl-${m[1]}">${esc(l)}</span>` : esc(l);
    }).join("\n");
    box.scrollTop = box.scrollHeight;
  }

  function kpi(label, v, cls = "") { return `<div class="kpi ${cls}"><div class="v">${v}</div><div class="k">${label}</div></div>`; }
  function renderSummary(job) {
    const s = job.compare_summary, a = job.anonymize_summary, arc = job.archive_check || {};
    let html = "";
    if (s) {
      const v = verdict(job);
      html += `<div class="verdict ${v.cls}">${v.long}</div>`;
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
        ${s.binary_redacted ? kpi("binaries redacted", s.binary_redacted, "warn") : ""}
        ${kpi("binary files identical", `${s.binary_identical}/${s.binary_files - (s.binary_redacted || 0)}`,
              s.binary_identical + (s.binary_redacted || 0) === s.binary_files ? "ok" : "err")}
        ${kpi("line-count mismatches", s.line_count_mismatches, s.line_count_mismatches ? "err" : "ok")}
        ${kpi("timestamp mismatches", s.timestamp_mismatches, s.timestamp_mismatches ? "warn" : "ok")}
        ${kpi("numeric-token mismatches", s.numeric_mismatches, s.numeric_mismatches ? "warn" : "ok")}
        ${kpi("mapping collisions", s.mapping_collisions || 0, s.mapping_collisions ? "warn" : "ok")}
        ${s.mapping_duplicate_pseudonyms ? kpi("duplicate pseudonyms", s.mapping_duplicate_pseudonyms, "err") : ""}
        ${kpi("XML structure preserved", `${s.xml_checked - s.xml_structure_changed}/${s.xml_checked}`, s.xml_structure_changed ? "err" : "ok")}
      </div>`;
      if (s.mapping_collisions) {
        html += `<p class="notes">collisions — original values that are also pseudonyms handed out elsewhere (e.g. the customer uses 100.64.0.0/10): <span class="mono">${(s.mapping_collision_sample || []).map(esc).join(", ")}</span>. They are ambiguous in the output, not leaked.</p>`;
      }
      if (s.mapping_duplicate_pseudonyms) {
        html += `<p class="notes">duplicate pseudonyms — distinct original values that received the same pseudonym (a mapping defect: correlation on the copy is wrong): <span class="mono">${(s.mapping_duplicate_sample || []).map(esc).join(", ")}</span>. Re-anonymize with a current build.</p>`;
      }
      if (arc.members_orig !== undefined) {
        html += `<p class="notes">archive: ${arc.members_orig} → ${arc.members_anon} members, order ${arc.order_preserved ? "preserved" : "<b>changed</b>"}, ${arc.metadata_differences} metadata difference(s)${(arc.mismatches || []).length ? " — " + arc.mismatches.map(esc).join("; ") : ""}</p>`;
      }
    }
    if (a && a.errors) {
      html += `<div class="verdict warn">⚠ ${a.errors} file(s) could not be processed by the
        anonymizer — the run log says which and why.</div>`;
    }
    if (a) {
      html += `<details><summary>anonymization stats</summary><div class="kpis">
        ${kpi("files", a.files_total)}${kpi("modified", a.modified)}${kpi("binary (untouched)", a.binary)}${a.redacted ? kpi("binaries redacted", a.redacted, "warn") : ""}${kpi("errors", a.errors, a.errors ? "err" : "")}
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
  if (hash.startsWith("job/")) openJob(hash.slice(4));
  else if (["jobs", "compare", "anonymize"].includes(hash)) showTab(hash);
  else loadJobs();
})();
