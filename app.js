/**
 * Certification Monitor: admin dashboard (plain JavaScript, no build step).
 *
 * Talks straight to Supabase from the browser:
 *   - Auth (email + password) for admins
 *   - Tables exams / attempts / events: row level security lets each admin see ONLY their own rows
 *   - Functions admin_unlock / admin_release for the two actions that change a student's attempt
 * Everything a student typed (names, details) is untrusted: it is always escaped before it is shown.
 */
(() => {
  "use strict";

  const CFG = window.APP_CONFIG || {};
  const app = document.getElementById("app");
  const POLL_MS = 5000;
  const SILENT_MS = 3 * 60 * 1000; // a certification in progress with no sign of life for 3 minutes is flagged

  /* ----------------------------------------------------------------- helpers */

  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const $ = (sel, root = document) => root.querySelector(sel);

  const configured = () =>
    !!CFG.SUPABASE_URL && !!CFG.SUPABASE_ANON_KEY &&
    !String(CFG.SUPABASE_URL).includes("PASTE_") && !String(CFG.SUPABASE_ANON_KEY).includes("PASTE_");

  function fmtTime(iso) {
    if (!iso) return "-";
    return new Date(iso).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" });
  }

  function ago(iso) {
    if (!iso) return "never";
    const s = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000));
    if (s < 10) return "just now";
    if (s < 60) return s + "s ago";
    const m = Math.floor(s / 60);
    if (m < 60) return m + "m ago";
    const h = Math.floor(m / 60);
    return h < 24 ? h + "h ago" : Math.floor(h / 24) + "d ago";
  }

  /** "training.fortinet.com" or a full address -> https://training.fortinet.com, or null. */
  function normalizeSite(input) {
    const raw = String(input || "").trim();
    if (!raw) return null;
    try {
      const u = new URL(/^https?:\/\//i.test(raw) ? raw : "https://" + raw);
      return u.hostname.includes(".") ? u.origin : null;
    } catch { return null; }
  }

  // Integrity score: starts at 100, only goes down, every point traces to an event.
  const score = (a) => Math.max(0, 100 - 15 * a.strikes - Math.min(10, 2 * a.copy_attempts));
  const band = (n) => (n >= 85 ? "fine" : n >= 60 ? "look" : "review");

  /** A CSV cell that spreadsheets will not run as a formula. */
  function csvCell(v) {
    let s = String(v ?? "");
    if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
    return /[",\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
  }

  function downloadCsv(filename, header, rows) {
    const text = [header, ...rows].map((r) => r.map(csvCell).join(",")).join("\r\n");
    const url = URL.createObjectURL(new Blob(["\ufeff" + text], { type: "text/csv;charset=utf-8" }));
    const a = document.createElement("a");
    a.href = url; a.download = filename;
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  /* ----------------------------------------------------------- Supabase calls */

  let session = null;
  try { session = JSON.parse(localStorage.getItem("cm_session") || "null"); } catch { session = null; }

  function setSession(j) {
    session = {
      access_token: j.access_token,
      refresh_token: j.refresh_token,
      expires_at: Date.now() + (Number(j.expires_in) || 3600) * 1000,
      email: (j.user && j.user.email) || (session && session.email) || ""
    };
    localStorage.setItem("cm_session", JSON.stringify(session));
  }

  function clearSession() {
    session = null;
    localStorage.removeItem("cm_session");
  }

  async function authCall(path, body) {
    const res = await fetch(`${CFG.SUPABASE_URL}/auth/v1/${path}`, {
      method: "POST",
      headers: { apikey: CFG.SUPABASE_ANON_KEY, "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
    const j = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(j.msg || j.error_description || j.message || "Request failed (" + res.status + ")");
    return j;
  }

  async function accessToken() {
    if (!session) throw new Error("Please sign in.");
    if (Date.now() > session.expires_at - 60000) {
      try { setSession(await authCall("token?grant_type=refresh_token", { refresh_token: session.refresh_token })); }
      catch { clearSession(); throw new Error("Your session expired. Please sign in again."); }
    }
    return session.access_token;
  }

  async function rest(path, { method = "GET", body, prefer, headers } = {}) {
    const token = await accessToken();
    const res = await fetch(`${CFG.SUPABASE_URL}/rest/v1/${path}`, {
      method,
      headers: {
        apikey: CFG.SUPABASE_ANON_KEY, Authorization: "Bearer " + token,
        "Content-Type": "application/json", ...(prefer ? { Prefer: prefer } : {}), ...(headers || {})
      },
      body: body === undefined ? undefined : JSON.stringify(body)
    });
    const text = await res.text();
    let json = null;
    try { json = text ? JSON.parse(text) : null; } catch { json = null; }
    if (!res.ok) {
      if (res.status === 401) clearSession();
      throw new Error((json && (json.message || json.error)) || "Error " + res.status);
    }
    return json;
  }

  const rpc = (fn, args) => rest("rpc/" + fn, { method: "POST", body: args });

  async function fetchAll(path) {
    const out = [];
    for (let offset = 0; ; offset += 1000) {
      const page = await rest(`${path}&limit=1000&offset=${offset}`);
      out.push(...page);
      if (page.length < 1000) return out;
    }
  }

  /* -------------------------------------------------------------------- views */

  let pollTimer = null;
  const stopPolling = () => { if (pollTimer) { clearInterval(pollTimer); pollTimer = null; } };

  function shell(content, showUser = true) {
    app.innerHTML = `
      <header class="top">
        <div class="brand"><a href="#/">Certification Monitor</a></div>
        <div class="who">${showUser && session ? `<span>${esc(session.email)}</span><button class="btn small ghost" id="signout">Sign out</button>` : ""}</div>
      </header>
      <main>${content}</main>`;
    const out = $("#signout");
    if (out) out.addEventListener("click", () => { clearSession(); stopPolling(); location.hash = "#/"; route(); });
  }

  function viewSetup() {
    shell(`<div class="card narrow"><h1>Almost there</h1>
      <p>Open <b>config.js</b> and paste your Supabase project URL and anon key, then redeploy.
      The steps are in SETUP.md.</p></div>`, false);
  }

  function viewAuth(message, kind) {
    shell(`
      <div class="card narrow">
        <h1>Admin sign in</h1>
        <p class="muted">For professors and admins. Students use the browser extension, not this page.</p>
        <label>Email<input id="email" type="email" autocomplete="username"></label>
        <label>Password<input id="password" type="password" autocomplete="current-password"></label>
        <div class="row"><button class="btn" id="signin">Sign in</button><button class="btn secondary" id="signup">Create an account</button></div>
        <p class="msg ${kind || ""}" id="msg">${esc(message || "")}</p>
      </div>`, false);

    const say = (t, k) => { const m = $("#msg"); m.textContent = t; m.className = "msg " + (k || ""); };
    const creds = () => ({ email: $("#email").value.trim(), password: $("#password").value });

    async function go(kind) {
      const { email, password } = creds();
      if (!email || !password) return say("Enter your email and password.", "error");
      say(kind === "signup" ? "Creating account..." : "Signing in...");
      try {
        if (kind === "signup") {
          if (password.length < 6) return say("Use a password of at least 6 characters.", "error");
          const j = await authCall("signup", { email, password });
          if (j.access_token) setSession(j);
          else return viewAuth("Account created. Check your email to confirm it, then sign in.", "ok");
        } else {
          setSession(await authCall("token?grant_type=password", { email, password }));
        }
        location.hash = "#/";
        route();
      } catch (e) { say(e.message, "error"); }
    }
    $("#signin").addEventListener("click", () => go("signin"));
    $("#signup").addEventListener("click", () => go("signup"));
    $("#password").addEventListener("keydown", (e) => { if (e.key === "Enter") go("signin"); });
  }

  function viewError(err) {
    if (!session) return viewAuth(err.message, "error");
    shell(`<div class="card"><h1>Something went wrong</h1><p class="msg error">${esc(err.message)}</p>
      <button class="btn" id="retry">Try again</button></div>`);
    $("#retry").addEventListener("click", route);
  }

  /* ----------------------------------------------------------------- exam list */

  const examFields = (e = {}) => `
    <label>Title<input id="f-title" type="text" maxlength="120" value="${esc(e.title || "")}" placeholder="Fortinet NSE 1 certification"></label>
    <label>Website to monitor <small>(the certification site)</small>
      <input id="f-site" type="text" value="${esc(e.site_url || "")}" placeholder="https://training.fortinet.com"></label>
    <div class="grid">
      <label>Strikes before lock<input id="f-strikes" type="number" min="1" max="10" value="${esc(e.max_strikes ?? 5)}"></label>
      <label>Lockout hours <small>(0 = until I unlock)</small><input id="f-hours" type="number" min="0" max="720" value="${esc(e.lockout_hours ?? 24)}"></label>
    </div>
    <label class="check"><input id="f-copy" type="checkbox" ${e.block_copy_paste === false ? "" : "checked"}> Block copy, paste and right-click during the certification</label>`;

  function readExamFields() {
    const site = normalizeSite($("#f-site").value);
    const title = $("#f-title").value.trim();
    if (!title) throw new Error("Enter a title.");
    if (!site) throw new Error("Enter the certification website, for example https://training.fortinet.com");
    return {
      title, site_url: site,
      max_strikes: Math.min(10, Math.max(1, parseInt($("#f-strikes").value, 10) || 5)),
      lockout_hours: Math.min(720, Math.max(0, parseInt($("#f-hours").value, 10) || 0)),
      block_copy_paste: $("#f-copy").checked
    };
  }

  async function viewExams() {
    shell(`<p class="muted">Loading...</p>`);
    const exams = await rest("exams?select=id,title,site_url,join_code,status,max_strikes,created_at&order=created_at.desc");
    shell(`
      <div class="row between"><div><h1>Your certifications</h1><p class="muted">Create a certification, go live, and give students the join code.</p></div></div>
      <details class="card" ${exams.length ? "" : "open"}>
        <summary>+ New certification</summary><div style="margin-top:14px">
          ${examFields()}
          <button class="btn" id="create">Create certification</button>
          <p class="msg" id="msg"></p>
        </div>
      </details>
      ${exams.length ? `<div class="card tablewrap"><table>
        <thead><tr><th>Title</th><th>Website</th><th>Status</th><th>Join code</th><th></th></tr></thead>
        <tbody>${exams.map((e) => `<tr>
          <td><b>${esc(e.title)}</b></td><td>${esc(e.site_url)}</td>
          <td><span class="badge ${esc(e.status)}">${esc(e.status)}</span></td>
          <td><code>${esc(e.join_code)}</code></td>
          <td class="actions"><a class="btn small secondary" style="text-decoration:none" href="#/exam/${esc(e.id)}">Open</a></td></tr>`).join("")}
        </tbody></table></div>` : `<div class="card empty">No certifications yet. Create your first one above.</div>`}`);

    $("#create").addEventListener("click", async () => {
      const msg = $("#msg");
      try {
        const body = readExamFields();
        msg.textContent = "Creating..."; msg.className = "msg";
        const rows = await rest("exams", { method: "POST", body, prefer: "return=representation" });
        location.hash = "#/exam/" + rows[0].id;
      } catch (e) { msg.textContent = e.message; msg.className = "msg error"; }
    });
  }

  /* --------------------------------------------------------------- exam detail */

  const ATTEMPT_COLS = "id,name,email,claimed,status,strikes,copy_attempts,locked_until,joined_at,started_at,finished_at,last_violation_at,last_seen";
  const KIND_LABEL = {
    joined: "Joined", rejoined: "Rejoined", join_refused: "Join refused", started: "Started", finished: "Finished",
    violation: "Violation", locked: "Locked out", lock_expired: "Lock expired", copy_blocked: "Copy/paste blocked",
    unlocked: "Unlocked by admin", released: "Name released"
  };
  const BAD_KINDS = new Set(["violation", "locked", "join_refused", "copy_blocked"]);

  async function viewExam(id) {
    shell(`<p class="muted">Loading...</p>`);
    const found = await rest(`exams?id=eq.${encodeURIComponent(id)}&select=*`);
    if (!found.length) return shell(`<div class="card"><h1>Certification not found</h1><p><a href="#/">Back to your certifications</a></p></div>`);
    let exam = found[0];
    let attempts = [];
    let busy = false;

    shell(`
      <p><a href="#/" class="muted">&larr; All certifications</a></p>
      <div id="head"></div>
      <details class="card"><summary>Certification settings</summary><div style="margin-top:14px">
        <div id="settings">${examFields(exam)}</div>
        <button class="btn" id="save">Save settings</button><p class="msg" id="save-msg"></p>
      </div></details>
      <div id="stats" class="chips"></div>
      <div class="card" id="monitor"></div>`);

    function renderHead() {
      const next = { draft: ["Go live", "ok", "live"], live: ["End certification", "danger", "ended"], ended: ["Reopen", "secondary", "live"] }[exam.status];
      $("#head").innerHTML = `
        <div class="card">
          <div class="row between">
            <div><h1>${esc(exam.title)}</h1>
              <p class="muted">${esc(exam.site_url)} &middot; <span class="badge ${esc(exam.status)}">${esc(exam.status)}</span></p></div>
            <button class="btn ${next[1]}" id="status-btn">${next[0]}</button>
          </div>
          <div class="row" style="margin-top:10px">
            <span class="code" id="join-code">${esc(exam.join_code)}</span>
            <button class="btn small secondary" id="copy-code">Copy code</button>
          </div>
          <p class="note" style="margin-top:10px">${exam.status === "live"
            ? "Students: install the extension, click its icon, then enter this join code and your full name."
            : exam.status === "draft"
              ? "Students cannot join yet. Press Go live when the certification starts."
              : "This certification has ended. Students are no longer monitored."}</p>
        </div>`;
      $("#copy-code").addEventListener("click", async (ev) => {
        try { await navigator.clipboard.writeText(exam.join_code); ev.target.textContent = "Copied"; } catch { ev.target.textContent = "Select and copy"; }
      });
      $("#status-btn").addEventListener("click", async () => {
        if (exam.status === "live") {
          const n = attempts.filter((a) => a.status === "in_progress").length;
          if (!confirm(n ? `${n} student(s) are still working. End the certification anyway?` : "End this certification? Students stop being monitored.")) return;
        }
        try {
          const rows = await rest(`exams?id=eq.${encodeURIComponent(exam.id)}`, { method: "PATCH", body: { status: next[2] }, prefer: "return=representation" });
          exam = rows[0]; renderHead();
        } catch (e) { alert(e.message); }
      });
    }

    function renderMonitor() {
      const now = Date.now();
      const list = attempts.map((a) => ({ ...a, score: score(a) }))
        .sort((x, y) => (y.status === "locked") - (x.status === "locked") || x.score - y.score || x.name.localeCompare(y.name));
      const count = (s) => attempts.filter((a) => a.status === s).length;
      $("#stats").innerHTML = [
        ["Students", attempts.length], ["In progress", count("in_progress")], ["Locked", count("locked")],
        ["Finished", count("finished")], ["Needs review", list.filter((a) => a.score < 60).length]
      ].map(([l, n]) => `<div class="chip"><b>${n}</b><span>${l}</span></div>`).join("");

      $("#monitor").innerHTML = `
        <div class="row between"><h2>Live monitor</h2>
          <div class="row"><button class="btn small ghost" id="csv-attempts">Attempts CSV</button>
          <button class="btn small ghost" id="csv-events">Events CSV</button></div></div>
        ${list.length ? `<div class="tablewrap"><table>
          <thead><tr><th>Student</th><th>Status</th><th>Strikes</th><th>Score</th><th>Last violation</th><th>Last seen</th><th></th></tr></thead>
          <tbody>${list.map((a) => {
            const silent = a.status === "in_progress" && a.last_seen && now - new Date(a.last_seen).getTime() > SILENT_MS;
            const pips = Array.from({ length: exam.max_strikes }, (_, i) =>
              `<span class="pip${i < a.strikes ? " on" : ""}${i < a.strikes && a.strikes >= 3 ? " hot" : ""}"></span>`).join("");
            return `<tr class="${a.status === "locked" ? "locked" : ""}">
              <td><b>${esc(a.name)}</b>${a.claimed ? "" : ` <span class="note">(released)</span>`}</td>
              <td><span class="badge ${esc(a.status)}">${esc(a.status.replace("_", " "))}</span></td>
              <td><span class="pips">${pips}</span> <span class="note">${a.strikes}/${exam.max_strikes}</span></td>
              <td><span class="score ${band(a.score)}">${a.score}</span></td>
              <td>${esc(ago(a.last_violation_at))}</td>
              <td>${esc(ago(a.last_seen))}${silent ? ` <span class="flag" title="No sign of life during the certification">&#9888; silent</span>` : ""}</td>
              <td class="actions">
                ${a.status === "locked" ? `<button class="btn small ok" data-act="unlock" data-id="${esc(a.id)}">Unlock</button>` : ""}
                <button class="btn small secondary" data-act="timeline" data-id="${esc(a.id)}">Timeline</button>
                <button class="btn small ghost" data-act="release" data-id="${esc(a.id)}" title="Let this name join from a new browser">Release</button>
                <button class="btn small danger" data-act="delete" data-id="${esc(a.id)}">Delete</button>
              </td></tr>`;
          }).join("")}</tbody></table></div>
          <p class="note" style="margin-top:10px">Score = 100 &minus; 15 per strike &minus; 2 per blocked copy/paste (max 10). 85+ fine, 60&ndash;84 worth a look, below 60 needs review. It is a prompt to review, not a verdict.</p>`
          : `<div class="empty">No students yet. Share the join code once the certification is live.</div>`}`;

      $("#csv-attempts").addEventListener("click", () => downloadCsv(
        `${exam.title}-attempts.csv`,
        ["Name", "Status", "Strikes", "Copy/paste attempts", "Score", "Joined", "Started", "Finished", "Last violation", "Last seen"],
        list.map((a) => [a.name, a.status, a.strikes, a.copy_attempts, a.score, a.joined_at, a.started_at, a.finished_at, a.last_violation_at, a.last_seen])));
      $("#csv-events").addEventListener("click", async () => {
        const names = new Map(attempts.map((a) => [a.id, a.name]));
        const evs = await fetchAll(`events?exam_id=eq.${encodeURIComponent(exam.id)}&select=created_at,attempt_id,kind,detail&order=created_at.asc`);
        downloadCsv(`${exam.title}-events.csv`, ["Time", "Student", "Event", "Detail"],
          evs.map((e) => [e.created_at, names.get(e.attempt_id) || "(deleted)", KIND_LABEL[e.kind] || e.kind, e.detail]));
      });
    }

    async function load() {
      if (busy) return;
      busy = true;
      try {
        attempts = await rest(`attempts?exam_id=eq.${encodeURIComponent(exam.id)}&select=${ATTEMPT_COLS}&order=name.asc`);
        renderMonitor();
      } catch (e) { const m = $("#monitor"); if (m) m.insertAdjacentHTML("afterbegin", `<p class="msg error">Connection problem: ${esc(e.message)}</p>`); }
      busy = false;
    }

    async function showTimeline(attemptId) {
      const a = attempts.find((x) => x.id === attemptId);
      const evs = await rest(`events?attempt_id=eq.${encodeURIComponent(attemptId)}&select=kind,detail,created_at&order=created_at.asc&limit=1000`);
      const bg = document.createElement("div");
      bg.className = "modal-bg";
      bg.innerHTML = `<div class="modal" role="dialog" aria-label="Timeline">
        <div class="row between"><h2>${esc(a ? a.name : "Timeline")}</h2><button class="btn small ghost" id="close">Close</button></div>
        <ul class="timeline">${evs.map((e) => `<li><time>${esc(fmtTime(e.created_at))}</time>
          <span class="k ${BAD_KINDS.has(e.kind) ? "bad" : ""}">${esc(KIND_LABEL[e.kind] || e.kind)}</span><span>${esc(e.detail)}</span></li>`).join("") || `<li>No events.</li>`}</ul></div>`;
      document.body.append(bg);
      const close = () => bg.remove();
      bg.addEventListener("click", (ev) => { if (ev.target === bg) close(); });
      $("#close", bg).addEventListener("click", close);
    }

    renderHead();
    $("#save").addEventListener("click", async () => {
      const msg = $("#save-msg");
      try {
        const body = readExamFields();
        const rows = await rest(`exams?id=eq.${encodeURIComponent(exam.id)}`, { method: "PATCH", body, prefer: "return=representation" });
        exam = rows[0]; renderHead(); renderMonitor();
        msg.textContent = "Saved. Students' extensions pick this up within a minute."; msg.className = "msg ok";
      } catch (e) { msg.textContent = e.message; msg.className = "msg error"; }
    });
    $("#monitor").addEventListener("click", async (ev) => {
      const btn = ev.target.closest("button[data-act]");
      if (!btn) return;
      const { act, id } = btn.dataset;
      try {
        if (act === "timeline") return await showTimeline(id);
        if (act === "unlock") await rpc("admin_unlock", { p_attempt: id });
        if (act === "release") { if (!confirm("Release this name so the student can join again from a new browser?")) return; await rpc("admin_release", { p_attempt: id }); }
        if (act === "delete") { if (!confirm("Delete this student and their history?")) return; await rest(`attempts?id=eq.${encodeURIComponent(id)}`, { method: "DELETE" }); }
        await load();
      } catch (e) { alert(e.message); }
    });

    await load();
    pollTimer = setInterval(load, POLL_MS);
  }

  /* -------------------------------------------------------------------- router */

  async function route() {
    stopPolling();
    if (!configured()) return viewSetup();
    if (!session) return viewAuth();
    const m = location.hash.match(/^#\/exam\/([0-9a-f-]{36})$/i);
    try { if (m) await viewExam(m[1]); else await viewExams(); }
    catch (e) { viewError(e); }
  }

  window.addEventListener("hashchange", route);
  route();
})();
