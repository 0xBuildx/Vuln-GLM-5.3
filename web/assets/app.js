const $ = (sel, root = document) => root.querySelector(sel);
const app = $("#app");
const modal = $("#modal");
const toastEl = $("#toast");

const state = {
  health: null,
  overview: null,
  audits: [],
  agents: [],
  audit: null,
  events: [],
  listening: null,
  source: null,
  filter: "all",
  openFinding: null,
  browse: null,
};

function esc(s) {
  return String(s ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

function toast(msg) {
  toastEl.hidden = false;
  toastEl.textContent = msg;
  clearTimeout(toastEl._t);
  toastEl._t = setTimeout(() => (toastEl.hidden = true), 2800);
}

async function api(path, opts = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json", ...(opts.headers || {}) },
    ...opts,
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const data = await res.json();
      detail = data.detail || JSON.stringify(data);
    } catch {}
    throw new Error(detail);
  }
  const ct = res.headers.get("content-type") || "";
  if (ct.includes("text/markdown")) return res.text();
  return res.json();
}

function parts() {
  return (location.hash.replace(/^#/, "") || "/").split("/").filter(Boolean);
}

function iconSend() {
  return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M12 19V5M5 12l7-7 7 7"/></svg>`;
}

function iconSearch() {
  return `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="7"/><path d="M20 20l-3-3"/></svg>`;
}

function sevChip(level) {
  return `<span class="chip-sev ${esc(level)}">${esc(level)}</span>`;
}

function sevBar(counts) {
  const order = [
    ["critical", "var(--crit)"],
    ["high", "var(--high)"],
    ["medium", "var(--med)"],
    ["low", "var(--low)"],
  ];
  const max = Math.max(1, ...order.map(([k]) => counts[k] || 0));
  return order
    .map(
      ([k, c]) => `<div class="sev-row">
        <span>${k.slice(0, 4)}</span>
        <span class="bar"><i style="width:${((counts[k] || 0) / max) * 100}%;background:${c}"></i></span>
        <span class="n">${counts[k] || 0}</span>
      </div>`
    )
    .join("");
}

let asciiRaf = 0;
let asciiResize = null;
let asciiPointer = null;
let asciiGen = 0;

function stopAsciiHero() {
  asciiGen += 1;
  if (asciiRaf) cancelAnimationFrame(asciiRaf);
  asciiRaf = 0;
  if (asciiResize) {
    window.removeEventListener("resize", asciiResize);
    asciiResize = null;
  }
  if (asciiPointer) {
    const { canvas, move, leave, down } = asciiPointer;
    canvas.removeEventListener("pointermove", move);
    canvas.removeEventListener("pointerleave", leave);
    canvas.removeEventListener("pointerdown", down);
    asciiPointer = null;
  }
}

function startAsciiHero(canvas) {
  if (!canvas) return;
  stopAsciiHero();
  const gen = asciiGen;
  const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const ctx = canvas.getContext("2d", { alpha: false });
  const src = document.createElement("canvas");
  const sctx = src.getContext("2d", { willReadFrequently: true });
  const layer = document.createElement("canvas");
  const lctx = layer.getContext("2d");
  let dots = [];
  let cell = 5.4;
  const mouse = { x: -9999, y: -9999, inside: false };
  const ripples = [];
  let lastRipple = 0;

  function spawnRipple(x, y, amp) {
    ripples.push({ x, y, t0: performance.now(), amp });
    if (ripples.length > 8) ripples.shift();
  }

  function paintMask() {
    const w = canvas.parentElement ? canvas.parentElement.clientWidth : canvas.clientWidth || 1100;
    const h =
      w < 560
        ? Math.max(240, Math.min(340, Math.round(w * 0.68)))
        : w < 720
          ? Math.max(200, Math.min(300, Math.round(w * 0.38)))
          : Math.max(200, Math.min(320, Math.round(w * 0.26)));
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    canvas.width = Math.max(1, Math.floor(w * dpr));
    canvas.height = Math.max(1, Math.floor(h * dpr));
    canvas.style.width = `${w}px`;
    canvas.style.height = `${h}px`;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    layer.width = canvas.width;
    layer.height = canvas.height;
    lctx.setTransform(dpr, 0, 0, dpr, 0, 0);

    cell = w < 720 ? 5.2 : 5.5;
    const cols = Math.max(64, Math.floor(w / cell));
    const rows = Math.max(20, Math.floor(h / cell));
    const scale = 8;
    const sw = cols * scale;
    const sh = rows * scale;
    src.width = sw;
    src.height = sh;
    sctx.fillStyle = "#000";
    sctx.fillRect(0, 0, sw, sh);
    sctx.fillStyle = "#fff";
    sctx.textAlign = "left";
    sctx.textBaseline = "alphabetic";
    sctx.imageSmoothingEnabled = true;
    if (sctx.letterSpacing !== undefined) sctx.letterSpacing = `${Math.max(1, sw * 0.0012)}px`;

    const lines =
      w < 560
        ? [
            { text: "Your code,", style: "italic 560" },
            { text: "audited by", style: "500" },
            { text: "GLM", style: "560" },
          ]
        : [
            { text: "Your code,", style: "italic 560" },
            { text: "audited by GLM", style: "500" },
          ];
    const pad = sw * 0.028;
    const face = `"Newsreader", "Iowan Old Style", Georgia, serif`;
    const fit = (text, style, start) => {
      let size = start;
      sctx.font = `${style} ${size}px ${face}`;
      while (sctx.measureText(text).width > sw - pad * 2 && size > 18) {
        size -= 2;
        sctx.font = `${style} ${size}px ${face}`;
      }
      return size;
    };
    const start = sh * (lines.length === 3 ? 0.22 : 0.36);
    const sized = lines.map((line) => ({ ...line, size: fit(line.text, line.style, start) }));
    const block = sized.reduce((n, line) => n + line.size, 0) + (sized.length - 1) * (sh * 0.06);
    let y = (sh - block) / 2 + sized[0].size * 0.86;
    sized.forEach((line, i) => {
      sctx.font = `${line.style} ${line.size}px ${face}`;
      sctx.fillText(line.text, pad, y);
      y += line.size + sh * 0.06;
      if (i === 0 && sctx.letterSpacing !== undefined) sctx.letterSpacing = `${Math.max(0.5, sw * 0.0006)}px`;
    });

    const pix = sctx.getImageData(0, 0, sw, sh).data;
    const next = [];
    const cw = w / cols;
    const ch = h / rows;
    for (let y = 0; y < rows; y++) {
      const stagger = (y % 2) * 0.5;
      for (let x = 0; x < cols; x++) {
        let acc = 0;
        let n = 0;
        const x0 = x * scale;
        const y0 = y * scale;
        for (let dy = 1; dy < scale; dy += 2) {
          for (let dx = 1; dx < scale; dx += 2) {
            acc += pix[((y0 + dy) * sw + Math.min(sw - 1, x0 + dx)) * 4];
            n += 1;
          }
        }
        const ink = acc / (n * 255);
        if (ink < 0.1) continue;
        const soft = ink < 0.22 ? (ink - 0.1) / 0.12 : 1;
        const px = (x + 0.5 + stagger) * cw;
        const py = (y + 0.5) * ch;
        next.push({
          x: px,
          y: py,
          px,
          py,
          vx: 0,
          vy: 0,
          ink,
          alpha: 0.28 + soft * ink * 0.72,
          r: (0.7 + ink * 1.35) * (cell * 0.2),
        });
      }
    }
    dots = next;
  }

  function forces(dot, t) {
    let ox = 0;
    let oy = 0;
    let glow = 0;
    if (!reduced && mouse.inside) {
      const dx = dot.x - mouse.x;
      const dy = dot.y - mouse.y;
      const d = Math.hypot(dx, dy) || 0.001;
      const reach = 108;
      if (d < reach) {
        const k = 1 - d / reach;
        const s = k * k;
        ox += (dx / d) * s * 26;
        oy += (dy / d) * s * 26;
        glow += s;
      }
    }
    if (!reduced) {
      for (let r = 0; r < ripples.length; r++) {
        const wave = ripples[r];
        const age = (t - wave.t0) / 1000;
        if (age > 1.7) continue;
        const dx = dot.x - wave.x;
        const dy = dot.y - wave.y;
        const d = Math.hypot(dx, dy) || 0.001;
        const radius = age * 240;
        const band = 36;
        const ring = Math.abs(d - radius);
        if (ring >= band) continue;
        const fall = 1 - age / 1.7;
        const k = (1 - ring / band) * fall;
        ox += (dx / d) * k * wave.amp;
        oy += (dy / d) * k * wave.amp;
        glow += k;
      }
    }
    return { ox, oy, glow: Math.min(1, glow) };
  }

  function stepDots(t) {
    for (let i = 0; i < dots.length; i++) {
      const dot = dots[i];
      const { ox, oy, glow } = forces(dot, t);
      dot.glow = glow;
      if (reduced) {
        dot.px = dot.x;
        dot.py = dot.y;
        continue;
      }
      const tx = dot.x + ox;
      const ty = dot.y + oy;
      dot.vx = (dot.vx + (tx - dot.px) * 0.22) * 0.72;
      dot.vy = (dot.vy + (ty - dot.py) * 0.22) * 0.72;
      dot.px += dot.vx;
      dot.py += dot.vy;
    }
  }

  function drawDots(target, bloom) {
    const H = canvas.clientHeight;
    for (let i = 0; i < dots.length; i++) {
      const dot = dots[i];
      const glow = dot.glow || 0;
      const lift = 0.92 + (1 - dot.y / Math.max(1, H)) * 0.08;
      target.globalAlpha = bloom ? dot.alpha * 0.55 : Math.min(1, dot.alpha + glow * 0.35);
      target.fillStyle = bloom
        ? "#d9e0ff"
        : `rgb(${236 + glow * 19}, ${240 + glow * 15}, ${255})`;
      target.beginPath();
      target.arc(
        dot.px,
        dot.py,
        bloom ? dot.r * 2.4 : dot.r * (0.92 + lift * 0.12 + glow * 0.25),
        0,
        Math.PI * 2
      );
      target.fill();
    }
    target.globalAlpha = 1;
  }

  function frame(now) {
    if (gen !== asciiGen) return;
    const W = canvas.clientWidth;
    const H = canvas.clientHeight;
    const t = now || performance.now();
    stepDots(t);
    ctx.fillStyle = "#090b10";
    ctx.fillRect(0, 0, W, H);

    lctx.clearRect(0, 0, W, H);
    drawDots(lctx, true);
    ctx.save();
    ctx.filter = "blur(7px)";
    ctx.globalAlpha = 0.55;
    ctx.drawImage(layer, 0, 0, W, H);
    ctx.restore();
    drawDots(ctx, false);

    if (!reduced) {
      while (ripples.length && t - ripples[0].t0 > 1800) ripples.shift();
      asciiRaf = requestAnimationFrame(frame);
    }
  }

  const pointerPos = (ev) => {
    const box = canvas.getBoundingClientRect();
    return { x: ev.clientX - box.left, y: ev.clientY - box.top };
  };
  const onMove = (ev) => {
    const p = pointerPos(ev);
    mouse.x = p.x;
    mouse.y = p.y;
    mouse.inside = true;
    if (reduced) return;
    const now = performance.now();
    if (now - lastRipple > 90) {
      spawnRipple(p.x, p.y, 12);
      lastRipple = now;
    }
  };
  const onLeave = () => {
    mouse.inside = false;
  };
  const onDown = (ev) => {
    const p = pointerPos(ev);
    mouse.x = p.x;
    mouse.y = p.y;
    mouse.inside = true;
    if (!reduced) spawnRipple(p.x, p.y, 26);
  };

  const boot = async () => {
    try {
      if (document.fonts) {
        await Promise.all([
          document.fonts.load('italic 560 80px "Newsreader"'),
          document.fonts.load('500 80px "Newsreader"'),
          document.fonts.ready,
        ]);
      }
    } catch {}
    if (gen !== asciiGen) return;
    paintMask();
    if (reduced) frame(0);
    else asciiRaf = requestAnimationFrame(frame);
  };

  asciiResize = () => {
    paintMask();
    if (reduced) frame(0);
  };
  window.addEventListener("resize", asciiResize);
  canvas.addEventListener("pointermove", onMove);
  canvas.addEventListener("pointerleave", onLeave);
  canvas.addEventListener("pointerdown", onDown);
  asciiPointer = { canvas, move: onMove, leave: onLeave, down: onDown };
  boot();
}

function engineChip() {
  const h = state.health || {};
  if (h.live) {
    return `<span class="chip live"><span class="dot ok"></span>${esc(h.model || "live")}</span>`;
  }
  return `<span class="chip"><span class="dot"></span>demo · add GLM key</span>`;
}

function header() {
  return `<header class="top">
    <div class="top-in">
      <a class="brand" href="#/">
        <span class="mark"></span>
        <span class="brand-name">Vuln</span>
      </a>
      <div class="nav">
        ${engineChip()}
        <a class="chip" href="#/agents">Agents</a>
        <a class="chip" href="#/settings">Settings</a>
      </div>
    </div>
  </header>`;
}

async function refreshHealth() {
  state.health = await api("/api/health");
}

async function renderHome() {
  const [overview, audits] = await Promise.all([api("/api/overview"), api("/api/audits")]);
  state.overview = overview;
  state.audits = audits;
  const live = overview.live?.scanning || [];
  const counts = overview.severity_counts || {};
  const q = "";
  const rows = audits
    .map((a) => {
      const langs = Object.keys(a.index_json?.languages || {})[0] || a.source_kind;
      return `<a class="ledger-row" href="#/audits/${a.id}">
        <span>
          <span class="repo-name">${esc(a.name)}</span>
          <span class="muted" style="display:block;margin-top:4px">${esc(a.source)}</span>
        </span>
        <span class="muted">${esc(langs || "—")}</span>
        <span class="tiny">${esc(a.status)}${a.status === "running" ? " · live" : ""}</span>
        <span class="repo-name">${a.finding_count ?? "—"}</span>
        <span class="tiny">${esc(a.mode)}</span>
      </a>`;
    })
    .join("");

  app.innerHTML = `${header()}
    <main class="wrap">
      <section class="hero">
        <h1 class="sr-only">Your code, audited by GLM</h1>
        <canvas id="ascii-hero" class="ascii-hero" aria-hidden="true"></canvas>
        <div class="hero-row">
          <p class="lede">
            Point Vuln at a folder. GLM-5.3 maps trust boundaries, then writes pentest-style
            findings: attacker, preconditions, blast radius, evidence, and why SAST would miss it.
          </p>
          <div>
            <form id="composer" class="composer" autocomplete="off">
              <input name="source" placeholder="/path/to/your/repo  ·  demo  ·  https://github.com/org/repo" required />
              <button class="send" type="submit" aria-label="Start audit">${iconSend()}</button>
            </form>
            <div class="composer-meta">
              <button type="button" id="browse-btn">Browse a folder</button>
              <button type="button" id="demo-btn">Run Harbor Shop demo</button>
              <label class="tiny" style="display:inline-flex;gap:6px;align-items:center;letter-spacing:0;text-transform:none">
                Diff vs
                <input name="base" id="base-ref" class="field" style="width:120px;padding:4px 8px" placeholder="main" />
              </label>
              <span>Local folders stay on this host · GLM-5.3 reads source only</span>
            </div>
          </div>
        </div>
      </section>

      <section class="band" aria-label="Live scans">
        <div class="cell">
          <p class="kicker"><span class="dot ${live.length ? "ok pulse" : ""}"></span> Live — scanning now</p>
          <p class="tiny" style="margin-top:10px">${live.length} active</p>
        </div>
        ${
          live.length
            ? live
                .slice(0, 3)
                .map(
                  (s) => `<a class="cell" href="#/audits/${s.id}">
                    <div class="repo-name">${esc(s.name)}</div>
                    <div class="tiny" style="margin-top:6px">${esc(s.status)} · ${s.findings_so_far} found</div>
                  </a>`
                )
                .join("")
            : `<div class="cell" style="grid-column:span 3"><p class="tiny">Standing by — drop a folder above.</p></div>`
        }
      </section>

      <section class="band y" aria-label="Metrics">
        <div class="cell"><div class="num">${overview.scanned_project_count}</div><div class="kicker">Folders scanned</div></div>
        <div class="cell"><div class="num">${overview.finding_total}</div><div class="kicker">Findings discovered</div></div>
        <div class="cell"><div class="num">${overview.scan_in_progress_count}</div><div class="kicker">Scans in progress</div></div>
        <div class="cell">${sevBar(counts)}<div class="kicker" style="margin-top:10px">Findings by severity</div></div>
      </section>

      <section>
        <div class="section-h">
          <div>
            <p class="kicker">Folder index</p>
            <h2>Scanned folders</h2>
          </div>
          <div class="search-wrap">
            ${iconSearch()}
            <input class="search" id="q" placeholder="Search folders" />
          </div>
        </div>
        <div class="ledger-head">
          <span>Folder</span><span>Kind</span><span>Last scan</span><span>Findings</span><span>Mode</span>
        </div>
        <div id="ledger">${rows || `<div class="empty">No folders yet. Browse one or run the demo.</div>`}</div>
      </section>
    </main>`;

  $("#composer").onsubmit = async (ev) => {
    ev.preventDefault();
    const source = ev.target.source.value.trim();
    const base = ($("#base-ref") && $("#base-ref").value.trim()) || "";
    await startAudit(source, { base_ref: base || null });
  };
  $("#browse-btn").onclick = () => openBrowse(state.health?.home || "/home");
  $("#demo-btn").onclick = () => startAudit("demo", { name: "Harbor Shop", mode: "demo" });
  $("#q").oninput = (ev) => {
    const needle = ev.target.value.toLowerCase();
    document.querySelectorAll(".ledger-row").forEach((row) => {
      row.style.display = row.textContent.toLowerCase().includes(needle) ? "" : "none";
    });
  };
  startAsciiHero($("#ascii-hero"));
}

async function startAudit(source, extra = {}) {
  try {
    const audit = await api("/api/audits", {
      method: "POST",
      body: {
        source,
        mode: extra.mode || "auto",
        name: extra.name || null,
        focus: extra.focus || "",
        base_ref: extra.base_ref || null,
      },
    });
    location.hash = `#/audits/${audit.id}`;
  } catch (err) {
    toast(err.message);
  }
}

async function openBrowse(path) {
  try {
    state.browse = await api(`/api/browse?path=${encodeURIComponent(path)}`);
  } catch (err) {
    toast(err.message);
    return;
  }
  const b = state.browse;
  modal.hidden = false;
  modal.innerHTML = `<div class="sheet">
    <div class="section-h" style="margin-top:0">
      <div>
        <p class="kicker">This machine</p>
        <h2 style="font-size:18px">Choose a folder</h2>
      </div>
      <button class="btn ghost" id="close-modal">Close</button>
    </div>
    <p class="tiny" style="margin:8px 0 0">${esc(b.path)}</p>
    <div class="sheet-list">
      <div class="dir" data-path="${esc(b.parent)}"><span>../</span><span class="tiny">parent</span></div>
      ${b.dirs.map((d) => `<div class="dir" data-path="${esc(d.path)}"><span>${esc(d.name)}/</span><span class="tiny">open</span></div>`).join("")}
    </div>
    <div style="display:flex;gap:8px">
      <button class="btn primary" id="scan-here">Scan this folder</button>
    </div>
  </div>`;
  $("#close-modal").onclick = () => (modal.hidden = true);
  modal.onclick = (e) => {
    if (e.target === modal) modal.hidden = true;
  };
  modal.querySelectorAll("[data-path]").forEach((el) => {
    el.onclick = () => openBrowse(el.dataset.path);
  });
  $("#scan-here").onclick = () => {
    modal.hidden = true;
    startAudit(b.path);
  };
}

function stopEvents() {
  if (state.source) {
    state.source.close();
    state.source = null;
  }
  state.listening = null;
}

function eventRow(ev) {
  return `<div class="event ${esc(ev.kind)}">
    <div class="who">${esc(ev.agent || "system")}<div class="tiny">${esc(ev.kind)}</div></div>
    <div class="msg">${esc(ev.message)}</div>
  </div>`;
}

function scanPhase(events) {
  if (events.some((e) => e.kind === "status" && /completed|failed|cancelled/i.test(e.message))) return 3;
  if (
    events.some(
      (e) =>
        e.kind === "think" ||
        e.kind === "finding" ||
        /hunting|launching mapper/i.test(e.message || "")
    )
  )
    return 2;
  if (events.some((e) => e.kind === "index" || /index/i.test(e.message || ""))) return 1;
  return 0;
}

function lastIndex(events) {
  return [...events].reverse().find((e) => e.kind === "index") || null;
}

function hunterMap(events) {
  const map = {};
  events.forEach((e) => {
    const id = e.agent || "system";
    map[id] = e;
  });
  return map;
}

function paintLive() {
  const events = state.events;
  const phase = scanPhase(events);
  const stages = ["Queued", "Indexing", "Hunting", "Results"];
  document.querySelectorAll(".stage").forEach((el, i) => {
    el.classList.toggle("on", i === phase);
    el.classList.toggle("done", i < phase);
  });
  const title = $("#scan-title");
  if (title) {
    title.textContent =
      phase <= 1 ? "Indexing your source" : phase === 2 ? "Agents are hunting" : "Scan finished";
  }
  const idx = lastIndex(events);
  const indexEl = $("#index-line");
  if (indexEl && idx) {
    const p = idx.payload || {};
    indexEl.innerHTML = `<span>${p.files ?? "—"} files · ${p.routes ?? "—"} routes</span><span class="path">${esc(p.path || idx.message || "")}</span>`;
  }
  const found = events.filter((e) => e.kind === "finding").length;
  const foundEl = $("#found-n");
  if (foundEl) foundEl.textContent = found;
  const covEv = [...events].reverse().find((e) => e.payload && e.payload.total != null);
  const covEl = $("#cov-line");
  if (covEl && covEv && covEv.payload) {
    const c = covEv.payload;
    covEl.textContent = `Routes ${c.reviewed || 0}/${c.total || 0} reviewed · ${c.open || 0} open`;
  }
  const board = $("#hunters");
  if (board) {
    const agents = hunterMap(events);
    board.innerHTML = Object.entries(agents)
      .filter(([id]) => id !== "system")
      .map(([id, ev]) => {
        const hot = ev.kind === "think" || ev.kind === "read" || ev.kind === "index";
        return `<div class="hunter ${hot ? "hot" : ""}">
          <div class="name">${esc(id)} · ${esc(ev.kind)}</div>
          <div class="act">${esc(ev.message)}</div>
        </div>`;
      })
      .join("");
  }
}

function listen(id) {
  if (state.listening === id && state.source) return;
  stopEvents();
  const last = state.events.reduce((n, e) => Math.max(n, e.id || 0), 0);
  const src = new EventSource(`/api/audits/${id}/events?after=${last}`);
  state.source = src;
  state.listening = id;
  src.onmessage = async (ev) => {
    const event = JSON.parse(ev.data);
    if (state.events.some((e) => e.id && e.id === event.id)) return;
    state.events.push(event);
    const feed = $("#live-feed");
    if (feed) feed.insertAdjacentHTML("afterbegin", eventRow(event));
    paintLive();
    if (event.kind === "status" && /completed|failed|cancelled/i.test(event.message)) {
      stopEvents();
      await loadAudit(id, true);
    }
  };
  src.addEventListener("done", async () => {
    stopEvents();
    await loadAudit(id, true);
  });
}

async function loadAudit(id, rerender = true) {
  state.audit = await api(`/api/audits/${id}`);
  if (rerender) await renderAudit();
}

async function renderAudit() {
  const id = parts()[1];
  if (!state.audit || state.audit.id !== id) {
    state.audit = await api(`/api/audits/${id}`);
    state.events = [];
    state.openFinding = null;
  }
  const a = state.audit;
  const running = ["pending", "running"].includes(a.status);
  if (running) return await renderScan(a);
  return renderProject(a);
}

async function renderScan(a) {
  if (!state.events.length) {
    try {
      state.events = await api(`/api/audits/${a.id}/log`);
    } catch {
      state.events = [];
    }
  }
  const stages = ["Queued", "Indexing", "Hunting", "Results"];
  const phase = scanPhase(state.events);
  app.innerHTML = `<div class="scan">
    <header class="top"><div class="top-in">
      <a class="chip" href="#/">← Vuln</a>
      ${engineChip()}
    </div></header>
    <main class="scan-main">
      <div class="scan-grid">
        <aside class="scan-side">
          <p class="kicker">Live scan</p>
          <h1 id="scan-title">${phase <= 1 ? "Indexing" : "Hunting"}</h1>
          <p class="muted">${esc(a.name)}</p>
          <p class="tiny" style="margin-top:8px;normal-case;letter-spacing:0;text-transform:none">${esc(a.source)}</p>
          <div style="margin-top:20px">
            <div class="found-n" id="found-n">0</div>
            <p class="kicker">Findings so far</p>
          </div>
          <ol class="stages">
            ${stages
              .map((label, i) => `<li class="stage ${i === phase ? "on" : i < phase ? "done" : ""}">${esc(label)}</li>`)
              .join("")}
          </ol>
          <div style="margin-top:18px"><button class="btn" id="cancel">Cancel</button></div>
        </aside>
        <div class="panel">
          <div class="index-line" id="index-line"><span>waiting for index…</span></div>
          <div class="index-line" id="cov-line">Routes —/— reviewed</div>
          <div class="hunters" id="hunters"></div>
          <div class="feed" id="live-feed">${state.events.slice().reverse().map(eventRow).join("")}</div>
        </div>
      </div>
    </main>
  </div>`;
  paintLive();
  $("#cancel").onclick = async () => {
    const btn = $("#cancel");
    if (btn) {
      btn.disabled = true;
      btn.textContent = "Cancelling…";
    }
    try {
      await api(`/api/audits/${a.id}/cancel`, { method: "POST" });
      toast("Cancelled");
      await loadAudit(a.id, true);
    } catch (err) {
      toast(err.message);
      if (btn) {
        btn.disabled = false;
        btn.textContent = "Cancel";
      }
    }
  };
  listen(a.id);
}

function countsFrom(findings) {
  const c = { critical: 0, high: 0, medium: 0, low: 0 };
  findings.forEach((f) => {
    if (c[f.severity] != null) c[f.severity] += 1;
  });
  return c;
}

function fact(title, body) {
  if (body == null || body === "" || (Array.isArray(body) && !body.length)) return "";
  if (Array.isArray(body)) {
    return `<div class="fact"><p class="kicker">${esc(title)}</p><ul>${body
      .map((x) => `<li>${esc(x)}</li>`)
      .join("")}</ul></div>`;
  }
  return `<div class="fact"><p class="kicker">${esc(title)}</p><p>${esc(body)}</p></div>`;
}

function findingBody(f) {
  const d = f.details || {};
  return `<div class="report">
    <div class="report-main">
      <p class="kicker">How it works</p>
      <p class="prose">${esc(f.description || f.summary)}</p>
      <p class="kicker" style="margin-top:22px">Attack path</p>
      <ol class="steps">${(f.attack_path || []).map((s) => `<li>${esc(s)}</li>`).join("")}</ol>
      <p class="kicker" style="margin-top:22px">Evidence</p>
      ${(f.evidence || [])
        .map(
          (e) => `<div class="ev">
            <div class="path">${esc(e.path)}:${e.start_line}–${e.end_line}</div>
            <p class="muted">${esc(e.why || "")}</p>
            <pre>${esc(e.snippet || "")}</pre>
          </div>`
        )
        .join("")}
      ${f.root_cause ? `<p class="kicker" style="margin-top:18px">Root cause</p><p class="prose">${esc(f.root_cause)}</p>` : ""}
      ${f.remediation ? `<p class="kicker" style="margin-top:18px">Remediation</p><p class="prose">${esc(f.remediation)}</p>` : ""}
    </div>
    <aside>
      ${fact("Attacker", d.attacker)}
      ${fact("OWASP", d.owasp)}
      ${fact("CWE", f.cwe)}
      ${fact("Category", f.category)}
      ${fact("Preconditions", d.preconditions)}
      ${fact("Affected routes", d.affected_routes)}
      ${fact("Blast radius", d.blast_radius || f.impact)}
      ${fact("Why SAST misses this", d.why_sast_misses)}
      ${fact("Regression tests", d.fix_tests)}
      ${fact("Confidence", d.confidence_rationale || `${Math.round((f.confidence || 0) * 100)}% · ${f.verified ? "verified" : "unverified"}`)}
      ${fact("Agent", f.agent)}
    </aside>
  </div>`;
}

function cweBars(findings) {
  const map = {};
  findings.forEach((f) => {
    if (f.cwe) map[f.cwe] = (map[f.cwe] || 0) + 1;
  });
  const list = Object.entries(map).sort((a, b) => b[1] - a[1]).slice(0, 6);
  const max = Math.max(1, ...list.map((x) => x[1]));
  if (!list.length) return "";
  return `<section style="margin-top:36px">
    <h2 style="font-family:var(--display);font-size:16px">Top CWE categories</h2>
    ${list
      .map(
        ([cwe, n]) => `<div class="sev-row" style="max-width:80%">
          <span style="width:84px">${esc(cwe)}</span>
          <span class="bar"><i style="width:${(n / max) * 100}%;background:rgba(237,239,244,0.4)"></i></span>
          <span class="n">${n}</span>
        </div>`
      )
      .join("")}
  </section>`;
}

async function renderProject(a) {
  const tab = parts()[2] || "overview";
  const findings = a.findings || [];
  const filtered = state.filter === "all" ? findings : findings.filter((f) => f.severity === state.filter);
  const counts = countsFrom(findings);
  const headerBlock = `${header()}
    <main class="wrap page">
      <a class="back" href="#/">← All audits</a>
      <div class="page-head">
        <div class="tiny" style="margin-top:16px">${esc(a.mode)} · ${esc(a.status)}</div>
        <h1>${esc(a.name)}</h1>
        <p class="muted">${esc(a.source)}</p>
        ${
          a.coverage
            ? `<p class="tiny" style="margin-top:10px">Routes ${a.coverage.reviewed || 0}/${a.coverage.total || 0} reviewed · ${a.coverage.findings || 0} with findings · ${a.coverage.open || 0} still open</p>`
            : ""
        }
        <div style="margin-top:16px;display:flex;gap:8px;flex-wrap:wrap">
          <a class="btn primary" href="/api/audits/${a.id}/report.md" target="_blank">Download report</a>
        </div>
      </div>
      <div class="tabs">
        <a href="#/audits/${a.id}" class="${tab === "overview" ? "on" : ""}">Overview</a>
        <a href="#/audits/${a.id}/findings" class="${tab === "findings" ? "on" : ""}">Findings</a>
        <a href="#/audits/${a.id}/activity" class="${tab === "activity" ? "on" : ""}">Activity</a>
      </div>`;

  if (tab === "findings") {
    app.innerHTML =
      headerBlock +
      `<div style="display:flex;gap:8px;margin:18px 0">
        ${["all", "critical", "high", "medium", "low"]
          .map((k) => `<button class="btn ${state.filter === k ? "primary" : "ghost"}" data-f="${k}">${k}</button>`)
          .join("")}
      </div>
      ${filtered
        .map((f) => {
          const open = state.openFinding === f.id;
          return `<article class="issue ${open ? "open" : ""}">
            <div class="issue-h" data-open="${f.id}">
              <div>
                <div style="display:flex;gap:6px;align-items:center;flex-wrap:wrap">
                  ${sevChip(f.severity)}
                  ${f.cwe ? `<span class="tag">${esc(f.cwe)}</span>` : ""}
                  ${f.details && f.details.owasp ? `<span class="tag">${esc(f.details.owasp)}</span>` : ""}
                  ${f.details && f.details.attacker ? `<span class="tag">${esc(f.details.attacker)}</span>` : ""}
                  ${f.category ? `<span class="tag">${esc(f.category)}</span>` : ""}
                </div>
                <h3>${esc(f.title)}</h3>
                <p class="muted">${esc(f.summary)}</p>
              </div>
              <span class="tiny">${f.verified ? "verified" : "unverified"} · ${esc(f.agent)}</span>
            </div>
            ${
              open
                ? `<div class="issue-b">
                    ${findingBody(f)}
                    <div style="display:flex;gap:8px;margin-top:16px">
                      ${["open", "accepted", "ignored", "fixed"]
                        .map((s) => `<button class="btn ${f.status === s ? "primary" : "ghost"}" data-st="${s}" data-id="${f.id}">${s}</button>`)
                        .join("")}
                    </div>
                  </div>`
                : ""
            }
          </article>`;
        })
        .join("") || `<div class="empty">No findings in this filter.</div>`}
    </main>`;
    app.querySelectorAll("[data-f]").forEach((btn) => {
      btn.onclick = () => {
        state.filter = btn.dataset.f;
        renderProject(state.audit);
      };
    });
    app.querySelectorAll("[data-open]").forEach((el) => {
      el.onclick = () => {
        state.openFinding = state.openFinding === el.dataset.open ? null : el.dataset.open;
        renderProject(state.audit);
      };
    });
    app.querySelectorAll("[data-st]").forEach((btn) => {
      btn.onclick = async () => {
        await api(`/api/audits/${a.id}/findings/${btn.dataset.id}`, {
          method: "PATCH",
          body: { status: btn.dataset.st },
        });
        await loadAudit(a.id, true);
      };
    });
    return;
  }

  if (tab === "activity") {
    app.innerHTML =
      headerBlock +
      `<div class="panel" style="width:100%;margin-top:24px">
        <div class="feed" id="live-feed" style="max-height:none">${state.events.slice().reverse().map(eventRow).join("") || `<div class="empty">No events cached. Re-run to watch GLM hunt live.</div>`}</div>
      </div></main>`;
    return;
  }

  const tm = a.threat_model || {};
  const crit = findings.filter((f) => f.severity === "critical").length;
  app.innerHTML =
    headerBlock +
    `<div class="stat-row">
      <div class="stat-card"><div class="num">${findings.length}</div><p class="kicker">Findings</p></div>
      <div class="stat-card"><div class="num">${crit}</div><p class="kicker">Critical</p></div>
      <div class="stat-card"><div class="num">${(a.chains || []).length}</div><p class="kicker">Attack chains</p></div>
      <div class="stat-card"><div class="num">${a.coverage ? `${a.coverage.reviewed || 0}/${a.coverage.total || 0}` : "—"}</div><p class="kicker">Routes reviewed</p></div>
    </div>
    <div class="two">
      <section>
        <p class="kicker">Severity mix</p>
        <div style="margin-top:10px">${sevBar(counts)}</div>
        ${cweBars(findings)}
        <p class="kicker" style="margin-top:28px">Highest severity</p>
        ${(findings.slice(0, 4) || [])
          .map(
            (f) => `<a class="issue" href="#/audits/${a.id}/findings" style="display:block">
              <div class="issue-h">
                <div>
                  ${sevChip(f.severity)} ${f.cwe ? `<span class="tag">${esc(f.cwe)}</span>` : ""}
                  <h3 style="font-size:18px">${esc(f.title)}</h3>
                  <p class="muted">${esc(f.summary)}</p>
                </div>
              </div>
            </a>`
          )
          .join("") || `<div class="empty">No findings.</div>`}
      </section>
      <section>
        <p class="kicker">Attack chains</p>
        ${(a.chains || [])
          .map(
            (c) => `<div class="chain">${sevChip(c.severity)}<h3>${esc(c.title)}</h3>
              <p class="muted">${esc(c.summary)}</p>
              <ol class="steps">${(c.steps || []).map((s) => `<li>${esc(s)}</li>`).join("")}</ol>
            </div>`
          )
          .join("") || `<div class="empty">No chains.</div>`}
        <div class="tm" style="margin-top:22px">
          <p class="kicker">Threat model</p>
          <p class="muted">${esc(tm.summary || "Mapper has not written a threat model yet.")}</p>
        </div>
      </section>
    </div>
    </main>`;
}

async function renderAgents() {
  state.agents = await api("/api/agents");
  app.innerHTML = `${header()}<main class="wrap page">
    <p class="kicker">Roster</p>
    <h1>Orchestrate agents</h1>
    <p class="lede">Each specialist hunts a class, then writes a full ticket — not a one-line alert. Toggle who runs on the next scan.</p>
    ${state.agents
      .map(
        (a) => `<label class="agent-row">
          <input type="checkbox" data-toggle="${esc(a.id)}" ${a.enabled ? "checked" : ""} />
          <div><b>${esc(a.name)}</b><div class="muted">${esc(a.description)}</div></div>
          <span class="tiny">${esc(a.phase)}</span>
        </label>`
      )
      .join("")}
    <form class="form" id="custom" style="margin-top:28px;max-width:480px">
      <label>Custom specialist id</label><input class="field" name="id" required />
      <label>Name</label><input class="field" name="name" required />
      <label>Hunt brief</label><textarea class="field" name="focus" required></textarea>
      <button class="btn primary" style="margin-top:16px" type="submit">Add to roster</button>
    </form>
  </main>`;
  app.querySelectorAll("[data-toggle]").forEach((el) => {
    el.onchange = () =>
      api(`/api/agents/${el.dataset.toggle}`, { method: "PATCH", body: { enabled: el.checked } });
  });
  $("#custom").onsubmit = async (ev) => {
    ev.preventDefault();
    const fd = new FormData(ev.target);
    try {
      await api("/api/agents", {
        method: "POST",
        body: { id: fd.get("id"), name: fd.get("name"), focus: fd.get("focus"), description: "" },
      });
      renderAgents();
    } catch (err) {
      toast(err.message);
    }
  };
}

async function renderSettings() {
  const s = await api("/api/settings");
  app.innerHTML = `${header()}<main class="wrap page">
    <p class="kicker">Engine</p>
    <h1>GLM-5.3 settings</h1>
    <p class="lede">Vuln defaults to Z.ai GLM-5.3 — the cybersecurity-tuned coding model. Keys stay on this host.</p>
    <form class="form" id="settings" style="max-width:520px">
      <label>Provider</label>
      <select class="field" name="provider">
        <option value="auto" ${!s.provider || s.provider === "auto" ? "selected" : ""}>Auto (GLM if keyed, else Grok)</option>
        <option value="zai" ${s.provider === "zai" ? "selected" : ""}>Z.ai GLM-5.3</option>
        <option value="xai" ${s.provider === "xai" ? "selected" : ""}>SpaceXAI Grok</option>
      </select>
      <label>Z.ai API key ${s.zai ? "· set" : ""}</label>
      <input class="field" name="zai_key" type="password" placeholder="${s.zai ? "••••••••  (leave blank to keep)" : "paste ZAI_API_KEY"}" />
      <label>xAI API key ${s.xai ? "· set" : ""}</label>
      <input class="field" name="xai_key" type="password" placeholder="${s.xai ? "••••••••  (leave blank to keep)" : "optional fallback"}" />
      <button class="btn primary" style="margin-top:18px" type="submit">Save</button>
    </form>
    <p class="tiny" style="margin-top:18px">Or export ZAI_API_KEY in .env and restart. Coding-plan hosts can set ZAI_BASE_URL=https://api.z.ai/api/coding/paas/v4</p>
  </main>`;
  $("#settings").onsubmit = async (ev) => {
    ev.preventDefault();
    const fd = new FormData(ev.target);
    const body = { provider: fd.get("provider") };
    if (fd.get("zai_key")) body.zai_key = fd.get("zai_key");
    if (fd.get("xai_key")) body.xai_key = fd.get("xai_key");
    try {
      await api("/api/settings", { method: "POST", body });
      await refreshHealth();
      toast("Saved");
      renderSettings();
    } catch (err) {
      toast(err.message);
    }
  };
}

async function route() {
  stopAsciiHero();
  modal.hidden = true;
  const p = parts();
  try {
    if (!p.length) return renderHome();
    if (p[0] === "agents") return renderAgents();
    if (p[0] === "settings") return renderSettings();
    if (p[0] === "audits") return renderAudit();
    return renderHome();
  } catch (err) {
    app.innerHTML = `${header()}<main class="wrap page"><div class="empty">${esc(err.message)}</div></main>`;
  }
}

window.addEventListener("hashchange", route);
window.addEventListener("keydown", (e) => {
  if (e.key === "Escape") modal.hidden = true;
});

(async function boot() {
  try {
    await refreshHealth();
  } catch {
    state.health = { live: false };
  }
  route();
})();
