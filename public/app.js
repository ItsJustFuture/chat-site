"use strict";

// Debug hook: enable tap hit-testing logs by setting `window.__TAP_DEBUG__ = true` in the console.
window.__TAP_DEBUG__ = window.__TAP_DEBUG__ ?? false;
const IS_IOS = /iPad|iPhone|iPod/.test(navigator.userAgent) || (navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1);
const PREFERS_REDUCED_MOTION = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
const DELETE_ANIM_MS = PREFERS_REDUCED_MOTION ? 1 : 200;

function safeJsonParse(raw, fallback) {
  try {
    if (raw === null || raw === undefined || raw === "") return fallback;
    if (typeof raw === "object") return raw;
    return JSON.parse(raw);
  } catch {
    return fallback;
  }
}

function safeNumber(value, fallback = 0) {
  const num = Number(value);
  return Number.isFinite(num) ? num : fallback;
}

function safeString(value, fallback = "") {
  if (typeof value === "string") return value;
  if (value === null || value === undefined) return fallback;
  return String(value);
}

function triggerReactionBounce(btn, removing = false){
  if (!btn || !btn.classList || PREFERS_REDUCED_MOTION) return;
  const addClass = removing ? "react-bounce-remove" : "react-bounce-add";
  btn.classList.remove("react-bounce-add", "react-bounce-remove");
  void btn.offsetWidth;
  btn.classList.add(addClass);
  btn.addEventListener("animationend", () => btn.classList.remove(addClass), { once:true });
}

function withFlip(container, keyAttr, updateFn){
  if (!container || typeof updateFn !== "function" || PREFERS_REDUCED_MOTION) {
    updateFn?.();
    return;
  }
  const firstRects = new Map();
  container.querySelectorAll(`[${keyAttr}]`).forEach((el) => {
    const key = el.getAttribute(keyAttr);
    if (!key) return;
    firstRects.set(key, el.getBoundingClientRect());
  });

  updateFn();

  container.querySelectorAll(`[${keyAttr}]`).forEach((el) => {
    const key = el.getAttribute(keyAttr);
    if (!key || !firstRects.has(key)) return;
    const first = firstRects.get(key);
    const last = el.getBoundingClientRect();
    const dx = first.left - last.left;
    const dy = first.top - last.top;
    if (!dx && !dy) return;
    el.classList.remove("anim-flip");
    el.style.transform = `translate(${dx}px, ${dy}px)`;
    el.classList.add("anim-flip");
    requestAnimationFrame(() => {
      el.style.transform = "";
    });
    const cleanup = () => {
      el.classList.remove("anim-flip");
      el.style.transform = "";
    };
    el.addEventListener("transitionend", cleanup, { once:true });
    setTimeout(cleanup, 220);
  });
}

// ---- Toasts (lightweight inline confirmations)
let toastStackEl = null;
function ensureToastStack(){
  if (toastStackEl) return toastStackEl;
  const wrap = document.createElement("div");
  wrap.className = "toastStack";
  wrap.setAttribute("aria-live", "polite");
  wrap.setAttribute("aria-atomic", "true");
  wrap.id = "toastStack";
  document.body.appendChild(wrap);
  toastStackEl = wrap;
  return toastStackEl;
}
function showToast(message, { actionLabel, actionFn, durationMs = 4200 } = {}){
  const root = ensureToastStack();
  const toast = document.createElement("div");
  toast.className = "toast";
  const msg = document.createElement("div");
  msg.className = "toastMessage";
  msg.textContent = safeString(message, "");
  toast.appendChild(msg);

  if (actionLabel && typeof actionFn === "function") {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "btn btnTertiary toastAction";
    btn.textContent = actionLabel;
    btn.addEventListener("click", () => {
      try {
        const result = actionFn();
        if (result && typeof result.then === "function") {
          result.catch(() => showToast("Couldn’t undo — try again."));
        }
      } catch {
        showToast("Couldn’t undo — try again.");
      }
      toast.remove();
    });
    toast.appendChild(btn);
  }

  root.appendChild(toast);
  const toasts = Array.from(root.querySelectorAll(".toast"));
  if (toasts.length > 3) {
    toasts.slice(0, toasts.length - 3).forEach((el) => el.remove());
  }

  const duration = Number(durationMs) || 4200;
  const timer = setTimeout(() => toast.remove(), duration);
  toast.addEventListener("mouseenter", () => clearTimeout(timer));
  toast.addEventListener("mouseleave", () => setTimeout(() => toast.remove(), 1200));
  return toast;
}
const toast = showToast;

// ---- Rooms: Site/User mode (pill switcher under Latest update)
let activeRoomMode = (localStorage.getItem("roomMode") || "site").toLowerCase();
if(activeRoomMode !== "site" && activeRoomMode !== "user") activeRoomMode = "site";

function getRoomModeMasterName(){
  return activeRoomMode === "user" ? "User Rooms" : "Site Rooms";
}

function ensureRoomModeSwitch(){
  const latestUpdate = document.getElementById("latestUpdate");
  const roomsPanel = document.getElementById("roomsPanel");
  if(!latestUpdate || !roomsPanel) return;
  if(document.getElementById("roomModeSwitch")) return;

  const wrap = document.createElement("div");
  wrap.className = "roomModeSwitch";
  wrap.id = "roomModeSwitch";
  wrap.innerHTML = `
    <button type="button" data-room-mode="site">Site Rooms</button>
    <button type="button" data-room-mode="user">User Rooms</button>
  `;

  latestUpdate.insertAdjacentElement("afterend", wrap);

  const sync = () => {
    wrap.querySelectorAll("button").forEach((btn) => {
      btn.classList.toggle("active", btn.dataset.roomMode === activeRoomMode);
    });
  };
  sync();

  wrap.addEventListener("click", (e) => {
    const btn = e.target?.closest?.("button[data-room-mode]");
    if(!btn) return;
    const next = btn.dataset.roomMode;
    if(next !== "site" && next !== "user") return;
    if(next === activeRoomMode) return;
    activeRoomMode = next;
    try{ localStorage.setItem("roomMode", activeRoomMode); }catch(_){ /* ignore */ }
    sync();
    // Re-render the room list with the new mode.
    renderRoomsList(roomStructure || []);
  });
}

// ---- Scroll pinning scheduler (hoisted)
// This function is referenced early (e.g. visualViewport listeners inside initLayoutMetrics).
// It must be hoisted to avoid TDZ/ReferenceError when app.js is evaluated.
let __stickToBottomRaf = 0;
function queueStickToBottom(){
  if(__stickToBottomRaf) cancelAnimationFrame(__stickToBottomRaf);
  __stickToBottomRaf = requestAnimationFrame(()=>{
    if(typeof stickToBottomIfWanted !== "function") return;
    stickToBottomIfWanted();
  });
}

// ---- Theme registry with tiers
const THEMES = [
  // Public themes (everyone)
  { id:"minimal-light", name:"Minimal Light", mode:"light", tier:"public" },
  { id:"minimal-dark", name:"Minimal Dark", mode:"dark", tier:"public" },
  { id:"minimal-light-hc", name:"Minimal Light (High Contrast)", mode:"light", tier:"public" },
  { id:"minimal-dark-hc", name:"Minimal Dark (High Contrast)", mode:"dark", tier:"public" },
  { id:"paper", name:"Paper / Parchment", mode:"light", tier:"public" },
  { id:"sky-light", name:"Sky Light", mode:"light", tier:"public" },
  { id:"fantasy-tavern", name:"Fantasy Tavern", mode:"dark", tier:"public" },
  { id:"fantasy-tavern-ember", name:"Fantasy Tavern (Ember)", mode:"dark", tier:"public" },
  { id:"desert-dusk", name:"Desert Dusk", mode:"dark", tier:"public" },

  // VIP: everything else (future-proof)
  { id:"__vip__", name:"VIP Exclusive", tier:"vip", hidden:true }
];


/* ---- Visual viewport + layout shell metrics (single source of truth) ---- */
(function initLayoutMetrics(){
  const root = document.documentElement;
  const body = document.body;
  const selectors = {
    appRoot: "#app",
    chatShell: "main.chat",
    chatScroller: ".msgs",
    composer: ".inputBar",
    menuShell: ".menuPanel",
    menuScroller: ".channels .menuContent",
    header: ".topbar",
    player: "#ytSticky",
    menuHeader: ".menuNav",
    changelog: "#changelogEditor",
    changelogInput: "#changelogBodyInput, #changelogTitleInput",
    dmScroller: ".dmPanel .dmMessages, #dmModal .dmMessages, .dmMsgs, .messages"
  };

  const isIOS = IS_IOS;
  if(body) body.classList.toggle("ios", isIOS);

  let raf = 0;
  let overlay = null;
  let outlineSheet = null;

  const debugEnabled = () => localStorage.getItem("debugKB") === "1";

  function toggleDebugClass(on){
    if(!body) return;
    body.classList.toggle("debug-kb", !!on);
  }

  function ensureOverlay(){
    const on = debugEnabled();
    toggleDebugClass(on);
    if(!on){
      if(overlay){ overlay.remove(); overlay = null; }
      if(outlineSheet){ outlineSheet.remove(); outlineSheet = null; }
      return;
    }
    if(!outlineSheet){
      outlineSheet = document.createElement("style");
      outlineSheet.id = "kbDebugOutlines";
      const outlineTargets = [
        selectors.appRoot,
        selectors.chatShell,
        selectors.chatScroller,
        selectors.composer,
        selectors.header,
        selectors.menuShell,
        selectors.menuScroller,
        selectors.player,
        selectors.changelog
      ].map(sel => `body.debug-kb ${sel}`).join(",\n");
      const changelogInputs = selectors.changelogInput.split(",").map(s => `body.debug-kb ${s.trim()}`).join(",\n");
      outlineSheet.textContent = `
        ${outlineTargets} {
          outline: 2px solid rgba(0, 200, 255, 0.45);
          outline-offset: -2px;
        }
        ${changelogInputs} {
          outline: 2px dashed rgba(255, 150, 0, 0.55);
          outline-offset: 2px;
        }
      `;
      document.head.appendChild(outlineSheet);
    }
    if(overlay) return;
    overlay = document.createElement("div");
    overlay.id = "kbDebugOverlay";
    Object.assign(overlay.style, {
      position: "fixed",
      right: "8px",
      bottom: "8px",
      zIndex: "9999",
      background: "rgba(0,0,0,0.78)",
      color: "#fff",
      fontSize: "11px",
      padding: "10px",
      borderRadius: "10px",
      maxWidth: "360px",
      lineHeight: "1.4",
      pointerEvents: "none",
      fontFamily: "Menlo, Consolas, monospace",
      boxShadow: "0 8px 24px rgba(0,0,0,0.35)",
      backdropFilter: "blur(6px)"
    });
    document.body.appendChild(overlay);
  }

  function measureRect(sel){
    const el = typeof sel === "string" ? document.querySelector(sel) : sel;
    if(!el || !el.getBoundingClientRect) return null;
    const r = el.getBoundingClientRect();
    return { top: Math.round(r.top), bottom: Math.round(r.bottom), height: Math.round(r.height) };
  }

  function measureHeight(sel){
    const rect = measureRect(sel);
    return rect ? rect.height : 0;
  }

  function isVisible(el){
    if(!el) return false;
    const style = getComputedStyle(el);
    if(style.display === "none" || style.visibility === "hidden") return false;
    return el.offsetHeight > 0;
  }

  function renderOverlay(metrics){
    ensureOverlay();
    if(!overlay) return;
    const cs = getComputedStyle(root);
    const val = (name) => cs.getPropertyValue(name).trim();
    const describeScroll = (obj) => {
      if(!obj || !obj.el) return "n/a";
      return `${obj.name} [h:${obj.el.clientHeight} sh:${obj.el.scrollHeight} top:${Math.round(obj.el.scrollTop)}]`;
    };
    const lines = [
      `innerHeight: ${window.innerHeight} | doc.clientHeight: ${document.documentElement.clientHeight}`,
      `vv.height: ${metrics.vvHeight} | vv.offsetTop: ${metrics.vvTop} | vv.pageTop: ${metrics.vvPageTop}`,
      `kbInset: ${metrics.kbInset}`,
      `vars --vvh:${val("--vvh")} --vvhPx:${val("--vvhPx")} --vvTop:${val("--vvTop")} --kbInset:${val("--kbInset")}`,
      `header:${val("--headerH")} composer:${val("--composerH")} player:${val("--playerH")} menuHeader:${val("--menuHeaderH")}`,
      `chat scroll: ${describeScroll(metrics.chatScroll)}`,
      `dm scroll: ${describeScroll(metrics.dmScroll)}`,
      `menu scroll: ${describeScroll(metrics.menuScroll)}`,
      `Rect app: ${metrics.appRect ? JSON.stringify(metrics.appRect) : "n/a"}`,
      `Rect topbar: ${metrics.headerRect ? JSON.stringify(metrics.headerRect) : "n/a"}`,
      `Rect chat shell: ${metrics.chatShellRect ? JSON.stringify(metrics.chatShellRect) : "n/a"}`,
      `Rect msgs: ${metrics.chatRect ? JSON.stringify(metrics.chatRect) : "n/a"}`,
      `Rect composer: ${metrics.composerRect ? JSON.stringify(metrics.composerRect) : "n/a"}`,
      `Rect menu shell: ${metrics.menuShellRect ? JSON.stringify(metrics.menuShellRect) : "n/a"}`,
      `Rect menuContent: ${metrics.menuRect ? JSON.stringify(metrics.menuRect) : "n/a"}`,
      `Rect changelog form: ${metrics.changelogRect ? JSON.stringify(metrics.changelogRect) : "n/a"}`,
      `Active input: ${metrics.activeInput || "none"}`
    ];
    overlay.innerHTML = lines.join("<br>");
  }

  function collectMetrics(){
    const vv = window.visualViewport;
    const vvReliable = vv && typeof vv.height === "number" && vv.height > 120;
    const vvHeight = vvReliable ? vv.height : window.innerHeight;
    const vvTop = vvReliable ? Number(vv.offsetTop || 0) : 0;
    const vvPageTop = vvReliable && typeof vv.pageTop === "number" ? vv.pageTop : "";
    const kbInset = Math.max(0, Math.round(window.innerHeight - vvHeight - vvTop));

    const composer = document.querySelector(selectors.composer);
    const player = document.querySelector(selectors.player);

    const headerH = measureHeight(selectors.header) || 54;
    const composerH = measureHeight(composer) || 72;
    const menuHeaderH = measureHeight(selectors.menuHeader) || 0;

    const metrics = {
      vvHeight: Math.round(vvHeight),
      vvTop,
      vvPageTop,
      kbInset,
      headerH,
      composerH,
      playerH: (isVisible(player) && !player?.classList.contains("is-hidden")) ? measureHeight(player) : 0,
      menuHeaderH,
      appRect: measureRect(selectors.appRoot),
      chatShellRect: measureRect(selectors.chatShell),
      headerRect: measureRect(selectors.header),
      chatRect: measureRect(selectors.chatScroller),
      composerRect: measureRect(selectors.composer),
      menuShellRect: measureRect(selectors.menuShell),
      menuRect: measureRect(selectors.menuScroller),
      changelogRect: measureRect(selectors.changelog),
      chatScroll: describeScroller("main.chat .msgs"),
      dmScroll: describeScroller(selectors.dmScroller),
      menuScroll: describeScroller(selectors.menuScroller),
      activeInput: document.activeElement && document.activeElement.tagName ? document.activeElement.tagName.toLowerCase() : ""
    };

    root.style.setProperty("--vvh", `${metrics.vvHeight}px`);
    root.style.setProperty("--vvhPx", `${metrics.vvHeight}px`);
    root.style.setProperty("--vvTop", `${metrics.vvTop}px`);
    root.style.setProperty("--kbInset", `${metrics.kbInset}px`);
    root.style.setProperty("--headerH", `${metrics.headerH}px`);
    root.style.setProperty("--composerH", `${metrics.composerH}px`);
    root.style.setProperty("--playerH", `${metrics.playerH}px`);
    root.style.setProperty("--menuHeaderH", `${metrics.menuHeaderH}px`);

    if(body) body.classList.toggle("kb-open", metrics.kbInset > 40);
    renderOverlay(metrics);
    runInvariants(metrics);
    return metrics;
  }

  function describeScroller(sel){
    const el = typeof sel === "string" ? document.querySelector(sel) : sel;
    if(!el) return null;
    const style = getComputedStyle(el);
    const isScroll = /(auto|scroll)/.test(style.overflowY || "") || el.classList.contains("msgs");
    return { el, name: sel, isScroll };
  }

  function runInvariants(metrics){
    if(!debugEnabled()) return;
    const appEl = document.querySelector(selectors.appRoot);
    const msgs = document.querySelector(selectors.chatScroller);
    const composer = document.querySelector(selectors.composer);
    if(!appEl || !msgs || !composer) return;
    const appRect = appEl.getBoundingClientRect();
    const msgsRect = msgs.getBoundingClientRect();
    const composerRect = composer.getBoundingClientRect();
    const vv = window.visualViewport;
    const expectedBottom = (vv?.height || window.innerHeight) + (vv?.offsetTop || 0);
    const tolerance = 3;
    const failures = [];
    if(Math.abs(appRect.bottom - expectedBottom) > tolerance){ failures.push("app shell not bound to visualViewport"); }
    if(composerRect.bottom - appRect.bottom > tolerance){ failures.push("composer exceeds shell"); }
    if(Math.abs(msgsRect.bottom - composerRect.top) > tolerance){ failures.push("msgs not meeting composer"); }
    if(failures.length){
      console.warn("[layout invariant FAIL]", failures.join("; "), { appRect, msgsRect, composerRect, metrics });
    }
  }

  function schedule(label){
    if(debugEnabled() && label) console.log("[layout]", label);
    if(raf) cancelAnimationFrame(raf);
    raf = requestAnimationFrame(()=>{ raf = 0; collectMetrics(); });
  }

  window.addEventListener("resize", () => schedule("resize"), { passive:true });
  window.addEventListener("orientationchange", () => schedule("orientationchange"), { passive:true });
  if(window.visualViewport){
    window.visualViewport.addEventListener("resize", () => schedule("vv-resize"), { passive:true });
    window.visualViewport.addEventListener("scroll", () => schedule("vv-scroll"), { passive:true });
  }

  window.addEventListener("load", () => schedule("load"), { passive:true, once:true });
  document.addEventListener("visibilitychange", () => { if(!document.hidden) schedule("visible"); });
  document.addEventListener("focusin", () => schedule("focusin"));
  document.addEventListener("focusout", () => schedule("focusout"));
  const scrollWatch = () => schedule("scroll container");
  [selectors.chatScroller, selectors.menuScroller, selectors.dmScroller].forEach(sel => {
    document.querySelector(sel)?.addEventListener("scroll", scrollWatch, { passive:true });
  });

  schedule("init");
})();

/* ---- Tap interceptor debug (iOS topbar hit-test) ---- */
(function initTapInterceptorDebug(){
  if(!window.__TAP_DEBUG__) return;

  const highlight = (el) => {
    if(!el || !el.style) return;
    const prevOutline = el.style.outline;
    const prevOffset = el.style.outlineOffset;
    el.style.outline = "3px solid red";
    el.style.outlineOffset = "-3px";
    setTimeout(() => {
      el.style.outline = prevOutline;
      el.style.outlineOffset = prevOffset;
    }, 300);
  };

  const logTap = (e) => {
    const topbar = document.querySelector(".topbar");
    if(!topbar) return;

    const touch = (e.touches && e.touches[0]) ? e.touches[0] : e;
    if(!touch || typeof touch.clientX !== "number" || typeof touch.clientY !== "number") return;

    const rect = topbar.getBoundingClientRect();
    const withinTopbar = touch.clientX >= rect.left && touch.clientX <= rect.right && touch.clientY >= rect.top && touch.clientY <= rect.bottom;
    if(!withinTopbar) return;

    const topMost = document.elementFromPoint(touch.clientX, touch.clientY);
    const path = (typeof e.composedPath === "function") ? e.composedPath().slice(0, 10) : [];

    const topMostInfo = topMost ? (() => {
      const r = topMost.getBoundingClientRect();
      const cs = getComputedStyle(topMost);
      return {
        rect: { top: Math.round(r.top), left: Math.round(r.left), width: Math.round(r.width), height: Math.round(r.height) },
        styles: {
          position: cs.position,
          zIndex: cs.zIndex,
          pointerEvents: cs.pointerEvents,
          opacity: cs.opacity,
          visibility: cs.visibility,
          transform: cs.transform
        }
      };
    })() : null;

    console.log("[tap-debug]", {
      target: e.target,
      topMost,
      point: { x: touch.clientX, y: touch.clientY },
      path,
      topMostInfo
    });

    highlight(topMost);
  };

  ["pointerdown", "touchstart"].forEach(evt => {
    document.addEventListener(evt, logTap, { capture:true, passive:true });
  });
})();

// ---- iOS double-tap zoom guard (layered atop CSS/meta)
(function initIosDoubleTapGuard(){
  try{
    if(!IS_IOS || !document?.addEventListener) return;
    let lastTapTs = 0;
    let lastX = 0;
    let lastY = 0;
    const radius = 20;
    const thresholdMs = 320;
    const formSelector = "input, textarea, select, option, [contenteditable='true']";
    const linkSelector = "a[href]";

    const onTouchEnd = (ev) => {
      try{
        if(ev.touches && ev.touches.length > 1) { lastTapTs = 0; return; }
        const touch = ev.changedTouches && ev.changedTouches[0];
        if(!touch) return;
        const target = ev.target;
        const now = Date.now();
        const dx = touch.clientX - lastX;
        const dy = touch.clientY - lastY;
        const dist = Math.hypot(dx, dy);
        const isForm = !!(target && target.closest && target.closest(formSelector));
        const isLink = !!(target && target.closest && target.closest(linkSelector));

        if(!isForm && !isLink && now - lastTapTs > 0 && now - lastTapTs < thresholdMs && dist < radius){
          ev.preventDefault();
        }

        lastTapTs = now;
        lastX = touch.clientX;
        lastY = touch.clientY;
      }catch{}
    };

    document.addEventListener("touchend", onTouchEnd, { passive:false, capture:true });
  }catch{}
})();

/* ---- Focus visibility helper (keep inputs inside their scroll shells) ---- */
(function initFocusVisibility(){
  const scrollSelectors = [
    ".msgs",
    ".channels .menuContent",
    ".menuContent",
    ".modalBody",
    ".dmMessages",
    ".dmMsgs",
    ".messages"
  ];

  function findScrollContainer(el){
    let node = el;
    while(node && node !== document.body){
      if(node.matches && scrollSelectors.some(sel => node.matches(sel))) return node;
      node = node.parentElement;
    }
    return null;
  }

  function scrollNearest(target){
    if(!target || !(target instanceof HTMLElement)) return;
    const isFormEl = target instanceof HTMLInputElement || target instanceof HTMLTextAreaElement || target instanceof HTMLSelectElement || target.isContentEditable;
    if(!isFormEl) return;

    let container = findScrollContainer(target);
    if(!container){
      const chatShell = target.closest("main.chat, .chat");
      if(chatShell) container = chatShell.querySelector(".msgs");
    }
    if(!container) return;

    if(container.classList.contains("msgs")){
      container.scrollTop = container.scrollHeight;
      return;
    }

    container.scrollIntoView({ block: "nearest", inline: "nearest" });
    container.scrollTop = Math.max(0, container.scrollTop - 12);
  }

  document.addEventListener("focusin", (e) => {
    scrollNearest(e.target);
  }, { passive:true });
})();

/* ---- Quiet sound cues (optional) ---- */
const Sound = (() => {
  // Settings keys
  const KEY_ENABLED = "soundEnabled";
  const KEY_ROOM = "soundRoom";
  const KEY_DM = "soundDm";
  const KEY_MENTION = "soundMention";
  const KEY_SENT = "soundSent";
  const KEY_RECEIVE = "soundReceive";
  const KEY_REACTION = "soundReaction";

  let ctx = null;

  function getBool(key, def = false){
    const v = localStorage.getItem(key);
    if (v === null) return def;
    return v === "1";
  }
  function setBool(key, on){
    localStorage.setItem(key, on ? "1" : "0");
  }

  function enabled(){ return getBool(KEY_ENABLED, false); }
  function roomOn(){ return getBool(KEY_ROOM, true); }
  function dmOn(){ return getBool(KEY_DM, true); }
  function mentionOn(){ return getBool(KEY_MENTION, true); }
  function sentOn(){ return getBool(KEY_SENT, false); }
  function receiveOn(){ return getBool(KEY_RECEIVE, false); }
  function reactionOn(){ return getBool(KEY_REACTION, false); }

  async function ensureUnlocked(){
    if (!enabled()) return false;
    if (!ctx) ctx = new (window.AudioContext || window.webkitAudioContext)();
    if (ctx.state === "suspended") {
      try { await ctx.resume(); } catch {}
    }
    return ctx && ctx.state === "running";
  }

  function beep({ freq = 660, dur = 0.06, vol = 0.05, type = "sine" } = {}){
    if (!enabled()) return;
    // Try to lazily unlock audio (some browsers require a prior user gesture).
    try {
      if (!ctx) ctx = new (window.AudioContext || window.webkitAudioContext)();
      if (ctx.state === "suspended") {
        // Fire-and-forget resume; if it succeeds, we'll retry once shortly.
        ctx.resume?.().then(() => {
          // Retry once after resume (if this beep was attempted before unlock)
          setTimeout(() => { try { beep({ freq, dur, vol, type }); } catch {} }, 30);
        }).catch(() => {});
        return;
      }
      if (ctx.state !== "running") return;
    } catch { return; }

    try{
      const t0 = ctx.currentTime;
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();

      osc.type = type;
      osc.frequency.setValueAtTime(freq, t0);

      // Very quiet, gentle envelope
      gain.gain.setValueAtTime(0.0001, t0);
      gain.gain.exponentialRampToValueAtTime(Math.max(0.0002, vol), t0 + 0.01);
      gain.gain.exponentialRampToValueAtTime(0.0001, t0 + dur);

      osc.connect(gain);
      gain.connect(ctx.destination);

      osc.start(t0);
      osc.stop(t0 + dur + 0.02);
    }catch{}
  }

  const cues = {
    room: () => beep({ freq: 520, dur: 0.05, vol: 0.045 }),
    dm: () => { beep({ freq: 740, dur: 0.05, vol: 0.05 }); setTimeout(()=>beep({ freq: 980, dur: 0.05, vol: 0.04 }), 70); },
    mention: () => beep({ freq: 880, dur: 0.06, vol: 0.05, type: "triangle" }),
    sent: () => beep({ freq: 600, dur: 0.05, vol: 0.04, type: "sine" }),
    receive: () => beep({ freq: 460, dur: 0.06, vol: 0.045, type: "sine" }),
    reaction: () => beep({ freq: 760, dur: 0.05, vol: 0.035, type: "triangle" }),
  };

  function shouldRoom(){ return enabled() && roomOn(); }
  function shouldDm(){ return enabled() && dmOn(); }
  function shouldMention(){ return enabled() && mentionOn(); }
  function shouldSent(){ return enabled() && sentOn(); }
  function shouldReceive(){ return enabled() && receiveOn(); }
  function shouldReaction(){ return enabled() && reactionOn(); }

  function exportPrefs(){
    return {
      enabled: enabled(),
      room: roomOn(),
      dm: dmOn(),
      mention: mentionOn(),
      sent: sentOn(),
      receive: receiveOn(),
      reaction: reactionOn(),
    };
  }

  function importPrefs(p = {}){
    if (!p || typeof p !== "object") return;
    for (const [key, store] of [["enabled", KEY_ENABLED], ["room", KEY_ROOM], ["dm", KEY_DM], ["mention", KEY_MENTION], ["sent", KEY_SENT], ["receive", KEY_RECEIVE], ["reaction", KEY_REACTION]]) {
      if (typeof p[key] === "boolean") setBool(store, p[key]);
    }
  }

  return {
    keys: { KEY_ENABLED, KEY_ROOM, KEY_DM, KEY_MENTION, KEY_SENT, KEY_RECEIVE, KEY_REACTION },
    get: { enabled, roomOn, dmOn, mentionOn, sentOn, receiveOn, reactionOn },
    set: { setBool },
    ensureUnlocked,
    cues,
    exportPrefs,
    importPrefs,
    shouldRoom, shouldDm, shouldMention, shouldSent, shouldReceive, shouldReaction
  };
})();
/* ---- Sound unlock helper: attempt resume on first user gesture ---- */
(function wireSoundUnlockOnce(){
  let armed = true;
  async function unlock(){
    if (!armed) return;
    armed = false;
    try { await Sound.ensureUnlocked(); } catch {}
  }
  window.addEventListener("pointerdown", unlock, { passive:true, once:true });
  window.addEventListener("touchstart", unlock, { passive:true, once:true });
  window.addEventListener("keydown", unlock, { once:true });
})();
;
;

/* ---- iOS Safari: prevent input-focus zoom (font-size must be >= 16px) */
(function preventIosInputZoom(){
  const isIOS = /iPad|iPhone|iPod/.test(navigator.userAgent) || (navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1);
  if(!isIOS) return;

  function needsFix(el){
    if(!el || !(el instanceof HTMLElement)) return false;
    const tag = el.tagName?.toLowerCase();
    if(tag !== "input" && tag !== "textarea" && tag !== "select") return false;
    // Don't interfere with range sliders (they're fine)
    if(tag === "input" && el.type === "range") return false;
    const fs = parseFloat(getComputedStyle(el).fontSize || "16");
    return Number.isFinite(fs) && fs > 0 && fs < 16;
  }

  document.addEventListener("focusin", (e)=>{
    const el = e.target;
    if(!needsFix(el)) return;
    if(!el.dataset.__prevFontSize) el.dataset.__prevFontSize = el.style.fontSize || "";
    el.style.fontSize = "16px";
  });

  document.addEventListener("focusout", (e)=>{
    const el = e.target;
    if(!el || !(el instanceof HTMLElement)) return;
    if(el.dataset.__prevFontSize !== undefined){
      el.style.fontSize = el.dataset.__prevFontSize;
      delete el.dataset.__prevFontSize;
    }
  });
})();


(function forceHideYouTubeStickyOnBoot(){
  function hide(){
    const el = document.getElementById("ytSticky");
    if(!el) return;
    el.classList.add("is-hidden");
    el.classList.remove("yt-compact", "yt-collapsed");
    el.classList.add("yt-expanded");
  }
  if(document.readyState === "loading"){
    document.addEventListener("DOMContentLoaded", hide, { once:true });
  } else {
    hide();
  }
})();


let socket = null;
let me = null;
let progression = { gold: 0, xp: 0, level: 1, xpIntoLevel: 0, xpForNextLevel: 100 };
let activeProfileTab = "profile";
let activeCustomizePage = null;
let profileEditMode = false;
let currentProfileIsSelf = false;
let profileLikeState = { count: 0, liked: false, isSelf: false };
let modalFriendInfo = null;
let currentRoom = "main";
let featureFlags = {};
let memoryFeatureAvailable = false;
let memoryEnabled = false;
let memorySettingsLoaded = false;
let memoryFilter = "all";
let memoryLoading = false;
let roomStructure = { masters: [], categories: [], rooms: [] };
let roomCollapseState = { master: {}, category: {} };
const memoryCacheByFilter = new Map();
const DICE_ROOM_ID = "diceroom";
const SURVIVAL_ROOM_ID = "survivalsimulator";
function isDiceRoom(activeRoom){
  const roomName = typeof activeRoom === "string"
    ? activeRoom
    : (activeRoom?.name ?? activeRoom?.id ?? "");
  return String(roomName || "").toLowerCase() === DICE_ROOM_ID;
}
function isSurvivalRoom(activeRoom){
  const roomName = typeof activeRoom === "string"
    ? activeRoom
    : (activeRoom?.name ?? activeRoom?.id ?? "");
  return String(roomName || "").toLowerCase() === SURVIVAL_ROOM_ID;
}
function displayRoomName(room){
  if (isDiceRoom(room)) return "Dice Room";
  if (isSurvivalRoom(room)) return "Survival Simulator";
  return room;
}

let lastUsers = [];
let membersViewMode = "room"; // room|friends
let friendsCache = [];
let friendsDirty = true;
const roleCache = new Map();
const reactionsCache = Object.create(null);
const dmReactionsCache = Object.create(null);
const dmReadCache = Object.create(null); // threadId -> { userId, messageId, ts }
const userFxMap = Object.create(null);
const CHAT_FX_DEFAULTS = Object.freeze({
  enabled: true,
  glow: "off",
  font: "system",
  nameFont: "system",
  radius: 14,
  border: 0,
  glass: 0,
  blur: 0,
  density: "cozy",
  accent: "",
  bubbleColor: "",
  textColor: "",
  nameColor: "",
  autoContrast: false,
  textBold: false,
  textItalic: false,
  textGlow: "off",
  textGradientEnabled: false,
  textGradientA: "",
  textGradientB: "",
  textGradientAngle: 135,
  polishPack: true,
  polishAuras: true,
  polishAnimations: true
});
const TONE_OPTIONS = Object.freeze([
  { key: "chill", emoji: "😌", name: "Chill", description: "Relaxed / friendly" },
  { key: "joke", emoji: "😂", name: "Joke", description: "Joking / playful" },
  { key: "sarcastic", emoji: "🙃", name: "Sarcastic", description: "Sarcasm" },
  { key: "serious", emoji: "⚠️", name: "Serious", description: "Serious / important" }
]);
const CHAT_FX_FONT_STACKS = Object.freeze({
  system: "system-ui, -apple-system, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, sans-serif",
  inter: "\"Inter\", system-ui, -apple-system, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, sans-serif",
  roboto: "\"Roboto\", system-ui, -apple-system, \"Segoe UI\", \"Helvetica Neue\", Arial, sans-serif",
  opensans: "\"Open Sans\", system-ui, -apple-system, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, sans-serif",
  lato: "\"Lato\", system-ui, -apple-system, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, sans-serif",
  poppins: "\"Poppins\", \"Segoe UI\", system-ui, -apple-system, Roboto, \"Helvetica Neue\", Arial, sans-serif",
  nunito: "\"Nunito\", \"Segoe UI\", system-ui, -apple-system, Roboto, \"Helvetica Neue\", Arial, sans-serif",
  jetbrains: "\"JetBrains Mono\", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, \"Liberation Mono\", \"Courier New\", monospace",
  inconsolata: "\"Inconsolata\", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, \"Liberation Mono\", \"Courier New\", monospace",
  spacemono: "\"Space Mono\", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, \"Liberation Mono\", \"Courier New\", monospace",
  ibmplexmono: "\"IBM Plex Mono\", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, \"Liberation Mono\", \"Courier New\", monospace",
  dmmono: "\"DM Mono\", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, \"Liberation Mono\", \"Courier New\", monospace",
  rubik: "\"Rubik\", system-ui, -apple-system, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, sans-serif",
  montserrat: "\"Montserrat\", system-ui, -apple-system, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, sans-serif",
  spacegrotesk: "\"Space Grotesk\", system-ui, -apple-system, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, sans-serif",
  worksans: "\"Work Sans\", system-ui, -apple-system, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, sans-serif",
  sourcesans3: "\"Source Sans 3\", system-ui, -apple-system, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, sans-serif",
  raleway: "\"Raleway\", system-ui, -apple-system, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, sans-serif",
  oswald: "\"Oswald\", system-ui, -apple-system, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, sans-serif",
  ubuntu: "\"Ubuntu\", system-ui, -apple-system, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, sans-serif",
  firasans: "\"Fira Sans\", system-ui, -apple-system, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, sans-serif",
  merriweather: "\"Merriweather\", Georgia, \"Times New Roman\", Times, serif",
  playfair: "\"Playfair Display\", Georgia, \"Times New Roman\", Times, serif",
  crimson: "\"Crimson Text\", Georgia, \"Times New Roman\", Times, serif",
  libreserif: "\"Libre Baskerville\", Georgia, \"Times New Roman\", Times, serif",
  robotoslab: "\"Roboto Slab\", Georgia, \"Times New Roman\", Times, serif",
  alegreya: "\"Alegreya\", Georgia, \"Times New Roman\", Times, serif",
  anton: "\"Anton\", system-ui, -apple-system, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, sans-serif",
  bebas: "\"Bebas Neue\", system-ui, -apple-system, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, sans-serif",
  abril: "\"Abril Fatface\", Georgia, \"Times New Roman\", Times, serif",
  pacifico: "\"Pacifico\", system-ui, -apple-system, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, sans-serif",
  dancing: "\"Dancing Script\", system-ui, -apple-system, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, sans-serif",
  caveat: "\"Caveat\", system-ui, -apple-system, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, sans-serif",
  indieflower: "\"Indie Flower\", system-ui, -apple-system, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, sans-serif",
  permanentmarker: "\"Permanent Marker\", system-ui, -apple-system, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, sans-serif",
  pressstart: "\"Press Start 2P\", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, \"Liberation Mono\", \"Courier New\", monospace",
  cinzel: "\"Cinzel\", Georgia, \"Times New Roman\", Times, serif",
  gothicA1: "\"Gothic A1\", system-ui, -apple-system, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, sans-serif",
  metalmania: "\"Metal Mania\", system-ui, -apple-system, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, sans-serif",
  orbitron: "\"Orbitron\", \"Segoe UI\", system-ui, -apple-system, \"Helvetica Neue\", Arial, sans-serif",
  oxanium: "\"Oxanium\", \"Segoe UI\", system-ui, -apple-system, \"Helvetica Neue\", Arial, sans-serif",
  audiowide: "\"Audiowide\", \"Segoe UI\", system-ui, -apple-system, \"Helvetica Neue\", Arial, sans-serif",
  rajdhani: "\"Rajdhani\", \"Segoe UI\", system-ui, -apple-system, \"Helvetica Neue\", Arial, sans-serif",
  chakrapetch: "\"Chakra Petch\", \"Segoe UI\", system-ui, -apple-system, \"Helvetica Neue\", Arial, sans-serif",
  sharetechmono: "\"Share Tech Mono\", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, \"Liberation Mono\", \"Courier New\", monospace",
  electrolize: "\"Electrolize\", \"Segoe UI\", system-ui, -apple-system, \"Helvetica Neue\", Arial, sans-serif",
  quantico: "\"Quantico\", \"Segoe UI\", system-ui, -apple-system, \"Helvetica Neue\", Arial, sans-serif",
  turretroad: "\"Turret Road\", \"Segoe UI\", system-ui, -apple-system, \"Helvetica Neue\", Arial, sans-serif",
  syncopate: "\"Syncopate\", \"Segoe UI\", system-ui, -apple-system, \"Helvetica Neue\", Arial, sans-serif",
  bungee: "\"Bungee\", \"Segoe UI\", system-ui, -apple-system, \"Helvetica Neue\", Arial, sans-serif",
  bungeeinline: "\"Bungee Inline\", \"Segoe UI\", system-ui, -apple-system, \"Helvetica Neue\", Arial, sans-serif",
  bungeeshade: "\"Bungee Shade\", \"Segoe UI\", system-ui, -apple-system, \"Helvetica Neue\", Arial, sans-serif",
  monoton: "\"Monoton\", \"Segoe UI\", system-ui, -apple-system, \"Helvetica Neue\", Arial, sans-serif",
  righteous: "\"Righteous\", \"Segoe UI\", system-ui, -apple-system, \"Helvetica Neue\", Arial, sans-serif",
  luckiestguy: "\"Luckiest Guy\", \"Segoe UI\", system-ui, -apple-system, \"Helvetica Neue\", Arial, sans-serif",
  lilitaone: "\"Lilita One\", \"Segoe UI\", system-ui, -apple-system, \"Helvetica Neue\", Arial, sans-serif",
  blackopsone: "\"Black Ops One\", \"Segoe UI\", system-ui, -apple-system, \"Helvetica Neue\", Arial, sans-serif",
  rubikglitch: "\"Rubik Glitch\", \"Segoe UI\", system-ui, -apple-system, \"Helvetica Neue\", Arial, sans-serif",
  fascinateinline: "\"Fascinate Inline\", \"Segoe UI\", system-ui, -apple-system, \"Helvetica Neue\", Arial, sans-serif",
  vt323: "\"VT323\", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, \"Liberation Mono\", \"Courier New\", monospace",
  silkscreen: "\"Silkscreen\", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, \"Liberation Mono\", \"Courier New\", monospace",
  pixelifysans: "\"Pixelify Sans\", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, \"Liberation Mono\", \"Courier New\", monospace",
  tiny5: "\"Tiny5\", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, \"Liberation Mono\", \"Courier New\", monospace",
  fredoka: "\"Fredoka\", \"Segoe UI\", system-ui, -apple-system, \"Helvetica Neue\", Arial, sans-serif",
  baloo2: "\"Baloo 2\", \"Segoe UI\", system-ui, -apple-system, \"Helvetica Neue\", Arial, sans-serif",
  bubblegumsans: "\"Bubblegum Sans\", \"Segoe UI\", system-ui, -apple-system, \"Helvetica Neue\", Arial, sans-serif",
  chewy: "\"Chewy\", \"Segoe UI\", system-ui, -apple-system, \"Helvetica Neue\", Arial, sans-serif",
  sniglet: "\"Sniglet\", \"Segoe UI\", system-ui, -apple-system, \"Helvetica Neue\", Arial, sans-serif",
  cormorantgaramond: "\"Cormorant Garamond\", Georgia, \"Times New Roman\", Times, serif",
  ebgaramond: "\"EB Garamond\", Georgia, \"Times New Roman\", Times, serif",
  bodonimoda: "\"Bodoni Moda\", Georgia, \"Times New Roman\", Times, serif",
  prata: "\"Prata\", Georgia, \"Times New Roman\", Times, serif",
  marcellus: "\"Marcellus\", Georgia, \"Times New Roman\", Times, serif",
  kaushanscript: "\"Kaushan Script\", \"Segoe UI\", system-ui, -apple-system, cursive",
  greatvibes: "\"Great Vibes\", \"Segoe UI\", system-ui, -apple-system, cursive",
  allura: "\"Allura\", \"Segoe UI\", system-ui, -apple-system, cursive",
  sacramento: "\"Sacramento\", \"Segoe UI\", system-ui, -apple-system, cursive",
  satisfy: "\"Satisfy\", \"Segoe UI\", system-ui, -apple-system, cursive",
  yellowtail: "\"Yellowtail\", \"Segoe UI\", system-ui, -apple-system, cursive",
  marckscript: "\"Marck Script\", \"Segoe UI\", system-ui, -apple-system, cursive",
  unifrakturcook: "\"UnifrakturCook\", \"Times New Roman\", Times, serif",
  unifrakturmaguntia: "\"UnifrakturMaguntia\", \"Times New Roman\", Times, serif",
  pirataone: "\"Pirata One\", \"Times New Roman\", Times, serif",
  newrocker: "\"New Rocker\", \"Times New Roman\", Times, serif",
  eater: "\"Eater\", \"Times New Roman\", Times, serif",
  nosifer: "\"Nosifer\", \"Times New Roman\", Times, serif"
});

// A large, categorized font catalog. We lazy-load Google Fonts on demand so we can
// offer many options without bloating initial load.
const CHAT_FX_FONT_CATALOG = Object.freeze([
  {
    label: "System",
    items: [
      { key: "system", label: "System" }
    ]
  },
  {
    label: "Sans",
    items: [
      { key: "inter", label: "Inter" },
      { key: "roboto", label: "Roboto" },
      { key: "opensans", label: "Open Sans" },
      { key: "lato", label: "Lato" },
      { key: "poppins", label: "Poppins" },
      { key: "nunito", label: "Nunito" },
      { key: "rubik", label: "Rubik" },
      { key: "montserrat", label: "Montserrat" },
      { key: "spacegrotesk", label: "Space Grotesk" },
      { key: "worksans", label: "Work Sans" },
      { key: "sourcesans3", label: "Source Sans 3" },
      { key: "raleway", label: "Raleway" },
      { key: "oswald", label: "Oswald" },
      { key: "ubuntu", label: "Ubuntu" },
      { key: "firasans", label: "Fira Sans" },
      { key: "gothicA1", label: "Gothic A1" }
    ]
  },
  {
    label: "Serif",
    items: [
      { key: "merriweather", label: "Merriweather" },
      { key: "playfair", label: "Playfair Display" },
      { key: "crimson", label: "Crimson Text" },
      { key: "libreserif", label: "Libre Baskerville" },
      { key: "robotoslab", label: "Roboto Slab" },
      { key: "alegreya", label: "Alegreya" },
      { key: "cinzel", label: "Cinzel" }
    ]
  },
  {
    label: "Mono",
    items: [
      { key: "jetbrains", label: "JetBrains Mono" },
      { key: "inconsolata", label: "Inconsolata" },
      { key: "spacemono", label: "Space Mono" },
      { key: "ibmplexmono", label: "IBM Plex Mono" },
      { key: "dmmono", label: "DM Mono" },
      { key: "pressstart", label: "Press Start 2P" }
    ]
  },
  {
    label: "Display",
    items: [
      { key: "anton", label: "Anton" },
      { key: "bebas", label: "Bebas Neue" },
      { key: "abril", label: "Abril Fatface" }
    ]
  },
  {
    label: "Handwriting",
    items: [
      { key: "pacifico", label: "Pacifico" },
      { key: "dancing", label: "Dancing Script" },
      { key: "caveat", label: "Caveat" },
      { key: "indieflower", label: "Indie Flower" },
      { key: "permanentmarker", label: "Permanent Marker" }
    ]
  },
  {
    label: "Alt",
    items: [
      { key: "metalmania", label: "Metal Mania" }
    ]
  },
  {
    label: "Cyber / Sci-Fi",
    items: [
      { key: "orbitron", label: "Orbitron" },
      { key: "oxanium", label: "Oxanium" },
      { key: "audiowide", label: "Audiowide" },
      { key: "rajdhani", label: "Rajdhani" },
      { key: "chakrapetch", label: "Chakra Petch" },
      { key: "sharetechmono", label: "Share Tech Mono" },
      { key: "electrolize", label: "Electrolize" },
      { key: "quantico", label: "Quantico" },
      { key: "turretroad", label: "Turret Road" },
      { key: "syncopate", label: "Syncopate" }
    ]
  },
  {
    label: "Neon / Display",
    items: [
      { key: "bungee", label: "Bungee" },
      { key: "bungeeinline", label: "Bungee Inline" },
      { key: "bungeeshade", label: "Bungee Shade" },
      { key: "monoton", label: "Monoton" },
      { key: "righteous", label: "Righteous" },
      { key: "luckiestguy", label: "Luckiest Guy" },
      { key: "lilitaone", label: "Lilita One" },
      { key: "blackopsone", label: "Black Ops One" },
      { key: "rubikglitch", label: "Rubik Glitch" },
      { key: "fascinateinline", label: "Fascinate Inline" }
    ]
  },
  {
    label: "Gothic / Metal",
    items: [
      { key: "unifrakturcook", label: "UnifrakturCook" },
      { key: "unifrakturmaguntia", label: "UnifrakturMaguntia" },
      { key: "pirataone", label: "Pirata One" },
      { key: "newrocker", label: "New Rocker" },
      { key: "eater", label: "Eater" },
      { key: "nosifer", label: "Nosifer" }
    ]
  },
  {
    label: "Retro / Arcade",
    items: [
      { key: "vt323", label: "VT323" },
      { key: "silkscreen", label: "Silkscreen" },
      { key: "pixelifysans", label: "Pixelify Sans" },
      { key: "tiny5", label: "Tiny5" }
    ]
  },
  {
    label: "Cute / Bubble",
    items: [
      { key: "fredoka", label: "Fredoka" },
      { key: "baloo2", label: "Baloo 2" },
      { key: "bubblegumsans", label: "Bubblegum Sans" },
      { key: "chewy", label: "Chewy" },
      { key: "sniglet", label: "Sniglet" }
    ]
  },
  {
    label: "Elegant / Luxury",
    items: [
      { key: "cormorantgaramond", label: "Cormorant Garamond" },
      { key: "ebgaramond", label: "EB Garamond" },
      { key: "bodonimoda", label: "Bodoni Moda" },
      { key: "prata", label: "Prata" },
      { key: "marcellus", label: "Marcellus" }
    ]
  },
  {
    label: "Handwriting (Stylish)",
    items: [
      { key: "kaushanscript", label: "Kaushan Script" },
      { key: "greatvibes", label: "Great Vibes" },
      { key: "allura", label: "Allura" },
      { key: "sacramento", label: "Sacramento" },
      { key: "satisfy", label: "Satisfy" },
      { key: "yellowtail", label: "Yellowtail" },
      { key: "marckscript", label: "Marck Script" }
    ]
  }
]);

const CHAT_FX_GOOGLE_FAMILIES = Object.freeze({
  inter: "Inter:wght@400;500;600;700",
  roboto: "Roboto:wght@400;500;700",
  opensans: "Open+Sans:wght@400;600;700",
  lato: "Lato:wght@400;700",
  poppins: "Poppins:wght@400;500;600;700",
  nunito: "Nunito:wght@400;600;700",
  jetbrains: "JetBrains+Mono:wght@400;600",
  inconsolata: "Inconsolata:wght@400;600;700",
  spacemono: "Space+Mono:wght@400;700",
  ibmplexmono: "IBM+Plex+Mono:wght@400;600",
  dmmono: "DM+Mono:wght@400;500",
  rubik: "Rubik:wght@400;500;600;700",
  montserrat: "Montserrat:wght@400;500;600;700",
  spacegrotesk: "Space+Grotesk:wght@400;500;600;700",
  worksans: "Work+Sans:wght@400;500;600;700",
  sourcesans3: "Source+Sans+3:wght@400;600;700",
  raleway: "Raleway:wght@400;600;700",
  oswald: "Oswald:wght@400;600;700",
  ubuntu: "Ubuntu:wght@400;500;700",
  firasans: "Fira+Sans:wght@400;500;700",
  merriweather: "Merriweather:wght@400;700",
  playfair: "Playfair+Display:wght@400;600;700",
  crimson: "Crimson+Text:wght@400;600;700",
  libreserif: "Libre+Baskerville:wght@400;700",
  robotoslab: "Roboto+Slab:wght@400;600;700",
  alegreya: "Alegreya:wght@400;600;700",
  anton: "Anton",
  bebas: "Bebas+Neue",
  abril: "Abril+Fatface",
  pacifico: "Pacifico",
  dancing: "Dancing+Script:wght@400;600;700",
  caveat: "Caveat:wght@400;600;700",
  indieflower: "Indie+Flower",
  permanentmarker: "Permanent+Marker",
  pressstart: "Press+Start+2P",
  cinzel: "Cinzel:wght@400;600;700",
  gothicA1: "Gothic+A1:wght@400;600;700",
  metalmania: "Metal+Mania",
  orbitron: "Orbitron:wght@400;500;600;700",
  oxanium: "Oxanium:wght@400;500;600;700",
  audiowide: "Audiowide",
  rajdhani: "Rajdhani:wght@400;500;600;700",
  chakrapetch: "Chakra+Petch:wght@400;500;600;700",
  sharetechmono: "Share+Tech+Mono",
  electrolize: "Electrolize",
  quantico: "Quantico:wght@400;700",
  turretroad: "Turret+Road:wght@400;500;700",
  syncopate: "Syncopate:wght@400;700",
  bungee: "Bungee",
  bungeeinline: "Bungee+Inline",
  bungeeshade: "Bungee+Shade",
  monoton: "Monoton",
  righteous: "Righteous",
  luckiestguy: "Luckiest+Guy",
  lilitaone: "Lilita+One",
  blackopsone: "Black+Ops+One",
  rubikglitch: "Rubik+Glitch",
  fascinateinline: "Fascinate+Inline",
  vt323: "VT323",
  silkscreen: "Silkscreen:wght@400;700",
  pixelifysans: "Pixelify+Sans:wght@400;500;600;700",
  tiny5: "Tiny5",
  fredoka: "Fredoka:wght@400;500;600;700",
  baloo2: "Baloo+2:wght@400;500;600;700",
  bubblegumsans: "Bubblegum+Sans",
  chewy: "Chewy",
  sniglet: "Sniglet:wght@400;800",
  cormorantgaramond: "Cormorant+Garamond:wght@400;500;600;700",
  ebgaramond: "EB+Garamond:wght@400;500;600;700",
  bodonimoda: "Bodoni+Moda:wght@400;500;600;700",
  prata: "Prata",
  marcellus: "Marcellus",
  kaushanscript: "Kaushan+Script",
  greatvibes: "Great+Vibes",
  allura: "Allura",
  sacramento: "Sacramento",
  satisfy: "Satisfy",
  yellowtail: "Yellowtail",
  marckscript: "Marck+Script",
  unifrakturcook: "UnifrakturCook:wght@700",
  unifrakturmaguntia: "UnifrakturMaguntia",
  pirataone: "Pirata+One",
  newrocker: "New+Rocker",
  eater: "Eater",
  nosifer: "Nosifer"
});

const _loadedGoogleFonts = new Set();
function ensureGoogleFontLoaded(fontKey){
  const key = String(fontKey || "").trim();
  if (!key || key === "system") return;
  const family = CHAT_FX_GOOGLE_FAMILIES[key];
  if (!family) return;
  if (_loadedGoogleFonts.has(key)) return;
  _loadedGoogleFonts.add(key);
  const id = `gf-${key}`;
  if (document.getElementById(id)) return;
  const link = document.createElement("link");
  link.id = id;
  link.rel = "stylesheet";
  link.href = `https://fonts.googleapis.com/css2?family=${family}&display=swap`;
  document.head.appendChild(link);
}

function buildFontSelectOptionsHTML(){
  return CHAT_FX_FONT_CATALOG.map((group) => {
    const options = (group.items || []).map((it) => {
      const k = it.key;
      const label = it.label || it.key;
      return `<option value="${k}">${escapeHtml(label)}</option>`;
    }).join("");
    return `<optgroup label="${escapeHtml(group.label)}">${options}</optgroup>`;
  }).join("");
}
const CHAT_FX_DENSITY_PRESETS = Object.freeze({
  compact: { padY: 6, padX: 8, innerGap: 4, timeSize: 10, groupGap: 0, dmGap: 4, dmGapTight: 0 },
  cozy: { padY: 10, padX: 12, innerGap: 6, timeSize: 11, groupGap: 1, dmGap: 6, dmGapTight: 1 },
  spacious: { padY: 12, padX: 14, innerGap: 8, timeSize: 12, groupGap: 4, dmGap: 10, dmGapTight: 2 }
});

const msgIndex = [];
let dmThreads = [];
let activeDmId = null;
const dmMessages = new Map();
const badgeDefaults = { direct: "#ed4245", group: "#5865f2" };
let badgePrefs = { ...badgeDefaults };
let directBadgePending = false;
let groupBadgePending = false;
const dmNeonDefaults = { color: "#5865f2" };
let dmNeonColor = dmNeonDefaults.color;
let dmTab = "direct";
let dmViewMode = "inbox";
const dmUnreadThreads = new Set();
let chatFxPrefs = { ...CHAT_FX_DEFAULTS };
let chatFxDraft = null;
let chatFxPrefEls = null;
let chatFxPreviewBubble = null;
let chatFxPreviewAvatar = null;
let chatFxPreviewName = null;
let chatFxPreviewRoleIcon = null;
let chatFxPreviewTime = null;
// Text & Identity sticky preview
let textFxPreviewBubble = null;
let textFxPreviewAvatar = null;
let textFxPreviewName = null;
let textFxPreviewRoleIcon = null;
let textFxPreviewTime = null;
let chatFxStatus = null;
let chatFxPrefsLoaded = false;
let chatFxPrefsLoading = false;

// --- DM avatar strip (direct DMs only): last-read + lightweight avatar cache
const DM_LAST_READ_KEY = "dm:lastRead:v1";
const AVATAR_CACHE_KEY = "dm:avatarCache:v1";

function loadJson(key, fallback) {
  const raw = localStorage.getItem(key);
  const val = safeJsonParse(raw, fallback);
  return val ?? fallback;
}
function saveJson(key, value) {
  try { localStorage.setItem(key, JSON.stringify(value)); } catch {}
}

/* ---- UI scale (small screens + user override) */
const UI_SCALE_KEY = "ui:scale:v1";

function applyUiScale(scale){
  // If scale is null/undefined, revert to auto (CSS media queries).
  if(scale === null || scale === undefined || scale === ""){
    document.documentElement.style.removeProperty("--uiScale");
    try{ localStorage.removeItem(UI_SCALE_KEY); }catch{}
    return;
  }
  const n = Number(scale);
  if(!Number.isFinite(n)) return;
  const clamped = Math.max(0.80, Math.min(1.05, n));
  document.documentElement.style.setProperty("--uiScale", String(clamped));
  try{ localStorage.setItem(UI_SCALE_KEY, String(clamped)); }catch{}
}

function loadUiScale(){
  try{
    const raw = localStorage.getItem(UI_SCALE_KEY);
    if(!raw) return null;
    const n = Number(raw);
    return Number.isFinite(n) ? n : null;
  }catch{ return null; }
}

/* ---- Notifications (client-side MVP) ---- */
const NOTIFICATIONS_KEY = "notifications:v1";
const NOTIFICATIONS_READ_KEY = "notifications:readAt:v1";
const NOTIFICATIONS_MAX = 50;
let notifications = loadJson(NOTIFICATIONS_KEY, []);
let notificationsReadAt = Number(localStorage.getItem(NOTIFICATIONS_READ_KEY) || 0);
notifications = (Array.isArray(notifications) ? notifications : []).map((item) => ({
  ...item,
  read: item?.read ?? (Number(item?.ts || 0) <= notificationsReadAt),
}));

function notificationIcon(type){
  if (type === "mention") return "💬";
  if (type === "reaction") return "✨";
  if (type === "moderation") return "🛡️";
  if (type === "friend_request") return "🤝";
  if (type === "system") return "📣";
  return "🔔";
}

function saveNotifications(){
  saveJson(NOTIFICATIONS_KEY, notifications);
}


function pushNotification({ id = null, type = "system", text = "", ts = Date.now(), target = "", meta = null } = {}){
  const message = String(text || "").trim();
  if (!message) return;
  const entryId = id || `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  const entry = {
    id: entryId,
    type,
    text: message,
    ts: Number(ts) || Date.now(),
    target,
    meta: meta && typeof meta === 'object' ? meta : null,
    read: false,
  };
  // de-dupe by id
  const existingIdx = notifications.findIndex((n) => n.id === entry.id);
  if (existingIdx >= 0) {
    notifications[existingIdx] = { ...notifications[existingIdx], ...entry };
  } else {
    notifications = [entry, ...notifications].slice(0, NOTIFICATIONS_MAX);
  }
  saveNotifications();
  renderNotifications();
  updateNotificationsBadge();
}

function pushFriendRequestNotification({ requestId, fromUsername, fromAvatar, ts } = {}){
  const rid = Number(requestId) || 0;
  const uname = String(fromUsername || '').trim();
  if (!rid || !uname) return;
  pushNotification({
    id: `friendreq:${rid}`,
    type: 'friend_request',
    text: `${uname} sent you a friend request`,
    ts: Number(ts) || Date.now(),
    target: `profile:${uname}`,
    meta: { requestId: rid, fromUsername: uname, fromAvatar: fromAvatar || null, status: 'pending' }
  });
}

function updateNotificationsBadge(){
  if (!notificationsDot) return;
  const hasUnread = notifications.some(item => !item.read);
  notificationsDot.style.display = hasUnread ? "" : "none";
}

function markNotificationsRead(){
  if (!notifications.length) return;
  notifications = notifications.map(item => ({ ...item, read: true }));
  notificationsReadAt = Date.now();
  try{ localStorage.setItem(NOTIFICATIONS_READ_KEY, String(notificationsReadAt)); }catch{}
  saveNotifications();
  updateNotificationsBadge();
}

function notificationGroupLabel(ts){
  const date = new Date(ts);
  if (Number.isNaN(date.getTime())) return "Older";
  const now = new Date();
  const startToday = new Date(now.getFullYear(), now.getMonth(), now.getDate());
  const startThat = new Date(date.getFullYear(), date.getMonth(), date.getDate());
  const diffDays = Math.round((startToday - startThat) / 86400000);
  if (diffDays <= 0) return "Today";
  if (diffDays === 1) return "Yesterday";
  return "Older";
}

function renderNotifications(){
  if (!notificationsList || !notificationsEmpty) return;
  notificationsList.innerHTML = "";
  if (!notifications.length){
    notificationsEmpty.style.display = "block";
    return;
  }
  notificationsEmpty.style.display = "none";

  const grouped = new Map();
  notifications.forEach((item) => {
    const label = notificationGroupLabel(item.ts);
    if (!grouped.has(label)) grouped.set(label, []);
    grouped.get(label).push(item);
  });

  for (const [label, items] of grouped.entries()){
    const groupEl = document.createElement("div");
    groupEl.className = "notificationsGroup";
    const heading = document.createElement("div");
    heading.className = "notificationsGroupTitle";
    heading.textContent = label;
    groupEl.appendChild(heading);

    items.forEach((item) => {
      const isFriendReq = item.type === 'friend_request' && item.meta && Number(item.meta.requestId);
      if (isFriendReq) {
        const m = item.meta || {};
        const row = document.createElement('div');
        row.className = 'notificationsRow friendReq';
        row.dataset.notificationId = item.id;
        row.dataset.requestId = String(Number(m.requestId) || '');
        row.innerHTML = `
          <button class="notifAvatarBtn" type="button" data-action="open-profile" data-username="${escapeHtml(m.fromUsername||'')}">
            <span class="notificationsIcon" aria-hidden="true">🤝</span>
          </button>
          <div class="notifBody">
            <div class="notificationsText">${escapeHtml(item.text)}</div>
            <div class="notificationsTime">${escapeHtml(fmtAbs(item.ts))}</div>
          </div>
          <div class="notifActions">
            <button class="btn btnSecondary small" type="button" data-action="accept" data-request-id="${Number(m.requestId)}">Accept</button>
            <button class="btn btnSecondary small" type="button" data-action="decline" data-request-id="${Number(m.requestId)}">Decline</button>
          </div>
        `;

        // Replace icon button content with actual avatar node
        const avatarBtn = row.querySelector('.notifAvatarBtn');
        if (avatarBtn) {
          avatarBtn.innerHTML = '';
          avatarBtn.appendChild(avatarNode(m.fromAvatar, m.fromUsername, 'User'));
        }
        // Disable actions if already handled
        const status = String(m.status || 'pending');
        if (status !== 'pending') {
          row.classList.add('handled');
          row.querySelectorAll('[data-action="accept"],[data-action="decline"]').forEach((b) => b.disabled = true);
        }

        groupEl.appendChild(row);
        return;
      }

      const row = document.createElement("button");
      row.type = "button";
      row.className = "notificationsRow";
      row.dataset.notificationId = item.id;
      row.innerHTML = `
        <span class="notificationsIcon" aria-hidden="true">${notificationIcon(item.type)}</span>
        <span class="notificationsText">${escapeHtml(item.text)}</span>
        <span class="notificationsTime">${escapeHtml(fmtAbs(item.ts))}</span>
      `;
      groupEl.appendChild(row);
    });
    notificationsList.appendChild(groupEl);
  }
}

function openNotificationsModal(){
  if (!notificationsModal) return;
  notificationsModal.hidden = false;
  // Pull any pending friend requests so notifications stay useful after refresh
  syncFriendRequestNotifications();
  renderNotifications();
  markNotificationsRead();
}

function closeNotificationsModal(){
  if (!notificationsModal) return;
  notificationsModal.hidden = true;
}


async function syncFriendRequestNotifications(){
  try {
    const res = await fetch('/api/friends/requests');
    if (!res.ok) return;
    const data = await res.json();
    const incoming = Array.isArray(data?.incoming) ? data.incoming : [];
    incoming.forEach((req) => {
      pushFriendRequestNotification({
        requestId: req.id,
        fromUsername: req?.from?.username,
        fromAvatar: req?.from?.avatar,
        ts: req.createdAt
      });
    });
  } catch {}
}

let dmLastRead = loadJson(DM_LAST_READ_KEY, {}); // { [threadId]: lastReadTs }
let avatarCache = loadJson(AVATAR_CACHE_KEY, {}); // { [username]: avatarUrl }

function normalizeChatFxFontKey(input){
  const raw = String(input || "").trim().toLowerCase();
  if (!raw) return CHAT_FX_DEFAULTS.font;

  // Exact key match
  if (Object.prototype.hasOwnProperty.call(CHAT_FX_FONT_STACKS, raw)) return raw;

  // A few fuzzy aliases (for forward/backward compatibility)
  if (raw.includes("jetbrains")) return "jetbrains";
  if (raw.includes("ibm") && raw.includes("plex") && raw.includes("mono")) return "ibmplexmono";
  if (raw.includes("space") && raw.includes("mono")) return "spacemono";
  if (raw.includes("space") && raw.includes("grotesk")) return "spacegrotesk";
  if (raw.includes("open") && raw.includes("sans")) return "opensans";
  if (raw.includes("source") && raw.includes("sans")) return "sourcesans3";
  if (raw.includes("press") && raw.includes("start")) return "pressstart";
  if (raw.includes("playfair")) return "playfair";
  if (raw.includes("merriweather")) return "merriweather";
  if (raw.includes("montserrat")) return "montserrat";
  if (raw.includes("rubik")) return "rubik";
  if (raw.includes("inter")) return "inter";
  if (raw.includes("poppins")) return "poppins";
  if (raw.includes("nunito")) return "nunito";
  if (raw.includes("system")) return "system";
  return CHAT_FX_DEFAULTS.font;
}

function normalizeChatFxDensity(input){
  const raw = String(input || "").trim().toLowerCase();
  if (raw === "compact" || raw === "cozy" || raw === "spacious") return raw;
  return CHAT_FX_DEFAULTS.density;
}

function normalizeChatFxGlow(input){
  const raw = String(input || "").trim().toLowerCase();
  if (raw === "soft" || raw === "neon" || raw === "strong" || raw === "off") return raw;
  return CHAT_FX_DEFAULTS.glow;
}

function normalizeChatFxTextGlow(input){
  const raw = String(input || "").trim().toLowerCase();
  if (raw === "soft" || raw === "neon" || raw === "strong" || raw === "off") return raw;
  return CHAT_FX_DEFAULTS.textGlow;
}

function normalizeChatFxBool(input, fallback = false){
  if (input === true) return true;
  if (input === false) return false;
  return fallback;
}

function normalizeChatFxNumber(input, fallback, min, max){
  const n = Number(input);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, n));
}

function normalizeChatFxAccent(input){
  if (!input) return "";
  const raw = String(input).trim();
  if (/^#([0-9a-f]{3}|[0-9a-f]{6})$/i.test(raw)) return raw;
  return "";
}

function normalizeChatFxBubbleColor(input){
  if (!input) return "";
  const raw = String(input).trim();
  if (/^#([0-9a-f]{3}|[0-9a-f]{6})$/i.test(raw)) return raw;
  return "";
}

function normalizeChatFxTextColor(input){
  if (!input) return "";
  const raw = String(input).trim();
  if (/^#([0-9a-f]{3}|[0-9a-f]{6})$/i.test(raw)) return raw;
  return "";
}

function normalizeChatFxNameColor(input){
  if (!input) return "";
  const raw = String(input).trim();
  if (/^#([0-9a-f]{3}|[0-9a-f]{6})$/i.test(raw)) return raw;
  return "";
}

function normalizeChatFxGradientColor(input){
  if (!input) return "";
  const raw = String(input).trim();
  if (/^#[0-9a-f]{6}$/i.test(raw)) return raw;
  return "";
}

function normalizeChatFx(input){
  const fx = (input && typeof input === "object") ? input : {};
  const enabled = fx.enabled !== false;
  const radiusRaw = (fx.radius ?? fx.bubbleRadius);
  const borderRaw = (fx.border ?? fx.borderPx);
  const blurRaw = (fx.blur ?? fx.glassBlur);
  const bubbleColorRaw = (fx.bubbleColor ?? fx.bubbleBg ?? fx.bubble);
  const nameFontRaw = (fx.nameFont ?? fx.usernameFont ?? fx.userNameFont ?? fx.uNameFont);
  const nameColorRaw = (fx.nameColor ?? fx.usernameColor ?? fx.userNameColor ?? fx.uNameColor);
  return {
    enabled,
    glow: normalizeChatFxGlow(fx.glow),
    font: normalizeChatFxFontKey(fx.font),
    nameFont: normalizeChatFxFontKey(nameFontRaw),
    radius: normalizeChatFxNumber(radiusRaw, CHAT_FX_DEFAULTS.radius, 6, 28),
    border: normalizeChatFxNumber(borderRaw, CHAT_FX_DEFAULTS.border, 0, 3),
    glass: normalizeChatFxNumber(fx.glass, CHAT_FX_DEFAULTS.glass, 0, 1),
    blur: normalizeChatFxNumber(blurRaw, CHAT_FX_DEFAULTS.blur, 0, 16),
    density: normalizeChatFxDensity(fx.density),
    accent: normalizeChatFxAccent(fx.accent),
    bubbleColor: normalizeChatFxBubbleColor(bubbleColorRaw),
    textColor: normalizeChatFxTextColor(fx.textColor),
    nameColor: normalizeChatFxNameColor(nameColorRaw),
    autoContrast: fx.autoContrast === true,
    textBold: normalizeChatFxBool(fx.textBold, CHAT_FX_DEFAULTS.textBold),
    textItalic: normalizeChatFxBool(fx.textItalic, CHAT_FX_DEFAULTS.textItalic),
    textGlow: normalizeChatFxTextGlow(fx.textGlow),
    textGradientEnabled: normalizeChatFxBool(fx.textGradientEnabled, CHAT_FX_DEFAULTS.textGradientEnabled),
    textGradientA: normalizeChatFxGradientColor(fx.textGradientA),
    textGradientB: normalizeChatFxGradientColor(fx.textGradientB),
    textGradientAngle: normalizeChatFxNumber(fx.textGradientAngle, CHAT_FX_DEFAULTS.textGradientAngle, 0, 360),
    polishPack: normalizeChatFxBool(fx.polishPack, CHAT_FX_DEFAULTS.polishPack),
    polishAuras: normalizeChatFxBool(fx.polishAuras, CHAT_FX_DEFAULTS.polishAuras),
    polishAnimations: normalizeChatFxBool(fx.polishAnimations, CHAT_FX_DEFAULTS.polishAnimations)
  };
}

function updateUserFxMap(username, fx){
  if (!username) return;
  const key = String(username);
  userFxMap[key] = normalizeChatFx(fx);
}

function escapeSelectorValue(value) {
  if (window.CSS?.escape) return CSS.escape(String(value));
  return String(value).replace(/["\\]/g, "\\$&");
}

function updateUserFxInDom(username, fx){
  const name = String(username || "");
  if (!name) return;
  const normalized = normalizeChatFx(fx);
  const selector = `.msgGroup[data-user="${escapeSelectorValue(name)}"]`;
  document.querySelectorAll(selector).forEach((group) => {
    const body = group.querySelector(".msgGroupBody");
    group.querySelectorAll(".bubble").forEach((bubble) => {
      applyChatFxToBubble(bubble, normalized, { groupBody: body });
    });
    group.querySelectorAll(".unameText").forEach((el) => applyNameFxToEl(el, normalized));
  });

  if (activeDmId && dmMessagesEl) {
    const threadMessages = dmMessages.get(activeDmId) || dmMessages.get(String(activeDmId)) || [];
    if (threadMessages.some((m) => String(m.user || "") === name)) {
      renderDmMessages(activeDmId);
    }
  }
}

function hydrateUserFxMap(authorsFx){
  if (!authorsFx) return;
  if (Array.isArray(authorsFx)){
    authorsFx.forEach((entry)=>{
      if (!entry) return;
      const name = entry.user || entry.username || entry.name || "";
      const fx = entry.chatFx || entry.fx || entry;
      updateUserFxMap(name, fx);
    });
    return;
  }
  if (typeof authorsFx === "object"){
    Object.entries(authorsFx).forEach(([name, fx]) => updateUserFxMap(name, fx));
  }
}

function resolveMessageAuthor(message){
  return String(message?.user ?? message?.username ?? message?.from ?? message?.sender ?? "");
}

function resolveChatFx(message, author){
  const name = author || resolveMessageAuthor(message);
  const baseFx = userFxMap[name] || {};
  const msgFx = message?.chatFx;
  const merged = msgFx ? { ...baseFx, ...msgFx } : baseFx;
  return normalizeChatFx(merged);
}

function applyNameFxToEl(el, fx){
  if (!el) return;
  const resolved = normalizeChatFx(fx);
  const effective = resolved.enabled ? resolved : CHAT_FX_DEFAULTS;
  const stack = CHAT_FX_FONT_STACKS[effective.nameFont] || CHAT_FX_FONT_STACKS[effective.font] || CHAT_FX_FONT_STACKS.system;
  ensureGoogleFontLoaded(effective.nameFont);
  // Only apply when explicitly set, so we don't override theme styles unnecessarily.
  el.style.fontFamily = stack;
  const c = String(effective.nameColor || "").trim();
  el.style.color = c || "";
}

function parseCssRgbToTuple(cssColor){
  const raw = String(cssColor || "").trim();
  // rgb(r, g, b) or rgba(r, g, b, a)
  const m = raw.match(/^rgba?\(([^)]+)\)$/i);
  if(!m) return null;
  const parts = m[1].split(",").map((p) => p.trim());
  if(parts.length < 3) return null;
  const r = Number(parts[0]);
  const g = Number(parts[1]);
  const b = Number(parts[2]);
  const a = parts.length >= 4 ? Number(parts[3]) : 1;
  if(![r,g,b,a].every((n) => Number.isFinite(n))) return null;
  return { r, g, b, a };
}

function relativeLuminance({ r, g, b }){
  // sRGB -> linear
  const srgb = [r, g, b].map((v) => {
    const x = Math.max(0, Math.min(255, v)) / 255;
    return x <= 0.03928 ? x / 12.92 : Math.pow((x + 0.055) / 1.055, 2.4);
  });
  return 0.2126 * srgb[0] + 0.7152 * srgb[1] + 0.0722 * srgb[2];
}

function pickAutoContrastTextColor(el){
  if(!el) return "";
  let bg = "";
  try{ bg = getComputedStyle(el).backgroundColor; }catch{}
  let t = parseCssRgbToTuple(bg);
  // If transparent, use body background as a fallback.
  if(!t || (t.a !== undefined && t.a < 0.15)){
    try{ t = parseCssRgbToTuple(getComputedStyle(document.body).backgroundColor); }catch{}
  }
  if(!t) return "";
  const lum = relativeLuminance(t);
  return lum > 0.52 ? "#000000" : "#ffffff";
}

function hexToRgbTuple(hex){
  const raw = String(hex || "").trim();
  const m = raw.match(/^#([0-9a-f]{6})$/i);
  if (!m) return null;
  const n = parseInt(m[1], 16);
  const r = (n >> 16) & 255;
  const g = (n >> 8) & 255;
  const b = n & 255;
  return { r, g, b, a: 1 };
}

function pickAutoContrastFromHex(hex){
  const t = hexToRgbTuple(hex);
  if (!t) return "";
  const lum = relativeLuminance(t);
  return lum > 0.52 ? "#000000" : "#ffffff";
}

function contrastRatio(colorA, colorB){
  const l1 = relativeLuminance(colorA);
  const l2 = relativeLuminance(colorB);
  const lighter = Math.max(l1, l2);
  const darker = Math.min(l1, l2);
  return (lighter + 0.05) / (darker + 0.05);
}

function clearContrastReinforcement(bubble){
  if (!bubble) return;
  bubble.classList.remove("fx-contrastBoost");
  bubble.style.removeProperty("--fx-contrast-shadow");
  bubble.style.removeProperty("--fx-contrast-stroke");
  bubble.style.removeProperty("--fx-contrast-stroke-color");
}

function applyContrastReinforcement(bubble){
  if (!bubble) return;
  if (!isPolishPackEnabled()) {
    clearContrastReinforcement(bubble);
    return;
  }
  const bg = hexToRgbTuple(bubble.dataset.fxBubbleColor) || parseCssRgbToTuple(getComputedStyle(bubble).backgroundColor);
  if (!bg) {
    clearContrastReinforcement(bubble);
    return;
  }

  const candidates = [];
  if (bubble.classList.contains("fx-textGradient")) {
    const gradA = hexToRgbTuple(bubble.dataset.fxTextGradA);
    const gradB = hexToRgbTuple(bubble.dataset.fxTextGradB);
    if (gradA) candidates.push(gradA);
    if (gradB) candidates.push(gradB);
  }

  const directText = hexToRgbTuple(bubble.dataset.fxTextColor);
  if (directText) candidates.push(directText);

  if (!candidates.length) {
    const textEl = bubble.querySelector(".text") || bubble;
    const computed = parseCssRgbToTuple(getComputedStyle(textEl).color);
    if (computed && (computed.a == null || computed.a >= 0.2)) candidates.push(computed);
  }

  if (!candidates.length) {
    clearContrastReinforcement(bubble);
    return;
  }

  const minRatio = Math.min(...candidates.map((c) => contrastRatio(c, bg)));
  if (minRatio >= 3.2) {
    clearContrastReinforcement(bubble);
    return;
  }

  const sample = candidates[0];
  const lightText = relativeLuminance(sample) > 0.5;
  const shadowColor = lightText ? "rgba(0,0,0,0.48)" : "rgba(255,255,255,0.45)";
  const strokeColor = lightText ? "rgba(0,0,0,0.5)" : "rgba(255,255,255,0.5)";
  bubble.classList.add("fx-contrastBoost");
  bubble.style.setProperty("--fx-contrast-shadow", `0 1px 2px ${shadowColor}`);
  bubble.style.setProperty("--fx-contrast-stroke", "0.35px");
  bubble.style.setProperty("--fx-contrast-stroke-color", strokeColor);
}

function updateContrastReinforcementAll(){
  document.querySelectorAll(".bubble, .dmBubble").forEach((bubble) => applyContrastReinforcement(bubble));
}

function queueContrastReinforcement(bubble){
  if (!bubble) return;
  requestAnimationFrame(() => applyContrastReinforcement(bubble));
}

function applyChatFxToBubble(bubble, fx, options = {}){
  if (!bubble) return;
  const resolved = normalizeChatFx(fx);
  const effective = resolved.enabled ? resolved : CHAT_FX_DEFAULTS;
  const glowMap = { off: 0, soft: 0.4, neon: 0.8, strong: 1.15 };
  const glowValue = glowMap[effective.glow] ?? 0;
  const textGlowMap = { off: 0, soft: 0.35, neon: 0.8, strong: 1.2 };
  const textGlowValue = textGlowMap[effective.textGlow] ?? 0;

  // Lazy-load any selected Google fonts.
  ensureGoogleFontLoaded(effective.font);
  ensureGoogleFontLoaded(effective.nameFont);

  const fontStack = CHAT_FX_FONT_STACKS[effective.font] || CHAT_FX_FONT_STACKS.system;
  const nameFontStack = CHAT_FX_FONT_STACKS[effective.nameFont] || fontStack;
  const densityPreset = CHAT_FX_DENSITY_PRESETS[effective.density] || CHAT_FX_DENSITY_PRESETS.cozy;
  const radiusGrouped = Math.max(8, effective.radius - 2);

  // Bubble background override (optional)
  const bubbleBg = (effective.bubbleColor || "").trim();
  if (bubbleBg) bubble.style.setProperty("--fx-bubble-bg", bubbleBg);
  else bubble.style.removeProperty("--fx-bubble-bg");

  bubble.style.setProperty("--fx-font-family", fontStack);
  bubble.style.setProperty("--fx-name-font-family", nameFontStack);
  const nameColor = (effective.nameColor || "").trim();
  bubble.style.setProperty("--fx-name-color", nameColor);
  bubble.style.setProperty("--fx-glow", String(glowValue));
  bubble.style.setProperty("--fx-accent", effective.accent || "var(--accent)");
  // Text colour: explicit override beats auto-contrast.
  const textOverride = (effective.textColor || "").trim();
  const autoContrast = !!effective.autoContrast && !textOverride;
  // If the user has set a bubble background colour, prefer that for auto-contrast.
  const autoColor = autoContrast ? (bubbleBg ? pickAutoContrastFromHex(bubbleBg) : pickAutoContrastTextColor(bubble)) : "";
  bubble.style.setProperty("--fx-text", textOverride || autoColor || "");
  bubble.dataset.fxTextColor = textOverride || autoColor || "";
  bubble.dataset.fxBubbleColor = bubbleBg || "";
  bubble.style.setProperty("--fx-text-weight", effective.textBold ? "700" : "400");
  bubble.style.setProperty("--fx-text-style", effective.textItalic ? "italic" : "normal");
  bubble.style.setProperty("--fx-text-glow", String(textGlowValue));
  const gradientEnabled = !!effective.textGradientEnabled;
  const gradientA = effective.textGradientA || "var(--fx-accent, var(--accent))";
  const gradientB = effective.textGradientB || "#00e5ff";
  bubble.style.setProperty("--fx-text-grad-a", gradientA);
  bubble.style.setProperty("--fx-text-grad-b", gradientB);
  bubble.style.setProperty("--fx-text-grad-angle", `${effective.textGradientAngle}deg`);
  bubble.dataset.fxTextGradA = gradientA;
  bubble.dataset.fxTextGradB = gradientB;
  bubble.classList.toggle("fx-textGradient", gradientEnabled);
  bubble.classList.toggle("fx-autoContrast", autoContrast);
  bubble.style.setProperty("--fx-radius", `${effective.radius}px`);
  bubble.style.setProperty("--fx-radius-grouped", `${radiusGrouped}px`);
  bubble.style.setProperty("--fx-border", `${effective.border}px`);
  bubble.style.setProperty("--fx-glass", String(effective.glass));
  bubble.style.setProperty("--fx-blur", `${effective.blur}px`);
  bubble.style.setProperty("--fx-density", effective.density);
  bubble.style.setProperty("--fx-pad-y", `${densityPreset.padY}px`);
  bubble.style.setProperty("--fx-pad-x", `${densityPreset.padX}px`);
  bubble.style.setProperty("--fx-inner-gap", `${densityPreset.innerGap}px`);
  bubble.style.setProperty("--fx-time-size", `${densityPreset.timeSize}px`);

  bubble.classList.remove("fx-density-compact", "fx-density-cozy", "fx-density-spacious");
  bubble.classList.add(`fx-density-${effective.density}`);

  if (options.groupBody){
    options.groupBody.style.setProperty("--fx-group-gap", `${densityPreset.groupGap}px`);
  }
  if (options.dmRow){
    options.dmRow.style.setProperty("--fx-dm-gap", `${densityPreset.dmGap}px`);
    options.dmRow.style.setProperty("--fx-dm-gap-tight", `${densityPreset.dmGapTight}px`);
  }
  if (options.dmWrap){
    options.dmWrap.style.setProperty("--fx-time-size", `${densityPreset.timeSize}px`);
  }
}

function markDmRead(threadId, ts) {
  const cur = Number(dmLastRead[threadId] || 0);
  const next = Number(ts || 0);
  if (next > cur) {
    dmLastRead[threadId] = next;
    saveJson(DM_LAST_READ_KEY, dmLastRead);
  }
}

async function getAvatarUrl(username) {
  if (!username) return "";
  if (avatarCache[username]) return avatarCache[username];
  try {
    const { res, json } = await api(`/api/profile/${encodeURIComponent(username)}`);
    if (res.ok && json && json.avatar_url) {
      avatarCache[username] = json.avatar_url;
      saveJson(AVATAR_CACHE_KEY, avatarCache);
      return json.avatar_url;
    }
  } catch {}
  return "";
}

function otherParty(thread) {
  if (!thread) return "";
  if (thread.otherUser?.username) return thread.otherUser.username;

  const meKey = normKey(me?.username);
  const parts = Array.isArray(thread.participants) ? thread.participants : [];
  const details = Array.isArray(thread.participantsDetail) ? thread.participantsDetail.map(p => p?.username).filter(Boolean) : [];

  const all = [...parts, ...details].filter(Boolean);
  for (const n of all) {
    if (normKey(n) !== meKey) return n;
  }
  return all[0] || "";
}

function isDirectThread(thread) {
  return !thread.is_group && (thread.participants || []).length <= 2;
}

let dmPickerMode = "create";
let dmPickerSelection = new Set();
let dmPickerThreadId = null;
let dmPickerExisting = [];
let levelToastTimer = null;

/* ---- Tap-blocker regression guard (mobile & touch) ----
   Prevent hidden overlays (opacity:0 / visibility:hidden) from stealing taps on top-right buttons.
   This is defensive: if something regresses, we auto-disable pointer events on the hidden blocker. */
function initTapBlockerGuard(){
  const isTouch = ("ontouchstart" in window) || (navigator.maxTouchPoints > 0);
  if(!isTouch) return;

  const ids = ["dmToggleBtn","groupDmToggleBtn","notificationsBtn","openMembersBtn"];
  const testOnce = () => {
    for(const id of ids){
      const btn = document.getElementById(id);
      if(!btn) continue;

      const r = btn.getBoundingClientRect();
      if(r.width <= 0 || r.height <= 0) continue;

      const x = Math.floor(r.left + r.width/2);
      const y = Math.floor(r.top  + r.height/2);
      let el = document.elementFromPoint(x, y);
      if(!el) continue;

      // if click would hit the button (or its child), we're good
      if(el === btn || btn.contains(el)) continue;

      // walk up to find a likely overlay that is hidden but still intercepting taps
      let cur = el;
      for(let hop = 0; hop < 6 && cur; hop++){
        const cs = window.getComputedStyle(cur);
        const hidden = (cs.visibility === "hidden") || (parseFloat(cs.opacity || "1") === 0);
        if(hidden && cs.pointerEvents !== "none"){
          cur.style.pointerEvents = "none";
          cur.dataset.tapGuard = "1";
          break;
        }
        cur = cur.parentElement;
      }
    }
  };

  const run = () => requestAnimationFrame(() => requestAnimationFrame(testOnce));
  if(document.readyState === "loading"){
    document.addEventListener("DOMContentLoaded", run, { once:true });
  } else {
    run();
  }
  window.addEventListener("resize", run, { passive:true });
}

initTapBlockerGuard();
let rightPanelMode = "rooms";
let activeMenuTab = "changelog";
let changelogEntries = [];
let changelogLoaded = false;
let changelogDirty = false;
const changelogLocalTouch = new Map();
let openChangelogId = null;
const CHANGELOG_REACTION_KEYS = ["heart", "clap", "down", "eyes"];
const CHANGELOG_REACTION_EMOJI = { heart:"♥️", clap:"👏", down:"👎", eyes:"👀" };
const changelogReactionBusy = new Set();
// When the server pushes a reactions update over websocket, it may arrive before
// the REST write has fully propagated. Preserve optimistic UI for a short window.
// (Used inside loadChangelog merging logic.)

// Same idea for FAQ reactions.
const faqLocalTouch = new Map();
let editingChangelogId = null;
let latestChangelogEntry = null;
let faqQuestions = [];
let faqLoaded = false;
let faqDirty = false;
let openFaqQuestionId = null;
const FAQ_REACTION_KEYS = ["helpful", "love", "funny", "confusing"];
const FAQ_REACTION_EMOJI = { helpful:"👍", love:"❤️", funny:"😂", confusing:"❓" };
const faqReactionBusy = new Set();
let editingFaqId = null;
const leaderboardState = {
  isOpen: false,
  inFlight: false,
  lastFetchAt: 0,
  intervalId: null,
  lastError: false,
  wsCooldownUntil: 0
};
const recentDiceRolls = new Map();
const diceRollTimers = new Map();
let typingUsers = new Set();
const typingPhraseCache = new Map();
let drawerTypingMode = false;
let drawerFocusOutTimer = null;
let activeDmUsers = new Set();
let diceCooldownUntil = 0;
const DICE_ROLL_COOLDOWN_MS = 1000;
const DICE_FACES = ["⚀", "⚁", "⚂", "⚃", "⚄", "⚅"];
const DICE_VARIANTS = ["d6", "d20", "2d6", "d100"];
const DICE_VARIANT_LABELS = {
  d6: "d6",
  d20: "d20",
  "2d6": "2d6",
  d100: "1–100",
};
const LUCK_MIN = -2.0;
const LUCK_MAX = 0.30;
const LUCK_BAR_SLOTS = 24;
const DICE_LUCKY_THRESHOLDS = {
  d6: 6,
  d20: 20,
  "2d6": 12,
  d100: 90,
};
let diceVariant = "d6";
let diceVariantMenuOpen = false;
const diceSessionStats = {
  consecutiveRolls: 0,
  highestRoll: 0,
  luckyStreak: 0,
  lastRollAt: 0,
};
let survivalState = {
  season: null,
  participants: [],
  alliances: [],
  events: [],
  history: [],
  selectedSeasonId: null,
  logBeforeId: null,
  winner: null,
  arena: {},
  lobbyUserIds: [],
  view: "none",
};
let survivalAutoRunTimer = null;
let survivalAutoRunning = false;
const luckState = {
  luck: 0,
  rollStreak: 0,
  lastUpdateAt: 0,
  hasValue: false,
};
let lastLuckRequestAt = 0;
const LUCK_REQUEST_COOLDOWN_MS = 2000;

function themeIdFromName(name){
  return String(name || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/(^-|-$)/g, "");
}
const THEME_TAG_KEYWORDS = [
  { match: /minimal/i, tag: "Minimal" },
  { match: /neon|cyberpunk/i, tag: "Neon" },
  { match: /fantasy|tavern/i, tag: "Fantasy" },
  { match: /space|nebula|galaxy/i, tag: "Space" },
  { match: /pastel|sorbet|cotton|pearl|glacier/i, tag: "Pastel" },
  { match: /forest|mint|aurora|lavender/i, tag: "Nature" },
  { match: /ocean|mist/i, tag: "Ocean" },
  { match: /desert|sand/i, tag: "Desert" },
  { match: /retro|terminal/i, tag: "Retro" },
  { match: /cherry|rose|blossom/i, tag: "Floral" },
  { match: /crimson|noir|obsidian|midnight/i, tag: "Moody" },
];
function inferThemeTags(name, mode, extra = []){
  const tags = new Set(extra.filter(Boolean));
  tags.add(mode === "Dark" ? "Dark" : "Light");
  for(const rule of THEME_TAG_KEYWORDS){
    if(rule.match.test(name)) tags.add(rule.tag);
  }
  return Array.from(tags);
}
function createTheme(name, mode, options = {}){
  const id = options.id || themeIdFromName(name);
  const access = options.access || "vip";
  const goldPrice = Number(options.goldPrice || 0);
  const isPurchasable = Boolean(options.isPurchasable || goldPrice);
  return {
    id,
    name,
    mode,
    access,
    isPurchasable,
    goldPrice: goldPrice || null,
    isNew: Boolean(options.isNew),
    tags: inferThemeTags(name, mode, options.tags || []),
  };
}
// Theme registry: add new themes here (metadata drives filtering, pinning, and gold unlocks).
const THEME_LIST = [
  createTheme("Minimal Dark", "Dark", { access: "public", tags: ["Minimal"] }),
  createTheme("Minimal Dark (High Contrast)", "Dark", { access: "public", tags: ["Minimal"] }),
  createTheme("Cyberpunk Neon", "Dark", { tags: ["Neon"] }),
  createTheme("Cyberpunk Neon (Midnight)", "Dark", { tags: ["Neon"] }),
  createTheme("Fantasy Tavern", "Dark", { access: "public", tags: ["Fantasy"] }),
  createTheme("Fantasy Tavern (Ember)", "Dark", { access: "public", tags: ["Fantasy"] }),
  createTheme("Space Explorer", "Dark", { tags: ["Space"] }),
  createTheme("Space Explorer (Nebula)", "Dark", { tags: ["Space"] }),
  createTheme("Minimal Light", "Light", { access: "public", tags: ["Minimal"] }),
  createTheme("Minimal Light (High Contrast)", "Light", { access: "public", tags: ["Minimal"] }),
  createTheme("Pastel Light", "Light", { tags: ["Pastel"] }),
  createTheme("Paper / Parchment", "Light", { access: "public", tags: ["Minimal"] }),
  createTheme("Sky Light", "Light", { access: "public" }),
  createTheme("Cherry Blossom (Dark)", "Dark", { tags: ["Floral"] }),
  createTheme("Cherry Blossom (Light)", "Light", { tags: ["Floral"] }),
  createTheme("420 Friendly (Light)", "Light", { tags: ["Nature"] }),
  createTheme("420 Friendly (Dark)", "Dark", { tags: ["Nature"] }),
  createTheme("Aurora Night", "Dark", { tags: ["Nature", "Moody"] }),
  createTheme("Mint Soda", "Light", { tags: ["Nature"] }),
  createTheme("Lavender Fog", "Light", { tags: ["Nature"] }),
  createTheme("Crimson Noir", "Dark", { tags: ["Moody"] }),
  createTheme("Ocean Mist", "Light", { tags: ["Ocean"] }),
  createTheme("Deep Ocean", "Dark", { tags: ["Ocean", "Moody"] }),
  createTheme("Sunlit Sand", "Light", { tags: ["Desert"] }),
  createTheme("Graphite", "Dark", { tags: ["Minimal"] }),
  createTheme("Forest Night", "Dark", { tags: ["Nature"] }),
  createTheme("Retro Terminal", "Dark", { tags: ["Retro"] }),
  createTheme("Desert Dusk", "Dark", { access: "public", tags: ["Desert"] }),
  createTheme("Arctic Light", "Light", { tags: ["Minimal"] }),
  createTheme("Rose Quartz", "Light", { tags: ["Floral"] }),
  createTheme("Lemonade", "Light", { tags: ["Pastel"] }),

  // --- VIP + Gold unlock pack
  createTheme("Sunrise Sorbet", "Light", { tags: ["Pastel"], isNew: true }),
  createTheme("Cotton Candy Sky", "Light", { tags: ["Pastel"] }),
  createTheme("Prismatic Pearl", "Light", { access: "gold", goldPrice: 2800, tags: ["Pastel"] }),
  createTheme("Citrus Splash", "Light", { tags: ["Pastel"] }),
  createTheme("Glacier Bloom", "Light", { tags: ["Pastel"] }),
  createTheme("Aurora Pastel", "Light", { tags: ["Pastel", "Nature"] }),

  createTheme("Midnight Mirage", "Dark", { tags: ["Moody"] }),
  createTheme("Neon Abyss", "Dark", { access: "gold", goldPrice: 4200, tags: ["Neon"] }),
  createTheme("Velvet Galaxy", "Dark", { access: "gold", goldPrice: 4500, tags: ["Space", "Moody"] }),
  createTheme("Obsidian Aurora", "Dark", { tags: ["Moody"] }),
  createTheme("Iris & Lola Neon", "Dark", { tags: ["Neon"] }),

];

const IRIS_LOLA_THEME = "Iris & Lola Neon";
const IRIS_LOLA_ALLOWED_USERNAMES = ["Iri", "Lola Henderson"];
const IRIS_LOLA_ALLOWED_USER_IDS = [];
let onlineUsers = [];
const IRIS_LOLA_SHARED_WINDOW_MS = 5000;
const IRIS_LOLA_SHARED_COOLDOWN_MS = 4 * 60 * 1000;
let irisLolaSharedMomentTs = 0;
let irisLolaLastPartnerMsgTs = 0;
let irisLolaLastSelfMsgTs = 0;
let irisLolaStarfieldReady = false;
let irisLolaAmbientLoopsReady = false;
let irisLolaConstellationTimer = null;
let irisLolaShootingStarTimer = null;
let irisLolaTintTimer = null;
let irisLolaDrawerEasterCooldownUntil = 0;

function normalizeUserKey(value) {
  return String(value || "").trim().toLowerCase();
}
function getUserId(user) {
  return user?.id ?? user?.user_id ?? user?.userId ?? null;
}
function isIrisLolaAllowedUser(user) {
  const userId = getUserId(user);
  if (userId != null && IRIS_LOLA_ALLOWED_USER_IDS.length) {
    return IRIS_LOLA_ALLOWED_USER_IDS.map(String).includes(String(userId));
  }
  const uname = normalizeUserKey(user?.username || "");
  return IRIS_LOLA_ALLOWED_USERNAMES.some((allowed) => normalizeUserKey(allowed) === uname);
}
function isIrisLolaAllowed() {
  return isIrisLolaAllowedUser(me);
}
function isIrisLolaThemeActive(themeName) {
  const active = themeName || document.body?.getAttribute("data-theme") || "";
  return active === IRIS_LOLA_THEME;
}
function getPartnerId(coupleState, myUserId) {
  const activeId = Number(coupleState?.active?.partnerId) || 0;
  if (activeId) return activeId;
  const couple = coupleState?.couple || coupleState?.active?.couple;
  const uid = Number(myUserId) || 0;
  if (!couple || !uid) return null;
  const a = Number(couple.user_a_id ?? couple.user1_id ?? couple.userAId ?? couple.user1Id ?? 0) || 0;
  const b = Number(couple.user_b_id ?? couple.user2_id ?? couple.userBId ?? couple.user2Id ?? 0) || 0;
  if (!a || !b) return null;
  if (uid === a) return b;
  if (uid === b) return a;
  return null;
}
function getPartnerUsername(coupleState, myUserId) {
  const activeName = safeString(coupleState?.active?.partner || "");
  if (activeName) return activeName;
  const partner = coupleState?.partner;
  if (partner?.username) return String(partner.username);
  const couple = coupleState?.couple || coupleState?.active?.couple;
  if (!couple) return "";
  const uid = Number(myUserId) || 0;
  if (!uid) return "";
  const a = Number(couple.user_a_id ?? couple.user1_id ?? couple.userAId ?? couple.user1Id ?? 0) || 0;
  const b = Number(couple.user_b_id ?? couple.user2_id ?? couple.userBId ?? couple.user2Id ?? 0) || 0;
  if (!a || !b) return "";
  if (uid === a) return safeString(couple.user_b_name || couple.user2_name || "");
  if (uid === b) return safeString(couple.user_a_name || couple.user1_name || "");
  return "";
}
function shouldShowTogetherGlow(themeActive, coupleActive, partnerOnline) {
  return !!(themeActive && coupleActive && partnerOnline);
}
function shouldShowSharedMoment(now, lastEventTs, cooldownMs) {
  const last = Number(lastEventTs) || 0;
  return !last || (now - last) >= Number(cooldownMs || 0);
}
function shouldAnimateAmbientEffects(prefersReducedMotion) {
  return !prefersReducedMotion;
}
// Iris & Lola Couples Theme Enhancement
// Example usage:
// isIrisLolaThemeActive("Iris & Lola Neon") -> true
// getPartnerId({ active: { partnerId: 42 } }, 7) -> 42
// shouldShowTogetherGlow(true, true, true) -> true
// shouldShowSharedMoment(Date.now(), Date.now() - 240000, 240000) -> true
// shouldAnimateAmbientEffects(true) -> false
function isCoupleActiveState(coupleState) {
  const active = coupleState?.active;
  if (!active || !active.partner) return false;
  const prefs = active.prefs || {};
  const partnerPrefs = active.partnerPrefs || {};
  if (prefs.enabled === false || partnerPrefs.enabled === false) return false;
  return true;
}
function isUserOnlineByName(name) {
  if (!name) return false;
  const set = new Set((onlineUsers || []).map((n) => normalizeUserKey(n)));
  return set.has(normalizeUserKey(name));
}
function ensureIrisLolaStarfield() {
  if (irisLolaStarfieldReady) return;
  const existing = document.getElementById("irisLolaStarfield");
  if (existing) {
    irisLolaStarfieldReady = true;
    return;
  }
  const field = document.createElement("div");
  field.id = "irisLolaStarfield";
  field.className = "irisLolaStarfield";
  field.setAttribute("aria-hidden", "true");
  const stars = [
    { x: "8%", y: "18%", size: "1px", dur: "26s", delay: "-4s" },
    { x: "22%", y: "64%", size: "2px", dur: "32s", delay: "-12s" },
    { x: "38%", y: "32%", size: "1px", dur: "28s", delay: "-8s" },
    { x: "54%", y: "12%", size: "1px", dur: "36s", delay: "-18s" },
    { x: "66%", y: "58%", size: "2px", dur: "30s", delay: "-6s" },
    { x: "74%", y: "28%", size: "1px", dur: "24s", delay: "-10s" },
    { x: "82%", y: "72%", size: "1px", dur: "34s", delay: "-20s" },
    { x: "92%", y: "40%", size: "2px", dur: "40s", delay: "-16s" },
    { x: "14%", y: "82%", size: "1px", dur: "38s", delay: "-22s" },
    { x: "46%", y: "78%", size: "1px", dur: "27s", delay: "-14s" },
  ];
  stars.forEach((star) => {
    const node = document.createElement("span");
    node.className = "irisLolaStar";
    node.style.setProperty("--x", star.x);
    node.style.setProperty("--y", star.y);
    node.style.setProperty("--size", star.size);
    node.style.setProperty("--dur", star.dur);
    node.style.setProperty("--delay", star.delay);
    // Keep a numeric copy so we can draw constellation whispers.
    node.dataset.x = String(parseFloat(String(star.x).replace('%','')) || 0);
    node.dataset.y = String(parseFloat(String(star.y).replace('%','')) || 0);
    field.appendChild(node);
  });
  // Mount inside the chat pane when possible so stars/shooting-stars are visible
  // even if the app shell has an opaque background on some devices/browsers.
  const mount = document.querySelector(".chat") || document.getElementById("app") || document.body;
  mount?.appendChild(field);
  irisLolaStarfieldReady = true;
}

function clearIrisLolaAmbientLoops(){
  try{ if (irisLolaConstellationTimer) clearInterval(irisLolaConstellationTimer); }catch{}
  try{ if (irisLolaShootingStarTimer) clearTimeout(irisLolaShootingStarTimer); }catch{}
  try{ if (irisLolaTintTimer) clearInterval(irisLolaTintTimer); }catch{}
  irisLolaConstellationTimer = null;
  irisLolaShootingStarTimer = null;
  irisLolaTintTimer = null;
  irisLolaAmbientLoopsReady = false;
}

function setIrisLolaSkyTintVars(){
  try{
    // Slightly different aurora tint through the day; subtle so it doesn't fight readability.
    const now = new Date();
    const h = now.getHours() + (now.getMinutes()/60);
    // Night (0-6, 20-24): deeper purple; Day: greener.
    const night = (h < 6 || h >= 20);
    const dusk = (!night && (h < 9 || h >= 17));

    const root = document.documentElement;
    if (night){
      root.style.setProperty('--irisLolaSkyA', 'rgba(42, 0, 64, .72)');
      root.style.setProperty('--irisLolaSkyB', 'rgba(0, 120, 92, .42)');
      root.style.setProperty('--irisLolaSkyC', 'rgba(128, 0, 184, .22)');
    } else if (dusk){
      root.style.setProperty('--irisLolaSkyA', 'rgba(24, 10, 56, .60)');
      root.style.setProperty('--irisLolaSkyB', 'rgba(0, 160, 126, .38)');
      root.style.setProperty('--irisLolaSkyC', 'rgba(168, 62, 255, .20)');
    } else {
      root.style.setProperty('--irisLolaSkyA', 'rgba(10, 26, 42, .48)');
      root.style.setProperty('--irisLolaSkyB', 'rgba(0, 190, 140, .34)');
      root.style.setProperty('--irisLolaSkyC', 'rgba(130, 40, 220, .16)');
    }
  }catch{}
}

function spawnIrisLolaShootingStar(){
  if (!shouldUseIrisLolaAmbient()) return;
  const field = document.getElementById('irisLolaStarfield');
  if (!field) return;
  if (!shouldAnimateAmbientEffects(PREFERS_REDUCED_MOTION)) return;

  const node = document.createElement('span');
  node.className = 'irisLolaShootingStar';
  // Start somewhere near the top-right and streak down-left.
  const startX = 70 + Math.random() * 25; // %
  const startY = 6 + Math.random() * 30;  // %
  const len = 80 + Math.random() * 90;    // px
  const dur = 900 + Math.random() * 800;  // ms
  node.style.setProperty('--sx', `${startX}%`);
  node.style.setProperty('--sy', `${startY}%`);
  node.style.setProperty('--len', `${len}px`);
  node.style.setProperty('--sdur', `${dur}ms`);
  field.appendChild(node);
  setTimeout(()=>{ try{ node.remove(); }catch{} }, dur + 350);
}

function scheduleIrisLolaShootingStar(){
  try{ if (irisLolaShootingStarTimer) clearTimeout(irisLolaShootingStarTimer); }catch{}
  if (!shouldUseIrisLolaAmbient() || !shouldAnimateAmbientEffects(PREFERS_REDUCED_MOTION)) return;
  const delay = 2000 + Math.random() * 5200; // 2s-7.2s
  irisLolaShootingStarTimer = setTimeout(()=>{
    spawnIrisLolaShootingStar();
    scheduleIrisLolaShootingStar();
  }, delay);
}

function spawnIrisLolaConstellationWhisper(){
  if (!shouldUseIrisLolaAmbient()) return;
  const field = document.getElementById('irisLolaStarfield');
  if (!field) return;
  if (!shouldAnimateAmbientEffects(PREFERS_REDUCED_MOTION)) return;
  const stars = Array.from(field.querySelectorAll('.irisLolaStar'));
  if (stars.length < 3) return;

  const rect = field.getBoundingClientRect();
  const pick = () => stars[Math.floor(Math.random() * stars.length)];
  const a = pick();
  let b = pick();
  let c = pick();
  // avoid duplicates
  for (let i=0;i<6 && (b===a);i++) b = pick();
  for (let i=0;i<6 && (c===a || c===b);i++) c = pick();

  const toXY = (el) => {
    const xPct = parseFloat(el.dataset.x || '0') / 100;
    const yPct = parseFloat(el.dataset.y || '0') / 100;
    return { x: rect.width * xPct, y: rect.height * yPct };
  };
  const p1 = toXY(a), p2 = toXY(b), p3 = toXY(c);

  const makeLine = (pFrom, pTo) => {
    const dx = pTo.x - pFrom.x;
    const dy = pTo.y - pFrom.y;
    const dist = Math.sqrt(dx*dx + dy*dy);
    const ang = Math.atan2(dy, dx) * (180/Math.PI);
    const line = document.createElement('span');
    line.className = 'irisLolaConstellationLine';
    line.style.left = `${pFrom.x}px`;
    line.style.top = `${pFrom.y}px`;
    line.style.width = `${dist}px`;
    line.style.transform = `translate3d(0,0,0) rotate(${ang}deg)`;
    return line;
  };

  const wrap = document.createElement('div');
  wrap.className = 'irisLolaConstellationWhisper';
  wrap.appendChild(makeLine(p1, p2));
  wrap.appendChild(makeLine(p2, p3));
  field.appendChild(wrap);
  setTimeout(()=>{ try{ wrap.remove(); }catch{} }, 1300);
}

function ensureIrisLolaAmbientLoops(){
  if (irisLolaAmbientLoopsReady) return;
  if (!shouldUseIrisLolaAmbient()) { clearIrisLolaAmbientLoops(); return; }
  ensureIrisLolaStarfield();

  // Time-based tint updates.
  setIrisLolaSkyTintVars();
  irisLolaTintTimer = setInterval(setIrisLolaSkyTintVars, 5 * 60 * 1000);

  // Occasional constellation whispers: very rare.
  irisLolaConstellationTimer = setInterval(()=>{
    try{ spawnIrisLolaConstellationWhisper(); }catch{}
  }, 2 * 60 * 1000 + Math.floor(Math.random()*60*1000));

  // Shooting stars: randomized cadence.
  scheduleIrisLolaShootingStar();

  irisLolaAmbientLoopsReady = true;
}
function updateIrisLolaTogetherClass() {
  const themeActive = isIrisLolaThemeActive();
  const coupleActive = isCoupleActiveState(couplesState);
  const partnerName = getPartnerUsername(couplesState, getUserId(me));
  const bothOnline = !!(partnerName && isUserOnlineByName(partnerName) && isUserOnlineByName(me?.username));
  const on = shouldShowTogetherGlow(themeActive, coupleActive, bothOnline);
  document.body?.classList.toggle("irisLolaTogether", !!on);
  document.body?.classList.toggle("irisLolaCoupleActive", !!(themeActive && coupleActive));
  updateIrisLolaAvatarGlows({ themeActive, coupleActive, bothOnline, partnerName });
  // Ambient layer: subtle starfield + shooting stars + rare constellation whispers.
  if (themeActive) ensureIrisLolaAmbientLoops();
  else clearIrisLolaAmbientLoops();
}
function updateIrisLolaAvatarGlows({ themeActive, coupleActive, bothOnline, partnerName } = {}) {
  const allow = shouldShowTogetherGlow(themeActive, coupleActive, bothOnline);
  const partnerKey = normalizeUserKey(partnerName || "");
  const meKey = normalizeUserKey(me?.username || "");
  if (memberList) {
    memberList.querySelectorAll(".mItem").forEach((row) => {
      const uname = normalizeUserKey(row.dataset.username || "");
      const target = row.querySelector(".mAvatar");
      if (!target) return;
      const isPair = allow && (uname === partnerKey || uname === meKey);
      target.classList.toggle("irisLolaTogetherGlow", !!isPair);
    });
  }
  if (profileSheetAvatar && profileSheetHero) {
    const profileName = normalizeUserKey(profileSheetHero.dataset.username || "");
    const isPair = allow && (profileName === partnerKey || profileName === meKey);
    profileSheetAvatar.classList.toggle("irisLolaTogetherGlow", !!isPair);
  }
}
function formatIrisLolaStatusLabel(statusLabel, username) {
  if (!statusLabel || statusLabel !== "Online") return statusLabel;
  if (!isIrisLolaThemeActive() || !isCoupleActiveState(couplesState)) return statusLabel;
  const partnerName = getPartnerUsername(couplesState, getUserId(me));
  if (!partnerName) return statusLabel;
  return normalizeUserKey(username) === normalizeUserKey(partnerName) ? "Here together" : statusLabel;
}
function isPartnerName(username) {
  const partnerName = getPartnerUsername(couplesState, getUserId(me));
  if (!partnerName) return false;
  return normalizeUserKey(username) === normalizeUserKey(partnerName);
}
function shouldUseIrisLolaCoupleUi() {
  return isIrisLolaThemeActive() && isCoupleActiveState(couplesState);
}
function shouldUseIrisLolaAmbient() {
  return isIrisLolaThemeActive();
}
const DEFAULT_THEME = "Minimal Dark";
let currentTheme = document.body?.getAttribute("data-theme") || DEFAULT_THEME;
let themeActiveFilter = "all";
let themeSortMode = "recommended";
let themeSearchQuery = "";
let themePinnedIds = [];
let themeFavoriteIds = [];
let themeOwnedIds = [];
let themeRecents = [];
let themePreviewId = themeIdFromName(currentTheme);
let themeSelectedId = themePreviewId;
let themeActionThemeId = "";
const MAX_IMAGE_GIF_BYTES = 25 * 1024 * 1024;
const MAX_AUDIO_BYTES = 15 * 1024 * 1024;
const MAX_VIDEO_BYTES = 100 * 1024 * 1024;
const AUDIO_UPLOAD_ALLOWED_MIME = new Set(["audio/mpeg", "audio/mp4"]);
const AUDIO_UPLOAD_ALLOWED_EXT = new Set(["mp3", "m4a"]);

let modalTargetUsername = null;
let modalTargetUserId = null;
let pendingFile = null;
let roomPendingAttachment = null;
let dmPendingAttachment = null;
let roomUploadToken = null;
let dmUploadToken = null;
let roomUploading = false;
let dmUploading = false;
let uploadXhr = null;
let memberMenuUser = null;
let memberMenuUsername = "";
let memberMenuAnchor = null;
let memberMenuRaf = null;
let replyTarget = null;
let dmReplyTarget = null;
let chatPinned = true;
let dmPinned = true;
let unseenMainMessages = 0;

// ---- DOM
const loginView = document.getElementById("loginView");
const chatView = document.getElementById("chatView");
const restrictedView = document.getElementById("restrictedView");

const restrictedTitle = document.getElementById("restrictedTitle");
const restrictedSub = document.getElementById("restrictedSub");
const restrictedReasonText = document.getElementById("restrictedReasonText");
const restrictedTimerWrap = document.getElementById("restrictedTimerWrap");
const restrictedTimer = document.getElementById("restrictedTimer");
const restrictedRecheckBtn = document.getElementById("restrictedRecheckBtn");
const restrictedLogoutBtn = document.getElementById("restrictedLogoutBtn");

const appealThread = document.getElementById("appealThread");
const appealInput = document.getElementById("appealInput");
const appealSendBtn = document.getElementById("appealSendBtn");
const appealRefreshBtn = document.getElementById("appealRefreshBtn");
const appealMsg = document.getElementById("appealMsg");
const appealStatusText = document.getElementById("appealStatusText");

const appealsPanelBtn = document.getElementById("appealsPanelBtn");
const referralsPanelBtn = document.getElementById("referralsPanelBtn");
const roleDebugPanelBtn = document.getElementById("roleDebugPanelBtn");
const featureFlagsPanelBtn = document.getElementById("featureFlagsPanelBtn");
const sessionsPanelBtn = document.getElementById("sessionsPanelBtn");
const appealsPanel = document.getElementById("appealsPanel");
const referralsPanel = document.getElementById("referralsPanel");
const roleDebugPanel = document.getElementById("roleDebugPanel");
const appealsCloseBtn = document.getElementById("appealsCloseBtn");
const appealsList = document.getElementById("appealsList");
const referralsCloseBtn = document.getElementById("referralsCloseBtn");
const referralsRefreshBtn = document.getElementById("referralsRefreshBtn");
const referralsList = document.getElementById("referralsList");
const referralsDetailUser = document.getElementById("referralsDetailUser");
const referralsDetailMeta = document.getElementById("referralsDetailMeta");
const referralsDetailReason = document.getElementById("referralsDetailReason");
const referralsCopyUserBtn = document.getElementById("referralsCopyUserBtn");
const referralsMarkDoneBtn = document.getElementById("referralsMarkDoneBtn");
const referralsActionMsg = document.getElementById("referralsActionMsg");

const roleDebugCloseBtn = document.getElementById("roleDebugCloseBtn");
const featureFlagsCloseBtn = document.getElementById("featureFlagsCloseBtn");
const featureFlagsReloadBtn = document.getElementById("featureFlagsReloadBtn");
const featureFlagsGrid = document.getElementById("featureFlagsGrid");
const featureFlagsMsg = document.getElementById("featureFlagsMsg");

const sessionsCloseBtn = document.getElementById("sessionsCloseBtn");
const sessionsReloadBtn = document.getElementById("sessionsReloadBtn");
const sessionsTbody = document.getElementById("sessionsTbody");
const sessionsMsg = document.getElementById("sessionsMsg");

const roleDebugTarget = document.getElementById("roleDebugTarget");
const roleDebugRole = document.getElementById("roleDebugRole");
const roleDebugApplyBtn = document.getElementById("roleDebugApplyBtn");
const roleDebugUseSelectedBtn = document.getElementById("roleDebugUseSelectedBtn");
const roleDebugMsg = document.getElementById("roleDebugMsg");
const appealsDetail = document.getElementById("appealsDetail");
const appealsBackBtn = document.getElementById("appealsBackBtn");
const appealsDetailUser = document.getElementById("appealsDetailUser");
const appealsDetailMeta = document.getElementById("appealsDetailMeta");
const appealsDetailReason = document.getElementById("appealsDetailReason");
const appealsModlogs = document.getElementById("appealsModlogs");
const appealsThread = document.getElementById("appealsThread");
const appealsReplyInput = document.getElementById("appealsReplyInput");
const appealsReplyBtn = document.getElementById("appealsReplyBtn");
const appealsReplyMsg = document.getElementById("appealsReplyMsg");
const appealsDurationSelect = document.getElementById("appealsDurationSelect");
const appealsBanToKickBtn = document.getElementById("appealsBanToKickBtn");
const appealsUpdateKickBtn = document.getElementById("appealsUpdateKickBtn");
const appealsUnlockBtn = document.getElementById("appealsUnlockBtn");

const app = document.getElementById("app");
const addRoomBtn = document.getElementById("addRoomBtn");
const manageRoomsBtn = document.getElementById("manageRoomsBtn");
const menuToggleBtn = document.getElementById("menuToggleBtn");
const chanHeaderTitle = document.getElementById("chanHeaderTitle");
const roomsPanel = document.getElementById("roomsPanel");
const menuPanel = document.getElementById("menuPanel");
const menuNav = document.getElementById("menuNav");
const latestUpdate = document.getElementById("latestUpdate");
const latestUpdateTitle = document.getElementById("latestUpdateTitle");
const latestUpdateDate = document.getElementById("latestUpdateDate");
const latestUpdateBody = document.getElementById("latestUpdateBody");
const latestUpdateViewBtn = document.getElementById("latestUpdateViewBtn");
const latestUpdateReactions = document.getElementById("latestUpdateReactions");
let latestUpdateExpanded = false;
const changelogList = document.getElementById("changelogList");
const roomManageModal = document.getElementById("roomManageModal");
const roomManageCloseBtn = document.getElementById("roomManageCloseBtn");
const roomMasterCreateInput = document.getElementById("roomMasterCreateInput");
const roomMasterCreateBtn = document.getElementById("roomMasterCreateBtn");
const roomMasterList = document.getElementById("roomMasterList");
const roomMasterMsg = document.getElementById("roomMasterMsg");
const roomCategoryMasterSelect = document.getElementById("roomCategoryMasterSelect");
const roomCategoryCreateInput = document.getElementById("roomCategoryCreateInput");
const roomCategoryCreateBtn = document.getElementById("roomCategoryCreateBtn");
const roomCategoryList = document.getElementById("roomCategoryList");
const roomCategoryMsg = document.getElementById("roomCategoryMsg");
const roomManageMasterSelect = document.getElementById("roomManageMasterSelect");
const roomManageCategorySelect = document.getElementById("roomManageCategorySelect");
const roomManageRoomList = document.getElementById("roomManageRoomList");
const roomManageMsg = document.getElementById("roomManageMsg");
const roomCreateModal = document.getElementById("roomCreateModal");
const roomCreateCloseBtn = document.getElementById("roomCreateCloseBtn");
const roomCreateNameInput = document.getElementById("roomCreateNameInput");
const roomCreateMasterSelect = document.getElementById("roomCreateMasterSelect");
const roomCreateCategorySelect = document.getElementById("roomCreateCategorySelect");
const roomCreateSubmitBtn = document.getElementById("roomCreateSubmitBtn");
const roomCreateCancelBtn = document.getElementById("roomCreateCancelBtn");
const roomCreateMsg = document.getElementById("roomCreateMsg");

// Shared date formatter for Changelog + FAQ.
// IMPORTANT: keep this at top-level so it is in scope everywhere.
function formatChangelogDate(ts){
  if(ts == null || ts === "") return "";
  let d = null;

  // Accept epoch millis/seconds (number or numeric string)
  if(typeof ts === "number"){
    const ms = ts < 1e12 ? ts * 1000 : ts;
    d = new Date(ms);
  } else if(typeof ts === "string"){
    const trimmed = ts.trim();
    if(!trimmed) return "";
    const asNum = Number(trimmed);
    if(Number.isFinite(asNum)){
      const ms = asNum < 1e12 ? asNum * 1000 : asNum;
      d = new Date(ms);
    } else {
      d = new Date(trimmed);
    }
  } else {
    d = new Date(NaN);
  }

  if(!d || Number.isNaN(d.getTime())) return "";
  try{
    return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(d);
  }catch{
    // Older browsers fallback
    return d.toLocaleString();
  }
}
const changelogMsg = document.getElementById("changelogMsg");
const changelogActions = document.getElementById("changelogActions");
const changelogNewBtn = document.getElementById("changelogNewBtn");
const changelogEditor = document.getElementById("changelogEditor");
const changelogTitleInput = document.getElementById("changelogTitleInput");
const changelogBodyInput = document.getElementById("changelogBodyInput");
const changelogSaveBtn = document.getElementById("changelogSaveBtn");
const changelogCancelBtn = document.getElementById("changelogCancelBtn");
const changelogEditMsg = document.getElementById("changelogEditMsg");
const faqList = document.getElementById("faqList");
const dailyList = document.getElementById("dailyList");
const dailyReloadBtn = document.getElementById("dailyReloadBtn");
dailyReloadBtn?.addEventListener("click", ensureDailyLoaded);
const dailyMsg = document.getElementById("dailyMsg");

const faqMsg = document.getElementById("faqMsg");
const faqAskBtn = document.getElementById("faqAskBtn");
const faqForm = document.getElementById("faqForm");
const faqTitleInput = document.getElementById("faqTitleInput");
const faqDetailsInput = document.getElementById("faqDetailsInput");
const faqSubmitBtn = document.getElementById("faqSubmitBtn");
const faqCancelBtn = document.getElementById("faqCancelBtn");
const faqEditMsg = document.getElementById("faqEditMsg");

// FAQ: title-only question (max 140 chars). The answer is provided by staff.
if(faqTitleInput){
  faqTitleInput.maxLength = 140;
}
const channelsCloseBtn = document.getElementById("channelsCloseBtn");
const membersCloseBtn  = document.getElementById("membersCloseBtn");
const viewCustom = document.getElementById("viewCustomize");

const customizeShell = document.getElementById("customizeShell");
const customizeSearch = document.getElementById("customizeSearch");
const customizeCardGrid = document.getElementById("customizeCardGrid");
const customizeSubpages = document.getElementById("customizeSubpages");
const customizeCards = Array.from(document.querySelectorAll(".customizeCard"));
const customizeBackBtns = Array.from(document.querySelectorAll(".customizeBackBtn"));
const customizePages = Array.from(document.querySelectorAll(".customizeSubpage"));

const chatSpacingCompact = document.getElementById("chatSpacingCompact");
const effectsPreset = document.getElementById("effectsPreset");
const reduceMotionToggle = document.getElementById("reduceMotionToggle");

const resetChatAppearanceBtn = document.getElementById("resetChatAppearanceBtn");
const resetTextIdentityBtn = document.getElementById("resetTextIdentityBtn");
const resetProfileAppearanceBtn = document.getElementById("resetProfileAppearanceBtn");
const resetEffectsBtn = document.getElementById("resetEffectsBtn");
const resetLayoutBtn = document.getElementById("resetLayoutBtn");
const resetAdvancedBtn = document.getElementById("resetAdvancedBtn");

const actionMuteBtn = document.getElementById("actionMuteBtn");
const actionKickBtn = document.getElementById("actionKickBtn");
const actionBanBtn = document.getElementById("actionBanBtn");
const actionAppealsBtn = document.getElementById("actionAppealsBtn");

const profileEditToggleRow = document.getElementById("profileEditToggleRow");
const profileEditToggleBtn = document.getElementById("profileEditToggleBtn");
const profileEditSection = document.getElementById("profileEditSection");
const prefSoundEnabled = document.getElementById("prefSoundEnabled");
const prefSoundRoom = document.getElementById("prefSoundRoom");
const prefSoundDm = document.getElementById("prefSoundDm");
const prefSoundMention = document.getElementById("prefSoundMention");
const prefSoundSent = document.getElementById("prefSoundSent");
const prefSoundReceive = document.getElementById("prefSoundReceive");
const prefSoundReaction = document.getElementById("prefSoundReaction");
const prefSoundStatus = document.getElementById("prefSoundStatus");
const prefComfortMode = document.getElementById("prefComfortMode");
const prefComfortHelp = document.getElementById("prefComfortHelp");


const authForm = document.getElementById("authForm");
const authUser = document.getElementById("authUser");
const authPass = document.getElementById("authPass");
const authMsg = document.getElementById("authMsg");
const authValidation = document.getElementById("authValidation");
const loginBtn = document.getElementById("loginBtn");
const regBtn = document.getElementById("regBtn");
const togglePassBtn = document.getElementById("togglePassBtn");
const captchaWrap = document.getElementById("captchaWrap");
const captchaWidget = document.getElementById("captchaWidget");
const captchaNote = document.getElementById("captchaNote");
const passwordUpgradeView = document.getElementById("passwordUpgradeView");
const passwordUpgradeForm = document.getElementById("passwordUpgradeForm");
const upgradeCurrentPass = document.getElementById("upgradeCurrentPass");
const upgradeNewPass = document.getElementById("upgradeNewPass");
const upgradeConfirmPass = document.getElementById("upgradeConfirmPass");
const passwordUpgradeMsg = document.getElementById("passwordUpgradeMsg");
const passwordUpgradeSubmitBtn = document.getElementById("passwordUpgradeSubmitBtn");
const passwordUpgradeLogoutBtn = document.getElementById("passwordUpgradeLogoutBtn");


// Auth: show/hide password
togglePassBtn?.addEventListener("click", ()=>{
  if (!authPass) return;
  const isHidden = authPass.type === "password";
  authPass.type = isHidden ? "text" : "password";
  togglePassBtn.textContent = isHidden ? "🙈" : "👁";
  togglePassBtn.setAttribute("aria-label", isHidden ? "Hide password" : "Show password");
  togglePassBtn.title = isHidden ? "Hide password" : "Show password";
  authPass.focus();
});

const chanList = document.getElementById("chanList");
const nowRoom = document.getElementById("nowRoom");
const roomEventBanner = document.getElementById("roomEventBanner");
const roomTitle = document.getElementById("roomTitle");

const msgs = document.getElementById("msgs");
const typingEl = document.getElementById("typing");
const memberList = document.getElementById("memberList");
const memberGold = document.getElementById("memberGold");
const memberPills = document.getElementById("memberPills");
const memberPillRoom = document.getElementById("memberPillRoom");
const memberPillFriends = document.getElementById("memberPillFriends");
const memberMenu = document.getElementById("memberMenu");
const memberMenuName = document.getElementById("memberMenuName");
const memberViewProfileBtn = document.getElementById("memberViewProfileBtn");
const memberDmBtn = document.getElementById("memberDmBtn");
const memberReferBtn = document.getElementById("memberReferBtn");

const appRoot = document.getElementById("app");
if (memberMenu && appRoot && memberMenu.parentElement !== appRoot) {
  appRoot.appendChild(memberMenu);
}
const commandPopup = document.getElementById("commandPopup");
const commandPopupTitle = document.getElementById("commandPopupTitle");
const commandPopupBody = document.getElementById("commandPopupBody");
const commandPopupClose = document.getElementById("commandPopupClose");

function setTypingIndicator(text = ""){
  if (!typingEl) return;
  typingEl.innerHTML = "";
  const clean = String(text || "").replace(/(?:\.{3}|…)\s*$/, "").trim();
  if (!clean) return;
  const label = document.createElement("span");
  label.className = "typingText";
  label.textContent = clean;
  const dots = document.createElement("span");
  dots.className = "typingDots";
  dots.setAttribute("aria-hidden", "true");
  for (let i = 0; i < 3; i++) {
    const dot = document.createElement("span");
    dot.className = "dot";
    dots.appendChild(dot);
  }
  typingEl.appendChild(label);
  typingEl.appendChild(dots);
}

// --- Draft persistence (per room & per DM) ---
function roomDraftKey(room){ return `draft:room:${sanitizeRoomClient(room||"main")}`; }
function dmDraftKey(threadId){ return `draft:dm:${String(threadId||"")}`; }

function saveRoomDraft(){
  try { localStorage.setItem(roomDraftKey(currentRoom), String(msgInput?.value||"")); } catch {}
}
function loadRoomDraft(){
  try {
    const v = localStorage.getItem(roomDraftKey(currentRoom));
    if (v != null && msgInput) msgInput.value = v;
  } catch {}
}

function saveDmDraft(){
  try {
    if (!activeDmId) return;
    localStorage.setItem(dmDraftKey(activeDmId), String(dmText?.value||""));
  } catch {}
}
function loadDmDraft(){
  try {
    if (!activeDmId || !dmText) return;
    const v = localStorage.getItem(dmDraftKey(activeDmId));
    if (v != null) dmText.value = v;
  } catch {}
}

const draftDebounce = (()=> {
  let t=null;
  return (fn)=>{
    clearTimeout(t);
    t=setTimeout(fn, 150);
  };
})();

const TONE_MENU_OPTIONS = Object.freeze([
  { key: "", emoji: "🚫", name: "None (clear tone)", description: "No tone" },
  ...TONE_OPTIONS
]);
let openToneMenu = null;
let toneMenuListenersBound = false;

function toneMenuButtonLabel(toneKey){
  const tone = toneMeta(toneKey);
  return tone ? `Tone: ${tone.name} ${tone.emoji}` : "Tone: None";
}

function toneMenuTooltip(toneKey){
  const tone = toneMeta(toneKey);
  return tone ? `Tone: ${tone.name} — ${tone.description}` : "Tone: None";
}

function updateToneMenu(container, activeKey){
  if (!container) return;
  const btn = container.querySelector(".toneMenuBtn");
  if (btn) {
    btn.textContent = "▴";
    btn.title = toneMenuTooltip(activeKey);
    btn.setAttribute("aria-label", toneMenuButtonLabel(activeKey));
  }
  container.classList.toggle("has-tone", !!activeKey);
  container.querySelectorAll(".toneMenuItem").forEach((item) => {
    const on = (item.dataset.tone || "") === (activeKey || "");
    item.classList.toggle("is-active", on);
    item.setAttribute("aria-checked", on ? "true" : "false");
  });
}

function closeToneMenu(menu){
  if (!menu) return;
  menu.container.classList.remove("is-open");
  menu.button.setAttribute("aria-expanded", "false");
  menu.panel.setAttribute("aria-hidden", "true");
  if (openToneMenu === menu) openToneMenu = null;
}

function openToneMenuPanel(menu){
  if (!menu) return;
  if (openToneMenu && openToneMenu !== menu) closeToneMenu(openToneMenu);
  menu.container.classList.add("is-open");
  menu.button.setAttribute("aria-expanded", "true");
  menu.panel.setAttribute("aria-hidden", "false");
  openToneMenu = menu;
}

function toggleToneMenu(menu){
  if (!menu) return;
  const isOpen = menu.container.classList.contains("is-open");
  if (isOpen) closeToneMenu(menu);
  else openToneMenuPanel(menu);
}

function bindToneMenuListeners(){
  if (toneMenuListenersBound) return;
  toneMenuListenersBound = true;
  document.addEventListener("pointerdown", (e) => {
    if (!openToneMenu) return;
    if (openToneMenu.container.contains(e.target)) return;
    closeToneMenu(openToneMenu);
  }, true);
  document.addEventListener("keydown", (e) => {
    if (e.key !== "Escape" || !openToneMenu) return;
    closeToneMenu(openToneMenu);
  });
}

function initToneMenu(container, getTone, setTone){
  if (!container) return;
  container.innerHTML = "";
  container.classList.add("toneMenu");

  const menuId = `${container.id || "tone"}Menu`;
  const button = document.createElement("button");
  button.type = "button";
  button.className = "toneMenuBtn";
  button.setAttribute("aria-expanded", "false");
  button.setAttribute("aria-controls", menuId);
  button.setAttribute("aria-haspopup", "menu");

  const panel = document.createElement("div");
  panel.className = "toneMenuPanel";
  panel.id = menuId;
  panel.setAttribute("role", "menu");
  panel.setAttribute("aria-hidden", "true");

  TONE_MENU_OPTIONS.forEach((tone) => {
    const item = document.createElement("button");
    item.type = "button";
    item.className = "toneMenuItem";
    item.dataset.tone = tone.key;
    item.setAttribute("role", "menuitemradio");
    item.setAttribute("aria-checked", "false");

    const emoji = document.createElement("span");
    emoji.className = "toneMenuEmoji";
    emoji.textContent = tone.emoji;

    const textWrap = document.createElement("span");
    textWrap.className = "toneMenuText";

    const name = document.createElement("span");
    name.className = "toneMenuName";
    name.textContent = tone.name;

    const desc = document.createElement("span");
    desc.className = "toneMenuDesc";
    desc.textContent = tone.description;

    textWrap.appendChild(name);
    textWrap.appendChild(desc);
    item.appendChild(emoji);
    item.appendChild(textWrap);
    panel.appendChild(item);
  });

  const menuState = { container, button, panel };
  button.addEventListener("click", (e) => {
    e.preventDefault();
    toggleToneMenu(menuState);
  });

  panel.addEventListener("click", (e) => {
    const item = e.target.closest(".toneMenuItem");
    if (!item) return;
    const next = item.dataset.tone || "";
    setTone(next);
    updateToneMenu(container, next);
    closeToneMenu(menuState);
  });

  container.appendChild(button);
  container.appendChild(panel);
  updateToneMenu(container, getTone());
  bindToneMenuListeners();
}

const msgInput = document.getElementById("msgInput");
const sendBtn = document.getElementById("sendBtn");
const searchInput = document.getElementById("searchInput");
const tonePicker = document.getElementById("tonePicker");
const dmTonePicker = document.getElementById("dmTonePicker");
let activeTone = "";
let activeDmTone = "";
msgInput?.addEventListener("input", ()=>draftDebounce(saveRoomDraft));

const chatShell = document.querySelector("main.chat");
const composerEl = document.querySelector(".inputBar");
let jumpToLatestBtn = null;

msgs?.addEventListener("scroll", handleChatScroll, { passive:true });

const fileInput = document.getElementById("fileInput");
const audioFileInput = document.getElementById("audioFileInput");
const mediaBtn = document.getElementById("mediaBtn");
const mediaMenu = document.getElementById("mediaMenu");
const mediaMenuImage = document.getElementById("mediaMenuImage");
const mediaMenuAudioUpload = document.getElementById("mediaMenuAudioUpload");
const mediaMenuVoice = document.getElementById("mediaMenuVoice");
const mediaVoiceLabel = document.getElementById("mediaVoiceLabel");
const diceVariantToggle = document.getElementById("diceVariantToggle");
const diceVariantMenu = document.getElementById("diceVariantMenu");
const diceVariantLabel = document.getElementById("diceVariantLabel");
const diceInfoBtn = document.getElementById("diceInfoBtn");
const dicePayoutPopover = document.getElementById("dicePayoutPopover");
const diceVariantWrap = document.getElementById("diceVariantWrap");
const luckMeter = document.getElementById("luckMeter");
const luckMeterBar = document.getElementById("luckMeterBar");
const luckMeterBarText = document.getElementById("luckMeterBarText");
const luckMeterValue = document.getElementById("luckMeterValue");
const luckMeterStreak = document.getElementById("luckMeterStreak");
const survivalPanel = document.getElementById("survivalPanel");
const survivalSeasonTitle = document.getElementById("survivalSeasonTitle");
const survivalStatus = document.getElementById("survivalStatus");
const survivalDayPhase = document.getElementById("survivalDayPhase");
const survivalAliveCount = document.getElementById("survivalAliveCount");
const survivalNewSeasonBtn = document.getElementById("survivalNewSeasonBtn");
const survivalAdvanceBtn = document.getElementById("survivalAdvanceBtn");
const survivalAutoRunBtn = document.getElementById("survivalAutoRunBtn");
const survivalEndBtn = document.getElementById("survivalEndBtn");
const survivalRosterBtn = document.getElementById("survivalRosterBtn");
const survivalLogBtn = document.getElementById("survivalLogBtn");
const survivalHideViewBtn = document.getElementById("survivalHideViewBtn");
const survivalCollapseBtn = document.getElementById("survivalCollapseBtn");
const survivalMiniBtn = document.getElementById("survivalMiniBtn");
const survivalArenaBtn = document.getElementById("survivalArenaBtn");
const survivalLobbyBtn = document.getElementById("survivalLobbyBtn");
const survivalHistorySelect = document.getElementById("survivalHistorySelect");
const survivalLogFeed = document.getElementById("survivalLogFeed");
const survivalLogList = document.getElementById("survivalLogList");
const survivalArena = document.getElementById("survivalArena");
const survivalArenaGrid = document.getElementById("survivalArenaGrid");
const survivalLobbyCount = document.getElementById("survivalLobbyCount");
const survivalNewSeasonModal = document.getElementById("survivalNewSeasonModal");
const survivalNewSeasonClose = document.getElementById("survivalNewSeasonClose");
const survivalSeasonTitleInput = document.getElementById("survivalSeasonTitleInput");
const survivalParticipantList = document.getElementById("survivalParticipantList");
const survivalCouplesToggle = document.getElementById("survivalCouplesToggle");
const survivalChaosToggle = document.getElementById("survivalChaosToggle");
const survivalLobbyToggle = document.getElementById("survivalLobbyToggle");
const survivalNpcNames = document.getElementById("survivalNpcNames");
const survivalFillSlots = document.getElementById("survivalFillSlots");
const survivalSeasonStartBtn = document.getElementById("survivalSeasonStartBtn");
const survivalSeasonMsg = document.getElementById("survivalSeasonMsg");
const survivalRosterModal = document.getElementById("survivalRosterModal");
const survivalRosterClose = document.getElementById("survivalRosterClose");
const survivalRosterList = document.getElementById("survivalRosterList");
const survivalLogModal = document.getElementById("survivalLogModal");
const survivalLogClose = document.getElementById("survivalLogClose");
const survivalLogModalList = document.getElementById("survivalLogModalList");
const survivalLogLoadBtn = document.getElementById("survivalLogLoadBtn");

let mediaMenuOpen = false;
let voiceRec = { recorder: null, stream: null, chunks: [], startedAt: 0 };
let dicePayoutOpen = false;


// Survival UI can be collapsed to a small button (spectators can rely on system messages).
let survivalUiCollapsed = false;
try { survivalUiCollapsed = localStorage.getItem("survivalUiCollapsed") === "1"; } catch {}

function setSurvivalUiCollapsed(collapsed) {
  survivalUiCollapsed = !!collapsed;
  try { localStorage.setItem("survivalUiCollapsed", survivalUiCollapsed ? "1" : "0"); } catch {}
  const inRoom = isSurvivalRoom(currentRoom);
  if (survivalPanel) survivalPanel.hidden = !inRoom || survivalUiCollapsed;
  if (survivalMiniBtn) survivalMiniBtn.hidden = !inRoom || !survivalUiCollapsed;
  // When collapsed, close expanded views; system messages remain visible in chat.
  if (survivalUiCollapsed) {
    survivalState.view = "none";
  }
  renderSurvivalPanel();
}

// Wire collapse/expand controls
survivalCollapseBtn?.addEventListener("click", () => setSurvivalUiCollapsed(!survivalUiCollapsed));
survivalMiniBtn?.addEventListener("click", () => setSurvivalUiCollapsed(false));

// On boot, hide dice-only UI unless we are already in the Dice Room.
try {
  const nowDiceRoom = isDiceRoom(currentRoom);
  if (diceVariantWrap) diceVariantWrap.style.display = nowDiceRoom ? "" : "none";
  if (luckMeter) luckMeter.style.display = nowDiceRoom ? "" : "none";
  const nowSurvivalRoom = isSurvivalRoom(currentRoom);
  if (survivalPanel) survivalPanel.hidden = !nowSurvivalRoom || survivalUiCollapsed;
  if (survivalMiniBtn) survivalMiniBtn.hidden = !nowSurvivalRoom || !survivalUiCollapsed;
  // Expanded log/map views are optional; spectators can rely on system messages in chat.
  if (survivalLogFeed) survivalLogFeed.hidden = !nowSurvivalRoom || survivalUiCollapsed || survivalState.view !== "log";
  if (survivalArena) survivalArena.hidden = !nowSurvivalRoom || survivalUiCollapsed || survivalState.view !== "arena";
} catch {}

function closeMediaMenu(){
  if(!mediaMenu) return;
  mediaMenuOpen = false;
  mediaMenu.hidden = true;
  mediaBtn?.setAttribute("aria-expanded","false");
}
function openMediaMenu(){
  if(!mediaMenu) return;
  mediaMenuOpen = true;
  mediaMenu.hidden = false;
  mediaBtn?.setAttribute("aria-expanded","true");
}
function toggleMediaMenu(){
  if(mediaMenuOpen) closeMediaMenu();
  else openMediaMenu();
}

function updateDiceVariantLabel(){
  if (!diceVariantLabel) return;
  diceVariantLabel.textContent = DICE_VARIANT_LABELS[diceVariant] || diceVariant;
}

const DICE_PAYOUT_RULES = {
  d6: {
    title: "d6 payouts",
    lines: ["1–5: -50 Gold", "6: +500 Gold"],
    note: "Tip: swapping variants changes the risk/reward.",
  },
  d20: {
    title: "d20 payouts",
    lines: [
      "1–5: -250 Gold",
      "6–10: -100 Gold",
      "11–14: +100 Gold",
      "15–17: +250 Gold",
      "18–19: +500 Gold",
      "20: +1000 Gold",
    ],
    note: "High rolls hit bigger bursts.",
  },
  "2d6": {
    title: "2d6 payouts",
    lines: ["No 6s: -100 Gold", "One 6: +500 Gold", "Two 6s: +1500 Gold"],
    note: "Each die counts.",
  },
  d100: {
    title: "1–100 payouts",
    lines: ["69: +69 Gold", "100: +5000 Gold", "Everything else: -25 Gold"],
    note: "Jackpot is rare — but cheap to try.",
  },
};

function renderDicePayoutPopover(){
  if (!dicePayoutPopover) return;
  const rule = DICE_PAYOUT_RULES[diceVariant] || DICE_PAYOUT_RULES.d6;
  const lines = (rule.lines || []).map((t)=>`<li>${escapeHtml(t)}</li>`).join("");
  dicePayoutPopover.innerHTML = `
    <h4>${escapeHtml(rule.title)}</h4>
    <ul>${lines}</ul>
    <div class="payoutNote">${escapeHtml(rule.note || "")}</div>
  `;
}

function openDicePayout(){
  if (!dicePayoutPopover) return;
  renderDicePayoutPopover();
  dicePayoutOpen = true;
  dicePayoutPopover.hidden = false;
  diceInfoBtn?.setAttribute("aria-expanded", "true");
}

function closeDicePayout(){
  if (!dicePayoutPopover) return;
  dicePayoutOpen = false;
  dicePayoutPopover.hidden = true;
  diceInfoBtn?.setAttribute("aria-expanded", "false");
}

function toggleDicePayout(){
  if (dicePayoutOpen) closeDicePayout();
  else openDicePayout();
}

function closeDiceVariantMenu(){
  if (!diceVariantMenu) return;
  diceVariantMenuOpen = false;
  diceVariantMenu.hidden = true;
  diceVariantToggle?.setAttribute("aria-expanded", "false");
}

function openDiceVariantMenu(){
  if (!diceVariantMenu) return;
  diceVariantMenuOpen = true;
  diceVariantMenu.hidden = false;
  diceVariantToggle?.setAttribute("aria-expanded", "true");
}

function toggleDiceVariantMenu(){
  if (diceVariantMenuOpen) closeDiceVariantMenu();
  else openDiceVariantMenu();
}

function setDiceVariant(nextVariant){
  if (!DICE_VARIANTS.includes(nextVariant)) return;
  diceVariant = nextVariant;
  updateDiceVariantLabel();
  renderDicePayoutPopover();
  if (diceVariantMenu) {
    diceVariantMenu.querySelectorAll("[data-variant]").forEach((btn) => {
      const isActive = btn.dataset.variant === nextVariant;
      btn.classList.toggle("active", isActive);
      btn.setAttribute("aria-checked", String(isActive));
    });
  }
}

function clampNumber(value, min, max){
  const num = Number(value || 0);
  return Math.max(min, Math.min(max, num));
}

function formatLuckValue(value){
  const num = Number(value || 0);
  const sign = num > 0 ? "+" : num < 0 ? "" : "";
  return `${sign}${num.toFixed(2)}`;
}

function renderLuckMeter(){
  if (!luckMeter || !luckMeterBarText) return;
  const luck = clampNumber(luckState.luck, LUCK_MIN, LUCK_MAX);
  const ratio = (luck - LUCK_MIN) / (LUCK_MAX - LUCK_MIN);
  const idx = Math.round(clampNumber(ratio, 0, 1) * (LUCK_BAR_SLOTS - 1));
  const slots = Array.from({ length: LUCK_BAR_SLOTS }, () => "-");
  slots[idx] = "^";
  luckMeterBarText.textContent = `|${slots.join("")}|`;
  if (luckMeterValue) luckMeterValue.textContent = formatLuckValue(luck);
  if (luckMeterStreak) luckMeterStreak.textContent = `Streak ${Number(luckState.rollStreak || 0)}`;
  luckMeterBar?.setAttribute("aria-valuenow", String(luck));
}

function requestLuckState(force = false){
  if (!socket) return;
  const now = Date.now();
  if (!force && now - lastLuckRequestAt < LUCK_REQUEST_COOLDOWN_MS) return;
  lastLuckRequestAt = now;
  socket.emit("luck:get");
}

function survivalIsOwner(){
  return me && roleRank(me.role) >= roleRank("Co-owner");
}

function updateSurvivalHistorySelect() {
  if (!survivalHistorySelect) return;
  const history = survivalState.history || [];
  survivalHistorySelect.innerHTML = "";
  const placeholder = document.createElement("option");
  placeholder.value = "";
  placeholder.textContent = history.length ? "Select season" : "No history yet";
  survivalHistorySelect.appendChild(placeholder);
  history.forEach((season) => {
    const opt = document.createElement("option");
    opt.value = season.id;
    const winner = season.winner ? ` — Winner: ${season.winner}` : "";
    opt.textContent = `${season.title}${winner}`;
    survivalHistorySelect.appendChild(opt);
  });
  if (survivalState.selectedSeasonId) {
    survivalHistorySelect.value = String(survivalState.selectedSeasonId);
  }
}

function getSurvivalAliveCount() {
  return (survivalState.participants || []).filter((p) => p.alive).length;
}

function renderSurvivalPanel() {
  if (!survivalPanel) return;
  const season = survivalState.season;
  const aliveCount = getSurvivalAliveCount();
  if (survivalSeasonTitle) survivalSeasonTitle.textContent = season ? season.title : "No season";
  if (survivalStatus) {
    let statusLabel = season ? season.status : "idle";
    if (season?.status === "finished" && survivalState.winner) {
      statusLabel = `finished — ${survivalState.winner}`;
    }
    survivalStatus.textContent = statusLabel;
  }
  if (survivalDayPhase) {
    const day = season?.day_index ? `Day ${season.day_index}` : "Day 1";
    const phase = season?.phase ? capitalize(season.phase) : "Day";
    survivalDayPhase.textContent = `${day} — ${phase}`;
  }
  if (survivalAliveCount) survivalAliveCount.textContent = `Alive: ${aliveCount}`;

  if (survivalCollapseBtn) {
    survivalCollapseBtn.textContent = survivalUiCollapsed ? '▸' : '▾';
    survivalCollapseBtn.setAttribute('aria-expanded', survivalUiCollapsed ? 'false' : 'true');
  }

  if (survivalNewSeasonBtn) survivalNewSeasonBtn.disabled = !survivalIsOwner();
  if (survivalAdvanceBtn) survivalAdvanceBtn.disabled = !survivalIsOwner() || !season || season.status !== "running";
  if (survivalAutoRunBtn) survivalAutoRunBtn.disabled = !survivalIsOwner() || !season || season.status !== "running";
  if (survivalEndBtn) survivalEndBtn.disabled = !survivalIsOwner() || !season;
  if (survivalAutoRunBtn) survivalAutoRunBtn.textContent = survivalAutoRunning ? "Stop Auto" : "Auto-Run";
  updateSurvivalHistorySelect();

  // View toggles
  const nowSurvivalRoom = isSurvivalRoom(currentRoom);
  const collapsed = !!survivalUiCollapsed;
  if (survivalPanel) survivalPanel.hidden = !nowSurvivalRoom || collapsed;
  if (survivalMiniBtn) survivalMiniBtn.hidden = !nowSurvivalRoom || !collapsed;
  if (survivalLogFeed) survivalLogFeed.hidden = !nowSurvivalRoom || collapsed || survivalState.view !== "log";
  if (survivalArena) survivalArena.hidden = !nowSurvivalRoom || collapsed || survivalState.view !== "arena";
}

function getSurvivalEventIcon(outcome = {}) {
  const type = outcome?.type;
  if (type === "kill" || type === "betray") return "☠️";
  if (type === "alliance") return "🤝";
  if (type === "injure") return "🩹";
  if (type === "heal" || type === "protect") return "💚";
  if (type === "loot" || type === "steal") return "🎒";
  if (type === "winner") return "🏆";
  if (type === "draw") return "⚠️";
  return "✨";
}

function renderSurvivalLog(targetEl, events) {
  if (!targetEl) return;
  targetEl.innerHTML = "";
  if (!events || !events.length) {
    const empty = document.createElement("div");
    empty.className = "survivalLogText";
    empty.textContent = "No events yet.";
    targetEl.appendChild(empty);
    return;
  }
  let lastHeader = "";
  (events || []).forEach((event) => {
    const header = `Day ${event.day_index} — ${capitalize(event.phase || "day")}`;
    if (header !== lastHeader) {
      const divider = document.createElement("div");
      divider.className = "survivalLogDivider";
      divider.textContent = header;
      targetEl.appendChild(divider);
      lastHeader = header;
    }
    const row = document.createElement("div");
    row.className = "survivalLogItem";
    const icon = document.createElement("div");
    icon.className = "survivalLogIcon";
    icon.textContent = getSurvivalEventIcon(event.outcome || {});
    const text = document.createElement("div");
    text.className = "survivalLogText";
    text.textContent = event.text || "";
    row.appendChild(icon);
    row.appendChild(text);
    targetEl.appendChild(row);
  });
}

const SURVIVAL_ARENA_ZONES = [
  "Open Field",
  "Pine Woods",
  "Rocky Ridge",
  "Ruins",
  "River Bend",
  "Caves",
  "Swamp",
  "Cornucopia",
];

function renderSurvivalArena() {
  if (!survivalArenaGrid) return;
  const participants = survivalState.participants || [];
  const byZone = new Map();
  participants.forEach((p) => {
    const zRaw = (p?.location || "Open Field").toString();
    const z = SURVIVAL_ARENA_ZONES.find((n) => n.toLowerCase() === zRaw.toLowerCase()) || "Open Field";
    if (!byZone.has(z)) byZone.set(z, []);
    byZone.get(z).push(p);
  });

  survivalArenaGrid.innerHTML = "";
  SURVIVAL_ARENA_ZONES.forEach((zone) => {
    const list = (byZone.get(zone) || []).slice().sort((a, b) => Number(b.alive) - Number(a.alive));
    const alive = list.filter((p) => p.alive).length;
    const danger = Number(survivalState.arena?.dangerLevels?.[zone] || 0);

    const card = document.createElement("div");
    card.className = "survivalZone";
    card.innerHTML = `
      <div class="survivalZoneTop">
        <div class="survivalZoneName">${escapeHtml(zone)}</div>
        <div class="survivalZoneMeta">Alive: ${alive} · Danger: ${danger}</div>
      </div>
      <div class="survivalZoneList"></div>
    `;
    const ul = card.querySelector(".survivalZoneList");
    const show = list.slice(0, 12);
    ul.innerHTML = show.map((p) => {
      const name = p?.display_name || "?";
      const cls = p?.alive ? "survivalZoneP" : "survivalZoneP dead";
      return `<span class="${cls}">${escapeHtml(name)}</span>`;
    }).join("");
    if (list.length > show.length) {
      const more = document.createElement("div");
      more.className = "small muted";
      more.textContent = `+${list.length - show.length} more`;
      card.appendChild(more);
    }
    survivalArenaGrid.appendChild(card);
  });

  if (survivalLobbyCount) {
    const count = (survivalState.lobbyUserIds || []).length;
    survivalLobbyCount.textContent = count ? `Lobby signups: ${count}` : "";
  }
  if (survivalLobbyBtn) {
    const isIn = !!me?.id && (survivalState.lobbyUserIds || []).includes(Number(me.id));
    survivalLobbyBtn.textContent = isIn ? "Opt-out" : "Opt-in";
  }
}

function renderSurvivalRoster() {
  if (!survivalRosterList) return;
  survivalRosterList.innerHTML = "";
  const alliances = new Map((survivalState.alliances || []).map((a) => [a.id, a.name]));
  const participants = (survivalState.participants || []).slice().sort((a, b) => Number(b.alive) - Number(a.alive));
  participants.forEach((p) => {
    const row = document.createElement("div");
    row.className = "survivalRosterRow";
    row.classList.toggle("dead", !p.alive);
    const avatar = document.createElement("div");
    avatar.className = "survivalRosterAvatar";
    if (p.avatar_url) avatar.style.backgroundImage = `url('${p.avatar_url}')`;
    const meta = document.createElement("div");
    meta.className = "survivalRosterMeta";
    const name = document.createElement("div");
    name.className = "survivalRosterName";
    name.textContent = p.display_name;
    const stats = document.createElement("div");
    stats.className = "survivalRosterStats";
    const status = document.createElement("span");
    status.className = `survivalRosterStatus ${p.alive ? "alive" : "dead"}`;
    status.textContent = p.alive ? "Alive" : "Down";
    const allianceName = p.alliance_id ? alliances.get(p.alliance_id) : null;
    stats.textContent = `${status.textContent} • ${p.kills || 0} KOs${allianceName ? ` • ${allianceName}` : ""}`;
    meta.appendChild(name);
    meta.appendChild(stats);
    row.appendChild(avatar);
    row.appendChild(meta);
    row.addEventListener("click", () => {
      if (p.display_name) openMemberProfile(p.display_name);
    });
    survivalRosterList.appendChild(row);
  });
}

async function loadSurvivalCurrent() {
  if (!isSurvivalRoom(currentRoom)) return;
  const { res, text } = await api("/api/survival/current", { method: "GET" });
  if (!res.ok) return;
  const payload = safeJsonParse(text, null);
  if (!payload) return;
  applySurvivalPayload(payload, { replaceEvents: true });
}

async function loadSurvivalSeason(seasonId, { beforeId = null } = {}) {
  if (!seasonId) return null;
  const url = beforeId ? `/api/survival/seasons/${seasonId}?before=${encodeURIComponent(beforeId)}` : `/api/survival/seasons/${seasonId}`;
  const { res, text } = await api(url, { method: "GET" });
  if (!res.ok) return null;
  const payload = safeJsonParse(text, null);
  if (!payload) return null;
  return payload;
}

function applySurvivalPayload(payload, { replaceEvents = false } = {}) {
  if (payload.season) survivalState.season = payload.season;
  if (Array.isArray(payload.participants)) survivalState.participants = payload.participants;
  if (Array.isArray(payload.alliances)) survivalState.alliances = payload.alliances;
  if (payload.winner !== undefined) survivalState.winner = payload.winner;
  if (Array.isArray(payload.history)) survivalState.history = payload.history;
  if (Array.isArray(payload.events)) {
    if (replaceEvents) {
      survivalState.events = payload.events;
    } else {
      survivalState.events = [...payload.events];
    }
    survivalState.logBeforeId = payload.events?.[0]?.id || survivalState.logBeforeId;
  }
  if (payload.arena && typeof payload.arena === "object") {
    survivalState.arena = payload.arena;
  }
  if (!survivalState.selectedSeasonId && payload.season) {
    survivalState.selectedSeasonId = payload.season.id;
  }
  renderSurvivalPanel();
  renderSurvivalLog(survivalLogList, survivalState.events);
  renderSurvivalArena();
}

async function openSurvivalNewSeasonModal() {
  if (!survivalNewSeasonModal) return;
  if (!survivalIsOwner()) return toast("Only Owner/Co-Owner can start a season.");
  survivalSeasonMsg.textContent = "";
  const now = new Date();
  if (survivalSeasonTitleInput) {
    survivalSeasonTitleInput.value = `Season — ${now.toLocaleString()}`;
  }
  const users = (lastUsers || []).filter((u) => u?.name);
  survivalParticipantList.innerHTML = "";
  if (survivalCouplesToggle) survivalCouplesToggle.checked = false;
  if (survivalChaosToggle) survivalChaosToggle.checked = false;
  if (survivalLobbyToggle) survivalLobbyToggle.checked = false;
  if (survivalNpcNames) survivalNpcNames.value = "";
  if (survivalFillSlots) survivalFillSlots.value = "0";
  users.forEach((user) => {
    if (!user?.id) return;
    const row = document.createElement("label");
    row.className = "survivalParticipantRow";
    row.innerHTML = `<input type="checkbox" value="${user.id}"/> ${escapeHtml(user.name)}`;
    survivalParticipantList.appendChild(row);
  });
  survivalNewSeasonModal.hidden = false;
  survivalNewSeasonModal.style.display = "flex";
  survivalNewSeasonModal.classList.remove("modal-closing");
  if (PREFERS_REDUCED_MOTION) {
    survivalNewSeasonModal.classList.add("modal-visible");
  } else {
    requestAnimationFrame(() => survivalNewSeasonModal.classList.add("modal-visible"));
  }
}

function closeSurvivalNewSeasonModal() {
  if (!survivalNewSeasonModal) return;
  survivalNewSeasonModal.classList.remove("modal-visible");
  survivalNewSeasonModal.classList.add("modal-closing");
  setTimeout(() => {
    survivalNewSeasonModal.style.display = "none";
    survivalNewSeasonModal.classList.remove("modal-closing");
    survivalNewSeasonModal.hidden = true;
  }, 140);
}

function openSurvivalRosterModal() {
  if (!survivalRosterModal) return;
  renderSurvivalRoster();
  survivalRosterModal.hidden = false;
  survivalRosterModal.style.display = "flex";
  survivalRosterModal.classList.remove("modal-closing");
  if (PREFERS_REDUCED_MOTION) {
    survivalRosterModal.classList.add("modal-visible");
  } else {
    requestAnimationFrame(() => survivalRosterModal.classList.add("modal-visible"));
  }
}

function closeSurvivalRosterModal() {
  if (!survivalRosterModal) return;
  survivalRosterModal.classList.remove("modal-visible");
  survivalRosterModal.classList.add("modal-closing");
  setTimeout(() => {
    survivalRosterModal.style.display = "none";
    survivalRosterModal.classList.remove("modal-closing");
    survivalRosterModal.hidden = true;
  }, 140);
}

function openSurvivalLogModal() {
  if (!survivalLogModal) return;
  renderSurvivalLog(survivalLogModalList, survivalState.events);
  survivalLogModal.hidden = false;
  survivalLogModal.style.display = "flex";
  survivalLogModal.classList.remove("modal-closing");
  if (PREFERS_REDUCED_MOTION) {
    survivalLogModal.classList.add("modal-visible");
  } else {
    requestAnimationFrame(() => survivalLogModal.classList.add("modal-visible"));
  }
}

function closeSurvivalLogModal() {
  if (!survivalLogModal) return;
  survivalLogModal.classList.remove("modal-visible");
  survivalLogModal.classList.add("modal-closing");
  setTimeout(() => {
    survivalLogModal.style.display = "none";
    survivalLogModal.classList.remove("modal-closing");
    survivalLogModal.hidden = true;
  }, 140);
}

async function startSurvivalSeason() {
  if (!survivalIsOwner()) return;
  const mode = document.querySelector("input[name='survivalPickMode']:checked")?.value || "online";
  const selected = Array.from(
    survivalParticipantList.querySelectorAll("input[type='checkbox']:checked")
  ).map((el) => Number(el.value));
  const onlineIds = (lastUsers || []).map((u) => u?.id).filter((id) => Number.isInteger(id));
  const participantIds = mode === "select" ? selected : onlineIds;
  const npcRaw = (survivalNpcNames?.value || "").trim();
  const fillSlots = Number(survivalFillSlots?.value || 0) || 0;
  const npcCount = npcRaw ? npcRaw.split(/[\n,]/g).map((s) => s.trim()).filter(Boolean).length : 0;
  const baseCount = participantIds.length + npcCount;
  const desiredCount = fillSlots > 0 ? Math.max(fillSlots, baseCount) : baseCount;
  if (desiredCount < 2) {
    if (survivalSeasonMsg) survivalSeasonMsg.textContent = "Add at least two total participants (users or custom names).";
    return;
  }
  if (survivalSeasonStartBtn) survivalSeasonStartBtn.disabled = true;
  if (survivalSeasonMsg) survivalSeasonMsg.textContent = "Starting season...";
  try {
    const payload = {
      title: survivalSeasonTitleInput?.value || "",
      participant_user_ids: participantIds,
      include_lobby: !!survivalLobbyToggle?.checked,
      npc_names: npcRaw,
      fill_slots: fillSlots,
      options: {
        includeCouples: !!survivalCouplesToggle?.checked,
        chaoticMode: !!survivalChaosToggle?.checked,
      },
    };
    const { res, text } = await api("/api/survival/seasons", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!res.ok) throw new Error(text || "Failed");
    const data = safeJsonParse(text, null);
    if (data) applySurvivalPayload(data, { replaceEvents: true });
    closeSurvivalNewSeasonModal();
  } catch (err) {
    if (survivalSeasonMsg) survivalSeasonMsg.textContent = err?.message || "Failed to start season.";
  } finally {
    if (survivalSeasonStartBtn) survivalSeasonStartBtn.disabled = false;
  }
}

async function advanceSurvivalSeason() {
  if (!survivalIsOwner()) return;
  const seasonId = survivalState.season?.id;
  if (!seasonId) return;
  try {
    const { res, text } = await api(`/api/survival/seasons/${seasonId}/advance`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    });
    if (!res.ok) throw new Error(text || "Failed");
    const data = safeJsonParse(text, null);
    if (data) applySurvivalPayload(data, { replaceEvents: true });
  } catch (err) {
    toast(err?.message || "Could not advance season.");
  }
}

async function endSurvivalSeason() {
  if (!survivalIsOwner()) return;
  const seasonId = survivalState.season?.id;
  if (!seasonId) return;
  if (!confirm("End this season early?")) return;
  try {
    const { res, text } = await api(`/api/survival/seasons/${seasonId}/end`, { method: "POST" });
    if (!res.ok) throw new Error(text || "Failed");
    const data = safeJsonParse(text, null);
    if (data) applySurvivalPayload(data, { replaceEvents: true });
  } catch (err) {
    toast(err?.message || "Could not end season.");
  }
}

function startSurvivalAutoRun() {
  if (survivalAutoRunTimer) return;
  survivalAutoRunning = true;
  renderSurvivalPanel();
  survivalAutoRunTimer = setInterval(async () => {
    if (!survivalState.season || survivalState.season.status !== "running") {
      stopSurvivalAutoRun();
      return;
    }
    await advanceSurvivalSeason();
  }, 2200);
}

function stopSurvivalAutoRun() {
  if (survivalAutoRunTimer) clearInterval(survivalAutoRunTimer);
  survivalAutoRunTimer = null;
  survivalAutoRunning = false;
  renderSurvivalPanel();
}

async function loadOlderSurvivalLog() {
  const seasonId = survivalState.selectedSeasonId || survivalState.season?.id;
  if (!seasonId || !survivalState.logBeforeId) return;
  const payload = await loadSurvivalSeason(seasonId, { beforeId: survivalState.logBeforeId });
  if (!payload || !payload.events?.length) return;
  survivalState.logBeforeId = payload.events[0]?.id || survivalState.logBeforeId;
  survivalState.events = [...payload.events, ...survivalState.events];
  renderSurvivalLog(survivalLogModalList, survivalState.events);
}

function isHighRoll(variant, result){
  const threshold = DICE_LUCKY_THRESHOLDS[variant];
  if (!threshold) return false;
  return result >= threshold;
}

function updateDiceSessionStats(payload){
  if (!payload || payload.userId !== me?.id) return;
  const now = Date.now();
  if (diceSessionStats.lastRollAt && now - diceSessionStats.lastRollAt > 5 * 60 * 1000) {
    diceSessionStats.consecutiveRolls = 0;
    diceSessionStats.luckyStreak = 0;
  }
  diceSessionStats.lastRollAt = now;
  diceSessionStats.consecutiveRolls += 1;

  const result = Number(payload.result ?? payload.value ?? 0);
  if (result > diceSessionStats.highestRoll) {
    diceSessionStats.highestRoll = result;
    toast?.(`🎯 New high: ${result}`);
  }

  if (isHighRoll(payload.variant, result)) {
    diceSessionStats.luckyStreak += 1;
  } else {
    diceSessionStats.luckyStreak = 0;
  }

  if (diceSessionStats.luckyStreak === 3) {
    toast?.("🔥 Lucky Streak x3");
  }

  if (diceSessionStats.consecutiveRolls === 5 || diceSessionStats.consecutiveRolls === 10) {
    toast?.(`🔥 ${diceSessionStats.consecutiveRolls} roll streak!`);
  }
}

function triggerDiceButtonShake(){
  if (!mediaBtn || PREFERS_REDUCED_MOTION) return;
  mediaBtn.classList.remove("diceShaking");
  void mediaBtn.offsetWidth;
  mediaBtn.classList.add("diceShaking");
  mediaBtn.addEventListener("animationend", () => mediaBtn.classList.remove("diceShaking"), { once:true });
}

function rollDiceImmediate(nextVariant = diceVariant){
  if (!socket || !isDiceRoom(currentRoom)) return;
  const now = Date.now();
  if (now < diceCooldownUntil) {
    const left = Math.max(1, Math.ceil((diceCooldownUntil - now) / 1000));
    addSystem(`Roll available in ${left}s`);
    return;
  }
  diceCooldownUntil = now + DICE_ROLL_COOLDOWN_MS;
  triggerDiceButtonShake();
  socket.emit("dice:roll", { room: currentRoom, variant: nextVariant, clientTs: now });
}

if(chatShell){
  jumpToLatestBtn = document.createElement("button");
  jumpToLatestBtn.id = "jumpToLatest";
  jumpToLatestBtn.type = "button";
  jumpToLatestBtn.textContent = "Jump to latest";
  chatShell.appendChild(jumpToLatestBtn);
  jumpToLatestBtn.addEventListener("click", ()=>{
    unseenMainMessages = 0;
    stickToBottomIfWanted({ force:true, behavior:"smooth" });
  });
}

if(msgs) handleChatScroll();

if(window.ResizeObserver && composerEl){
  const composerObserver = new ResizeObserver(()=> queueStickToBottom());
  composerObserver.observe(composerEl);
}

// iOS virtual keyboard: keep the conversation pinned to bottom on the *first* viewport resize.
// When the keyboard appears, scrollTop can briefly land off-bottom, causing a jarring jump.
let __vvPinRaf = 0;
// On iOS Safari, scroll position can be mutated *before* the first visualViewport resize fires.
// Capture a "was pinned" snapshot on input focus so we can force-pin even if chatPinned flips.
let __vvExpectKeyboard = false;
let __vvChatPinnedSnapshot = true;
let __vvDmPinnedSnapshot = true;
let __vvExpectTimer = null;

function markExpectKeyboard(){
  // Only meaningful on mobile / iOS, but harmless elsewhere.
  __vvExpectKeyboard = true;
  __vvChatPinnedSnapshot = isNearBottom(msgs, 260);
  __vvDmPinnedSnapshot = isNearBottom(dmMessagesEl, 260);
  if(__vvExpectTimer) clearTimeout(__vvExpectTimer);
  // Keyboard open/close animations can take a beat on iOS.
  __vvExpectTimer = setTimeout(()=>{ __vvExpectKeyboard = false; }, 1400);
}

function handleVisualViewportPin(){
  if(__vvPinRaf) cancelAnimationFrame(__vvPinRaf);
  __vvPinRaf = requestAnimationFrame(()=>{
    // If the user was pinned to bottom before the resize, force it.
    // Use the focus snapshot during keyboard open so we don't lose the pinned state.
    const shouldForceChat = __vvExpectKeyboard ? __vvChatPinnedSnapshot : chatPinned;
    const shouldForceDm = __vvExpectKeyboard ? __vvDmPinnedSnapshot : dmPinned;
    if(shouldForceChat) stickToBottomIfWanted({ force:true, behavior:"auto" });
    if(shouldForceDm && dmMessagesEl) {
      try{ dmMessagesEl.scrollTo({ top: dmMessagesEl.scrollHeight, behavior:"auto" }); }
      catch{ dmMessagesEl.scrollTop = dmMessagesEl.scrollHeight; }
    }
    // One more pass after layout settles (Safari iOS sometimes needs it).
    setTimeout(()=>{
      if(shouldForceChat) stickToBottomIfWanted({ force:true, behavior:"auto" });
      if(shouldForceDm && dmMessagesEl) dmMessagesEl.scrollTop = dmMessagesEl.scrollHeight;
    }, 60);
  });
}
if(window.visualViewport){
  window.visualViewport.addEventListener("resize", handleVisualViewportPin, { passive:true });
  window.visualViewport.addEventListener("scroll", handleVisualViewportPin, { passive:true });
}

const meAvatar = document.getElementById("meAvatar");
const meName = document.getElementById("meName");
const meRole = document.getElementById("meRole");
const meStatusText = document.getElementById("meStatusText");
const statusSelect = document.getElementById("statusSelect");
const profileBtn = document.getElementById("profileBtn");
const couplesBtn = document.getElementById("couplesBtn");
const couplesModal = document.getElementById("couplesModal");
const couplesModalBody = document.getElementById("couplesModalBody");
const couplesModalClose = document.getElementById("couplesModalClose");
let couplesModalDock = null;

// Defensive: ensure Couples modal is truly closed on boot. (Prevents a "stuck" top bar if
// something rehydrates styles or the DOM ends up in a weird state after prior patches.)
try {
  if (couplesModal) {
    couplesModal.style.display = "none";
    couplesModal.classList.remove("modal-visible", "modal-closing");
    couplesModal.hidden = true;
  }
} catch {}
const replyPreview = document.getElementById("replyPreview");
const replyPreviewText = document.getElementById("replyPreviewText");
const replyPreviewClose = document.getElementById("replyPreviewClose");
const mentionDropdown = document.getElementById("mentionDropdown");

// iOS keyboard / visualViewport: capture a "was pinned" snapshot before the keyboard resizes the viewport.
// markExpectKeyboard is defined below (function hoisting), safe to reference here.
msgInput?.addEventListener("focus", () => { try{ markExpectKeyboard(); }catch{} });
msgInput?.addEventListener("touchstart", () => { try{ markExpectKeyboard(); }catch{} }, { passive:true });

// dms
const dmPanel = document.getElementById("dmPanel");
const dmToggleBtn = document.getElementById("dmToggleBtn");
const groupDmToggleBtn = document.getElementById("groupDmToggleBtn");
const dmBadgeDot = document.getElementById("dmBadgeDot");
const groupDmBadgeDot = document.getElementById("groupDmBadgeDot");

// Quick avatar strips (shown before opening the DM panel)
const dmQuickBar = document.getElementById("dmQuickBar");
const dmQuickStrip = document.getElementById("dmQuickStrip");
const groupQuickBar = document.getElementById("groupQuickBar");
const groupQuickStrip = document.getElementById("groupQuickStrip");
const dmQuickEmpty = document.getElementById("dmQuickEmpty");
const groupQuickEmpty = document.getElementById("groupQuickEmpty");
const groupQuickStartBtn = document.getElementById("groupQuickStartBtn");

const DM_THREAD_ENTRY_SELECTOR = ".dmAvatarBtn";
function updateDmThreadPlaceholderVisibility(){
  const applyVisibility = (stripEl, emptyEl) => {
    if (!stripEl || !emptyEl) return;
    const hasThreads = !!stripEl.querySelector(DM_THREAD_ENTRY_SELECTOR);
    stripEl.hidden = false;
    emptyEl.hidden = false;
    stripEl.classList.toggle("hidden", !hasThreads);
    emptyEl.classList.toggle("hidden", hasThreads);
  };
  applyVisibility(dmQuickStrip || dmStrip, dmQuickEmpty);
  applyVisibility(groupQuickStrip, groupQuickEmpty);
}

const dmCloseBtn = document.getElementById("dmCloseBtn");
const dmBackBtn = document.getElementById("dmBackBtn");
const dmTabs = document.getElementById("dmTabs");
const dmCreateGroupBtn = document.getElementById("dmCreateGroupBtn");
const dmThreadList = document.getElementById("dmThreadList");
const dmStrip = document.getElementById("dmStrip");
const dmMsg = document.getElementById("dmMsg");
const dmNotice = document.getElementById("dmNotice");

function setDmNotice(text){
  if(!dmMsg) return;
  dmMsg.textContent = text || "";
  // Only show the notice text when it has content.
  if(dmNotice) dmNotice.classList.toggle("hasNotice", !!dmMsg.textContent);
}
const dmMetaTitle = document.getElementById("dmMetaTitle");
const dmMetaPeople = document.getElementById("dmMetaPeople");
const dmMetaAvatar = document.getElementById("dmMetaAvatar");
const dmMessagesEl = document.getElementById("dmMessages");
const dmText = document.getElementById("dmText");
const dmFileInput = document.getElementById("dmFileInput");
const dmPickFileBtn = document.getElementById("dmPickFileBtn");
const dmSendBtn = document.getElementById("dmSendBtn");

// iOS keyboard / visualViewport: snapshot pinned state for DM view too.
dmText?.addEventListener("focus", () => { try{ markExpectKeyboard(); }catch{} });
dmText?.addEventListener("touchstart", () => { try{ markExpectKeyboard(); }catch{} }, { passive:true });
dmText?.addEventListener("input", ()=>draftDebounce(saveDmDraft));

// Ensure DM quick bars start closed on load (safety net in case markup defaults are changed)
hideAllDmQuickBars();

// DM media upload
dmPickFileBtn?.addEventListener("click", () => { dmFileInput?.click(); });
dmFileInput?.addEventListener("change", async () => {
  const fileRaw = dmFileInput.files && dmFileInput.files[0] ? dmFileInput.files[0] : null;
  const file = normalizeSelectedFile(fileRaw);
  if(!file) return;
  // reset input so the same file can be re-selected
  try{ dmFileInput.value = ""; }catch{}
  dmPendingAttachment = null;
  const validation = validateUploadFile(file);
  if(!validation.ok){
    setDmNotice(validation.message || "File not allowed.");
    return;
  }
  dmUploadToken = `${Date.now()}-${Math.random()}`;
  const token = dmUploadToken;
  setDmUploadingState(true);
  try{
    setDmNotice("Uploading media…");
    const up = await uploadChatFileWithProgress(file);
    if(token !== dmUploadToken) return;
    dmPendingAttachment = { url: up.url, mime: up.mime, type: up.type, size: up.size };
    dmUploadToken = null;
    setDmUploadingState(false);
    sendDmMessage();
  }catch(e){
    if(token !== dmUploadToken) return;
    dmUploadToken = null;
    dmPendingAttachment = null;
    setDmUploadingState(false);
    setDmNotice(String(e?.message || "Upload failed."));
  }
});


dmMessagesEl?.addEventListener("scroll", ()=>{ dmPinned = isNearBottom(dmMessagesEl, 160); });
const dmUserBtn = document.getElementById("dmUserBtn");
const dmInfoBtn = document.getElementById("dmInfoBtn");
const dmSettingsBtn = document.getElementById("dmSettingsBtn");
const likeProfileBtn = document.getElementById("likeProfileBtn");
const profileEditBtn = document.getElementById("profileEditBtn");
const profileSettingsBtn = document.getElementById("profileSettingsBtn");
const likeCount = document.getElementById("likeCount");
const profileLikeMsg = document.getElementById("profileLikeMsg");
const leaderboardXp = document.getElementById("leaderboardXp");
const leaderboardGold = document.getElementById("leaderboardGold");
const leaderboardDice = document.getElementById("leaderboardDice");
const leaderboardLikes = document.getElementById("leaderboardLikes");
const leaderboardsMsg = document.getElementById("leaderboardsMsg");
const leaderboardsUpdatedAt = document.getElementById("leaderboardsUpdatedAt");
const refreshLeaderboardsBtn = document.getElementById("refreshLeaderboardsBtn");
const dmSettingsMenu = document.getElementById("dmSettingsMenu");
const dmDeleteHistoryBtn = document.getElementById("dmDeleteHistoryBtn");
const dmReportBtn = document.getElementById("dmReportBtn");
const dmReplyPreview = document.getElementById("dmReplyPreview");
const dmReplyPreviewText = document.getElementById("dmReplyPreviewText");
const dmReplyClose = document.getElementById("dmReplyClose");
const dmMentionDropdown = document.getElementById("dmMentionDropdown");
const dmNeonColorInput = document.getElementById("dmNeonColor");
const dmNeonColorText = document.getElementById("dmNeonColorText");
const dmPickerModal = document.getElementById("dmPickerModal");
const dmModalCloseBtn = document.getElementById("dmModalCloseBtn");
const dmModalCancelBtn = document.getElementById("dmModalCancelBtn");
const dmModalPrimaryBtn = document.getElementById("dmModalPrimaryBtn");
const dmModalSearch = document.getElementById("dmModalSearch");
const dmModalTitle = document.getElementById("dmModalTitle");
const dmModalSubtitle = document.getElementById("dmModalSubtitle");
const dmPickerList = document.getElementById("dmPickerList");
const dmInfoModal = document.getElementById("dmInfoModal");
const dmInfoCloseBtn = document.getElementById("dmInfoCloseBtn");
const dmInfoTitle = document.getElementById("dmInfoTitle");
const dmInfoSubtitle = document.getElementById("dmInfoSubtitle");
const dmInfoMembers = document.getElementById("dmInfoMembers");
const dmInfoAddBtn = document.getElementById("dmInfoAddBtn");
const dmLeaveBtn = document.getElementById("dmLeaveBtn");

const customNav = document.getElementById("customNav");
const themeMsg = document.getElementById("themeMsg");
const currentThemeLabel = document.getElementById("currentThemeLabel");
const openThemesModalBtn = document.getElementById("openThemesModalBtn");
const themesModal = document.getElementById("themesModal");
const themesModalCloseBtn = document.getElementById("themesModalClose");
const themesModalSearch = document.getElementById("themesModalSearch");
const themesModalFilters = document.getElementById("themesModalFilters");
const themesModalSort = document.getElementById("themesModalSort");
const themesFiltersBtn = document.getElementById("themesFiltersBtn");
const themesFiltersSheet = document.getElementById("themesFiltersSheet");
const themesFiltersSheetBody = document.getElementById("themesFiltersSheetBody");
const themesFiltersSheetClose = document.getElementById("themesFiltersSheetClose");
const themesPinnedSection = document.getElementById("themesPinnedSection");
const themesPinnedGrid = document.getElementById("themesPinnedGrid");
const themesAllGrid = document.getElementById("themesAllGrid");
const themesEmptyState = document.getElementById("themesEmptyState");
const themesPreviewFrame = document.getElementById("themesPreviewFrame");
const themesPreviewName = document.getElementById("themesPreviewName");
const themesApplyBtn = document.getElementById("themesApplyBtn");
const themesBuyBtn = document.getElementById("themesBuyBtn");
const themesPreviewHint = document.getElementById("themesPreviewHint");
const themesActionSheet = document.getElementById("themesActionSheet");
const themesActionSheetTitle = document.getElementById("themesActionSheetTitle");
const themesActionPinBtn = document.getElementById("themesActionPinBtn");
const themesActionFavoriteBtn = document.getElementById("themesActionFavoriteBtn");
const themesActionApplyBtn = document.getElementById("themesActionApplyBtn");
const themesActionBuyBtn = document.getElementById("themesActionBuyBtn");
const themesActionCloseBtn = document.getElementById("themesActionCloseBtn");
const customNavButtons = Array.from(document.querySelectorAll(".customNavBtn"));

// drawers
const drawerOverlay = document.getElementById("drawerOverlay");
const openChannelsBtn = document.getElementById("openChannelsBtn");
const openMembersBtn = document.getElementById("openMembersBtn");
const channelsPane = document.getElementById("channelsPane");
const membersPane = document.getElementById("membersPane");

// upload preview
const uploadPreview = document.getElementById("uploadPreview");
const previewThumb = document.getElementById("previewThumb");
const uploadName = document.getElementById("uploadName");
const uploadInfo = document.getElementById("uploadInfo");
const uploadProgress = document.getElementById("uploadProgress");
const cancelUploadBtn = document.getElementById("cancelUploadBtn");

// modal
const modal = document.getElementById("modal");
const closeModalBtn = document.getElementById("closeModalBtn");
const modalTitle = document.getElementById("modalTitle");
const modalMeta = document.getElementById("modalMeta");
const modalAvatar = document.getElementById("modalAvatar");
const modalName = document.getElementById("modalName");
const modalRole = document.getElementById("modalRole");
const modalMood = document.getElementById("modalMood");
const profileVibes = document.getElementById("profileVibes");
const profileSheetHero = document.getElementById("profileSheetHero");
const profileSheetBg = document.getElementById("profileSheetBg");
const profileSheetAvatar = document.getElementById("profileSheetAvatar");
const profileSheetAvatarActions = document.getElementById("profileSheetAvatarActions");
const profileSheetName = document.getElementById("profileSheetName");
const profileSheetNameRow = document.querySelector(".profileSheetNameRow");
const profileSheetRoleChip = document.getElementById("profileSheetRoleChip");
const profileSheetStats = document.getElementById("profileSheetStats");
const profileSheetStars = document.getElementById("profileSheetStars");
const profileSheetLikes = document.getElementById("profileSheetLikes");
const profileSheetSub = document.getElementById("profileSheetSub");
const profileCoupleChip = document.getElementById("profileCoupleChip");
const profileCoupleCard = document.getElementById("profileCoupleCard");
const profileCoupleBody = document.getElementById("profileCoupleBody");
const profileCoupleAvatars = document.getElementById("profileCoupleAvatars");
const profileCoupleName = document.getElementById("profileCoupleName");
const profileCoupleBadge = document.getElementById("profileCoupleBadge");
const profileCoupleMeta = document.getElementById("profileCoupleMeta");
const profileCoupleBio = document.getElementById("profileCoupleBio");
const profileSheetAge = document.getElementById("profileSheetAge");
const profileSheetGender = document.getElementById("profileSheetGender");
const profileSheetDetails = document.getElementById("profileSheetDetails");
const profileMenu = document.getElementById("profileMenu");
const profilePresenceDot = document.getElementById("profilePresenceDot");
const mediaLightbox = document.getElementById("mediaLightbox");
const mediaLightboxImg = document.getElementById("mediaLightboxImg");
const mediaLightboxVideo = document.getElementById("mediaLightboxVideo");
const mediaLightboxClose = document.getElementById("mediaLightboxClose");

// info
const infoAge = document.getElementById("infoAge");
const infoGender = document.getElementById("infoGender");
const infoLanguage = document.getElementById("infoLanguage");
const infoCreated = document.getElementById("infoCreated");
const infoLastSeen = document.getElementById("infoLastSeen");
const infoRoom = document.getElementById("infoRoom");
const infoStatus = document.getElementById("infoStatus");
const profileMoodValue = document.getElementById("profileMood");
const profileStatusValue = document.getElementById("profileStatus");

// tabs/views
const tabProfile = document.getElementById("tabProfile");
const tabTimeline = document.getElementById("tabTimeline");
const tabCustomize = document.getElementById("tabCustomize");
const tabActions = document.getElementById("tabActions");
const addFriendBtn = document.getElementById("addFriendBtn");
const declineFriendBtn = document.getElementById("declineFriendBtn");

const viewAccount = document.getElementById("viewProfile");
const viewTimeline = document.getElementById("viewTimeline");
const viewMore = document.getElementById("viewActions");
const viewAbout = document.getElementById("viewAbout");
const viewModeration = document.getElementById("viewModeration");
const profileCustomEmpty = document.getElementById("profileCustomEmpty");

const bioRender = document.getElementById("bioRender");
const copyUsernameBtn = document.getElementById("copyUsernameBtn");
const mediaMsg = document.getElementById("mediaMsg");
const profileActionMsg = document.getElementById("profileActionMsg");
const customizeMsg = document.getElementById("customizeMsg");
const levelPanel = document.getElementById("levelPanel");
const levelBadge = document.getElementById("levelBadge");
const xpText = document.getElementById("xpText");
const xpProgress = document.getElementById("xpProgress");
const xpNote = document.getElementById("xpNote");
const levelToast = document.getElementById("levelToast");
const levelToastText = document.getElementById("levelToastText");
const profileSheetVibes = document.getElementById("profileSheetVibes");
const profileSheetOverlay = document.getElementById("profileSheetOverlay");

const memoryFilterBar = document.getElementById("memoryFilterBar");
const memoryFilterChips = Array.from(document.querySelectorAll(".memoryFilterChip"));
const memoryFeaturedSection = document.getElementById("memoryFeaturedSection");
const memoryFeaturedRow = document.getElementById("memoryFeaturedRow");
const memoryTimelineList = document.getElementById("memoryTimelineList");
const memoryEmptyState = document.getElementById("memoryEmptyState");
const memoryTimelineMsg = document.getElementById("memoryTimelineMsg");

const directBadgeColor = document.getElementById("directBadgeColor");
const groupBadgeColor = document.getElementById("groupBadgeColor");
const directBadgeColorText = document.getElementById("directBadgeColorText");
const groupBadgeColorText = document.getElementById("groupBadgeColorText");
const saveBadgePrefsBtn = document.getElementById("saveBadgePrefsBtn");
// (dmBadgeDot + groupDmBadgeDot declared above near DM panel wiring)

// my profile edit
const myProfileEdit = document.getElementById("myProfileEdit");
const memorySettingsPanel = document.getElementById("memorySettingsPanel");
const memoryEnabledToggle = document.getElementById("memoryEnabledToggle");
const memorySettingsMsg = document.getElementById("memorySettingsMsg");
const avatarFile = document.getElementById("avatarFile");
const headerColorA = document.getElementById("headerColorA");
const headerColorB = document.getElementById("headerColorB");
const headerColorAText = document.getElementById("headerColorAText");
const headerColorBText = document.getElementById("headerColorBText");
let avatarPreviewUrl = null;

// couples (opt-in)
const couplesPartnerInput = document.getElementById("couplesPartnerInput");
const couplesRequestBtn = document.getElementById("couplesRequestBtn");
const couplesPendingBox = document.getElementById("couplesPendingBox");
const couplesPendingList = document.getElementById("couplesPendingList");
const couplesActiveBox = document.getElementById("couplesActiveBox");
const couplesActiveTitle = document.getElementById("couplesActiveTitle");
const couplesEnabledToggle = document.getElementById("couplesEnabledToggle");
const couplesShowProfileToggle = document.getElementById("couplesShowProfileToggle");
const couplesBadgeToggle = document.getElementById("couplesBadgeToggle");
const couplesAuraToggle = document.getElementById("couplesAuraToggle");
const couplesShowMembersToggle = document.getElementById("couplesShowMembersToggle");
const couplesGroupToggle = document.getElementById("couplesGroupToggle");
const couplesAllowPingToggle = document.getElementById("couplesAllowPingToggle");
const couplesV2Box = document.getElementById("couplesV2Box");
const couplesPrivacySelect = document.getElementById("couplesPrivacySelect");
const couplesNameInput = document.getElementById("couplesNameInput");
const couplesBioInput = document.getElementById("couplesBioInput");
const couplesShowBadgeToggle = document.getElementById("couplesShowBadgeToggle");
const couplesBonusesToggle = document.getElementById("couplesBonusesToggle");
const couplesSettingsSaveBtn = document.getElementById("couplesSettingsSaveBtn");
const couplesNudgeBtn = document.getElementById("couplesNudgeBtn");
const couplesV2Status = document.getElementById("couplesV2Status");
const couplesUnlinkBtn = document.getElementById("couplesUnlinkBtn");
const couplesMsg = document.getElementById("couplesMsg");

let couplesState = { active: null, incoming: [], outgoing: [] };
const editMood = document.getElementById("editMood");
const editUsername = document.getElementById("editUsername");
const changeUsernameBtn = document.getElementById("changeUsernameBtn");
const editAge = document.getElementById("editAge");
const editGender = document.getElementById("editGender");
const vibeTagOptions = document.getElementById("vibeTagOptions");
const vibeTagLimitLabel = document.getElementById("vibeTagLimit");
const editBio = document.getElementById("editBio");
const bioHelperToggle = document.getElementById("bioHelperToggle");
const bioHelper = document.getElementById("bioHelper");
const bioHelperPreview = document.getElementById("bioHelperPreview");
const bioHelperButtons = document.getElementById("bioHelperButtons");
const saveProfileBtn = document.getElementById("saveProfileBtn");
const refreshProfileBtn = document.getElementById("refreshProfileBtn");
const profileMsg = document.getElementById("profileMsg");
const logoutBtn = document.getElementById("logoutBtn");
const logoutTopBtn = document.getElementById("logoutTopBtn");

setMsgline(profileActionMsg, "");
setMsgline(profileLikeMsg, "");
setMsgline(mediaMsg, "");
ensureVisibleOnFocus(editBio);
ensureVisibleOnFocus(changelogBodyInput);
if (avatarFile && !avatarFile._wired){
  avatarFile._wired = true;
  avatarFile.addEventListener("change", () => {
    const file = avatarFile.files?.[0];
    if (!file) return;
    applyAvatarPreview(file);
  });
}
const uiScaleRange = document.getElementById("uiScaleRange");
const uiScaleValue = document.getElementById("uiScaleValue");
const uiScaleResetBtn = document.getElementById("uiScaleResetBtn");
const notificationsBtn = document.getElementById("notificationsBtn");
const notificationsModal = document.getElementById("notificationsModal");
const notificationsCloseBtn = document.getElementById("notificationsCloseBtn");
const notificationsClearBtn = document.getElementById("notificationsClearBtn");
const notificationsList = document.getElementById("notificationsList");
const notificationsEmpty = document.getElementById("notificationsEmpty");
const notificationsDot = document.getElementById("notificationsDot");

let bioPreviewTimer = null;
function renderBioPreview(){
  if(!bioHelperPreview || !editBio) return;
  bioHelperPreview.innerHTML = renderBBCode(editBio.value || "");
}

function scheduleBioPreview(){
  if(bioPreviewTimer) clearTimeout(bioPreviewTimer);
  bioPreviewTimer = setTimeout(renderBioPreview, 90);
}

function toggleBioHelperPanel(){
  if(!bioHelper) return;
  const isHidden = bioHelper.hasAttribute("hidden");
  if(isHidden){
    bioHelper.removeAttribute("hidden");
    scheduleBioPreview();
  } else {
    bioHelper.setAttribute("hidden", "");
  }
}

function insertBioTag(tag){
  if(!editBio) return;
  const start = editBio.selectionStart ?? editBio.value.length;
  const end = editBio.selectionEnd ?? start;
  const selection = editBio.value.slice(start, end);
  let before = "";
  let after = "";
  let body = selection;

  switch(tag){
    case "b": before = "[b]"; after = "[/b]"; break;
    case "i": before = "[i]"; after = "[/i]"; break;
    case "u": before = "[u]"; after = "[/u]"; break;
    case "s": before = "[s]"; after = "[/s]"; break;
    case "quote": before = "[quote]"; after = "[/quote]"; break;
    case "code": before = "[code]"; after = "[/code]"; break;
    case "url": {
      const url = prompt("Enter URL", selection || "https://");
      if(!url) return;
      before = `[url=${url}]`;
      after = "[/url]";
      body = selection || "link text";
      break;
    }
    case "color": {
      const color = prompt("Color (hex or name)", selection || "#ff6b6b");
      if(!color) return;
      before = `[color=${color}]`;
      after = "[/color]";
      body = selection || "text";
      break;
    }
    case "img": {
      const url = selection || prompt("Image URL", "https://");
      if(!url) return;
      before = "[img]";
      after = "[/img]";
      body = url;
      break;
    }
    default: return;
  }

  const snippet = `${before}${body || ""}${after}`;
  editBio.setRangeText(snippet, start, end, "end");
  scheduleBioPreview();
  editBio.focus();
}

if(bioHelperButtons){
  bioHelperButtons.addEventListener("click", (ev)=>{
    const target = ev.target;
    if(!(target instanceof HTMLElement)) return;
    const tag = target.dataset?.bioTag;
    if(tag) insertBioTag(tag);
  });
}
if(bioHelperToggle){
  bioHelperToggle.addEventListener("click", toggleBioHelperPanel);
}
if(editBio){
  editBio.addEventListener("input", scheduleBioPreview, { passive:true });
}

// member quick mod / actions overlay (staff)
const actionsBtn = document.getElementById("actionsBtn");
const inlineMemberActionsShade = document.getElementById("inlineMemberActionsShade");
const memberActionsOverlay = document.getElementById("memberActionsOverlay");
const closeMemberActionsBtn = document.getElementById("closeMemberActionsBtn");

const quickReason = document.getElementById("quickReason");
const quickReasonPresets = document.getElementById("quickReasonPresets");
const quickMuteMins = document.getElementById("quickMuteMins");
const quickBanMins = document.getElementById("quickBanMins");
const quickKickSeconds = document.getElementById("quickKickSeconds");
const quickKickBtn = document.getElementById("quickKickBtn");
const quickUnkickBtn = document.getElementById("quickUnkickBtn");
const quickMuteBtn = document.getElementById("quickMuteBtn");
const quickUnmuteBtn = document.getElementById("quickUnmuteBtn");
const quickBanBtn = document.getElementById("quickBanBtn");
const quickModMsg = document.getElementById("quickModMsg");

let modalCanModerate = false;

function openMemberActionsOverlay(){
  if (!inlineMemberActionsShade || !memberActionsOverlay) return;
  if (!modalTargetUsername || !modalCanModerate) return;
  inlineMemberActionsShade.style.display = "flex";
  memberActionsOverlay.style.display = "block";
  if (quickModMsg) quickModMsg.textContent = "";
  try { quickReason?.focus(); } catch {}
}

function closeMemberActionsOverlay(){
  if (memberActionsOverlay) memberActionsOverlay.style.display = "none";
  if (inlineMemberActionsShade) inlineMemberActionsShade.style.display = "none";
}

// Actions button wiring (staff quick menu)
if (actionsBtn && !actionsBtn._wired){
  actionsBtn._wired = true;
  actionsBtn.addEventListener("click", openMemberActionsOverlay);
}
if (closeMemberActionsBtn && !closeMemberActionsBtn._wired){
  closeMemberActionsBtn._wired = true;
  closeMemberActionsBtn.addEventListener("click", closeMemberActionsOverlay);
}
if (inlineMemberActionsShade && !inlineMemberActionsShade._wired){
  inlineMemberActionsShade._wired = true;
  inlineMemberActionsShade.addEventListener("click", (e)=>{
    if (e.target === inlineMemberActionsShade) closeMemberActionsOverlay();
  });
}

actionMuteBtn?.addEventListener("click", openMemberActionsOverlay);
actionKickBtn?.addEventListener("click", openMemberActionsOverlay);
actionBanBtn?.addEventListener("click", openMemberActionsOverlay);
actionAppealsBtn?.addEventListener("click", openAppealsPanel);


// moderation panel
const modUserSelect = document.getElementById("modUserSelect");
const modUser = document.getElementById("modUser");
const modReason = document.getElementById("modReason");
const modMuteMins = document.getElementById("modMuteMins");
const modBanMins = document.getElementById("modBanMins");
const modKickBtn = document.getElementById("modKickBtn");
const modMuteBtn = document.getElementById("modMuteBtn");
const modBanBtn = document.getElementById("modBanBtn");
const modUnmuteBtn = document.getElementById("modUnmuteBtn");
const modUnbanBtn = document.getElementById("modUnbanBtn");
const modWarnBtn = document.getElementById("modWarnBtn");
const modOpenProfileBtn = document.getElementById("modOpenProfileBtn");
const modRefreshTargetsBtn = document.getElementById("modRefreshTargetsBtn");
const modSetRole = document.getElementById("modSetRole");
const modSetRoleBtn = document.getElementById("modSetRoleBtn");
const modReasonPresets = document.getElementById("modReasonPresets");
const modMsg = document.getElementById("modMsg");

// logs
const logUser = document.getElementById("logUser");
const logAction = document.getElementById("logAction");
const logLimit = document.getElementById("logLimit");
const refreshLogsBtn = document.getElementById("refreshLogsBtn");
const logsMsg = document.getElementById("logsMsg");
const logsBody = document.getElementById("logsBody");

refreshModTargetOptions();

// ---- helpers
function escapeHtml(s){
  return String(s).replace(/[&<>"']/g, m => ({
    "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#039;"
  }[m]));
}

function capitalize(value){
  const str = String(value || "");
  return str ? str.charAt(0).toUpperCase() + str.slice(1) : "";
}

// Linkify plain-text URLs into safe anchors.
// Always pass ESCAPED text into linkify (e.g. linkify(escapeHtml(text))).
function linkify(escapedText){
  const s = String(escapedText ?? "");
  // Match http(s) URLs and www.* URLs (escapedText should not contain raw HTML)
  const re = /(\bhttps?:\/\/[^\s<]+|\bwww\.[^\s<]+)/gi;
  return s.replace(re, (url) => {
    const href = url.startsWith("http") ? url : `https://${url}`;
    return `<a href="${href}" target="_blank" rel="noopener noreferrer">${url}</a>`;
  });
}

function normKey(u){ return String(u||"").trim().toLowerCase(); }
function extractYouTubeIds(text){
  const s = String(text||"");
  const re = /(?:https?:\/\/)?(?:www\.)?(?:youtube\.com\/(?:watch\?v=|shorts\/|embed\/)|youtu\.be\/)([A-Za-z0-9_-]{6,})/ig;
  const hits = [];
  let m;
  while((m = re.exec(s))){
    if(m[1]) hits.push(m[1]);
  }
  // Preserve order while deduping
  return hits.filter((id, idx) => hits.indexOf(id) === idx);
}
function stripYouTubeUrls(text){
  return String(text||"").replace(/(?:https?:\/\/)?(?:www\.)?(?:youtube\.com\/(?:watch\?v=|shorts\/|embed\/)[^\s]+|youtu\.be\/[^\s]+)/gi, "").trim();
}
const YOUTUBE_META_CACHE = new Map();
function fetchYouTubeMeta(videoId){
  if(!videoId) return Promise.resolve(null);
  if(YOUTUBE_META_CACHE.has(videoId)) return Promise.resolve(YOUTUBE_META_CACHE.get(videoId));
  const url = `https://noembed.com/embed?url=https://www.youtube.com/watch?v=${encodeURIComponent(videoId)}`;
  return fetch(url)
    .then(r => r.ok ? r.json() : null)
    .then(data => {
      if(!data) return null;
      const meta = {
        title: data.title || "YouTube video",
        channel: data.author_name || "YouTube",
        thumbnail: data.thumbnail_url || `https://i.ytimg.com/vi/${videoId}/hqdefault.jpg`,
        url: data.url || `https://www.youtube.com/watch?v=${videoId}`
      };
      YOUTUBE_META_CACHE.set(videoId, meta);
      return meta;
    })
    .catch(()=>null);
}
function formatTimeShort(sec){
  const s = Math.max(0, Math.floor(sec||0));
  const m = Math.floor(s/60);
  const rem = s % 60;
  return `${m}:${rem.toString().padStart(2,"0")}`;
}

// Main chat timestamp helper (HH:MM).
// NOTE: `buildMainMsgItem()` expects `formatTime(ts)` to exist. A prior refactor
// left only `formatTimeShort()` (used by the YouTube player), which caused
// main-room messages to throw during render (avatar would appear but message
// text would not).
function formatTime(ts){
  const d = new Date(Number(ts || Date.now()));
  // Use locale time but keep it compact.
  try{
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  }catch{
    const hh = String(d.getHours()).padStart(2,"0");
    const mm = String(d.getMinutes()).padStart(2,"0");
    return `${hh}:${mm}`;
  }
}
const StickyYouTubePlayer = (()=>{
  let container, playerHolder, titleEl, channelEl, thumbEl, playPauseBtn, muteBtn, volumeSlider, seekSlider, currentTimeEl, durationEl, qualitySelect, minimizeBtn, closeBtn;
  let player = null;
  let apiReadyPromise = null;
  let progressTimer = null;
  let currentVideoId = null;
  let pendingAutoplay = false;
  let state = "expanded";

  // Some YT "quality levels" are actually size-like tiers (large/medium/small/tiny).
  // We treat those as player size controls.
  const YT_SIZE_LEVELS = ["large","medium","small","tiny"];
  const YT_SIZE_CLASS = { large:"yt-size-large", medium:"yt-size-medium", small:"yt-size-small", tiny:"yt-size-tiny" };
  const YT_SIZE_HEIGHT = { large:240, medium:180, small:140, tiny:110 };
  const YT_SIZE_STORAGE_KEY = "yt_player_size";
  const YT_SIZE_DEFAULT = "medium";


  function loadApi(){
    if(window.YT?.Player) return Promise.resolve(window.YT);
    if(apiReadyPromise) return apiReadyPromise;
    apiReadyPromise = new Promise((resolve, reject)=>{
      const prevCb = window.onYouTubeIframeAPIReady;
      window.onYouTubeIframeAPIReady = ()=>{ prevCb?.(); resolve(window.YT); };
      const script = document.createElement("script");
      script.src = "https://www.youtube.com/iframe_api";
      script.async = true;
      script.onerror = (err)=>reject(err);
      document.head.appendChild(script);
    });
    return apiReadyPromise;
  }

  function initDom(){
    container = document.getElementById("ytSticky");
    if(!container) return;
    playerHolder = document.getElementById("ytStickyFrame");
    titleEl = document.getElementById("ytStickyTitle");
    channelEl = document.getElementById("ytStickyChannel");
    thumbEl = document.getElementById("ytStickyThumb");
    playPauseBtn = document.getElementById("ytPlayPause");
    muteBtn = document.getElementById("ytMute");
    volumeSlider = document.getElementById("ytVolume");
    seekSlider = document.getElementById("ytSeek");
    currentTimeEl = document.getElementById("ytCurrentTime");
    durationEl = document.getElementById("ytDuration");
    qualitySelect = document.getElementById("ytQuality");
    minimizeBtn = document.getElementById("ytMinimize");
    closeBtn = document.getElementById("ytClose");
    playPauseBtn?.addEventListener("click", togglePlayPause);
    muteBtn?.addEventListener("click", toggleMute);
    volumeSlider?.addEventListener("input", handleVolumeChange);
    seekSlider?.addEventListener("input", handleSeek);
    seekSlider?.addEventListener("change", handleSeek);
    qualitySelect?.addEventListener("change", applyQuality);
    minimizeBtn?.addEventListener("click", cycleState);
    closeBtn?.addEventListener("click", close);
    applyState("expanded");

    // restore saved player size (or default)
    try{
      let saved = localStorage.getItem(YT_SIZE_STORAGE_KEY);
      if(!saved || !YT_SIZE_LEVELS.includes(saved)) saved = YT_SIZE_DEFAULT;
      applyPlayerSize(saved, { persist:false });
    }catch{
      applyPlayerSize(YT_SIZE_DEFAULT, { persist:false });
    }
  }


  function applyPlayerSize(size, opts={}){
    if(!container) return;
    const s = String(size||"").toLowerCase();
    if(!YT_SIZE_LEVELS.includes(s)) return;
    Object.values(YT_SIZE_CLASS).forEach(cls => container.classList.remove(cls));
    const cls = YT_SIZE_CLASS[s];
    if(cls) container.classList.add(cls);

    const h = YT_SIZE_HEIGHT[s] || YT_SIZE_HEIGHT[YT_SIZE_DEFAULT];
    try{
      const holder = document.querySelector("#ytSticky .ytPlayerHolder");
      if(holder){ holder.style.minHeight = h + "px"; holder.style.height = h + "px"; }
      if(playerHolder){ playerHolder.style.minHeight = h + "px"; playerHolder.style.height = h + "px"; }
      if(player && typeof player.setSize === "function"){
        const w = Math.max(240, Math.floor((playerHolder?.getBoundingClientRect().width || holder?.getBoundingClientRect().width || 0)));
        if(w) player.setSize(w, h);
      }
    }catch{}

    if(opts.persist !== false){
      try{ localStorage.setItem(YT_SIZE_STORAGE_KEY, s); }catch{}
    }
  }
  function applyState(next){
    state = next || "expanded";
    if(!container) return;
    container.classList.remove("yt-expanded", "yt-compact", "yt-collapsed");
    container.classList.add(`yt-${state}`);
  }

  function ensurePlayer(){
    if(player) return Promise.resolve(player);
    return loadApi().then(()=>{
      player = new YT.Player(playerHolder, {
        height: "180",
        width: "320",
        host: "https://www.youtube-nocookie.com",
        playerVars: { playsinline:1, controls:0, modestbranding:1, rel:0, autoplay:0, enablejsapi:1, origin: window.location.origin },
        events: {
          onReady: handleReady,
          onStateChange: handleStateChange,
          onPlaybackQualityChange: refreshQualityOptions,
          onError: handleError,
        }
      });
      return player;
    });
  }

  function handleReady(){
    updateVolumeUi(player.getVolume?.());
    refreshQualityOptions();
    try{
      const saved = localStorage.getItem(YT_SIZE_STORAGE_KEY) || YT_SIZE_DEFAULT;
      if(YT_SIZE_LEVELS.includes(saved)) applyPlayerSize(saved, { persist:false });
    }catch{}
  }
  function handleStateChange(e){
    const state = e.data;
    if(state === YT.PlayerState.PLAYING){
      startProgress();
    }else{
      stopProgress();
      updateProgress();
    }
    updatePlayPauseUi();
  }


  // YouTube sometimes surfaces a generic "An error occurred. Please try again later."
  // on the first attempted load/play. We do a single lightweight retry to avoid
  // showing the error to users.
  let lastLoadId = null;
  let didRetryForId = Object.create(null);

  function handleError(e){
    try{
      const code = e?.data;
      const vid = lastLoadId || currentVideoId;
      if(!vid) return;

      // Retry only once per video id per session.
      if(didRetryForId[vid]) return;
      didRetryForId[vid] = true;

      // Small delay to let the iframe settle, then re-cue and play (if requested).
      setTimeout(()=>{
        if(!player || currentVideoId !== vid) return;
        try{
          // Re-cue then play. Using cue first tends to be more reliable than a direct load+play.
          player.cueVideoById?.(vid);
          if(pendingAutoplay){
            // playVideo requires a user gesture in some environments; this is typically
            // invoked from a click on the preview card.
            player.playVideo?.();
          }
        }catch(err){
          console.warn("[YouTube] retry failed", err, code);
        }
      }, 250);
    }catch(err){
      console.warn("[YouTube] onError handler failed", err);
    }
  }

  function startProgress(){
    stopProgress();
    progressTimer = setInterval(updateProgress, 300);
  }
  function stopProgress(){
    if(progressTimer){
      clearInterval(progressTimer);
      progressTimer = null;
    }
  }
  function updateProgress(){
    if(!player || !seekSlider) return;
    const dur = Math.max(0, Number(player.getDuration?.() || 0));
    const pos = Math.max(0, Number(player.getCurrentTime?.() || 0));
    seekSlider.max = dur || 0;
    seekSlider.value = pos;
    currentTimeEl.textContent = formatTimeShort(pos);
    durationEl.textContent = dur ? formatTimeShort(dur) : "--:--";
  }
  function updatePlayPauseUi(){
    if(!player || !playPauseBtn) return;
    const state = player.getPlayerState?.();
    const isPlaying = state === YT.PlayerState.PLAYING || state === YT.PlayerState.BUFFERING;
    playPauseBtn.textContent = isPlaying ? "❚❚" : "▶";
    playPauseBtn.setAttribute("aria-label", isPlaying ? "Pause" : "Play");
  }
  function updateVolumeUi(vol){
    if(!volumeSlider || typeof vol !== "number") return;
    volumeSlider.value = vol;
    muteBtn.textContent = player?.isMuted?.() ? "🔇" : "🔊";
  }
  function handleVolumeChange(){
    if(!player) return;
    const v = Number(volumeSlider.value);
    player.setVolume?.(v);
    if(player.isMuted?.() && v > 0) player.unMute?.();
    updateVolumeUi(v);
  }
  function handleSeek(){
    if(!player) return;
    const t = Number(seekSlider.value || 0);
    player.seekTo?.(t, true);
    updateProgress();
  }
  function togglePlayPause(){
    if(!player) return;
    const state = player.getPlayerState?.();
    if(state === YT.PlayerState.PLAYING || state === YT.PlayerState.BUFFERING){
      player.pauseVideo?.();
    }else{
      player.playVideo?.();
    }
  }
  function toggleMute(){
    if(!player) return;
    if(player.isMuted?.()) player.unMute(); else player.mute();
    updateVolumeUi(player.getVolume?.());
  }
  function applyQuality(){
    if(!qualitySelect) return;
    const vRaw = String(qualitySelect.value || "").trim();
    if(!vRaw) return;
    const v = vRaw.toLowerCase();

    // Size controls (LARGE/MEDIUM/SMALL/TINY)
    if(YT_SIZE_LEVELS.includes(v)){
      applyPlayerSize(v, { persist:true });
      return;
    }

    if(!player || !currentVideoId) return;

    // "default" in our UI means Auto.
    const q = (v === "default") ? "auto" : v;

    try{
      if(q === "auto"){
        // Let YouTube adapt.
        player.setPlaybackQuality?.("default");
        return;
      }

      const pos = Math.max(0, Number(player.getCurrentTime?.() || 0));
      const st = Number(player.getPlayerState?.() || 0);
      const wasPlaying = (st === window.YT?.PlayerState?.PLAYING || st === window.YT?.PlayerState?.BUFFERING);

      // Best-effort: setPlaybackQuality + cue at current position with suggestedQuality.
      player.setPlaybackQuality?.(q);
      player.cueVideoById?.({ videoId: currentVideoId, startSeconds: pos, suggestedQuality: q });
      if(wasPlaying){
        // Small delay gives the cue time to apply.
        setTimeout(()=>{ try{ player.playVideo?.(); }catch{} }, 0);
      }
    }catch(err){
      console.warn("[YouTube] applyQuality failed", err);
    }
  }
  function refreshQualityOptions(){
    if(!player || !qualitySelect) return;
    const levelsRaw = (player.getAvailableQualityLevels?.() || []).filter(Boolean);
    const currentQ = String(player.getPlaybackQuality?.() || "").toLowerCase();

    const qualityLevels = [];
    const sizeLevels = [];
    levelsRaw.forEach(lvl => {
      const v = String(lvl).toLowerCase();
      if(!v) return;
      if(YT_SIZE_LEVELS.includes(v)) sizeLevels.push(v);
      else qualityLevels.push(v);
    });

    // Keep common qualities in a nice order when available.
    const prefOrder = ["highres","hd2160","hd1440","hd1080","hd720","large","medium","small","tiny"];
    const uniqQ = Array.from(new Set(["default", ...qualityLevels]));
    uniqQ.sort((a,b)=>{
      const ia = prefOrder.indexOf(a);
      const ib = prefOrder.indexOf(b);
      if(ia === -1 && ib === -1) return a.localeCompare(b);
      if(ia === -1) return 1;
      if(ib === -1) return -1;
      return ia - ib;
    });

    const sizeSaved = (()=>{ try{ return localStorage.getItem(YT_SIZE_STORAGE_KEY) || ""; }catch{ return ""; } })();

    qualitySelect.innerHTML = "";

    const ogQ = document.createElement("optgroup");
    ogQ.label = "Quality";
    uniqQ.forEach(lvl => {
      const opt = document.createElement("option");
      opt.value = lvl;
      opt.textContent = (lvl === "default") ? "Auto" : lvl.toUpperCase();
      if((lvl === "default" && (!currentQ || currentQ === "default" || currentQ === "auto")) || lvl === currentQ){
        opt.selected = true;
      }
      ogQ.appendChild(opt);
    });
    qualitySelect.appendChild(ogQ);

    const ogS = document.createElement("optgroup");
    ogS.label = "Player size";
    // Use our canonical order for size options
    YT_SIZE_LEVELS.forEach(sz => {
      const opt = document.createElement("option");
      opt.value = sz;
      opt.textContent = sz.toUpperCase();
      if(sizeSaved && sizeSaved.toLowerCase() === sz) opt.selected = true;
      ogS.appendChild(opt);
    });
    qualitySelect.appendChild(ogS);
  }

  function setMeta(meta){
    if(!meta) return;
    if(titleEl) titleEl.textContent = meta.title || "YouTube video";
    if(channelEl) channelEl.textContent = meta.channel || "YouTube";
    if(thumbEl) thumbEl.style.backgroundImage = meta.thumbnail ? `url(${meta.thumbnail})` : "";
  }

  function reveal(expanded=true){
    if(!container) return;
    container.classList.remove("is-hidden");
    applyState(expanded ? "expanded" : state);
  }
  function cycleState(){
    if(!container) return;
    const order = ["expanded", "compact", "collapsed"];
    const idx = Math.max(0, order.indexOf(state));
    const next = order[(idx + 1) % order.length];
    applyState(next);
  }
  function close(){
    stopProgress();
    if(player){
      try { player.stopVideo?.(); } catch{}
      try { player.destroy?.(); } catch{}
    }
    player = null;
    currentVideoId = null;
    if(container){
      container.classList.add("is-hidden");
      applyState("expanded");
    }
    if(titleEl) titleEl.textContent = "YouTube player";
    if(channelEl) channelEl.textContent = "";
    if(thumbEl) thumbEl.style.backgroundImage = "";
  }

  function loadVideo(videoId, meta={}, { autoplay=true }={}){
    if(!videoId) return;
    currentVideoId = videoId;
    pendingAutoplay = Boolean(autoplay);
    setMeta(meta);
    reveal(true);
    ensurePlayer().then(()=>{
      if(!player) return;
      lastLoadId = videoId;
      // allow a fresh single retry for this load
      if(didRetryForId[videoId]) delete didRetryForId[videoId];
      if(!pendingAutoplay){
        player.cueVideoById?.(videoId);
      }else{
        // Prefer cue + play; it tends to avoid the initial generic playback error
        // some users see on the very first click.
        player.cueVideoById?.(videoId);

        // Defer play until the cue has settled.
        setTimeout(()=>{
          if(!player || currentVideoId !== videoId) return;
          try{
            player.playVideo?.();
          }catch{
            try { player.mute?.(); player.playVideo?.(); } catch{}
          }
        }, 0);
      }
      updatePlayPauseUi();
      refreshQualityOptions();
      updateVolumeUi(player.getVolume?.());
      updateProgress();
    }).catch(err => console.error("[YouTube] failed to load api/player", err));
    fetchYouTubeMeta(videoId).then(remoteMeta => {
      if(remoteMeta && currentVideoId === videoId) setMeta(remoteMeta);
    });
  }

  initDom();

  return { loadVideo, close, minimize: cycleState };
})();

function buildYouTubePreview(videoId){
  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = "ytMiniCard";
  btn.innerHTML = `
    <div class="ytMiniThumb" aria-hidden="true"></div>
    <div class="ytMiniMeta">
      <div class="ytMiniTitle">YouTube video</div>
      <div class="ytMiniChannel">Tap to play</div>
    </div>
    <div class="ytMiniAction">▶ Play</div>
  `;
  const thumb = btn.querySelector(".ytMiniThumb");
  const titleEl = btn.querySelector(".ytMiniTitle");
  const channelEl = btn.querySelector(".ytMiniChannel");

  function applyMeta(meta){
    if(!meta) return;
    if(titleEl) titleEl.textContent = meta.title || "YouTube video";
    if(channelEl) channelEl.textContent = meta.channel || "YouTube";
    if(thumb) thumb.style.backgroundImage = meta.thumbnail ? `url(${meta.thumbnail})` : "";
  }

  btn.addEventListener("click", (e)=>{
    e.stopPropagation();
    const cached = YOUTUBE_META_CACHE.get(videoId) || {};
    StickyYouTubePlayer.loadVideo(videoId, cached, { autoplay:true });
  });

  const cachedMeta = YOUTUBE_META_CACHE.get(videoId);
  if(cachedMeta) applyMeta(cachedMeta);
  else fetchYouTubeMeta(videoId).then(meta => { if(meta) applyMeta(meta); });

  return btn;
}

function diceFace(val){ return DICE_FACES[val - 1] || val || ""; }
function fmtAbs(ts){
  if(!ts) return "—";
  const n = Number(ts);
  if(!Number.isFinite(n)) return "—";
  return new Date(n).toLocaleString();
}
function fmtCreated(ts){
  if(!ts) return "—";
  // Accept numeric strings and seconds timestamps.
  let raw = ts;
  if (typeof raw === "string") raw = raw.trim();
  const asNum = (typeof raw === "number") ? raw : Number(raw);
  if (Number.isFinite(asNum)) {
    const ms = asNum < 1e12 ? asNum * 1000 : asNum;
    const d = new Date(ms);
    if (!Number.isNaN(d.getTime())) return d.toLocaleString();
  }
  const d = new Date(raw);
  if(Number.isNaN(d.getTime())) return String(ts);
  return d.toLocaleString();
}
function formatMemberSince(value){
  if(value == null || value === "") return "—";
  let date = null;
  if(typeof value === "number"){
    const ms = value < 1e12 ? value * 1000 : value;
    date = new Date(ms);
  }else if(typeof value === "string"){
    const trimmed = value.trim();
    if(!trimmed) return "—";
    const asNum = Number(trimmed);
    if(Number.isFinite(asNum)){
      const ms = asNum < 1e12 ? asNum * 1000 : asNum;
      date = new Date(ms);
    }else{
      date = new Date(trimmed);
    }
  }else{
    date = new Date(NaN);
  }

  if(!date || Number.isNaN(date.getTime())) return "—";
  const dd = String(date.getDate()).padStart(2, "0");
  const mm = String(date.getMonth() + 1).padStart(2, "0");
  const yyyy = String(date.getFullYear());
  return `${dd}/${mm}/${yyyy}`;
}
function bytesToNice(n){
  n = Number(n||0);
  const units = ["B","KB","MB","GB"];
  let u = 0;
  while(n >= 1024 && u < units.length-1){ n /= 1024; u++; }
  return `${n.toFixed(u===0?0:1)} ${units[u]}`;
}
function previewText(text, max=180){
  const raw = String(text || "").trim();
  if(raw.length <= max) return raw;
  return `${raw.slice(0, max - 1)}…`;
}

const ROLES = ["Guest","User","VIP","Moderator","Admin","Co-owner","Owner"];

function normalizeRole(role){
  const raw = String(role||"").trim();
  if(!raw) return "User";
  const key = raw.toLowerCase();
  const map = {
    "guest":"Guest","user":"User","vip":"VIP","moderator":"Moderator","mod":"Moderator",
    "admin":"Admin","administrator":"Admin",
    "coowner":"Co-owner","co-owner":"Co-owner","co owner":"Co-owner","co-owner ":"Co-owner",
    "owner":"Owner"
  };
  return map[key] || (raw[0].toUpperCase()+raw.slice(1));
}


const THEME_BY_ID = new Map(THEME_LIST.map((theme) => [theme.id, theme]));
const THEME_BY_NAME = new Map(THEME_LIST.map((theme) => [theme.name, theme]));
const THEME_TAGS = Array.from(
  new Set(
    THEME_LIST.flatMap((theme) => theme.tags || [])
  )
).sort((a, b) => a.localeCompare(b, undefined, { sensitivity: "base" }));
function canApplyThemeForUser(theme, role, ownedIds = []){
  if (!theme) return false;
  if (theme.name === IRIS_LOLA_THEME) return isIrisLolaAllowed();
  const userRole = role || "User";
  if (theme.access === "vip" && roleRank(userRole) < roleRank("VIP")) return false;
  if (theme.access === "gold") {
    const owned = ownedIds.includes(theme.id);
    if (!owned && roleRank(userRole) < roleRank("VIP")) return false;
  }
  return true;
}
function canUseThemeName(themeName){
  const theme = THEME_BY_NAME.get(themeName);
  if (!theme) return false;
  const role = (typeof me !== "undefined" && me && me.role) ? me.role : "User";
  return canApplyThemeForUser(theme, role, themeOwnedIds);
}

function roleRank(role){ const norm = normalizeRole(role); const i = ROLES.findIndex(r=>r.toLowerCase()===String(norm).toLowerCase()); return i===-1?1:i; }


function getFeatureFlag(key, fallback=false){
  const v = featureFlags && Object.prototype.hasOwnProperty.call(featureFlags, key) ? featureFlags[key] : undefined;
  if (typeof v === "boolean") return v;
  if (typeof v === "number") return !!v;
  if (typeof v === "string") return v === "true" || v === "1" || v === "on";
  return fallback;
}

function parseFeatureAllowlist(value){
  if(!value) return new Set();
  if(Array.isArray(value)){
    return new Set(value.map((item)=>String(item).trim().toLowerCase()).filter(Boolean));
  }
  if(typeof value === "string"){
    return new Set(value.split(",").map((item)=>String(item).trim().toLowerCase()).filter(Boolean));
  }
  return new Set();
}

function isCouplesV2EnabledFor(user){
  if(!getFeatureFlag("COUPLES_V2_ENABLED", false)) return false;
  if(roleRank(user?.role || "User") >= roleRank("Owner")) return true;
  const allowlist = parseFeatureAllowlist(featureFlags?.COUPLES_V2_ALLOWLIST);
  if(!allowlist.size) return false;
  const username = String(user?.username || "").trim().toLowerCase();
  const userId = user?.id ?? user?.user_id ?? user?.userId;
  if(username && allowlist.has(username)) return true;
  if(userId != null && allowlist.has(String(userId).toLowerCase())) return true;
  return false;
}

function applyAmbientClasses(){
  const enabled = getFeatureFlag("ambientFx", true);
  const reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const on = !!enabled && !reduce;
  document.body.classList.toggle("ambientfx", on);
  document.body.classList.toggle("ambient-main", on && String(currentRoom)==="main");
  document.body.classList.toggle("ambient-diceroom", on && String(currentRoom)==="diceroom");
  document.body.classList.toggle("ambient-music", on && String(currentRoom)==="music");
  document.body.classList.toggle("ambient-nsfw", on && String(currentRoom)==="nsfw");
}

function applyAutoContrast(){
  const enabled = getFeatureFlag("autoContrast", true);
  document.body.classList.toggle("auto-contrast", !!enabled);
  try{
    if(typeof updateContrastReinforcementAll === "function"){
      updateContrastReinforcementAll();
    }
  }catch(_){}
}

function applyFeatureFlags(){
  applyAmbientClasses();
  applyAutoContrast();
}

const STATUS_ALIASES = {
  "Do Not Disturb": "DnD",
  "Listening to Music": "Music",
  "Looking to Chat": "Chatting",
  "Invisible": "Lurking",
};
let VIBE_TAG_DEFS = [];
let VIBE_TAG_OPTIONS = [];
let VIBE_TAG_LIMIT = 3;
const VIBE_TAG_LOOKUP = new Map();
function normalizeStatusLabel(status, fallback=""){
  const raw = String(status || "").trim();
  if(!raw) return fallback;
  return STATUS_ALIASES[raw] || raw;
}

function statusDotColor(status){
  const normalized = normalizeStatusLabel(status, "Online");
  switch(normalized){
    case "Online": return "var(--ok)";
    case "Away": return "var(--warn)";
    case "Busy": return "var(--danger)";
    case "DnD": return "var(--danger)";
    case "Idle": return "var(--gray)";
    case "Lurking": return "var(--gray)";
    default: return "var(--accent)";
  }
}

function updateVibeTagLimitText(){
  if(vibeTagLimitLabel) vibeTagLimitLabel.textContent = String(VIBE_TAG_LIMIT);
}

function setVibeTagDefs(payload){
  const defs = Array.isArray(payload?.vibes) ? payload.vibes : [];
  VIBE_TAG_DEFS = defs.filter((def) => def && def.label && def.emoji);
  VIBE_TAG_OPTIONS = VIBE_TAG_DEFS.map((def) => def.label);
  if (Number.isFinite(Number(payload?.limit))) {
    VIBE_TAG_LIMIT = Number(payload.limit);
  }
  VIBE_TAG_LOOKUP.clear();
  VIBE_TAG_DEFS.forEach((def) => {
    const label = String(def.label || "").trim();
    if (!label) return;
    const normalized = label.toLowerCase();
    VIBE_TAG_LOOKUP.set(normalized, { ...def, label });
    if (def.id) VIBE_TAG_LOOKUP.set(String(def.id).toLowerCase(), { ...def, label });
  });
  updateVibeTagLimitText();
}

async function loadVibeTags(){
  try{
    const res = await fetch("/api/vibes");
    if(!res.ok) return;
    const data = await res.json();
    setVibeTagDefs(data);
  }catch(err){
    console.warn("Failed to load vibe tags:", err);
  }
}

function getVibeDef(tag){
  const key = String(tag || "").trim().toLowerCase();
  if(!key) return null;
  return VIBE_TAG_LOOKUP.get(key) || null;
}

function formatVibeChipLabel(tag){
  const def = getVibeDef(tag);
  if(def?.emoji && def?.label) return `${def.emoji} ${def.label}`;
  return String(tag || "").trim();
}

function sanitizeVibeTagsClient(raw){
  const arr = Array.isArray(raw) ? raw : [];
  const out = [];
  const hasOptions = VIBE_TAG_OPTIONS.length > 0;
  arr.forEach((v) => {
    if (out.length >= VIBE_TAG_LIMIT) return;
    const val = String(v || "").trim();
    if (!val) return;
    if(hasOptions){
      const hit = VIBE_TAG_OPTIONS.find((opt) => opt.toLowerCase() === val.toLowerCase());
      if (hit && !out.includes(hit)) out.push(hit);
    } else if (!out.includes(val)) {
      out.push(val);
    }
  });
  return out;
}
function roleBadgeColor(role){
  switch(role){
    case "Owner": return "#f0b132";
    case "Co-owner": return "#e67e22";
    case "Admin": return "#ed4245";
    case "Moderator": return "#3498db";
    case "VIP": return "#9b59b6";
    case "Guest": return "#95a5a6";
    default: return "#bdc3c7";
  }
}
function roleIcon(role){
  switch(role){
    case "Owner": return "👑";
    case "Co-owner": return "⭐";
    case "Admin": return "🛡️";
    case "Moderator": return "🔧";
    case "VIP": return "💎";
    case "Guest": return "👥";
    default: return "👤";
  }
}
const PRESET_REASONS = [
  "Spam / Advertising",
  "Harassment / Bullying",
  "Off-topic",
  "NSFW content",
  "Impersonation",
  "Cheating / Exploits",
];
function populateReasonPresets(container, targetInput){
  if(!container || !targetInput) return;
  container.innerHTML = "";
  PRESET_REASONS.forEach(reason => {
    const btn=document.createElement("button");
    btn.type="button";
    btn.className="pillBtn";
    btn.textContent=reason;
    btn.addEventListener("click", () => {
      targetInput.value = reason;
      targetInput.focus();
    });
    container.appendChild(btn);
  });
}
populateReasonPresets(quickReasonPresets, quickReason);
populateReasonPresets(modReasonPresets, modReason);

function roleKey(role){
  const r = String(role || "").toLowerCase().replace(/[_\s]+/g, "-");
  if(r.includes("co") && r.includes("owner")) return "coowner";
  if(r.includes("owner")) return "owner";
  if(r.includes("admin")) return "admin";
  if(r.includes("mod")) return "moderator";
  if(r.includes("vip")) return "vip";
  if(r.includes("guest")) return "guest";
  return "member";
}

function toneMeta(toneKey){
  if (!toneKey) return null;
  return TONE_OPTIONS.find((tone) => tone.key === toneKey) || null;
}

function presenceFlags(username, explicitStatus){
  const key = normKey(username);
  const u = (lastUsers || []).find((user) => normKey(user?.name) === key || normKey(user?.username) === key);
  const status = normalizeStatusLabel(explicitStatus || u?.status || "Online", "Online");
  const isIdle = status === "Idle" || status === "Away" || status === "Lurking";
  const isDnd = status === "Busy" || status === "DnD";
  const isTyping = key && typingUsers.has(key);
  const isActiveDm = key && activeDmUsers.has(key);
  const isOnline = !isIdle && !isDnd;
  return { status, isIdle, isDnd, isTyping, isActiveDm, isOnline };
}

function resolvePresenceAuraTarget(el){
  if (!el) return null;
  if (el.classList?.contains("msgAvatar") || el.classList?.contains("dmAvatar") || el.classList?.contains("avatar") || el.classList?.contains("dmMetaAvatar")) {
    return el;
  }
  return el.closest?.(".msgAvatar, .dmAvatar, .avatar, .dmMetaAvatar") || el;
}

function applyPresenceAura(el, username, opts = {}){
  const target = resolvePresenceAuraTarget(el);
  if (!target || !target.classList) return;
  const key = normKey(username || opts.username || target.dataset.username || "");
  if (key) target.dataset.username = key;
  if (!isPolishAurasEnabled()) {
    target.classList.remove("presenceAura", "isTyping", "isActiveDm", "isIdle", "isOnline", "isDnd", "isVip");
    delete target.dataset.status;
    return;
  }
  const { status, isIdle, isTyping, isActiveDm, isDnd, isOnline } = presenceFlags(key, opts.status);
  target.classList.add("presenceAura");
  target.classList.toggle("isTyping", !!isTyping);
  target.classList.toggle("isActiveDm", !!isActiveDm);
  target.classList.toggle("isIdle", !!isIdle);
  target.classList.toggle("isDnd", !!isDnd);
  target.classList.toggle("isOnline", !!isOnline);
  if (status) target.dataset.status = status;
}

function applyAvatarMeta(el, user = {}){
  if (!el || !el.classList) return;
  const username = typeof user === "string" ? user : (user?.username || user?.name || "");
  const role = (typeof user === "object") ? (user?.role || user?.userRole || null) : null;
  const target = resolvePresenceAuraTarget(el);
  if (target && username) target.dataset.username = normKey(username);
  if (target) {
    const isVip = role && roleRank(role) >= roleRank("VIP");
    target.classList.toggle("isVip", !!isVip);
  }
  applyPresenceAura(target || el, username, { status: user?.status });
}

function setPresenceClass(username, status){
  const key = normKey(username || "");
  if (!key) return;
  const selector = `[data-username="${escapeSelectorValue(key)}"]`;
  document.querySelectorAll(selector).forEach((node) => applyPresenceAura(node, key, { status }));
}

function updatePresenceAuras(){
  document.querySelectorAll(".presenceAura, .msgAvatar, .dmAvatar, .avatar, .dmMetaAvatar").forEach((el)=>{
    const name = el.dataset.username || el.getAttribute("data-username") || el.getAttribute("alt") || "";
    applyPresenceAura(el, name);
  });
}

function typingPhraseFor(name){
  const key = normKey(name);
  const now = Date.now();
  const existing = typingPhraseCache.get(key);
  if (existing && now - existing.ts < 3500) return existing.text;
  const base = TYPING_PHRASES[Math.floor(Math.random()*TYPING_PHRASES.length)] || "{name} is typing…";
  const text = base.replace("{name}", name);
  typingPhraseCache.set(key, { text, ts: now });
  return text;
}

function avatarNode(url, fallbackText, role, presenceName){
  const rKey = roleKey(role);
  const pName = presenceName || fallbackText;

  const buildFallback = () => {
    const wrap=document.createElement("div");
    wrap.className = `avatarFallback role-${rKey}` + (rKey === "vip" ? " vipDiamond" : "");
    wrap.textContent=(fallbackText||"?").slice(0,1).toUpperCase();
    applyAvatarMeta(wrap, { username: pName, role });
    return wrap;
  };

  if(url){
    const img=document.createElement("img");
    img.className = "avatarImg";
    img.src=url;
    img.alt="avatar";
    img.loading="lazy";
    img.onerror = () => {
      img.replaceWith(buildFallback());
    };
    applyAvatarMeta(img, { username: pName, role });
    return img;
  }
  return buildFallback();
}

function updateRoleCache(username, role){
  const key = normKey(username);
  if (!key) return;
  roleCache.set(key, role || "User");
}
function cachedRoleForUser(username){
  const key = normKey(username);
  return roleCache.get(key) || roleForUser(username);
}

function roleForUser(name){
  const n = String(name || "").toLowerCase();
  if (!n) return "member";
  if (String(me?.username||"").toLowerCase() === n) return me?.role || "member";
  const hit = (lastUsers || []).find((u)=>String(u?.name||"").toLowerCase()===n);
  return hit?.role || "member";
}

function makeAvatarEl({ username, role, avatarUrl, size = 34 }) {
  // outer element
  const el = document.createElement("div");
  el.className = "avatar";
  el.style.width = `${size}px`;
  el.style.height = `${size}px`;

  // If we have a real avatar URL, use it as an <img> so it’s guaranteed to render as-is.
  if (avatarUrl) {
    const img = document.createElement("img");
    img.className = "avatarImg";
    img.src = avatarUrl;
    img.alt = username || "avatar";

    // If the image fails, fall back to gradient default
    img.onerror = () => {
      el.innerHTML = "";
      el.classList.add("avatarFallback", `role-${roleKey(role)}`);
      el.textContent = (username || "?").slice(0, 1).toUpperCase();
    };

    el.appendChild(img);
    applyAvatarMeta(el, { username, role });
    return el;
  }

  // No avatar URL -> default gradient fallback
  el.classList.add("avatarFallback", `role-${roleKey(role)}`);
  el.textContent = (username || "?").slice(0, 1).toUpperCase();
  applyAvatarMeta(el, { username, role });
  return el;
}

// Resolve role + avatar URL for a username from the latest presence list.
function getUserMeta(username){
  const name = String(username || "");
  const meName = String(me?.username || "");
  if (name && meName && name.toLowerCase() === meName.toLowerCase()) {
    return { role: me?.role || "member", avatarUrl: me?.avatar || me?.avatarUrl || null, username: meName, status: me?.status || "Online", vibe_tags: sanitizeVibeTagsClient(me?.vibe_tags) };
  }
  const u = (lastUsers || []).find(x => String((x.username||x.name||"")).toLowerCase() === name.toLowerCase());
  return { role: u?.role || "member", avatarUrl: u?.avatar || u?.avatarUrl || null, username: u?.username || u?.name || name, status: u?.status, vibe_tags: sanitizeVibeTagsClient(u?.vibe_tags) };
}

const IDENTITY_GLOW_PALETTE = [
  "#6c7af7",
  "#58a6ff",
  "#a855f7",
  "#ff7ad9",
  "#ffb347",
  "#5ee6c9"
];
const ROLE_GLOW_MAP = {
  "Owner": "#f6c358",
  "Co-owner": "#ff9f43",
  "Admin": "#ff6b6b",
  "Moderator": "#54a0ff",
  "VIP": "#b96bff",
  "Guest": "#8f9ca6",
  "User": "#6c7af7",
  "Member": "#6c7af7"
};
function clamp(num, min, max){ return Math.min(max, Math.max(min, num)); }
function hashString(input){
  const str = String(input || "");
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    hash = ((hash << 5) - hash) + str.charCodeAt(i);
    hash |= 0;
  }
  return Math.abs(hash);
}
function hexToRgb(hex){
  const raw = String(hex || "").replace("#", "");
  const normalized = raw.length === 3 ? raw.split("").map((c)=>c + c).join("") : raw;
  const int = Number.parseInt(normalized || "0", 16);
  return {
    r: (int >> 16) & 255,
    g: (int >> 8) & 255,
    b: int & 255
  };
}
function rgbToHex({ r, g, b }){
  const toHex = (v) => String(v.toString(16)).padStart(2, "0");
  return `#${toHex(clamp(Math.round(r), 0, 255))}${toHex(clamp(Math.round(g), 0, 255))}${toHex(clamp(Math.round(b), 0, 255))}`;
}
function rgbToHsl({ r, g, b }){
  const rn = r / 255;
  const gn = g / 255;
  const bn = b / 255;
  const max = Math.max(rn, gn, bn);
  const min = Math.min(rn, gn, bn);
  let h = 0;
  let s = 0;
  const l = (max + min) / 2;
  const d = max - min;
  if (d !== 0) {
    s = l > 0.5 ? d / (2 - max - min) : d / (max + min);
    switch (max) {
      case rn: h = (gn - bn) / d + (gn < bn ? 6 : 0); break;
      case gn: h = (bn - rn) / d + 2; break;
      default: h = (rn - gn) / d + 4; break;
    }
    h /= 6;
  }
  return { h, s, l };
}
function hslToRgb({ h, s, l }){
  if (s === 0) {
    const v = Math.round(l * 255);
    return { r: v, g: v, b: v };
  }
  const hue2rgb = (p, q, t) => {
    let tt = t;
    if (tt < 0) tt += 1;
    if (tt > 1) tt -= 1;
    if (tt < 1/6) return p + (q - p) * 6 * tt;
    if (tt < 1/2) return q;
    if (tt < 2/3) return p + (q - p) * (2/3 - tt) * 6;
    return p;
  };
  const q = l < 0.5 ? l * (1 + s) : l + s - l * s;
  const p = 2 * l - q;
  const r = hue2rgb(p, q, h + 1/3);
  const g = hue2rgb(p, q, h);
  const b = hue2rgb(p, q, h - 1/3);
  return { r: Math.round(r * 255), g: Math.round(g * 255), b: Math.round(b * 255) };
}
function mixRgb(a, b, ratio = 0.5){
  const r = a.r + (b.r - a.r) * ratio;
  const g = a.g + (b.g - a.g) * ratio;
  const bch = a.b + (b.b - a.b) * ratio;
  return { r, g, b: bch };
}
function getUserIdentityGlow(user){
  const username = safeString(user?.username || user?.name || "");
  const role = normalizeRole(user?.role || user?.userRole || "User");
  const baseHex = ROLE_GLOW_MAP[role] || null;
  const fallbackHex = IDENTITY_GLOW_PALETTE[hashString(username) % IDENTITY_GLOW_PALETTE.length] || "#6c7af7";
  const seedHex = baseHex || fallbackHex;
  let baseRgb = hexToRgb(seedHex);

  const vibes = sanitizeVibeTagsClient(user?.vibe_tags);
  if (vibes.length) {
    const vibeHash = hashString(vibes.join("|"));
    const hsl = rgbToHsl(baseRgb);
    const hueShift = ((vibeHash % 18) - 9) / 360;
    hsl.h = (hsl.h + hueShift + 1) % 1;
    hsl.s = clamp(hsl.s + Math.min(0.12, vibes.length * 0.03), 0.2, 0.9);
    hsl.l = clamp(hsl.l + 0.04, 0.24, 0.75);
    baseRgb = hslToRgb(hsl);
  }

  const partner = safeString(user?.couple?.partner || "");
  if (partner && partner.toLowerCase() !== username.toLowerCase()) {
    const partnerHex = IDENTITY_GLOW_PALETTE[hashString(partner) % IDENTITY_GLOW_PALETTE.length] || "#6c7af7";
    const partnerRgb = hexToRgb(partnerHex);
    baseRgb = mixRgb(baseRgb, partnerRgb, 0.35);
  }

  const colorHex = rgbToHex(baseRgb);
  return {
    color: colorHex,
    rgb: `${Math.round(baseRgb.r)} ${Math.round(baseRgb.g)} ${Math.round(baseRgb.b)}`
  };
}
function applyIdentityGlow(el, user){
  if (!el || !el.style) return;
  const glow = getUserIdentityGlow(user || {});
  if (!glow?.color) return;
  el.style.setProperty("--userGlow", glow.color);
  el.style.setProperty("--userGlowRgb", glow.rgb);
}

const MSG_IMPACT_LONG_THRESHOLD = 160;
function detectMessageImpactVariant(targetEl, rawText){
  if (!targetEl) return "";
  const hasMedia = !!targetEl.querySelector(".attachment, .msg-media-thumb, .ytMiniCard, iframe, video");
  if (hasMedia) return "media";
  const len = String(rawText || "").trim().length;
  if (len > MSG_IMPACT_LONG_THRESHOLD) return "long";
  return "";
}
function applyMessageImpactAnimation(el, { variant, isVip } = {}){
  if (!el || !el.classList || !isPolishAnimationsEnabled()) return;
  const classes = ["msgEnter"];
  if (variant) classes.push(`msgEnter--${variant}`);
  if (isVip) classes.push("msgEnter--vip");
  el.classList.remove("msgEnter", "msgEnter--long", "msgEnter--media", "msgEnter--vip");
  el.classList.add(...classes);
  const cleanup = () => {
    el.classList.remove(...classes);
  };
  el.addEventListener("animationend", cleanup, { once:true });
  setTimeout(cleanup, 800);
}


function clearMsgs(){
  msgs.innerHTML="";
  setTypingIndicator("");
  msgIndex.length=0;
  typingUsers = new Set();
  updatePresenceAuras();
  unseenMainMessages = 0;
  updateJumpToLatestButton();
}
function isDiceResultSystemMessage(text){
  if (!isDiceRoom(currentRoom)) return false;
  const raw = String(text || "");
  const hasRoll = /rolled/i.test(raw);
  const hasDiceHint = /[⚀⚁⚂⚃⚄⚅]|d6|d20|2d6|1–100|1-100|d100|🎲/i.test(raw);
  return hasRoll && hasDiceHint;
}

function addSystem(text, options = {}){
  const div=document.createElement("div");
  div.className="sys";
  if (options.className) div.classList.add(options.className);

  // Dice Room: make system messages larger, and make dice faces much more visible
  if(currentRoom === "diceroom"){
    const safe = escapeHtml(String(text ?? ""));
    // Wrap dice unicode faces so CSS can scale them independently
    const withFaces = safe.replace(/[⚀⚁⚂⚃⚄⚅]/g, (m)=>`<span class="diceFace">${m}</span>`);
    div.innerHTML = withFaces;
  }else{
    div.textContent = text;
  }

  msgs.appendChild(div);
  const shouldStick = isNearBottom(msgs, 160);
  stickToBottomIfWanted({ force: shouldStick });
  if(!shouldStick) noteUnseenMainMessage();
}

let commandPopupDismissed=false;
let selectedVibeTags = [];
function hideCommandPopup(){
  commandPopup.classList.remove("show");
}
function showCommandPopup(title, bodyHtml){
  commandPopupDismissed=false;
  commandPopupTitle.textContent=title;
  commandPopupBody.innerHTML=bodyHtml;
  commandPopup.classList.add("show");
}
commandPopupClose?.addEventListener("click", ()=>{ commandPopupDismissed=true; hideCommandPopup(); });

function handleCommandResponse(payload){
  if(commandPopupDismissed) commandPopupDismissed=false;
  if(payload.type === "help" && Array.isArray(payload.commands)){
    const roleLabel = payload.role || me?.role || "";
    const items = payload.commands.map(cmd=>{
      return `<div class="commandHelpItem"><div class="name">/${escapeHtml(cmd.name)}</div><div class="small">${escapeHtml(cmd.description||"")}</div><div class="usage">${escapeHtml(cmd.usage||"")}</div><div class="small">Example: ${escapeHtml(cmd.example||"")}</div></div>`;
    }).join("");
    showCommandPopup(`Commands you can use (Role: ${roleLabel})`, `<div class="commandHelpList">${items}</div>`);
    return;
  }
  const msg = escapeHtml(payload?.message || "No response");
  const title = payload?.ok ? "Command" : "Command error";
  showCommandPopup(title, msg);
}

function escapeRegex(str){
  return String(str || "").replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
function applyMentions(text, { linkifyText = false } = {}){
  const safe = escapeHtml(text);
  const names = new Set((lastUsers || []).map((u) => u.username || u.name));
  if (me?.username) names.add(me.username);
  const list = Array.from(names).filter(Boolean);
  let output = safe;
  if (list.length) {
    const pattern = list.map(escapeRegex).join("|");
    const re = new RegExp(`@(${pattern})(?=$|[^\\S]|[.,!?:;])`, "gi");
    output = safe.replace(re, (m)=>`<span class="mention">${m}</span>`);
  }
  return linkifyText ? linkify(output) : output;
}
function hasMention(text, username){
  const name = String(username || "").trim();
  if (!name) return false;
  const pattern = new RegExp(`(^|[^\\w])@${escapeRegex(name)}(?=$|[^\\w])`, "i");
  return pattern.test(String(text || ""));
}

const MESSAGE_HIGHLIGHT_MS = PREFERS_REDUCED_MOTION ? 1 : 1400;
function focusMainMessage(messageId){
  if (!messageId) return false;
  const target = document.querySelector(`.msgItem[data-mid="${escapeSelectorValue(messageId)}"]`);
  if (!target) return false;
  target.scrollIntoView({ behavior: "smooth", block: "center" });
  target.classList.remove("msg-mention-hit");
  void target.offsetWidth;
  target.classList.add("msg-mention-hit");
  setTimeout(() => target.classList.remove("msg-mention-hit"), MESSAGE_HIGHLIGHT_MS);
  return true;
}
function isNearBottom(el, threshold = 120){
  if(!el) return true;
  return el.scrollHeight - el.scrollTop - el.clientHeight <= threshold;
}
function scrollToBottom(el, behavior = "auto"){
  if(!el) return;
  try{
    el.scrollTo({ top: el.scrollHeight, behavior });
  }catch{
    el.scrollTop = el.scrollHeight;
  }
}
function handleChatScroll(){
  chatPinned = isNearBottom(msgs, 160);
  if(chatPinned) unseenMainMessages = 0;
  updateJumpToLatestButton();
}
function updateJumpToLatestButton(){
  if(!jumpToLatestBtn) return;
  const show = !chatPinned;
  const count = unseenMainMessages > 0 ? ` (${unseenMainMessages})` : "";
  jumpToLatestBtn.classList.toggle("show", show);
  jumpToLatestBtn.textContent = `Jump to latest${count}`;
}
function noteUnseenMainMessage(){
  if(chatPinned) return;
  unseenMainMessages = Math.min(unseenMainMessages + 1, 999);
  updateJumpToLatestButton();
}
function stickToBottomIfWanted(opts = {}){
  if(!msgs) return;
  const { force = false, behavior = "auto", threshold = 160 } = opts;
  const shouldStick = force || isNearBottom(msgs, threshold);
  if(!shouldStick) return;
  scrollToBottom(msgs, behavior);
  chatPinned = true;
  unseenMainMessages = 0;
  updateJumpToLatestButton();
}
// queueStickToBottom is declared near the top of the file (hoisted) to avoid TDZ errors.
function mentionCandidates(){
  const names = new Set((lastUsers || []).map((u) => u.username || u.name));
  if (me?.username) names.add(me.username);
  return Array.from(names).filter(Boolean);
}
function findMentionTrigger(value, cursor){
  const before = value.slice(0, cursor);
  const at = before.lastIndexOf("@");
  if (at === -1) return null;
  if (at > 0 && /\S/.test(before[at - 1])) return null;
  const query = before.slice(at + 1);
  if (query.includes("@") || query.includes("\n")) return null;
  return { start: at, query };
}
function renderMentionDropdown(dropdown, inputEl){
  if (!dropdown || !inputEl) return;
  const cursor = inputEl.selectionStart ?? inputEl.value.length;
  const trigger = findMentionTrigger(inputEl.value, cursor);
  if (!trigger) {
    dropdown.classList.remove("show");
    dropdown.innerHTML = "";
    return;
  }
  const term = trigger.query.toLowerCase();
  const matches = mentionCandidates()
    .filter((n) => !term || n.toLowerCase().includes(term))
    .slice(0, 6);
  if (!matches.length) {
    dropdown.classList.remove("show");
    dropdown.innerHTML = "";
    return;
  }

  dropdown.innerHTML = matches
    .map((name) => `<button type="button" data-name="${escapeHtml(name)}">@${escapeHtml(name)}</button>`)
    .join("");
  dropdown.dataset.start = String(trigger.start);
  dropdown.dataset.inputId = inputEl.id || "";
  dropdown.classList.add("show");
}
function acceptMention(dropdown, name){
  if (!dropdown) return;
  const inputId = dropdown.dataset.inputId;
  const start = Number(dropdown.dataset.start);
  if (!inputId || Number.isNaN(start)) return;
  const inputEl = document.getElementById(inputId);
  if (!inputEl) return;
  const value = inputEl.value;
  const before = value.slice(0, start);
  const after = value.slice(inputEl.selectionEnd ?? value.length);
  const insertion = `@${name} `;
  inputEl.value = before + insertion + after;
  const pos = before.length + insertion.length;
  inputEl.focus();
  inputEl.setSelectionRange(pos, pos);
  dropdown.classList.remove("show");
}

// BBCode render (escape HTML then whitelist a subset)
function renderBBCode(input){
  let s = escapeHtml(input || "");
  s = s.replace(/\r?\n/g, "<br>");
  s = s.replace(/\[b\](.*?)\[\/b\]/gi, "<b>$1</b>");
  s = s.replace(/\[i\](.*?)\[\/i\]/gi, "<i>$1</i>");
  s = s.replace(/\[u\](.*?)\[\/u\]/gi, "<u>$1</u>");
  s = s.replace(/\[s\](.*?)\[\/s\]/gi, "<s>$1</s>");
  s = s.replace(/\[quote\](.*?)\[\/quote\]/gis, "<blockquote>$1</blockquote>");
  s = s.replace(/\[code\](.*?)\[\/code\]/gis, "<pre><code>$1</code></pre>");
  s = s.replace(/\[color=([#a-z0-9]+)\](.*?)\[\/color\]/gi, (m,c,body)=>{
    const ok = /^#[0-9a-f]{3,8}$/i.test(c) || /^[a-z]{3,20}$/i.test(c);
    return ok ? `<span style="color:${c}">${body}</span>` : body;
  });
  s = s.replace(/\[url=([^\]]+)\](.*?)\[\/url\]/gi, (m,url,body)=>{
    url = String(url||"").trim();
    if(!/^https?:\/\//i.test(url)) return body;
    return `<a href="${escapeHtml(url)}" target="_blank" rel="noreferrer noopener">${body}</a>`;
  });
  s = s.replace(/\[img\](.*?)\[\/img\]/gi, (m,url)=>{
    url = String(url||"").trim();
  const ok = /^https?:\/\//i.test(url) || /^\/(uploads|avatars|avatar)\//i.test(url);
    if(!ok) return "";
    return `<img src="${escapeHtml(url)}" alt="img" style="max-width:100%; border-radius:14px; border:1px solid rgba(0,0,0,.2);">`;
  });
  return s;
}
function loadBadgePrefsFromStorage(){
  try{
    const raw = localStorage.getItem("dmBadgePrefs");
    const parsed = raw ? JSON.parse(raw) : {};
    return { ...badgeDefaults, ...parsed };
  }catch{
    return { ...badgeDefaults };
  }
}
const HEX_COLOR_RE = /^#([0-9a-f]{3}|[0-9a-f]{4}|[0-9a-f]{6}|[0-9a-f]{8})$/i;
const PROFILE_GRADIENT_DEFAULT_A = "#ff6a2b";
const PROFILE_GRADIENT_DEFAULT_B = "#2b0f08";
const prefersReducedMotion = window.matchMedia ? window.matchMedia("(prefers-reduced-motion: reduce)") : { matches: false };
let headerGradientPreviewFrame = 0;
let headerGradientPreviewNext = null;
let currentProfileHeaderRole = "";
function saveBadgePrefsToStorage(){
  try{ localStorage.setItem("dmBadgePrefs", JSON.stringify(badgePrefs)); }
  catch{}
}
function isValidCssColor(color){
  const c = String(color || "").trim();
  if(!c) return false;
  const s = new Option().style;
  s.color = c;
  return s.color !== "";
}
function normalizeColorForInput(color, fallback){
  if(HEX_COLOR_RE.test(color || "")) return color;
  if(HEX_COLOR_RE.test(fallback || "")) return fallback;
  return "#000000";
}
function sanitizeHexColorInput(raw, fallback=""){
  const c = String(raw || "").trim();
  if(HEX_COLOR_RE.test(c)) return c;
  if(HEX_COLOR_RE.test(fallback || "")) return fallback;
  return "";
}
function sanitizeColor(raw, fallback, hardDefault){
  if(isValidCssColor(raw)) return raw.trim();
  if(isValidCssColor(fallback)) return fallback.trim();
  if(isValidCssColor(hardDefault)) return hardDefault.trim();
  return hardDefault || badgeDefaults.direct;
}
function hexToRgb(hex){
  const m = /^#?([0-9a-fA-F]{6})$/.exec((hex || "").trim());
  if(!m) return null;
  const intVal = parseInt(m[1], 16);
  return {
    r: (intVal >> 16) & 255,
    g: (intVal >> 8) & 255,
    b: intVal & 255
  };
}
function relativeLuminance({ r, g, b }){
  const toLinear = (c) => {
    const channel = c / 255;
    return channel <= 0.03928 ? channel / 12.92 : Math.pow((channel + 0.055) / 1.055, 2.4);
  };
  return 0.2126 * toLinear(r) + 0.7152 * toLinear(g) + 0.0722 * toLinear(b);
}
function computeProfileTextTheme(colorA, colorB){
  const a = hexToRgb(colorA) || hexToRgb(PROFILE_GRADIENT_DEFAULT_A) || { r: 255, g: 106, b: 43 };
  const b = hexToRgb(colorB) || hexToRgb(PROFILE_GRADIENT_DEFAULT_B) || { r: 43, g: 15, b: 8 };
  const avgLum = (relativeLuminance(a) + relativeLuminance(b)) / 2;
  const lightText = avgLum < 0.55;
  return lightText ? {
    text: "#fdfdfd",
    shadow: "0 1px 4px rgba(0,0,0,0.65)",
    pillBg: "rgba(0,0,0,0.32)",
    pillBorder: "rgba(255,255,255,0.22)"
  } : {
    text: "#0d1b24",
    shadow: "0 1px 3px rgba(255,255,255,0.35)",
    pillBg: "rgba(255,255,255,0.24)",
    pillBorder: "rgba(0,0,0,0.18)"
  };
}
function buildProfileHeaderGradient(colorA, colorB){
  const a = sanitizeHexColorInput(colorA, PROFILE_GRADIENT_DEFAULT_A) || PROFILE_GRADIENT_DEFAULT_A;
  const b = sanitizeHexColorInput(colorB, PROFILE_GRADIENT_DEFAULT_B) || PROFILE_GRADIENT_DEFAULT_B;
  const rgb = hexToRgb(a);
  const highlight = rgb ? `radial-gradient(900px 260px at 70% 30%, rgba(${rgb.r},${rgb.g},${rgb.b},0.28), transparent 60%)` : "";
  const layers = [highlight, `linear-gradient(135deg, ${a}, ${b})`].filter(Boolean);
  return layers.join(", ");
}
function applyProfileHeaderOverlay(role){
  if(!profileSheetOverlay) return;
  const r = (role || "").toLowerCase();
  const overlayClass = r.includes("owner") ? (r.includes("co") ? "co-owner" : "owner")
    : r.includes("admin") ? "admin"
    : r.includes("mod") ? "moderator"
    : r.includes("vip") ? "vip"
    : r.includes("member") ? "member"
    : r.includes("guest") ? "guest" : "";

  profileSheetOverlay.className = "profileSheetOverlay";
  if(overlayClass) profileSheetOverlay.classList.add(`role-${overlayClass}`);
}
function applyProfileHeaderGradient(colorA, colorB, role){
  if(!profileSheetBg && !profileSheetHero) return;
  const a = sanitizeHexColorInput(colorA, PROFILE_GRADIENT_DEFAULT_A) || PROFILE_GRADIENT_DEFAULT_A;
  const b = sanitizeHexColorInput(colorB, PROFILE_GRADIENT_DEFAULT_B) || PROFILE_GRADIENT_DEFAULT_B;
  const gradient = buildProfileHeaderGradient(a, b);
  if(profileSheetBg){
    profileSheetBg.style.background = gradient;
    profileSheetBg.style.backgroundRepeat = "no-repeat";
    profileSheetBg.style.backgroundSize = "cover";
    profileSheetBg.style.setProperty("--profileHeaderBg", gradient);
  }
  if(profileSheetHero){
    const theme = computeProfileTextTheme(a, b);
    profileSheetHero.style.setProperty("--profileHeaderText", theme.text);
    profileSheetHero.style.setProperty("--profileHeaderTextShadow", theme.shadow);
    profileSheetHero.style.setProperty("--profileHeaderPillBg", theme.pillBg);
    profileSheetHero.style.setProperty("--profileHeaderPillBorder", theme.pillBorder);
  }
  applyProfileHeaderOverlay(role || currentProfileHeaderRole);
}
function loadDmNeonColorFromStorage(){
  try {
    const raw = localStorage.getItem("dmNeonColor");
    if (raw) return raw;
  } catch {}

  // One-time migration from legacy DM background preference.
  try {
    const legacyRaw = localStorage.getItem("dmThemePrefs");
    const parsed = safeJsonParse(legacyRaw, {});
    const legacyColor = parsed?.background;
    if (legacyColor) {
      localStorage.setItem("dmNeonColor", legacyColor);
      localStorage.removeItem("dmThemePrefs");
      return legacyColor;
    }
  } catch {}

  return dmNeonDefaults.color;
}
function saveDmNeonColorToStorage(){
  try { localStorage.setItem("dmNeonColor", dmNeonColor); }
  catch{}
  queuePersistPrefs({ dmNeonColor });
}
function applyDmNeonPrefs(){
  const color = sanitizeColor(dmNeonColor, dmNeonDefaults.color, dmNeonDefaults.color);
  dmNeonColor = color;
  document.documentElement.style.setProperty("--dm-neon", color);
  if(dmNeonColorInput) dmNeonColorInput.value = normalizeColorForInput(color, dmNeonDefaults.color);
  if(dmNeonColorText) dmNeonColorText.value = color;
}

function sanitizeThemeName(name){
  const match = THEME_LIST.find((t) => t.name === name);
  return match ? match.name : DEFAULT_THEME;
}
function getStoredTheme(){
  try{ return localStorage.getItem("theme") || ""; }
  catch{ return ""; }
}
function setStoredTheme(theme){
  try{ localStorage.setItem("theme", theme); }
  catch{}
}
async function fetchThemePreference(){
  if(!me) return null;
  try{
    const res = await fetch("/api/me/theme");
    if(!res.ok) return null;
    const data = await res.json();
    return data?.theme || null;
  }catch{
    return null;
  }
}
async function persistThemePreference(theme){
  if(!me) return;
  try{
    const res = await fetch("/api/me/theme", {
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({ theme })
    });
    if(res.ok){
      const data = await res.json();
      if(data?.theme) me.theme = data.theme;
    }
  }catch{}
}


// ---- Server-persisted user prefs (badge colors, DM theme, etc.)
async function persistUserPrefs(prefs){
  if(!me) return null;
  try{
    const res = await fetch("/api/me/prefs", {
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({ prefs })
    });
    if(!res.ok) return null;
    const data = await res.json().catch(()=>null);
    return data?.prefs || null;
  }catch{
    return null;
  }
}

let prefsSaveTimer = null;
let prefsPending = {};
function queuePersistPrefs(partial){
  if(!partial || typeof partial !== "object") return;
  prefsPending = { ...prefsPending, ...partial };
  if(prefsSaveTimer) clearTimeout(prefsSaveTimer);
  prefsSaveTimer = setTimeout(async () => {
    const payload = prefsPending;
    prefsPending = {};
    prefsSaveTimer = null;
    await persistUserPrefs(payload);
  }, 800);
}

const COMFORT_MODE_KEY = "comfortMode";
function readComfortModeStorage(){
  const raw = localStorage.getItem(COMFORT_MODE_KEY);
  if (raw === "1") return true;
  if (raw === "0") return false;
  return null;
}
function applyComfortMode(enabled, { persistLocal = true, persistServer = true } = {}){
  const on = !!enabled;
  document.body?.classList.toggle("comfortMode", on);
  if (prefComfortMode) prefComfortMode.checked = on;
  if (persistLocal) {
    try { localStorage.setItem(COMFORT_MODE_KEY, on ? "1" : "0"); } catch {}
  }
  if (persistServer) queuePersistPrefs({ comfortMode: on });
  if (prefComfortHelp) {
    prefComfortHelp.textContent = on
      ? "Comfort mode is on: animations and glows are softened."
      : "Softens glows, confetti, and motion-heavy animations.";
  }
}

function mergeChatFxDefaults(fx){
  const safe = (fx && typeof fx === "object") ? fx : {};
  const merged = { ...CHAT_FX_DEFAULTS, ...safe };
  if (safe.enabled === false) merged.enabled = false;
  return normalizeChatFx(merged);
}

function isPolishPackEnabled(){
  const body = document.body;
  if (body) return body.classList.contains("polish-pack");
  return chatFxPrefs?.polishPack !== false;
}

function isPolishAurasEnabled(){
  const body = document.body;
  if (body) return body.classList.contains("polish-auras");
  return isPolishPackEnabled() && chatFxPrefs?.polishAuras !== false;
}

function isPolishAnimationsEnabled(){
  const body = document.body;
  if (body) return body.classList.contains("polish-animations");
  return isPolishPackEnabled() && chatFxPrefs?.polishAnimations !== false && !PREFERS_REDUCED_MOTION;
}

function updatePolishPackClasses(fx = chatFxPrefs){
  const body = document.body;
  if (!body) return;
  const normalized = normalizeChatFx(fx);
  const pack = normalized.polishPack !== false;
  const auras = pack && normalized.polishAuras !== false;
  const anim = pack && normalized.polishAnimations !== false && !PREFERS_REDUCED_MOTION;
  body.classList.toggle("polish-pack", pack);
  body.classList.toggle("polish-auras", auras);
  body.classList.toggle("polish-animations", anim);

  if (!auras) {
    document.querySelectorAll(".presenceAura").forEach((el) => {
      el.classList.remove("presenceAura", "isTyping", "isActiveDm", "isIdle", "isOnline", "isDnd", "isVip");
      delete el.dataset.status;
    });
  } else {
    updatePresenceAuras();
  }

  updateContrastReinforcementAll();
}

function applyChatFxPrefsFromServer(fx){
  chatFxPrefs = mergeChatFxDefaults(fx);
  chatFxPrefsLoaded = true;
  if (me?.username){
    me.chatFx = { ...chatFxPrefs };
    updateUserFxMap(me.username, chatFxPrefs);
  }
  if (chatFxPrefEls){
    syncChatFxControls(chatFxPrefs);
    updateChatFxPreview(chatFxPrefs);
    chatFxDraft = { ...chatFxPrefs };
  }
  updatePolishPackClasses();
}

async function loadChatFxPrefs({ force = false } = {}){
  if (!me) return;
  if (chatFxPrefsLoading) return;
  if (chatFxPrefsLoaded && !force){
    if (chatFxPrefEls){
      syncChatFxControls(chatFxPrefs);
      updateChatFxPreview(chatFxPrefs);
      chatFxDraft = { ...chatFxPrefs };
    }
    return;
  }
  chatFxPrefsLoading = true;
  try{
    const res = await fetch("/api/me/prefs");
    if(!res.ok) return;
    const data = await res.json();
    const prefs = data?.prefs || {};
    applyChatFxPrefsFromServer(prefs.chatFx || {});
  }catch{
  }finally{
    chatFxPrefsLoading = false;
  }
}

async function loadUserPrefs(){
  try{
    const res = await fetch("/api/me/prefs");
    if(!res.ok) return;
    const data = await res.json();
    const prefs = data?.prefs || {};
    if(prefs.dmBadgePrefs && typeof prefs.dmBadgePrefs === "object"){
      badgePrefs = { ...badgeDefaults, ...prefs.dmBadgePrefs };
      applyBadgePrefs();
      saveBadgePrefsToStorage();
  queuePersistPrefs({ dmBadgePrefs: badgePrefs });
    }
    if (typeof prefs.dmNeonColor === "string") {
      dmNeonColor = prefs.dmNeonColor;
      applyDmNeonPrefs();
      saveDmNeonColorToStorage();
    } else if (prefs.dmThemePrefs && typeof prefs.dmThemePrefs === "object" && typeof prefs.dmThemePrefs.background === "string") {
      dmNeonColor = prefs.dmThemePrefs.background;
      applyDmNeonPrefs();
      saveDmNeonColorToStorage();
      queuePersistPrefs({ dmNeonColor });
    }
    if (Array.isArray(prefs.pinnedThemeIds)) {
      themePinnedIds = normalizeThemeIdList(prefs.pinnedThemeIds);
    }
    if (Array.isArray(prefs.favoriteThemeIds)) {
      themeFavoriteIds = normalizeThemeIdList(prefs.favoriteThemeIds);
    }
    if (Array.isArray(prefs.ownedThemeIds)) {
      themeOwnedIds = normalizeThemeIdList(prefs.ownedThemeIds);
    }
    if (prefs.sound && typeof prefs.sound === "object") {
      Sound.importPrefs(prefs.sound);
      syncSoundPrefsUI(false);
    }
    const comfortPref = typeof prefs.comfortMode === "boolean" ? prefs.comfortMode : null;
    const comfortStored = readComfortModeStorage();
    const comfortEnabled = comfortPref ?? comfortStored ?? false;
    applyComfortMode(comfortEnabled, { persistLocal: true, persistServer: false });
    if (comfortPref == null && comfortStored != null) {
      queuePersistPrefs({ comfortMode: comfortEnabled });
    }
    if (prefs.chatFx && typeof prefs.chatFx === "object") {
      applyChatFxPrefsFromServer(prefs.chatFx);
    } else {
      applyChatFxPrefsFromServer({});
    }
  }catch{}
}
function applyTheme(themeName, { persist=true, silent=false, storeLocal=persist } = {}){
  const safe = sanitizeThemeName(themeName || DEFAULT_THEME);
  currentTheme = safe;
  themeSelectedId = themeIdFromName(safe);
  themePreviewId = themeSelectedId;
  document.body?.setAttribute("data-theme", safe);
  if(storeLocal) setStoredTheme(safe);
  if(persist) persistThemePreference(safe);
  updateCurrentThemeLabel();
  recordThemeRecent(themeSelectedId);
  renderThemeCatalog();
  if(themeMsg && !silent){
    themeMsg.textContent = `Theme applied: ${safe}`;
    setTimeout(() => { if(themeMsg.textContent.startsWith("Theme applied")) themeMsg.textContent = ""; }, 2400);
  }
  updateIrisLolaTogetherClass();
}
function createThemeThumbnail(themeName){
  const wrap = document.createElement("div");
  wrap.className = "themeThumbnail";
  wrap.setAttribute("data-theme", themeName);
  wrap.innerHTML = `
    <div class="themeMiniLayout">
      <div class="themeMiniSidebar">
        <div class="miniItem"></div>
        <div class="miniItem"></div>
        <div class="miniItem"></div>
      </div>
      <div class="themeMiniMain">
        <div class="themeMiniMsg">
          <div class="themeMiniAvatar"></div>
          <div class="themeMiniBubble">Hey there!</div>
        </div>
        <div class="themeMiniMsg">
          <div class="themeMiniAvatar"></div>
          <div class="themeMiniBubble self">All set?</div>
        </div>
        <div class="themeMiniButton">Action</div>
      </div>
    </div>
  `;
  return wrap;
}
function updateCurrentThemeLabel(){
  if (currentThemeLabel) currentThemeLabel.textContent = currentTheme || DEFAULT_THEME;
}
function normalizeThemeIdList(list){
  const ids = Array.isArray(list) ? list.map((id) => String(id)) : [];
  const unique = [];
  const seen = new Set();
  for (const id of ids) {
    if (!THEME_BY_ID.has(id) || seen.has(id)) continue;
    seen.add(id);
    unique.push(id);
  }
  return unique;
}
const THEME_RECENTS_KEY = "themeRecents";
function loadThemeRecents(){
  try {
    const raw = localStorage.getItem(THEME_RECENTS_KEY);
    return normalizeThemeIdList(raw ? JSON.parse(raw) : []);
  } catch {
    return [];
  }
}
function saveThemeRecents(){
  try { localStorage.setItem(THEME_RECENTS_KEY, JSON.stringify(themeRecents)); } catch {}
}
function recordThemeRecent(themeId){
  if (!themeId) return;
  const next = [themeId, ...themeRecents.filter((id) => id !== themeId)];
  themeRecents = next.slice(0, 12);
  saveThemeRecents();
}
function getPinnedLimit(role){
  return roleRank(role || "User") >= roleRank("VIP") ? 5 : 2;
}
function canPinTheme(role, pinnedCount){
  return pinnedCount < getPinnedLimit(role);
}
function isThemeOwned(themeId){
  return themeOwnedIds.includes(themeId);
}
function isThemeLockedForUser(theme){
  const role = me?.role || "User";
  if (!theme) return true;
  if (theme.name === IRIS_LOLA_THEME && !isIrisLolaAllowed()) return true;
  if (theme.access === "vip" && roleRank(role) < roleRank("VIP")) return true;
  if (theme.access === "gold" && !isThemeOwned(theme.id) && roleRank(role) < roleRank("VIP")) return true;
  return false;
}
function updateThemePreview(themeId){
  const theme = THEME_BY_ID.get(themeId) || THEME_BY_NAME.get(currentTheme);
  if (!theme) return;
  themePreviewId = theme.id;
  if (themesPreviewFrame) themesPreviewFrame.setAttribute("data-theme", theme.name);
  if (themesPreviewName) themesPreviewName.textContent = theme.name;
  if (themesPreviewHint) themesPreviewHint.textContent = "Preview only — apply when you’re ready.";
  updateThemeActionButtons();
}
function updateThemeActionButtons(){
  const theme = THEME_BY_ID.get(themeSelectedId);
  if (!themesApplyBtn || !theme) return;
  const locked = isThemeLockedForUser(theme);
  themesApplyBtn.disabled = locked || theme.name === currentTheme;
  const showBuy = theme.access === "gold" && !isThemeOwned(theme.id) && roleRank(me?.role || "User") < roleRank("VIP");
  if (themesBuyBtn) {
    themesBuyBtn.style.display = showBuy ? "inline-flex" : "none";
    themesBuyBtn.textContent = showBuy ? `Buy for ${theme.goldPrice} Gold` : "Buy for 0 Gold";
  }
}
function createThemeCard(theme){
  const isPinned = themePinnedIds.includes(theme.id);
  const isFavorite = themeFavoriteIds.includes(theme.id);
  const owned = isThemeOwned(theme.id);
  const locked = isThemeLockedForUser(theme);
  const card = document.createElement("button");
  card.type = "button";
  card.className = `themeCardV2${themeSelectedId === theme.id ? " selected" : ""}`;
  card.dataset.themeId = theme.id;
  card.innerHTML = `
    <div class="themeCardTop">
      <div class="themeCardName">${escapeHtml(theme.name)}</div>
      <div class="themeCardActions">
        <button class="themeCardAction themePinBtn${isPinned ? " active" : ""}" type="button" aria-label="Pin theme">📌</button>
        <button class="themeCardAction themeFavBtn${isFavorite ? " active" : ""}" type="button" aria-label="Favorite theme">★</button>
      </div>
    </div>
  `;
  card.appendChild(createThemeThumbnail(theme.name));
  const badges = document.createElement("div");
  badges.className = "themeCardBadges";
  if (theme.access === "vip") {
    const badge = document.createElement("span");
    badge.className = "themeBadge vip";
    badge.textContent = "VIP";
    badges.appendChild(badge);
  }
  if (theme.access === "gold" && !owned) {
    const badge = document.createElement("span");
    badge.className = "themeBadge gold";
    badge.textContent = `${theme.goldPrice} Gold`;
    badges.appendChild(badge);
  }
  if (owned) {
    const badge = document.createElement("span");
    badge.className = "themeBadge owned";
    badge.textContent = "Owned";
    badges.appendChild(badge);
  }
  if (locked) {
    const badge = document.createElement("span");
    badge.className = "themeBadge locked";
    badge.textContent = theme.access === "vip" ? "Locked" : "Locked";
    badges.appendChild(badge);
  }
  card.appendChild(badges);
  const pinBtn = card.querySelector(".themePinBtn");
  const favBtn = card.querySelector(".themeFavBtn");
  pinBtn?.addEventListener("click", (e) => {
    e.stopPropagation();
    toggleThemePin(theme.id);
  });
  favBtn?.addEventListener("click", (e) => {
    e.stopPropagation();
    toggleThemeFavorite(theme.id);
  });
  card.addEventListener("click", () => {
    themeSelectedId = theme.id;
    updateThemePreview(theme.id);
    renderThemeCatalog();
  });
  card.addEventListener("contextmenu", (e) => {
    e.preventDefault();
    openThemeActionSheet(theme.id);
  });
  let pressTimer = null;
  card.addEventListener("pointerdown", (e) => {
    if (e.pointerType !== "touch") return;
    pressTimer = setTimeout(() => openThemeActionSheet(theme.id), 500);
  });
  card.addEventListener("pointerup", () => {
    if (pressTimer) clearTimeout(pressTimer);
  });
  card.addEventListener("pointerleave", () => {
    if (pressTimer) clearTimeout(pressTimer);
  });
  return card;
}
function buildFilterList(){
  const base = [
    { id: "all", label: "All" },
    { id: "pinned", label: "Pinned" },
    { id: "favorites", label: "Favorites" },
    { id: "recents", label: "Recents" },
    { id: "unlocked", label: "Unlocked" },
    { id: "vip", label: "VIP" },
  ];
  const tags = THEME_TAGS.map((tag) => ({ id: tag.toLowerCase(), label: tag }));
  return [...base, ...tags];
}
function renderFilterPills(container){
  if (!container) return;
  container.innerHTML = "";
  for (const filter of buildFilterList()){
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = `pillBtn${themeActiveFilter === filter.id ? " active" : ""}`;
    btn.textContent = filter.label;
    btn.addEventListener("click", () => {
      themeActiveFilter = filter.id;
      renderThemeCatalog();
      renderFilterPills(themesModalFilters);
      renderFilterPills(themesFiltersSheetBody);
    });
    container.appendChild(btn);
  }
}
function applyThemeFilters(themes){
  const role = me?.role || "User";
  let results = themes.filter((theme) => theme.name !== IRIS_LOLA_THEME || isIrisLolaAllowed());
  if (themeSearchQuery) {
    const query = themeSearchQuery.toLowerCase();
    results = results.filter((theme) => theme.name.toLowerCase().includes(query));
  }
  switch (themeActiveFilter) {
    case "pinned":
      results = results.filter((theme) => themePinnedIds.includes(theme.id));
      break;
    case "favorites":
      results = results.filter((theme) => themeFavoriteIds.includes(theme.id));
      break;
    case "recents":
      results = results.filter((theme) => themeRecents.includes(theme.id));
      break;
    case "unlocked":
      results = results.filter((theme) => canApplyThemeForUser(theme, role, themeOwnedIds));
      break;
    case "vip":
      results = results.filter((theme) => theme.access === "vip");
      break;
    default:
      if (themeActiveFilter !== "all") {
        results = results.filter((theme) => (theme.tags || []).map((t) => t.toLowerCase()).includes(themeActiveFilter));
      }
      break;
  }
  return results;
}
function sortThemes(themes){
  const base = [...themes];
  const rankMap = new Map(themeRecents.map((id, idx) => [id, idx]));
  const favoriteSet = new Set(themeFavoriteIds);
  const pinnedSet = new Set(themePinnedIds);
  switch (themeSortMode) {
    case "newest":
      return base.sort((a, b) => (b.isNew === a.isNew ? 0 : b.isNew ? 1 : -1));
    case "az":
      return base.sort((a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: "base" }));
    case "favorites":
      return base.sort((a, b) => {
        const favDiff = Number(favoriteSet.has(b.id)) - Number(favoriteSet.has(a.id));
        if (favDiff !== 0) return favDiff;
        return a.name.localeCompare(b.name, undefined, { sensitivity: "base" });
      });
    case "pinned":
      return base.sort((a, b) => {
        const pinDiff = Number(pinnedSet.has(b.id)) - Number(pinnedSet.has(a.id));
        if (pinDiff !== 0) return pinDiff;
        return a.name.localeCompare(b.name, undefined, { sensitivity: "base" });
      });
    default:
      return base.sort((a, b) => {
        const rA = rankMap.has(a.id) ? rankMap.get(a.id) : Number.MAX_SAFE_INTEGER;
        const rB = rankMap.has(b.id) ? rankMap.get(b.id) : Number.MAX_SAFE_INTEGER;
        if (rA !== rB) return rA - rB;
        return a.name.localeCompare(b.name, undefined, { sensitivity: "base" });
      });
  }
}
function renderThemeCatalog(){
  if (!themesAllGrid || !themesPinnedGrid) return;
  renderFilterPills(themesModalFilters);
  renderFilterPills(themesFiltersSheetBody);
  const filtered = sortThemes(applyThemeFilters(THEME_LIST));
  const pinnedThemes = themePinnedIds.map((id) => THEME_BY_ID.get(id)).filter(Boolean);
  const shouldShowPinned = themeActiveFilter === "all" && pinnedThemes.length > 0;
  if (themesPinnedSection) themesPinnedSection.style.display = shouldShowPinned ? "block" : "none";
  themesPinnedGrid.innerHTML = "";
  if (shouldShowPinned) {
    pinnedThemes.forEach((theme) => themesPinnedGrid.appendChild(createThemeCard(theme)));
  }
  themesAllGrid.innerHTML = "";
  filtered.forEach((theme) => themesAllGrid.appendChild(createThemeCard(theme)));
  if (themesEmptyState) themesEmptyState.classList.toggle("show", filtered.length === 0);
  updateThemePreview(themeSelectedId);
}
function toggleThemePin(themeId){
  const isPinned = themePinnedIds.includes(themeId);
  if (isPinned) {
    themePinnedIds = themePinnedIds.filter((id) => id !== themeId);
  } else {
    const role = me?.role || "User";
    if (!canPinTheme(role, themePinnedIds.length)) {
      toast(`Pin limit reached. VIP can pin up to ${getPinnedLimit("VIP")} themes.`);
      return;
    }
    themePinnedIds = [themeId, ...themePinnedIds];
  }
  queuePersistPrefs({ pinnedThemeIds: themePinnedIds });
  renderThemeCatalog();
}
function toggleThemeFavorite(themeId){
  if (themeFavoriteIds.includes(themeId)) {
    themeFavoriteIds = themeFavoriteIds.filter((id) => id !== themeId);
  } else {
    themeFavoriteIds = [themeId, ...themeFavoriteIds];
  }
  queuePersistPrefs({ favoriteThemeIds: themeFavoriteIds });
  renderThemeCatalog();
}
async function purchaseTheme(themeId){
  const theme = THEME_BY_ID.get(themeId);
  if (!theme || theme.access !== "gold") return;
  if (isThemeOwned(themeId)) {
    toast("You already own this theme.");
    return;
  }
  try {
    const res = await fetch("/api/themes/purchase", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ themeId }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      if (data?.error === "insufficient_gold") {
        toast("Not enough gold.");
        return;
      }
      toast(data?.error || "Purchase failed.");
      return;
    }
    if (Array.isArray(data.ownedThemeIds)) {
      themeOwnedIds = normalizeThemeIdList(data.ownedThemeIds);
    }
    if (data.gold != null) {
      applyProgressionPayload({ gold: data.gold });
    }
    toast(`Purchased ${theme.name}!`);
    renderThemeCatalog();
  } catch {
    toast("Purchase failed.");
  }
}
function openThemesModal(){
  if (!themesModal) return;
  themeRecents = loadThemeRecents();
  themeSelectedId = themeIdFromName(currentTheme);
  updateThemePreview(themeSelectedId);
  renderThemeCatalog();
  themesModal.classList.add("show");
  themesModal.setAttribute("aria-hidden", "false");
}
function closeThemesModal(){
  themesModal?.classList.remove("show");
  themesModal?.setAttribute("aria-hidden", "true");
  closeThemeActionSheet();
  closeThemesFiltersSheet();
}
function openThemesFiltersSheet(){
  themesFiltersSheet?.classList.add("show");
  themesFiltersSheet?.setAttribute("aria-hidden", "false");
}
function closeThemesFiltersSheet(){
  themesFiltersSheet?.classList.remove("show");
  themesFiltersSheet?.setAttribute("aria-hidden", "true");
}
function openThemeActionSheet(themeId){
  const theme = THEME_BY_ID.get(themeId);
  if (!theme || !themesActionSheet) return;
  themeActionThemeId = themeId;
  if (themesActionSheetTitle) themesActionSheetTitle.textContent = theme.name;
  if (themesActionPinBtn) themesActionPinBtn.textContent = themePinnedIds.includes(themeId) ? "Unpin theme" : "Pin theme";
  if (themesActionFavoriteBtn) themesActionFavoriteBtn.textContent = themeFavoriteIds.includes(themeId) ? "Unfavorite" : "Favorite";
  if (themesActionApplyBtn) themesActionApplyBtn.disabled = isThemeLockedForUser(theme) || theme.name === currentTheme;
  const showBuy = theme.access === "gold" && !isThemeOwned(theme.id) && roleRank(me?.role || "User") < roleRank("VIP");
  if (themesActionBuyBtn) {
    themesActionBuyBtn.style.display = showBuy ? "inline-flex" : "none";
    themesActionBuyBtn.textContent = showBuy ? `Buy for ${theme.goldPrice} Gold` : "Buy for 0 Gold";
  }
  themesActionSheet.classList.add("show");
  themesActionSheet.setAttribute("aria-hidden", "false");
}
function closeThemeActionSheet(){
  themesActionSheet?.classList.remove("show");
  themesActionSheet?.setAttribute("aria-hidden", "true");
  themeActionThemeId = "";
}
function switchCustomizationSection(section){
  customNavButtons.forEach((btn) => {
    const isActive = btn.dataset.section === section;
    btn.classList.toggle("active", isActive);
  });
  document.querySelectorAll(".customPanel").forEach((panel) => {
    panel.classList.toggle("active", panel.id === `customPanel${section[0].toUpperCase()}${section.slice(1)}`);
  });
}
function initCustomizationUi(){
  customNavButtons.forEach((btn) => {
    btn.addEventListener("click", () => switchCustomizationSection(btn.dataset.section));
  });
  openThemesModalBtn?.addEventListener("click", openThemesModal);
  themesModalCloseBtn?.addEventListener("click", closeThemesModal);
  themesModal?.addEventListener("click", (e) => {
    if (e.target === themesModal) closeThemesModal();
  });
  themesModalSearch?.addEventListener("input", (e) => {
    themeSearchQuery = e.target.value.trim();
    renderThemeCatalog();
  });
  themesModalSort?.addEventListener("change", (e) => {
    themeSortMode = e.target.value;
    renderThemeCatalog();
  });
  themesFiltersBtn?.addEventListener("click", openThemesFiltersSheet);
  themesFiltersSheetClose?.addEventListener("click", closeThemesFiltersSheet);
  themesFiltersSheet?.addEventListener("click", (e) => {
    if (e.target === themesFiltersSheet) closeThemesFiltersSheet();
  });
  themesApplyBtn?.addEventListener("click", () => {
    const theme = THEME_BY_ID.get(themeSelectedId);
    if (!theme) return;
    if (isThemeLockedForUser(theme)) {
      toast("This theme is locked.");
      return;
    }
    applyTheme(theme.name, { persist: true });
  });
  themesBuyBtn?.addEventListener("click", () => {
    purchaseTheme(themeSelectedId);
  });
  themesActionPinBtn?.addEventListener("click", () => {
    if (themeActionThemeId) toggleThemePin(themeActionThemeId);
    closeThemeActionSheet();
  });
  themesActionFavoriteBtn?.addEventListener("click", () => {
    if (themeActionThemeId) toggleThemeFavorite(themeActionThemeId);
    closeThemeActionSheet();
  });
  themesActionApplyBtn?.addEventListener("click", () => {
    const theme = THEME_BY_ID.get(themeActionThemeId);
    if (theme && !isThemeLockedForUser(theme)) applyTheme(theme.name, { persist: true });
    closeThemeActionSheet();
  });
  themesActionBuyBtn?.addEventListener("click", () => {
    purchaseTheme(themeActionThemeId);
    closeThemeActionSheet();
  });
  themesActionCloseBtn?.addEventListener("click", closeThemeActionSheet);
  themesActionSheet?.addEventListener("click", (e) => {
    if (e.target === themesActionSheet) closeThemeActionSheet();
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeThemesModal();
  });
  themeRecents = loadThemeRecents();
  updateCurrentThemeLabel();
  renderThemeCatalog();
}
async function loadThemePreference(){
  let desired = sanitizeThemeName(getStoredTheme() || currentTheme || DEFAULT_THEME);
  if(me){
    if(me.theme) desired = sanitizeThemeName(me.theme);
    else {
      const serverTheme = await fetchThemePreference();
      if(serverTheme) desired = sanitizeThemeName(serverTheme);
    }
  }
  applyTheme(desired, { persist:false, silent:true });
}

function applyBadgePrefs(){
  if(directBadgeColorText) directBadgeColorText.value = badgePrefs.direct;
  if(groupBadgeColorText) groupBadgeColorText.value = badgePrefs.group;
  if(directBadgeColor) directBadgeColor.value = normalizeColorForInput(badgePrefs.direct, badgeDefaults.direct);
  if(groupBadgeColor) groupBadgeColor.value = normalizeColorForInput(badgePrefs.group, badgeDefaults.group);
  if(dmBadgeDot) dmBadgeDot.style.backgroundColor = badgePrefs.direct;
  if(groupDmBadgeDot) groupDmBadgeDot.style.backgroundColor = badgePrefs.group;
}
function refreshDmBadgesFromThreads(){
  // Rebuild unread state from authoritative thread metadata (unreadCount).
  // IMPORTANT: clear first; otherwise badges can "stick" forever.
  dmUnreadThreads.clear();

  let hasDirect = false;
  let hasGroup = false;
  for(const th of (dmThreads || [])){
    const tid = String(th.id);
    const unread = Number(th.unreadCount || 0);
    if(unread > 0) dmUnreadThreads.add(tid);
    const isGroup = !!th.is_group;
    const pending = dmUnreadThreads.has(tid);
    if(pending){
      if(isGroup) hasGroup = true; else hasDirect = true;
    }
  }
  setBadgeVisibility("direct", hasDirect);
  setBadgeVisibility("group", hasGroup);
}

function setBadgeVisibility(kind, visible){
  const el = kind === "group" ? groupDmBadgeDot : dmBadgeDot;
  if(kind === "group") groupBadgePending = visible; else directBadgePending = visible;
  if(el) el.style.display = visible ? "block" : "none";
}
function clearDmBadges(){
  setBadgeVisibility("direct", false);
  setBadgeVisibility("group", false);
}
function isGroupThread(threadId){
  const meta = dmThreads.find((t) => String(t.id) === String(threadId));
  return !!(meta?.is_group || meta?.isGroup);
}
function markDmNotification(threadId, isGroupHint){
  const isGroup = typeof isGroupHint === "boolean" ? isGroupHint : isGroupThread(threadId);
  if(dmPanel?.classList.contains("open") && activeDmId === threadId) return;
  dmUnreadThreads.add(threadId);
  setBadgeVisibility(isGroup ? "group" : "direct", true);
}
badgePrefs = loadBadgePrefsFromStorage();
applyBadgePrefs();
dmNeonColor = loadDmNeonColorFromStorage();
applyDmNeonPrefs();
initCustomizationUi();
const EMOJI_CHOICES = ["😀","😁","😂","🙂","😉","😍","😘","🤔","😤","😭","😡","🥹","😈","💀","🔥","👀","🖕","♥️","💯","👍","👎","🎉","📸","🫦",];

let reactionMenuEl = null;
let reactionMenuFor = null;
let reactionMenuRow = null;
let reactionMenuMode = "main"; // "main" | "dm"
let reactionMenuThreadId = null;

function ensureReactionMenu(){
  if(reactionMenuEl) return;
  reactionMenuEl = document.createElement("div");
  reactionMenuEl.className = "reactionMenu";
  reactionMenuEl.innerHTML = `<div class="reactionGrid"></div>`;
  document.body.appendChild(reactionMenuEl);

  // click outside closes
  document.addEventListener("mousedown", (e)=>{
    if(reactionMenuEl?.classList.contains("open") && !reactionMenuEl.contains(e.target)){
      closeReactionMenu();
    }
  });
  document.addEventListener("keydown", (e)=>{
    if(e.key === "Escape") closeReactionMenu();
  });
  window.addEventListener("scroll", ()=>closeReactionMenu(), {passive:true});
}

function openReactionMenu(messageId, anchorEl, rowEl){
  ensureReactionMenu();
  reactionMenuMode = "main";
  reactionMenuThreadId = null;
  reactionMenuFor = messageId;
  reactionMenuRow = rowEl;

  const grid = reactionMenuEl.querySelector(".reactionGrid");
  grid.innerHTML = "";

  for(const em of EMOJI_CHOICES){
    const b = document.createElement("button");
    b.type = "button";
    b.textContent = em;
    b.onclick = ()=>{
      triggerReactionBounce(b, false);
      if (reactionMenuMode === "dm") {
        socket?.emit("dm reaction", { threadId: reactionMenuThreadId, messageId, emoji: em });
      } else {
        socket?.emit("reaction", { messageId, emoji: em });
      }
      closeReactionMenu();
    };
    grid.appendChild(b);
  }

  // position near anchor
  const rect = anchorEl.getBoundingClientRect();
  reactionMenuEl.classList.add("open");

  // place above if possible, else below
  const menuRect = reactionMenuEl.getBoundingClientRect();
  let x = Math.min(window.innerWidth - menuRect.width - 12, Math.max(12, rect.left));
  let y = rect.top - menuRect.height - 10;
  if(y < 12) y = rect.bottom + 10;

  reactionMenuEl.style.left = `${x}px`;
  reactionMenuEl.style.top = `${y}px`;

  // on mobile, force show actions while menu is open
  if(rowEl) rowEl.classList.add("showActions");
}

function openDmReactionMenu(threadId, messageId, anchorEl, rowEl){
  ensureReactionMenu();
  reactionMenuMode = "dm";
  reactionMenuThreadId = threadId;
  reactionMenuFor = messageId;
  reactionMenuRow = rowEl;

  const grid = reactionMenuEl.querySelector(".reactionGrid");
  grid.innerHTML = "";

  for (const em of EMOJI_CHOICES) {
    const b = document.createElement("button");
    b.type = "button";
    b.textContent = em;
    b.onclick = ()=>{
      triggerReactionBounce(b, false);
      socket?.emit("dm reaction", { threadId, messageId, emoji: em });
      closeReactionMenu();
    };
    grid.appendChild(b);
  }

  const rect = anchorEl.getBoundingClientRect();
  reactionMenuEl.classList.add("open");
  const menuRect = reactionMenuEl.getBoundingClientRect();
  let x = Math.min(window.innerWidth - menuRect.width - 12, Math.max(12, rect.left));
  let y = rect.top - menuRect.height - 10;
  if (y < 12) y = rect.bottom + 10;
  reactionMenuEl.style.left = `${x}px`;
  reactionMenuEl.style.top = `${y}px`;
  if (rowEl) rowEl.classList.add("showActions");
}

function closeReactionMenu(){
  if(!reactionMenuEl) return;
  reactionMenuEl.classList.remove("open");
  if(reactionMenuRow) reactionMenuRow.classList.remove("showActions");
  reactionMenuFor = null;
  reactionMenuRow = null;
}

// Tap outside to hide message action buttons (mobile-friendly).
// Use pointerdown so it works reliably on iOS Safari.
document.addEventListener("pointerdown", (e) => {
  if (e?.target?.closest(".msgItem")) return;
  if (e?.target?.closest(".dmRow")) return;
  if (e?.target?.closest(".reactionMenu")) return;
  document.querySelectorAll(".msgItem.showActions").forEach((el) => el.classList.remove("showActions"));
  document.querySelectorAll(".dmRow.showActions").forEach((el) => el.classList.remove("showActions"));
  closeReactionMenu();
}, { capture: true });

// Tap outside to hide message action buttons (mobile).
document.addEventListener("click", (e)=>{
  const isTouch = window.matchMedia && window.matchMedia("(hover: none)").matches;
  if (!isTouch && window.innerWidth > 980) return;
  if (e.target && e.target.closest && e.target.closest(".msgItem")) return;
  document.querySelectorAll(".msgItem.showActions").forEach((el)=>el.classList.remove("showActions"));
});
function openMediaLightbox(src, kind){
  if (!mediaLightbox || !mediaLightboxImg || !mediaLightboxVideo) return;
  mediaLightbox.classList.add("show");
  document.body.classList.add("lockScroll");
  if (kind === "video") {
    mediaLightboxVideo.src = src;
    mediaLightboxVideo.style.display = "block";
    mediaLightboxImg.style.display = "none";
    mediaLightboxVideo.play().catch(()=>{});
  } else {
    mediaLightboxImg.src = src;
    mediaLightboxImg.style.display = "block";
    mediaLightboxVideo.pause();
    mediaLightboxVideo.style.display = "none";
  }
}
function closeMediaLightbox(){
  if (!mediaLightbox) return;
  mediaLightbox.classList.remove("show");
  document.body.classList.remove("lockScroll");
  if (mediaLightboxImg) mediaLightboxImg.src = "";
  if (mediaLightboxVideo) {
    mediaLightboxVideo.pause();
    mediaLightboxVideo.src = "";
  }
}
mediaLightboxClose?.addEventListener("click", closeMediaLightbox);
mediaLightbox?.addEventListener("click", (e) => { if (e.target === mediaLightbox) closeMediaLightbox(); });
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && mediaLightbox?.classList.contains("show")) closeMediaLightbox();
});

const IMAGE_EXTS = new Set(["png", "jpg", "jpeg", "gif", "webp", "bmp", "svg"]);
const VIDEO_EXTS = new Set(["mp4", "webm", "mov", "m4v", "ogg"]);
const AUDIO_EXTS = new Set(["mp3", "m4a", "aac", "wav", "ogg", "opus", "flac"]);
function inferAttachmentKind({ mime, type, url } = {}) {
  const typeKey = normalizeUserKey(type);
  if (typeKey === "image" || typeKey === "gif") return "image";
  if (typeKey === "video") return "video";

  const mimeKey = normalizeUserKey(mime);
  if (mimeKey.startsWith("image/")) return "image";
  if (mimeKey.startsWith("audio/")) return "audio";
  if (mimeKey.startsWith("video/")) return "video";

  const cleanUrl = String(url || "").split(/[?#]/)[0];
  const ext = cleanUrl.includes(".") ? cleanUrl.split(".").pop().toLowerCase() : "";
  if (IMAGE_EXTS.has(ext)) return "image";
  if (AUDIO_EXTS.has(ext)) return "audio";
  if (VIDEO_EXTS.has(ext)) return "video";
  return "file";
}
function renderAttachmentNode({ url, mime, type } = {}) {
  const cleanUrl = String(url || "").trim();
  if (!cleanUrl) return null;
  const kind = inferAttachmentKind({ mime, type, url: cleanUrl });
  const att = document.createElement("div");
  att.className = "attachment";

  if (kind === "image") {
    const img = document.createElement("img");
    img.className = "msg-media-thumb";
    img.loading = "lazy";
    img.src = cleanUrl;
    img.alt = "attachment";
    img.addEventListener("click", (e) => {
      e.stopPropagation();
      openMediaLightbox(cleanUrl, "image");
    });
    att.appendChild(img);
    return att;
  }

  if (kind === "video") {
    const video = document.createElement("video");
    video.className = "msg-media-thumb";
    video.src = cleanUrl;
    video.controls = true;
    video.playsInline = true;
    video.preload = "metadata";
    att.appendChild(video);
    return att;
  }


  if (kind === "audio") {
    const wrap = document.createElement("div");
    wrap.className = "attachment audioAttachment";
    wrap.dataset.src = cleanUrl;

    const btn = document.createElement("button");
    btn.className = "audioPlayBtn";
    btn.type = "button";
    btn.setAttribute("aria-label", "Play audio");
    btn.textContent = "▶";
    wrap.appendChild(btn);

    const wave = document.createElement("div");
    wave.className = "audioWave";
    wrap.appendChild(wave);

    const meta = document.createElement("div");
    meta.className = "audioMeta";
    const time = document.createElement("span");
    time.className = "audioTime";
    time.textContent = "";
    meta.appendChild(time);

    const dl = document.createElement("a");
    dl.className = "audioDownload";
    dl.href = cleanUrl;
    dl.target = "_blank";
    dl.rel = "noopener";
    dl.textContent = "Download";
    meta.appendChild(dl);

    wrap.appendChild(meta);

    // Lazy-init waveform only when user interacts (better for mobile performance)
    let ws = null;
    let ready = false;

    const ensurePlayer = () => {
      if (ws || wrap.dataset.fallback === "1") return;
      if (!window.WaveSurfer || typeof window.WaveSurfer.create !== "function") {
        // Fallback: native audio control
        wrap.dataset.fallback = "1";
        wave.innerHTML = "";
        const audio = document.createElement("audio");
        audio.src = cleanUrl;
        audio.controls = true;
        audio.preload = "metadata";
        audio.className = "audioNative";
        wave.appendChild(audio);
        audio.addEventListener("loadedmetadata", () => {
          if (isFinite(audio.duration)) time.textContent = formatSeconds(audio.duration);
        });
        return;
      }

      ws = window.WaveSurfer.create({
        container: wave,
        height: 44,
        barWidth: 2,
        barGap: 2,
        barRadius: 2,
        cursorWidth: 0,
        interact: true,
        normalize: true,
      });

      ws.on("ready", () => {
        ready = true;
        const dur = ws.getDuration ? ws.getDuration() : 0;
        if (dur && isFinite(dur)) time.textContent = formatSeconds(dur);
      });

      ws.on("play", () => { btn.textContent = "❚❚"; wrap.classList.add("playing"); });
      ws.on("pause", () => { btn.textContent = "▶"; wrap.classList.remove("playing"); });
      ws.on("finish", () => { btn.textContent = "▶"; wrap.classList.remove("playing"); });

      ws.load(cleanUrl);
    };

    // Format helper (local)
    function formatSeconds(sec){
      const s = Math.max(0, Math.floor(sec || 0));
      const m = Math.floor(s / 60);
      const r = s % 60;
      return `${m}:${String(r).padStart(2,"0")}`;
    }

    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      ensurePlayer();
      // If fallback, clicking play does nothing special (native controls)
      if (!ws) return;
      if (!ready) {
        // Queue play once ready
        if (typeof ws.once === "function") {
          ws.once("ready", () => { try { ws.play(); } catch {} });
        } else {
          ws.on("ready", () => { try { ws.play(); } catch {} });
        }
        return;
      }
      try { ws.isPlaying() ? ws.pause() : ws.play(); } catch {}
    });

    return wrap;
  }

  const a = document.createElement("a");
  a.href = cleanUrl;
  a.target = "_blank";
  a.rel = "noopener";
  a.textContent = "Download attachment";
  att.appendChild(a);
  return att;
}

// Iris & Lola Couples Theme Enhancement
function maybeShowIrisLolaSharedMoment({ isSelf, isPartner, messageTs, container, anchorItem }) {
  if (!shouldUseIrisLolaCoupleUi()) return;
  if (!isSelf && !isPartner) return;
  const now = Number(messageTs) || Date.now();
  if (isSelf) irisLolaLastSelfMsgTs = now;
  if (isPartner) irisLolaLastPartnerMsgTs = now;
  const otherTs = isSelf ? irisLolaLastPartnerMsgTs : irisLolaLastSelfMsgTs;
  if (!otherTs || Math.abs(now - otherTs) > IRIS_LOLA_SHARED_WINDOW_MS) return;
  if (!shouldShowSharedMoment(now, irisLolaSharedMomentTs, IRIS_LOLA_SHARED_COOLDOWN_MS)) return;
  irisLolaSharedMomentTs = now;
  const badge = document.createElement("div");
  badge.className = "irisLolaSharedMoment";
  if (!shouldAnimateAmbientEffects(PREFERS_REDUCED_MOTION)) badge.classList.add("no-motion");
  badge.textContent = "💖";
  if (container && anchorItem) {
    container.insertBefore(badge, anchorItem);
    setTimeout(() => badge.remove(), 1200);
  }

  // Message-proximity glow: when you and your partner speak close together, softly brighten.
  try{
    document.body?.classList.add('irisLolaProximityGlow');
    setTimeout(()=>{ try{ document.body?.classList.remove('irisLolaProximityGlow'); }catch{} }, 2000);
  }catch{}
}

function addMessage(m){
  // --- Main chat grouping: consecutive messages from same user are visually grouped ---
  const shouldStick = isNearBottom(msgs, 160);

  const mid = m.messageId;
  const senderName = String(m.user ?? m.username ?? m.from ?? m.sender ?? "");
  const senderRole = String(m.role ?? m.userRole ?? "");
  const isSelf = !!(senderName && me && (senderName === me.username));
  const rawText = String((m.text ?? m.message ?? m.msg ?? "") || "");
  if (m?.chatFx) updateUserFxMap(senderName, m.chatFx);
  const resolvedFx = resolveChatFx(m, senderName);


// Hydrate reply context client-side (server may only send replyToId)
try{
  if(m && m.replyToId && (!m.replyToUser || !m.replyToText)){
    const hit = msgIndex.find((x)=> String(x.id) === String(m.replyToId));
    if(hit){
      m.replyToUser = m.replyToUser || hit.user;
      m.replyToText = m.replyToText || hit.text;
    }
  }
}catch{}

  // Decide whether we can append into the previous group
  const lastEl = msgs?.lastElementChild;
  const canGroup =
    lastEl &&
    lastEl.classList &&
    lastEl.classList.contains("msgGroup") &&
    String(lastEl.dataset.user||"") === String(senderName||"") &&
    String(lastEl.dataset.role||"") === String(senderRole||"") &&
    String(lastEl.dataset.self||"") === String(isSelf ? "1" : "0") &&
    // Optional time window to avoid grouping across long pauses
    (Number(m.ts||0) - Number(lastEl.dataset.lastTs||0) <= 2 * 60 * 1000);

  let group = lastEl;
  if(!canGroup){
    group = document.createElement("div");
    group.className = "msgGroup" + (isSelf ? " self" : "");
    group.dataset.user = senderName || "";
    group.dataset.role = senderRole || "";
    group.dataset.self = isSelf ? "1" : "0";
    group.dataset.lastTs = String(Number(m.ts||0) || Date.now());

    const av = document.createElement("div");
    av.className = "msgAvatar";
    av.appendChild(avatarNode(m.avatar, senderName, senderRole));
    applyAvatarMeta(av, { username: senderName, role: senderRole, status: m.status });
    av.title = `View ${senderName} profile`;
    av.tabIndex = 0;
    const openProfile = (e) => { e.stopPropagation(); openMemberProfile(senderName); };
    av.addEventListener("click", openProfile);
    av.addEventListener("keydown", (e)=>{ if(e.key==="Enter"||e.key===" "){ openProfile(e); }});
    group.appendChild(av);

    const body = document.createElement("div");
    body.className = "msgGroupBody";
    group.appendChild(body);

    msgs.appendChild(group);
  }else{
    group.dataset.lastTs = String(Number(m.ts||0) || Date.now());
  }

  const body = group.querySelector(".msgGroupBody");
  if(!body) return;

  const item = buildMainMsgItem(m, {
    showHeader: !canGroup, // show username/role only on first in group
    isSelf
  });
  item.dataset.username = normKey(senderName || "");
  const isPartner = isPartnerName(senderName);
  if (shouldUseIrisLolaCoupleUi() && !isSelf && isPartner) {
    item.classList.add("couple-partner-msg");
  }

  const bubbleEl = item.querySelector(".bubble");
  applyChatFxToBubble(bubbleEl, resolvedFx, { groupBody: body });
  applyIdentityGlow(item, { username: senderName, role: senderRole, vibe_tags: m?.vibe_tags, couple: m?.couple });
  body.appendChild(item);
  maybeShowIrisLolaSharedMoment({
    isSelf,
    isPartner,
    messageTs: m?.ts,
    container: body,
    anchorItem: item
  });
  queueContrastReinforcement(bubbleEl);

  if (m.__fresh && !isSelf && hasMention(rawText, me?.username)) {
    const snippet = rawText.trim().slice(0, 140);
    const suffix = snippet ? `: ${snippet}` : "";
    pushNotification({
      type: "mention",
      text: `${senderName} mentioned you${suffix}`,
      target: `message:${mid}`
    });
  }

  if (m.__fresh) {
    if (isPolishAnimationsEnabled()) {
      item.classList.add("msg-new");
      setTimeout(() => item.classList.remove("msg-new"), 220);
    }
    const variant = detectMessageImpactVariant(item, rawText);
    const isVip = roleRank(senderRole) >= roleRank("VIP");
    applyMessageImpactAnimation(item, { variant, isVip });
    delete m.__fresh;
  }


// Mark grouped messages so bubbles visually merge into one
try{
  if(!canGroup){
    item.classList.add("gFirst","gLast");
  }else{
    item.classList.add("gCont","gLast");
    const prev = item.previousElementSibling;
    if(prev){
      // prev was the last; it becomes mid (or first if it was the first in the group)
      prev.classList.remove("gLast");
      if(!prev.classList.contains("gFirst")) prev.classList.add("gMid");
    }
    // ensure the first child is flagged as first
    const first = body.firstElementChild;
    if(first) first.classList.add("gFirst");
  }
}catch{}

// Update rolling index for reply lookups
try{
  msgIndex.push({ id: mid, user: senderName, text: String(m.text||""), ts: Number(m.ts||Date.now()) });
  if(msgIndex.length > 500) msgIndex.splice(0, msgIndex.length - 500);
}catch{}

  const wantStick = shouldStick || isSelf;
  stickToBottomIfWanted({ force: wantStick, behavior: isSelf ? "smooth" : "auto" });
  if(!wantStick) noteUnseenMainMessage();
}

function buildMainMsgItem(m, opts){
  const { showHeader, isSelf } = opts || {};
  const mid = m.messageId;

  const item = document.createElement("div");
  item.className = "msgItem" + (isSelf ? " self" : "");
  item.dataset.mid = mid;

  const bubble = document.createElement("div");
  bubble.className = "bubble";

  // Header/meta
  const meta = document.createElement("div");
  meta.className = "meta";

  const name = document.createElement("div");
  name.className = "name";
  const roleTag = roleKey(m.role);
  name.dataset.role = roleTag;
  if (showHeader) {
    const ico = document.createElement("span");
    ico.className = "roleIco";
    ico.textContent = `${roleIcon(m.role)} `;
    const uname = document.createElement("span");
    uname.className = "unameText";
    uname.dataset.role = roleTag;
    uname.textContent = String(m.user || "");
    name.appendChild(ico);
    name.appendChild(uname);
  }

  const time = document.createElement("div");
  time.className = "time";
  time.textContent = formatTime(m.ts);
  const tone = toneMeta(m.tone || m.toneKey);
  if (tone) {
    const toneEl = document.createElement("span");
    toneEl.className = "toneBadge";
    toneEl.textContent = tone.emoji;
    const toneLabel = `Tone: ${tone.name} — ${tone.description}`;
    toneEl.title = toneLabel;
    toneEl.setAttribute("aria-label", toneLabel);
    time.appendChild(toneEl);
  }

  // Edited indicator
  const editedAt = m.editedAt || m.edited_at || 0;
  if (editedAt) {
    const ed = document.createElement("span");
    ed.className = "editedTag";
    ed.textContent = " (edited)";
    time.appendChild(ed);
  }

  meta.appendChild(name);
  meta.appendChild(time);
  bubble.appendChild(meta);

  // Body text + youtube stripping
  const rawText = String((m.text ?? m.message ?? m.msg ?? "") || "");
  let ytIds = [];
  let displayText = rawText;
  try {
    ytIds = extractYouTubeIds(rawText);
    displayText = ytIds.length ? stripYouTubeUrls(rawText) : rawText;
  } catch (err) {
    console.warn("[addMessage] YouTube parse failed:", err);
    ytIds = [];
    displayText = rawText;
  }

  if(displayText.trim()){
    const text = document.createElement("div");
    text.className = "text";
    text.innerHTML = applyMentions(displayText, { linkifyText: true }).replace(/\n/g, "<br/>");
    bubble.appendChild(text);
  }

  if(ytIds && ytIds.length){
    ytIds.forEach(id => bubble.appendChild(buildYouTubePreview(id)));
  }

  const attachmentPayload = m?.attachment?.url
    ? { url: m.attachment.url, type: m.attachment.type, mime: m.attachment.mime }
    : (m.attachmentUrl ? { url: m.attachmentUrl, type: m.attachmentType, mime: m.attachmentMime } : null);
  if (attachmentPayload) {
    const node = renderAttachmentNode(attachmentPayload);
    if (node) bubble.appendChild(node);
  }

  // Reply preview (inline) if present
  if(m.replyToId && m.replyToUser){
    const rp = document.createElement("div");
    rp.className = "replyContext";

    const u = document.createElement("div");
    u.className = "replyUser";
    u.textContent = String(m.replyToUser || "");

    const sn = document.createElement("div");
    sn.className = "replySnippet";
    sn.textContent = String(m.replyToText || "").slice(0, 140);

    rp.appendChild(u);
    rp.appendChild(sn);

    rp.addEventListener("click", (e)=>{
      e.stopPropagation();
      const target = document.querySelector(`[data-mid="${m.replyToId}"]`);
      if(target) target.scrollIntoView({ behavior:"smooth", block:"center" });
    });

    // Place just under meta, above text/media
    bubble.insertBefore(rp, meta.nextSibling);
  }


  // Reactions container (kept outside bubble so it can sit beside it)
  const reacts = document.createElement("div");
  reacts.className = "reacts";
  reacts.id = "reacts-" + mid;

  // Actions rail
  const actions = document.createElement("div");
  actions.className = "msgActions";

  const reactToggle = document.createElement("button");
  reactToggle.className = "reactBtn";
  reactToggle.type = "button";
  reactToggle.textContent = "❤️‍🔥";
  reactToggle.title = "React";
  reactToggle.onclick = (e)=>{
    e.stopPropagation();
    if(reactionMenuFor === mid) closeReactionMenu();
    else openReactionMenu(mid, reactToggle, item);
  };
  actions.appendChild(reactToggle);

const replyBtn = document.createElement("button");
replyBtn.className = "actBtn";
replyBtn.type = "button";
replyBtn.textContent = "↩️";
replyBtn.title = "Reply";
replyBtn.onclick = (e)=>{
  e.stopPropagation();
  setReplyTarget({
    id: mid,
    user: String(m.user || ""),
    text: String(m.text || "")
  });
  try { msgInput && msgInput.focus(); } catch(_) {}
};
actions.appendChild(replyBtn);


  // Edit (self, within window)
  const now = Date.now();
  const canEdit = isSelf && Number(m.ts||0) && (now - Number(m.ts||0) <= 5*60*1000);
  if(canEdit){
    const editBtn = document.createElement("button");
    editBtn.className = "editBtn";
    editBtn.type = "button";
    editBtn.textContent = "✏️";
    editBtn.title = "Edit";
    editBtn.onclick = (e)=>{
      e.stopPropagation();
      startMainEdit(mid, String((m.text ?? m.message ?? m.msg ?? "") || ""), item, bubble);
    };
    actions.appendChild(editBtn);
  }

  if (canDeleteMessage(isSelf)) {
    const del = document.createElement("button");
    del.type="button";
    del.className="delBtn";
    del.textContent="🗑️";
    del.title="Delete";
    del.onclick=(e)=>{
      e.stopPropagation();
      if(!confirm("Delete this message?")) return;
      markMessageDeleting(item);
      socket?.emit("delete message", { messageId: mid }, (res = {}) => {
        if (!res.ok) {
          clearMessageDeleting(item);
          addSystem(res.message || "Failed to delete message.");
          return;
        }
        handleMainMessageDeleted(mid);
      });
    };
    actions.appendChild(del);
  }

  // Wrap bubble + reactions so reactions remain OUTSIDE the bubble.
  // Actions are rendered as a horizontal bar BELOW the message, and only
  // expand when opened. This avoids reserving space and keeps groups aligned.
  const main = document.createElement("div");
  main.className = "msgMain";
  main.appendChild(bubble);
  main.appendChild(reacts);
  main.appendChild(actions);

  item.appendChild(main);

  // Mobile tap-to-toggle actions (per message item)
  const toggleActions = (e) => {
    if (e?.target?.closest("button, a, input, textarea, select, label")) return;
    if (e?.stopPropagation) e.stopPropagation();

    document.querySelectorAll(".msgItem.showActions").forEach((el) => {
      if (el !== item) el.classList.remove("showActions");
    });

    const on = item.classList.toggle("showActions");
    if (!on) closeReactionMenu();
  };

  bubble.addEventListener("click", toggleActions);
  bubble.addEventListener("touchstart", toggleActions, { passive:false });

  // Initial reactions render if present
  if(m.reactions) renderReactions(mid, m.reactions);

  return item;
}

function startMainEdit(messageId, currentText, itemEl, bubbleEl){
  if(!bubbleEl) return;
  const existing = bubbleEl.querySelector(".editBox");
  if(existing) return;

  // Remove current text node display (but keep meta/reply/attachments)
  const textEl = bubbleEl.querySelector(".text");
  if(textEl) textEl.style.display = "none";

  const box = document.createElement("div");
  box.className = "editBox";
  const ta = document.createElement("textarea");
  ta.value = String(currentText || "");
  ta.maxLength = 2000;
  ta.rows = 3;

  const row = document.createElement("div");
  row.className = "editRow";

  const cancel = document.createElement("button");
  cancel.type="button";
  cancel.textContent="Cancel";
  cancel.onclick=()=>{
    box.remove();
    if(textEl) textEl.style.display = "";
  };

  const save = document.createElement("button");
  save.type="button";
  save.textContent="Save";
  save.className="primary";
  save.onclick=()=>{
    const next = String(ta.value||"").trim();
    if(!next) return;
    socket?.emit("edit message", { messageId, text: next });
    box.remove();
    if(textEl){
      textEl.innerHTML = applyMentions(next, { linkifyText: true }).replace(/\n/g, "<br/>");
      textEl.style.display = "";
    }
  };

  row.appendChild(cancel);
  row.appendChild(save);
  box.appendChild(ta);
  box.appendChild(row);
  bubbleEl.appendChild(box);

  setTimeout(()=>ta.focus(), 0);
}

function safeAddMessage(m){
  try{
    addMessage(m);
  }catch(err){
    console.error("addMessage failed", err, m);
  }
}


function renderReactions(messageId, reactionsMap){
  reactionsCache[messageId] = reactionsMap || {};
  const counts = {};
  for(const u in reactionsCache[messageId]){
    const em = reactionsCache[messageId][u];
    counts[em]=(counts[em]||0)+1;
  }
  const container=document.getElementById("reacts-"+messageId);
  if(!container) return;
  container.innerHTML="";
  Object.entries(counts).forEach(([emoji,count])=>{
    const pill=document.createElement("div");
    pill.className="reactPill";
    pill.textContent=`${emoji} ${count}`;
    // Tap/click a reaction pill:
    // - If it's your current reaction, remove it.
    // - If it's someone else's (or you reacted with a different emoji), add yours (counts +1).
    pill.title = "React";
    pill.style.cursor = "pointer";
    pill.addEventListener("click", (e)=>{
      e.stopPropagation();
      let removing = false;
      if (me?.username) {
        const myKey = normKey(me.username);
        for (const user in reactionsCache[messageId] || {}) {
          if (normKey(user) === myKey) {
            removing = reactionsCache[messageId][user] === emoji;
            break;
          }
        }
      }
      triggerReactionBounce(pill, removing);
      socket?.emit("reaction", { messageId, emoji });
    });
    container.appendChild(pill);
  });

  const host = container.closest(".msgItem");
  if(host) host.classList.toggle("hasReacts", Object.keys(counts).length > 0);
}

function renderDmReactions(messageId, reactionsMap){
  dmReactionsCache[messageId] = reactionsMap || {};
  const counts = {};
  for (const u in dmReactionsCache[messageId]) {
    const em = dmReactionsCache[messageId][u];
    counts[em] = (counts[em] || 0) + 1;
  }
  const container = document.getElementById("dm-reacts-" + messageId);
  if (!container) return;
  container.innerHTML = "";
  Object.entries(counts).forEach(([emoji, count]) => {
    const pill = document.createElement("div");
    pill.className = "reactPill";
    pill.textContent = `${emoji} ${count}`;
    pill.title = "React";
    pill.style.cursor = "pointer";
    pill.addEventListener("click", (e)=>{
      e.stopPropagation();
      // Use current active DM thread id
      const tid = (window.activeDmId != null) ? Number(window.activeDmId) : null;
      if (!Number.isInteger(tid)) return;
      let removing = false;
      if (me?.username) {
        const myKey = normKey(me.username);
        for (const user in dmReactionsCache[messageId] || {}) {
          if (normKey(user) === myKey) {
            removing = dmReactionsCache[messageId][user] === emoji;
            break;
          }
        }
      }
      triggerReactionBounce(pill, removing);
      socket?.emit("dm reaction", { threadId: tid, messageId, emoji });
    });
    container.appendChild(pill);
  });

  const host = container.closest(".dmRow");
  if(host) host.classList.toggle("hasReacts", Object.keys(counts).length > 0);
}

function canDeleteMessage(isSelf){
  const myRole = me?.role || "User";
  const isModerator = roleRank(myRole) >= roleRank("Moderator");
  if (isModerator) return true;
  return isSelf && roleRank(myRole) >= roleRank("VIP");
}

function markMessageDeleting(row){
  if (!row) return;
  row.classList.add("message--deleting");
  row.dataset.deletePending = "1";
}

function clearMessageDeleting(row){
  if (!row) return;
  row.classList.remove("message--deleting");
  delete row.dataset.deletePending;
  delete row.dataset.deleteRemoving;
}

function removeMessageWithAnimation(row, onDone){
  if (!row || row.dataset.deleteRemoving === "1") return;
  row.dataset.deleteRemoving = "1";
  row.classList.add("message--deleting");
  let finished = false;
  const finish = () => {
    if (finished) return;
    finished = true;
    row.removeEventListener("transitionend", onEnd);
    if (row.isConnected) row.remove();
    if (onDone) onDone();
  };
  const onEnd = (e) => {
    if (e.target !== row) return;
    finish();
  };
  row.addEventListener("transitionend", onEnd);
  setTimeout(finish, DELETE_ANIM_MS + 80);
}

function removeFromMsgIndex(messageId){
  const idx = msgIndex.findIndex((x) => String(x.id) === String(messageId));
  if (idx !== -1) msgIndex.splice(idx, 1);
}

function cleanupEmptyMessageGroup(group){
  if(!group) return;
  const body = group.querySelector(".msgGroupBody");
  if(!body || !body.querySelector(".msgItem")) group.remove();
}

function handleMainMessageDeleted(messageId){
  removeFromMsgIndex(messageId);
  const row = document.querySelector(`[data-mid="${messageId}"]`);
  const group = row?.closest(".msgGroup");
  if (row) {
    removeMessageWithAnimation(row, () => {
      closeReactionMenu();
      cleanupEmptyMessageGroup(group);
    });
  }
  else closeReactionMenu();
}

function handleDmMessageDeleted(threadId, messageId){
  const midKey = String(messageId);
  delete dmReactionsCache[midKey];

  const tidKey = dmMessages.has(threadId) ? threadId : String(threadId);
  const arr = dmMessages.get(tidKey) || [];
  const idx = arr.findIndex((x) => String(x.messageId || x.id) === midKey);
  if (idx !== -1) {
    arr.splice(idx, 1);
    dmMessages.set(tidKey, arr);
  }

  const row = document.querySelector(`[data-dm-mid="${midKey}"]`);
  if (row) removeMessageWithAnimation(row);
}

function getSafeInsetPx(varName) {
  const raw = getComputedStyle(document.documentElement).getPropertyValue(varName);
  const parsed = parseFloat(raw);
  return Number.isFinite(parsed) ? parsed : 0;
}

function scheduleMemberMenuPosition() {
  if (!memberMenu?.classList.contains("open")) return;
  if (memberMenuRaf) return;
  memberMenuRaf = requestAnimationFrame(() => {
    memberMenuRaf = null;
    positionMemberMenu();
  });
}

function positionMemberMenu() {
  if (!memberMenu || !memberMenuAnchor || !memberMenuAnchor.isConnected) {
    closeMemberMenu();
    return;
  }

  const anchorRect = memberMenuAnchor.getBoundingClientRect();
  const viewport = window.visualViewport;
  const viewportWidth = viewport?.width ?? window.innerWidth;
  const viewportHeight = viewport?.height ?? window.innerHeight;
  if (anchorRect.bottom < 0 || anchorRect.top > viewportHeight) {
    closeMemberMenu();
    return;
  }

  const appRect = appRoot?.getBoundingClientRect() ?? { left: 0, top: 0 };
  memberMenu.style.visibility = "hidden";
  memberMenu.style.left = "0px";
  memberMenu.style.top = "0px";

  const menuRect = memberMenu.getBoundingClientRect();
  const menuWidth = menuRect.width;
  const menuHeight = menuRect.height;

  const safeTop = getSafeInsetPx("--safeT");
  const safeBottom = getSafeInsetPx("--safeB");
  const safeLeft = getSafeInsetPx("--safeL");
  const safeRight = getSafeInsetPx("--safeR");

  const pad = 12;
  const gap = 8;
  let left = anchorRect.right + gap;
  let top = anchorRect.top + (anchorRect.height / 2) - (menuHeight / 2);

  if (left + menuWidth + pad + safeRight > viewportWidth) {
    left = anchorRect.left - menuWidth - gap;
  }

  left = Math.min(Math.max(left, pad + safeLeft), viewportWidth - menuWidth - pad - safeRight);
  top = Math.min(Math.max(top, pad + safeTop), viewportHeight - menuHeight - pad - safeBottom);

  memberMenu.style.left = `${left - appRect.left}px`;
  memberMenu.style.top = `${top - appRect.top}px`;
  memberMenu.style.visibility = "";
}

function closeMemberMenu(){
  if (!memberMenu) return;
  memberMenu.classList.remove("open");
  memberMenuUser = null;
  memberMenuUsername = "";
  memberMenuAnchor = null;
  if (memberMenuRaf) {
    cancelAnimationFrame(memberMenuRaf);
    memberMenuRaf = null;
  }
}


// ---- Member quick-actions menu buttons
memberViewProfileBtn?.addEventListener("click", ()=>{
  const uname = (memberMenuUsername || memberMenuUser?.username || memberMenuUser?.name || "").trim();
  if (uname) openMemberProfile(uname);
  closeMemberMenu();
});
memberDmBtn?.addEventListener("click", ()=>{
  const uname = (memberMenuUsername || memberMenuUser?.username || memberMenuUser?.name || "").trim();

memberReferBtn?.addEventListener("click", ()=>{
  const target = (memberMenuUsername || memberMenuUser?.username || memberMenuUser?.name || "").trim();
  if(!target) return;
  const reason = prompt(`Referral reason for ${target}:`, "") || "";
  const clean = reason.trim();
  if(!clean){ return; }
  if(!confirmModeration("referral", target)) return;
  socket?.emit("referrals:create", { username: target, reason: clean }, (resp)=>{
    if(resp?.ok){
      toast?.(`Referral sent for ${target}.`);
    }else{
      toast?.(resp?.error || "Failed to send referral.");
    }
  });
  closeMemberMenu();
});

  if (uname) startDirectMessage(uname, memberMenuUser?.id ?? memberMenuUser?.userId ?? memberMenuUser?.user_id);
  closeMemberMenu();
});

function openMemberMenu(user, anchor){
  if (!memberMenu || !membersPane) {
    // Fallback if the quick-actions menu is unavailable
    const uname = user?.username || user?.name || "";
    if (uname) openMemberProfile(uname);
    return;
  }

  const anchorEl = anchor?.querySelector(".mName") || anchor;
  if (memberMenu.classList.contains("open") && memberMenuAnchor === anchorEl) {
    closeMemberMenu();
    return;
  }

  memberMenuUser = user;
  memberMenuUsername = user?.username || user?.name || "";
  memberMenuAnchor = anchorEl;
  // Show "Refer ban" for Moderators (they cannot ban directly)
  if(memberReferBtn){
    const isSelf = (memberMenuUsername && me?.username && memberMenuUsername.toLowerCase()===me.username.toLowerCase());
    memberReferBtn.style.display = (!isSelf && (me?.role==="Moderator")) ? "inline-flex" : "none";
  }
  if (memberMenuName) memberMenuName.textContent = `${roleIcon(user.role)} ${user.name}`;
  memberMenu.classList.add("open");
  scheduleMemberMenuPosition();
}

function updateGoldUI(){
  if (!memberGold) return;
  if (progression && progression.gold != null) {
    const g = Number(progression.gold || 0);
    memberGold.textContent = `Gold: ${g.toLocaleString()}`;
    memberGold.classList.add("show");
  } else {
    memberGold.classList.remove("show");
  }
}

function levelInfoClient(xpRaw){
  let xp = Math.max(0, Math.floor(Number(xpRaw) || 0));
  let level = 1;
  let remaining = xp;
  while (remaining >= level * 100) {
    remaining -= level * 100;
    level += 1;
  }
  const xpForNextLevel = level * 100;
  return { level, xpIntoLevel: remaining, xpForNextLevel };
}

function deriveProfileLevel(info){
  const levelVal = Number(info?.level);
  if (Number.isFinite(levelVal) && levelVal > 0) return levelVal;
  if (info && info.xp != null) return levelInfoClient(info.xp).level;
  return progression.level || 1;
}

function renderLevelProgress(data, isSelf){
  const info = data || progression || {};
  const levelVal = Number(info.level || progression.level || 1);
  if (levelBadge) levelBadge.textContent = `Level ${levelVal}`;

  const hasXp = isSelf && typeof info.xpIntoLevel === "number" && typeof info.xpForNextLevel === "number" && info.xpForNextLevel > 0;
  if (xpText) {
    xpText.style.display = "block";
    xpText.textContent = hasXp ? `XP: ${Math.max(0, info.xpIntoLevel || 0)} / ${info.xpForNextLevel}` : "XP hidden";
  }
  if (xpProgress) {
    const pct = hasXp ? Math.max(0, Math.min(100, ((info.xpIntoLevel || 0) / info.xpForNextLevel) * 100)) : 0;
    xpProgress.style.width = `${pct}%`;
  }
  if (xpNote) xpNote.style.display = hasXp ? "block" : "none";
}

function applyProgressionPayload(payload){
  if (!payload) return;
  const next = { ...progression };
  if (payload.gold != null) next.gold = Number(payload.gold || 0);
  if (payload.level != null) next.level = Number(payload.level) || next.level;
  if (payload.xp != null || payload.xpIntoLevel != null || payload.xpForNextLevel != null) {
    if (payload.xp != null) next.xp = Number(payload.xp || 0);
    if (payload.xpIntoLevel != null) next.xpIntoLevel = Number(payload.xpIntoLevel || 0);
    if (payload.xpForNextLevel != null) next.xpForNextLevel = Number(payload.xpForNextLevel || 100);

    if (payload.level == null && payload.xp != null) {
      const calc = levelInfoClient(payload.xp);
      next.level = calc.level;
      if (payload.xpIntoLevel == null) next.xpIntoLevel = calc.xpIntoLevel;
      if (payload.xpForNextLevel == null) next.xpForNextLevel = calc.xpForNextLevel;
    }
  }
  progression = next;
  updateGoldUI();
}

function showLevelToast(level){
  if (!levelToast || !levelToastText) return;
  clearTimeout(levelToastTimer);
  levelToastText.textContent = `Level ${level}!`;
  levelToast.classList.add("show");
  levelToastTimer = setTimeout(() => levelToast.classList.remove("show"), 3200);
}

function refreshModTargetOptions(users = lastUsers){
  if(!modUserSelect) return;
  const prev = modUserSelect.value;
  modUserSelect.innerHTML = "";
  const placeholder=document.createElement("option");
  placeholder.value="";
  placeholder.textContent = users && users.length ? "Select online member" : "No members online";
  modUserSelect.appendChild(placeholder);
  (users || []).forEach(u => {
    const opt=document.createElement("option");
    opt.value=u.name;
    opt.textContent=`${u.name} (${normalizeStatusLabel(u.status, "Online")})`;
    modUserSelect.appendChild(opt);
  });
  if(prev && Array.from(modUserSelect.options).some(o => o.value === prev)){
    modUserSelect.value = prev;
  }
}
function setModTarget(username){
  if(modUser) modUser.value = username || "";
  if(modUserSelect && username){
    const match = Array.from(modUserSelect.options).find(o => o.value === username);
    if(match) modUserSelect.value = username;
  }
}


function reorderCouplesInMembers(list){
  const users = Array.isArray(list) ? list.slice() : [];
  const byName = new Map(users.map(u => [u?.name, u]));
  const seen = new Set();
  const out = [];
  for (const u of users) {
    const name = u?.name;
    if (!name || seen.has(name)) continue;
    out.push(u);
    seen.add(name);
    const c = u?.couple;
    if (c && c.group && c.partner && byName.has(c.partner) && !seen.has(c.partner)) {
      const partnerUser = byName.get(c.partner);
      if (partnerUser && roleRank(partnerUser.role) === roleRank(u.role)) {
        out.push(partnerUser);
        seen.add(c.partner);
      }
    }
  }
  return (out.length === users.length) ? out : users;
}

function ensureIrisLolaPartnerAdjacency(list){
  if (!isIrisLolaThemeActive() || !isCoupleActiveState(couplesState)) return list;
  const meName = me?.username || "";
  const partnerName = getPartnerUsername(couplesState, getUserId(me));
  if (!meName || !partnerName) return list;
  const users = Array.isArray(list) ? list.slice() : [];
  let selfIdx = users.findIndex((u) => normalizeUserKey(u?.name) === normalizeUserKey(meName));
  let partnerIdx = users.findIndex((u) => normalizeUserKey(u?.name) === normalizeUserKey(partnerName));
  if (selfIdx === -1 || partnerIdx === -1) return list;
  const selfUser = users[selfIdx];
  const partnerUser = users[partnerIdx];
  if (!selfUser || !partnerUser) return list;
  if (roleRank(selfUser.role) !== roleRank(partnerUser.role)) return list;
  if (partnerIdx === selfIdx + 1) return users;
  const [partner] = users.splice(partnerIdx, 1);
  if (partnerIdx < selfIdx) selfIdx -= 1;
  users.splice(selfIdx + 1, 0, partner);
  return users;
}

function fmtDaysSince(ts){
  const t = Number(ts)||0;
  if (!t) return "";
  const days = Math.max(0, Math.floor((Date.now()-t)/86400000));
  return days === 1 ? "1 day" : `${days} days`;
}

function renderMembers(users){
  lastUsers = ensureIrisLolaPartnerAdjacency(reorderCouplesInMembers(users || []));
  cleanupRecentDiceRolls();
  refreshModTargetOptions(lastUsers);
  withFlip(memberList, "data-flip-key", () => {
    memberList.innerHTML="";
    const presentNames = new Set((lastUsers||[]).map(u=>u?.name).filter(Boolean));
    const themeActive = isIrisLolaThemeActive();
    const coupleActive = isCoupleActiveState(couplesState);
    const partnerName = getPartnerUsername(couplesState, getUserId(me));
    const showCoupleUi = themeActive && coupleActive && partnerName;
    const partnerKey = normalizeUserKey(partnerName || "");
    const meKey = normalizeUserKey(me?.username || "");
    const bothOnline = showCoupleUi && isUserOnlineByName(partnerName) && isUserOnlineByName(me?.username);
    const showTogetherGlow = shouldShowTogetherGlow(themeActive, coupleActive, bothOnline);
    let insertedMarker = false;
    lastUsers.forEach((u, idx)=>{
      updateRoleCache(u.username || u.name, u.role);
      if (u?.chatFx) updateUserFxMap(u.name, u.chatFx);
      const row=document.createElement("div");
      row.className="mItem";
      row.dataset.username = u.name;
      row.dataset.flipKey = u.name;
      const userKey = normalizeUserKey(u?.name || "");

      const av=document.createElement("div");
      av.className="mAvatar";
      applyAvatarMeta(av, { username: u.name, role: u.role, status: u.status });
      const partnerPresent = !!(u?.couple?.partner && presentNames.has(u.couple.partner));
      if (u?.couple?.aura && partnerPresent) av.classList.add("coupleAura");
      if (showTogetherGlow && (userKey === meKey || userKey === partnerKey)) {
        av.classList.add("irisLolaTogetherGlow");
      }
      av.appendChild(avatarNode(u.avatar, u.name, u.role));

      const dot=document.createElement("div");
      dot.className="dot";
      const statusLabel = normalizeStatusLabel(u.status, "Online");
      const statusDisplay = showCoupleUi ? formatIrisLolaStatusLabel(statusLabel, u?.name) : statusLabel;
      dot.style.background=statusDotColor(statusLabel);

      const meta=document.createElement("div");
      meta.className="mMeta";

      const name=document.createElement("div");
      name.className="mName";
      if (u?.couple?.badge && u?.couple?.partner) {
        const cb = document.createElement("span");
        cb.className = "coupleBadge";
        cb.title = `${u.couple.statusEmoji||"💜"} ${u.couple.statusLabel||"Linked"}: ${u.couple.partner}`;
        cb.textContent = String(u.couple.statusEmoji || "💜");
        name.appendChild(cb);
      }
      const ico = document.createElement("span");
      ico.className = "roleIco";
      ico.textContent = `${roleIcon(u.role)} `;
      const uname = document.createElement("span");
      uname.className = "unameText";
      uname.textContent = String(u.name || "");
      name.appendChild(ico);
      name.appendChild(uname);
      try{ applyNameFxToEl(uname, userFxMap[u.name] || u.chatFx || {}); }catch{}

      const sub=document.createElement("div");
      sub.className="mSub";
      sub.textContent=`${u.role} • ${statusDisplay}${u.mood?(" • "+u.mood):""}`;

      if (showCoupleUi && userKey === partnerKey) {
        row.classList.add("irisLolaPartnerRow");
      }

      meta.appendChild(name);
      meta.appendChild(sub);

      const vibes = sanitizeVibeTagsClient(u.vibe_tags);
      if (vibes.length) {
        const vibeRow = document.createElement("div");
        vibeRow.className = "vibeRow";
        vibes.forEach((v)=>{
          const chip = document.createElement("span");
          chip.className = "vibeChip mini";
          chip.textContent = formatVibeChipLabel(v);
          vibeRow.appendChild(chip);
        });
        meta.appendChild(vibeRow);
      }

      const roll = recentDiceRolls.get(normKey(u.name));
      if (roll && Date.now() - (roll.ts || 0) < 7000) {
        const rollRow = document.createElement("div");
        rollRow.className = "mRoll";
        rollRow.textContent = `Rolled ${diceFace(roll.value)}`;
        meta.appendChild(rollRow);
      }

      row.appendChild(av);
      row.appendChild(dot);
      row.appendChild(meta);

      row.onclick = (ev) => {
        ev.stopPropagation();
        openMemberMenu(u, row);
      };
      memberList.appendChild(row);
      if (!insertedMarker && showCoupleUi && userKey === meKey) {
        const nextUser = lastUsers[idx + 1];
        if (nextUser && normalizeUserKey(nextUser?.name) === partnerKey) {
          const marker = document.createElement("div");
          marker.className = "irisLolaCoupleMarker";
          marker.textContent = "💞";
          memberList.appendChild(marker);
          insertedMarker = true;
        }
      }
    });
  });
  updatePresenceAuras();
}

async function loadFriendsList(force=false){
  if (!force && !friendsDirty && Array.isArray(friendsCache)) return friendsCache;
  try {
    const res = await fetch('/api/friends/list');
    if (!res.ok) throw new Error(await res.text());
    const data = await res.json();
    friendsCache = Array.isArray(data?.friends) ? data.friends : [];
    friendsDirty = false;
    return friendsCache;
  } catch (e) {
    friendsCache = [];
    friendsDirty = true;
    return friendsCache;
  }
}

function setMembersViewMode(mode){
  membersViewMode = (mode === 'friends') ? 'friends' : 'room';
  if (memberPillRoom) memberPillRoom.classList.toggle('active', membersViewMode==='room');
  if (memberPillFriends) memberPillFriends.classList.toggle('active', membersViewMode==='friends');
  if (membersViewMode === 'friends') {
    loadFriendsList(true).then(renderFriendsList);
  } else {
    renderMembers(lastUsers);
  }
}

function renderFriendsList(list){
  const friends = Array.isArray(list) ? list : [];
  cleanupRecentDiceRolls();
  withFlip(memberList, 'data-flip-key', () => {
    memberList.innerHTML = '';
    if (!friends.length) {
      const empty = document.createElement('div');
      empty.className = 'emptyText';
      empty.textContent = 'No friends yet.';
      memberList.appendChild(empty);
      return;
    }

    friends.forEach((f) => {
      const row = document.createElement('div');
      row.className = 'mItem friendItem';
      row.dataset.username = f.username;
      row.dataset.flipKey = f.username;

      const av = document.createElement('div');
      av.className = 'mAvatar';
      av.appendChild(avatarNode(f.avatar, f.username, f.role || 'User'));

      const dot = document.createElement('div');
      dot.className = 'dot';
      const statusLabel = f.online ? 'Online' : 'Offline';
      dot.style.background = statusDotColor(statusLabel);
      applyAvatarMeta(av, { username: f.username, role: f.role || 'User', status: statusLabel });

      const meta = document.createElement('div');
      meta.className = 'mMeta';

      const name = document.createElement('div');
      name.className = 'mName';
      if (f.isFavorite) {
        const star = document.createElement('span');
        star.className = 'friendStar';
        star.textContent = '★';
        star.title = 'Favorite';
        name.appendChild(star);
      }
      const ico = document.createElement('span');
      ico.className = 'roleIco';
      ico.textContent = `${roleIcon(f.role)} `;
      const uname = document.createElement('span');
      uname.className = 'unameText';
      uname.textContent = f.username;
      name.appendChild(ico);
      name.appendChild(uname);

      const sub = document.createElement('div');
      sub.className = 'mSub';
      const where = f.online ? (f.currentRoom ? `• in ${displayRoomName(f.currentRoom)}` : '') : (f.lastSeen ? `• last seen ${fmtAbs(f.lastSeen)}` : '');
      sub.textContent = `${f.role || 'User'} • ${statusLabel} ${where}`.trim();

      meta.appendChild(name);
      meta.appendChild(sub);

      row.appendChild(av);
      row.appendChild(dot);
      row.appendChild(meta);

      row.onclick = (ev) => {
        ev.stopPropagation();
        openMemberMenu({ name: f.username, username: f.username, role: f.role || 'User', avatar: f.avatar, status: statusLabel }, row);
      };
      memberList.appendChild(row);
    });
  });
}



function cleanupRecentDiceRolls(maxAge = 7000){
  const now = Date.now();
  for (const [key, info] of recentDiceRolls.entries()) {
    if (!info?.ts || now - info.ts > maxAge) {
      recentDiceRolls.delete(key);
    }
  }
}

function noteDiceRoll(username, value){
  if (!username) return;
  const key = normKey(username);
  const payload = { value, ts: Date.now() };
  recentDiceRolls.set(key, payload);
  if (diceRollTimers.has(key)) clearTimeout(diceRollTimers.get(key));
  diceRollTimers.set(key, setTimeout(() => {
    recentDiceRolls.delete(key);
    diceRollTimers.delete(key);
    renderMembers(lastUsers);
  }, 6500));
  renderMembers(lastUsers);
}

async function loadProgression(){
  try{
    const res = await fetch("/api/me/progression");
    if(!res.ok) return;
    const data = await res.json();
    applyProgressionPayload(data);
  }catch{}
}

// Search filter
function applySearch(){
  const q = searchInput.value.trim().toLowerCase();
  if(!q){
    msgIndex.forEach(m => m.el.style.display = "");
    return;
  }
  msgIndex.forEach(m => {
    m.el.style.display = m.textLower.includes(q) ? "" : "none";
  });
}
searchInput.addEventListener("input", applySearch);

// drawers
function anyDrawerOpen(){
  return channelsPane?.classList.contains("open") || membersPane?.classList.contains("open");
}

const drawerTextSelectors = "input, textarea, select, [contenteditable='true'], [contenteditable='']";
function isDrawerTextTarget(target){
  if(!channelsPane || !target) return false;
  if(!(target instanceof HTMLElement)) return false;
  if(target.closest && target.closest(".bottomBar")) return false;
  return channelsPane.contains(target) && target.matches(drawerTextSelectors);
}

function setDrawerTypingMode(on){
  drawerTypingMode = !!on;
  if(channelsPane) channelsPane.classList.toggle("drawer-typing", drawerTypingMode);
}

function handleDrawerFocusIn(event){
  if(!isDrawerTextTarget(event.target)) return;
  if(drawerFocusOutTimer) clearTimeout(drawerFocusOutTimer);
  setDrawerTypingMode(true);
}

function handleDrawerFocusOut(){
  if(drawerFocusOutTimer) clearTimeout(drawerFocusOutTimer);
  drawerFocusOutTimer = setTimeout(()=>{
    const active = document.activeElement;
    const stillTyping = isDrawerTextTarget(active);
    setDrawerTypingMode(stillTyping);
  }, 120);
}

function setLeftDrawerOpen(isOpen){
  document.body.classList.toggle("drawer-left-open", !!isOpen);
}
function setRightDrawerOpen(isOpen){
  document.body.classList.toggle("drawer-right-open", !!isOpen);
}

function ensureDrawerOverlayClosed(){
  if(anyDrawerOpen()) return;
  drawerOverlay?.classList.remove("show");
}

// Keep CSS vars in sync so the DM panel can avoid covering the members pane on desktop.
function syncDesktopMembersWidth(){
  try{
    const root = document.documentElement;
    const isDesktop = window.matchMedia("(min-width: 981px)").matches;
    if (!isDesktop || !membersPane){
      root.style.setProperty("--membersW", "0px");
      return;
    }
    const cs = getComputedStyle(membersPane);
    if (cs.display === "none" || cs.visibility === "hidden"){
      root.style.setProperty("--membersW", "0px");
      return;
    }
    const r = membersPane.getBoundingClientRect();
    // If the drawer is off-canvas, treat it as closed.
    const onScreen = r.width > 0 && r.left < window.innerWidth && r.right > 0;
    root.style.setProperty("--membersW", onScreen ? `${Math.round(r.width)}px` : "0px");
  }catch{}
}
window.addEventListener("resize", syncDesktopMembersWidth);

// Drawer mode helper: only use the full-screen overlay on mobile/tablet.
function isMobileDrawerMode(){
  return window.matchMedia('(max-width: 980px)').matches;
}

function closeDrawers(){
  channelsPane?.classList.remove("open");
  membersPane?.classList.remove("open");
  drawerOverlay?.classList.remove("show");
  // When drawers close, let the mobile composer span full width again.
  document.body.classList.remove("drawer-left-open", "drawer-right-open");
  setDrawerTypingMode(false);
  closeMemberMenu();
  syncDesktopMembersWidth();
}

function maybeSpawnIrisLolaDrawerEaster(pane){
  try{
    if (!pane) return;
    if (!shouldUseIrisLolaCoupleUi()) return;
    if (!shouldAnimateAmbientEffects(PREFERS_REDUCED_MOTION)) return;
    const now = Date.now();
    if (now < irisLolaDrawerEasterCooldownUntil) return;
    // Rare: ~10% of opens, with a cooldown to avoid spam.
    if (Math.random() > 0.10) return;
    irisLolaDrawerEasterCooldownUntil = now + 18000; // 18s

    const star = document.createElement('span');
    star.className = 'irisLolaDrawerEasterStar';
    // Randomize a small corner region so it feels like it "pops" around.
    const x = 10 + Math.random() * 70; // %
    const y = 6 + Math.random() * 30;  // %
    star.style.setProperty('--dx', `${x}%`);
    star.style.setProperty('--dy', `${y}%`);
    pane.appendChild(star);
    setTimeout(()=>{ try{ star.remove(); }catch{} }, 1400);
  }catch{}
}
function openChannels(){
  // Desktop layouts render channels as a normal panel (not an off-canvas drawer).
  // If we show the mobile overlay on desktop, it will eat all taps and make UI feel “dead”.
  if(!isMobileDrawerMode()){
    closeDrawers();
    return;
  }
  // toggle
  if (channelsPane?.classList.contains('open')) { closeDrawers(); return; }

  membersPane?.classList.remove('open');
  channelsPane?.classList.add('open');
  drawerOverlay?.classList.add('show');
  maybeSpawnIrisLolaDrawerEaster(channelsPane);
  // Mobile: shift the fixed composer so it doesn't overlap the left drawer.
  document.body.classList.add('drawer-left-open');
  document.body.classList.remove('drawer-right-open');
  syncDesktopMembersWidth();
}

function openMembers(){
  if(!isMobileDrawerMode()){
    closeDrawers();
    return;
  }
  // toggle
  if (membersPane?.classList.contains('open')) { closeDrawers(); return; }

  channelsPane?.classList.remove('open');
  membersPane?.classList.add('open');
  drawerOverlay?.classList.add('show');
  maybeSpawnIrisLolaDrawerEaster(membersPane);
  // Mobile: shift the fixed composer so it doesn't overlap the right drawer.
  document.body.classList.add('drawer-right-open');
  document.body.classList.remove('drawer-left-open');
  syncDesktopMembersWidth();
}

openChannelsBtn?.addEventListener("click", openChannels);
openMembersBtn?.addEventListener("click", openMembers);
channelsPane?.addEventListener("focusin", handleDrawerFocusIn, true);
channelsPane?.addEventListener("focusout", handleDrawerFocusOut, true);

/* Outside tap close: use pointerdown (better on mobile) */
/* Outside tap close: only when the user taps the overlay itself (never the drawers). */
drawerOverlay?.addEventListener("pointerdown", (e) => {
  if(e.target !== drawerOverlay) return;
  closeDrawers();
}, { passive:true });
document.addEventListener("keydown", (e)=>{ if(e.key==="Escape") closeDrawers(); });
channelsCloseBtn?.addEventListener("click", closeDrawers);
membersCloseBtn?.addEventListener("click", closeDrawers);

// Safety: if the viewport crosses the desktop/mobile breakpoint, never leave the overlay active.
window.addEventListener('resize', () => {
  try{
    if(!isMobileDrawerMode()) closeDrawers();
    else ensureDrawerOverlayClosed();
  }catch{}
}, { passive:true });
window.addEventListener('pageshow', () => {
  try{
    ensureDrawerOverlayClosed();
    if(!isMobileDrawerMode()) closeDrawers();
  }catch{}
});

// dms (rebuilt)
let dmSettingsOpen = false;
function closeDmSettingsMenu(){
  dmSettingsOpen = false;
  dmSettingsMenu?.classList.remove("open");
  dmSettingsBtn?.setAttribute("aria-expanded", "false");
}
function toggleDmSettingsMenu(){
  if (!dmSettingsMenu) return;
  dmSettingsOpen = !dmSettingsOpen;
  dmSettingsMenu.classList.toggle("open", dmSettingsOpen);
  dmSettingsBtn?.setAttribute("aria-expanded", dmSettingsOpen ? "true" : "false");
}

function threadLabel(t){
  if (!t) return "Direct Message";

  // Prefer explicit "other user" if provided by the server.
  const otherUser = t.otherUser?.username || t.other_user?.username || null;
  if (!t.is_group && otherUser) return otherUser;

  // Fall back to participants / participantsDetail (case-insensitive vs me).
  const meKey = normKey(me?.username);
  const namesFromParticipants = Array.isArray(t.participants) ? t.participants : [];
  const namesFromDetail = Array.isArray(t.participantsDetail) ? t.participantsDetail.map(p => p?.username).filter(Boolean) : [];
  const all = [...namesFromParticipants, ...namesFromDetail].filter(Boolean);

  // Deduplicate, preserve order
  const seen = new Set();
  const parts = [];
  for (const n of all) {
    const k = normKey(n);
    if (!k || seen.has(k)) continue;
    seen.add(k);
    parts.push(n);
  }

  const others = parts.filter(p => normKey(p) !== meKey);

  if (t.title) return t.title;
  if (t.is_group) return others.join(", ") || "Group chat";
  return others[0] || otherUser || "Direct Message";
}

function lockBodyScroll(lock){
  document.body.classList.toggle("bodyLocked", !!lock);
}

function formatDmTime(ts){
  if (!ts) return "";
  return new Date(ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function threadAvatarNode(t){
  const wrap = document.createElement("div");
  wrap.className = "dmAvatar";
  wrap.appendChild(avatarNode(null, threadLabel(t), "member"));
  return wrap;
}

function syncDmTabUi(){
  dmTabs?.querySelectorAll("[data-dm-tab]")?.forEach((btn) => {
    const on = btn.dataset.dmTab === dmTab;
    btn.classList.toggle("active", on);
    btn.setAttribute("aria-selected", on ? "true" : "false");
  });
  if (dmCreateGroupBtn) dmCreateGroupBtn.style.display = dmTab === "group" ? "block" : "none";
}

function setDmViewMode(mode){
  const next = mode === "thread" ? "thread" : "inbox";
  dmViewMode = next;
  if (!dmPanel) return;
  dmPanel.classList.toggle("dmModeInbox", next === "inbox");
  dmPanel.classList.toggle("dmModeThread", next === "thread");
}

function setDmTab(tab){
  dmTab = tab === "group" ? "group" : "direct";
  syncDmTabUi();
  renderDmThreads();
}

setDmViewMode("inbox");

// Some deployments mount DM routes under /api (e.g. /api/dm/thread) while others use
// /dm directly. Try the likely variant first and fall back on 404.
async function dmFetch(url, options){
  const u = String(url || "");
  const tries = [];

  if (u.startsWith("/dm/")) {
    tries.push("/api" + u);
    tries.push(u);
  } else if (u.startsWith("/api/dm/")) {
    tries.push(u);
    tries.push(u.replace(/^\/api/, ""));
  } else {
    // Not a DM endpoint
    tries.push(u);
  }

  let lastRes;
  for (const candidate of tries) {
    try {
      const res = await fetch(candidate, options);
      lastRes = res;
      // Only fall back on 404 (route missing). Any other status should be surfaced.
      if (res && res.status !== 404) return res;
    } catch (e) {
      // Network errors: try next candidate, then rethrow at end.
      lastRes = null;
    }
  }
  if (!lastRes) throw new Error("Network error");
  return lastRes;
}

function renderThreadItem(t){
  const div = document.createElement("div");
  div.className = "dmItem" + (t.id === activeDmId ? " active" : "");
  const label = threadLabel(t);
  const preview = t.last_text ? String(t.last_text).slice(0, 80) : "No messages yet";
  if (!t.is_group) {
    const other = (t.participants || []).find((p) => p !== me?.username) || label;
    const meta = getUserMeta(other);
    div.dataset.username = normKey(meta.username || other);
    applyIdentityGlow(div, meta);
  }

  div.appendChild(threadAvatarNode(t));

  const meta = document.createElement("div");
  meta.className = "dmItemMeta";

  const top = document.createElement("div");
  top.className = "dmItemTop";
  const title = document.createElement("div");
  title.className = "name";
  title.textContent = label;
  // Apply username styling for direct-message thread labels (the "other" user's name).
  try {
    if (!t.is_group && !t.title) {
      const other = (t.participants || []).find((p) => p !== me?.username);
      if (other && userFxMap[other]) applyNameFxToEl(title, userFxMap[other]);
    }
  } catch {}
  const time = document.createElement("div");
  time.className = "dmItemTime";
  time.textContent = formatDmTime(t.last_ts);
  top.appendChild(title);
  top.appendChild(time);

  const bottom = document.createElement("div");
  bottom.className = "dmItemBottom";
  const prev = document.createElement("div");
  prev.className = "small preview";
  prev.textContent = preview;
  bottom.appendChild(prev);

  if (dmUnreadThreads.has(t.id)) {
    const unread = document.createElement("div");
    unread.className = "dmUnread";
    unread.textContent = "New";
    bottom.appendChild(unread);
  }

  meta.appendChild(top);
  meta.appendChild(bottom);

  div.appendChild(meta);
  div.onclick = () => openDmThread(t.id);
  return div;
}

function renderDirectThreads(){
  const list = (dmThreads || []).filter(isDirectThread);
  const stripEl = dmQuickStrip || dmStrip;
  if (!stripEl) return;

  withFlip(stripEl, "data-flip-key", () => {
    stripEl.innerHTML = "";
    if (list.length === 0) {
      updateDmThreadPlaceholderVisibility();
      return;
    }

    list.sort((a,b)=>(Number(b.last_ts||0)-Number(a.last_ts||0)));
    for (const t of list) {
      const other = otherParty(t) || threadLabel(t) || "?";

      // Resolve avatar from the DM thread payload first, then fall back to cached / profile fetch.
      const fromDetail = Array.isArray(t.participantsDetail)
        ? (t.participantsDetail.find(p => normKey(p?.username) === normKey(other)) || null)
        : null;
      const avatarUrl = t.otherUser?.avatar || fromDetail?.avatar || avatarCache?.[other] || null;

      const meta = getUserMeta(other);
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "dmThreadBtn";
      btn.dataset.threadId = t.id;
      btn.dataset.flipKey = `dm-thread-${t.id}`;
      if (String(t.id) === String(activeDmId)) btn.classList.add("active");

      const wrap = document.createElement("div");
      wrap.className = "dmThreadRow";
      wrap.dataset.username = normKey(meta.username || other);
      applyIdentityGlow(wrap, { username: meta.username || other, role: meta.role, vibe_tags: meta.vibe_tags, couple: meta.couple });

      const av = makeAvatarEl({
        username: meta.username || other,
        role: meta.role || "member",
        avatarUrl: meta.avatarUrl || avatarUrl || null,
        size: 34
      });
      av.classList.add("dmThreadAvatar");

      const body = document.createElement("div");
      body.className = "dmThreadBody";

      const top = document.createElement("div");
      top.className = "dmThreadTop";

      const name = document.createElement("div");
      name.className = "dmThreadName";
      name.textContent = other;

      const ts = document.createElement("div");
      ts.className = "dmThreadTs";
      ts.textContent = formatRelativeTime(t.last_ts || t.created_at);

      top.appendChild(name);
      top.appendChild(ts);

      const preview = document.createElement("div");
      preview.className = "dmThreadPreview";
      preview.textContent = (t.last_text || "").trim() || "—";

      body.appendChild(top);
      body.appendChild(preview);

      const badge = document.createElement("div");
      badge.className = "dmUnreadBadge";
      const uc = Number(t.unreadCount || 0);
      if (uc > 0) {
        badge.textContent = String(Math.min(99, uc));
        badge.classList.add("show");
      }

      wrap.appendChild(av);
      wrap.appendChild(body);
      wrap.appendChild(badge);
      btn.appendChild(wrap);

      btn.addEventListener("click", ()=>{
        hideAllDmQuickBars();
        openDmPanel();
        openDmThread(t.id);
      });

      // If we still don't have a URL, fetch in the background and update this thread avatar.
      if (other && !meta.avatarUrl && !avatarUrl) {
        getAvatarUrl(other).then((u)=>{
          if (!u) return;
          try{
            const img = av.querySelector("img.avatarImg");
            if (img) img.src = u;
            else {
              // rebuild avatar element with the fetched URL
              const repl = makeAvatarEl({ username: meta.username || other, role: meta.role || "member", avatarUrl: u, size: 34 });
              repl.classList.add("dmThreadAvatar");
              av.replaceWith(repl);
            }
          }catch{}
        }).catch(()=>{});
      }

      stripEl.appendChild(btn);
    }
  });

  updateDmThreadPlaceholderVisibility();
}

function vennPreview(thread){
  const wrap = document.createElement("div");
  wrap.className = "groupVenn";
  const parts = (thread.participants || []).filter(Boolean);
  const others = parts.filter((p)=>String(p).toLowerCase() !== String(me?.username||"").toLowerCase());
  const picks = (others.length ? others : parts).slice(0, 3);

  for (let i=0;i<3;i++) {
    const name = picks[i] || "?";
    const um = getUserMeta(name);
    const av = makeAvatarEl({ username: um.username || name, role: um.role, avatarUrl: um.avatarUrl, size: 30 });
    av.classList.add("vennAvatar", `v${i+1}`);
    wrap.appendChild(av);
  }
  return wrap;
}

function renderGroupThreads(){
  const list = (dmThreads || []).filter((t)=>!!t.is_group);
  const stripEl = groupQuickStrip;
  if (!stripEl) return;

  withFlip(stripEl, "data-flip-key", () => {
    stripEl.innerHTML = "";
    if (list.length === 0) {
      updateDmThreadPlaceholderVisibility();
      return;
    }
    list.sort((a,b)=>(Number(b.last_ts||0)-Number(a.last_ts||0)));

    for (const t of list) {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "dmAvatarBtn" + (String(activeDmId)===String(t.id) ? " active" : "");
      btn.title = threadLabel(t);
      btn.dataset.flipKey = `dm-group-${t.id}`;

      const badge = document.createElement("span");
      badge.className = "dmUnreadBadge";
      const lastRead = Number(dmLastRead[t.id] || 0);
      const lastTs = Number(t.last_ts || 0);
      const unread = dmUnreadThreads.has(t.id) || (lastTs > lastRead);
      badge.style.display = unread ? "block" : "none";

      const preview = vennPreview(t);
      preview.appendChild(badge);
      btn.appendChild(preview);

      btn.addEventListener("click", ()=>{
        hideAllDmQuickBars();
        openDmPanel();
        openDmThread(t.id);
      });
      stripEl.appendChild(btn);
    }
  });
  updateDmThreadPlaceholderVisibility();
}

function renderDmThreadList(){
  if (!dmThreadList) return;
  dmThreadList.innerHTML = "";
  const direct = (dmThreads || []).filter(isDirectThread);
  const groups = (dmThreads || []).filter((t)=>!!t.is_group);
  const sortByRecent = (a, b) => Number(b.last_ts || 0) - Number(a.last_ts || 0);

  if (!direct.length && !groups.length) {
    const empty = document.createElement("div");
    empty.className = "dmEmpty";
    empty.textContent = "No DM threads yet.";
    dmThreadList.appendChild(empty);
    return;
  }

  if (direct.length) {
    const title = document.createElement("div");
    title.className = "dmSectionTitle";
    title.textContent = "Direct messages";
    dmThreadList.appendChild(title);
    direct.sort(sortByRecent).forEach((t) => dmThreadList.appendChild(renderThreadItem(t)));
  }

  if (groups.length) {
    const title = document.createElement("div");
    title.className = "dmSectionTitle";
    title.textContent = "Group chats";
    dmThreadList.appendChild(title);
    groups.sort(sortByRecent).forEach((t) => dmThreadList.appendChild(renderThreadItem(t)));
  }
}

function renderDmThreads(){
  // Backwards-compatible entrypoint.
  renderDirectThreads();
  renderGroupThreads();
  renderDmThreadList();
}


async function loadDmThreads(){
  try {
    const res = await dmFetch("/dm/threads");
    if (!res.ok) {
      setDmNotice("Could not load threads.");
      return;
    }
    const raw = await res.json();

dmThreads = (raw || []).map((t) => ({ ...t, is_group: !!t.is_group }));

// Seed the avatar cache from DM thread payloads so DMs can render pfps immediately.
try{
  let touched = false;
  for (const t of dmThreads) {
    const detail = Array.isArray(t.participantsDetail) ? t.participantsDetail : [];
    for (const p of detail) {
      if (p?.username && p?.avatar && !avatarCache[p.username]) {
        avatarCache[p.username] = p.avatar;
        touched = true;
      }
    }
    if (t?.otherUser?.username && t?.otherUser?.avatar && !avatarCache[t.otherUser.username]) {
      avatarCache[t.otherUser.username] = t.otherUser.avatar;
      touched = true;
    }
  }
  if (touched) saveJson(AVATAR_CACHE_KEY, avatarCache);
}catch{}
    refreshDmBadgesFromThreads();
    syncDmTabUi();
    renderDmThreads();
  } catch {
    setDmNotice("Could not load threads.");
  }
}

function resolveParticipantIdsByNames(names = []){
  const ids = new Set();
  for (const name of names) {
    const key = normKey(name);
    const hit = (lastUsers || []).find((u) => normKey(u?.name || u?.username) === key);
    const id = Number(hit?.id ?? hit?.userId ?? hit?.user_id);
    if (Number.isInteger(id) && id > 0) ids.add(id);
  }
  return Array.from(ids);
}

async function startDirectMessage(username, targetId){
  if (!username) return;
  const target = String(username).trim();
  const meName = String(me?.username || "").trim();
  // Prevent starting a DM with yourself (case-insensitive, to survive server normalization).
  if (meName && target.toLowerCase() === meName.toLowerCase()) {
    setDmNotice("You can't start a DM with yourself.");
    return;
  }
  // If 'me' is not ready yet, don't attempt creation.
  if (!meName) {
    setDmNotice("Please wait a moment and try again.");
    return;
  }

  setDmTab("direct");
  openDmPanel();
  closeMemberMenu();

  if (!dmThreads.length) await loadDmThreads();

  const existing = dmThreads.find((t) => {
    if (t.is_group) return false;
    const parts = (t.participants || []).map((p)=>String(p||"").toLowerCase());
    return parts.includes(target.toLowerCase());
  });
  if (existing) {
    openDmThread(existing.id);
    return;
  }

  setDmNotice("Preparing chat...");
  try {
    const resolvedId = Number(targetId);
    const participantIds = Number.isInteger(resolvedId) && resolvedId > 0
      ? [resolvedId]
      : resolveParticipantIdsByNames([target]);

    const res = await dmFetch("/dm/thread", {
      method: "POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify({
        kind: "direct",
        participants: [target],
        participantIds,
      })
    });

    if (!res.ok) {
      const text = await res.text();
      setDmNotice(text || "Could not start DM.");
      toast?.(text || "Could not start DM.");
      return;
    }

    const data = await res.json();
    // Don't waste vertical space with a persistent "DM ready" banner.
    setDmNotice(data.reused ? "Opened existing DM." : "");

    if (data.threadId) {
      upsertThreadMeta(data.threadId, { participants: [target, meName].filter(Boolean), is_group: false });
      await loadDmThreads();
      openDmThread(data.threadId);
    }
  } catch {
    setDmNotice("Could not start DM.");
    toast?.("Could not start DM.");
  }
}

function openDmPanel(){
  dmPanel.classList.add("open");
  setDmNotice("");
  setDmViewMode("inbox");
  // Do not clear badges on open; only clear when a thread is actually read.
  syncDmTabUi();

  // load threads if we haven't yet
  if (!dmThreads.length) loadDmThreads();
  else renderDmThreads();
}

function closeDmPanel(){
  dmPanel.classList.remove("open");
  closeDmSettingsMenu();

  // Leaving the active DM prevents ongoing read receipts/badge suppression while the panel is closed.
  if (activeDmId) {
    try { socket?.emit("dm leave", { threadId: activeDmId }); } catch {}
  }
  activeDmId = null;
  activeDmUsers = new Set();
  updatePresenceAuras();
}


function renderDmMessages(threadId){
  if (!dmMessagesEl) return;

  const keepOffset = dmMessagesEl.scrollHeight - dmMessagesEl.scrollTop;
  const stick = isNearBottom(dmMessagesEl, 160);

  dmMessagesEl.innerHTML = "";
  const msgsArr = dmMessages.get(threadId) || [];
  const threadMeta = dmThreads.find(t => String(t.id) === String(threadId));

  // For read receipts, we only show "Seen" under the latest message YOU sent.
  let lastSelfMid = null;
  for (let j = msgsArr.length - 1; j >= 0; j--) {
    const mm = msgsArr[j];
    if (String(mm.user) === String(me?.username) && (mm.messageId || mm.id)) {
      lastSelfMid = (mm.messageId || mm.id);
      break;
    }
  }
  const rr = dmReadCache[String(threadId)] || null;
  const otherReadMid = (rr && me && rr.userId && String(rr.userId) !== String(me.id)) ? Number(rr.messageId) : null;


  if (!msgsArr.length) {
    const empty = document.createElement("div");
    empty.className = "dmEmpty";
    empty.textContent = "No messages yet. Say hi to save this thread.";
    dmMessagesEl.appendChild(empty);
    dmPinned = true;
    return;
  }

  for (let i = 0; i < msgsArr.length; i++) {
    const m = msgsArr[i];
    const isSelf = String(m.user) === String(me?.username);
    const authorName = resolveMessageAuthor(m);
    if (m?.chatFx) updateUserFxMap(authorName, m.chatFx);
    const resolvedFx = resolveChatFx(m, authorName);

    const prev = i > 0 ? msgsArr[i - 1] : null;
    const next = i < (msgsArr.length - 1) ? msgsArr[i + 1] : null;

    const samePrev = prev && String(prev.user) === String(m.user) && Math.abs((Number(m.ts)||0) - (Number(prev.ts)||0)) <= 2*60*1000;
    const sameNext = next && String(next.user) === String(m.user) && Math.abs((Number(next.ts)||0) - (Number(m.ts)||0)) <= 2*60*1000;

    // Group classes: start/mid/end/solo (used for meta + bubble tail)
    let gClass = " g-solo";
    if (samePrev && sameNext) gClass = " g-mid";
    else if (samePrev && !sameNext) gClass = " g-end";
    else if (!samePrev && sameNext) gClass = " g-start";


    const row = document.createElement("div");
    row.className = "dmRow" + (isSelf ? " self" : "") + gClass;
    row.dataset.dmMid = m.messageId || m.id;
    row.dataset.username = normKey(authorName || "");
    applyIdentityGlow(row, { username: authorName, role: m.role || roleForUser(authorName), vibe_tags: m?.vibe_tags, couple: m?.couple });
    const isPartner = isPartnerName(authorName);
    if (shouldUseIrisLolaCoupleUi() && !isSelf && isPartner) {
      row.classList.add("couple-partner-msg");
    }

// Avatar column (non-self). Keep spacing consistent for grouped messages.
const threadMeta = dmThreads.find(t => String(t.id) === String(threadId));
if (!isSelf) {
  const slot = document.createElement("div");
  slot.className = "dmAvatarSlot";

  const prevUserKey = normKey(prev?.user || prev?.username || resolveMessageAuthor(prev) || "");
  const curUserKey  = normKey(m?.user || m?.username || authorName || "");
  const showAvatar = !prev || prevUserKey !== curUserKey;

  if (showAvatar) {
    const fromDetail = Array.isArray(threadMeta?.participantsDetail)
      ? (threadMeta.participantsDetail.find(p => normKey(p?.username) === normKey(authorName)) || null)
      : null;

    const avatarUrl = threadMeta?.otherUser?.username && normKey(threadMeta.otherUser.username) === normKey(authorName)
      ? threadMeta.otherUser.avatar
      : (fromDetail?.avatar || avatarCache?.[authorName] || null);

    const meta = getUserMeta(authorName);

    const av = makeAvatarEl({
      username: meta.username || authorName,
      role: meta.role || "member",
      avatarUrl: meta.avatarUrl || avatarUrl || null,
      size: 30
    });
    av.classList.add("dmMsgAvatar");
    slot.appendChild(av);

    // Fetch avatar if we don't have it yet (background)
    if (authorName && !meta.avatarUrl && !avatarUrl) {
      getAvatarUrl(authorName).then((u)=>{
        if (!u) return;
        try{
          const img = av.querySelector("img.avatarImg");
          if (img) img.src = u;
          else {
            const repl = makeAvatarEl({ username: meta.username || authorName, role: meta.role || "member", avatarUrl: u, size: 30 });
            repl.classList.add("dmMsgAvatar");
            av.replaceWith(repl);
          }
        }catch{}
      }).catch(()=>{});
    }
  } else {
    slot.classList.add("empty");
    // Keep layout width but hide the avatar for grouped messages.
    slot.innerHTML = "<div class='dmAvatarSpacer'></div>";
  }

  row.appendChild(slot);
}

    // Actions bar (reveals below the bubble; does NOT reserve horizontal space)
    const actions = document.createElement("div");
    actions.className = "dmActionsBar";

    const reactBtn = document.createElement("button");
    reactBtn.type = "button";
    reactBtn.className = "iconBtn smallIcon";
    reactBtn.title = "React";
    reactBtn.textContent = "😀";
    reactBtn.onclick = (e) => {
      e.stopPropagation();
      openDmReactionMenu(threadId, (m.messageId || m.id), reactBtn, row);
    };

    const replyBtn = document.createElement("button");
    replyBtn.type = "button";
    replyBtn.className = "iconBtn smallIcon";
    replyBtn.title = "Reply";
    replyBtn.textContent = "↩️";
    replyBtn.onclick = (e) => {
      e.stopPropagation();
      setDmReplyTarget({ id: m.messageId || m.id, user: m.user, text: m.text });
      focusDmComposer();
    };

    actions.appendChild(reactBtn);
    actions.appendChild(replyBtn);
    // Edit (self, within 5 minutes)
    const canEdit = isSelf && Number(m.ts||0) && (Date.now() - Number(m.ts||0) <= 5*60*1000);
    if (canEdit) {
      const editBtn = document.createElement("button");
      editBtn.type = "button";
      editBtn.className = "iconBtn smallIcon";
      editBtn.title = "Edit";
      editBtn.textContent = "✏️";
      editBtn.onclick = (e) => {
        e.stopPropagation();
        startDmEdit(threadId, (m.messageId || m.id), m.text || "");
      };
      actions.appendChild(editBtn);
    }
    if (canDeleteMessage(isSelf)) {
      const delBtn = document.createElement("button");
      delBtn.type = "button";
      delBtn.className = "iconBtn smallIcon";
      delBtn.title = "Delete";
      delBtn.textContent = "🗑️";
      delBtn.onclick = (e) => {
        e.stopPropagation();
        const ok = confirm("Delete this message?");
        if (!ok) return;
        markMessageDeleting(row);
        const msgId = (m.messageId || m.id);
        socket?.emit("dm delete message", { threadId, messageId: msgId }, (res = {}) => {
          if (!res.ok) {
            clearMessageDeleting(row);
            addSystem(res.message || "Failed to delete message.");
            return;
          }
          handleDmMessageDeleted(threadId, msgId);
        });
      };
      actions.appendChild(delBtn);
    }

    // Bubble + meta
    const bubbleWrap = document.createElement("div");
    bubbleWrap.className = "dmBubbleWrap";

    const bubble = document.createElement("div");
    bubble.className = "dmBubble" + (isSelf ? " self" : "");
    applyChatFxToBubble(bubble, resolvedFx, { dmRow: row, dmWrap: bubbleWrap });

    if (m.replyToId && (m.replyToUser || m.replyToText)) {
      const replyLink = document.createElement("button");
      replyLink.type = "button";
      replyLink.className = "dmReplyContext";
      replyLink.innerHTML = `
        <div class="replyUser">@${escapeHtml(m.replyToUser || "")}</div>
        <div class="replySnippet">${escapeHtml((m.replyToText || "").slice(0, 120))}</div>
      `;
      replyLink.onclick = (e) => {
        e.stopPropagation();
        const target = dmMessagesEl.querySelector(`[data-dm-mid="${m.replyToId}"]`);
        if (target) target.scrollIntoView({ behavior: "smooth", block: "center" });
      };
      bubble.appendChild(replyLink);
    }

    const text = document.createElement("div");
    text.className = "dmText";
    text.innerHTML = applyMentions(m.text || "");
    bubble.appendChild(text);

    const attachmentPayload = m?.attachment?.url
      ? { url: m.attachment.url, type: m.attachment.type, mime: m.attachment.mime }
      : (m.attachmentUrl ? { url: m.attachmentUrl, type: m.attachmentType, mime: m.attachmentMime } : null);
    if (attachmentPayload) {
      const node = renderAttachmentNode(attachmentPayload);
      if (node) bubble.appendChild(node);
    }

    const meta = document.createElement("div");
    meta.className = "dmMetaRow";
    const u = document.createElement("span");
    u.className = "dmMetaUser";
    u.textContent = m.user || "";
    u.dataset.role = roleKey(m.role || roleForUser(m.user));

    if (gClass !== " g-start" && gClass !== " g-solo") {
      u.textContent = ""; // grouped: avoid repeating the username
      u.style.display = "none";
    }
    const t = document.createElement("span");
    t.className = "dmMetaTime";
    t.textContent = m.ts ? new Date(m.ts).toLocaleTimeString([], {hour:"2-digit", minute:"2-digit"}) : "";
    const tone = toneMeta(m.tone || m.toneKey);
    if (tone) {
      const toneEl = document.createElement("span");
      toneEl.className = "toneBadge";
      toneEl.textContent = tone.emoji;
      const toneLabel = `Tone: ${tone.name} — ${tone.description}`;
      toneEl.title = toneLabel;
      toneEl.setAttribute("aria-label", toneLabel);
      t.appendChild(toneEl);
    }

    const dmEditedAt = m.editedAt || m.edited_at || 0;
    if (dmEditedAt) {
      const ed = document.createElement("span");
      ed.className = "editedTag";
      ed.textContent = " (edited)";
      t.appendChild(ed);
    }
    meta.appendChild(u);
    meta.appendChild(t);

    const reacts = document.createElement("div");
    reacts.className = "reacts";
    reacts.id = "dm-reacts-" + (m.messageId || m.id);
    reacts.dataset.threadId = String(threadId);
    meta.appendChild(reacts);

    // Read receipt: show "Seen" only on your latest message, when the other user has marked it read.
    const midForSeen = (m.messageId || m.id);
    if (isSelf && lastSelfMid && String(midForSeen) === String(lastSelfMid) && otherReadMid && Number(otherReadMid) >= Number(midForSeen)) {
      const seen = document.createElement("span");
      seen.className = "dmSeen";
      seen.textContent = "Seen";
      meta.appendChild(seen);
    }

    bubbleWrap.appendChild(bubble);
    bubbleWrap.appendChild(meta);
    // Actions live below the meta (and do not affect horizontal alignment/width when closed)
    bubbleWrap.appendChild(actions);

    // If we already have reactions cached for this message, render them now.
    const midKey = String(m.messageId || m.id);
    if (dmReactionsCache[midKey]) renderDmReactions(midKey, dmReactionsCache[midKey]);

    // Only the bubble stack goes into the row (actions are inside bubbleWrap).
    row.appendChild(bubbleWrap);
    queueContrastReinforcement(bubble);

    // Mobile/desktop: tap/click the bubble to toggle actions (parity with main chat)
    const toggleActions = (e) => {
      if (e?.target?.closest("button, a, input, textarea, select, label")) return;
      if (e?.stopPropagation) e.stopPropagation();

      document.querySelectorAll(".dmRow.showActions").forEach((el) => {
        if (el !== row) el.classList.remove("showActions");
      });

      const on = row.classList.toggle("showActions");
      if (!on) closeReactionMenu();
    };

    bubble.addEventListener("click", toggleActions);
    bubble.addEventListener("touchstart", toggleActions, { passive:false });

    if (m.__fresh) {
      if (isPolishAnimationsEnabled()) {
        row.classList.add("msg-new");
        setTimeout(() => row.classList.remove("msg-new"), 220);
      }
      const variant = detectMessageImpactVariant(row, m.text || "");
      const isVip = roleRank(m.role || roleForUser(authorName)) >= roleRank("VIP");
      applyMessageImpactAnimation(row, { variant, isVip });
      delete m.__fresh;
    }
    dmMessagesEl.appendChild(row);
  }

  requestAnimationFrame(() => {
    if (stick) {
      dmMessagesEl.scrollTop = dmMessagesEl.scrollHeight;
    } else {
      dmMessagesEl.scrollTop = Math.max(0, dmMessagesEl.scrollHeight - keepOffset);
    }
    dmPinned = stick;
  });
}

function startDmEdit(threadId, messageId, currentText){
  const tid = String(threadId);
  const mid = String(messageId);
  // Find the row and bubble text
  const row = document.querySelector(`.dmRow[data-dm-mid="${mid}"]`);
  const textEl = row?.querySelector(".dmText");
  if (!row || !textEl) return;
  if (row.querySelector(".editBox")) return;

  textEl.style.display = "none";

  const box = document.createElement("div");
  box.className = "editBox";

  const ta = document.createElement("textarea");
  ta.value = String(currentText || "");
  ta.maxLength = 2000;
  ta.rows = 3;

  const r = document.createElement("div");
  r.className = "editRow";

  const cancel = document.createElement("button");
  cancel.type="button";
  cancel.textContent="Cancel";
  cancel.onclick=()=>{
    box.remove();
    textEl.style.display = "";
  };

  const save = document.createElement("button");
  save.type="button";
  save.textContent="Save";
  save.className="primary";
  save.onclick=()=>{
    const next = String(ta.value||"").trim();
    if(!next) return;
    socket?.emit("dm edit message", { threadId: tid, messageId: mid, text: next });
    box.remove();
    textEl.innerHTML = linkify(escapeHtml(next)).replace(/\n/g, "<br/>");
    textEl.style.display = "";
  };

  r.appendChild(cancel);
  r.appendChild(save);
  box.appendChild(ta);
  box.appendChild(r);

  const bubble = row.querySelector(".dmBubble");
  bubble?.appendChild(box);
  setTimeout(()=>ta.focus(), 0);
}


function setDmMeta(thread){
  if (!thread) {
    dmMetaTitle.textContent = "Pick a thread";
    dmMetaPeople.textContent = "";
    if (dmMetaAvatar) dmMetaAvatar.innerHTML = "";
    activeDmUsers = new Set();
    updatePresenceAuras();
    return;
  }

  dmMetaTitle.textContent = threadLabel(thread);

  const namesFromParticipants = Array.isArray(thread.participants) ? thread.participants : [];
  const namesFromDetail = Array.isArray(thread.participantsDetail) ? thread.participantsDetail.map(p => p?.username).filter(Boolean) : [];
  const names = [...namesFromParticipants, ...namesFromDetail].filter(Boolean);

  // Track who is "in" this DM for presence auras (exclude self)
  activeDmUsers = new Set(names.map(normKey));
  activeDmUsers.delete(normKey(me?.username));

  // "People" line
  dmMetaPeople.textContent = thread.is_group
    ? `${names.length} member${names.length === 1 ? "" : "s"}`
    : names.filter(n => normKey(n) !== normKey(me?.username)).join(", ");

  // Avatar in DM header:
  // - direct: other user's avatar
  // - group: stable fallback avatar
  if (dmMetaAvatar) {
    dmMetaAvatar.innerHTML = "";
    try{
      if (!thread.is_group) {
        const otherName = thread.otherUser?.username
          || (names.find(n => normKey(n) !== normKey(me?.username)) || null);

        const fromDetail = Array.isArray(thread.participantsDetail)
          ? (thread.participantsDetail.find(p => normKey(p?.username) === normKey(otherName)) || null)
          : null;

        const avatarUrl = thread.otherUser?.avatar || fromDetail?.avatar || avatarCache?.[otherName] || null;
        const meta = getUserMeta(otherName);

        const av = makeAvatarEl({
          username: meta.username || otherName || "?",
          role: meta.role || "member",
          avatarUrl: meta.avatarUrl || avatarUrl || null,
          size: 32
        });

        dmMetaAvatar.appendChild(av);

        // If we still don't have a URL, try fetching it in the background.
        if (otherName && !meta.avatarUrl && !avatarUrl) {
          getAvatarUrl(otherName).then((u) => {
            if (!u) return;
            // refresh only if still on same thread
            if (String(activeDmId) !== String(thread.id)) return;
            dmMetaAvatar.innerHTML = "";
            dmMetaAvatar.appendChild(makeAvatarEl({
              username: meta.username || otherName,
              role: meta.role || "member",
              avatarUrl: u,
              size: 32
            }));
          }).catch(()=>{});
        }
      } else {
        dmMetaAvatar.appendChild(makeAvatarEl({
          username: threadLabel(thread),
          role: "member",
          avatarUrl: null,
          size: 32
        }));
      }
    }catch{}
  }
}

function openDmThread(threadId){
  // persist draft for previous thread before switching
  saveDmDraft();

  // Leave previous thread room before switching
  if (activeDmId && String(activeDmId) !== String(threadId)) {
    try { socket?.emit("dm leave", { threadId: activeDmId }); } catch {}
  }
  activeDmId = threadId;
  loadDmDraft();

  const meta = dmThreads.find(t => String(t.id) === String(threadId));
  if (meta) setDmTab(meta.is_group ? "group" : "direct");
  setDmViewMode("thread");
  dmUnreadThreads.delete(threadId);
  renderDmThreads();
  setDmMeta(meta);
  if (meta) setBadgeVisibility(meta.is_group ? "group" : "direct", false);
  setDmReplyTarget(null);

  dmMessagesEl.innerHTML = "<div class='dmEmpty'>Loading...</div>";
  socket?.emit("dm join", { threadId });
}

async function deleteDmHistory(){
  if (!activeDmId) {
    setDmNotice("Pick a thread first.");
    return;
  }

  const meta = dmThreads.find((t) => String(t.id) === String(activeDmId));
  const label = meta ? threadLabel(meta) : "this DM";
  const ok = confirm(`Delete all messages in "${label}" for everyone?`);
  if (!ok) return;

  setDmNotice("Deleting history...");
  try {
    const res = await dmFetch(`/dm/thread/${activeDmId}/messages`, { method: "DELETE" });
    if (!res.ok) {
      const text = await res.text();
      setDmNotice(text || "Could not delete history.");
      return;
    }

    dmMessages.set(activeDmId, []);
    const thread = dmThreads.find((t) => String(t.id) === String(activeDmId));
    if (thread) {
      thread.last_text = "";
      thread.last_ts = null;
    }
    renderDmMessages(activeDmId);
    renderDmThreads();
    setDmNotice("History cleared.");
    closeDmSettingsMenu();
  } catch {
    setDmNotice("Could not delete history.");
  }
}

function upsertThreadMeta(tid, updater){
  const idx = dmThreads.findIndex(t => String(t.id) === String(tid));
  if (idx === -1) dmThreads.unshift({ id: tid, participants: [], ...updater });
  else dmThreads[idx] = { ...dmThreads[idx], ...updater };
  renderDmThreads();
}

function sendDmMessage(){
  if (!activeDmId) return;
  const txt = (dmText?.value || "").trim();
  const att = dmPendingAttachment;
  if (dmUploading && !att) return;
  if (!txt && !att) return;

  socket?.emit("dm message", {
    threadId: activeDmId,
    text: txt,
    replyToId: dmReplyTarget?.id || null,
    attachment: att ? { url: att.url, mime: att.mime, type: att.type, size: att.size } : null,
    tone: activeDmTone || ""
  });

  if (Sound.shouldSent()) Sound.cues.sent();

  dmText.value = "";
  dmPendingAttachment = null;
  setDmReplyTarget(null);
  activeDmTone = "";
  updateToneMenu(dmTonePicker, activeDmTone);
  // Clear any "ready" notice
  setDmNotice("");
}

function filteredDmCandidates(term, excludeList){
  const termNorm = normKey(term || "");
  const excluded = new Set((excludeList || []).map((n) => normKey(n)));
  const base = (lastUsers || []).filter((u) => {
    const statusLabel = normalizeStatusLabel(u.status, "Online");
    return statusLabel !== "Offline";
  });

  return base
    .filter((u) => !excluded.has(normKey(u.name)))
    .filter((u) => !termNorm || normKey(u.name).includes(termNorm))
    .sort((a, b) => a.name.localeCompare(b.name));
}

function renderDmPickerList(){
  if (!dmPickerList) return;
  dmPickerList.innerHTML = "";
  const candidates = filteredDmCandidates(dmModalSearch?.value || "", dmPickerExisting);

  if (!candidates.length) {
    const empty = document.createElement("div");
    empty.className = "dmEmpty";
    empty.textContent = "No members match.";
    dmPickerList.appendChild(empty);
    return;
  }

  for (const u of candidates) {
    const row = document.createElement("label");
    row.className = "dmPickerRow";
    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.checked = dmPickerSelection.has(u.name);
    checkbox.onchange = () => {
      if (checkbox.checked) dmPickerSelection.add(u.name); else dmPickerSelection.delete(u.name);
      syncDmPickerCta();
    };

    const avatarWrap = document.createElement("div");
    avatarWrap.className = "dmAvatar";
    avatarWrap.appendChild(avatarNode(u.avatar, u.name, u.role));

    const meta = document.createElement("div");
    meta.className = "dmItemMeta";
    const name = document.createElement("div");
    name.className = "dmPickerName";
    name.textContent = u.name;
    const sub = document.createElement("div");
    sub.className = "dmPickerSub";
    const statusLabel = normalizeStatusLabel(u.status, "Online");
    sub.textContent = `${u.role || ""} ${u.role ? "• " : ""}${statusLabel}`;
    meta.appendChild(name);
    meta.appendChild(sub);

    row.appendChild(checkbox);
    row.appendChild(avatarWrap);
    row.appendChild(meta);

    dmPickerList.appendChild(row);
  }
}

function syncDmPickerCta(){
  const count = dmPickerSelection.size;
  const min = dmPickerMode === "create" ? 2 : 1;
  const verb = dmPickerMode === "add" ? "Add" : "Create";
  if (dmModalPrimaryBtn) {
    dmModalPrimaryBtn.disabled = count < min;
    dmModalPrimaryBtn.textContent = verb;
  }
  if (dmModalSubtitle) dmModalSubtitle.textContent = dmPickerMode === "add"
    ? "Pick at least one person to invite"
    : "Pick at least two people";
}

function openDmPicker(mode = "create", threadId = null, existing = []){
  dmPickerMode = mode;
  dmPickerThreadId = threadId;
  dmPickerExisting = existing || [];
  dmPickerSelection = new Set();
  if (dmModalSearch) dmModalSearch.value = "";

  if (dmModalTitle) dmModalTitle.textContent = mode === "add" ? "Add members" : "Create group";
  syncDmPickerCta();
  renderDmPickerList();
  lockBodyScroll(true);
  dmPickerModal?.classList.add("show");
  dmModalSearch?.focus();
}

function closeDmPicker(){
  dmPickerModal?.classList.remove("show");
  lockBodyScroll(false);
}

async function submitDmPicker(){
  const names = Array.from(dmPickerSelection);
  if (!names.length) return;

  if (dmPickerMode === "add" && dmPickerThreadId) {
    await addMembersToGroup(dmPickerThreadId, names);
    return;
  }

  try {
    dmModalPrimaryBtn.disabled = true;
    const participantIds = resolveParticipantIdsByNames(names);
    const res = await dmFetch("/dm/thread", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        kind: "group",
        participants: names,
        participantIds,
        // Compatibility keys
        users: names.join(","),
      }),
    });
    dmModalPrimaryBtn.disabled = false;
    if (!res.ok) {
      const txt = await res.text();
      setDmNotice(txt || "Could not create group.");
      toast?.(txt || "Could not create group.");
      return;
    }
    const data = await res.json();
    closeDmPicker();
    await loadDmThreads();
    if (data.threadId) openDmThread(data.threadId);
  } catch {
    setDmNotice("Could not create group.");
    toast?.("Could not create group.");
  }
}

async function fetchDmInfo(threadId){
  const res = await dmFetch(`/dm/thread/${threadId}`);
  if (!res.ok) throw new Error("Failed info");
  return res.json();
}

async function openDmInfo(threadId = activeDmId){
  const meta = dmThreads.find((t) => String(t.id) === String(threadId));
  if (!meta || !meta.is_group) {
    setDmNotice("Group info is only available inside a group chat.");
    return;
  }
  try {
    const data = await fetchDmInfo(threadId);
    dmInfoTitle.textContent = data.title || threadLabel(meta);
    const names = data.participants || [];
    dmInfoSubtitle.textContent = `${names.length} member${names.length === 1 ? "" : "s"}`;
    dmInfoMembers.innerHTML = "";
    names.forEach((name) => {
      const row = document.createElement("div");
      row.className = "dmInfoMember";
      const avatar = document.createElement("div");
      avatar.className = "dmAvatar";
      avatar.appendChild(avatarNode(null, name, "member"));
      const label = document.createElement("div");
      label.textContent = name;
      row.appendChild(avatar);
      row.appendChild(label);
      dmInfoMembers.appendChild(row);
    });
    lockBodyScroll(true);
    dmInfoModal?.classList.add("show");
  } catch {
    setDmNotice("Could not load group info.");
  }
}

function closeDmInfo(){
  dmInfoModal?.classList.remove("show");
  lockBodyScroll(false);
}

async function addMembersToGroup(threadId, names){
  if (!names?.length) return;
  try {
    dmModalPrimaryBtn.disabled = true;
    const res = await dmFetch(`/dm/thread/${threadId}/participants`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ participants: names }),
    });
    dmModalPrimaryBtn.disabled = false;
    if (!res.ok) {
      setDmNotice((await res.text()) || "Could not add members.");
      return;
    }
    closeDmPicker();
    await loadDmThreads();
    openDmInfo(threadId);
  } catch {
    setDmNotice("Could not add members.");
  }
}

async function leaveGroup(threadId){
  const ok = confirm("Leave this group?");
  if (!ok) return;
  try {
    const res = await dmFetch(`/dm/thread/${threadId}/leave`, { method: "POST" });
    if (!res.ok) {
      setDmNotice((await res.text()) || "Could not leave group.");
      return;
    }
    dmThreads = dmThreads.filter((t) => t.id !== threadId);
    dmMessages.delete(threadId);
    dmUnreadThreads.delete(threadId);
    activeDmId = null;
    closeDmInfo();
    renderDmThreads();
    dmMetaTitle.textContent = "Pick a thread";
    dmMetaPeople.textContent = "";
    dmMessagesEl.innerHTML = "";
  } catch {
    setDmNotice("Could not leave group.");
  }
}

function hideAllDmQuickBars(){
  if (dmQuickBar) dmQuickBar.hidden = true;
  if (groupQuickBar) groupQuickBar.hidden = true;
}

async function toggleDmQuickBar(kind){
  // kind: "direct" | "group"
  const targetBar = kind === "group" ? groupQuickBar : dmQuickBar;
  if (!targetBar) return;

  // Toggle: if already open, close it.
  const willShow = targetBar.hidden;
  hideAllDmQuickBars();
  targetBar.hidden = !willShow;

  if (!willShow) return;

  // Ensure threads are loaded before rendering strips.
  if (!dmThreads.length) await loadDmThreads();
  if (kind === "group") renderGroupThreads();
  else renderDirectThreads();
}

dmToggleBtn?.addEventListener("click", () => { toggleDmQuickBar("direct"); });
groupDmToggleBtn?.addEventListener("click", () => { toggleDmQuickBar("group"); });

groupQuickStartBtn?.addEventListener("click", (e) => {
  e.stopPropagation();
  // Use the same group DM picker used inside the group DM panel
  hideAllDmQuickBars();
  openDmPicker("create");
});

function closeQuickBarsOnOutside(e){
  const t = e.target;
  const directOpen = dmQuickBar && !dmQuickBar.hidden;
  const groupOpen = groupQuickBar && !groupQuickBar.hidden;
  if (!directOpen && !groupOpen) return;

  if (dmToggleBtn?.contains(t) || groupDmToggleBtn?.contains(t)) return;
  if (dmQuickBar?.contains(t) || groupQuickBar?.contains(t)) return;

  hideAllDmQuickBars();
}

// Close the quick DM avatar strips when clicking/tapping outside of them.
// (Some mobile browsers can be flaky with pointer events, so listen to a few.)
document.addEventListener("pointerdown", closeQuickBarsOnOutside, true);
document.addEventListener("mousedown", closeQuickBarsOnOutside, true);
document.addEventListener("touchstart", closeQuickBarsOnOutside, { capture: true, passive: true });


// The DM panel is entered only after selecting a thread from the quick strip.
dmCreateGroupBtn?.addEventListener("click", () => openDmPicker("create"));
dmCloseBtn?.addEventListener("click", closeDmPanel);
dmBackBtn?.addEventListener("click", () => setDmViewMode("inbox"));
dmSendBtn?.addEventListener("click", sendDmMessage);
dmInfoBtn?.addEventListener("click", () => openDmInfo());
dmSettingsBtn?.addEventListener("click", (e) => {
  e.stopPropagation();
  toggleDmSettingsMenu();
});
dmDeleteHistoryBtn?.addEventListener("click", deleteDmHistory);
dmReportBtn?.addEventListener("click", () => {
  setDmNotice("Report feature coming soon.");
  closeDmSettingsMenu();
});
dmModalCloseBtn?.addEventListener("click", closeDmPicker);
dmModalCancelBtn?.addEventListener("click", closeDmPicker);
dmPickerModal?.addEventListener("click", (e) => { if (e.target === dmPickerModal) closeDmPicker(); });
dmModalPrimaryBtn?.addEventListener("click", submitDmPicker);
dmModalSearch?.addEventListener("input", () => { renderDmPickerList(); syncDmPickerCta(); });
dmInfoCloseBtn?.addEventListener("click", closeDmInfo);
dmInfoModal?.addEventListener("click", (e) => { if (e.target === dmInfoModal) closeDmInfo(); });
dmInfoAddBtn?.addEventListener("click", () => {
  const meta = dmThreads.find((t) => String(t.id) === String(activeDmId));
  const existing = meta?.participants || [];
  closeDmInfo();
  if (activeDmId) openDmPicker("add", activeDmId, existing);
});
dmLeaveBtn?.addEventListener("click", () => { if (activeDmId) leaveGroup(activeDmId); });

document.addEventListener("click", (e) => {
  if (!dmSettingsOpen) return;
  if (dmSettingsMenu?.contains(e.target)) return;
  if (dmSettingsBtn?.contains(e.target)) return;
  closeDmSettingsMenu();
});

dmNeonColorInput?.addEventListener("input", () => {
  dmNeonColor = dmNeonColorInput.value;
  if(dmNeonColorText) dmNeonColorText.value = dmNeonColorInput.value;
  applyDmNeonPrefs();
  saveDmNeonColorToStorage();
});
dmNeonColorText?.addEventListener("input", () => {
  const safe = sanitizeColor(dmNeonColorText.value, dmNeonColor, dmNeonDefaults.color);
  dmNeonColor = safe;
  applyDmNeonPrefs();
  saveDmNeonColorToStorage();
});

memberViewProfileBtn?.addEventListener("click", () => {
  const uname = (memberMenuUser?.username || memberMenuUser?.name || memberMenuUsername || "").trim();
  if (uname) openMemberProfile(uname);
  closeMemberMenu();
});

memberDmBtn?.addEventListener("click", () => {
  if (memberMenuUser) startDirectMessage(memberMenuUser.name, memberMenuUser?.id ?? memberMenuUser?.userId ?? memberMenuUser?.user_id);
});

document.addEventListener("click", (e) => {
  if (!memberMenu?.classList.contains("open")) return;
  if (memberMenu.contains(e.target)) return;
  if (e.target.closest(".mItem")) return;
  closeMemberMenu();
});
document.addEventListener("keydown", (e) => {
  if (e.key !== "Escape") return;
  if (memberMenu?.classList.contains("open")) closeMemberMenu();
});

const repositionMemberMenu = () => scheduleMemberMenuPosition();
membersPane?.addEventListener("scroll", repositionMemberMenu, { passive: true });
window.addEventListener("resize", repositionMemberMenu, { passive: true });
window.visualViewport?.addEventListener("resize", repositionMemberMenu, { passive: true });
window.visualViewport?.addEventListener("scroll", repositionMemberMenu, { passive: true });

mentionDropdown?.addEventListener("click", (e) => {
  const btn = e.target.closest("button[data-name]");
  if (!btn) return;
  acceptMention(mentionDropdown, btn.dataset.name || "");
});
dmMentionDropdown?.addEventListener("click", (e) => {
  const btn = e.target.closest("button[data-name]");
  if (!btn) return;
  acceptMention(dmMentionDropdown, btn.dataset.name || "");
});
document.addEventListener("click", (e) => {
  if (mentionDropdown && !mentionDropdown.contains(e.target) && e.target !== msgInput) {
    mentionDropdown.classList.remove("show");
  }
  if (dmMentionDropdown && !dmMentionDropdown.contains(e.target) && e.target !== dmText) {
    dmMentionDropdown.classList.remove("show");
  }
});

dmText?.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey) {
    e.preventDefault();
    sendDmMessage();
  }
});
dmText?.addEventListener("input", ()=>renderMentionDropdown(dmMentionDropdown, dmText));

// "Message" button on profile -> always direct DM
dmUserBtn?.addEventListener("click", () => {
  if (modalTargetUsername) {
    closeModal();
    startDirectMessage(modalTargetUsername, modalTargetUserId);
  }
});
profileEditBtn?.addEventListener("click", () => {
  if (!currentProfileIsSelf) return;
  setProfileEditMode(true);
  setTab("profile");
});
profileEditToggleBtn?.addEventListener("click", () => {
  if (!currentProfileIsSelf) return;
  setProfileEditMode(!profileEditMode);
});
profileSettingsBtn?.addEventListener("click", async () => {
  if (!currentProfileIsSelf) {
    if (modalTargetUsername) {
      closeModal();
      startDirectMessage(modalTargetUsername, modalTargetUserId);
    }
    return;
  }
  setTab("customize");
  try { syncSoundPrefsUI(true); } catch {}
  await loadChatFxPrefs({ force: true });
});

// unified media button
mediaBtn?.addEventListener("click", (e) => {
  // Dice Room keeps the "tap to roll" affordance
  if (isDiceRoom(currentRoom)) {
    e?.preventDefault();
    e?.stopPropagation();
    e?.stopImmediatePropagation();
    rollDiceImmediate(diceVariant);
    return;
  }
  toggleMediaMenu();
});

// close menu when clicking outside
document.addEventListener("pointerdown", (e) => {
  if (!mediaMenuOpen) return;
  const t = e.target;
  if (!t) return;
  if (mediaMenu?.contains(t) || mediaBtn?.contains(t)) return;
  closeMediaMenu();
}, { capture: true });

// menu actions
mediaMenuImage?.addEventListener("click", () => {
  closeMediaMenu();
  // images + videos share fileInput (validation will gate)
  fileInput?.click();
});
mediaMenuAudioUpload?.addEventListener("click", () => {
  closeMediaMenu();
  audioFileInput?.click();
});

diceVariantToggle?.addEventListener("click", (e) => {
  if (!isDiceRoom(currentRoom)) return;
  e.preventDefault();
  e.stopPropagation();
  if (dicePayoutOpen) closeDicePayout();
  toggleDiceVariantMenu();
});

diceVariantMenu?.addEventListener("click", (e) => {
  const btn = e.target.closest("[data-variant]");
  if (!btn) return;
  e.preventDefault();
  e.stopPropagation();
  const nextVariant = btn.dataset.variant;
  setDiceVariant(nextVariant);
  closeDiceVariantMenu();
});

document.addEventListener("pointerdown", (e) => {
  if (!diceVariantMenuOpen) return;
  const t = e.target;
  if (!t) return;
  if (diceVariantMenu?.contains(t) || diceVariantToggle?.contains(t)) return;
  closeDiceVariantMenu();
}, { capture:true });

async function startVoiceRecording(){
  if (voiceRec.recorder) return;
  if (!navigator.mediaDevices?.getUserMedia) {
    addSystem("Voice notes aren't supported on this browser.");
    return;
  }
  try {
    const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
    // Prefer iOS-friendly types when available
    const candidates = [
      "audio/mp4",      // iOS Safari often prefers this
      "audio/webm;codecs=opus",
      "audio/webm",
      "audio/ogg;codecs=opus",
    ];
    let mimeType = "";
    for (const t of candidates) {
      if (window.MediaRecorder && MediaRecorder.isTypeSupported?.(t)) { mimeType = t; break; }
    }
    const rec = new MediaRecorder(stream, mimeType ? { mimeType } : undefined);
    voiceRec = { recorder: rec, stream, chunks: [], startedAt: Date.now() };
    mediaVoiceLabel && (mediaVoiceLabel.textContent = "Stop");
    mediaMenuVoice?.classList.add("recording");
    rec.ondataavailable = (ev) => { if (ev.data && ev.data.size) voiceRec.chunks.push(ev.data); };
    rec.onstop = async () => {
      try {
        const blob = new Blob(voiceRec.chunks, { type: rec.mimeType || "audio/webm" });
        const ext = (rec.mimeType || "").includes("mp4") ? "m4a" : ((rec.mimeType || "").includes("ogg") ? "ogg" : "webm");
        const file = new File([blob], `voice-${Date.now()}.${ext}`, { type: blob.type });

        // Reuse your existing upload pipeline
        roomPendingAttachment = null;
        const validation = validateUploadFile(file);
        if (!validation.ok) {
          addSystem(validation.message || "Voice note not allowed.");
          return;
        }
        showUploadPreview(file);
        roomUploadToken = `${Date.now()}-${Math.random()}`;
        const token = roomUploadToken;
        setRoomUploadingState(true);
        const up = await uploadChatFileWithProgress(file);
        if (token !== roomUploadToken) return;
        roomPendingAttachment = { url: up.url, mime: up.mime, type: up.type, size: up.size };
        roomUploadToken = null;
        setRoomUploadingState(false);
        sendMessage();
      } catch (err) {
        addSystem(`Voice note upload failed: ${err?.message || "Upload failed."}`);
      }
    };
    rec.start();
    addSystem("🎙️ Recording… tap Voice again to stop.");
  } catch (e) {
    addSystem("Microphone permission denied.");
  }
}

function stopVoiceRecording(){
  try { voiceRec.recorder?.stop(); } catch {}
  try { voiceRec.stream?.getTracks?.().forEach(t=>t.stop()); } catch {}
  voiceRec.recorder = null;
  voiceRec.stream = null;
  voiceRec.chunks = [];
  voiceRec.startedAt = 0;
  mediaVoiceLabel && (mediaVoiceLabel.textContent = "Voice");
  mediaMenuVoice?.classList.remove("recording");
}

mediaMenuVoice?.addEventListener("click", async () => {
  // don't close menu while recording; toggle start/stop
  if (voiceRec.recorder) {
    stopVoiceRecording();
    closeMediaMenu();
    return;
  }
  await startVoiceRecording();
});

// upload preview

function inferMimeFromFilename(filename){
  const name = String(filename || "").toLowerCase();
  const ext = (name.includes(".") ? name.split(".").pop() : "").slice(0, 10);
  switch(ext){
    case "mp3": return "audio/mpeg";
    case "m4a": return "audio/mp4";
    case "aac": return "audio/aac";
    case "wav": return "audio/wav";
    case "ogg": return "audio/ogg";
    case "oga": return "audio/ogg";
    case "opus": return "audio/opus";
    case "webm": return "audio/webm";
    default: return "";
  }
}
function getFileExtension(filename){
  const name = String(filename || "").toLowerCase();
  return name.includes(".") ? name.split(".").pop() : "";
}
function normalizeSelectedFile(file){
  if(!file) return file;
  const mime = String(file.type || "");
  if(mime && mime !== "application/octet-stream") return file;
  const inferred = inferMimeFromFilename(file.name);
  if(!inferred) return file;
  try{
    return new File([file], file.name, { type: inferred, lastModified: file.lastModified });
  }catch{
    return file;
  }
}

function validateUploadFile(file){
  let mime = String(file?.type || "");
  if(!mime || mime === "application/octet-stream"){
    const inferred = inferMimeFromFilename(file?.name);
    if(inferred) mime = inferred;
  }
  const isImage = /^image\//i.test(mime);
  const isAudio = /^audio\//i.test(mime);
  const isVideo = /^video\//i.test(mime);
  if(!isImage && !isAudio && !isVideo){
    return { ok: false, message: "Only images, GIFs, audio, or videos are allowed." };
  }
  const maxBytes = isVideo ? MAX_VIDEO_BYTES : (isAudio ? MAX_AUDIO_BYTES : MAX_IMAGE_GIF_BYTES);
  if(file.size > maxBytes){
    const label = isVideo ? "video" : (isAudio ? "audio" : "image/GIF");
    return { ok: false, message: `Max ${label} size is ${bytesToNice(maxBytes)}.` };
  }
  return { ok: true, isImage, isAudio, isVideo, maxBytes };
}
function validateAudioUploadFile(file){
  const base = validateUploadFile(file);
  if (!base.ok) return base;
  if (!base.isAudio) {
    return { ok: false, message: "Audio upload supports MP3 or M4A only." };
  }
  let mime = String(file?.type || "");
  if(!mime || mime === "application/octet-stream"){
    const inferred = inferMimeFromFilename(file?.name);
    if(inferred) mime = inferred;
  }
  const ext = getFileExtension(file?.name);
  const mimeAllowed = AUDIO_UPLOAD_ALLOWED_MIME.has(mime);
  const extAllowed = AUDIO_UPLOAD_ALLOWED_EXT.has(ext);
  if (!mimeAllowed || !extAllowed) {
    return { ok: false, message: "Audio upload supports MP3 or M4A only." };
  }
  return base;
}
function setRoomUploadingState(isUploading){
  roomUploading = isUploading;
  if(sendBtn) sendBtn.disabled = isUploading;
}
function setDmUploadingState(isUploading){
  dmUploading = isUploading;
  if(dmSendBtn) dmSendBtn.disabled = isUploading;
}
function showUploadPreview(file){
  pendingFile = file;
  uploadPreview.style.display = "flex";
  uploadName.textContent = file.name;
  uploadInfo.textContent = `${bytesToNice(file.size)} • ${file.type || "unknown type"}`;
  uploadProgress.style.width = "0%";

  previewThumb.innerHTML = "";
  const url = URL.createObjectURL(file);

  if ((file.type || "").startsWith("image/")) {
    const img=document.createElement("img");
    img.src=url;
    img.onload=()=>URL.revokeObjectURL(url);
    previewThumb.appendChild(img);
  } else if ((file.type || "").startsWith("audio/")) {
    const a=document.createElement("audio");
    a.src=url; a.controls=true; a.preload="metadata";
    a.onloadeddata=()=>URL.revokeObjectURL(url);
    previewThumb.appendChild(a);
  } else if (file.type === "video/mp4" || file.type === "video/quicktime") {
    const v=document.createElement("video");
    v.src=url; v.muted=true; v.playsInline=true; v.preload="metadata";
    v.onloadeddata=()=>URL.revokeObjectURL(url);
    previewThumb.appendChild(v);
  } else {
    previewThumb.textContent="FILE";
    URL.revokeObjectURL(url);
  }
}
function clearUploadPreview(){
  pendingFile=null;
  uploadPreview.style.display="none";
  previewThumb.innerHTML="";
  uploadName.textContent="";
  uploadInfo.textContent="";
  uploadProgress.style.width="0%";
}
fileInput.addEventListener("change", () => {
  const fRaw=fileInput.files?.[0];
  const f=normalizeSelectedFile(fRaw);
  if(!f) return clearUploadPreview();
  roomPendingAttachment = null;
  const validation = validateUploadFile(f);
  if(!validation.ok){
    addSystem(validation.message || "File not allowed.");
    fileInput.value="";
    return clearUploadPreview();
  }
  showUploadPreview(f);
  roomUploadToken = `${Date.now()}-${Math.random()}`;
  const token = roomUploadToken;
  setRoomUploadingState(true);
  uploadChatFileWithProgress(f).then((up) => {
    if(token !== roomUploadToken) return;
    roomPendingAttachment = { url: up.url, mime: up.mime, type: up.type, size: up.size };
    roomUploadToken = null;
    setRoomUploadingState(false);
    sendMessage();
  }).catch((e) => {
    if(token !== roomUploadToken) return;
    roomUploadToken = null;
    setRoomUploadingState(false);
    addSystem(`Upload failed: ${e?.message || "Upload failed."}`);
  });
});

audioFileInput?.addEventListener("change", () => {
  const fRaw = audioFileInput.files?.[0];
  const f = normalizeSelectedFile(fRaw);
  if(!f) return clearUploadPreview();
  roomPendingAttachment = null;
  const validation = validateAudioUploadFile(f);
  if(!validation.ok){
    addSystem(validation.message || "File not allowed.");
    audioFileInput.value = "";
    return clearUploadPreview();
  }
  showUploadPreview(f);
  roomUploadToken = `${Date.now()}-${Math.random()}`;
  const token = roomUploadToken;
  setRoomUploadingState(true);
  uploadChatFileWithProgress(f, { uploadKind: "audio-upload" }).then((up) => {
    if(token !== roomUploadToken) return;
    roomPendingAttachment = { url: up.url, mime: up.mime, type: up.type, size: up.size };
    roomUploadToken = null;
    setRoomUploadingState(false);
    sendMessage();
  }).catch((e) => {
    if(token !== roomUploadToken) return;
    roomUploadToken = null;
    setRoomUploadingState(false);
    addSystem(`Upload failed: ${e?.message || "Upload failed."}`);
  }).finally(() => {
    try { audioFileInput.value = ""; } catch {}
  });
});
cancelUploadBtn.addEventListener("click", () => {
  if(uploadXhr){ uploadXhr.abort(); uploadXhr=null; addSystem("Upload canceled."); }
  fileInput.value="";
  try { audioFileInput.value=""; } catch {}
  try { if (voiceRec.recorder) stopVoiceRecording(); } catch {}
  roomUploadToken = null;
  roomPendingAttachment = null;
  setRoomUploadingState(false);
  clearUploadPreview();
});
function uploadChatFileWithProgress(file, options = {}){
  return new Promise((resolve,reject)=>{
    const form=new FormData();
    form.append("file", file);
    if (options?.uploadKind) form.append("uploadKind", String(options.uploadKind));
    const xhr=new XMLHttpRequest();
    uploadXhr=xhr;
    xhr.open("POST","/upload");
    xhr.responseType="json";
    xhr.upload.onprogress=(e)=>{
      if(!e.lengthComputable) return;
      const pct=Math.max(0,Math.min(100,(e.loaded/e.total)*100));
      uploadProgress.style.width=`${pct.toFixed(0)}%`;
    };
    xhr.onload=()=>{
      uploadXhr=null;
      if(xhr.status>=200 && xhr.status<300) return resolve(xhr.response);
      reject(new Error((xhr.response && xhr.response.message) || xhr.responseText || "Upload failed."));
    };
    xhr.onerror=()=>{ uploadXhr=null; reject(new Error("Upload failed.")); };
    xhr.onabort=()=>{ uploadXhr=null; reject(new Error("Upload canceled.")); };
    xhr.send(form);
  });
}

// tabs
function focusActiveTab(){
  if (window.matchMedia("(max-width: 760px)").matches) return;
  const active = document.querySelector(".tab.active");
  active?.scrollIntoView({ behavior:"smooth", inline:"center", block:"nearest" });
}

function setCustomizePage(category = null){
  activeCustomizePage = category;
  const isWide = window.matchMedia && window.matchMedia("(min-width: 900px)").matches;
  customizePages.forEach((page) => {
    const isActive = page.dataset.category === category;
    page.classList.toggle("active", isActive);
    page.style.display = isActive ? "block" : "none";
  });
  if (customizeCardGrid) customizeCardGrid.style.display = (isWide ? "grid" : (category ? "none" : "grid"));
  if (customizeSubpages) customizeSubpages.classList.toggle("showing", isWide ? true : !!category);
  const scrollHost = modal?.querySelector(".modalBody");
  if (scrollHost) scrollHost.scrollTop = 0;
}

function setTab(tab){
  activeProfileTab = tab;
  for(const el of document.querySelectorAll(".tab")){
    el.classList.toggle("active", el.dataset.tab===tab);
  }
  if (viewAccount) viewAccount.style.display = tab==="profile" ? "block" : "none";
  if (viewTimeline) viewTimeline.style.display = tab==="timeline" ? "block" : "none";
  if (viewCustom) viewCustom.style.display = tab==="customize" ? "block" : "none";
  if (viewMore) viewMore.style.display = tab==="actions" ? "block" : "none";
  if (tab !== "profile") setProfileEditMode(false);
  if (tab === "customize" && currentProfileIsSelf) setCustomizePage(activeCustomizePage || null);
  if (tab === "customize") {
    applyCustomizeVisibility();
    if (currentProfileIsSelf) {
      loadChatFxPrefs({ force: true }).catch(() => {});
    }
  }
  if (tab === "timeline") {
    // If the user hasn't enabled the feature yet, show a helpful message instead of a blank panel.
    if (!memoryEnabled) {
      try {
        if (memoryTimelineList) memoryTimelineList.innerHTML = "";
        if (memoryFeaturedSection) memoryFeaturedSection.style.display = "none";
        if (memoryEmptyState) memoryEmptyState.style.display = "";
        if (memoryTimelineMsg) {
          memoryTimelineMsg.textContent = "Enable Memory Timeline in your profile settings to start collecting memories.";
        }
      } catch {}
    } else {
      void loadMemories();
    }
  }
  syncProfileEditUi();
  focusActiveTab();
  const scrollHost = modal?.querySelector(".modalBody");
  if (scrollHost) scrollHost.scrollTop = 0;
}
tabCustomize?.addEventListener("click", ()=>setTab("customize"));
tabTimeline?.addEventListener("click", async () => {
  setTab("timeline");
  if (memoryEnabled) await loadMemories();
});

function applyCustomizeVisibility(){
  const showCustomize = currentProfileIsSelf;
  if (profileCustomEmpty) profileCustomEmpty.style.display = showCustomize ? "none" : "";
  if (customizeShell) customizeShell.style.display = showCustomize ? "" : "none";
  if (!showCustomize){
    setCustomizePage(null);
  }
}

function filterCustomize(query){
  const q = String(query || "").trim().toLowerCase();
  const cards = customizeCards.length ? customizeCards : [];
  cards.forEach((card) => {
    const text = (card.dataset.search || card.textContent || "").toLowerCase();
    card.hidden = !!q && !text.includes(q);
  });

  const items = Array.from(document.querySelectorAll("[data-customize-item]"));
  let matches = 0;
  items.forEach((item) => {
    const text = (item.dataset.search || item.textContent || "").toLowerCase();
    const hit = !q || text.includes(q);
    item.hidden = !hit;
    if (hit) matches += 1;
  });

  customizePages.forEach((page) => {
    if (!q) return;
    const pageItems = page.querySelectorAll("[data-customize-item]");
    const anyVisible = Array.from(pageItems).some((item) => !item.hidden);
    page.classList.toggle("hasMatches", anyVisible);
  });

  if (!q) {
    customizePages.forEach((page) => page.classList.remove("hasMatches"));
  }
  return matches;
}

customizeCards.forEach((card) => {
  card.addEventListener("click", () => {
    if (!currentProfileIsSelf) return;
    if (card.dataset.category === "themes") {
      openThemesModal();
      return;
    }
    setCustomizePage(card.dataset.category || null);
  });
});
customizeBackBtns.forEach((btn) => {
  btn.addEventListener("click", () => setCustomizePage(null));
});
customizeSearch?.addEventListener("input", () => {
  const value = customizeSearch.value;
  filterCustomize(value);
});

memoryFilterChips.forEach((chip) => {
  chip.addEventListener("click", async () => {
    const next = chip.dataset.filter || "all";
    if (memoryFilter === next) return;
    memoryFilter = next;
    updateMemoryFilterChips();
    await loadMemories({ force: true });
  });
});

// New profile edit menu + avatar action wiring
wireSoundPrefs();
wireComfortMode();
wireChatFxPrefs();
wireProfileAvatarActions();
wireHeaderGradientInputs();
tabProfile?.addEventListener("click", ()=>setTab("profile"));
tabActions?.addEventListener("click", async ()=>{
  setTab("actions");
  if (viewModeration?.style.display !== "none") await refreshLogs();
});

// modal open/close
function openModal(){
  if (!modal) return;
  modal.style.display="flex";
  modal.classList.remove("modal-closing");
  if (PREFERS_REDUCED_MOTION) {
    modal.classList.add("modal-visible");
    return;
  }
  requestAnimationFrame(() => {
    modal.classList.add("modal-visible");
  });
}
function closeModal(){
  if (!modal) return;
  modal.classList.remove("modal-visible");
  modal.classList.add("modal-closing");
  modalTargetUsername=null;
  modalTargetUserId=null;
  setProfileEditMode(false);
  setCustomizePage(null);
  quickModMsg.textContent="";
  modMsg.textContent="";
  logsMsg.textContent="";
  setMsgline(mediaMsg, "");
  if (customizeMsg) customizeMsg.textContent = "";
  if (PREFERS_REDUCED_MOTION) {
    modal.style.display="none";
    modal.classList.remove("modal-closing");
    return;
  }
  setTimeout(() => {
    modal.style.display="none";
    modal.classList.remove("modal-closing");
  }, 220);
}

// Couples popout modal (reuses the existing Couples nodes from the profile editor)
function dockCouplesIntoModal(){
  if (!couplesModalBody) return false;
  const couplesFieldEl = document.getElementById("couplesField");
  const couplesActiveEl = document.getElementById("couplesActiveBox");
  const couplesMsgEl = document.getElementById("couplesMsg");
  // If the profile modal isn't open yet (or these nodes aren't mounted),
  // don't open an empty Couples modal that looks "stuck" at the top.
  if (!couplesFieldEl || !couplesActiveEl) return false;

  if (!couplesModalDock) {
    couplesModalDock = {
      field: { el: couplesFieldEl, parent: couplesFieldEl.parentNode, next: couplesFieldEl.nextSibling },
      active: { el: couplesActiveEl, parent: couplesActiveEl.parentNode, next: couplesActiveEl.nextSibling },
      msg: couplesMsgEl ? { el: couplesMsgEl, parent: couplesMsgEl.parentNode, next: couplesMsgEl.nextSibling } : null,
    };
  }

  // Clear modal body then append the existing nodes (no duplicated IDs)
  couplesModalBody.innerHTML = "";
  couplesModalBody.appendChild(couplesFieldEl);
  couplesModalBody.appendChild(couplesActiveEl);
  if (couplesMsgEl) couplesModalBody.appendChild(couplesMsgEl);
  return true;
}

function undockCouplesFromModal(){
  if (!couplesModalDock) return;
  try {
    const d = couplesModalDock;
    if (d.field?.parent) d.field.parent.insertBefore(d.field.el, d.field.next || null);
    if (d.active?.parent) d.active.parent.insertBefore(d.active.el, d.active.next || null);
    if (d.msg?.parent) d.msg.parent.insertBefore(d.msg.el, d.msg.next || null);
  } catch {}
}

function openCouplesModal(){
  if (!couplesModal) return;
  const ok = dockCouplesIntoModal();
  if (!ok) {
    toast?.("Open your profile first to use Couples.");
    return;
  }
  try { couplesModal.hidden = false; } catch {}
  couplesModal.style.display = "flex";
  couplesModal.classList.remove("modal-closing");
  if (PREFERS_REDUCED_MOTION) {
    couplesModal.classList.add("modal-visible");
  } else {
    requestAnimationFrame(() => couplesModal.classList.add("modal-visible"));
  }
  // Refresh state so the popout shows the latest immediately
  try { refreshCouplesUI(); } catch {}
}

function closeCouplesModal(){
  if (!couplesModal) return;
  couplesModal.classList.remove("modal-visible");
  undockCouplesFromModal();

  if (PREFERS_REDUCED_MOTION) {
    couplesModal.style.display = "none";
    couplesModal.classList.remove("modal-closing");
    try { couplesModal.hidden = true; } catch {}
    return;
  }
  couplesModal.classList.add("modal-closing");
  setTimeout(() => {
    couplesModal.style.display = "none";
    couplesModal.classList.remove("modal-closing");
    try { couplesModal.hidden = true; } catch {}
  }, 140);
}

couplesBtn?.addEventListener("click", openCouplesModal);
couplesModalClose?.addEventListener("click", closeCouplesModal);
couplesModal?.addEventListener("click", (e) => {
  if (e.target === couplesModal) closeCouplesModal();
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && couplesModal && couplesModal.style.display !== "none") {
    closeCouplesModal();
  }
  if (e.key === "Escape" && roomManageModal && roomManageModal.style.display !== "none") {
    closeRoomManageModal();
  }
  if (e.key === "Escape" && roomCreateModal && roomCreateModal.style.display !== "none") {
    closeRoomCreateModal();
  }
  if (e.key === "Escape" && survivalNewSeasonModal && survivalNewSeasonModal.style.display !== "none") {
    closeSurvivalNewSeasonModal();
  }
  if (e.key === "Escape" && survivalRosterModal && survivalRosterModal.style.display !== "none") {
    closeSurvivalRosterModal();
  }
  if (e.key === "Escape" && survivalLogModal && survivalLogModal.style.display !== "none") {
    closeSurvivalLogModal();
  }
});

closeModalBtn.addEventListener("click", closeModal);
modal.addEventListener("click", (e)=>{ if(e.target===modal) closeModal(); });

survivalNewSeasonBtn?.addEventListener("click", openSurvivalNewSeasonModal);
survivalNewSeasonClose?.addEventListener("click", closeSurvivalNewSeasonModal);
survivalNewSeasonModal?.addEventListener("click", (e) => {
  if (e.target === survivalNewSeasonModal) closeSurvivalNewSeasonModal();
});
survivalSeasonStartBtn?.addEventListener("click", startSurvivalSeason);
survivalAdvanceBtn?.addEventListener("click", advanceSurvivalSeason);
survivalEndBtn?.addEventListener("click", endSurvivalSeason);
survivalRosterBtn?.addEventListener("click", openSurvivalRosterModal);
survivalRosterClose?.addEventListener("click", closeSurvivalRosterModal);
survivalRosterModal?.addEventListener("click", (e) => {
  if (e.target === survivalRosterModal) closeSurvivalRosterModal();
});
survivalLogBtn?.addEventListener("click", (e) => {
  survivalState.view = "log";
  renderSurvivalPanel();
  if (e?.shiftKey) openSurvivalLogModal();
});
survivalArenaBtn?.addEventListener("click", () => {
  survivalState.view = "arena";
  renderSurvivalPanel();
  renderSurvivalArena();
});
survivalLogClose?.addEventListener("click", closeSurvivalLogModal);
survivalLogModal?.addEventListener("click", (e) => {
  if (e.target === survivalLogModal) closeSurvivalLogModal();
});
survivalLogLoadBtn?.addEventListener("click", loadOlderSurvivalLog);
survivalLobbyBtn?.addEventListener("click", async () => {
  if (!me?.id) return;
  const isIn = (survivalState.lobbyUserIds || []).includes(Number(me.id));
  const endpoint = isIn ? "/api/survival/lobby/leave" : "/api/survival/lobby/join";
  try {
    await api(endpoint, { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
    const { res, text } = await api("/api/survival/lobby", { method: "GET" });
    if (res.ok) {
      const data = safeJsonParse(text, null);
      if (data && Array.isArray(data.user_ids)) {
        survivalState.lobbyUserIds = data.user_ids.map((x) => Number(x)).filter((x) => x > 0);
      }
    }
  } catch {}
  renderSurvivalArena();
});
survivalAutoRunBtn?.addEventListener("click", () => {
  if (!survivalAutoRunning) startSurvivalAutoRun();
  else stopSurvivalAutoRun();
});
survivalHistorySelect?.addEventListener("change", async (e) => {
  const val = e.target.value;
  if (!val) return;
  const payload = await loadSurvivalSeason(val);
  if (!payload) return;
  survivalState.selectedSeasonId = payload.season?.id || Number(val);
  applySurvivalPayload(payload, { replaceEvents: true });
  renderSurvivalLog(survivalLogModalList, survivalState.events);
  renderSurvivalRoster();
});
// Allow viewers to close the expanded log/map UI (system messages remain in chat).
survivalHideViewBtn?.addEventListener("click", () => {
  survivalState.view = "none";
  renderSurvivalPanel();
});


// rooms
function setActiveRoom(room){
  const wasDiceRoom = isDiceRoom(currentRoom);
  const wasSurvivalRoom = isSurvivalRoom(currentRoom);
  currentRoom = room;
  const nowDiceRoom = isDiceRoom(room);
  const nowSurvivalRoom = isSurvivalRoom(room);
  document.body.classList.toggle("dice-room", nowDiceRoom);
  document.body.classList.toggle("survival-room", nowSurvivalRoom);
  nowRoom.textContent = displayRoomName(room);
  roomTitle.textContent = displayRoomName(room);
  msgInput.placeholder = `Message ${displayRoomName(room)}`;
  loadRoomDraft();

  // Ensure room-specific UI doesn't leak into other rooms.
  if (diceVariantWrap) diceVariantWrap.style.display = nowDiceRoom ? "" : "none";
  if (luckMeter) luckMeter.style.display = nowDiceRoom ? "" : "none";
  if (survivalPanel) survivalPanel.hidden = !nowSurvivalRoom || survivalUiCollapsed;
  if (survivalMiniBtn) survivalMiniBtn.hidden = !nowSurvivalRoom || !survivalUiCollapsed;
  if (survivalLogFeed) survivalLogFeed.hidden = !nowSurvivalRoom || survivalUiCollapsed || survivalState.view !== "log";
  if (survivalArena) survivalArena.hidden = !nowSurvivalRoom || survivalUiCollapsed || survivalState.view !== "arena";
  // If a modal is open that is built around room/profile context, close it when switching rooms.
  try {
    if (couplesModal && couplesModal.style.display && couplesModal.style.display !== "none") closeCouplesModal();
  } catch {}
  try {
    if (survivalRosterModal && survivalRosterModal.style.display && survivalRosterModal.style.display !== "none") closeSurvivalRosterModal();
  } catch {}
  try {
    if (survivalLogModal && survivalLogModal.style.display && survivalLogModal.style.display !== "none") closeSurvivalLogModal();
  } catch {}
  try {
    if (survivalNewSeasonModal && survivalNewSeasonModal.style.display && survivalNewSeasonModal.style.display !== "none") closeSurvivalNewSeasonModal();
  } catch {}


  // Dice Room: swap media button to dice roll
  try { closeMediaMenu(); } catch {}
  try { closeDiceVariantMenu(); } catch {}
  if (mediaBtn) {
    if (nowDiceRoom) {
      mediaBtn.textContent = "🎲";
      mediaBtn.title = "Roll Dice";
    } else {
      mediaBtn.textContent = "＋";
      mediaBtn.title = "Media";
    }
  }
  if (wasDiceRoom && !nowDiceRoom) {
    resetDiceSessionStats();
    try { closeDicePayout(); } catch {}
  }
  if (nowDiceRoom) {
    renderLuckMeter();
    requestLuckState();
  }
  if (wasSurvivalRoom && !nowSurvivalRoom) {
    stopSurvivalAutoRun();
  }
  if (nowSurvivalRoom) {
    loadSurvivalCurrent();
  }
  document.querySelectorAll(".chan").forEach(el=>{
    el.classList.toggle("active", el.dataset.room === room);
  });
}

let activeRoomEvent = null;
let roomEventTimer = null;

function updateRoomEventBanner(){
  if(!roomEventBanner) return;
  if(!getFeatureFlag("roomEvents", true) || !activeRoomEvent || !activeRoomEvent.endsAt){
    roomEventBanner.hidden = true;
    roomEventBanner.innerHTML = "";
    if(roomEventTimer){ clearInterval(roomEventTimer); roomEventTimer=null; }
    return;
  }
  roomEventBanner.hidden = false;
  const leftMs = Math.max(0, Number(activeRoomEvent.endsAt) - Date.now());
  const leftSec = Math.ceil(leftMs/1000);
  const mm = Math.floor(leftSec/60);
  const ss = String(leftSec%60).padStart(2,"0");
  roomEventBanner.innerHTML = `
    <div class="meta">
      <span class="tag">${escapeHtml(String(activeRoomEvent.type||"event"))}</span>
      <span>${escapeHtml(String(activeRoomEvent.title||"Room Event"))}</span>
      <span class="count">• ${mm}:${ss}</span>
    </div>
  `;
}

function setRoomEvent(ev){
  activeRoomEvent = ev || null;
  updateRoomEventBanner();
  if(roomEventTimer){ clearInterval(roomEventTimer); roomEventTimer=null; }
  if(activeRoomEvent && activeRoomEvent.endsAt){
    roomEventTimer = setInterval(updateRoomEventBanner, 1000);
  }
}

function joinRoom(room){
  room = sanitizeRoomClient(room) || "main";
  saveRoomDraft();

  setActiveRoom(room);
  clearMsgs();
  socket?.emit("join room", { room, status: normalizeStatusLabel(statusSelect.value, "Online") });
  closeDrawers();
}
chanList.addEventListener("click", (e)=>{
  const masterToggle = e.target.closest("[data-room-master-toggle]");
  if(masterToggle){
    const masterId = masterToggle.dataset.roomMasterToggle;
    const wrapper = masterToggle.closest(".roomMaster");
    if(wrapper){
      const collapsed = !wrapper.classList.contains("collapsed");
      wrapper.classList.toggle("collapsed", collapsed);
      roomCollapseState.master[String(masterId)] = collapsed;
      persistRoomMasterCollapse(masterId, collapsed);
    }
    return;
  }
  const categoryToggle = e.target.closest("[data-room-category-toggle]");
  if(categoryToggle){
    const categoryId = categoryToggle.dataset.roomCategoryToggle;
    const wrapper = categoryToggle.closest(".roomCategory");
    if(wrapper){
      const collapsed = !wrapper.classList.contains("collapsed");
      wrapper.classList.toggle("collapsed", collapsed);
      roomCollapseState.category[String(categoryId)] = collapsed;
      persistRoomCategoryCollapse(categoryId, collapsed);
    }
    return;
  }
  const el=e.target.closest(".chan");
  if(!el) return;
  const r=el.dataset.room;
  if(r && r!==currentRoom) joinRoom(r);
});
function sanitizeRoomClient(r){
  r = String(r || "").trim().replace(/^#+/, "").toLowerCase();
  r = r.replace(/[^a-z0-9_-]/g, "").slice(0,24);
  return r;
}

function normalizeRoomStructurePayload(payload){
  if(!payload || typeof payload !== "object") return null;
  const masters = Array.isArray(payload.masters) ? payload.masters : [];
  const categories = Array.isArray(payload.categories) ? payload.categories : [];
  const rooms = Array.isArray(payload.rooms) ? payload.rooms : [];
  const userCollapse = payload.userCollapse && typeof payload.userCollapse === "object" ? payload.userCollapse : null;
  return { masters, categories, rooms, userCollapse };
}

function cleanCollapseMap(raw){
  if(!raw || typeof raw !== "object") return {};
  const out = {};
  for(const [key, val] of Object.entries(raw)){
    out[String(key)] = !!val;
  }
  return out;
}

function setRoomStructure(payload, { updateCollapse = true } = {}){
  const normalized = normalizeRoomStructurePayload(payload);
  if(!normalized) return false;
  roomStructure = {
    masters: normalized.masters,
    categories: normalized.categories,
    rooms: normalized.rooms,
  };
  if(updateCollapse && normalized.userCollapse){
    roomCollapseState = {
      master: cleanCollapseMap(normalized.userCollapse.master),
      category: cleanCollapseMap(normalized.userCollapse.category),
    };
  }
  renderRoomsList(roomStructure);
  if(roomManageModal && roomManageModal.style.display !== "none" && !roomManageModal.hidden){
    refreshRoomManageUi();
  }
  return true;
}

function sortByOrderThenName(a, b, orderKey){
  const diff = Number(a?.[orderKey] || 0) - Number(b?.[orderKey] || 0);
  if(diff !== 0) return diff;
  return String(a?.name || "").localeCompare(String(b?.name || ""), undefined, { sensitivity: "base" });
}

function ensureDefaultMasters(masters){
  const out = [...masters];
  const byName = new Map(out.map((m) => [String(m.name || ""), m]));
  if(!byName.has("Site Rooms")){
    out.push({ id: "temp-site", name: "Site Rooms", sort_order: 0, temporary: true });
  }
  if(!byName.has("User Rooms")){
    out.push({ id: "temp-user", name: "User Rooms", sort_order: 1, temporary: true });
  }
  return out;
}

function ensureUncategorized(categories, masterId){
  const existing = categories.find((c) => String(c.master_id) === String(masterId) && String(c.name || "") === "Uncategorized");
  if(existing) return existing;
  return { id: `temp-uncat-${masterId}`, master_id: masterId, name: "Uncategorized", sort_order: 0, temporary: true };
}

function getDefaultMasterIds(masters){
  const site = masters.find((m) => String(m.name || "") === "Site Rooms");
  const user = masters.find((m) => String(m.name || "") === "User Rooms");
  return { site: site?.id, user: user?.id };
}

function renderRoomsList(structureOrRooms){
  if(Array.isArray(structureOrRooms)){
    withFlip(chanList, "data-flip-key", () => {
      chanList.innerHTML = "";
      for(const r of structureOrRooms || []){
        const div = document.createElement("div");
        div.className = "chan" + (r === currentRoom ? " active" : "");
        div.dataset.room = r;
        div.dataset.flipKey = `room-${r}`;
        div.textContent = displayRoomName(r);
        chanList.appendChild(div);
      }
    });
    return;
  }

  const payload = normalizeRoomStructurePayload(structureOrRooms) || { masters: [], categories: [], rooms: [] };
  const masters = ensureDefaultMasters(payload.masters || []);
  const categories = payload.categories || [];
  const rooms = payload.rooms || [];
  const categoriesByMaster = new Map();
  const categoryById = new Map();
  for(const cat of categories){
    if(!cat) continue;
    const masterId = cat.master_id;
    if(!categoriesByMaster.has(masterId)) categoriesByMaster.set(masterId, []);
    categoriesByMaster.get(masterId).push(cat);
    categoryById.set(String(cat.id), cat);
  }

  const masterIds = getDefaultMasterIds(masters);
  const fallbackCategories = new Map();
  for(const master of masters){
    const ensured = ensureUncategorized(categories, master.id);
    fallbackCategories.set(String(master.id), ensured);
    if(!categoriesByMaster.has(master.id)) categoriesByMaster.set(master.id, []);
    if(ensured.temporary) categoriesByMaster.get(master.id).push(ensured);
  }

  const roomsByCategory = new Map();
  for(const room of rooms){
    const categoryId = room?.category_id;
    if(categoryId && categoryById.has(String(categoryId))){
      if(!roomsByCategory.has(String(categoryId))) roomsByCategory.set(String(categoryId), []);
      roomsByCategory.get(String(categoryId)).push(room);
      continue;
    }

    const isUserRoom = Number(room?.is_user_room || 0) === 1;
    const fallbackMasterId = isUserRoom ? masterIds.user : masterIds.site;
    const fallbackCategory = fallbackCategories.get(String(fallbackMasterId));
    if(!fallbackCategory) continue;
    const fallbackId = String(fallbackCategory.id);
    if(!roomsByCategory.has(fallbackId)) roomsByCategory.set(fallbackId, []);
    roomsByCategory.get(fallbackId).push({ ...room, category_id: fallbackCategory.id });
  }

  withFlip(chanList, "data-flip-key", () => {
    chanList.innerHTML = "";
    const sortedMasters = [...masters].sort((a, b) => sortByOrderThenName(a, b, "sort_order"));
    const activeMasterName = getRoomModeMasterName();
    for(const master of sortedMasters){
      // Only show the active master (Site Rooms vs User Rooms) via the pill switcher.
      if(String(master?.name || "") !== String(activeMasterName)) continue;
      const masterId = master.id;
      const masterWrap = document.createElement("div");
      masterWrap.className = "roomMaster";
      masterWrap.dataset.masterId = masterId;
      if(roomCollapseState.master[String(masterId)]) masterWrap.classList.add("collapsed");

      const masterHeader = document.createElement("button");
      masterHeader.type = "button";
      masterHeader.className = "roomMasterHeader";
      masterHeader.dataset.roomMasterToggle = String(masterId);
      masterHeader.innerHTML = `
        <span class="roomHeaderLabel">
          <span class="roomChevron">▾</span>
          <span>${escapeHtml(master.name || "Rooms")}</span>
        </span>
      `;

      const masterBody = document.createElement("div");
      masterBody.className = "roomMasterBody";

      const masterCategories = (categoriesByMaster.get(masterId) || [])
        .sort((a, b) => sortByOrderThenName(a, b, "sort_order"));

      for(const category of masterCategories){
        const categoryId = category.id;
        const categoryWrap = document.createElement("div");
        categoryWrap.className = "roomCategory";
        categoryWrap.dataset.categoryId = categoryId;
        if(roomCollapseState.category[String(categoryId)]) categoryWrap.classList.add("collapsed");

        const categoryHeader = document.createElement("button");
        categoryHeader.type = "button";
        categoryHeader.className = "roomCategoryHeader";
        categoryHeader.dataset.roomCategoryToggle = String(categoryId);
        categoryHeader.innerHTML = `
          <span class="roomHeaderLabel">
            <span class="roomChevron">▾</span>
            <span>${escapeHtml(category.name || "Category")}</span>
          </span>
        `;

        const categoryBody = document.createElement("div");
        categoryBody.className = "roomCategoryBody";
        const roomList = document.createElement("div");
        roomList.className = "roomList";
        const categoryRooms = (roomsByCategory.get(String(categoryId)) || [])
          .sort((a, b) => sortByOrderThenName(a, b, "room_sort_order"));

        for(const r of categoryRooms){
          const name = r?.name || r;
          if(!name) continue;
          const div = document.createElement("div");
          div.className = "chan" + (name === currentRoom ? " active" : "");
          div.dataset.room = name;
          div.dataset.flipKey = `room-${name}`;
          div.textContent = displayRoomName(name);
          roomList.appendChild(div);
        }

        categoryBody.appendChild(roomList);
        categoryWrap.appendChild(categoryHeader);
        categoryWrap.appendChild(categoryBody);
        masterBody.appendChild(categoryWrap);
      }

      // With the pill switcher we only ever show one master at a time,
      // so we render its categories directly without a redundant master dropdown header.
      masterWrap.classList.add("roomMasterSingle");
      masterWrap.appendChild(masterBody);
      chanList.appendChild(masterWrap);
    }
  });
}

async function loadRooms(){
  const {res, text} = await api("/rooms", { method:"GET" });
  if(!res.ok){
    renderRoomsList((roomStructure.rooms || []).map((r) => r?.name || r).filter(Boolean));
    return;
  }
  try{
    const payload = JSON.parse(text);
    const applied = setRoomStructure(payload);
    if(!applied && Array.isArray(payload)) renderRoomsList(payload);
  }catch{
    renderRoomsList((roomStructure.rooms || []).map((r) => r?.name || r).filter(Boolean));
  }
}

function openRoomCreateModal(){
  if(!roomCreateModal) return;
  if(roomCreateMsg) roomCreateMsg.textContent = "";
  if(roomCreateNameInput) roomCreateNameInput.value = "";
  populateRoomCreateSelects();
  roomCreateModal.hidden = false;
  roomCreateModal.style.display = "flex";
  roomCreateModal.classList.remove("modal-closing");
  if(PREFERS_REDUCED_MOTION){
    roomCreateModal.classList.add("modal-visible");
  }else{
    requestAnimationFrame(()=> roomCreateModal.classList.add("modal-visible"));
  }
  requestAnimationFrame(()=> roomCreateNameInput?.focus?.());
}

function closeRoomCreateModal(){
  if(!roomCreateModal) return;
  roomCreateModal.classList.remove("modal-visible");
  if(PREFERS_REDUCED_MOTION){
    roomCreateModal.style.display = "none";
    roomCreateModal.hidden = true;
    return;
  }
  roomCreateModal.classList.add("modal-closing");
  setTimeout(()=>{
    roomCreateModal.style.display = "none";
    roomCreateModal.hidden = true;
    roomCreateModal.classList.remove("modal-closing");
  }, 140);
}

async function submitCreateRoom(){
  const raw = String(roomCreateNameInput?.value || "");
  const name = sanitizeRoomClient(raw);
  if(!name){
    if(roomCreateMsg) roomCreateMsg.textContent = "Invalid room name.";
    return;
  }
  const masterId = roomCreateMasterSelect?.value || "";
  const categoryId = roomCreateCategorySelect?.value || "";
  const payload = { name };
  if(categoryId) payload.category_id = Number(categoryId) || categoryId;
  if(masterId) payload.master_id = Number(masterId) || masterId;

  const {res, text} = await api("/rooms", {
    method:"POST",
    headers: {"Content-Type":"application/json"},
    body: JSON.stringify(payload),
  });
  if(!res.ok){
    if(roomCreateMsg) roomCreateMsg.textContent = text || "Failed to create room.";
    return;
  }
  closeRoomCreateModal();
  await loadRooms();
  joinRoom(name);
}

async function createRoomFlow(){
  if(roomCreateModal){
    openRoomCreateModal();
    return;
  }
  const raw = prompt("New room name (letters/numbers/_/-):");
  if(!raw) return;
  const name = sanitizeRoomClient(raw);
  if(!name){ addSystem("Invalid room name."); return; }

  const {res, text} = await api("/rooms", {
    method:"POST",
    headers: {"Content-Type":"application/json"},
    body: JSON.stringify({ name })
  });
  if(!res.ok){
    addSystem(text || "Failed to create room.");
    return;
  }

  await loadRooms();
  joinRoom(name);
}

function getSortedMasters({ includeTemporary = true } = {}){
  const masters = ensureDefaultMasters(roomStructure.masters || []);
  const sorted = [...masters].sort((a, b) => sortByOrderThenName(a, b, "sort_order"));
  if(includeTemporary) return sorted;
  return sorted.filter((m) => !m.temporary && !String(m.id || "").startsWith("temp-"));
}

function getSortedCategories(masterId, { includeTemporary = true } = {}){
  const categories = (roomStructure.categories || []).filter((c) => String(c.master_id) === String(masterId));
  let list = [...categories].sort((a, b) => sortByOrderThenName(a, b, "sort_order"));
  const ensured = ensureUncategorized(list, masterId);
  if(!list.find((c) => String(c.name || "") === "Uncategorized")) list = [...list, ensured];
  list.sort((a, b) => sortByOrderThenName(a, b, "sort_order"));
  if(includeTemporary) return list;
  return list.filter((c) => !c.temporary && !String(c.id || "").startsWith("temp-"));
}

function getSortedRoomsForCategory(categoryId){
  const rooms = (roomStructure.rooms || []).filter((r) => String(r.category_id) === String(categoryId));
  return [...rooms].sort((a, b) => sortByOrderThenName(a, b, "room_sort_order"));
}

function populateSelect(el, options, selectedValue){
  if(!el) return;
  el.innerHTML = "";
  for(const opt of options){
    const option = document.createElement("option");
    option.value = opt.value;
    option.textContent = opt.label;
    if(String(opt.value) === String(selectedValue)) option.selected = true;
    el.appendChild(option);
  }
}

function populateRoomCreateSelects(){
  const masters = getSortedMasters();
  const defaultMaster = masters.find((m) => m.name === "Site Rooms") || masters[0];
  const masterId = roomCreateMasterSelect?.value || defaultMaster?.id || "";
  populateSelect(
    roomCreateMasterSelect,
    masters.map((m) => ({ value: m.id, label: m.name })),
    masterId
  );
  const categories = masterId ? getSortedCategories(masterId) : [];
  const defaultCategory = categories.find((c) => c.name === "Uncategorized") || categories[0];
  populateSelect(
    roomCreateCategorySelect,
    categories.map((c) => ({ value: c.id, label: c.name })),
    defaultCategory?.id || ""
  );
}

function populateManageMasterSelects(){
  const masters = getSortedMasters({ includeTemporary: false });
  populateSelect(
    roomCategoryMasterSelect,
    masters.map((m) => ({ value: m.id, label: m.name })),
    roomCategoryMasterSelect?.value || masters[0]?.id || ""
  );
  populateSelect(
    roomManageMasterSelect,
    masters.map((m) => ({ value: m.id, label: m.name })),
    roomManageMasterSelect?.value || masters[0]?.id || ""
  );
  populateManageCategorySelects();
}

function populateManageCategorySelects(){
  const masterId = roomManageMasterSelect?.value || "";
  const categories = masterId ? getSortedCategories(masterId, { includeTemporary: false }) : [];
  populateSelect(
    roomManageCategorySelect,
    categories.map((c) => ({ value: c.id, label: c.name })),
    roomManageCategorySelect?.value || categories[0]?.id || ""
  );
}

function renderRoomMasterList(){
  if(!roomMasterList) return;
  const masters = getSortedMasters({ includeTemporary: false });
  roomMasterList.innerHTML = "";
  for(const master of masters){
    const row = document.createElement("div");
    row.className = "roomManageRow";
    const isDefault = master.name === "Site Rooms" || master.name === "User Rooms";
    row.innerHTML = `
      <div class="label">${escapeHtml(master.name)}</div>
      <div class="actions">
        <button class="btn secondary" data-action="rename">Rename</button>
        <button class="btn secondary" data-action="up">Up</button>
        <button class="btn secondary" data-action="down">Down</button>
        <button class="btn danger" data-action="delete">Delete</button>
      </div>
    `;
    if(isDefault){
      row.querySelectorAll("[data-action='rename'], [data-action='delete']").forEach((btn) => { btn.disabled = true; });
    }
    const actions = row.querySelector(".actions");
    actions?.addEventListener("click", async (e) => {
      const btn = e.target.closest("button");
      if(!btn) return;
      const action = btn.dataset.action;
      if(action === "rename"){
        const next = prompt("Rename master:", master.name);
        if(!next) return;
        await api(`/api/room-masters/${master.id}`, {
          method:"PATCH",
          headers: { "Content-Type":"application/json" },
          body: JSON.stringify({ name: next })
        });
      }
      if(action === "delete"){
        if(!confirm(`Delete master "${master.name}"? Rooms will move to Site Rooms.`)) return;
        await api(`/api/room-masters/${master.id}`, { method:"DELETE" });
      }
      if(action === "up" || action === "down"){
        const index = masters.findIndex((m) => String(m.id) === String(master.id));
        const swapWith = action === "up" ? index - 1 : index + 1;
        if(swapWith < 0 || swapWith >= masters.length) return;
        const orderedIds = [...masters].map((m) => m.id);
        [orderedIds[index], orderedIds[swapWith]] = [orderedIds[swapWith], orderedIds[index]];
        await api("/api/room-masters/reorder", {
          method:"PATCH",
          headers: { "Content-Type":"application/json" },
          body: JSON.stringify({ orderedIds })
        });
      }
      await loadRooms();
    });
    roomMasterList.appendChild(row);
  }
}

function renderRoomCategoryList(){
  if(!roomCategoryList) return;
  const masterId = roomCategoryMasterSelect?.value || "";
  const masters = getSortedMasters({ includeTemporary: false });
  const categories = masterId ? getSortedCategories(masterId, { includeTemporary: false }) : [];
  roomCategoryList.innerHTML = "";
  for(const category of categories){
    const row = document.createElement("div");
    row.className = "roomManageRow";
    const isDefault = String(category.name || "") === "Uncategorized";
    const masterOptions = masters.map((m) => `<option value="${m.id}">${escapeHtml(m.name)}</option>`).join("");
    row.innerHTML = `
      <div class="label">${escapeHtml(category.name)}</div>
      <select class="roomManageMoveSelect">${masterOptions}</select>
      <div class="actions">
        <button class="btn secondary" data-action="rename">Rename</button>
        <button class="btn secondary" data-action="up">Up</button>
        <button class="btn secondary" data-action="down">Down</button>
        <button class="btn secondary" data-action="move">Move</button>
        <button class="btn danger" data-action="delete">Delete</button>
      </div>
    `;
    const moveSelect = row.querySelector(".roomManageMoveSelect");
    if(moveSelect) moveSelect.value = masterId;
    if(isDefault && moveSelect) moveSelect.disabled = true;
    if(isDefault){
      row.querySelectorAll("[data-action='rename'], [data-action='delete'], [data-action='move']")
        .forEach((btn) => { btn.disabled = true; });
    }
    const actions = row.querySelector(".actions");
    actions?.addEventListener("click", async (e) => {
      const btn = e.target.closest("button");
      if(!btn) return;
      const action = btn.dataset.action;
      if(action === "rename"){
        const next = prompt("Rename subcategory:", category.name);
        if(!next) return;
        await api(`/api/room-categories/${category.id}`, {
          method:"PATCH",
          headers: { "Content-Type":"application/json" },
          body: JSON.stringify({ name: next })
        });
      }
      if(action === "delete"){
        if(!confirm(`Delete subcategory "${category.name}"?`)) return;
        await api(`/api/room-categories/${category.id}`, { method:"DELETE" });
      }
      if(action === "move"){
        const targetMaster = moveSelect?.value || "";
        if(!targetMaster || targetMaster === String(masterId)) return;
        await api(`/api/room-categories/${category.id}`, {
          method:"PATCH",
          headers: { "Content-Type":"application/json" },
          body: JSON.stringify({ master_id: Number(targetMaster) || targetMaster })
        });
      }
      if(action === "up" || action === "down"){
        const index = categories.findIndex((c) => String(c.id) === String(category.id));
        const swapWith = action === "up" ? index - 1 : index + 1;
        if(swapWith < 0 || swapWith >= categories.length) return;
        const orderedIds = [...categories].map((c) => c.id);
        [orderedIds[index], orderedIds[swapWith]] = [orderedIds[swapWith], orderedIds[index]];
        await api("/api/room-categories/reorder", {
          method:"PATCH",
          headers: { "Content-Type":"application/json" },
          body: JSON.stringify({ master_id: Number(masterId) || masterId, orderedIds })
        });
      }
      await loadRooms();
    });
    roomCategoryList.appendChild(row);
  }
}

function renderRoomManageRoomsList(){
  if(!roomManageRoomList) return;
  const masterId = roomManageMasterSelect?.value || "";
  const categoryId = roomManageCategorySelect?.value || "";
  const categories = masterId ? getSortedCategories(masterId) : [];
  const rooms = categoryId ? getSortedRoomsForCategory(categoryId) : [];
  const masterOptions = getSortedMasters().map((m) => ({
    master: m,
    categories: getSortedCategories(m.id),
  }));
  const moveOptions = masterOptions
    .flatMap((entry) => entry.categories.map((c) => ({
      value: c.id,
      label: `${entry.master.name} / ${c.name}`,
    })));
  roomManageRoomList.innerHTML = "";
  for(const room of rooms){
    const row = document.createElement("div");
    row.className = "roomManageRow";
    const optionsMarkup = moveOptions.map((opt) => `<option value="${opt.value}">${escapeHtml(opt.label)}</option>`).join("");
    row.innerHTML = `
      <div class="label">${escapeHtml(displayRoomName(room.name))}</div>
      <select class="roomManageMoveSelect">${optionsMarkup}</select>
      <div class="actions">
        <button class="btn secondary" data-action="up">Up</button>
        <button class="btn secondary" data-action="down">Down</button>
        <button class="btn secondary" data-action="move">Move</button>
      </div>
    `;
    const moveSelect = row.querySelector(".roomManageMoveSelect");
    if(moveSelect) moveSelect.value = categoryId;
    const actions = row.querySelector(".actions");
    actions?.addEventListener("click", async (e) => {
      const btn = e.target.closest("button");
      if(!btn) return;
      const action = btn.dataset.action;
      if(action === "move"){
        const target = moveSelect?.value || "";
        if(!target || target === String(categoryId)) return;
        await api(`/api/rooms/${encodeURIComponent(room.name)}/move`, {
          method:"PATCH",
          headers: { "Content-Type":"application/json" },
          body: JSON.stringify({ category_id: Number(target) || target })
        });
      }
      if(action === "up" || action === "down"){
        const index = rooms.findIndex((r) => r.name === room.name);
        const swapWith = action === "up" ? index - 1 : index + 1;
        if(swapWith < 0 || swapWith >= rooms.length) return;
        const orderedIds = [...rooms].map((r) => r.name);
        [orderedIds[index], orderedIds[swapWith]] = [orderedIds[swapWith], orderedIds[index]];
        await api("/api/rooms/reorder", {
          method:"PATCH",
          headers: { "Content-Type":"application/json" },
          body: JSON.stringify({ category_id: Number(categoryId) || categoryId, orderedIds })
        });
      }
      await loadRooms();
    });
    roomManageRoomList.appendChild(row);
  }
}

function refreshRoomManageUi(){
  populateManageMasterSelects();
  renderRoomMasterList();
  renderRoomCategoryList();
  renderRoomManageRoomsList();
}

function openRoomManageModal(){
  if(!roomManageModal) return;
  if(!me){
    toast("Loading your profile — try again in a second.");
    return;
  }
  if(roleRank(me.role) < roleRank("Owner")){
    toast("Room management is Owner-only.");
    return;
  }
  if(roomMasterMsg) roomMasterMsg.textContent = "";
  if(roomCategoryMsg) roomCategoryMsg.textContent = "";
  if(roomManageMsg) roomManageMsg.textContent = "";
  const activeTab = document.querySelector("[data-room-manage-tab].active")?.dataset?.roomManageTab || "masters";
  setRoomManageTab(activeTab);
  roomManageModal.hidden = false;
  roomManageModal.style.display = "flex";
  roomManageModal.classList.remove("modal-closing");
  if(PREFERS_REDUCED_MOTION){
    roomManageModal.classList.add("modal-visible");
  }else{
    requestAnimationFrame(()=> roomManageModal.classList.add("modal-visible"));
  }
}

function closeRoomManageModal(){
  if(!roomManageModal) return;
  roomManageModal.classList.remove("modal-visible");
  if(PREFERS_REDUCED_MOTION){
    roomManageModal.style.display = "none";
    roomManageModal.hidden = true;
    return;
  }
  roomManageModal.classList.add("modal-closing");
  setTimeout(()=>{
    roomManageModal.style.display = "none";
    roomManageModal.hidden = true;
    roomManageModal.classList.remove("modal-closing");
  }, 140);
}

function setRoomManageTab(tab){
  const next = tab || "masters";
  document.querySelectorAll("[data-room-manage-tab]").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.roomManageTab === next);
  });
  document.querySelectorAll("[data-room-manage-section]").forEach((section) => {
    section.classList.toggle("active", section.dataset.roomManageSection === next);
  });
  refreshRoomManageUi();
}

async function persistRoomMasterCollapse(masterId, collapsed){
  if(!masterId || !Number.isFinite(Number(masterId))) return;
  await api("/api/users/me/room-master-collapsed", {
    method:"PATCH",
    headers: { "Content-Type":"application/json" },
    body: JSON.stringify({ master_id: masterId, collapsed }),
  });
}

async function persistRoomCategoryCollapse(categoryId, collapsed){
  if(!categoryId || !Number.isFinite(Number(categoryId))) return;
  await api("/api/users/me/room-category-collapsed", {
    method:"PATCH",
    headers: { "Content-Type":"application/json" },
    body: JSON.stringify({ category_id: categoryId, collapsed }),
  });
}

function updateRoomControlsVisibility(){
  if(addRoomBtn){
    const canCreate = me && roleRank(me.role) >= roleRank("Co-owner");
    addRoomBtn.style.display = rightPanelMode === "rooms" && canCreate ? "inline-flex" : "none";
  }
  if(manageRoomsBtn){
    const isOwner = me && roleRank(me.role) >= roleRank("Owner");
    manageRoomsBtn.style.display = rightPanelMode === "rooms" && isOwner ? "inline-flex" : "none";
    if(!isOwner) closeRoomManageModal();
  }
}

function ensureChangelogLoaded(force = false){
  if (activeMenuTab !== "changelog") return;
  return loadChangelog(force);
}

function ensureFaqLoaded(force = false){
  if(activeMenuTab !== "faq") return;
  return loadFaq(force);
}

let dailyLoadedForKey = null;

async function ensureDailyLoaded(){
  if(!getFeatureFlag("dailyChallenges", true)) return;
  try{
    const r = await fetch("/api/challenges/today");
    const j = await r.json();
    if(!j?.ok) throw new Error("bad");
    if(dailyLoadedForKey === j.dayKey) {
      renderDaily(j);
      return;
    }
    dailyLoadedForKey = j.dayKey;
    renderDaily(j);
  }catch(e){
    if(dailyMsg) dailyMsg.textContent = "Failed to load daily challenges.";
  }
}

function renderDaily(data){
  if(!dailyList) return;
  if(dailyMsg) dailyMsg.textContent = "";
  const challenges = data.challenges || [];
  dailyList.innerHTML = "";
  for(const c of challenges){
    const done = !!c.done;
    const claimed = !!c.claimed;
    const item = document.createElement("div");
    item.className = "dailyItem";
    const prog = Math.min(Number(c.progress||0), Number(c.goal||0));
    item.innerHTML = `
      <div class="dailyLeft">
        <div class="title">${escapeHtml(c.label || c.id)}</div>
        <div class="small muted">${prog}/${c.goal} • Reward: ${c.rewardXp||0} XP + ${c.rewardGold||0} gold</div>
      </div>
      <div class="dailyRight">
        <span class="badge ${done ? "done" : ""}">${done ? "Complete" : "In progress"}</span>
        <button class="btn ${claimed ? "secondary" : ""}" ${(!done || claimed) ? "disabled" : ""}>${claimed ? "Claimed" : "Claim"}</button>
      </div>
    `;
    const btn = item.querySelector("button");
    btn?.addEventListener("click", async ()=>{
      try{
        btn.disabled = true;
        const r = await fetch("/api/challenges/claim", {
          method:"POST",
          headers:{ "Content-Type":"application/json" },
          body: JSON.stringify({ id: c.id })
        });
        const j = await r.json();
        if(!j?.ok) throw new Error("bad");
        await ensureDailyLoaded();
        try{ await loadProgression(); }catch(_){}
      }catch(e){
        if(dailyMsg) dailyMsg.textContent = "Could not claim yet.";
        btn.disabled = false;
      }
    });
    dailyList.appendChild(item);
  }
}


function renderLeaderboard(listEl, items, mapper){
  if (!listEl) return;
  listEl.innerHTML = "";
  if (!items?.length) {
    const empty = document.createElement("div");
    empty.className = "small muted";
    empty.textContent = "No entries yet.";
    listEl.appendChild(empty);
    return;
  }

  items.forEach((item, idx) => {
    const row = document.createElement("div");
    row.className = "leaderboardItem";
    const label = document.createElement("div");
    label.className = "label";
    const meta = document.createElement("div");
    meta.className = "meta";

    const mapped = mapper?.(item, idx) || {};
    label.textContent = mapped.label || `${idx + 1}. ${item.username}`;
    meta.textContent = mapped.meta || "";

    row.appendChild(label);
    row.appendChild(meta);
    listEl.appendChild(row);
  });
}

function formatLeaderboardTime(ts){
  if(!ts) return "";
  try{
    return new Intl.DateTimeFormat(undefined, { hour12:false, hour:"2-digit", minute:"2-digit", second:"2-digit" }).format(new Date(ts));
  }catch{
    const d = new Date(ts);
    return Number.isNaN(d.getTime()) ? "" : d.toLocaleTimeString();
  }
}

function updateLeaderboardTimestamp(ts){
  if(!leaderboardsUpdatedAt) return;
  leaderboardsUpdatedAt.textContent = ts ? `Last updated: ${formatLeaderboardTime(ts)}` : "";
}

function stopLeaderboardPolling(){
  if(leaderboardState.intervalId){
    clearInterval(leaderboardState.intervalId);
    leaderboardState.intervalId = null;
  }
}

function startLeaderboardPolling(){
  stopLeaderboardPolling();
  leaderboardState.intervalId = setInterval(()=>{
    if(leaderboardState.isOpen) fetchLeaderboards({ force:true, reason:"poll" });
  }, 15000);
}

async function fetchLeaderboards({ force=false, reason="manual" } = {}){
  if(leaderboardState.inFlight) return;
  if(!force && !leaderboardState.isOpen && reason !== "manual") return;
  leaderboardState.inFlight = true;
  if(leaderboardsMsg){
    leaderboardsMsg.textContent = (reason === "manual" || !leaderboardState.lastFetchAt) ? "Loading..." : "";
  }
  try{
    const res = await fetch("/api/leaderboard", { credentials:"include" });
    if(!res.ok) throw new Error("failed");
    const data = await res.json();
    renderLeaderboard(leaderboardXp, data?.xp, (item, idx) => ({ label: `${idx + 1}. ${item.username}`, meta: `Level ${item.level}` }));
    renderLeaderboard(leaderboardGold, data?.gold, (item, idx) => ({ label: `${idx + 1}. ${item.username}`, meta: `${Number(item.gold || 0).toLocaleString()} Gold` }));
    renderLeaderboard(leaderboardDice, data?.dice, (item, idx) => ({ label: `${idx + 1}. ${item.username}`, meta: `${Number(item.sixes || 0)}× ${diceFace(6)}` }));
    renderLeaderboard(leaderboardLikes, data?.likes, (item, idx) => ({ label: `${idx + 1}. ${item.username}`, meta: `${Number(item.likes || 0)} likes` }));
    leaderboardState.lastFetchAt = Date.now();
    leaderboardState.lastError = false;
    if (leaderboardsMsg) leaderboardsMsg.textContent = "";
    updateLeaderboardTimestamp(leaderboardState.lastFetchAt);
  }catch{
    leaderboardState.lastError = true;
    if (leaderboardsMsg) leaderboardsMsg.textContent = "Failed to refresh leaderboards.";
  }finally{
    leaderboardState.inFlight = false;
  }
}

function setLeaderboardOpen(isOpen){
  const next = !!isOpen;
  if(leaderboardState.isOpen === next) return;
  leaderboardState.isOpen = next;
  if(next){
    fetchLeaderboards({ force:true, reason:"open" });
    startLeaderboardPolling();
  }else{
    stopLeaderboardPolling();
  }
}

function setRightPanelMode(mode){
  rightPanelMode = mode === "menu" ? "menu" : "rooms";
  if(roomsPanel) roomsPanel.style.display = rightPanelMode === "rooms" ? "flex" : "none";
  if(menuPanel) menuPanel.style.display = rightPanelMode === "menu" ? "flex" : "none";
  if(chanHeaderTitle) chanHeaderTitle.textContent = rightPanelMode === "menu" ? "Menu" : "Rooms";
  if(menuToggleBtn) menuToggleBtn.classList.toggle("active", rightPanelMode === "menu");
  updateRoomControlsVisibility();
  if(rightPanelMode === "menu" && activeMenuTab === "changelog") ensureChangelogLoaded();
  if(rightPanelMode === "menu" && activeMenuTab === "faq") ensureFaqLoaded();
  setLeaderboardOpen(rightPanelMode === "menu" && activeMenuTab === "leaderboards");
}

function setMenuTab(tab){
  activeMenuTab = tab || "changelog";
  document.querySelectorAll("[data-menu-tab]").forEach((btn)=>{
    btn.classList.toggle("active", btn.dataset.menuTab === activeMenuTab);
  });
  document.querySelectorAll("[data-menu-section]").forEach((section)=>{
    section.classList.toggle("active", section.dataset.menuSection === activeMenuTab);
  });
  if(activeMenuTab === "changelog") ensureChangelogLoaded();
  if(activeMenuTab === "faq") ensureFaqLoaded();
  if(activeMenuTab === "daily") ensureDailyLoaded();
  setLeaderboardOpen(activeMenuTab === "leaderboards" && rightPanelMode === "menu");
}

function updateChangelogControlsVisibility(){
  const isOwner = me && roleRank(me.role) >= roleRank("Owner");
  if(changelogActions) changelogActions.style.display = isOwner ? "flex" : "none";
  if(!isOwner) closeChangelogEditor();
}

function scrollChangelogEditorIntoView(){
  if(!changelogEditor) return;
  const scroller = menuPanel?.querySelector(".menuContent") || document.querySelector(".menuContent");
  if(scroller && scroller.contains(changelogEditor)){
    const rect = changelogEditor.getBoundingClientRect();
    const scrollerRect = scroller.getBoundingClientRect();
    if(rect.top < scrollerRect.top || rect.bottom > scrollerRect.bottom){
      try { changelogEditor.scrollIntoView({ behavior:"smooth", block:"nearest" }); } catch {}
    }
    return;
  }
  try { changelogEditor.scrollIntoView({ behavior:"smooth", block:"nearest" }); } catch {}
}

function openChangelogEditor(entry){
  if(!changelogEditor) return;
  editingChangelogId = entry?.id || null;
  if(changelogTitleInput) changelogTitleInput.value = entry?.title || "";
  if(changelogBodyInput) changelogBodyInput.value = entry?.body || "";
  if(changelogEditMsg) changelogEditMsg.textContent = "";
  changelogEditor.style.display = "block";
  requestAnimationFrame(()=>{
    scrollChangelogEditorIntoView();
    changelogTitleInput?.focus();
  });
}

function closeChangelogEditor(){
  editingChangelogId = null;
  if(changelogEditor) changelogEditor.style.display = "none";
  if(changelogTitleInput) changelogTitleInput.value = "";
  if(changelogBodyInput) changelogBodyInput.value = "";
  if(changelogEditMsg) changelogEditMsg.textContent = "";
}

function emptyChangelogReactions(){
  return { heart:0, clap:0, down:0, eyes:0 };
}

function emptyMyChangelogReactions(){
  return { heart:false, clap:false, down:false, eyes:false };
}

// --- FAQ reactions (mirror changelog normalizers)
function emptyFaqReactions(){
  const base = {};
  for(const key of FAQ_REACTION_KEYS) base[key] = 0;
  return base;
}

function emptyMyFaqReactions(){
  const base = {};
  for(const key of FAQ_REACTION_KEYS) base[key] = false;
  return base;
}

function normalizeFaqReactions(raw){
  const base = emptyFaqReactions();
  const src = raw && typeof raw === "object" ? raw : {};
  for(const key of FAQ_REACTION_KEYS){
    const val = src[key];
    if(Array.isArray(val)){
      base[key] = val.length;
    }else if(val && typeof val === "object" && typeof val.count === "number"){
      base[key] = Math.max(0, Math.round(val.count));
    }else if(Number.isFinite(Number(val))){
      base[key] = Math.max(0, Math.round(Number(val)));
    }
  }
  return base;
}

function normalizeMyFaqReactions(raw){
  const base = emptyMyFaqReactions();
  const src = raw && typeof raw === "object" ? raw : {};
  for(const key of FAQ_REACTION_KEYS){
    const val = src[key];
    base[key] = Array.isArray(val) ? val.includes(me?.username) : !!val;
  }
  return base;
}

function normalizeChangelogReactions(raw){
  const base = emptyChangelogReactions();
  const src = raw && typeof raw === "object" ? raw : {};
  for(const key of CHANGELOG_REACTION_KEYS){
    const val = src[key];
    if(Array.isArray(val)){
      base[key] = val.length;
    }else if(val && typeof val === "object" && typeof val.count === "number"){
      base[key] = Math.max(0, Math.round(val.count));
    }else if(Number.isFinite(Number(val))){
      base[key] = Math.max(0, Math.round(Number(val)));
    }
  }
  return base;
}

function normalizeMyChangelogReactions(raw){
  const base = emptyMyChangelogReactions();
  const src = raw && typeof raw === "object" ? raw : {};
  for(const key of CHANGELOG_REACTION_KEYS){
    const val = src[key];
    base[key] = Array.isArray(val) ? val.includes(me?.username) : !!val;
  }
  return base;
}

function normalizeChangelogEntry(entry){
  if(!entry) return null;
  const base = { ...entry };
  base.title = entry.title || "";
  base.body = entry.body || "";
  base.reactions = normalizeChangelogReactions(entry.reactions);
  base.myReactions = normalizeMyChangelogReactions(entry.myReactions);
  return base;
}

function updateChangelogEntryState(entryId, next, { touch=false } = {}){
  if(!entryId) return;
  const idx = changelogEntries.findIndex(e => e && String(e.id) === String(entryId));
  if(idx >= 0){
    const merged = normalizeChangelogEntry({ ...changelogEntries[idx], ...(next || {}) });
    if(merged){
      changelogEntries[idx] = merged;
      if(touch) changelogLocalTouch.set(String(entryId), Date.now());
    }
  }
}

async function loadChangelog(force=false){
  if(!force && changelogLoaded && !changelogDirty) return;
  const requestStartedAt = Date.now();
  const prevEntries = Array.isArray(changelogEntries) ? [...changelogEntries] : [];
  if(changelogMsg) changelogMsg.textContent = "Loading changelog...";
  const {res, text} = await api("/api/changelog", { method:"GET" });
  if(!res.ok){
    if(changelogMsg) changelogMsg.textContent = res.status === 403 ? "You do not have permission." : "Failed to load changelog.";
    changelogEntries = [];
    renderChangelogList();
    return;
  }

  try{
    const rows = JSON.parse(text || "[]");
    const normalized = Array.isArray(rows) ? rows.map(normalizeChangelogEntry).filter(Boolean) : [];
    const touched = new Map(changelogLocalTouch);
    const now = Date.now();
    const preserveWindowMs = 2000;
    changelogEntries = normalized.map(entry => {
      if(!entry || entry.id === undefined || entry.id === null) return entry;
      const key = String(entry.id);
      const localTouchedAt = touched.get(key) || 0;
      // Preserve optimistic UI if the user just reacted, even if a websocket
      // refresh arrives before the server's GET reflects the change.
      if(localTouchedAt && (localTouchedAt > requestStartedAt || (now - localTouchedAt) < preserveWindowMs)){
        const prev = prevEntries.find(e => e && String(e.id) === key);
        if(prev){
          return { ...entry, reactions: prev.reactions, myReactions: prev.myReactions, __localUpdatedAt: prev.__localUpdatedAt || localTouchedAt };
        }
      }
      if(localTouchedAt){
        entry.__localUpdatedAt = Math.max(entry.__localUpdatedAt || 0, localTouchedAt);
      }
      return entry;
    });
    changelogReactionBusy.clear();
    const serverIds = new Set(changelogEntries.map(e => e?.id !== undefined && e?.id !== null ? String(e.id) : null).filter(Boolean));
    for(const key of Array.from(changelogLocalTouch.keys())){
      if(!serverIds.has(key)) changelogLocalTouch.delete(key);
    }
  }catch{
    changelogEntries = [];
  }

  if(openChangelogId && !changelogEntries.some(e => String(e.id) === String(openChangelogId))){
    openChangelogId = null;
  }

  changelogLoaded = true;
  changelogDirty = false;
  if(changelogMsg) changelogMsg.textContent = changelogEntries.length ? "" : "No changelog entries yet.";
  renderChangelogList();
}

function renderChangelogList(){
  if(!changelogList) return;
  changelogList.innerHTML = "";

  if(!changelogEntries.length){
    const empty = document.createElement("div");
    empty.className = "small muted";
    empty.textContent = "No changelog entries yet.";
    changelogList.appendChild(empty);
    return;
  }

  const isOwner = me && roleRank(me.role) >= roleRank("Owner");

  for(const entry of changelogEntries){
    const entryId = String(entry.id);
    const isOpen = openChangelogId === entryId;

    const item = document.createElement("details");
    item.className = "clItem";
    item.dataset.changelogId = entryId;
    item.open = isOpen;

    const summary = document.createElement("summary");
    summary.className = "clSummary";

    const left = document.createElement("div");
    left.className = "clLeft";

    const title = document.createElement("div");
    title.className = "clTitle";
    title.textContent = (entry.title || "").trim() || "Update";
    left.appendChild(title);

    const meta = document.createElement("div");
    meta.className = "clMeta";
    meta.textContent = formatChangelogDate(entry.created_at || entry.createdAt || entry.timestamp);
    left.appendChild(meta);

    summary.appendChild(left);

    // Reactions (always visible, even when collapsed)
    const reactions = normalizeChangelogReactions(entry.reactions);
    const myReactions = normalizeMyChangelogReactions(entry.myReactions || entry.my_reactions || entry.mine);
    const reactionRow = document.createElement("div");
    reactionRow.className = "clReactions";
    const reactionKeys = ["heart","clap","down","eyes"];
    const reactionLabels = { heart:"♥️", clap:"👏", down:"👎", eyes:"👀" };

    for(const key of reactionKeys){
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "clReactBtn";
      btn.dataset.changelogReact = key;
      btn.dataset.changelogId = entryId;

      const emoji = document.createElement("span");
      emoji.className = "clReactEmoji";
      emoji.textContent = reactionLabels[key] || key;
      btn.appendChild(emoji);

      const count = document.createElement("span");
      count.className = "clReactCount";
      count.textContent = String(Math.max(0, Number(reactions[key] ?? 0)));
      btn.appendChild(count);

      btn.classList.toggle("active", !!myReactions[key]);
      reactionRow.appendChild(btn);
    }

    summary.appendChild(reactionRow);

    const chev = document.createElement("span");
    chev.className = "clChevron";
    chev.setAttribute("aria-hidden", "true");
    chev.textContent = "⌄";
    summary.appendChild(chev);

    item.appendChild(summary);

    const panel = document.createElement("div");
    panel.className = "clPanel";

    const body = document.createElement("div");
    body.className = "clBody";
    body.innerHTML = escapeHtml(entry.body || "").replace(/\n/g, "<br>");
    panel.appendChild(body);

    if(isOwner){
      const actions = document.createElement("div");
      actions.className = "clActions";

      const editBtn = document.createElement("button");
      editBtn.className = "btn secondary";
      editBtn.type = "button";
      editBtn.textContent = "Edit";
      editBtn.dataset.changelogEdit = entryId;

      const delBtn = document.createElement("button");
      delBtn.className = "btn danger";
      delBtn.type = "button";
      delBtn.textContent = "Delete";
      delBtn.dataset.changelogDelete = entryId;

      actions.appendChild(editBtn);
      actions.appendChild(delBtn);
      panel.appendChild(actions);
    }

    item.appendChild(panel);

    // Native <details> expansion is the most reliable option on iOS Safari.
    // Keep only one open at a time for readability (without re-rendering).
    item.addEventListener("toggle", ()=>{
      const nowOpen = item.open;
      openChangelogId = nowOpen ? entryId : (openChangelogId === entryId ? null : openChangelogId);
      if(!nowOpen) return;
      changelogList.querySelectorAll("details.clItem[open]").forEach((other)=>{
        if(other !== item) other.open = false;
      });
    }, { passive:true });

    changelogList.appendChild(item);
  }
}

function handleChangelogListClick(event){
  if(!changelogList) return;

  const popBtn = (btn)=>{
    if(!btn || !btn.classList) return;
    const removing = btn.classList.contains("active");
    triggerReactionBounce(btn, removing);
  };

  // Reactions live inside <summary>. Prevent them from toggling the <details>.
  const reactBtn = event.target.closest("[data-changelog-react]");
  if(reactBtn && changelogList.contains(reactBtn)){
    event.preventDefault();
    event.stopPropagation();
    popBtn(reactBtn);
    const entryId = reactBtn.dataset.changelogId;
    const reaction = reactBtn.dataset.changelogReact;
    if(entryId && reaction) toggleChangelogReaction(entryId, reaction);
    return;
  }

  const editBtn = event.target.closest("[data-changelog-edit]");
  if(editBtn && changelogList.contains(editBtn)){
    event.preventDefault();
    event.stopPropagation();
    const entryId = String(editBtn.dataset.changelogEdit || "");
    const entry = changelogEntries.find(e => String(e.id) === entryId);
    if(entry) openChangelogEditor(entry);
    return;
  }

  const delBtn = event.target.closest("[data-changelog-delete]");
  if(delBtn && changelogList.contains(delBtn)){
    event.preventDefault();
    event.stopPropagation();
    const entryId = String(delBtn.dataset.changelogDelete || "");
    if(entryId) deleteChangelogEntry(entryId);
    return;
  }

  // Backward compatibility (older markup)
  const legacyReactionBtn = event.target.closest("[data-changelog-reaction]");
  if(legacyReactionBtn && changelogList.contains(legacyReactionBtn)){
    event.preventDefault();
    event.stopPropagation();
    const entryId = legacyReactionBtn.dataset.entryId;
    const reaction = legacyReactionBtn.dataset.changelogReaction;
    if(entryId && reaction) toggleChangelogReaction(entryId, reaction);
    return;
  }
}

function normalizeFaqQuestion(row){
  if(!row) return null;
  const normalizeTs = (v) => {
    const n = Number(v);
    return Number.isFinite(n) && n > 0 ? n : null;
  };
  return {
    id: row.id,
    question_title: row.question_title || "Untitled",
    // question_details is kept for backwards compatibility with older builds,
    // but the current FAQ behavior is: question = title-only.
    // The "answer" is stored in answer_body and edited by privileged roles.
    question_details: row.question_details || "",
    answer_body: row.answer_body || "",
    created_at: normalizeTs(row.created_at || row.createdAt || row.timestamp),
    answered_at: normalizeTs(row.answered_at || row.answeredAt),
    reactions: normalizeFaqReactions(row.reactions),
    myReactions: normalizeMyFaqReactions(row.myReactions)
  };
}

function renderFaqList(){
  if(!faqList) return;
  faqList.innerHTML = "";
  if(!faqQuestions.length){
    const empty = document.createElement("div");
    empty.className = "card muted";
    empty.textContent = "No questions yet.";
    faqList.appendChild(empty);
    return;
  }

  const isPrivileged = me && roleRank(me.role) >= roleRank("Admin");
  for(const item of faqQuestions){
    const wrap = document.createElement("div");
    wrap.className = "faqEntry";
    wrap.dataset.questionId = String(item.id);
    const isOpen = String(openFaqQuestionId) === String(item.id);
    wrap.classList.toggle("is-open", isOpen);

    const hasAnswer = !!String(item.answer_body || "").trim();

    const header = document.createElement("div");
    header.className = "faqHeader";

    const metaBlock = document.createElement("div");

    const titleRow = document.createElement("div");
    titleRow.className = "faqTitleRow";

    const status = document.createElement("span");
    status.className = "faqStatus";
    status.textContent = hasAnswer ? "✅" : "❌";
    status.title = hasAnswer ? "Answered" : "Unanswered";
    titleRow.appendChild(status);

    const title = document.createElement("div");
    title.className = "faqTitle";
    title.textContent = item.question_title || "Untitled";
    titleRow.appendChild(title);
    const metaRow = document.createElement("div");
    metaRow.className = "faqMetaRow";
    const meta = document.createElement("div");
    meta.className = "faqMeta";
    meta.textContent = formatChangelogDate(item.created_at);
    metaRow.appendChild(meta);

    const toggle = document.createElement("button");
    toggle.type = "button";
    toggle.className = "btn text faqToggle";
    toggle.dataset.faqToggle = String(item.id);
    toggle.textContent = isOpen ? "Hide" : "View";
    metaRow.appendChild(toggle);

    metaBlock.appendChild(titleRow);
    metaBlock.appendChild(metaRow);
    header.appendChild(metaBlock);

    // Allow privileged roles to remove abusive questions.
    if(isPrivileged){
      const controls = document.createElement("div");
      controls.className = "faqControls";
      const delBtn = document.createElement("button");
      delBtn.type = "button";
      delBtn.className = "btn danger";
      delBtn.dataset.faqDelete = String(item.id);
      delBtn.textContent = "Delete";
      controls.appendChild(delBtn);
      header.appendChild(controls);
    }
    wrap.appendChild(header);

    const details = document.createElement("div");
    details.className = "faqDetails";
    details.hidden = !isOpen;

    // Do not show a "question body"; the question is title-only.

    const reactions = normalizeFaqReactions(item.reactions);
    const mine = normalizeMyFaqReactions(item.myReactions);
    const reactionRow = document.createElement("div");
    reactionRow.className = "faqReactions";
    const busy = faqReactionBusy.has(String(item.id));
    for(const key of FAQ_REACTION_KEYS){
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "faqReactionBtn";
      btn.dataset.faqReaction = key;
      btn.dataset.questionId = String(item.id);
      const emoji = document.createElement("span");
      emoji.className = "faqReactionEmoji";
      emoji.textContent = FAQ_REACTION_EMOJI[key] || key;
      const count = document.createElement("span");
      count.className = "faqReactionCount";
      count.textContent = String(Math.max(0, Number(reactions[key] ?? 0)));
      btn.appendChild(emoji);
      btn.appendChild(count);
      btn.classList.toggle("active", !!mine[key]);
      btn.disabled = busy;
      reactionRow.appendChild(btn);
    }

    const answerBlock = document.createElement("div");
    answerBlock.className = "faqAnswerBlock";
    const answerLabel = document.createElement("div");
    answerLabel.className = "faqMeta";
    answerLabel.textContent = item.answered_at ? `Answered ${formatChangelogDate(item.answered_at)}` : "Awaiting answer";
    answerBlock.appendChild(answerLabel);

    if(isPrivileged && editingFaqId === item.id){
      const editArea = document.createElement("textarea");
      editArea.className = "faqAnswerEdit";
      editArea.value = item.answer_body || "";
      editArea.dataset.faqAnswerInput = String(item.id);
      answerBlock.appendChild(editArea);

      const actions = document.createElement("div");
      actions.className = "faqAnswerActions";
      const saveBtn = document.createElement("button");
      saveBtn.className = "btn";
      saveBtn.type = "button";
      saveBtn.dataset.faqSaveAnswer = String(item.id);
      saveBtn.textContent = "Save answer";
      const cancelBtn = document.createElement("button");
      cancelBtn.className = "btn secondary";
      cancelBtn.type = "button";
      cancelBtn.dataset.faqCancelAnswer = String(item.id);
      cancelBtn.textContent = "Cancel";
      actions.appendChild(saveBtn);
      actions.appendChild(cancelBtn);
      answerBlock.appendChild(actions);
    } else {
      const body = document.createElement("div");
      body.className = "faqAnswerText";
      body.textContent = hasAnswer ? item.answer_body : "No answer yet.";
      answerBlock.appendChild(body);
      if(isPrivileged){
        const editBtn = document.createElement("button");
        editBtn.className = "btn secondary";
        editBtn.type = "button";
        editBtn.dataset.faqEditAnswer = String(item.id);
        editBtn.textContent = item.answer_body ? "Edit answer" : "Add answer";
        answerBlock.appendChild(editBtn);
      }
    }

    details.appendChild(reactionRow);
    details.appendChild(answerBlock);
    wrap.appendChild(details);
    faqList.appendChild(wrap);
  }
}

function handleFaqListClick(event){
  if(!faqList) return;

  const popBtn = (btn)=>{
    if(!btn || !btn.classList) return;
    const removing = btn.classList.contains("active");
    triggerReactionBounce(btn, removing);
  };
  const delBtn = event.target.closest("[data-faq-delete]");
  if(delBtn && faqList.contains(delBtn)){
    const qid = delBtn.dataset.faqDelete;
    if(qid) deleteFaqQuestion(qid);
    return;
  }

  const reactionBtn = event.target.closest("[data-faq-reaction]");
  if(reactionBtn && faqList.contains(reactionBtn)){
    event.preventDefault();
    popBtn(reactionBtn);
    const reaction = reactionBtn.dataset.faqReaction;
    const questionId = reactionBtn.dataset.questionId;
    if(questionId && reaction) toggleFaqReaction(questionId, reaction);
    return;
  }

  const toggleBtn = event.target.closest("[data-faq-toggle]");
  if(toggleBtn && faqList.contains(toggleBtn)){
    const qid = toggleBtn.dataset.faqToggle;
    if(qid){
      openFaqQuestionId = String(openFaqQuestionId) === String(qid) ? null : qid;
      if(openFaqQuestionId) editingFaqId = null;
      renderFaqList();
    }
    return;
  }

  const editBtn = event.target.closest("[data-faq-edit-answer]");
  if(editBtn && faqList.contains(editBtn)){
    const qid = editBtn.dataset.faqEditAnswer;
    if(qid){
      openFaqQuestionId = qid;
      editingFaqId = Number(qid);
      renderFaqList();
      const input = faqList.querySelector("[data-faq-answer-input]");
      input?.focus();
    }
    return;
  }

  const saveBtn = event.target.closest("[data-faq-save-answer]");
  if(saveBtn && faqList.contains(saveBtn)){
    const qid = saveBtn.dataset.faqSaveAnswer;
    const input = faqList.querySelector("[data-faq-answer-input]");
    if(qid && input){
      saveFaqAnswer(qid, input.value);
    }
    return;
  }

  const cancelBtn = event.target.closest("[data-faq-cancel-answer]");
  if(cancelBtn && faqList.contains(cancelBtn)){
    editingFaqId = null;
    renderFaqList();
    return;
  }

  const deleteBtn = event.target.closest("[data-faq-delete]");
  if(deleteBtn && faqList.contains(deleteBtn)){
    const qid = deleteBtn.dataset.faqDelete;
    if(qid) deleteFaqQuestion(qid);
    return;
  }
}

async function deleteFaqQuestion(questionId){
  const qKey = String(questionId);
  if(!qKey) return;
  if(!confirm("Delete this question?")) return;
  try{
    const {res, text} = await api(`/api/faq/${encodeURIComponent(qKey)}`, { method:"DELETE" });
    if(!res.ok) throw new Error(text || "Failed to delete");
    faqQuestions = faqQuestions.filter(q => q && String(q.id) !== qKey);
    if(String(openFaqQuestionId) === qKey) openFaqQuestionId = null;
    editingFaqId = null;
    renderFaqList();
  }catch(err){
    alert(err?.message || "Failed to delete question");
  }
}

async function toggleChangelogReaction(entryId, reaction){
  if(!entryId || !reaction) return;
  const entryKey = String(entryId);
  if(changelogReactionBusy.has(entryKey)) return;
  const entry = changelogEntries.find(e => e && String(e.id) === entryKey);
  if(!entry) return;
  const prev = entry ? {
    reactions: { ...(entry.reactions || {}) },
    myReactions: { ...(entry.myReactions || {}) }
  } : null;

  changelogReactionBusy.add(entryKey);

  if(prev){
    const nextActive = !prev.myReactions?.[reaction];
    const nextCount = Math.max(0, Number(prev.reactions?.[reaction] || 0) + (nextActive ? 1 : -1));
    updateChangelogEntryState(entryId, {
      reactions: { ...prev.reactions, [reaction]: nextCount },
      myReactions: { ...prev.myReactions, [reaction]: nextActive }
    }, { touch:true });
  }
  renderChangelogList();

  try{
    const {res, text} = await api(`/api/changelog/${entryId}/reaction`, {
      method: "POST",
      headers:{"Content-Type":"application/json"},
      body: JSON.stringify({ reaction })
    });

    if(!res.ok){
      if(prev) updateChangelogEntryState(entryId, prev);
      changelogLocalTouch.delete(entryKey);
      if(changelogMsg) changelogMsg.textContent = text || "Failed to update reaction.";
    }else{
      try{
        const payload = JSON.parse(text || "{}") || {};
        const hasServerState = payload && (payload.reactions || payload.myReactions);
        if(hasServerState){
          updateChangelogEntryState(entryId, payload, { touch:true });
        }else{
          await loadChangelog(true);
        }
      }catch{
        await loadChangelog(true);
      }
    }
  }catch{
    if(prev) updateChangelogEntryState(entryId, prev);
    changelogLocalTouch.delete(entryKey);
    if(changelogMsg) changelogMsg.textContent = "Failed to update reaction.";
  }finally{
    if(!prev) changelogLocalTouch.delete(entryKey);
    changelogReactionBusy.delete(entryKey);
    renderChangelogList();
  }
}

async function saveChangelogEntry(){
  if(!changelogTitleInput || !changelogBodyInput) return;
  const title = changelogTitleInput.value.trim();
  const body = changelogBodyInput.value.trim();
  if(!title){ if(changelogEditMsg) changelogEditMsg.textContent = "Title is required."; return; }

  if(changelogEditMsg) changelogEditMsg.textContent = "Saving...";
  const payload = { title, body };
  const path = editingChangelogId ? `/api/changelog/${editingChangelogId}` : "/api/changelog";
  const method = editingChangelogId ? "PUT" : "POST";
  const {res, text} = await api(path, {
    method,
    headers:{"Content-Type":"application/json"},
    body: JSON.stringify(payload)
  });
  if(!res.ok){
    if(changelogEditMsg) changelogEditMsg.textContent = text || "Failed to save entry.";
    return;
  }

  closeChangelogEditor();
  await loadChangelog(true);
  await loadLatestUpdateSnippet();
}

async function deleteChangelogEntry(id){
  if(!id) return;
  if(!confirm("Delete this entry?")) return;
  const {res, text} = await api(`/api/changelog/${id}`, {
    method:"DELETE",
    headers:{"Content-Type":"application/json"},
    body: JSON.stringify({ confirm:true })
  });
  if(!res.ok){
    alert(text || "Failed to delete entry.");
    return;
  }
  await loadChangelog(true);
  await loadLatestUpdateSnippet();
}

async function toggleFaqReaction(questionId, reaction){
  const qKey = String(questionId);
  if(!qKey || faqReactionBusy.has(qKey)) return;
  const idx = faqQuestions.findIndex((q)=> q && String(q.id) === qKey);
  if(idx === -1) return;
  const entry = faqQuestions[idx];
  const reactions = normalizeFaqReactions(entry.reactions);
  const mine = normalizeMyFaqReactions(entry.myReactions);
  const isActive = !!mine[reaction];
  mine[reaction] = !isActive;
  reactions[reaction] = Math.max(0, (reactions[reaction] || 0) + (isActive ? -1 : 1));
  faqQuestions[idx] = { ...entry, reactions, myReactions: mine };
  faqLocalTouch.set(qKey, Date.now());
  faqReactionBusy.add(qKey);
  renderFaqList();
  try{
    const {res, text} = await api(`/api/faq/${encodeURIComponent(qKey)}/react`, {
      method:"POST", headers:{"Content-Type":"application/json"},
      body: JSON.stringify({ reaction })
    });
    if(!res.ok) throw new Error(text || "Failed");
    const payload = JSON.parse(text || "null");
    const normalized = normalizeFaqQuestion(payload);
    if(normalized){
      faqQuestions[idx] = normalized;
    }
  }catch(err){
    if(faqMsg) faqMsg.textContent = (err?.message || "Failed to update reaction");
    faqDirty = true;
  }finally{
    faqReactionBusy.delete(qKey);
    renderFaqList();
  }
}

async function saveFaqAnswer(questionId, answer){
  const qKey = String(questionId);
  if(!qKey) return;
  if(faqEditMsg) faqEditMsg.textContent = "Saving answer...";
  try{
    const {res, text} = await api(`/api/faq/${encodeURIComponent(qKey)}/answer`, {
      method:"PATCH", headers:{"Content-Type":"application/json"},
      body: JSON.stringify({ answer })
    });
    if(!res.ok) throw new Error(text || "Failed to save");
    const payload = JSON.parse(text || "null");
    const normalized = normalizeFaqQuestion(payload);
    if(normalized){
      const idx = faqQuestions.findIndex((q)=> q && String(q.id) === qKey);
      if(idx !== -1) faqQuestions[idx] = normalized;
    }
    editingFaqId = null;
    if(faqEditMsg) faqEditMsg.textContent = "";
    renderFaqList();
  }catch(err){
    if(faqEditMsg) faqEditMsg.textContent = err?.message || "Failed to save answer.";
  }
}

function openFaqForm(){
  if(!faqForm) return;
  faqForm.style.display = "flex";
  faqTitleInput?.focus();
}

function closeFaqForm(){
  if(faqForm) faqForm.style.display = "none";
  if(faqTitleInput) faqTitleInput.value = "";
  if(faqDetailsInput) faqDetailsInput.value = "";
  if(faqEditMsg) faqEditMsg.textContent = "";
}

async function submitFaqQuestion(){
  if(!faqTitleInput) return;
  const title = faqTitleInput.value.trim();
  // Title-only questions; answer is provided later by privileged roles.
  const details = "";
  if(!title){
    if(faqEditMsg) faqEditMsg.textContent = "Question is required.";
    return;
  }
  if(faqEditMsg) faqEditMsg.textContent = "Submitting...";
  try{
    const {res, text} = await api("/api/faq", {
      method:"POST", headers:{"Content-Type":"application/json"},
      body: JSON.stringify({ title, details })
    });
    if(!res.ok) throw new Error(text || "Failed to submit");
    const payload = JSON.parse(text || "null");
    const normalized = normalizeFaqQuestion(payload);
    if(normalized){
      faqQuestions = [normalized, ...faqQuestions];
      openFaqQuestionId = normalized.id;
      editingFaqId = null;
      faqLoaded = true;
      faqDirty = false;
      renderFaqList();
    }
    closeFaqForm();
    if(faqMsg) faqMsg.textContent = "";
  }catch(err){
    if(faqEditMsg) faqEditMsg.textContent = err?.message || "Failed to submit question.";
  }
}

async function loadFaq(force = false){
  if(activeMenuTab !== "faq") return;
  if(!force && faqLoaded && !faqDirty) return;
  const requestStartedAt = Date.now();
  const prevQuestions = Array.isArray(faqQuestions) ? [...faqQuestions] : [];
  if(faqMsg) faqMsg.textContent = "Loading questions...";
  try{
    const {res, text} = await api("/api/faq", { method:"GET" });
    if(!res.ok) throw new Error(text || "Failed to load");
    const rows = JSON.parse(text || "[]");
    const normalized = Array.isArray(rows) ? rows.map(normalizeFaqQuestion).filter(Boolean) : [];
    const touched = new Map(faqLocalTouch);
    const now = Date.now();
    const preserveWindowMs = 2000;
    faqQuestions = normalized.map(q => {
      if(!q || q.id === undefined || q.id === null) return q;
      const key = String(q.id);
      const localTouchedAt = touched.get(key) || 0;
      if(localTouchedAt && (localTouchedAt > requestStartedAt || (now - localTouchedAt) < preserveWindowMs)){
        const prev = prevQuestions.find(p => p && String(p.id) === key);
        if(prev){
          return { ...q, reactions: prev.reactions, myReactions: prev.myReactions, __localUpdatedAt: prev.__localUpdatedAt || localTouchedAt };
        }
      }
      if(localTouchedAt){
        q.__localUpdatedAt = Math.max(q.__localUpdatedAt || 0, localTouchedAt);
      }
      return q;
    });
    faqLoaded = true;
    faqDirty = false;
    faqReactionBusy.clear();
    const serverIds = new Set(faqQuestions.map(q => q?.id !== undefined && q?.id !== null ? String(q.id) : null).filter(Boolean));
    for(const key of Array.from(faqLocalTouch.keys())){
      if(!serverIds.has(key)) faqLocalTouch.delete(key);
    }
    if(faqMsg) faqMsg.textContent = faqQuestions.length ? "" : "No questions yet.";
    renderFaqList();
  }catch(err){
    if(faqMsg) faqMsg.textContent = err?.message || "Failed to load questions.";
    faqQuestions = [];
    renderFaqList();
  }
}

async function loadLatestUpdateSnippet(){
  if(latestUpdate) latestUpdate.style.display = "none";
  const {res, text} = await api("/api/changelog?limit=1", { method:"GET" });
  if(!res.ok) return;
  try{
    const rows = JSON.parse(text || "[]");
    latestChangelogEntry = Array.isArray(rows) && rows.length ? rows[0] : null;
  }catch{
    latestChangelogEntry = null;
  }
  latestUpdateExpanded = false;
  renderLatestUpdateSnippet();
}

function renderLatestUpdateSnippet(){
  if(!latestUpdate) return;
  if(!latestChangelogEntry){
    latestUpdate.style.display = "none";
    return;
  }
  latestUpdate.style.display = "flex";

  // Compact by default to save UI space; expand only when user taps View.
  latestUpdate.classList.toggle("compact", !latestUpdateExpanded);

  if(latestUpdateTitle) latestUpdateTitle.textContent = latestChangelogEntry.title || "(untitled)";
  if(latestUpdateDate) latestUpdateDate.textContent = latestChangelogEntry.createdAt
    ? new Date(latestChangelogEntry.createdAt).toLocaleString()
    : "";

  // Render a compact reactions row directly under the timestamp.
  if(latestUpdateReactions){
    latestUpdateReactions.innerHTML = "";
    const reactions = normalizeChangelogReactions(latestChangelogEntry.reactions);
    const myReactions = normalizeMyChangelogReactions(latestChangelogEntry.myReactions);
    const entryBusy = changelogReactionBusy.has(latestChangelogEntry.id);
    for(const key of CHANGELOG_REACTION_KEYS){
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "changelogReactionBtn";
      btn.dataset.reaction = key;
      btn.classList.toggle("active", !!myReactions[key]);
      btn.disabled = entryBusy;

      const emoji = document.createElement("span");
      emoji.className = "changelogReactionEmoji";
      emoji.textContent = CHANGELOG_REACTION_EMOJI[key] || key;
      const count = document.createElement("span");
      count.className = "changelogReactionCount";
      count.textContent = String(Math.max(0, Number(reactions[key] ?? 0)));
      btn.appendChild(emoji);
      btn.appendChild(count);

      btn.addEventListener("click", ()=>toggleChangelogReaction(latestChangelogEntry.id, key));
      latestUpdateReactions.appendChild(btn);
    }
  }

  if(latestUpdateBody){
    latestUpdateBody.textContent = latestUpdateExpanded
      ? (latestChangelogEntry.body || "")
      : ""; // keep empty while compact
  }

  if(latestUpdateViewBtn){
    latestUpdateViewBtn.textContent = latestUpdateExpanded ? "Hide" : "View";
  }
}


if(menuToggleBtn){
  menuToggleBtn.addEventListener("click", ()=>{
    const next = rightPanelMode === "menu" ? "rooms" : "menu";
    if(next === "menu") setMenuTab(activeMenuTab || "changelog");
    setRightPanelMode(next);
  });
}
if(menuNav){
  menuNav.addEventListener("click", (e)=>{
    const btn = e.target.closest("[data-menu-tab]");
    if(!btn) return;
    setRightPanelMode("menu");
    setMenuTab(btn.dataset.menuTab);
  });
}
if(refreshLeaderboardsBtn) refreshLeaderboardsBtn.addEventListener("click", ()=> fetchLeaderboards({ force:true, reason:"manual" }));
if(changelogList) changelogList.addEventListener("click", handleChangelogListClick);
if(faqList) faqList.addEventListener("click", handleFaqListClick);
if(latestUpdateViewBtn){
  latestUpdateViewBtn.addEventListener("click", (e)=>{
    e.preventDefault();
    latestUpdateExpanded = !latestUpdateExpanded;
    renderLatestUpdateSnippet();
  });
}
if(changelogNewBtn) changelogNewBtn.addEventListener("click", ()=>openChangelogEditor());
if(changelogCancelBtn) changelogCancelBtn.addEventListener("click", closeChangelogEditor);
if(changelogSaveBtn) changelogSaveBtn.addEventListener("click", saveChangelogEntry);
if(faqAskBtn) faqAskBtn.addEventListener("click", openFaqForm);
if(faqCancelBtn) faqCancelBtn.addEventListener("click", closeFaqForm);
if(faqSubmitBtn) faqSubmitBtn.addEventListener("click", submitFaqQuestion);
closeChangelogEditor();

function setReplyTarget(target){
  replyTarget = target;
  if (!replyPreview || !replyPreviewText) return;
  if (target) {
    const base = String(target.text || target.attachment || "").trim();
    const snippet = base ? base.slice(0, 120) : "Attachment";
    replyPreviewText.textContent = `Replying to ${target.user || ""}: ${snippet}`;
    replyPreview.classList.add("show");
  } else {
    replyPreview.classList.remove("show");
    replyPreviewText.textContent = "";
  }
}
function setDmReplyTarget(target){
  dmReplyTarget = target;
  if (!dmReplyPreview || !dmReplyPreviewText) return;
  if (target) {
    const base = String(target.text || target.attachment || "").trim();
    const snippet = base ? base.slice(0, 120) : "Attachment";
    dmReplyPreviewText.textContent = `Replying to ${target.user || ""}: ${snippet}`;
    dmReplyPreview.classList.add("show");
  } else {
    dmReplyPreview.classList.remove("show");
    dmReplyPreviewText.textContent = "";
  }
}

initToneMenu(tonePicker, () => activeTone, (next) => { activeTone = next; });
initToneMenu(dmTonePicker, () => activeDmTone, (next) => { activeDmTone = next; });

// typing/send
let typingDebounce=null;
const TYPING_PHRASES = [
  "{name} is thinking…",
  "{name} is typing aggressively…",
  "{name} is composing a message…",
  "{name} is pondering their words…",
  "{name} is mashing keys softly…",
  "{name} is crafting a reply…"
];
function emitTyping(){
  if(!socket) return;
  socket.emit("typing");
  clearTimeout(typingDebounce);
  typingDebounce=setTimeout(()=>socket.emit("stop typing"), 900);
}
msgInput.addEventListener("input", (e)=>{ emitTyping(); renderMentionDropdown(mentionDropdown, msgInput); });
msgInput.addEventListener("keydown",(e)=>{
  if(e.key==="Enter"){ e.preventDefault(); sendMessage(); }
});
sendBtn.addEventListener("click", sendMessage);
replyPreviewClose?.addEventListener("click", ()=>setReplyTarget(null));
dmReplyClose?.addEventListener("click", ()=>setDmReplyTarget(null));
msgInput?.addEventListener("click", ()=>renderMentionDropdown(mentionDropdown, msgInput));
msgInput?.addEventListener("focus", ()=>renderMentionDropdown(mentionDropdown, msgInput));
dmText?.addEventListener("click", ()=>renderMentionDropdown(dmMentionDropdown, dmText));
dmText?.addEventListener("focus", ()=>renderMentionDropdown(dmMentionDropdown, dmText));

async function sendMessage(){
  if(!socket) return;
  const text = msgInput.value || "";
  const file = pendingFile;
  const attachmentReady = roomPendingAttachment;
  if(roomUploading && !attachmentReady) return;
  if(!text.trim() && !file && !attachmentReady) return;

  try{
    let attachment = attachmentReady;
    if(!attachment && file){
      addSystem(`Uploading ${file.name}...`);
      attachment = await uploadChatFileWithProgress(file);
    }

    socket.emit("chat message", {
      text,
      replyToId: replyTarget?.id || null,
      attachmentUrl: attachment?.url || "",
      attachmentType: attachment?.type || "",
      attachmentMime: attachment?.mime || "",
      attachmentSize: attachment?.size || 0,
      tone: activeTone || ""
    });

    if (Sound.shouldSent()) Sound.cues.sent();

    msgInput.value="";
    fileInput.value="";
    clearUploadPreview();
    roomPendingAttachment = null;
    roomUploadToken = null;
    setRoomUploadingState(false);
    setReplyTarget(null);
    activeTone = "";
    updateToneMenu(tonePicker, activeTone);
    socket.emit("stop typing");

    // keep focus on mobile
    if(window.innerWidth <= 980) setTimeout(()=>msgInput.focus(), 50);
  }catch(e){
    addSystem(`Upload failed: ${e.message}`);
  }
}

// auto-idle
let idleTimer=null;
let lastNonIdleStatus="Online";
function resetIdle(){
  if(statusSelect.value==="Idle"){
    const restoredStatus = normalizeStatusLabel(lastNonIdleStatus, "Online");
    statusSelect.value=restoredStatus;
    socket?.emit("status change",{status:restoredStatus});
    meStatusText.textContent = restoredStatus;
  }
  clearTimeout(idleTimer);
  idleTimer=setTimeout(()=>{
    if(statusSelect.value!=="Idle"){
      lastNonIdleStatus=normalizeStatusLabel(statusSelect.value, "Online");
      statusSelect.value="Idle";
      socket?.emit("status change",{status:"Idle"});
      meStatusText.textContent="Idle";
    }
  },120000);
}
["mousemove","keydown","click","touchstart"].forEach(evt=>{
  document.addEventListener(evt, resetIdle, {passive:true});
});

statusSelect.addEventListener("change", ()=>{
  const selected = normalizeStatusLabel(statusSelect.value, "Online");
  statusSelect.value = selected;
  if(selected!=="Idle") lastNonIdleStatus=selected;
  socket?.emit("status change", {status: selected});
  meStatusText.textContent = selected;
  resetIdle();
});

// ---- auth helpers
let authUserState = null;
let authHandlersBound = false;
let passwordUpgradeHandlersBound = false;

function getAuthUser(){
  return authUserState;
}

function isAuthenticated(){
  return !!authUserState;
}

function setAuthUser(user){
  authUserState = user || null;
}


function setView(mode){
  if(!loginView || !chatView) return;
  document.body.classList.remove("auth-pending");
  if(mode === "login"){
    loginView.hidden = false;
    chatView.hidden = true;
    if(restrictedView) restrictedView.hidden = true;
    if(passwordUpgradeView) passwordUpgradeView.hidden = true;
  }else if(mode === "chat"){
    loginView.hidden = true;
    chatView.hidden = false;
    if(restrictedView) restrictedView.hidden = true;
    if(passwordUpgradeView) passwordUpgradeView.hidden = true;
  }else if(mode === "restricted"){
    loginView.hidden = true;
    chatView.hidden = true;
    if(restrictedView) restrictedView.hidden = false;
    if(passwordUpgradeView) passwordUpgradeView.hidden = true;
  }else if(mode === "password-upgrade"){
    loginView.hidden = true;
    chatView.hidden = true;
    if(restrictedView) restrictedView.hidden = true;
    if(passwordUpgradeView) passwordUpgradeView.hidden = false;
  }else{
    loginView.hidden = true;
    chatView.hidden = true;
    if(restrictedView) restrictedView.hidden = true;
    if(passwordUpgradeView) passwordUpgradeView.hidden = true;
  }
}

function setAuthLoading(loading, message = ""){
  if(authMsg) authMsg.textContent = message;
  if(authValidation && !loading && message) authValidation.textContent = "";
  if(loginBtn) loginBtn.disabled = loading;
  if(regBtn) regBtn.disabled = loading;
  if(authUser) authUser.disabled = loading;
  if(authPass) authPass.disabled = loading;
}

function setAuthValidation(message = ""){
  if(authValidation) authValidation.textContent = message;
}

let passwordUpgradeNonce = "";
let passwordUpgradeSubmitting = false;

function setPasswordUpgradeMessage(message = ""){
  if(passwordUpgradeMsg) passwordUpgradeMsg.textContent = message;
}

function setPasswordUpgradeLoading(loading, message = ""){
  passwordUpgradeSubmitting = loading;
  if(passwordUpgradeSubmitBtn) passwordUpgradeSubmitBtn.disabled = loading;
  if(passwordUpgradeLogoutBtn) passwordUpgradeLogoutBtn.disabled = loading;
  if(upgradeCurrentPass) upgradeCurrentPass.disabled = loading;
  if(upgradeNewPass) upgradeNewPass.disabled = loading;
  if(upgradeConfirmPass) upgradeConfirmPass.disabled = loading;
  if(message) setPasswordUpgradeMessage(message);
}

function showPasswordUpgradeView({ nonce = "" } = {}){
  passwordUpgradeNonce = nonce || "";
  setView("password-upgrade");
  setPasswordUpgradeLoading(false, "");
  setPasswordUpgradeMessage("");
  if(upgradeCurrentPass){
    upgradeCurrentPass.value = "";
    upgradeNewPass.value = "";
    upgradeConfirmPass.value = "";
    requestAnimationFrame(()=> upgradeCurrentPass?.focus?.());
  }
}

async function checkPasswordUpgradeStatus(){
  try{
    const res = await fetch("/password-upgrade/status", { credentials: "include" });
    if(!res.ok) return false;
    const data = await res.json().catch(()=>({}));
    if(data?.required){
      showPasswordUpgradeView({ nonce: data?.nonce || "" });
      return true;
    }
  }catch{}
  return false;
}

async function api(path, options){
  try{
    const res = await fetch(path, { credentials: "include", ...options });
    const text=await res.text().catch(()=> "");
    return {res, text};
  }catch{
    return {res:{ok:false,status:0}, text:"Network error"};
  }
}

async function validateSession({ silent = false } = {}){
  let meRes;
  try{
    // Explicit credentials prevents edge cases where the session cookie isn't sent.
    meRes = await fetch("/me", { credentials: "include" });
  }catch(err){
    console.error("Failed to reach /me:", err);
    if(!silent && authMsg) authMsg.textContent = "Unable to reach the server. Please try again.";
    return null;
  }

  if(!meRes?.ok){
    if(!silent && authMsg) authMsg.textContent = "Please login.";
    return null;
  }

  try{
    const payload = await meRes.json();
    return payload || null;
  }catch(err){
    console.error("Invalid /me response:", err);
    if(!silent && authMsg) authMsg.textContent = "Server response was invalid. Please refresh and try again.";
    return null;
  }
}

let captchaConfigLoaded = false;
let captchaProvider = "none";
let captchaSiteKey = "";
let captchaToken = "";

function resetCaptchaToken(){
  captchaToken = "";
  if(captchaProvider === "turnstile" && window.turnstile && captchaWidget?.dataset?.captchaId){
    window.turnstile.reset(captchaWidget.dataset.captchaId);
  }
  if(captchaProvider === "hcaptcha" && window.hcaptcha && captchaWidget?.dataset?.captchaId){
    window.hcaptcha.reset(captchaWidget.dataset.captchaId);
  }
}

function renderCaptchaWidget(){
  if(!captchaWidget || !captchaSiteKey) return;
  if(captchaProvider === "turnstile" && window.turnstile){
    const widgetId = window.turnstile.render(captchaWidget, {
      sitekey: captchaSiteKey,
      callback: (token)=>{ captchaToken = token || ""; },
      "expired-callback": ()=>{ captchaToken = ""; },
    });
    captchaWidget.dataset.captchaId = String(widgetId);
  }
  if(captchaProvider === "hcaptcha" && window.hcaptcha){
    const widgetId = window.hcaptcha.render(captchaWidget, {
      sitekey: captchaSiteKey,
      callback: (token)=>{ captchaToken = token || ""; },
      "expired-callback": ()=>{ captchaToken = ""; },
    });
    captchaWidget.dataset.captchaId = String(widgetId);
  }
}

async function initCaptcha(){
  if(captchaConfigLoaded) return;
  captchaConfigLoaded = true;
  if(!captchaWrap || !captchaWidget) return;
  try{
    const res = await fetch("/api/captcha-config", { credentials: "include" });
    const data = await res.json().catch(()=>({}));
    captchaProvider = String(data?.provider || "none");
    captchaSiteKey = String(data?.siteKey || "");
    if(!captchaSiteKey || captchaProvider === "none"){
      captchaWrap.hidden = true;
      return;
    }
    captchaWrap.hidden = false;
    if(captchaNote) captchaNote.textContent = captchaProvider === "turnstile"
      ? "Protected by Cloudflare Turnstile."
      : "Protected by hCaptcha.";
    const script = document.createElement("script");
    script.async = true;
    script.defer = true;
    script.src = captchaProvider === "turnstile"
      ? "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit"
      : "https://js.hcaptcha.com/1/api.js?render=explicit";
    script.onload = renderCaptchaWidget;
    document.head.appendChild(script);
  }catch(err){
    captchaWrap.hidden = true;
  }
}

function initLoginUI(){
  setView("login");
  setAuthLoading(false, "");
  setAuthValidation("");
  initCaptcha();
  initPasswordUpgradeUI();
  if(!authHandlersBound){
    authHandlersBound = true;
    authForm?.addEventListener("submit", (e)=>{
      e.preventDefault();
      doLogin();
    });
    loginBtn?.addEventListener("click", (e)=>{ e?.preventDefault?.(); doLogin(); });
    regBtn?.addEventListener("click", (e)=>{ e?.preventDefault?.(); doRegister(); });
  }
  if(authUser && !isAuthenticated()){
    requestAnimationFrame(()=> authUser?.focus?.());
  }
}

function initPasswordUpgradeUI(){
  if(passwordUpgradeHandlersBound) return;
  passwordUpgradeHandlersBound = true;
  passwordUpgradeForm?.addEventListener("submit", (e)=>{
    e.preventDefault();
    doPasswordUpgrade();
  });
  passwordUpgradeLogoutBtn?.addEventListener("click", (e)=>{
    e?.preventDefault?.();
    doLogout();
  });
}

const KICK_LENGTH_OPTIONS = [
  { label: "1 week", seconds: 7 * 24 * 60 * 60 },
  { label: "5 days", seconds: 5 * 24 * 60 * 60 },
  { label: "3 days", seconds: 3 * 24 * 60 * 60 },
  { label: "2 days", seconds: 2 * 24 * 60 * 60 },
  { label: "1 day", seconds: 1 * 24 * 60 * 60 },
  { label: "12 hrs", seconds: 12 * 60 * 60 },
  { label: "8 hrs", seconds: 8 * 60 * 60 },
  { label: "3 hrs", seconds: 3 * 60 * 60 },
  { label: "2 hrs", seconds: 2 * 60 * 60 },
  { label: "1 hr", seconds: 60 * 60 },
  { label: "45m", seconds: 45 * 60 },
  { label: "30m", seconds: 30 * 60 },
  { label: "15m", seconds: 15 * 60 },
  { label: "10m", seconds: 10 * 60 },
  { label: "5min", seconds: 5 * 60 },
  { label: "1min", seconds: 60 },
];

function isStaffRole(role){
  const r = String(role || "");
  return ["Admin","Co owner","Owner"].includes(r) || r === "Moderator";
}

let restrictedCountdownTimer = null;
let currentRestriction = null;
let myAppeal = null;
let myAppealMessages = [];
// Dedicated socket for the restricted (kicked/banned) screen.
// Keeps appeals working even if the main chat socket was force-disconnected.
let restrictedSocket = null;

function pad2(n){ return String(Math.max(0, n|0)).padStart(2, "0"); }

function formatCountdown(ms){
  const total = Math.max(0, Math.floor(ms / 1000));
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  return `${pad2(h)}:${pad2(m)}:${pad2(s)}`;
}

function renderAppealThread(targetEl, messages){
  if(!targetEl) return;
  targetEl.innerHTML = "";
  const arr = Array.isArray(messages) ? messages : [];
  if(!arr.length){
    const empty = document.createElement("div");
    empty.className = "small muted";
    empty.textContent = "No messages yet.";
    targetEl.appendChild(empty);
    return;
  }
  for(const msg of arr){
    const row = document.createElement("div");
    row.className = "appealMsgRow " + (msg.author_role === "admin" ? "admin" : "user");
    const meta = document.createElement("div");
    meta.className = "appealMsgMeta";
    const who = msg.author_name || (msg.author_role === "admin" ? "Staff" : "You");
    meta.textContent = `${who} • ${formatChangelogDate(msg.created_at || msg.createdAt || Date.now())}`;
    const body = document.createElement("div");
    body.className = "appealMsgBody";
    body.textContent = msg.message || "";
    row.appendChild(meta);
    row.appendChild(body);
    targetEl.appendChild(row);
  }
  targetEl.scrollTop = targetEl.scrollHeight;
}

function showRestrictedView(restr){
  currentRestriction = restr || { type:"none" };
  const type = String(currentRestriction.type || "none");
  const reason = String(currentRestriction.reason || "").trim() || "No reason provided.";
  const expiresAt = currentRestriction.expiresAt != null ? Number(currentRestriction.expiresAt) : null;

  if(type === "ban"){
    if(restrictedTitle) restrictedTitle.textContent = "You’ve been banned";
    if(restrictedSub) restrictedSub.textContent = "You can’t access the chat right now.";
    if(restrictedTimerWrap) restrictedTimerWrap.hidden = true;
  }else{
    if(restrictedTitle) restrictedTitle.textContent = "You’ve been kicked";
    if(restrictedSub) restrictedSub.textContent = "You’ll be able to re-enter after the timer ends.";
    if(restrictedTimerWrap) restrictedTimerWrap.hidden = false;
  }
  if(restrictedReasonText) restrictedReasonText.textContent = reason;

  if(restrictedCountdownTimer) clearInterval(restrictedCountdownTimer);
  restrictedCountdownTimer = null;

  if(type === "kick" && expiresAt){
    const tick = () => {
      const ms = expiresAt - Date.now();
      if(restrictedTimer) restrictedTimer.textContent = formatCountdown(ms);
      if(ms <= 0){
        if(restrictedTimer) restrictedTimer.textContent = "00:00:00";
        // auto re-check
        doRestrictionRecheck();
      }
    };
    tick();
    restrictedCountdownTimer = setInterval(tick, 1000);
  }

  setView("restricted");
}

async function doRestrictionRecheck(){
  if(appealMsg) appealMsg.textContent = "";
  try{
    const rRes = await fetch("/api/restriction", { credentials:"include" });
    const r = await rRes.json().catch(()=>({type:"none"}));
    if(r?.type && r.type !== "none"){
      showRestrictedView(r);
      await refreshMyAppeal();
      return;
    }
    // no restriction -> boot normal chat
    if(restrictedCountdownTimer) clearInterval(restrictedCountdownTimer);
    restrictedCountdownTimer = null;
    await initChatApp();
  }catch(e){
    if(appealMsg) appealMsg.textContent = "Could not re-check access.";
  }
}

async function ensureRestrictedSocket(){
  // Recreate if missing or disconnected.
  if(restrictedSocket && restrictedSocket.connected) return restrictedSocket;
  if(restrictedSocket && !restrictedSocket.connected){
    try{ restrictedSocket.disconnect(); }catch{}
    restrictedSocket = null;
  }

  restrictedSocket = io();
  // If server emits restriction updates (e.g., staff changed it), keep UI in sync.
  restrictedSocket.on("restriction:status", (payload) => {
    if(payload?.type && payload.type !== "none"){
      showRestrictedView(payload);
      refreshMyAppeal();
    }else{
      // unlocked
      doRestrictionRecheck();
    }
  });
  restrictedSocket.on("connect_error", (err)=> {
    console.warn("socket connect error", err?.message || err);
  });
  return restrictedSocket;
}

async function refreshMyAppeal(){
  await ensureRestrictedSocket();
  return new Promise((resolve) => {
    restrictedSocket.emit("appeal:fetchMine", {}, (payload) => {
      const appeal = payload?.appeal || null;
      myAppeal = appeal;
      myAppealMessages = payload?.messages || [];
      renderAppealThread(appealThread, myAppealMessages);
      if(appealStatusText){
        if(myAppeal?.id) appealStatusText.textContent = "Ticket is open. Staff replies will show here.";
        else appealStatusText.textContent = "One ticket per user.";
      }
      resolve(payload);
    });
  });
}

async function sendMyAppeal(){
  const text = String(appealInput?.value || "").trim();
  if(!text){
    if(appealMsg) appealMsg.textContent = "Please type your appeal message.";
    return;
  }
  if(appealMsg) appealMsg.textContent = "";
  await ensureRestrictedSocket();

  const eventName = myAppeal?.id ? "appeal:send" : "appeal:create";
  restrictedSocket.emit(eventName, { message: text }, (resp) => {
    if(!resp?.ok){
      if(appealMsg) appealMsg.textContent = resp?.error || "Appeal failed.";
      return;
    }
    myAppeal = resp.appeal || myAppeal;
    myAppealMessages = resp.messages || myAppealMessages;
    renderAppealThread(appealThread, myAppealMessages);
    if(appealInput) appealInput.value = "";
    if(appealMsg) appealMsg.textContent = "Sent.";
    setTimeout(()=>{ if(appealMsg?.textContent==="Sent.") appealMsg.textContent=""; }, 1500);
  });
}

// Staff Appeals Panel (in-chat only)
let staffAppeals = [];
let activeAppealId = null;

function initAppealsDurationSelect(){
  if(!appealsDurationSelect) return;
  appealsDurationSelect.innerHTML = "";
  for(const opt of KICK_LENGTH_OPTIONS){
    const o = document.createElement("option");
    o.value = String(opt.seconds);
    o.textContent = opt.label;
    appealsDurationSelect.appendChild(o);
  }
  appealsDurationSelect.value = String(60 * 60); // default 1hr
}

function openAppealsPanel(){
  if(!appealsPanel) return;
  appealsPanel.hidden = false;
  loadAppealsList();
}
function closeAppealsPanel(){
  if(!appealsPanel) return;
  appealsPanel.hidden = true;
  activeAppealId = null;
  if(appealsDetail) appealsDetail.hidden = true;
}

function renderAppealsList(items){
  if(!appealsList) return;
  appealsList.innerHTML = "";
  const arr = Array.isArray(items) ? items : [];
  if(!arr.length){
    const empty = document.createElement("div");
    empty.className = "card muted";
    empty.textContent = "No open appeals.";
    appealsList.appendChild(empty);
    return;
  }
  for(const a of arr){
    const card = document.createElement("button");
    card.type = "button";
    card.className = "appealListItem";
    const title = document.createElement("div");
    title.className = "title";
    title.textContent = a.username;
    const meta = document.createElement("div");
    meta.className = "small muted";
    meta.textContent = `${String(a.restriction_type || "").toUpperCase()} • Updated ${formatChangelogDate(a.updated_at || a.updatedAt || a.created_at)}`;
    card.appendChild(title);
    card.appendChild(meta);
    card.addEventListener("click", ()=> openAppealDetail(a.id));
    appealsList.appendChild(card);
  }
}

function renderModlogs(items){
  if(!appealsModlogs) return;
  appealsModlogs.innerHTML = "";
  const arr = Array.isArray(items) ? items : [];
  if(!arr.length){
    const empty = document.createElement("div");
    empty.className = "small muted";
    empty.textContent = "No moderation logs yet.";
    appealsModlogs.appendChild(empty);
    return;
  }
  for(const m of arr){
    const row = document.createElement("div");
    row.className = "modlogRow";
    const line = document.createElement("div");
    line.className = "small";
    const when = formatChangelogDate(m.created_at || m.createdAt || Date.now());
    line.textContent = `${when} • ${m.action_type || m.actionType} • ${m.actor_username || m.actorUsername || "system"} • ${m.reason || ""}`;
    row.appendChild(line);
    appealsModlogs.appendChild(row);
  }
}

function loadAppealsList(){
  if(!socket) return;
  socket.emit("appeals:list", {}, (resp) => {
    if(!resp?.ok) return;
    staffAppeals = resp.items || [];
    renderAppealsList(staffAppeals);
  });
}

function openAppealDetail(id){
  activeAppealId = id;
  if(appealsDetail) appealsDetail.hidden = false;
  initAppealsDurationSelect();
  socket.emit("appeals:read", { appealId: id }, (resp) => {
    if(!resp?.ok) return;
    const a = resp.appeal;
    if(appealsDetailUser) appealsDetailUser.textContent = a.username;
    const rtype = String(a.restriction_type || "").toUpperCase();
    if(appealsDetailMeta) appealsDetailMeta.textContent = `${rtype} • Ticket #${a.id}`;
    if(appealsDetailReason) appealsDetailReason.textContent = a.reason_at_time || "—";
    renderAppealThread(appealsThread, resp.messages || []);
    renderModlogs(resp.modlogs || []);
  });
}

function staffReply(){
  const text = String(appealsReplyInput?.value || "").trim();
  if(!text || !activeAppealId) return;
  if(appealsReplyMsg) appealsReplyMsg.textContent = "";
  socket.emit("appeals:reply", { appealId: activeAppealId, message: text }, (resp) => {
    if(!resp?.ok){
      if(appealsReplyMsg) appealsReplyMsg.textContent = resp?.error || "Failed.";
      return;
    }
    if(appealsReplyInput) appealsReplyInput.value = "";
    if(appealsReplyMsg) appealsReplyMsg.textContent = "Sent.";
    openAppealDetail(activeAppealId);
  });
}

function staffAction(action){
  if(!activeAppealId) return;
  const dur = Number(appealsDurationSelect?.value || 3600);
  socket.emit("appeals:action", { appealId: activeAppealId, action, durationSeconds: dur }, (resp) => {
    if(!resp?.ok) return;
    loadAppealsList();
    if(appealsReplyMsg) appealsReplyMsg.textContent = "Updated.";
    setTimeout(()=>{ if(appealsReplyMsg?.textContent==="Updated.") appealsReplyMsg.textContent=""; }, 1200);
    openAppealDetail(activeAppealId);
  });
}

function bindRestrictedUI(){
  restrictedRecheckBtn?.addEventListener("click", doRestrictionRecheck);
  restrictedLogoutBtn?.addEventListener("click", async ()=>{
    try{ await fetch("/logout", { method:"POST", credentials:"include" }); }catch{}
    setAuthUser(null);
    initLoginUI();
  });
  appealRefreshBtn?.addEventListener("click", refreshMyAppeal);
  appealSendBtn?.addEventListener("click", sendMyAppeal);
}

function bindStaffAppealsUI(){
  appealsPanelBtn?.addEventListener("click", openAppealsPanel);
  appealsCloseBtn?.addEventListener("click", closeAppealsPanel);
  appealsBackBtn?.addEventListener("click", ()=>{ if(appealsDetail) appealsDetail.hidden = true; });
  appealsReplyBtn?.addEventListener("click", staffReply);
  appealsBanToKickBtn?.addEventListener("click", ()=> staffAction("ban_to_kick"));
  appealsUpdateKickBtn?.addEventListener("click", ()=> staffAction("update_kick"));
  appealsUnlockBtn?.addEventListener("click", ()=> staffAction("unlock"));
}


// Referrals (moderator -> admin review)
let staffReferrals = [];
let activeReferralId = null;

function openReferralsPanel(){
  if(!referralsPanel) return;
  referralsPanel.hidden = false;
  loadReferralsList();
}
function closeReferralsPanel(){
  if(!referralsPanel) return;
  referralsPanel.hidden = true;
  activeReferralId = null;
  if(referralsActionMsg) referralsActionMsg.textContent = "";
}
function loadReferralsList(){
  if(!socket) return;
  socket.emit("referrals:list", {}, (resp)=>{
    if(!resp?.ok) return;
    staffReferrals = resp.items || [];
    renderReferralsList(staffReferrals);
  });
}
function renderReferralsList(items){
  if(!referralsList) return;
  referralsList.innerHTML = "";
  const arr = Array.isArray(items) ? items : [];
  if(!arr.length){
    const empty = document.createElement("div");
    empty.className = "card muted";
    empty.textContent = "No open referrals.";
    referralsList.appendChild(empty);
    return;
  }
  for(const r of arr){
    const card = document.createElement("button");
    card.type = "button";
    card.className = "appealsCard";
    const when = r.created_at ? new Date(r.created_at).toLocaleString() : "";
    card.innerHTML = `
      <div class="appealsCardTop">
        <div class="appealsCardUser">${escapeHtml(r.target_username || "")}</div>
        <div class="small muted">${escapeHtml(when)}</div>
      </div>
      <div class="small muted">from ${escapeHtml(r.from_username || "")} (${escapeHtml(r.from_role || "")})</div>
      <div class="appealsCardReason">${escapeHtml(String(r.reason||"").slice(0,160))}</div>
    `;
    card.addEventListener("click", ()=> openReferralDetail(r.id));
    referralsList.appendChild(card);
  }
}
function openReferralDetail(id){
  activeReferralId = id;
  const r = (staffReferrals||[]).find(x=>String(x.id)===String(id));
  if(!r) return;
  if(referralsDetailUser) referralsDetailUser.textContent = r.target_username || "Referral";
  if(referralsDetailMeta){
    const when = r.created_at ? new Date(r.created_at).toLocaleString() : "";
    referralsDetailMeta.textContent = `${when} • from ${r.from_username || ""} (${r.from_role || ""})`;
  }
  if(referralsDetailReason) referralsDetailReason.textContent = r.reason || "";
  if(referralsActionMsg) referralsActionMsg.textContent = "";
}
function resolveReferral(){
  if(!activeReferralId) return;
  socket?.emit("referrals:resolve", { id: activeReferralId }, (resp)=>{
    if(!resp?.ok){
      if(referralsActionMsg) referralsActionMsg.textContent = resp?.error || "Failed to resolve.";
      return;
    }
    if(referralsActionMsg) referralsActionMsg.textContent = "Marked done.";
    loadReferralsList();
  });
}
function bindReferralsUI(){
  referralsPanelBtn?.addEventListener("click", openReferralsPanel);
  referralsCloseBtn?.addEventListener("click", closeReferralsPanel);
  referralsRefreshBtn?.addEventListener("click", loadReferralsList);
  referralsCopyUserBtn?.addEventListener("click", ()=>{
    const r = (staffReferrals||[]).find(x=>String(x.id)===String(activeReferralId));
    const uname = r?.target_username || "";
    if(uname) navigator.clipboard?.writeText(uname);
    if(referralsActionMsg) referralsActionMsg.textContent = uname ? "Copied." : "";
  });
  referralsMarkDoneBtn?.addEventListener("click", resolveReferral);
}

// Role Debug (quick role setter)
function openRoleDebugPanel(){
  if(!roleDebugPanel) return;
  roleDebugPanel.hidden = false;
  if(roleDebugMsg) roleDebugMsg.textContent = "";
}
function closeRoleDebugPanel(){
  if(!roleDebugPanel) return;
  roleDebugPanel.hidden = true;
  if(roleDebugMsg) roleDebugMsg.textContent = "";
}
function bindRoleDebugUI(){
  roleDebugPanelBtn?.addEventListener("click", openRoleDebugPanel);
  roleDebugCloseBtn?.addEventListener("click", closeRoleDebugPanel);
  roleDebugUseSelectedBtn?.addEventListener("click", ()=>{
    if(roleDebugTarget) roleDebugTarget.value = (memberMenuUsername || memberMenuUser?.username || memberMenuUser?.name || "").trim();
  });
  roleDebugApplyBtn?.addEventListener("click", async ()=>{
    const target = (roleDebugTarget?.value || "").trim();
    const role = (roleDebugRole?.value || "").trim();
    if(!target){ if(roleDebugMsg) roleDebugMsg.textContent="Enter a username."; return; }
    if(!role){ if(roleDebugMsg) roleDebugMsg.textContent="Choose a role."; return; }
    if(!confirmModeration("role update", target)) return;
    const prevRole = cachedRoleForUser(target);
    const resp = await emitModWithAck("mod set role", { username: target, role, reason: "" });
    if(!resp?.ok){ if(roleDebugMsg) roleDebugMsg.textContent = resp?.error || "Role update failed."; return; }
    updateRoleCache(target, role);
    if(roleDebugMsg) roleDebugMsg.textContent="Role change sent.";
    if (prevRole && prevRole !== role) {
      showToast(`Role updated for ${target}`, {
        actionLabel: "Undo",
        actionFn: () => undoWithAck("mod set role", { username: target, role: prevRole, reason: "Undo role" }),
        durationMs: 5200
      });
    }
  });
}


async function doLogin(){
  const username = authUser?.value?.trim() || "";
  const password = authPass?.value || "";
  if(!username){
    setAuthValidation("Please enter your username.");
    authUser?.focus();
    return;
  }
  if(!password){
    setAuthValidation("Please enter your password.");
    authPass?.focus();
    return;
  }
  if(captchaProvider !== "none" && !captchaToken){
    setAuthValidation("Please complete the captcha.");
    return;
  }
  setAuthValidation("");
  setAuthLoading(true, "Logging in...");
  const {res,text}=await api("/login",{
    method:"POST", headers:{"Content-Type":"application/json"},
    body:JSON.stringify({username, password, captchaToken})
  });
  if(!res.ok){
    setAuthLoading(false, text||"Login failed.");
    resetCaptchaToken();
    return;
  }
  const payload = safeJsonParse(text, {});
  if(payload?.code === "PASSWORD_UPGRADE_REQUIRED"){
    setAuthLoading(false, "");
    resetCaptchaToken();
    const pending = await checkPasswordUpgradeStatus();
    if(!pending){
      setAuthValidation("Password upgrade required. Please try again.");
    }
    return;
  }
  await initChatApp();
  setAuthLoading(false, "");
  resetCaptchaToken();
}

async function doPasswordUpgrade(){
  if(passwordUpgradeSubmitting) return;
  const currentPassword = upgradeCurrentPass?.value || "";
  const newPassword = upgradeNewPass?.value || "";
  const confirmPassword = upgradeConfirmPass?.value || "";

  if(!currentPassword){
    setPasswordUpgradeMessage("Enter your current password.");
    upgradeCurrentPass?.focus?.();
    return;
  }
  if(!newPassword){
    setPasswordUpgradeMessage("Enter a new password.");
    upgradeNewPass?.focus?.();
    return;
  }
  if(newPassword.length < 12){
    setPasswordUpgradeMessage("New password must be at least 12 characters.");
    upgradeNewPass?.focus?.();
    return;
  }
  if(newPassword !== confirmPassword){
    setPasswordUpgradeMessage("Passwords do not match.");
    upgradeConfirmPass?.focus?.();
    return;
  }

  setPasswordUpgradeLoading(true, "Updating password...");
  const {res,text} = await api("/password-upgrade", {
    method: "POST",
    headers: {"Content-Type":"application/json"},
    body: JSON.stringify({
      currentPassword,
      newPassword,
      confirmPassword,
      nonce: passwordUpgradeNonce,
    })
  });
  const payload = safeJsonParse(text, {});
  if(!res.ok || !payload?.ok){
    const message = payload?.message || text || "Password upgrade failed.";
    setPasswordUpgradeLoading(false, message);
    return;
  }
  setPasswordUpgradeLoading(false, "");
  window.location.reload();
}

async function doRegister(){
  const username = authUser?.value?.trim() || "";
  const password = authPass?.value || "";
  if(!username){
    setAuthValidation("Please choose a username.");
    authUser?.focus();
    return;
  }
  if(!password){
    setAuthValidation("Please choose a password.");
    authPass?.focus();
    return;
  }
  if(captchaProvider !== "none" && !captchaToken){
    setAuthValidation("Please complete the captcha.");
    return;
  }
  setAuthValidation("");
  setAuthLoading(true, "Registering...");
  const {res,text}=await api("/register",{
    method:"POST", headers:{"Content-Type":"application/json"},
    body:JSON.stringify({username, password, captchaToken})
  });
  if(!res.ok){
    setAuthLoading(false, text||"Register failed.");
    resetCaptchaToken();
    return;
  }
  setAuthLoading(false, "Registered! Now click Join chat.");
  resetCaptchaToken();
}

async function doLogout(){
  // Explicitly include credentials so the session cookie is always sent.
  await fetch("/logout", {method:"POST", credentials:"include"}).catch(()=>{});
  setAuthUser(null);
  me = null;
  if(socket){
    try { socket.removeAllListeners(); } catch {}
    try { socket.disconnect(); } catch {}
  }
  setView("login");
  initLoginUI();
}
logoutBtn?.addEventListener("click", doLogout);

/* ---- UI scale panel (topbar) */
(function initUiScaleControls(){
  const saved = loadUiScale();
  if(saved !== null) applyUiScale(saved);

  function effectiveScale(){
    const inline = getComputedStyle(document.documentElement).getPropertyValue("--uiScale").trim();
    const n = Number(inline);
    return (Number.isFinite(n) && n > 0) ? n : 1;
  }

  function syncUiScaleUi(){
    if(!uiScaleRange || !uiScaleValue) return;
    const eff = effectiveScale();
    uiScaleRange.value = String(eff);
    uiScaleValue.textContent = Math.round(eff * 100) + "%";
  }

  uiScaleRange?.addEventListener("input", ()=>{
    const v = Number(uiScaleRange.value);
    applyUiScale(v);
    uiScaleValue.textContent = Math.round(v * 100) + "%";
  });

  uiScaleResetBtn?.addEventListener("click", ()=>{
    applyUiScale(null);
    syncUiScaleUi();
  });

  window.addEventListener("resize", syncUiScaleUi, { passive:true });
  syncUiScaleUi();
})();

logoutTopBtn?.addEventListener("click", doLogout);

notificationsBtn?.addEventListener("click", (e) => {
  e.stopPropagation();
  openNotificationsModal();
});
notificationsCloseBtn?.addEventListener("click", (e) => {
  e.stopPropagation();
  closeNotificationsModal();
});
notificationsClearBtn?.addEventListener("click", () => {
  notifications = [];
  saveNotifications();
  renderNotifications();
  updateNotificationsBadge();
});
notificationsModal?.addEventListener("click", (e) => {
  if (e.target === notificationsModal) closeNotificationsModal();
});
notificationsList?.addEventListener("click", async (e) => {
  const actionEl = e.target.closest("[data-action]");
  if (actionEl) {
    const act = actionEl.getAttribute('data-action');
    const username = actionEl.getAttribute('data-username') || '';
    const rid = Number(actionEl.getAttribute('data-request-id') || 0);

    if (act === 'open-profile' && username) {
      openMemberProfile(username);
      return;
    }

    if ((act === 'accept' || act === 'decline') && rid) {
      actionEl.disabled = true;
      try {
        const res = await fetch('/api/friends/respond', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ requestId: rid, action: act })
        });
        if (!res.ok) throw new Error(await res.text());
        // Update local notification entry (so it doesn't keep showing as pending)
        const nid = `friendreq:${rid}`;
        const idx = notifications.findIndex((n) => n.id === nid);
        if (idx >= 0) {
          const n = { ...notifications[idx] };
          n.meta = { ...(n.meta || {}), status: act === 'accept' ? 'accepted' : 'declined' };
          n.text = act === 'accept' ? `You and ${n.meta?.fromUsername || 'them'} are now friends` : `Declined friend request from ${n.meta?.fromUsername || 'them'}`;
          notifications[idx] = n;
          saveNotifications();
          renderNotifications();
          updateNotificationsBadge();
        }
        friendsDirty = true;
      } catch (err) {
        actionEl.disabled = false;
        toast(err?.message || 'Could not respond');
      }
      return;
    }
  }

  const row = e.target.closest("[data-notification-id]");
  if (!row) return;
  const item = notifications.find((n) => n.id === row.dataset.notificationId);
  if (!item || !item.target) return;
  if (item.target.startsWith("profile:")) {
    const username = item.target.slice("profile:".length);
    if (username) openMemberProfile(username);
  }
  if (item.target.startsWith("message:")) {
    const messageId = item.target.slice("message:".length);
    if (focusMainMessage(messageId)) closeNotificationsModal();
  }
});

renderNotifications();
updateNotificationsBadge();

// Members view pills (Room / Friends)
memberPillRoom?.addEventListener('click', () => setMembersViewMode('room'));
memberPillFriends?.addEventListener('click', () => setMembersViewMode('friends'));

// ---- profiles
async function loadMyProfile(){
  const priorRole = me?.role;
  const res=await fetch("/profile");
  if(!res.ok) return;
  const p=await res.json();
  updateRoleCache(p.username, p.role);
  modalTargetUserId = Number(p?.id) || null;
  me.username = p.username;
  me.role = p.role;
  me.level = p.level || me.level;
  me.vibe_tags = sanitizeVibeTagsClient(p.vibe_tags);

  applyProgressionPayload(p);

  meName.textContent=p.username;
  meRole.textContent=`${roleIcon(p.role)} ${p.role}`;
  meAvatar.innerHTML="";
  meAvatar.appendChild(avatarNode(p.avatar, p.username, p.role));
  renderLevelProgress(progression, true);
  renderVibeOptions(me.vibe_tags || []);
  updateChatFxPreviewIdentity(me);
  if (editUsername) editUsername.value = "";
  if (priorRole && priorRole !== p.role) {
    pushNotification({ type: "system", text: `Role updated to ${p.role}.` });
  }
}

function setMsgline(el, text){
  if(!el) return;
  const raw = text == null ? "" : String(text);
  const visible = raw.trim().length > 0;
  el.textContent = raw;
  el.style.display = visible ? "" : "none";
}

function formatLastSeen(val){
  const hasVal = val !== undefined && val !== null && String(val).trim() !== "";
  return hasVal ? fmtAbs(val) : "—";
}

function ensureVisibleOnFocus(el){
  if(!el || el._visibleHooked) return;
  el._visibleHooked = true;
  el.addEventListener("focus", () => {
    setTimeout(() => {
      try { el.scrollIntoView({ block: "center", behavior: "smooth" }); } catch {}
    }, 60);
  });
}

function clearAvatarPreview(){
  if (avatarPreviewUrl) {
    try { URL.revokeObjectURL(avatarPreviewUrl); } catch {}
    avatarPreviewUrl = null;
  }
}

function applyAvatarPreview(file){
  if (!file || !profileSheetAvatar) return;
  clearAvatarPreview();
  avatarPreviewUrl = URL.createObjectURL(file);
  profileSheetAvatar.innerHTML = "";
  profileSheetAvatar.appendChild(avatarNode(avatarPreviewUrl, me?.username || "", me?.role || ""));
  if (profileMsg) profileMsg.textContent = "Avatar selected. Save to apply.";
}

function renderVibeChips(targetEl, tags){
  if(!targetEl) return;
  const vibes = sanitizeVibeTagsClient(tags);
  targetEl.innerHTML = "";
  if(!vibes.length){ targetEl.style.display = "none"; return; }
  targetEl.style.display = "flex";
  vibes.forEach((tag)=>{
    const chip = document.createElement("span");
    chip.className = "vibeChip";
    chip.textContent = formatVibeChipLabel(tag);
    targetEl.appendChild(chip);
  });
}

function renderVibeOptions(selected = []){
  if(!vibeTagOptions) return;
  selectedVibeTags = sanitizeVibeTagsClient(selected);
  vibeTagOptions.innerHTML = "";
  VIBE_TAG_DEFS.forEach((def)=>{
    const tag = def.label;
    const btn = document.createElement("button");
    btn.type = "button";
    const active = selectedVibeTags.includes(tag);
    btn.className = "pillBtn" + (active ? " active" : "");
    btn.textContent = formatVibeChipLabel(tag);
    btn.addEventListener("click", ()=>{
      const on = selectedVibeTags.includes(tag);
      if(on){
        selectedVibeTags = selectedVibeTags.filter((t)=>t!==tag);
      } else {
        if(selectedVibeTags.length >= VIBE_TAG_LIMIT) return;
        selectedVibeTags = [...selectedVibeTags, tag];
      }
      renderVibeOptions(selectedVibeTags);
    });
  vibeTagOptions.appendChild(btn);
  });
}

function getHeaderGradientInputValues(){
  const aRaw = headerColorAText?.value || headerColorA?.value;
  const bRaw = headerColorBText?.value || headerColorB?.value;
  const a = sanitizeHexColorInput(aRaw, PROFILE_GRADIENT_DEFAULT_A) || PROFILE_GRADIENT_DEFAULT_A;
  const b = sanitizeHexColorInput(bRaw, PROFILE_GRADIENT_DEFAULT_B) || PROFILE_GRADIENT_DEFAULT_B;
  return { a, b };
}

function closeFeatureFlagsPanel(){
  if(featureFlagsPanel) featureFlagsPanel.hidden = true;
  if(featureFlagsMsg) featureFlagsMsg.textContent = "";
}
function closeSessionsPanel(){
  if(sessionsPanel) sessionsPanel.hidden = true;
  if(sessionsMsg) sessionsMsg.textContent = "";
}

async function loadFeatureFlags(){
  if(!me || roleRank(me.role) < roleRank("Owner")) return;
  if(featureFlagsMsg) featureFlagsMsg.textContent = "Loading…";
  try{
    const r = await fetch("/api/owner/flags");
    const j = await r.json();
    if(!j?.ok) throw new Error("bad");
    featureFlags = j.flags || {};
    renderFeatureFlagsGrid();
    applyFeatureFlags();
    if(featureFlagsMsg) featureFlagsMsg.textContent = "Loaded.";
  }catch(e){
    if(featureFlagsMsg) featureFlagsMsg.textContent = "Failed to load.";
  }
}

function renderFeatureFlagsGrid(){
  if(!featureFlagsGrid) return;
  const known = [
    { key:"ambientFx", label:"Ambient FX", hint:"Subtle room ambience (Main/Dice/Music/NSFW)." },
    { key:"autoContrast", label:"Auto Contrast", hint:"Auto-adjust text/bubble contrast for readability." },
    { key:"dailyChallenges", label:"Daily Challenges", hint:"Enable daily XP + gold micro-challenges." },
    { key:"smartMentions", label:"Smart Mentions", hint:"Enable @here/@mods/@admins/@owner pings." },
    { key:"roomEvents", label:"Room Events", hint:"Enable /event banners." },
  ];

  featureFlagsGrid.innerHTML = "";
  for(const item of known){
    const val = getFeatureFlag(item.key, true);
    const card = document.createElement("div");
    card.className = "flagCard";
    card.innerHTML = `
      <div class="flagRow">
        <div>
          <div class="title">${escapeHtml(item.label)}</div>
          <div class="small muted">${escapeHtml(item.hint)}</div>
        </div>
        <div class="switch ${val ? "on" : ""}" role="switch" aria-checked="${val ? "true":"false"}"></div>
      </div>
    `;
    const sw = card.querySelector(".switch");
    sw?.addEventListener("click", async ()=>{
      const next = !getFeatureFlag(item.key, false);
      featureFlags[item.key] = next;
      sw.classList.toggle("on", next);
      sw.setAttribute("aria-checked", next ? "true":"false");
      try{
        const r = await fetch("/api/owner/flags", {
          method:"POST",
          headers:{ "Content-Type":"application/json" },
          body: JSON.stringify({ flags: featureFlags })
        });
        const j = await r.json();
        if(!j?.ok) throw new Error("bad");
        featureFlags = j.flags || featureFlags;
        applyFeatureFlags();
        if(featureFlagsMsg) featureFlagsMsg.textContent = "Saved.";
        setTimeout(()=>{ if(featureFlagsMsg) featureFlagsMsg.textContent = ""; }, 1200);
      }catch(e){
        if(featureFlagsMsg) featureFlagsMsg.textContent = "Save failed.";
      }
    });

    featureFlagsGrid.appendChild(card);
  }
}

function openFeatureFlagsPanel(){
  if(!me || roleRank(me.role) < roleRank("Owner")) return;
  if(featureFlagsPanel) featureFlagsPanel.hidden = false;
  loadFeatureFlags();
}

async function loadSessions(){
  if(!me || roleRank(me.role) < roleRank("Owner")) return;
  if(sessionsMsg) sessionsMsg.textContent = "Loading…";
  try{
    const r = await fetch("/api/owner/sessions");
    const j = await r.json();
    if(!j?.ok) throw new Error("bad");
    renderSessions(j.sessions || []);
    if(sessionsMsg) sessionsMsg.textContent = "Loaded.";
  }catch(e){
    if(sessionsMsg) sessionsMsg.textContent = "Failed to load.";
  }
}

function renderSessions(rows){
  if(!sessionsTbody) return;
  sessionsTbody.innerHTML = "";
  for(const s of rows){
    const tr = document.createElement("tr");
    const user = s.username || ("#"+s.userId);
    const ua = (s.userAgent || "").slice(0, 40);
    const connected = s.connectedAt ? new Date(s.connectedAt).toLocaleString() : "";
    tr.innerHTML = `
      <td>${escapeHtml(user)}</td>
      <td>${escapeHtml(String(s.role||""))}</td>
      <td>${escapeHtml(String(s.room||""))}</td>
      <td>${escapeHtml(connected)}</td>
      <td>${escapeHtml(ua)}</td>
      <td>${escapeHtml(String(s.tz||""))}</td>
    `;
    sessionsTbody.appendChild(tr);
  }
}

function openSessionsPanel(){
  if(!me || roleRank(me.role) < roleRank("Owner")) return;
  if(sessionsPanel) sessionsPanel.hidden = false;
  loadSessions();
}

function bindOwnerPanels(){
  featureFlagsPanelBtn?.addEventListener("click", openFeatureFlagsPanel);
  featureFlagsCloseBtn?.addEventListener("click", closeFeatureFlagsPanel);
  featureFlagsReloadBtn?.addEventListener("click", loadFeatureFlags);

  sessionsPanelBtn?.addEventListener("click", openSessionsPanel);
  sessionsCloseBtn?.addEventListener("click", closeSessionsPanel);
  sessionsReloadBtn?.addEventListener("click", loadSessions);
}

function scheduleProfileHeaderPreview(colorA, colorB){
  const next = { a: colorA, b: colorB };
  headerGradientPreviewNext = next;
  if(prefersReducedMotion?.matches){
    applyProfileHeaderGradient(next.a, next.b, currentProfileHeaderRole);
    return;
  }
  if(headerGradientPreviewFrame) return;
  headerGradientPreviewFrame = requestAnimationFrame(() => {
    headerGradientPreviewFrame = 0;
    const vals = headerGradientPreviewNext || next;
    headerGradientPreviewNext = null;
    applyProfileHeaderGradient(vals.a, vals.b, currentProfileHeaderRole);
  });
}
function syncHeaderGradientInputs(colorA, colorB){
  const a = sanitizeHexColorInput(colorA, PROFILE_GRADIENT_DEFAULT_A) || PROFILE_GRADIENT_DEFAULT_A;
  const b = sanitizeHexColorInput(colorB, PROFILE_GRADIENT_DEFAULT_B) || PROFILE_GRADIENT_DEFAULT_B;
  if(headerColorA) headerColorA.value = normalizeColorForInput(a, PROFILE_GRADIENT_DEFAULT_A);
  if(headerColorAText) headerColorAText.value = a;
  if(headerColorB) headerColorB.value = normalizeColorForInput(b, PROFILE_GRADIENT_DEFAULT_B);
  if(headerColorBText) headerColorBText.value = b;
  applyProfileHeaderGradient(a, b, currentProfileHeaderRole);
}
function wireHeaderGradientInputs(){
  if(headerColorA && !headerColorA._wired){
    headerColorA._wired = true;
    headerColorA.addEventListener("input", () => {
      const vals = getHeaderGradientInputValues();
      if(headerColorAText) headerColorAText.value = vals.a;
      scheduleProfileHeaderPreview(vals.a, vals.b);
    });
  }
  if(headerColorAText && !headerColorAText._wired){
    headerColorAText._wired = true;
    headerColorAText.addEventListener("input", () => {
      const vals = getHeaderGradientInputValues();
      if(headerColorA) headerColorA.value = normalizeColorForInput(vals.a, PROFILE_GRADIENT_DEFAULT_A);
      scheduleProfileHeaderPreview(vals.a, vals.b);
    });
  }
  if(headerColorB && !headerColorB._wired){
    headerColorB._wired = true;
    headerColorB.addEventListener("input", () => {
      const vals = getHeaderGradientInputValues();
      if(headerColorBText) headerColorBText.value = vals.b;
      scheduleProfileHeaderPreview(vals.a, vals.b);
    });
  }
  if(headerColorBText && !headerColorBText._wired){
    headerColorBText._wired = true;
    headerColorBText.addEventListener("input", () => {
      const vals = getHeaderGradientInputValues();
      if(headerColorB) headerColorB.value = normalizeColorForInput(vals.b, PROFILE_GRADIENT_DEFAULT_B);
      scheduleProfileHeaderPreview(vals.a, vals.b);
    });
  }
}

function isSelfProfile(p){
  if (!p || !me) return false;
  const meId = me.id ?? me.user_id;
  const targetId = p.id ?? p.user_id;
  if (meId !== undefined && targetId !== undefined && String(meId) === String(targetId)) return true;
  const meUser = normKey(me.username || "");
  const targetUser = normKey(p.username || "");
  return !!meUser && meUser === targetUser;
}

function fillProfileUI(p, isSelf){
  currentProfileIsSelf = !!isSelf;

  if (modalAvatar){
    modalAvatar.innerHTML="";
    modalAvatar.appendChild(avatarNode(p.avatar, p.username, p.role));
  }
  if (modalName) modalName.textContent=p.username;
  if (modalRole){
    modalRole.textContent=`${roleIcon(p.role)} ${p.role}`;
    modalRole.style.color=roleBadgeColor(p.role);
  }
  // Mood lives under the username/role in the header.
  if (modalMood) {
    const mood = String(p.mood || "").trim();
    modalMood.textContent = mood;
    modalMood.style.display = mood ? "block" : "none";
  }

  // Couple chip (view-only, opt-in)
  try {
    if (profileCoupleChip) {
      if (p?.couple?.partner) {
        const sinceTxt = p.couple.since ? ` · ${fmtDaysSince(p.couple.since)}` : "";
        profileCoupleChip.style.display = "";
        profileCoupleChip.textContent = `${p.couple.statusEmoji || "💜"} ${p.couple.statusLabel || "Linked"}: ${p.couple.partner}${sinceTxt}`;
      } else {
        profileCoupleChip.style.display = "none";
        profileCoupleChip.textContent = "";
      }
    }
  } catch {}

  try {
    const card = p?.coupleCard;
    const members = Array.isArray(card?.members) ? card.members.filter(Boolean) : [];
    const hasCard = members.length >= 2;
    if (profileCoupleBody) profileCoupleBody.style.display = hasCard ? "" : "none";
    if (profileCoupleChip) {
      const hasChip = !!(p?.couple?.partner);
      profileCoupleChip.style.display = (!hasCard && hasChip) ? "" : "none";
    }
    if (hasCard) {
      if (profileCoupleAvatars) {
        profileCoupleAvatars.innerHTML = "";
        members.slice(0, 2).forEach((m) => {
          profileCoupleAvatars.appendChild(avatarNode(m.avatar, m.username, m.role));
        });
      }
      if (profileCoupleName) {
        const defaultName = members.length >= 2 ? `${members[0].username} + ${members[1].username}` : "Couple";
        profileCoupleName.textContent = card?.coupleName ? card.coupleName : defaultName;
      }
      if (profileCoupleBadge) {
        if (card?.showBadge && card?.statusEmoji) {
          profileCoupleBadge.style.display = "";
          profileCoupleBadge.textContent = card.statusEmoji;
          profileCoupleBadge.title = `${card.statusEmoji} ${card.statusLabel || "Linked"}`;
        } else {
          profileCoupleBadge.style.display = "none";
          profileCoupleBadge.textContent = "";
          profileCoupleBadge.title = "";
        }
      }
      if (profileCoupleMeta) {
        const sinceTxt = card?.since ? `Together ${fmtDaysSince(card.since)}` : "Together";
        const privacyLabel = card?.privacy ? card.privacy.charAt(0).toUpperCase() + card.privacy.slice(1) : "Private";
        profileCoupleMeta.textContent = `${sinceTxt} • ${privacyLabel}`;
      }
      if (profileCoupleBio) {
        const bio = String(card?.coupleBio || "").trim();
        profileCoupleBio.textContent = bio ? bio : "No couple bio yet.";
      }
    }
  } catch {}

  if (infoAge) infoAge.textContent = (p.age ?? "—");
  if (infoGender) infoGender.textContent = (p.gender ?? "—");
  if (infoLanguage){
    const langRow = infoLanguage.closest(".profileInfoRow");
    if (langRow) langRow.style.display = "none";
  }
  if (infoCreated) infoCreated.textContent = formatMemberSince(p.created_at);
  if (infoLastSeen) infoLastSeen.textContent = formatLastSeen(p.last_seen);
  if (infoRoom) infoRoom.textContent = p.current_room ? `#${p.current_room}` : (p.last_room ? `#${p.last_room}` : "—");
  const statusLabel = normalizeStatusLabel(p.last_status, "");
  const statusDisplay = formatIrisLolaStatusLabel(statusLabel, p.username);
  if (infoStatus) infoStatus.textContent = statusDisplay || "—";
  if (profileMoodValue) profileMoodValue.textContent = p.mood ? p.mood : "—";
  if (profileStatusValue) profileStatusValue.textContent = statusDisplay || "—";

  bioRender.innerHTML = p.bio ? renderBBCode(p.bio) : "(no bio)";
  renderLevelProgress(p, isSelf);
  syncProfileLikes(p, isSelf);
  setMsgline(profileLikeMsg, "");
  setMsgline(profileActionMsg, "");
  setMsgline(mediaMsg, "");
  if (profileCoupleCard){
    const showCouple = (profileCoupleBody && profileCoupleBody.style.display !== "none")
      || (profileCoupleChip && profileCoupleChip.style.display !== "none");
    profileCoupleCard.style.display = showCouple ? "" : "none";
  }
  fillProfileSheetHeader(p, isSelf);
  syncProfileEditUi();
  if (levelPanel){
    levelPanel.style.display = "none";
    const title = levelPanel.previousElementSibling;
    if (title && title.classList.contains("sectionTitle")) title.style.display = "none";
  }
}


function fillProfileSheetHeader(p, isSelf){
  if (!profileSheetHero) return;

  currentProfileHeaderRole = p?.role || "";
  applyProfileHeaderGradient(p?.header_grad_a, p?.header_grad_b, currentProfileHeaderRole);
  applyIdentityGlow(profileSheetHero, p);
  profileSheetHero.dataset.username = p?.username || "";

  // Avatar
  if (profileSheetAvatar){
    profileSheetAvatar.innerHTML = "";
    profileSheetAvatar.appendChild(avatarNode(p.avatar, p.username, p.role));
  }

  // Name + role chip
  if (profileSheetName) profileSheetName.textContent = p.username || "—";
  if (profileSheetRoleChip){
    profileSheetRoleChip.textContent = p.role ? `${roleIcon(p.role)} ${p.role}` : "User";
    profileSheetRoleChip.style.color = roleBadgeColor(p.role || "User");
  }
  if (profileSheetNameRow){
    let ring = profileSheetNameRow.querySelector(".profileLevelRing");
    if (!ring){
      ring = document.createElement("span");
      ring.className = "profileLevelRing";
      ring.setAttribute("aria-label", "Account level");
      profileSheetNameRow.insertBefore(ring, profileSheetNameRow.firstChild);
    }
    const levelVal = deriveProfileLevel(p);
    ring.textContent = Number.isFinite(levelVal) ? levelVal.toLocaleString() : "—";
    const xpInto = (typeof p?.xpIntoLevel === "number") ? p.xpIntoLevel : (isSelf ? progression?.xpIntoLevel : null);
    const xpNext = (typeof p?.xpForNextLevel === "number") ? p.xpForNextLevel : (isSelf ? progression?.xpForNextLevel : null);
    if (typeof xpInto === "number" && typeof xpNext === "number" && xpNext > 0) {
      const pct = Math.max(0, Math.min(100, (xpInto / xpNext) * 100));
      ring.style.setProperty("--levelProgress", `${pct}%`);
    } else {
      ring.style.removeProperty("--levelProgress");
    }
  }

  // Age + gender
  const ageVal = p.age;
  const genderVal = (p.gender || "").trim();
  const showAge = ageVal !== undefined && ageVal !== null && String(ageVal).trim() !== "";
  const showGender = !!genderVal;
  if (profileSheetAge){
    profileSheetAge.textContent = showAge ? `Age ${ageVal}` : "";
    profileSheetAge.style.display = showAge ? "inline-flex" : "none";
  }
  if (profileSheetGender){
    profileSheetGender.textContent = showGender ? genderVal : "";
    profileSheetGender.style.display = showGender ? "inline-flex" : "none";
  }
  if (profileSheetDetails){
    profileSheetDetails.style.display = (showAge || showGender) ? "flex" : "none";
  }

  // Subline: mood + status/room snapshot
  const mood = p.mood ? `Mood: ${p.mood}` : "Mood: (none)";
  const room = p.current_room ? `• In #${p.current_room}` : (p.last_room ? `• Last: #${p.last_room}` : "");
  const statusLabel = normalizeStatusLabel(p.last_status, "");
  const statusDisplay = formatIrisLolaStatusLabel(statusLabel, p.username);
  const status = statusDisplay ? `• ${statusDisplay}` : "";
  if (profileSheetSub) profileSheetSub.textContent = `${mood} ${status} ${room}`.trim();
  updateProfilePresenceDot(statusLabel);
  renderVibeChips(profileSheetVibes, p.vibe_tags);
  updateIrisLolaTogetherClass();

  // Stats (likes are real; stars show level)
  if (profileSheetStats){
    profileSheetStats.style.display = "flex";
    if (profileSheetLikes){
      const likesVal = Number(p.likes || 0);
      profileSheetLikes.textContent = `${isSelf ? "❤️" : (p.likedByMe ? "❤️" : "♡")} ${likesVal.toLocaleString()}`;
    }
    if (profileSheetStars){
      const levelVal = deriveProfileLevel(p);
      profileSheetStars.textContent = `⭐ ${levelVal.toLocaleString()}`;
    }
  }
}

function updateProfilePresenceDot(statusLabel){
  if (!profilePresenceDot) return;
  const raw = String(statusLabel || "").toLowerCase();
  let status = "offline";
  if (raw.includes("online")) status = "online";
  else if (raw.includes("away")) status = "away";
  else if (raw.includes("busy")) status = "busy";
  else if (raw.includes("dnd")) status = "dnd";
  else if (raw.includes("idle")) status = "idle";
  else if (raw.includes("gaming")) status = "gaming";
  else if (raw.includes("music")) status = "music";
  else if (raw.includes("working")) status = "working";
  else if (raw.includes("chatting")) status = "chatting";
  else if (raw.includes("lurking")) status = "lurking";
  profilePresenceDot.dataset.status = status;
  profilePresenceDot.title = statusLabel || "Offline";
  profilePresenceDot.style.display = "inline-flex";
}

function setProfileEditMode(next){
  profileEditMode = !!next;
  if (profileEditSection) profileEditSection.style.display = profileEditMode ? "block" : "none";
  if (profileEditToggleBtn) {
    profileEditToggleBtn.textContent = profileEditMode ? "Exit edit mode" : "Edit profile";
    profileEditToggleBtn.setAttribute("aria-pressed", profileEditMode ? "true" : "false");
  }
  syncProfileEditUi();
}

function syncProfileEditUi(){
  const showAvatarActions = currentProfileIsSelf && profileEditMode;
  if (profileSheetAvatarActions) profileSheetAvatarActions.style.display = showAvatarActions ? "flex" : "none";
  if (profileEditSection) profileEditSection.style.display = (currentProfileIsSelf && profileEditMode) ? "block" : "none";
}

function updateProfileActions({ isSelf = false, canModerate = false } = {}){
  // Quick "Edit profile" button now lives in the top quick-actions row.
  if (profileEditToggleBtn) profileEditToggleBtn.style.display = isSelf ? "" : "none";
  if (profileEditToggleRow) profileEditToggleRow.style.display = "none";
  applyCustomizeVisibility();
  if (addFriendBtn) addFriendBtn.style.display = isSelf ? "none" : "";
  if (declineFriendBtn) declineFriendBtn.style.display = "none";
  if (!isSelf && addFriendBtn) {
    const st = String(modalFriendInfo?.status || 'none');
    const rid = Number(modalFriendInfo?.requestId || 0);
    addFriendBtn.disabled = false;
    addFriendBtn.dataset.requestId = rid ? String(rid) : '';
    if (st === 'friends') { addFriendBtn.textContent = '✅ Friends'; addFriendBtn.disabled = true; }
    else if (st === 'outgoing') { addFriendBtn.textContent = '⏳ Request Sent'; addFriendBtn.disabled = true; }
    else if (st === 'incoming') { addFriendBtn.textContent = '✅ Accept Friend'; if (declineFriendBtn) { declineFriendBtn.style.display = ''; declineFriendBtn.textContent = '✖ Decline'; declineFriendBtn.dataset.requestId = rid ? String(rid) : ''; } }
    else { addFriendBtn.textContent = '🤝 Add Friend'; }
  }
  const showActionsTab = canModerate && !isSelf;
  if (viewModeration) viewModeration.style.display = canModerate ? "" : "none";
  if (tabActions) tabActions.style.display = showActionsTab ? "" : "none";
  [actionMuteBtn, actionKickBtn, actionBanBtn, actionAppealsBtn].forEach((btn) => {
    if (!btn) return;
    btn.style.display = showActionsTab ? "" : "none";
    btn.disabled = !modalCanModerate;
  });
  if (!showActionsTab && activeProfileTab === "actions") {
    setTab("profile");
  }
  if (actionsBtn) {
    actionsBtn.style.display = "none";
  }
  if (profileEditBtn) {
    profileEditBtn.style.display = "none";
  }
  if (profileSettingsBtn) {
    profileSettingsBtn.style.display = "none";
  }
  syncProfileEditUi();
  updateMemoryVisibility();
  setMsgline(profileActionMsg, "");
}

function updateBanControlsVisibility(){
  const isAdminPlus = roleRank(me?.role || "User") >= roleRank("Admin");
  if (quickBanBtn) quickBanBtn.style.display = isAdminPlus ? "" : "none";
  if (modBanBtn) modBanBtn.style.display = isAdminPlus ? "" : "none";
  if (modUnbanBtn) modUnbanBtn.style.display = isAdminPlus ? "" : "none";
  if (actionBanBtn) actionBanBtn.style.display = isAdminPlus ? "" : "none";
}

function applyProfileMenuVisibility(){
  // VIP-only rows are hidden for non-VIP.
  const isVip = roleRank(me?.role || "User") >= roleRank("VIP");
  document.querySelectorAll(".vipOnly").forEach(el => {
    el.style.display = isVip ? "" : "none";
  });
}


function syncSoundPrefsUI(tryUnlock = false){
  if (!prefSoundEnabled) return;

  const enabled = Sound.get.enabled();
  const roomOn = Sound.get.roomOn();
  const dmOn = Sound.get.dmOn();
  const mentionOn = Sound.get.mentionOn();
  const sentOn = Sound.get.sentOn();
  const receiveOn = Sound.get.receiveOn();
  const reactionOn = Sound.get.reactionOn();

  prefSoundEnabled.checked = enabled;
  if (prefSoundRoom) prefSoundRoom.checked = roomOn;
  if (prefSoundDm) prefSoundDm.checked = dmOn;
  if (prefSoundMention) prefSoundMention.checked = mentionOn;
  if (prefSoundSent) prefSoundSent.checked = sentOn;
  if (prefSoundReceive) prefSoundReceive.checked = receiveOn;
  if (prefSoundReaction) prefSoundReaction.checked = reactionOn;

  const subDisabled = !enabled;
  if (prefSoundRoom) prefSoundRoom.disabled = subDisabled;
  if (prefSoundDm) prefSoundDm.disabled = subDisabled;
  if (prefSoundMention) prefSoundMention.disabled = subDisabled;
  if (prefSoundSent) prefSoundSent.disabled = subDisabled;
  if (prefSoundReceive) prefSoundReceive.disabled = subDisabled;
  if (prefSoundReaction) prefSoundReaction.disabled = subDisabled;

  if (prefSoundStatus){
    prefSoundStatus.textContent = enabled
      ? "Sounds enabled. If you don't hear anything on iOS, toggle once to unlock audio."
      : "Sounds disabled.";
  }

  if (tryUnlock && enabled) {
    Sound.ensureUnlocked().then((ok) => {
      if (prefSoundStatus && enabled) {
        prefSoundStatus.textContent = ok
          ? "Sounds enabled."
          : "Sounds enabled (tap once in the app if your browser requires audio unlock).";
      }
    });
  }
}

function wireSoundPrefs(){
  if (!prefSoundEnabled || prefSoundEnabled._wired) return;
  prefSoundEnabled._wired = true;

  // Initialize defaults if missing
  const k = Sound.keys;
  if (localStorage.getItem(k.KEY_ROOM) === null) localStorage.setItem(k.KEY_ROOM, "1");
  if (localStorage.getItem(k.KEY_DM) === null) localStorage.setItem(k.KEY_DM, "1");
  if (localStorage.getItem(k.KEY_MENTION) === null) localStorage.setItem(k.KEY_MENTION, "1");
  if (localStorage.getItem(k.KEY_SENT) === null) localStorage.setItem(k.KEY_SENT, "0");
  if (localStorage.getItem(k.KEY_RECEIVE) === null) localStorage.setItem(k.KEY_RECEIVE, "0");
  if (localStorage.getItem(k.KEY_REACTION) === null) localStorage.setItem(k.KEY_REACTION, "0");

  syncSoundPrefsUI(false);

  prefSoundEnabled.addEventListener("change", async () => {
    Sound.set.setBool(k.KEY_ENABLED, prefSoundEnabled.checked);
    syncSoundPrefsUI(true);
    queuePersistPrefs({ sound: Sound.exportPrefs() });

    // User gesture here: attempt to unlock + play a tiny confirmation
    if (prefSoundEnabled.checked) {
      const ok = await Sound.ensureUnlocked();
      if (!ok && prefSoundStatus){
        prefSoundStatus.textContent = "Audio is blocked by your browser until you tap the page once.";
      } else if (prefSoundStatus){
        prefSoundStatus.textContent = "";
      }
      // Tiny confirmation (room cue) if room cue is enabled, otherwise DM cue
      try {
        if (Sound.get.roomOn()) Sound.cues.room();
        else if (Sound.get.dmOn()) Sound.cues.dm();
        else if (Sound.get.mentionOn()) Sound.cues.mention();
      } catch {}
    } else if (prefSoundStatus) {
      prefSoundStatus.textContent = "";
    }
  });

  prefSoundRoom?.addEventListener("change", () => {
    Sound.set.setBool(k.KEY_ROOM, prefSoundRoom.checked);
    syncSoundPrefsUI(false);
    queuePersistPrefs({ sound: Sound.exportPrefs() });
  });

  prefSoundDm?.addEventListener("change", () => {
    Sound.set.setBool(k.KEY_DM, prefSoundDm.checked);
    syncSoundPrefsUI(false);
    queuePersistPrefs({ sound: Sound.exportPrefs() });
  });

  prefSoundMention?.addEventListener("change", () => {
    Sound.set.setBool(k.KEY_MENTION, prefSoundMention.checked);
    syncSoundPrefsUI(false);
    queuePersistPrefs({ sound: Sound.exportPrefs() });
  });

  prefSoundSent?.addEventListener("change", () => {
    Sound.set.setBool(k.KEY_SENT, prefSoundSent.checked);
    syncSoundPrefsUI(false);
    queuePersistPrefs({ sound: Sound.exportPrefs() });
  });

  prefSoundReceive?.addEventListener("change", () => {
    Sound.set.setBool(k.KEY_RECEIVE, prefSoundReceive.checked);
    syncSoundPrefsUI(false);
    queuePersistPrefs({ sound: Sound.exportPrefs() });
  });

  prefSoundReaction?.addEventListener("change", () => {
    Sound.set.setBool(k.KEY_REACTION, prefSoundReaction.checked);
    syncSoundPrefsUI(false);
    queuePersistPrefs({ sound: Sound.exportPrefs() });
  });
}

function wireComfortMode(){
  if (!prefComfortMode || prefComfortMode._wired) return;
  prefComfortMode._wired = true;
  if (reduceMotionToggle) reduceMotionToggle.checked = prefComfortMode.checked;
  prefComfortMode.addEventListener("change", () => {
    applyComfortMode(prefComfortMode.checked, { persistLocal: true, persistServer: true });
    if (reduceMotionToggle) reduceMotionToggle.checked = prefComfortMode.checked;
  });
}

function updateChatFxSliderValue(el, value, decimals = 0){
  if (!el) return;
  const num = Number(value);
  if (!Number.isFinite(num)) return;
  el.textContent = decimals > 0 ? num.toFixed(decimals) : String(Math.round(num));
}

function setChatFxControlsDisabled(disabled){
  if (!chatFxPrefEls) return;
  const controls = [
    chatFxPrefEls.glow,
    chatFxPrefEls.font,
    chatFxPrefEls.nameFont,
    chatFxPrefEls.radius,
    chatFxPrefEls.border,
    chatFxPrefEls.glass,
    chatFxPrefEls.blur,
    chatFxPrefEls.accent,
    chatFxPrefEls.nameColorPick,
    chatFxPrefEls.textBold,
    chatFxPrefEls.textItalic,
    chatFxPrefEls.textGlow,
    chatFxPrefEls.textGradientEnabled,
    chatFxPrefEls.textGradientA,
    chatFxPrefEls.textGradientAPick,
    chatFxPrefEls.textGradientAClear,
    chatFxPrefEls.textGradientB,
    chatFxPrefEls.textGradientBPick,
    chatFxPrefEls.textGradientBClear,
    chatFxPrefEls.textGradientAngle
  ];
  controls.forEach((el) => {
    if (el) el.disabled = disabled;
  });
  chatFxPrefEls.densityButtons?.forEach((btn) => {
    btn.disabled = disabled;
    btn.classList.toggle("disabled", disabled);
  });
}

function setChatFxDensityButtons(value){
  if (!chatFxPrefEls?.densityButtons) return;
  chatFxPrefEls.densityButtons.forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.value === value);
  });
  if (chatSpacingCompact) chatSpacingCompact.checked = value === "compact";
}

function getChatFxDensitySelection(){
  if (!chatFxPrefEls?.densityButtons) return CHAT_FX_DEFAULTS.density;
  const active = chatFxPrefEls.densityButtons.find((btn) => btn.classList.contains("active"));
  return active?.dataset.value || CHAT_FX_DEFAULTS.density;
}

function syncChatFxControls(fx){
  if (!chatFxPrefEls) return;
  const resolved = normalizeChatFx(fx);
  chatFxPrefEls.enabled.checked = resolved.enabled;
  chatFxPrefEls.glow.value = resolved.glow;
  chatFxPrefEls.font.value = resolved.font;
  if (chatFxPrefEls.nameFont) chatFxPrefEls.nameFont.value = resolved.nameFont;
  chatFxPrefEls.radius.value = String(resolved.radius);
  chatFxPrefEls.border.value = String(resolved.border);
  chatFxPrefEls.glass.value = String(resolved.glass);
  chatFxPrefEls.blur.value = String(resolved.blur);
  chatFxPrefEls.accent.value = resolved.accent || "";
  if (chatFxPrefEls.bubbleColor) chatFxPrefEls.bubbleColor.value = resolved.bubbleColor || "";
  if (chatFxPrefEls.textColor) chatFxPrefEls.textColor.value = resolved.textColor || "";
  if (chatFxPrefEls.nameColor) chatFxPrefEls.nameColor.value = resolved.nameColor || "";
  if (chatFxPrefEls.autoContrast) chatFxPrefEls.autoContrast.checked = !!resolved.autoContrast;
  if (chatFxPrefEls.textBold) chatFxPrefEls.textBold.checked = !!resolved.textBold;
  if (chatFxPrefEls.textItalic) chatFxPrefEls.textItalic.checked = !!resolved.textItalic;
  if (chatFxPrefEls.textGlow) chatFxPrefEls.textGlow.value = resolved.textGlow;
  if (chatFxPrefEls.textGradientEnabled) chatFxPrefEls.textGradientEnabled.checked = !!resolved.textGradientEnabled;
  if (chatFxPrefEls.textGradientA) chatFxPrefEls.textGradientA.value = resolved.textGradientA || "";
  if (chatFxPrefEls.textGradientB) chatFxPrefEls.textGradientB.value = resolved.textGradientB || "";
  if (chatFxPrefEls.textGradientAngle) chatFxPrefEls.textGradientAngle.value = String(resolved.textGradientAngle);
  if (chatFxPrefEls.polishPack) chatFxPrefEls.polishPack.checked = !!resolved.polishPack;
  if (chatFxPrefEls.polishAuras) chatFxPrefEls.polishAuras.checked = !!resolved.polishAuras;
  if (chatFxPrefEls.polishAnimations) chatFxPrefEls.polishAnimations.checked = !!resolved.polishAnimations;
  setChatFxDensityButtons(resolved.density);
  updateChatFxSliderValue(chatFxPrefEls.radiusValue, resolved.radius);
  updateChatFxSliderValue(chatFxPrefEls.borderValue, resolved.border);
  updateChatFxSliderValue(chatFxPrefEls.glassValue, resolved.glass, 2);
  updateChatFxSliderValue(chatFxPrefEls.blurValue, resolved.blur);
  updateChatFxSliderValue(chatFxPrefEls.textGradientAngleValue, resolved.textGradientAngle);
  setChatFxControlsDisabled(!resolved.enabled);

  // Keep color pickers in sync (they can't be blank, so use fallbacks when empty/invalid)
  try {
    if (chatFxPrefEls.bubbleColorPick) {
      const v = String(resolved.bubbleColor || "").trim();
      chatFxPrefEls.bubbleColorPick.value = /^#[0-9a-f]{6}$/i.test(v) ? v : "#2b2d31";
    }
    if (chatFxPrefEls.textColorPick) {
      const v = String(resolved.textColor || "").trim();
      chatFxPrefEls.textColorPick.value = /^#[0-9a-f]{6}$/i.test(v) ? v : "#ffffff";
    }
    if (chatFxPrefEls.nameColorPick) {
      const v = String(resolved.nameColor || "").trim();
      chatFxPrefEls.nameColorPick.value = /^#[0-9a-f]{6}$/i.test(v) ? v : "#ffffff";
    }
    if (chatFxPrefEls.textGradientAPick) {
      const v = String(resolved.textGradientA || "").trim();
      chatFxPrefEls.textGradientAPick.value = /^#[0-9a-f]{6}$/i.test(v) ? v : "#7c4dff";
    }
    if (chatFxPrefEls.textGradientBPick) {
      const v = String(resolved.textGradientB || "").trim();
      chatFxPrefEls.textGradientBPick.value = /^#[0-9a-f]{6}$/i.test(v) ? v : "#00e5ff";
    }
  } catch {}
}

function readChatFxFormRaw(){
  if (!chatFxPrefEls) return { ...CHAT_FX_DEFAULTS };
  return {
    enabled: chatFxPrefEls.enabled.checked,
    glow: chatFxPrefEls.glow.value,
    font: chatFxPrefEls.font.value,
    nameFont: chatFxPrefEls.nameFont?.value || CHAT_FX_DEFAULTS.nameFont,
    radius: Number(chatFxPrefEls.radius.value),
    border: Number(chatFxPrefEls.border.value),
    glass: Number(chatFxPrefEls.glass.value),
    blur: Number(chatFxPrefEls.blur.value),
    density: getChatFxDensitySelection(),
    accent: (chatFxPrefEls.accent.value || "").trim(),
    bubbleColor: (chatFxPrefEls.bubbleColor?.value || "").trim(),
    textColor: (chatFxPrefEls.textColor?.value || "").trim(),
    nameColor: (chatFxPrefEls.nameColor?.value || "").trim(),
    autoContrast: !!chatFxPrefEls.autoContrast?.checked,
    textBold: !!chatFxPrefEls.textBold?.checked,
    textItalic: !!chatFxPrefEls.textItalic?.checked,
    textGlow: chatFxPrefEls.textGlow?.value || CHAT_FX_DEFAULTS.textGlow,
    textGradientEnabled: !!chatFxPrefEls.textGradientEnabled?.checked,
    textGradientA: (chatFxPrefEls.textGradientA?.value || "").trim(),
    textGradientB: (chatFxPrefEls.textGradientB?.value || "").trim(),
    textGradientAngle: Number(chatFxPrefEls.textGradientAngle?.value),
    polishPack: !!chatFxPrefEls.polishPack?.checked,
    polishAuras: !!chatFxPrefEls.polishAuras?.checked,
    polishAnimations: !!chatFxPrefEls.polishAnimations?.checked
  };
}

function updateChatFxPreview(fx){
  const normalized = normalizeChatFx(fx);
  if (chatFxPreviewBubble) {
    applyChatFxToBubble(chatFxPreviewBubble, normalized);
    chatFxPreviewBubble.closest(".chatFxPreview")?.classList.toggle("disabled", !normalized.enabled);
  }
  if (textFxPreviewBubble) {
    applyChatFxToBubble(textFxPreviewBubble, normalized);
    textFxPreviewBubble.closest(".chatFxPreview")?.classList.toggle("disabled", !normalized.enabled);
  }
}

function updateChatFxPreviewIdentity(user = me){
  if (!chatFxPreviewName || !chatFxPreviewRoleIcon || !chatFxPreviewAvatar) {
    // Still allow Text & Identity preview to update even if the Chat Appearance preview isn't mounted.
    if (!textFxPreviewName || !textFxPreviewRoleIcon || !textFxPreviewAvatar) return;
  }
  const username = user?.username || "You";
  const role = normalizeRole(user?.role || "User");
  const roleToken = roleKey(role);
  if (chatFxPreviewName) {
    chatFxPreviewName.textContent = username;
    chatFxPreviewName.dataset.role = roleToken;
    chatFxPreviewName.closest(".name")?.setAttribute("data-role", roleToken);
  }
  if (chatFxPreviewRoleIcon) chatFxPreviewRoleIcon.textContent = `${roleIcon(role)} `;
  if (chatFxPreviewAvatar) {
    chatFxPreviewAvatar.innerHTML = "";
    chatFxPreviewAvatar.appendChild(avatarNode(user?.avatar || user?.avatarUrl, username, role, username));
  }
  if (chatFxPreviewTime) chatFxPreviewTime.textContent = "Just now";

  if (textFxPreviewName) {
    textFxPreviewName.textContent = username;
    textFxPreviewName.dataset.role = roleToken;
    textFxPreviewName.closest(".name")?.setAttribute("data-role", roleToken);
  }
  if (textFxPreviewRoleIcon) textFxPreviewRoleIcon.textContent = `${roleIcon(role)} `;
  if (textFxPreviewAvatar) {
    textFxPreviewAvatar.innerHTML = "";
    textFxPreviewAvatar.appendChild(avatarNode(user?.avatar || user?.avatarUrl, username, role, username));
  }
  if (textFxPreviewTime) textFxPreviewTime.textContent = "Just now";
}

function handleChatFxInput(){
  if (!chatFxPrefEls) return;
  const normalized = normalizeChatFx(readChatFxFormRaw());
  chatFxDraft = normalized;
  updateChatFxSliderValue(chatFxPrefEls.radiusValue, normalized.radius);
  updateChatFxSliderValue(chatFxPrefEls.borderValue, normalized.border);
  updateChatFxSliderValue(chatFxPrefEls.glassValue, normalized.glass, 2);
  updateChatFxSliderValue(chatFxPrefEls.blurValue, normalized.blur);
  updateChatFxSliderValue(chatFxPrefEls.textGradientAngleValue, normalized.textGradientAngle);
  updatePolishPackClasses(normalized);
  updateChatFxPreview(normalized);
  setChatFxControlsDisabled(!normalized.enabled);
}

function applyChatFxToSelfBubbles(fx){
  if (!me?.username) return;
  const normalized = normalizeChatFx(fx);
  document.querySelectorAll(".msgItem.self .bubble").forEach((bubble) => {
    const groupBody = bubble.closest(".msgGroupBody");
    applyChatFxToBubble(bubble, normalized, { groupBody });
    queueContrastReinforcement(bubble);
  });
  document.querySelectorAll(".dmRow.self").forEach((row) => {
    const bubble = row.querySelector(".dmBubble");
    const wrap = row.querySelector(".dmBubbleWrap");
    applyChatFxToBubble(bubble, normalized, { dmRow: row, dmWrap: wrap });
    queueContrastReinforcement(bubble);
  });
}

async function saveChatFxPrefs(){
  if (!chatFxPrefEls || !me) return;
  const normalized = normalizeChatFx(readChatFxFormRaw());
  if (chatFxStatus) chatFxStatus.textContent = "Saving...";
  const saved = await persistUserPrefs({ chatFx: normalized });
  if (!saved){
    if (chatFxStatus) chatFxStatus.textContent = "Could not save.";
    return;
  }
  applyChatFxPrefsFromServer(saved.chatFx || normalized);
  applyChatFxToSelfBubbles(chatFxPrefs);
  if (chatFxStatus) {
    chatFxStatus.textContent = "Saved.";
    setTimeout(() => {
      if (chatFxStatus?.textContent === "Saved.") chatFxStatus.textContent = "";
    }, 2400);
  }
}

const PERSONALISATION_SECTIONS_KEY = "ui.personalisation.openSections";
function initPersonalisationSections(container){
  if (!container) return;
  const sections = Array.from(container.querySelectorAll(".prefsSection"));
  if (!sections.length) return;
  let stored = [];
  try {
    const raw = localStorage.getItem(PERSONALISATION_SECTIONS_KEY);
    stored = raw ? JSON.parse(raw) : [];
  } catch {
    stored = [];
  }
  const storedSet = new Set(Array.isArray(stored) ? stored : []);
  sections.forEach((section, idx) => {
    const key = section.dataset.section || String(idx);
    if (storedSet.size) section.open = storedSet.has(key);
    section.addEventListener("toggle", () => {
      const openKeys = sections
        .filter((item) => item.open)
        .map((item) => item.dataset.section)
        .filter(Boolean);
      try { localStorage.setItem(PERSONALISATION_SECTIONS_KEY, JSON.stringify(openKeys)); } catch {}
    });
  });
}

function wireChatFxPrefs(){
  const chatFxFontEl = document.getElementById("chatFxFont");
  const chatFxNameFontEl = document.getElementById("chatFxNameFont");
  if (!chatFxFontEl || chatFxPrefEls) return;
  const fontOptions = buildFontSelectOptionsHTML();
  chatFxFontEl.innerHTML = fontOptions;
  if (chatFxNameFontEl) chatFxNameFontEl.innerHTML = fontOptions;

  const q = (sel) => document.querySelector(sel);
  chatFxPrefEls = {
    enabled: q("#chatFxEnabled"),
    glow: q("#chatFxGlow"),
    font: q("#chatFxFont"),
    nameFont: q("#chatFxNameFont"),
    radius: q("#chatFxRadius"),
    radiusValue: q("#chatFxRadiusValue"),
    border: q("#chatFxBorder"),
    borderValue: q("#chatFxBorderValue"),
    glass: q("#chatFxGlass"),
    glassValue: q("#chatFxGlassValue"),
    blur: q("#chatFxBlur"),
    blurValue: q("#chatFxBlurValue"),
    accent: q("#chatFxAccent"),
    bubbleColor: q("#chatFxBubbleColor"),
    bubbleColorPick: q("#chatFxBubbleColorPick"),
    bubbleColorClear: q("#chatFxBubbleColorClear"),
    textColor: q("#chatFxTextColor"),
    textColorPick: q("#chatFxTextColorPick"),
    textColorClear: q("#chatFxTextColorClear"),
    nameColor: q("#chatFxNameColor"),
    nameColorPick: q("#chatFxNameColorPick"),
    nameColorClear: q("#chatFxNameColorClear"),
    autoContrast: q("#chatFxAutoContrast"),
    textBold: q("#chatFxTextBold"),
    textItalic: q("#chatFxTextItalic"),
    textGlow: q("#chatFxTextGlow"),
    textGradientEnabled: q("#chatFxTextGradientEnabled"),
    textGradientA: q("#chatFxTextGradientA"),
    textGradientAPick: q("#chatFxTextGradientAPick"),
    textGradientAClear: q("#chatFxTextGradientAClear"),
    textGradientB: q("#chatFxTextGradientB"),
    textGradientBPick: q("#chatFxTextGradientBPick"),
    textGradientBClear: q("#chatFxTextGradientBClear"),
    textGradientAngle: q("#chatFxTextGradientAngle"),
    textGradientAngleValue: q("#chatFxTextGradientAngleValue"),
    polishPack: q("#chatFxPolishPack"),
    polishAuras: q("#chatFxPolishAuras"),
    polishAnimations: q("#chatFxPolishAnimations"),
    saveBtn: q("#chatFxSaveBtn"),
    status: q("#chatFxStatus"),
    densityRow: q("#chatFxDensity")
  };
  chatFxPrefEls.densityButtons = Array.from(chatFxPrefEls.densityRow?.querySelectorAll("button") || []);
  chatFxPreviewBubble = q("#chatFxPreviewBubble");
  chatFxPreviewAvatar = q("#chatFxPreviewAvatar");
  chatFxPreviewName = q("#chatFxPreviewName");
  chatFxPreviewRoleIcon = q("#chatFxPreviewRoleIcon");
  chatFxPreviewTime = q("#chatFxPreviewTime");

  // Text & Identity sticky preview (optional)
  textFxPreviewBubble = q("#textFxPreviewBubble");
  textFxPreviewAvatar = q("#textFxPreviewAvatar");
  textFxPreviewName = q("#textFxPreviewName");
  textFxPreviewRoleIcon = q("#textFxPreviewRoleIcon");
  textFxPreviewTime = q("#textFxPreviewTime");
  chatFxStatus = chatFxPrefEls.status;
  updateChatFxPreviewIdentity(me);

  chatFxPrefEls.enabled?.addEventListener("change", handleChatFxInput);
  chatFxPrefEls.glow?.addEventListener("change", handleChatFxInput);
  chatFxPrefEls.font?.addEventListener("change", handleChatFxInput);
  chatFxPrefEls.nameFont?.addEventListener("change", handleChatFxInput);
  chatFxPrefEls.radius?.addEventListener("input", handleChatFxInput);
  chatFxPrefEls.border?.addEventListener("input", handleChatFxInput);
  chatFxPrefEls.glass?.addEventListener("input", handleChatFxInput);
  chatFxPrefEls.blur?.addEventListener("input", handleChatFxInput);
  chatFxPrefEls.accent?.addEventListener("input", handleChatFxInput);
  chatFxPrefEls.bubbleColor?.addEventListener("input", handleChatFxInput);
  chatFxPrefEls.textColor?.addEventListener("input", handleChatFxInput);
  chatFxPrefEls.autoContrast?.addEventListener("change", handleChatFxInput);
  chatFxPrefEls.textBold?.addEventListener("change", handleChatFxInput);
  chatFxPrefEls.textItalic?.addEventListener("change", handleChatFxInput);
  chatFxPrefEls.textGlow?.addEventListener("change", handleChatFxInput);
  chatFxPrefEls.textGradientEnabled?.addEventListener("change", handleChatFxInput);
  chatFxPrefEls.textGradientA?.addEventListener("input", handleChatFxInput);
  chatFxPrefEls.textGradientB?.addEventListener("input", handleChatFxInput);
  chatFxPrefEls.textGradientAngle?.addEventListener("input", handleChatFxInput);
  chatFxPrefEls.polishPack?.addEventListener("change", handleChatFxInput);
  chatFxPrefEls.polishAuras?.addEventListener("change", handleChatFxInput);
  chatFxPrefEls.polishAnimations?.addEventListener("change", handleChatFxInput);
  chatFxPrefEls.accent?.addEventListener("blur", () => {
    const normalized = normalizeChatFx(readChatFxFormRaw());
    if (chatFxPrefEls?.accent) chatFxPrefEls.accent.value = normalized.accent || "";
    handleChatFxInput();
  });
  chatFxPrefEls.bubbleColor?.addEventListener("blur", () => {
    const normalized = normalizeChatFx(readChatFxFormRaw());
    if (chatFxPrefEls?.bubbleColor) chatFxPrefEls.bubbleColor.value = normalized.bubbleColor || "";
    // Keep picker in sync (only supports 6-digit).
    if (chatFxPrefEls?.bubbleColorPick) {
      const v = (normalized.bubbleColor || "").trim();
      if (/^#[0-9a-f]{6}$/i.test(v)) chatFxPrefEls.bubbleColorPick.value = v;
    }
    handleChatFxInput();
  });
  chatFxPrefEls.textColor?.addEventListener("blur", () => {
    const normalized = normalizeChatFx(readChatFxFormRaw());
    if (chatFxPrefEls?.textColor) chatFxPrefEls.textColor.value = normalized.textColor || "";
    handleChatFxInput();
  });
  chatFxPrefEls.textGradientA?.addEventListener("blur", () => {
    const normalized = normalizeChatFx(readChatFxFormRaw());
    if (chatFxPrefEls?.textGradientA) chatFxPrefEls.textGradientA.value = normalized.textGradientA || "";
    if (chatFxPrefEls?.textGradientAPick) {
      const v = String(normalized.textGradientA || "").trim();
      if (/^#[0-9a-f]{6}$/i.test(v)) chatFxPrefEls.textGradientAPick.value = v;
    }
    handleChatFxInput();
  });
  chatFxPrefEls.textGradientB?.addEventListener("blur", () => {
    const normalized = normalizeChatFx(readChatFxFormRaw());
    if (chatFxPrefEls?.textGradientB) chatFxPrefEls.textGradientB.value = normalized.textGradientB || "";
    if (chatFxPrefEls?.textGradientBPick) {
      const v = String(normalized.textGradientB || "").trim();
      if (/^#[0-9a-f]{6}$/i.test(v)) chatFxPrefEls.textGradientBPick.value = v;
    }
    handleChatFxInput();
  });

  // Color picker wiring (bubble + text): keep picker <-> text inputs synced and allow clearing to blank.
  const syncPickerFromText = (textEl, pickerEl, fallback) => {
    if (!textEl || !pickerEl) return;
    const v = String(textEl.value || "").trim();
    if (/^#([0-9a-f]{6})$/i.test(v)) pickerEl.value = v;
    else pickerEl.value = fallback;
  };
  const syncTextFromPicker = (textEl, pickerEl) => {
    if (!textEl || !pickerEl) return;
    textEl.value = pickerEl.value || "";
  };

  // Bubble color picker
  if (chatFxPrefEls.bubbleColorPick && chatFxPrefEls.bubbleColor){
    syncPickerFromText(chatFxPrefEls.bubbleColor, chatFxPrefEls.bubbleColorPick, "#2b2d31");
    chatFxPrefEls.bubbleColorPick.addEventListener("input", () => {
      syncTextFromPicker(chatFxPrefEls.bubbleColor, chatFxPrefEls.bubbleColorPick);
      handleChatFxInput();
    });
    chatFxPrefEls.bubbleColor.addEventListener("input", () => {
      syncPickerFromText(chatFxPrefEls.bubbleColor, chatFxPrefEls.bubbleColorPick, "#2b2d31");
    });
  }
  chatFxPrefEls.bubbleColorClear?.addEventListener("click", () => {
    if (chatFxPrefEls?.bubbleColor) chatFxPrefEls.bubbleColor.value = "";
    syncPickerFromText(chatFxPrefEls?.bubbleColor, chatFxPrefEls?.bubbleColorPick, "#2b2d31");
    handleChatFxInput();
  });

  // Text color picker
  if (chatFxPrefEls.textColorPick && chatFxPrefEls.textColor){
    syncPickerFromText(chatFxPrefEls.textColor, chatFxPrefEls.textColorPick, "#ffffff");
    chatFxPrefEls.textColorPick.addEventListener("input", () => {
      syncTextFromPicker(chatFxPrefEls.textColor, chatFxPrefEls.textColorPick);
      handleChatFxInput();
    });
    chatFxPrefEls.textColor.addEventListener("input", () => {
      syncPickerFromText(chatFxPrefEls.textColor, chatFxPrefEls.textColorPick, "#ffffff");
    });
  }
  chatFxPrefEls.textColorClear?.addEventListener("click", () => {
    if (chatFxPrefEls?.textColor) chatFxPrefEls.textColor.value = "";
    syncPickerFromText(chatFxPrefEls?.textColor, chatFxPrefEls?.textColorPick, "#ffffff");
    handleChatFxInput();
  });

  // Text gradient color pickers
  if (chatFxPrefEls.textGradientAPick && chatFxPrefEls.textGradientA){
    syncPickerFromText(chatFxPrefEls.textGradientA, chatFxPrefEls.textGradientAPick, "#7c4dff");
    chatFxPrefEls.textGradientAPick.addEventListener("input", () => {
      syncTextFromPicker(chatFxPrefEls.textGradientA, chatFxPrefEls.textGradientAPick);
      handleChatFxInput();
    });
    chatFxPrefEls.textGradientA.addEventListener("input", () => {
      syncPickerFromText(chatFxPrefEls.textGradientA, chatFxPrefEls.textGradientAPick, "#7c4dff");
    });
  }
  chatFxPrefEls.textGradientAClear?.addEventListener("click", () => {
    if (chatFxPrefEls?.textGradientA) chatFxPrefEls.textGradientA.value = "";
    syncPickerFromText(chatFxPrefEls?.textGradientA, chatFxPrefEls?.textGradientAPick, "#7c4dff");
    handleChatFxInput();
  });
  if (chatFxPrefEls.textGradientBPick && chatFxPrefEls.textGradientB){
    syncPickerFromText(chatFxPrefEls.textGradientB, chatFxPrefEls.textGradientBPick, "#00e5ff");
    chatFxPrefEls.textGradientBPick.addEventListener("input", () => {
      syncTextFromPicker(chatFxPrefEls.textGradientB, chatFxPrefEls.textGradientBPick);
      handleChatFxInput();
    });
    chatFxPrefEls.textGradientB.addEventListener("input", () => {
      syncPickerFromText(chatFxPrefEls.textGradientB, chatFxPrefEls.textGradientBPick, "#00e5ff");
    });
  }
  chatFxPrefEls.textGradientBClear?.addEventListener("click", () => {
    if (chatFxPrefEls?.textGradientB) chatFxPrefEls.textGradientB.value = "";
    syncPickerFromText(chatFxPrefEls?.textGradientB, chatFxPrefEls?.textGradientBPick, "#00e5ff");
    handleChatFxInput();
  });

  // Username color picker (no hex typing UI, but we still store a hex value internally)
  if (chatFxPrefEls.nameColorPick && chatFxPrefEls.nameColor){
    syncPickerFromText(chatFxPrefEls.nameColor, chatFxPrefEls.nameColorPick, "#ffffff");
    chatFxPrefEls.nameColorPick.addEventListener("input", () => {
      syncTextFromPicker(chatFxPrefEls.nameColor, chatFxPrefEls.nameColorPick);
      handleChatFxInput();
    });
  }
  chatFxPrefEls.nameColorClear?.addEventListener("click", () => {
    if (chatFxPrefEls?.nameColor) chatFxPrefEls.nameColor.value = "";
    syncPickerFromText(chatFxPrefEls?.nameColor, chatFxPrefEls?.nameColorPick, "#ffffff");
    handleChatFxInput();
  });

  chatFxPrefEls.densityButtons.forEach((btn) => {
    btn.addEventListener("click", () => {
      if (btn.disabled) return;
      setChatFxDensityButtons(btn.dataset.value);
      handleChatFxInput();
    });
  });
  if (chatSpacingCompact && !chatSpacingCompact._wired){
    chatSpacingCompact._wired = true;
    chatSpacingCompact.addEventListener("change", () => {
      const next = chatSpacingCompact.checked ? "compact" : "cozy";
      setChatFxDensityButtons(next);
      handleChatFxInput();
    });
  }

  if (effectsPreset && !effectsPreset._wired){
    effectsPreset._wired = true;
    effectsPreset.addEventListener("change", () => {
      if (!chatFxPrefEls) return;
      const preset = effectsPreset.value;
      if (!preset){
        return;
      }
      const presets = {
        soft: { glow: "soft", textGlow: "soft", glass: 0.3, blur: 4 },
        neon: { glow: "neon", textGlow: "neon", glass: 0.5, blur: 8 },
        minimal: { glow: "off", textGlow: "off", glass: 0, blur: 0 },
      };
      const next = presets[preset];
      if (!next) return;
      if (chatFxPrefEls.glow) chatFxPrefEls.glow.value = next.glow;
      if (chatFxPrefEls.textGlow) chatFxPrefEls.textGlow.value = next.textGlow;
      if (chatFxPrefEls.glass) chatFxPrefEls.glass.value = String(next.glass);
      if (chatFxPrefEls.blur) chatFxPrefEls.blur.value = String(next.blur);
      handleChatFxInput();
    });
  }

  if (reduceMotionToggle && !reduceMotionToggle._wired){
    reduceMotionToggle._wired = true;
    reduceMotionToggle.addEventListener("change", () => {
      if (!prefComfortMode) return;
      prefComfortMode.checked = reduceMotionToggle.checked;
      prefComfortMode.dispatchEvent(new Event("change", { bubbles: true }));
    });
  }

  chatFxPrefEls.saveBtn?.addEventListener("click", saveChatFxPrefs);

  syncChatFxControls(chatFxPrefs);
  updateChatFxPreview(chatFxPrefs);
  chatFxDraft = { ...chatFxPrefs };
}

function resetChatFxSection(section){
  if (!chatFxPrefEls) return;
  const defaults = mergeChatFxDefaults({});
  const applyTextDefaults = () => {
    if (chatFxPrefEls.font) chatFxPrefEls.font.value = defaults.font;
    if (chatFxPrefEls.nameFont) chatFxPrefEls.nameFont.value = defaults.nameFont;
    if (chatFxPrefEls.textColor) chatFxPrefEls.textColor.value = defaults.textColor || "";
    if (chatFxPrefEls.textColorPick) chatFxPrefEls.textColorPick.value = normalizeColorForInput(defaults.textColor || "#ffffff", "#ffffff");
    if (chatFxPrefEls.nameColor) chatFxPrefEls.nameColor.value = defaults.nameColor || "";
    if (chatFxPrefEls.nameColorPick) chatFxPrefEls.nameColorPick.value = normalizeColorForInput(defaults.nameColor || "#ffffff", "#ffffff");
    if (chatFxPrefEls.textBold) chatFxPrefEls.textBold.checked = !!defaults.textBold;
    if (chatFxPrefEls.textItalic) chatFxPrefEls.textItalic.checked = !!defaults.textItalic;
    if (chatFxPrefEls.textGlow) chatFxPrefEls.textGlow.value = defaults.textGlow;
    if (chatFxPrefEls.textGradientEnabled) chatFxPrefEls.textGradientEnabled.checked = !!defaults.textGradientEnabled;
    if (chatFxPrefEls.textGradientA) chatFxPrefEls.textGradientA.value = defaults.textGradientA || "";
    if (chatFxPrefEls.textGradientB) chatFxPrefEls.textGradientB.value = defaults.textGradientB || "";
    if (chatFxPrefEls.textGradientAngle) chatFxPrefEls.textGradientAngle.value = String(defaults.textGradientAngle);
    if (chatFxPrefEls.autoContrast) chatFxPrefEls.autoContrast.checked = !!defaults.autoContrast;
  };
  const applyBubbleDefaults = () => {
    if (chatFxPrefEls.enabled) chatFxPrefEls.enabled.checked = !!defaults.enabled;
    if (chatFxPrefEls.glow) chatFxPrefEls.glow.value = defaults.glow;
    if (chatFxPrefEls.radius) chatFxPrefEls.radius.value = String(defaults.radius);
    if (chatFxPrefEls.border) chatFxPrefEls.border.value = String(defaults.border);
    if (chatFxPrefEls.glass) chatFxPrefEls.glass.value = String(defaults.glass);
    if (chatFxPrefEls.blur) chatFxPrefEls.blur.value = String(defaults.blur);
    if (chatFxPrefEls.bubbleColor) chatFxPrefEls.bubbleColor.value = defaults.bubbleColor || "";
    if (chatFxPrefEls.bubbleColorPick) chatFxPrefEls.bubbleColorPick.value = normalizeColorForInput(defaults.bubbleColor || "#2b2d31", "#2b2d31");
    setChatFxDensityButtons(defaults.density);
  };

  if (section === "chat") applyBubbleDefaults();
  if (section === "text") applyTextDefaults();
  if (section === "profile") {
    if (chatFxPrefEls.polishAuras) chatFxPrefEls.polishAuras.checked = !!defaults.polishAuras;
    if (chatFxPrefEls.accent) chatFxPrefEls.accent.value = defaults.accent || "";
    syncHeaderGradientInputs(PROFILE_GRADIENT_DEFAULT_A, PROFILE_GRADIENT_DEFAULT_B);
  }
  if (section === "effects") {
    if (chatFxPrefEls.polishPack) chatFxPrefEls.polishPack.checked = !!defaults.polishPack;
    if (chatFxPrefEls.polishAnimations) chatFxPrefEls.polishAnimations.checked = !!defaults.polishAnimations;
    if (prefComfortMode) {
      prefComfortMode.checked = false;
      prefComfortMode.dispatchEvent(new Event("change", { bubbles: true }));
    }
    if (effectsPreset) effectsPreset.value = "";
  }
  handleChatFxInput();
}

resetChatAppearanceBtn?.addEventListener("click", () => resetChatFxSection("chat"));
resetTextIdentityBtn?.addEventListener("click", () => resetChatFxSection("text"));
resetProfileAppearanceBtn?.addEventListener("click", () => resetChatFxSection("profile"));
resetEffectsBtn?.addEventListener("click", () => resetChatFxSection("effects"));
resetLayoutBtn?.addEventListener("click", () => {
  uiScaleResetBtn?.click();
  if (reduceMotionToggle) reduceMotionToggle.checked = false;
});
resetAdvancedBtn?.addEventListener("click", () => {
  const defaults = {
    enabled: false,
    room: true,
    dm: true,
    mention: true,
    sent: false,
    receive: false,
    reaction: false,
  };
  Sound.importPrefs(defaults);
  syncSoundPrefsUI(true);
  queuePersistPrefs({ sound: Sound.exportPrefs() });

  dmNeonColor = dmNeonDefaults.color;
  applyDmNeonPrefs();
  saveDmNeonColorToStorage();

  badgePrefs = { ...badgeDefaults };
  applyBadgePrefs();
  saveBadgePrefsToStorage();
});

function wireProfileAvatarActions(){
  if (profileAvatarChangeBtn && !profileAvatarChangeBtn._wired){
    profileAvatarChangeBtn._wired = true;
    profileAvatarChangeBtn.addEventListener("click", () => {
      if (!currentProfileIsSelf) return;
      setProfileEditMode(true);
      setTab("profile");
      // Open file picker for avatar
      try{ avatarFile?.click(); } catch {}
    });
  }

  if (profileAvatarRemoveBtn && !profileAvatarRemoveBtn._wired){
    profileAvatarRemoveBtn._wired = true;
    profileAvatarRemoveBtn.addEventListener("click", async () => {
      if (!me?.username) return;
      if (!confirm("Remove your avatar?")) return;
      if (profileMsg) profileMsg.textContent = "Removing avatar...";
      try{
        const res = await fetch("/profile/avatar", { method: "DELETE" });
        if (!res.ok){
          const t = await res.text().catch(()=> "");
          if (profileMsg) profileMsg.textContent = t || "Could not remove avatar.";
          return;
        }
        if (profileMsg) profileMsg.textContent = "Avatar removed.";
        await loadMyProfile();
        await openMyProfile();
      }catch{
        if (profileMsg) profileMsg.textContent = "Could not remove avatar.";
      }
    });
  }
}

function syncProfileLikes(p = {}, isSelf = false){
  const likesVal = Number(p.likes || 0);
  profileLikeState = { count: likesVal, liked: !!p.likedByMe, isSelf: !!isSelf };
  if (likeCount) {
    likeCount.textContent = `${p.likedByMe ? "❤️" : "♡"} ${likesVal.toLocaleString()}`;
    likeCount.classList.toggle("active", !!p.likedByMe);
    likeCount.setAttribute("aria-pressed", p.likedByMe ? "true" : "false");
    likeCount.setAttribute("aria-label", isSelf ? "Likes" : (p.likedByMe ? "Unlike profile" : "Like profile"));
    likeCount.setAttribute("role", "button");
    likeCount.tabIndex = isSelf ? -1 : 0;
    likeCount.dataset.disabled = isSelf ? "true" : "false";
  }
  if (profileSheetLikes) profileSheetLikes.textContent = `${isSelf ? "❤️" : (p.likedByMe ? "❤️" : "♡")} ${likesVal.toLocaleString()}`;
  if (likeProfileBtn) {
    likeProfileBtn.disabled = !!isSelf;
    likeProfileBtn.classList.toggle("active", !!p.likedByMe);
    likeProfileBtn.setAttribute("aria-pressed", p.likedByMe ? "true" : "false");
    likeProfileBtn.textContent = isSelf ? "❤️ Likes" : (p.likedByMe ? "❤️ Liked" : "♡ Like");
  }
}
function syncCustomizationUI(){
  badgePrefs = loadBadgePrefsFromStorage();
  applyBadgePrefs();
  if (customizeMsg) customizeMsg.textContent = "";
}

function updateMemoryFilterChips(){
  memoryFilterChips.forEach((chip) => {
    const active = chip.dataset.filter === memoryFilter;
    chip.classList.toggle("active", active);
  });
}

function updateMemoryVisibility(){
  // The Timeline tab should be usable even when the feature is disabled, so users
  // can see what's available and toggle it on (instead of the button "doing nothing").
  const showTimeline = currentProfileIsSelf && memoryFeatureAvailable;
  if (tabTimeline) tabTimeline.style.display = showTimeline ? "" : "none";
  if (viewTimeline) viewTimeline.style.display = activeProfileTab === "timeline" && showTimeline ? "block" : "none";
  if (!showTimeline && activeProfileTab === "timeline") setTab("profile");

  const isOwner = roleRank(me?.role || "User") >= roleRank("Owner");
  const showSettings = currentProfileIsSelf && isOwner && memoryFeatureAvailable;
  if (memorySettingsPanel) memorySettingsPanel.style.display = showSettings ? "block" : "none";
  if (memoryEnabledToggle) memoryEnabledToggle.checked = !!memoryEnabled;
}

function renderMemoryTimeline(){
  if (!memoryTimelineList || !memoryFeaturedRow || !memoryEmptyState) return;
  const list = memoryCacheByFilter.get(memoryFilter) || [];
  const pinned = list.filter((m) => m.pinned);

  memoryTimelineList.innerHTML = "";
  memoryFeaturedRow.innerHTML = "";

  if (pinned.length) {
    if (memoryFeaturedSection) memoryFeaturedSection.style.display = "";
    pinned.forEach((memory) => {
      memoryFeaturedRow.appendChild(buildMemoryCard(memory, { compact: true }));
    });
  } else if (memoryFeaturedSection) {
    memoryFeaturedSection.style.display = "none";
  }

  list.forEach((memory) => {
    memoryTimelineList.appendChild(buildMemoryCard(memory));
  });

  memoryEmptyState.style.display = list.length ? "none" : "block";
}

function buildMemoryCard(memory, { compact = false } = {}){
  const card = document.createElement("div");
  card.className = `panelBox memoryCard${compact ? " compact" : ""}`;

  const icon = document.createElement("div");
  icon.className = "memoryCardIcon";
  icon.textContent = memory.icon || "✨";

  const body = document.createElement("div");
  const header = document.createElement("div");
  header.className = "memoryCardHeader";

  const title = document.createElement("div");
  title.className = "memoryCardTitle";
  title.textContent = memory.title || "Memory";

  const pinBtn = document.createElement("button");
  pinBtn.className = "iconBtn smallIcon memoryPinBtn";
  pinBtn.type = "button";
  pinBtn.textContent = "📌";
  pinBtn.setAttribute("aria-label", memory.pinned ? "Unpin memory" : "Pin memory");
  pinBtn.setAttribute("aria-pressed", memory.pinned ? "true" : "false");
  pinBtn.classList.toggle("active", !!memory.pinned);
  pinBtn.addEventListener("click", async (e) => {
    e.preventDefault();
    e.stopPropagation();
    await toggleMemoryPin(memory);
  });

  const meta = document.createElement("div");
  meta.className = "memoryCardMeta";
  meta.textContent = formatChangelogDate(memory.created_at || Date.now());

  const desc = document.createElement("div");
  desc.className = "memoryCardDesc";
  desc.textContent = memory.description || "";

  header.appendChild(title);
  header.appendChild(pinBtn);
  body.appendChild(header);
  body.appendChild(meta);
  if (!compact && desc.textContent) body.appendChild(desc);

  card.appendChild(icon);
  card.appendChild(body);
  return card;
}

async function refreshMemorySettings({ force = false } = {}){
  if (!currentProfileIsSelf) return;
  if (memorySettingsLoaded && !force) {
    updateMemoryVisibility();
    return;
  }
  try {
    const res = await fetch("/api/memory-settings");
    if (!res.ok) throw new Error(await res.text());
    const data = await res.json();
    memoryFeatureAvailable = !!data.available;
    memoryEnabled = !!data.enabled;
    memorySettingsLoaded = true;
    if (memorySettingsMsg) memorySettingsMsg.textContent = "";
  } catch (e) {
    memoryFeatureAvailable = false;
    memoryEnabled = false;
    if (memorySettingsMsg) memorySettingsMsg.textContent = "Memories are unavailable right now.";
  }
  updateMemoryVisibility();
}

async function loadMemories({ force = false } = {}){
  if (!currentProfileIsSelf || !memoryEnabled) return;
  if (!force && memoryCacheByFilter.has(memoryFilter)) {
    renderMemoryTimeline();
    return;
  }
  if (memoryLoading) return;
  memoryLoading = true;
  if (memoryTimelineMsg) memoryTimelineMsg.textContent = "Loading memories...";
  try {
    const res = await fetch(`/api/memories?filter=${encodeURIComponent(memoryFilter)}`);
    if (res.status === 403) {
      memoryEnabled = false;
      updateMemoryVisibility();
      return;
    }
    if (!res.ok) throw new Error(await res.text());
    const data = await res.json();
    memoryCacheByFilter.set(memoryFilter, Array.isArray(data.memories) ? data.memories : []);
  } catch (e) {
    if (memoryTimelineMsg) memoryTimelineMsg.textContent = e?.message || "Could not load memories.";
  } finally {
    memoryLoading = false;
    if (memoryTimelineMsg && memoryTimelineMsg.textContent === "Loading memories...") memoryTimelineMsg.textContent = "";
  }
  renderMemoryTimeline();
}

async function toggleMemoryPin(memory){
  if (!memory?.id) return;
  try {
    const res = await fetch(`/api/memories/${memory.id}/pin`, { method: "POST" });
    if (!res.ok) throw new Error(await res.text());
    const data = await res.json();
    memory.pinned = !!data.pinned;
    memoryCacheByFilter.set(
      memoryFilter,
      (memoryCacheByFilter.get(memoryFilter) || []).map((m) => (m.id === memory.id ? memory : m))
    );
    renderMemoryTimeline();
  } catch (e) {
    if (memoryTimelineMsg) memoryTimelineMsg.textContent = e?.message || "Could not update memory pin.";
  }
}

async function openMyProfile(){
  closeDrawers();
  clearAvatarPreview();

  // Try the self profile endpoint first (includes edit fields)
  let res = await fetch("/profile");
  if (!res.ok && me?.username){
    // Fallback to member profile route if /profile fails for any reason
    try { await openMemberProfile(me.username); return; } catch {}
  }
  if(!res.ok) return;
  const p = await res.json();
  updateRoleCache(p.username, p.role);
  modalTargetUsername = p.username;
  applyProgressionPayload(p);

  modalTitle.textContent="My Profile";
  // Created date is shown in the info grid; keep header meta empty.
  if (modalMeta) modalMeta.textContent = "";

  fillProfileUI(p, true);
  syncCustomizationUI();
  memoryFilter = "all";
  memoryCacheByFilter.clear();
  updateMemoryFilterChips();
  await refreshMemorySettings({ force: true });
  if (memoryEnabled) await loadMemories({ force: true });

  if (myProfileEdit) myProfileEdit.style.display="block";
  try { refreshCouplesUI(); } catch {}
  modalCanModerate = false;
  if (actionsBtn) actionsBtn.style.display = "none";
  closeMemberActionsOverlay();
  updateBanControlsVisibility();

  editMood.value=p.mood||"";
  if (editUsername) editUsername.value = "";
  editAge.value=(p.age ?? "");
  editGender.value=p.gender||"";
  editBio.value=p.bio||"";
  scheduleBioPreview();
  selectedVibeTags = sanitizeVibeTagsClient(p.vibe_tags);
  renderVibeOptions(selectedVibeTags);
  syncHeaderGradientInputs(p.header_grad_a, p.header_grad_b);
  avatarFile.value="";
  profileMsg.textContent="";
  setProfileEditMode(false);
  setCustomizePage(null);

  const canMod = (roleRank(me.role) >= roleRank("Moderator"));
  updateProfileActions({ isSelf: true, canModerate: canMod });
  setTab("profile");
  openModal();
}
profileBtn?.addEventListener("click", openMyProfile);

saveProfileBtn.addEventListener("click", async ()=>{
  profileMsg.textContent="Saving...";
  const form=new FormData();
  form.append("mood", editMood.value);
  form.append("age", editAge.value);
  form.append("gender", editGender.value);
  form.append("bio", editBio.value);
  form.append("vibeTags", JSON.stringify(selectedVibeTags || []));
  const grad = getHeaderGradientInputValues();
  form.append("headerColorA", grad.a);
  form.append("headerColorB", grad.b);
  if(avatarFile.files[0]) form.append("avatar", avatarFile.files[0]);

  const res=await fetch("/profile", {method:"POST", body:form});
  if(!res.ok){
    const t=await res.text().catch(()=> "Save failed.");
    profileMsg.textContent=t || "Save failed.";
    return;
  }
  profileMsg.textContent="Saved!";
  pushNotification({ type: "system", text: "Profile saved." });
  await loadMyProfile();
  socket?.emit("join room", { room: currentRoom, status: normalizeStatusLabel(statusSelect.value, "Online") });
  await openMyProfile();
});
changeUsernameBtn?.addEventListener("click", async () => {
  if (!editUsername) return;
  const desired = String(editUsername.value || "").trim();
  if (!desired) {
    profileMsg.textContent = "Enter a new username.";
    return;
  }
  profileMsg.textContent = "Changing username...";
  try {
    const res = await fetch("/api/me/username", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: desired }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok || !data.ok) {
      profileMsg.textContent = data.message || "Could not change username.";
      return;
    }
    profileMsg.textContent = `Username updated to ${data.username}.`;
    editUsername.value = "";
    await loadMyProfile();
    await loadProgression();
  } catch (err) {
    console.error("Username change failed", err);
    profileMsg.textContent = "Could not change username.";
  }
});
refreshProfileBtn.addEventListener("click", openMyProfile);

memoryEnabledToggle?.addEventListener("change", async () => {
  if (!currentProfileIsSelf) return;
  if (memorySettingsMsg) memorySettingsMsg.textContent = "Saving...";
  memoryEnabledToggle.disabled = true;
  try {
    const res = await fetch("/api/memory-settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ enabled: !!memoryEnabledToggle.checked }),
    });
    if (!res.ok) throw new Error(await res.text());
    const data = await res.json();
    memoryFeatureAvailable = !!data.available;
    memoryEnabled = !!data.enabled;
    if (!memoryEnabled) memoryCacheByFilter.clear();
    if (memorySettingsMsg) memorySettingsMsg.textContent = "Memory settings updated.";
    updateMemoryVisibility();
    if (memoryEnabled) await loadMemories({ force: true });
  } catch (e) {
    if (memorySettingsMsg) memorySettingsMsg.textContent = e?.message || "Could not update memory settings.";
    memoryEnabledToggle.checked = memoryEnabled;
  } finally {
    memoryEnabledToggle.disabled = false;
  }
});

async function openMemberProfile(username){
  modalTargetUsername = username;
  closeDrawers();

  const res=await fetch("/profile/" + encodeURIComponent(username));
  if(!res.ok) return;
  const p=await res.json();
  modalTargetUserId = Number(p?.id) || null;
  const isSelf = isSelfProfile(p);
  if (isSelf) applyProgressionPayload(p);

  modalTitle.textContent="Member Profile";
  // Created date is shown in the info grid; keep header meta empty.
  if (modalMeta) modalMeta.textContent = "";
  fillProfileUI(p, isSelf);
  modalFriendInfo = p.friend || null;
  syncCustomizationUI();
  memoryFilter = "all";
  memoryCacheByFilter.clear();
  updateMemoryFilterChips();
  if (isSelf) {
    await refreshMemorySettings({ force: true });
    if (memoryEnabled) await loadMemories({ force: true });
  } else {
    memoryFeatureAvailable = false;
    memoryEnabled = false;
    memorySettingsLoaded = false;
    updateMemoryVisibility();
  }

  if (myProfileEdit) myProfileEdit.style.display = isSelf ? "block" : "none";

  const iCanMod = (roleRank(me.role) >= roleRank("Moderator")) && (roleRank(me.role) > roleRank(p.role));
  modalCanModerate = iCanMod;
  memberActionsOverlay.style.display = iCanMod ? "block" : "none";
  updateBanControlsVisibility();
  quickReason.value=""; quickModMsg.textContent="";
  if(quickMuteMins) quickMuteMins.value = quickMuteMins.querySelector("option")?.value || "10";
  if(quickBanMins) quickBanMins.value = quickBanMins.querySelector("option")?.value || "0";
  if(quickKickSeconds) quickKickSeconds.value = quickKickSeconds.querySelector("option[selected]")?.value || quickKickSeconds.value || "300";

  setModTarget(username);
  if(modReason) modReason.value = "";
  if(modMsg) modMsg.textContent = "";

  updateProfileActions({ isSelf, canModerate: (roleRank(me.role) >= roleRank("Moderator")) });
  setProfileEditMode(false);
  setCustomizePage(null);
  setTab("profile");
  openModal();
}

let likeToggleInFlight = false;
async function toggleProfileLike() {
  if (!modalTargetUsername || likeToggleInFlight || profileLikeState.isSelf) return;
  setMsgline(profileLikeMsg, "");
  likeToggleInFlight = true;
  const prev = { ...profileLikeState };
  const nextLiked = !prev.liked;
  const nextCount = Math.max(0, prev.count + (nextLiked ? 1 : -1));
  syncProfileLikes({ likes: nextCount, likedByMe: nextLiked }, false);
  if (likeProfileBtn) likeProfileBtn.disabled = true;

  try {
    const res = await fetch(`/profile/${encodeURIComponent(modalTargetUsername)}/like`, { method: "POST" });
    if (!res.ok) {
      const t = await res.text().catch(() => "");
      throw new Error(t || "Could not update like.");
    }
    const data = await res.json();
    syncProfileLikes({ likes: data.likes, likedByMe: data.liked }, false);
  } catch (err) {
    syncProfileLikes({ likes: prev.count, likedByMe: prev.liked }, false);
    setMsgline(profileLikeMsg, err?.message || "Could not update like.");
  } finally {
    likeToggleInFlight = false;
    if (likeProfileBtn) likeProfileBtn.disabled = profileLikeState.isSelf;
  }
}

likeProfileBtn?.addEventListener("click", async () => {
  await toggleProfileLike();
});

declineFriendBtn?.addEventListener("click", async () => {
  if (!modalTargetUsername) return;
  const st = String(modalFriendInfo?.status || 'none');
  const rid = Number(declineFriendBtn.dataset.requestId || modalFriendInfo?.requestId || 0);
  if (st !== 'incoming' || !rid) return;
  setMsgline(profileActionMsg, "");
  try {
    const res = await fetch('/api/friends/respond', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ requestId: rid, action: 'decline' }) });
    if (!res.ok) throw new Error(await res.text());
    modalFriendInfo = { status: 'none', requestId: null };
    friendsDirty = true;
    setMsgline(profileActionMsg, 'Friend request declined.');
  } catch (e) {
    setMsgline(profileActionMsg, e?.message || 'Could not decline.');
  } finally {
    updateProfileActions({ isSelf: false, canModerate: (roleRank(me.role) >= roleRank("Moderator")) });
  }
});

addFriendBtn?.addEventListener("click", async () => {
  if (addFriendBtn.disabled) return;
  const st = String(modalFriendInfo?.status || 'none');
  const rid = Number(addFriendBtn.dataset.requestId || modalFriendInfo?.requestId || 0);
  if (!modalTargetUsername) return;
  setMsgline(profileActionMsg, "");
  try {
    if (st === 'incoming' && rid) {
      const res = await fetch('/api/friends/respond', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ requestId: rid, action: 'accept' }) });
      if (!res.ok) throw new Error(await res.text());
      modalFriendInfo = { status: 'friends', requestId: null };
      friendsDirty = true;
      setMsgline(profileActionMsg, 'Friend request accepted.');
    } else if (st === 'none') {
      const res = await fetch('/api/friends/request', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ to: modalTargetUsername }) });
      if (!res.ok) throw new Error(await res.text());
      const data = await res.json().catch(()=>({}));
      modalFriendInfo = { status: data?.autoAccepted ? 'friends' : 'outgoing', requestId: null };
      friendsDirty = true;
      setMsgline(profileActionMsg, data?.autoAccepted ? 'Friend added.' : 'Friend request sent.');
    }
  } catch (e) {
    setMsgline(profileActionMsg, e?.message || 'Could not update friend.');
  } finally {
    updateProfileActions({ isSelf: false, canModerate: (roleRank(me.role) >= roleRank("Moderator")) });
  }
});

likeCount?.addEventListener("click", async () => {
  if (profileLikeState.isSelf) return;
  await toggleProfileLike();
});
likeCount?.addEventListener("keydown", async (e) => {
  if (profileLikeState.isSelf) return;
  if (e.key === "Enter" || e.key === " ") {
    e.preventDefault();
    await toggleProfileLike();
  }
});

// media actions
copyUsernameBtn?.addEventListener("click", async ()=>{
  const u = modalTargetUsername || me?.username || "";
  try{ await navigator.clipboard.writeText(u); setMsgline(mediaMsg, "Copied username."); }
  catch{ setMsgline(mediaMsg, "Copy failed (browser blocked)."); }
});
saveBadgePrefsBtn?.addEventListener("click", () => {
  const directRaw = directBadgeColorText?.value || directBadgeColor?.value || badgePrefs.direct || badgeDefaults.direct;
  const groupRaw = groupBadgeColorText?.value || groupBadgeColor?.value || badgePrefs.group || badgeDefaults.group;
  badgePrefs = {
    direct: sanitizeColor(directRaw, directBadgeColor?.value, badgeDefaults.direct),
    group: sanitizeColor(groupRaw, groupBadgeColor?.value, badgeDefaults.group),
  };
  applyBadgePrefs();
  saveBadgePrefsToStorage();
  queuePersistPrefs({ dmBadgePrefs: badgePrefs });
  if (customizeMsg) customizeMsg.textContent = "Saved badge colors.";
});
directBadgeColor?.addEventListener("input", () => {
  if(directBadgeColorText) directBadgeColorText.value = directBadgeColor.value;
  if(dmBadgeDot) dmBadgeDot.style.backgroundColor = directBadgeColor.value;
});
groupBadgeColor?.addEventListener("input", () => {
  if(groupBadgeColorText) groupBadgeColorText.value = groupBadgeColor.value;
  if(groupDmBadgeDot) groupDmBadgeDot.style.backgroundColor = groupBadgeColor.value;
});
directBadgeColorText?.addEventListener("input", () => {
  const safe = sanitizeColor(directBadgeColorText.value, directBadgeColor?.value, badgeDefaults.direct);
  if(directBadgeColor) directBadgeColor.value = normalizeColorForInput(safe, badgeDefaults.direct);
  if(dmBadgeDot) dmBadgeDot.style.backgroundColor = safe;
});
groupBadgeColorText?.addEventListener("input", () => {
  const safe = sanitizeColor(groupBadgeColorText.value, groupBadgeColor?.value, badgeDefaults.group);
  if(groupBadgeColor) groupBadgeColor.value = normalizeColorForInput(safe, badgeDefaults.group);
  if(groupDmBadgeDot) groupDmBadgeDot.style.backgroundColor = safe;
});

// moderation quick tools
function requireReason(reason){
  const cleaned = (reason || "").trim();
  if(!cleaned) return "Reason is required.";
  if(cleaned.length < 3) return "Reason must be at least 3 characters.";
  return null;
}
function selectedModTarget(){
  const typed = (modUser?.value || "").trim();
  const chosen = modUserSelect?.value || "";
  return chosen || typed;
}
function confirmModeration(action, target){
  const label = target ? `${action} ${target}?` : `Confirm ${action}?`;
  return window.confirm(label);
}
function ensureTarget(target){
  if(!target) return "Select or enter a username.";
  return null;
}

function formatDurationLabel({ seconds = 0, minutes = 0 } = {}){
  let totalSeconds = Number(seconds) || 0;
  if (!totalSeconds && minutes) totalSeconds = Number(minutes) * 60;
  if (!totalSeconds || totalSeconds <= 0) return "5 minutes";
  if (totalSeconds < 60) return `${totalSeconds} seconds`;
  const totalMinutes = Math.round(totalSeconds / 60);
  if (totalMinutes < 60) return `${totalMinutes} minute${totalMinutes === 1 ? "" : "s"}`;
  const hours = Math.round(totalMinutes / 60);
  return `${hours} hour${hours === 1 ? "" : "s"}`;
}

function emitModWithAck(event, payload, { timeoutMs = 3500 } = {}){
  return new Promise((resolve) => {
    if (!socket) return resolve({ ok: false, error: "Disconnected." });
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      resolve({ ok: false, error: "No response." });
    }, timeoutMs);
    socket.emit(event, payload, (resp) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (resp && typeof resp.ok === "boolean") return resolve(resp);
      resolve({ ok: true });
    });
  });
}

function undoWithAck(event, payload){
  return emitModWithAck(event, payload).then((resp) => {
    if (!resp?.ok) throw new Error(resp?.error || "Undo failed.");
  });
}

quickKickBtn.addEventListener("click", async ()=>{
  const reason = (quickReason.value || "").trim();
  const err=requireReason(reason);
  if(err){ quickModMsg.textContent=err; return; }
  if(!modalTargetUsername){ quickModMsg.textContent="No target selected."; return; }
  if(!confirmModeration("kick", modalTargetUsername)) return;
  const durationSeconds = Number(quickKickSeconds?.value || 300);
  const resp = await emitModWithAck("mod kick", { username: modalTargetUsername, reason, durationSeconds });
  if(!resp?.ok){ quickModMsg.textContent = resp?.error || "Kick failed."; return; }
  quickModMsg.textContent="Kick sent.";
  showToast(`Kicked ${modalTargetUsername} for ${formatDurationLabel({ seconds: durationSeconds })}`, {
    actionLabel: "Undo",
    actionFn: () => undoWithAck("mod unkick", { username: modalTargetUsername }),
    durationMs: 5200
  });
});
if(quickUnkickBtn){
  quickUnkickBtn.addEventListener("click", async ()=>{
    if(!modalTargetUsername){ quickModMsg.textContent="No target selected."; return; }
    if(!confirmModeration("unkick", modalTargetUsername)) return;
    const resp = await emitModWithAck("mod unkick", { username: modalTargetUsername });
    if(!resp?.ok){ quickModMsg.textContent = resp?.error || "Unkick failed."; return; }
    quickModMsg.textContent="Unkick sent.";
  });
}
if(quickUnmuteBtn){
  quickUnmuteBtn.addEventListener("click", async ()=>{
    const reason = (quickReason.value || "").trim();
    const err=requireReason(reason);
    if(err){ quickModMsg.textContent=err; return; }
    if(!modalTargetUsername){ quickModMsg.textContent="No target selected."; return; }
    if(!confirmModeration("unmute", modalTargetUsername)) return;
    const resp = await emitModWithAck("mod unmute", { username: modalTargetUsername, reason });
    if(!resp?.ok){ quickModMsg.textContent = resp?.error || "Unmute failed."; return; }
    quickModMsg.textContent="Unmute sent.";
  });
}

quickMuteBtn.addEventListener("click", async ()=>{
  const reason = (quickReason.value || "").trim();
  const err=requireReason(reason);
  if(err){ quickModMsg.textContent=err; return; }
  if(!modalTargetUsername){ quickModMsg.textContent="No target selected."; return; }
  if(!confirmModeration("mute", modalTargetUsername)) return;
  const mins=Number(quickMuteMins.value || 10);
  const resp = await emitModWithAck("mod mute", { username: modalTargetUsername, minutes: mins, reason });
  if(!resp?.ok){ quickModMsg.textContent = resp?.error || "Mute failed."; return; }
  quickModMsg.textContent="Mute sent.";
  showToast(`Muted ${modalTargetUsername}`, {
    actionLabel: "Undo",
    actionFn: () => undoWithAck("mod unmute", { username: modalTargetUsername, reason: "Undo mute" }),
    durationMs: 5200
  });
});
quickBanBtn.addEventListener("click", async ()=>{
  const reason = (quickReason.value || "").trim();
  const err=requireReason(reason);
  if(err){ quickModMsg.textContent=err; return; }
  if(!modalTargetUsername){ quickModMsg.textContent="No target selected."; return; }
  if(!confirmModeration("ban", modalTargetUsername)) return;
  const mins=Number(quickBanMins.value || 0);
  const resp = await emitModWithAck("mod ban", { username: modalTargetUsername, minutes: mins, reason });
  if(!resp?.ok){ quickModMsg.textContent = resp?.error || "Ban failed."; return; }
  quickModMsg.textContent="Ban sent.";
});

// mod panel
modRefreshTargetsBtn?.addEventListener("click", ()=>{
  refreshModTargetOptions(lastUsers);
  modMsg.textContent = "Online list refreshed.";
});
modKickBtn.addEventListener("click", async ()=>{
  const reason = (modReason.value || "").trim();
  const err=requireReason(reason);
  if(err){ modMsg.textContent=err; return; }
  const target = selectedModTarget();
  const targetErr = ensureTarget(target);
  if(targetErr){ modMsg.textContent = targetErr; return; }
  if(!confirmModeration("kick", target)) return;
  const durationSeconds = 300;
  const resp = await emitModWithAck("mod kick", { username: target, reason, durationSeconds });
  if(!resp?.ok){ modMsg.textContent = resp?.error || "Kick failed."; return; }
  modMsg.textContent="Kick sent.";
  showToast(`Kicked ${target} for ${formatDurationLabel({ seconds: durationSeconds })}`, {
    actionLabel: "Undo",
    actionFn: () => undoWithAck("mod unkick", { username: target }),
    durationMs: 5200
  });
});
modMuteBtn.addEventListener("click", async ()=>{
  const reason = (modReason.value || "").trim();
  const err=requireReason(reason);
  if(err){ modMsg.textContent=err; return; }
  const target = selectedModTarget();
  const targetErr = ensureTarget(target);
  if(targetErr){ modMsg.textContent = targetErr; return; }
  if(!confirmModeration("mute", target)) return;
  const mins=Number(modMuteMins.value || 10);
  const resp = await emitModWithAck("mod mute", { username: target, minutes: mins, reason });
  if(!resp?.ok){ modMsg.textContent = resp?.error || "Mute failed."; return; }
  modMsg.textContent="Mute sent.";
  showToast(`Muted ${target}`, {
    actionLabel: "Undo",
    actionFn: () => undoWithAck("mod unmute", { username: target, reason: "Undo mute" }),
    durationMs: 5200
  });
});
modBanBtn.addEventListener("click", async ()=>{
  const reason = (modReason.value || "").trim();
  const err=requireReason(reason);
  if(err){ modMsg.textContent=err; return; }
  const target = selectedModTarget();
  const targetErr = ensureTarget(target);
  if(targetErr){ modMsg.textContent = targetErr; return; }
  if(!confirmModeration("ban", target)) return;
  const mins=Number(modBanMins.value || 0);
  const resp = await emitModWithAck("mod ban", { username: target, minutes: mins, reason });
  if(!resp?.ok){ modMsg.textContent = resp?.error || "Ban failed."; return; }
  modMsg.textContent="Ban sent.";
});
modUnmuteBtn.addEventListener("click", async ()=>{
  const reason = (modReason.value || "").trim();
  const err=requireReason(reason);
  if(err){ modMsg.textContent=err; return; }
  const target = selectedModTarget();
  const targetErr = ensureTarget(target);
  if(targetErr){ modMsg.textContent = targetErr; return; }
  if(!confirmModeration("unmute", target)) return;
  const resp = await emitModWithAck("mod unmute", { username: target, reason });
  if(!resp?.ok){ modMsg.textContent = resp?.error || "Unmute failed."; return; }
  modMsg.textContent="Unmute sent.";
});
modUnbanBtn.addEventListener("click", async ()=>{
  const reason = (modReason.value || "").trim();
  const err=requireReason(reason);
  if(err){ modMsg.textContent=err; return; }
  const target = selectedModTarget();
  const targetErr = ensureTarget(target);
  if(targetErr){ modMsg.textContent = targetErr; return; }
  if(!confirmModeration("unban", target)) return;
  const resp = await emitModWithAck("mod unban", { username: target, reason });
  if(!resp?.ok){ modMsg.textContent = resp?.error || "Unban failed."; return; }
  modMsg.textContent="Unban sent.";
});
modWarnBtn.addEventListener("click", ()=>{
  const reason = (modReason.value || "").trim();
  const err=requireReason(reason);
  if(err){ modMsg.textContent=err; return; }
  const target = selectedModTarget();
  const targetErr = ensureTarget(target);
  if(targetErr){ modMsg.textContent = targetErr; return; }
  if(!confirmModeration("warn", target)) return;
  socket?.emit("mod warn", { username: target, reason });
  modMsg.textContent="Warn sent.";
});
modOpenProfileBtn.addEventListener("click", async ()=>{
  const target = selectedModTarget();
  const targetErr = ensureTarget(target);
  if(targetErr){ modMsg.textContent = targetErr; return; }
  await openMemberProfile(target);
});
modSetRoleBtn.addEventListener("click", async ()=>{
  // Role changes can be done without a reason.
  const reason = (modReason.value || "").trim();
  const target = selectedModTarget();
  const targetErr = ensureTarget(target);
  if(targetErr){ modMsg.textContent = targetErr; return; }
  if(!modSetRole.value){ modMsg.textContent="Choose a role first."; return; }
  if(!confirmModeration("role update", target)) return;
  const prevRole = cachedRoleForUser(target);
  const nextRole = modSetRole.value;
  const resp = await emitModWithAck("mod set role", { username: target, role: nextRole, reason });
  if(!resp?.ok){ modMsg.textContent = resp?.error || "Role update failed."; return; }
  updateRoleCache(target, nextRole);
  modMsg.textContent="Role change sent.";
  if (prevRole && prevRole !== nextRole) {
    showToast(`Role updated for ${target}`, {
      actionLabel: "Undo",
      actionFn: () => undoWithAck("mod set role", { username: target, role: prevRole, reason: "Undo role" }),
      durationMs: 5200
    });
  }
});

// logs
async function loadModLogs({ user="", action="", limit=50 } = {}){
  const url = new URL("/mod/logs", location.origin);
  url.searchParams.set("limit", String(limit));
  if(user) url.searchParams.set("user", user);
  if(action) url.searchParams.set("action", action);
  const res = await fetch(url);
  if(!res.ok) return { ok:false, status:res.status, rows:[] };
  const rows = await res.json();
  return { ok:true, status:200, rows: rows || [] };
}
function renderLogs(rows){
  logsBody.innerHTML="";
  for(const r of rows){
    const tr=document.createElement("tr");
    tr.innerHTML = `
      <td>${escapeHtml(new Date(r.ts).toLocaleString())}</td>
      <td><span class="pill">${escapeHtml(r.actor_role || "")}</span> ${escapeHtml(r.actor_username || "")}</td>
      <td><span class="pill">${escapeHtml(r.action || "")}</span></td>
      <td>${escapeHtml(r.target_username || "—")}</td>
      <td>${escapeHtml(r.room || "—")}</td>
      <td>${escapeHtml(r.details || "")}</td>
    `;
    logsBody.appendChild(tr);
  }
}
async function refreshLogs(){
  logsMsg.textContent="Loading logs...";
  const limit=Number(logLimit.value || 50);
  const user=logUser.value.trim();
  const action=logAction.value;
  const result=await loadModLogs({ user, action, limit });
  if(!result.ok){
    logsMsg.textContent = result.status === 403 ? "You do not have permission to view logs." : "Failed to load logs.";
    renderLogs([]);
    return;
  }
  logsMsg.textContent = `Showing ${result.rows.length} log(s).`;
  renderLogs(result.rows);
}
refreshLogsBtn.addEventListener("click", refreshLogs);

// start app
async function initChatApp(){
  const sessionUser = await validateSession();
  if(!sessionUser){
    initLoginUI();
    return;
  }

  me = sessionUser;
  setAuthUser(sessionUser);
  setView("chat");

  // Staff-only: show staff buttons in members drawer
  if(appealsPanelBtn) appealsPanelBtn.hidden = !isStaffRole(me?.role);
  // Referrals are for Admin+ review (mods create them)
  if(referralsPanelBtn) referralsPanelBtn.hidden = !(me?.role==="Admin" || me?.role==="Co-owner" || me?.role==="Owner");
  // Role debug is for Owner/Co-Owner (and Admin as fallback)
  if(roleDebugPanelBtn) roleDebugPanelBtn.hidden = !(me?.role==="Owner" || me?.role==="Co-owner" || me?.role==="Admin");
  
  if(featureFlagsPanelBtn) featureFlagsPanelBtn.hidden = !(me?.role==="Owner");
  if(sessionsPanelBtn) sessionsPanelBtn.hidden = !(me?.role==="Owner");
initAppealsDurationSelect();

  await loadVibeTags();
  await loadThemePreference();

  await loadMyProfile();
  try { refreshCouplesUI(); } catch {}
  await loadUserPrefs();
  await loadProgression();
  renderLevelProgress(progression, true);

  setRightPanelMode("rooms");
  setMenuTab(activeMenuTab);
  updateChangelogControlsVisibility();
  updateRoomControlsVisibility();

  if (socket) {
    try { socket.removeAllListeners(); } catch {}
    try { socket.disconnect(); } catch {}
  }
  socket = io({
    transports: ["websocket", "polling"],
    reconnection: true,
    reconnectionAttempts: Infinity,
    reconnectionDelay: 500,
    reconnectionDelayMax: 4000,
    timeout: 15000,
  });

  // ---- Mobile suspend/resume: treat common disconnect reasons as benign ----
  let suppressRealtimeNoticesUntil = 0;

  function suppressRealtimeNoticesFor(ms = 5000){
    suppressRealtimeNoticesUntil = Date.now() + ms;
  }

  function isBenignDisconnect(reason){
    const r = String(reason || "").toLowerCase();
    return (
      Date.now() < suppressRealtimeNoticesUntil ||
      r === "transport close" ||
      r === "ping timeout" ||
      r === "io client disconnect" ||
      r === "io server disconnect"
    );
  }

  socket.on("connect", () => {
    try{
      socket.emit("client:hello", {
        tz: (Intl.DateTimeFormat && Intl.DateTimeFormat().resolvedOptions().timeZone) || null,
        locale: navigator.language || null,
        platform: navigator.platform || null,
      });
    }catch(_){}

    // Join initial room so history + realtime messages work reliably
    joinRoom(currentRoom);
  });

  socket.on("restriction:status", async (payload) => {
    if(payload?.type && payload.type !== "none"){
      try{ socket.disconnect(); }catch{}
      await ensureRestrictedSocket();
      showRestrictedView(payload);
      await refreshMyAppeal();
    }
  });

  socket.on("onlineUsers", (names) => {
    onlineUsers = Array.isArray(names) ? names : [];
    updateIrisLolaTogetherClass();
  });
  socket.on("connect_error", (err) => {
    // Very common during resume/network switching; avoid spooking users
    if(Date.now() < suppressRealtimeNoticesUntil) return;
    addSystem(`⚠️ Realtime connection failed: ${err?.message || err}`);
  });


  socket.on("featureFlags:update", (flags={})=>{
    featureFlags = (flags && typeof flags==="object") ? flags : {};
    applyFeatureFlags();
    // Keep owner panel in sync if open
    try{ renderFeatureFlagsGrid(); }catch(_){}
  });

  socket.on("couples:update", () => {
    try { refreshCouplesUI(); } catch {}
    try { emitLocalMembersRefresh(); } catch {}
  });

  socket.on("couples:nudge", (payload={}) => {
    const fromName = payload?.fromName || "Your partner";
    showToast(`${fromName} nudged you 💜`, { durationMs: 3200 });
  });

  socket.on("room:event", (payload={})=>{
    if(payload && payload.room && String(payload.room) !== String(currentRoom)) return;
    const ev = payload.active || null;
    setRoomEvent(ev);
  });

  socket.on("mention:ping", (payload={})=>{
    if(!getFeatureFlag("smartMentions", true)) return;
    const kind = String(payload.kind||"mention");
    const from = payload.from?.username || "Someone";
    showToast(`${from} pinged ${kind === "here" ? "@here" : "@"+kind}`, { durationMs: 2400 });
    // Optional: mention sound hook if present
    try{
      if(typeof playSound === "function") playSound("mention");
    }catch(_){}
  });

  socket.on("survival:update", (payload = {}) => {
    if (!isSurvivalRoom(currentRoom)) return;
    if (!payload || typeof payload !== "object") return;
    applySurvivalPayload(payload, { replaceEvents: true });
  });

  socket.on("survival:events", (payload = {}) => {
    if (!isSurvivalRoom(currentRoom)) return;
    if (!payload || payload.seasonId !== survivalState.season?.id) return;
    if (!Array.isArray(payload.events)) return;
    survivalState.events = [...survivalState.events, ...payload.events];
    renderSurvivalLog(survivalLogList, survivalState.events);
    if (survivalLogModal && survivalLogModal.style.display !== "none") {
      renderSurvivalLog(survivalLogModalList, survivalState.events);
    }
  });

  socket.on("survival:lobby", (payload = {}) => {
    if (!isSurvivalRoom(currentRoom)) return;
    const ids = Array.isArray(payload.user_ids) ? payload.user_ids : [];
    survivalState.lobbyUserIds = ids.map((x) => Number(x)).filter((x) => x > 0);
    renderSurvivalArena();
  });

socket.on("disconnect", (reason) => {
  if(isBenignDisconnect(reason)) return;
  addSystem(`⚠️ Disconnected: ${reason}`);
});
  

// Force a clean reconnect when returning from background (iOS Safari will often suspend sockets)
document.addEventListener("visibilitychange", () => {
  if(!socket) return;

  if(document.visibilityState === "hidden"){
    // Suppress scary notices while the app is backgrounded
    suppressRealtimeNoticesFor(60_000);
    try{ socket.disconnect(); }catch(_){}
    return;
  }

  // Visible again
  suppressRealtimeNoticesFor(5000);
  if(!socket.connected){
    try{ socket.connect(); }catch(_){}
  }

  // Re-join current room after reconnect (extra defensive)
  setTimeout(() => {
    try{ joinRoom(currentRoom); }catch(_){}
  }, 400);
});

window.addEventListener("online", () => {
  if(!socket) return;
  suppressRealtimeNoticesFor(5000);
  if(!socket.connected){
    try{ socket.connect(); }catch(_){}
  }
});
socket.on("roomStructure:update", (payload)=>setRoomStructure(payload, { updateCollapse: false }));
socket.on("rooms update", (rooms)=>renderRoomsList(rooms));
  socket.on("changelog updated", ()=>{
    changelogDirty = true;
    if(rightPanelMode === "menu" && activeMenuTab === "changelog") loadChangelog(true);
    loadLatestUpdateSnippet();
  });
  socket.on("changelog reactions updated", ()=>{
    changelogDirty = true;
    if(rightPanelMode === "menu" && activeMenuTab === "changelog") loadChangelog(true);
  });
  socket.on("faq:update", ()=>{
    faqDirty = true;
    if(rightPanelMode === "menu" && activeMenuTab === "faq") loadFaq(true);
  });
  socket.on("leaderboard:update", ()=>{
    if(!leaderboardState.isOpen) return;
    const now = Date.now();
    if(now - leaderboardState.lastFetchAt < 2000) return;
    if(now < leaderboardState.wsCooldownUntil) return;
    leaderboardState.wsCooldownUntil = now + 2000;
    fetchLeaderboards({ force:true, reason:"ws" });
  });
  await loadRooms();
  await loadLatestUpdateSnippet();
  // Insert the Site/User pill switcher under the Latest update card.
  ensureRoomModeSwitch();
  await loadDmThreads();

  // show Create Room button only for Co-owner+
  if(addRoomBtn){
    addRoomBtn.addEventListener("click", createRoomFlow);
  }
  if(manageRoomsBtn){
    manageRoomsBtn.addEventListener("click", openRoomManageModal);
  }
  roomManageCloseBtn?.addEventListener("click", closeRoomManageModal);
  roomManageModal?.addEventListener("click", (e)=>{ if(e.target === roomManageModal) closeRoomManageModal(); });
  roomCreateCloseBtn?.addEventListener("click", closeRoomCreateModal);
  roomCreateCancelBtn?.addEventListener("click", closeRoomCreateModal);
  roomCreateModal?.addEventListener("click", (e)=>{ if(e.target === roomCreateModal) closeRoomCreateModal(); });
  roomCreateSubmitBtn?.addEventListener("click", submitCreateRoom);
  roomCreateMasterSelect?.addEventListener("change", populateRoomCreateSelects);
  roomCategoryMasterSelect?.addEventListener("change", renderRoomCategoryList);
  roomManageMasterSelect?.addEventListener("change", () => {
    populateManageCategorySelects();
    renderRoomManageRoomsList();
  });
  roomManageCategorySelect?.addEventListener("change", renderRoomManageRoomsList);
  document.querySelectorAll("[data-room-manage-tab]").forEach((btn)=>{
    btn.addEventListener("click", ()=> setRoomManageTab(btn.dataset.roomManageTab));
  });
  roomMasterCreateBtn?.addEventListener("click", async () => {
    const name = String(roomMasterCreateInput?.value || "").trim();
    if(roomMasterMsg) roomMasterMsg.textContent = "";
    if(!name){
      if(roomMasterMsg) roomMasterMsg.textContent = "Enter a master name.";
      return;
    }
    await api("/api/room-masters", {
      method:"POST",
      headers: { "Content-Type":"application/json" },
      body: JSON.stringify({ name })
    });
    if(roomMasterCreateInput) roomMasterCreateInput.value = "";
    await loadRooms();
  });
  roomCategoryCreateBtn?.addEventListener("click", async () => {
    const masterId = roomCategoryMasterSelect?.value || "";
    const name = String(roomCategoryCreateInput?.value || "").trim();
    if(roomCategoryMsg) roomCategoryMsg.textContent = "";
    if(!masterId || !name){
      if(roomCategoryMsg) roomCategoryMsg.textContent = "Select a master and name.";
      return;
    }
    await api("/api/room-categories", {
      method:"POST",
      headers: { "Content-Type":"application/json" },
      body: JSON.stringify({ master_id: Number(masterId) || masterId, name })
    });
    if(roomCategoryCreateInput) roomCategoryCreateInput.value = "";
    await loadRooms();
  });
  updateRoomControlsVisibility();

  socket.on("system", (text) => {
    addSystem(text, { className: isDiceResultSystemMessage(text) ? "diceResult" : "" });
  });

  // Dice Room UI effects
  const diceOverlay = document.createElement("div");
  diceOverlay.id = "diceOverlay";
  diceOverlay.style.display = "none";

  // Inner bits so we can do variant-specific layouts/animations
  const diceOverlayInner = document.createElement("div");
  diceOverlayInner.className = "diceOverlayInner";
  const diceDisplayEl = document.createElement("div");
  diceDisplayEl.className = "diceDisplay";
  const diceSubEl = document.createElement("div");
  diceSubEl.className = "diceSub";
  const diceDeltaEl = document.createElement("div");
  diceDeltaEl.className = "diceDelta";
  diceOverlayInner.appendChild(diceDisplayEl);
  diceOverlayInner.appendChild(diceSubEl);
  diceOverlayInner.appendChild(diceDeltaEl);
  diceOverlay.appendChild(diceOverlayInner);
  const confettiLayer = document.createElement("div");
  confettiLayer.id = "confettiLayer";
  confettiLayer.style.display = "none";

  // attach overlays to chat area
  const chatMain = document.querySelector("main.chat") || document.getElementById("chatMain") || document.body;
  chatMain.style.position = chatMain.style.position || "relative";
  chatMain.appendChild(diceOverlay);
  chatMain.appendChild(confettiLayer);

  function showDiceAnimation({ result, variant, won, deltaGold, breakdown, outcome } = {}){
    const faces = ["⚀","⚁","⚂","⚃","⚄","⚅"];
    const v = String(variant || "d6").toLowerCase();
    const r = Number(result ?? 0);
    const dg = Number(deltaGold ?? 0);
    const sign = dg >= 0 ? "+" : "";
    const o = String(outcome || (dg > 0 ? "win" : "loss"));

    diceOverlay.style.display = "flex";
    diceOverlay.classList.remove(
      "variant-d6",
      "variant-d20",
      "variant-2d6",
      "variant-d100",
      "outcome-loss",
      "outcome-win",
      "outcome-bigwin",
      "outcome-jackpot",
      "outcome-nice"
    );
    diceOverlay.classList.add(`variant-${v}`);
    diceOverlay.classList.add(`outcome-${o}`);

    // Subtext + delta always (helps explain the new reward system)
    diceDeltaEl.textContent = `${sign}${dg} Gold`;
    diceSubEl.textContent = (v === "d6") ? "d6" : (v === "d20") ? "d20" : (v === "2d6") ? "2d6" : "1–100";

    const b = Array.isArray(breakdown) ? breakdown.map((n)=>Number(n||0)) : [];
    const twoDiceDisplay = b.length === 2 ? `${faces[b[0]-1]||"🎲"} ${faces[b[1]-1]||"🎲"}` : "🎲 🎲";
    const finalDisplay =
      v === "d6" ? (faces[(r || 1) - 1] || "🎲") :
      v === "2d6" ? twoDiceDisplay :
      v === "d20" ? String(r || "🎲") :
      String(r || "🎲");

    if (PREFERS_REDUCED_MOTION) {
      diceDisplayEl.textContent = finalDisplay;
      setTimeout(()=>{ diceOverlay.style.display="none"; }, 260);
      return;
    }

    let t = 0;
    const iv = setInterval(()=>{
      if (v === "d6") {
        diceDisplayEl.textContent = faces[Math.floor(Math.random()*6)];
      } else if (v === "2d6") {
        diceDisplayEl.textContent = `${faces[Math.floor(Math.random()*6)]} ${faces[Math.floor(Math.random()*6)]}`;
      } else if (v === "d20") {
        diceDisplayEl.textContent = String(1 + Math.floor(Math.random()*20));
      } else {
        diceDisplayEl.textContent = String(1 + Math.floor(Math.random()*100));
      }
      t += 1;
      if (t >= 11){
        clearInterval(iv);
        diceDisplayEl.textContent = finalDisplay;
        setTimeout(()=>{ diceOverlay.style.display="none"; }, 420);
        if (won || dg >= 500) popConfetti();
      }
    }, 80);
  }

  function popConfetti(){
    confettiLayer.innerHTML = "";
    confettiLayer.style.display = "block";
    for (let i=0;i<22;i++){
      const s=document.createElement("span");
      s.className="confetti";
      s.style.left = (10 + Math.random()*80) + "%";
      s.style.animationDelay = (Math.random()*0.15) + "s";
      s.style.transform = `rotate(${Math.random()*360}deg)`;
      confettiLayer.appendChild(s);
    }
    setTimeout(()=>{ confettiLayer.style.display="none"; confettiLayer.innerHTML=""; }, 900);
  }

  socket.on("dice:result", (payload = {}) => {
    const result = payload.result ?? payload.value;
    const variant = payload.variant || "d6";
    const won = !!payload.won;
    showDiceAnimation({
      result,
      variant,
      won,
      deltaGold: payload.deltaGold,
      breakdown: payload.breakdown,
      outcome: payload.outcome,
    });
    if (payload.userId === me?.id) {
      diceCooldownUntil = Date.now() + DICE_ROLL_COOLDOWN_MS;
      updateDiceSessionStats(payload);
      if (typeof refreshMe === "function") refreshMe();
    }
    if (payload.username) noteDiceRoll(payload.username, result);
  });
  socket.on("dice:error", (msg)=> {
    const m = String(msg||"");
    const match = m.match(/in (\d+(?:\.\d+)?)s/i);
    if (match) {
      const waitMs = Math.max(0, Number(match[1]) * 1000);
      diceCooldownUntil = Date.now() + waitMs;
    }
    addSystem(msg);
  });
  socket.on("luck:update", (payload = {}) => {
    if (payload && typeof payload.luck === "number") {
      luckState.luck = payload.luck;
      luckState.rollStreak = Number(payload.rollStreak || 0);
      luckState.lastUpdateAt = Number(payload.ts || Date.now());
      luckState.hasValue = true;
      renderLuckMeter();
    }
  });
  updateDiceVariantLabel();

  socket.on("command response", handleCommandResponse);
  socket.on("user list", (users)=>{
    if (membersViewMode === "friends") {
      lastUsers = reorderCouplesInMembers(users || []);
    } else {
      renderMembers(users);
    }
  });
  socket.on("user fx updated", (payload = {}) => {
    const name = safeString(payload.username, "").trim();
    if (!name) return;
    updateUserFxMap(name, payload.chatFx || payload.fx || {});
    updateUserFxInDom(name, payload.chatFx || payload.fx || {});
    renderDmThreads();
  });
  socket.on("typing update", (names)=>{
    typingUsers = new Set((names || []).map(normKey));
    const others=(names||[]).filter(n=>normKey(n)!==normKey(me.username));
    let text="";
    if(others.length===1) {
      const only = others[0];
      if (shouldUseIrisLolaCoupleUi() && isPartnerName(only)) text = "Typing with you…";
      else text = typingPhraseFor(only);
    }
    else if(others.length>1){
      const parts = others.slice(0,2).map(typingPhraseFor);
      text = parts.join(" • ");
      if(others.length>2) text += ` (+${others.length-2})`;
    }
    setTypingIndicator(text);
    stickToBottomIfWanted();
    (names || []).forEach((name) => setPresenceClass(name, "typing"));
    updatePresenceAuras();
  });
  socket.on("level up", ({ level }) => {
    if(level) progression.level = level;
    showLevelToast(level || "");
    loadProgression();
    renderLevelProgress(progression, true);
  });
  socket.on("progression:update", (payload = {}) => {
    applyProgressionPayload(payload);
    renderLevelProgress(progression, true);
  });
  socket.on("profile:update", async (payload = {}) => {
    if (payload?.username && me) {
      me.username = payload.username;
      meName.textContent = payload.username;
    }
    await loadMyProfile();
    renderLevelProgress(progression, true);
  });

  // Friends notifications
  socket.on("friend:request", (payload = {}) => {
    const rid = Number(payload?.requestId || payload?.id || 0);
    const from = payload?.from || {};
    const uname = String(from.username || payload?.username || '').trim();
    const av = from.avatar || payload?.avatar || null;
    if (rid && uname) {
      pushFriendRequestNotification({ requestId: rid, fromUsername: uname, fromAvatar: av, ts: Date.now() });
      friendsDirty = true;
    }
  });
  socket.on("friend:accepted", (payload = {}) => {
    const uname = String(payload?.username || '').trim();
    if (uname) pushNotification({ type: 'system', text: `🤝 You and ${uname} are now friends`, ts: Date.now(), target: `profile:${uname}` });
    friendsDirty = true;
  });
  socket.on("friend:declined", (payload = {}) => {
    const uname = String(payload?.username || '').trim();
    if (uname) pushNotification({ type: 'system', text: `${uname} declined your friend request`, ts: Date.now(), target: `profile:${uname}` });
    friendsDirty = true;
  });
  socket.on("friend:removed", (payload = {}) => {
    const uname = String(payload?.username || '').trim();
    if (uname) pushNotification({ type: 'system', text: `${uname} removed you as a friend`, ts: Date.now(), target: `profile:${uname}` });
    friendsDirty = true;
  });

  socket.on("history", (history)=>{
    let messages = history;
    if (history && !Array.isArray(history) && typeof history === "object") {
      hydrateUserFxMap(history.authorsFx || history.authors_fx || history.userFxMap);
      messages = history.messages || history.history || history.items || [];
    }
    clearMsgs();
    (messages||[]).forEach(m=>safeAddMessage(m));
    applySearch();
  });
  socket.on("chat message", (m)=>{
    m.__fresh = true;
    safeAddMessage(m);
    applySearch();

    // Quiet sound cues (optional)
    try{
      const from = String(m?.username || "");
      const self = String(me?.username || "");
      if (from && self && from !== self) {
        const txt = String(m?.text || "");
        const mentioned = hasMention(txt, self);
        let played = false;
        if (Sound.shouldReceive()) { Sound.cues.receive(); played = true; }
        if (mentioned && Sound.shouldMention()) Sound.cues.mention();
        else if (!played && Sound.shouldRoom()) Sound.cues.room();
      }
    }catch{}
  });
  socket.on("reaction update", ({ messageId, reactions }) => {
    renderReactions(messageId, reactions);
    if (Sound.shouldReaction()) Sound.cues.reaction();
  });

  const onMainMessageDeleted = ({ messageId }) => {
    if (!messageId) return;
    handleMainMessageDeleted(messageId);
  };
  socket.on("message deleted", onMainMessageDeleted);
  socket.on("messageDeleted", onMainMessageDeleted);

    socket.on("dm message edited", (payload = {}) => {
    const tid = String(payload.threadId || "");
    const mid = String(payload.messageId || "");
    const arr = dmMessages.get(tid) || [];
    const i = arr.findIndex(mm => String(mm.messageId || mm.id) === mid);
    if (i !== -1) {
      arr[i].text = safeString(payload.text, "");
      arr[i].editedAt = payload.editedAt || Date.now();
    }
    if (String(activeDmId) === tid) renderDmMessages(tid);
  });

  socket.on("message edited", (payload = {}) => {
    const mid = String(payload.messageId || "");
    // update index cache if present
    const idx = msgIndex.findIndex((x) => String(x.id) === mid);
    if (idx !== -1) {
      msgIndex[idx].text = safeString(payload.text, "");
      msgIndex[idx].editedAt = payload.editedAt || Date.now();
    }

    const item = document.querySelector(`.msgItem[data-mid="${mid}"]`);
    if (item) {
      const bubble = item.querySelector(".bubble");
      const textEl = bubble?.querySelector(".text");
      if (textEl) textEl.innerHTML = applyMentions(safeString(payload.text, ""), { linkifyText: true }).replace(/\n/g, "<br/>");
      const timeEl = bubble?.querySelector(".time");
      if (timeEl && !timeEl.querySelector(".editedTag")) {
        const ed = document.createElement("span");
        ed.className = "editedTag";
        ed.textContent = " (edited)";
        timeEl.appendChild(ed);
      }
    }
  });

socket.on("dm history", (payload = {}) => {
    const { threadId, messages = [], participants = [], title = "" } = payload || {};
    hydrateUserFxMap(payload?.authorsFx || payload?.authors_fx);
    if (Array.isArray(messages)) {
      messages.forEach((msg) => {
        if (msg?.chatFx) updateUserFxMap(resolveMessageAuthor(msg), msg.chatFx);
      });
    }
    const lastText = messages.length
      ? messages[messages.length - 1].text || ""
      : (dmThreads.find((t) => String(t.id) === String(threadId))?.last_text || "");

    const lastTs = messages.length
      ? messages[messages.length - 1].ts
      : (dmThreads.find((t) => String(t.id) === String(threadId))?.last_ts || Date.now());

    upsertThreadMeta(threadId, {
      participants,
      title,
      last_text: lastText,
      last_ts: lastTs,
      is_group: !!payload?.isGroup,
    });

    dmMessages.set(threadId, messages);
    renderDmThreads();

    if (String(activeDmId) === String(threadId)) {
      setDmMeta(dmThreads.find((t) => String(t.id) === String(threadId)));
      renderDmMessages(threadId);
      // Consider the thread read once we've rendered its history.
      const latest = (Array.isArray(messages) && messages.length)
        ? messages[messages.length - 1].ts
        : Date.now();
      markDmRead(threadId, latest);
      // Live read receipt (best-effort)
      try {
        const lastMsg = (Array.isArray(messages) && messages.length) ? messages[messages.length - 1] : null;
        const mid = lastMsg ? (lastMsg.messageId || lastMsg.id) : null;
        if (mid) socket?.emit("dm mark read", { threadId, messageId: mid, ts: lastMsg.ts || Date.now() });
      } catch {}

      // Optimistically clear unread count for this thread so badges update immediately.
      const meta = dmThreads.find(t => String(t.id) === String(threadId));
      if (meta) meta.unreadCount = 0;
      dmUnreadThreads.delete(String(threadId));
      refreshDmBadgesFromThreads();
      renderDmThreads();
    }
  });

  socket.on("dm history cleared", (payload = {}) => {
    const threadId = payload.threadId;
    if (!threadId) return;
    dmMessages.set(threadId, []);
    const meta = dmThreads.find((t) => String(t.id) === String(threadId));
    if (meta) {
      meta.last_text = "";
      meta.last_ts = null;
    }
    if (String(activeDmId) === String(threadId)) {
      renderDmMessages(threadId);
      setDmNotice("History was cleared.");
    }
    renderDmThreads();
  });

  socket.on("dm message", (m) => {
  try {
    m.__fresh = true;
    if (m?.chatFx) updateUserFxMap(resolveMessageAuthor(m), m.chatFx);
    const arr = dmMessages.get(m.threadId) || [];
    arr.push(m);
    dmMessages.set(m.threadId, arr);

    upsertThreadMeta(m.threadId, { last_text: m.text || "", last_ts: m.ts });

    // Quiet sound cues (optional)
    try{
      const self = String(me?.username || "");
      const from = String(m?.user || "");
      if (self && from && from !== self) {
        const txt = String(m?.text || "");
        const mentioned = hasMention(txt, self);
        let played = false;
        if (Sound.shouldReceive()) { Sound.cues.receive(); played = true; }
        if (mentioned && Sound.shouldMention()) Sound.cues.mention();
        else if (!played && Sound.shouldDm()) Sound.cues.dm();
      }
    }catch{}


    if (!dmThreads.find((t) => String(t.id) === String(m.threadId))) loadDmThreads();

    if (String(activeDmId) !== String(m.threadId)) {
      markDmNotification(m.threadId, isGroupThread(m.threadId));
    }

    if (dmPanel?.classList.contains("open") && String(activeDmId) === String(m.threadId)) {
      renderDmMessages(m.threadId);
      markDmRead(m.threadId, m.ts || Date.now());
    // Live read receipt (best-effort)
    if (dmPanel?.classList.contains("open") && String(activeDmId) === String(m.threadId) && (m.messageId || m.id)) {
      socket?.emit("dm mark read", { threadId: m.threadId, messageId: (m.messageId || m.id), ts: m.ts || Date.now() });
    }
      // Optimistically clear unread count for this thread so badges update immediately.
      const meta = dmThreads.find(t => String(t.id) === String(m.threadId));
      if (meta) meta.unreadCount = 0;
      dmUnreadThreads.delete(String(m.threadId));
      refreshDmBadgesFromThreads();
      renderDmThreads();
    }
  } catch (err) {
    console.error("dm message handler failed", err, m);
  }
});

  socket.on("dm read", (payload = {}) => {
    try {
      const tid = String(payload.threadId || "");
      if (!tid) return;
      dmReadCache[tid] = payload;

      // If the active thread matches, re-render to update "Seen" indicator
      if (String(activeDmId) === tid) {
        renderDmMessages(Number(tid));
      }
    } catch {}
  });


  socket.on("dm reaction update", (payload = {}) => {
    // Keep cache even if the thread isn't open yet.
    const midKey = String(payload.messageId || "");
    if (!midKey) return;
    dmReactionsCache[midKey] = payload.reactions || {};
    // Only render if the message is currently in the DOM.
    renderDmReactions(midKey, dmReactionsCache[midKey]);
    if (Sound.shouldReaction()) Sound.cues.reaction();
  });

  socket.on("dm message deleted", (payload = {}) => {
    handleDmMessageDeleted(payload.threadId, payload.messageId);
    if (String(activeDmId) === String(payload.threadId)) {
      closeReactionMenu();
    }
  });

  socket.on("dm thread invited", () => {
    loadDmThreads();
  });

  joinRoom("main"); // main will exist from seeded rooms
  meStatusText.textContent = normalizeStatusLabel(statusSelect.value, "Online");
  resetIdle();

  // hash profile links
  if(location.hash.startsWith("#profile:")){
    const u = decodeURIComponent(location.hash.slice("#profile:".length));
    if(u) openMemberProfile(u);
  }
  window.addEventListener("hashchange", ()=>{
    if(location.hash.startsWith("#profile:")){
      const u = decodeURIComponent(location.hash.slice("#profile:".length));
      if(u) openMemberProfile(u);
    }
  });
}

// boot: auth gate

async function bootApp(){
  setView("loading");
  bindRestrictedUI();
  bindStaffAppealsUI();
  bindReferralsUI();
  bindRoleDebugUI();
  bindOwnerPanels();
  initPasswordUpgradeUI();

  const sessionUser = await validateSession({ silent: true });
  if(sessionUser){
    me = sessionUser;
    setAuthUser(sessionUser);

    // Gate entry behind kick/ban restrictions (so login doesn't show chat UI)
    try{
      const rRes = await fetch("/api/restriction", { credentials:"include" });
      const r = await rRes.json().catch(()=>({ type:"none" }));
      if(r?.type && r.type !== "none"){
        // Connect socket only for appeals/status updates
        await ensureRestrictedSocket();
        showRestrictedView(r);
        await refreshMyAppeal();
        return;
      }
    }catch{}

    await initChatApp();
    return;
  }
  const pendingUpgrade = await checkPasswordUpgradeStatus();
  if(pendingUpgrade) return;
  initLoginUI();
}


document.addEventListener("DOMContentLoaded", bootApp);

// profile button also closes drawers
profileBtn?.addEventListener("click", () => { closeDrawers(); });

// close drawers when opening modal
modal?.addEventListener("show", closeDrawers);



function focusDmComposer(){
  if(!dmText) return;
  try{ dmText.focus({ preventScroll:true }); }catch{ dmText.focus(); }
  requestAnimationFrame(() => {
    const vv = window.visualViewport;
    const viewportBottom = (vv ? (vv.height + (vv.offsetTop || 0)) : window.innerHeight) - 8;
    const rect = dmText.getBoundingClientRect();
    if(rect.bottom > viewportBottom){
      window.scrollBy({ top: (rect.bottom - viewportBottom) + 16, behavior: "smooth" });
    }
  });
}

function focusMainComposer(){
  if(!msgInput) return;
  try{ msgInput.focus({ preventScroll:true }); }catch{ msgInput.focus(); }
  requestAnimationFrame(() => {
    const vv = window.visualViewport;
    const viewportBottom = (vv ? (vv.height + (vv.offsetTop || 0)) : window.innerHeight) - 8;
    const rect = msgInput.getBoundingClientRect();
    if(rect.bottom > viewportBottom){
      window.scrollBy({ top: (rect.bottom - viewportBottom) + 16, behavior: "smooth" });
    }
  });
}

const SOFT_INPUT_SELECTOR = ".menuContent input, .menuContent textarea, .modalContent input, .modalContent textarea, .faqAnswerEdit, #passwordUpgradeView input";

function updateKeyboardInset(target){
  const vv = window.visualViewport;
  let kb = 0;
  if(vv){
    kb = Math.max(0, window.innerHeight - (vv.height + (vv.offsetTop || 0)));
  }
  if(Number.isFinite(kb)){ document.documentElement?.style?.setProperty("--kb", `${Math.round(kb)}px`); }
  if(target && target.scrollIntoView){
    setTimeout(() => {
      try{ target.scrollIntoView({ block:"center", behavior:"smooth" }); }catch{}
    }, 120);
  }
}

document.addEventListener("focusin", (event)=>{
  const el = event.target;
  if(!(el instanceof HTMLElement)) return;
  if(!el.matches(SOFT_INPUT_SELECTOR)) return;
  document.body.classList.add("keyboard-open");
  updateKeyboardInset(el);
});

document.addEventListener("focusout", ()=>{
  setTimeout(()=>{
    const active = document.activeElement;
    if(active && active instanceof HTMLElement && active.matches(SOFT_INPUT_SELECTOR)) return;
    document.body.classList.remove("keyboard-open");
    document.documentElement?.style?.setProperty("--kb", "0px");
  }, 150);
});

window.visualViewport?.addEventListener("resize", ()=>{
  const active = document.activeElement;
  if(active && active instanceof HTMLElement && active.matches(SOFT_INPUT_SELECTOR)) updateKeyboardInset(active);
});

// focus behavior on mobile keyboard (avoid aggressive scroll jumps on iOS)
msgInput?.addEventListener("focus", () => {
  // Let the keyboard animate first, then gently keep the composer visible.
  setTimeout(() => {
    try{
      const vv = window.visualViewport;
      if(vv){
        // If the focused input is below the visible viewport, nudge it into view.
        const rect = msgInput.getBoundingClientRect();
        const visibleBottom = vv.height - 12;
        if(rect.bottom > visibleBottom){
          window.scrollBy({ top: rect.bottom - visibleBottom, left: 0, behavior: "smooth" });
        }
      }else{
        msgInput.scrollIntoView({ block: "nearest", behavior: "smooth" });
      }
    }catch{}
  }, 120);
});

/* === Unified profile opener === */
function openUserProfile(username){
  if(!username) return;
  if(typeof showProfileModal === "function") showProfileModal();
  if(typeof loadProfile === "function") loadProfile(username);
}

/* === Attach profile open on member click === */
document.addEventListener("click", (e)=>{
  const el = e.target.closest(".member, .memberName, .memberItem");
  if(!el) return;
  const username = el.dataset?.username || el.textContent?.trim();
  if(username) openUserProfile(username);
});

function canUseTheme(theme) {
  const role = window.currentUser?.role || "public";
  const hierarchy = { public:0, vip:1, staff:2, admin:3 };
  return hierarchy[role] >= hierarchy[theme.tier];
}


let __themePreviewTimer = null;

function getActiveThemeId() {
  // Prefer body attribute, fall back to localStorage
  const cur = document.body?.dataset?.theme;
  if (cur && cur.trim()) return cur.trim();
  try { return localStorage.getItem("theme") || ""; } catch (_) { return ""; }
}

function applyThemeId(themeId, persist = true) {
  // Use existing setTheme if available; otherwise set body dataset.
  if (typeof setTheme === "function") {
    // setTheme is assumed to persist; use persist=false to avoid saving if supported
    try { setTheme(themeId, persist); return; } catch (_) {}
  }
  if (document.body) document.body.dataset.theme = themeId;
  if (persist) {
    try { localStorage.setItem("theme", themeId); } catch (_) {}
  }
}

function previewTheme(themeId, seconds = 10) {
  const prev = getActiveThemeId();
  if (__themePreviewTimer) {
    clearTimeout(__themePreviewTimer);
    __themePreviewTimer = null;
  }
  applyThemeId(themeId, false);
  __themePreviewTimer = setTimeout(() => {
    applyThemeId(prev, false);
    __themePreviewTimer = null;
  }, seconds * 1000);
}



function isThemeVisible(themeName) {
  if (themeName === "Iris & Lola Neon") {
    return isIrisLolaAllowedUser(currentUser || me);
  }
  return true;
}

try{ syncDesktopMembersWidth(); }catch{}


// ---- Couples UI (opt-in)
async function refreshCouplesUI(){
  if (!myProfileEdit) return;
  if (!couplesPendingBox || !couplesActiveBox) return;

  try {
    const res = await fetch("/api/couples/me");
    if (!res.ok) throw new Error(await res.text().catch(()=> "Could not load couples"));
    couplesState = await res.json();
  } catch (e) {
    setMsgline(couplesMsg, e?.message || "Could not load couples");
    return;
  }

  // Pending list
  const incoming = couplesState?.incoming || [];
  const outgoing = couplesState?.outgoing || [];
  if (couplesPendingList) couplesPendingList.innerHTML = "";

  const anyPending = incoming.length || outgoing.length;
  if (couplesPendingBox) couplesPendingBox.style.display = anyPending ? "" : "none";

  const makePendingRow = (label, item, isIncoming) => {
    const row = document.createElement("div");
    row.className = "couplesPendingRow";
    const left = document.createElement("div");
    left.className = "couplesPendingLeft";
    left.textContent = `${label}: ${item.other}`;
    row.appendChild(left);

    const right = document.createElement("div");
    right.className = "couplesPendingRight";

    if (isIncoming) {
      const ok = document.createElement("button");
      ok.className = "btn btnPrimary";
      ok.type = "button";
      ok.textContent = "Accept";
      ok.onclick = async () => {
        setMsgline(couplesMsg, "");
        try {
          const r = await fetch("/api/couples/respond", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ linkId: item.linkId, accept: true })
          });
          if (!r.ok) throw new Error(await r.text().catch(()=> "Could not accept"));
          couplesState = await r.json();
          await refreshCouplesUI();
          emitLocalMembersRefresh();
        } catch (e) { setMsgline(couplesMsg, e?.message || "Could not accept"); }
      };
      right.appendChild(ok);
    }

    const no = document.createElement("button");
    no.className = "btn secondary";
    no.type = "button";
    no.textContent = isIncoming ? "Decline" : "Cancel";
    no.onclick = async () => {
      setMsgline(couplesMsg, "");
      try {
        const r = await fetch("/api/couples/respond", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ linkId: item.linkId, accept: false })
        });
        if (!r.ok) throw new Error(await r.text().catch(()=> "Could not update"));
        couplesState = await r.json();
        await refreshCouplesUI();
      } catch (e) { setMsgline(couplesMsg, e?.message || "Could not update"); }
    };
    right.appendChild(no);

    row.appendChild(right);
    return row;
  };

  if (couplesPendingList) {
    for (const it of incoming) couplesPendingList.appendChild(makePendingRow("Incoming", it, true));
    for (const it of outgoing) couplesPendingList.appendChild(makePendingRow("Outgoing", it, false));
  }

  const active = couplesState?.active || null;
  if (couplesActiveBox) couplesActiveBox.style.display = active ? "" : "none";

  if (active) {
    if (couplesActiveTitle) {
      const sinceTxt = active.since ? ` · ${fmtDaysSince(active.since)}` : "";
      couplesActiveTitle.textContent = `${active.statusEmoji||"💜"} ${active.statusLabel||"Linked"}: ${active.partner}${sinceTxt}`;
    }
    const p = active.prefs || {};
    if (couplesEnabledToggle) couplesEnabledToggle.checked = !!p.enabled;
    if (couplesShowProfileToggle) couplesShowProfileToggle.checked = !!p.showProfile;
    if (couplesBadgeToggle) couplesBadgeToggle.checked = !!p.badge;
    if (couplesAuraToggle) couplesAuraToggle.checked = !!p.aura;
    if (couplesShowMembersToggle) couplesShowMembersToggle.checked = !!p.showMembers;
    if (couplesGroupToggle) couplesGroupToggle.checked = !!p.groupMembers;
    if (couplesAllowPingToggle) couplesAllowPingToggle.checked = !!p.allowPing;
  }

  // disable toggles if no active link
  const toggles = [couplesEnabledToggle,couplesShowProfileToggle,couplesBadgeToggle,couplesAuraToggle,couplesShowMembersToggle,couplesGroupToggle,couplesAllowPingToggle];
  toggles.forEach(t => { if (t) t.disabled = !active; });

  if (couplesUnlinkBtn) couplesUnlinkBtn.disabled = !active;

  const canEditSettings = isCoupleMember(me?.id ?? me?.user_id ?? me?.userId, couplesState?.couple);
  const v2Enabled = !!(couplesState?.v2Enabled && active && canEditSettings);
  if (couplesV2Box) couplesV2Box.style.display = v2Enabled ? "" : "none";
  if (v2Enabled && couplesState?.couple) {
    const c = couplesState.couple;
    if (couplesPrivacySelect) couplesPrivacySelect.value = c.privacy || "private";
    if (couplesNameInput) couplesNameInput.value = c.couple_name || "";
    if (couplesBioInput) couplesBioInput.value = c.couple_bio || "";
    if (couplesShowBadgeToggle) couplesShowBadgeToggle.checked = c.show_badge !== false;
    if (couplesBonusesToggle) couplesBonusesToggle.checked = !!c.bonuses_enabled;
    if (couplesSettingsSaveBtn) couplesSettingsSaveBtn.disabled = false;
    if (couplesNudgeBtn) couplesNudgeBtn.disabled = false;
    if (couplesV2Status) {
      const sinceTxt = active?.since ? `Together ${fmtDaysSince(active.since)}` : "Couple card settings";
      couplesV2Status.textContent = sinceTxt;
    }
  } else {
    if (couplesSettingsSaveBtn) couplesSettingsSaveBtn.disabled = true;
    if (couplesNudgeBtn) couplesNudgeBtn.disabled = true;
    if (couplesV2Status) couplesV2Status.textContent = "";
  }
  updateIrisLolaTogetherClass();
}

function emitLocalMembersRefresh(){
  try {
    if (typeof emitUserListNow === "function") emitUserListNow();
  } catch {}
}

// best-effort helper: re-emit member list if we can
function emitUserListNow(){
  // The server pushes user list on join/updates; we can also request by toggling a no-op room refresh if such exists.
  // If socket exists, ask it to refresh:
  try { if (socket) socket.emit("refresh user list"); } catch {}
}

function isCoupleMember(currentUserId, couple){
  const uid = Number(currentUserId) || 0;
  if (!uid || !couple) return false;
  const a = Number(couple.user_a_id ?? couple.user1_id ?? couple.userAId ?? couple.user1Id ?? 0) || 0;
  const b = Number(couple.user_b_id ?? couple.user2_id ?? couple.userBId ?? couple.user2Id ?? 0) || 0;
  return uid === a || uid === b;
}

async function setCouplePrefs(patch){
  const active = couplesState?.active;
  if (!active?.linkId) return;
  setMsgline(couplesMsg, "");
  try {
    const r = await fetch("/api/couples/prefs", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ linkId: active.linkId, prefs: patch })
    });
    if (!r.ok) throw new Error(await r.text().catch(()=> "Could not save"));
    couplesState = await r.json();
    await refreshCouplesUI();
    emitLocalMembersRefresh();
  } catch (e) {
    setMsgline(couplesMsg, e?.message || "Could not save");
  }
}

async function setCoupleSettings(patch){
  const active = couplesState?.active;
  if (!active?.linkId) return;
  if (couplesV2Status) couplesV2Status.textContent = "Saving…";
  try {
    const r = await fetch("/api/couples/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(patch || {})
    });
    if (!r.ok) throw new Error(await r.text().catch(()=> "Could not save"));
    couplesState = await r.json();
    await refreshCouplesUI();
    emitLocalMembersRefresh();
    if (couplesV2Status) couplesV2Status.textContent = "Saved.";
  } catch (e) {
    if (couplesV2Status) couplesV2Status.textContent = e?.message || "Could not save";
  }
}

async function sendCoupleNudge(){
  if (couplesV2Status) couplesV2Status.textContent = "";
  try {
    const r = await fetch("/api/couples/nudge", { method: "POST" });
    if (!r.ok) throw new Error(await r.text().catch(()=> "Could not nudge"));
    if (couplesV2Status) couplesV2Status.textContent = "Nudge sent.";
  } catch (e) {
    if (couplesV2Status) couplesV2Status.textContent = e?.message || "Could not nudge";
  }
}

if (couplesRequestBtn) {
  couplesRequestBtn.onclick = async () => {
    setMsgline(couplesMsg, "");
    const name = String(couplesPartnerInput?.value || "").trim();
    if (!name) return setMsgline(couplesMsg, "Enter a username.");
    try {
      const r = await fetch("/api/couples/request", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ targetUsername: name })
      });
      if (!r.ok) throw new Error(await r.text().catch(()=> "Could not request"));
      couplesState = await r.json();
      if (couplesPartnerInput) couplesPartnerInput.value = "";
      await refreshCouplesUI();
    } catch (e) {
      setMsgline(couplesMsg, e?.message || "Could not request");
    }
  };
}

if (couplesEnabledToggle) couplesEnabledToggle.onchange = () => setCouplePrefs({ enabled: !!couplesEnabledToggle.checked });
if (couplesShowProfileToggle) couplesShowProfileToggle.onchange = () => setCouplePrefs({ showProfile: !!couplesShowProfileToggle.checked });
if (couplesBadgeToggle) couplesBadgeToggle.onchange = () => setCouplePrefs({ badge: !!couplesBadgeToggle.checked });
if (couplesAuraToggle) couplesAuraToggle.onchange = () => setCouplePrefs({ aura: !!couplesAuraToggle.checked });
if (couplesShowMembersToggle) couplesShowMembersToggle.onchange = () => setCouplePrefs({ showMembers: !!couplesShowMembersToggle.checked });
if (couplesGroupToggle) couplesGroupToggle.onchange = () => setCouplePrefs({ groupMembers: !!couplesGroupToggle.checked });
if (couplesAllowPingToggle) couplesAllowPingToggle.onchange = () => setCouplePrefs({ allowPing: !!couplesAllowPingToggle.checked });

if (couplesSettingsSaveBtn) {
  couplesSettingsSaveBtn.onclick = () => setCoupleSettings({
    privacy: couplesPrivacySelect?.value || "private",
    couple_name: couplesNameInput?.value || "",
    couple_bio: couplesBioInput?.value || "",
    show_badge: !!couplesShowBadgeToggle?.checked,
    bonuses_enabled: !!couplesBonusesToggle?.checked
  });
}
if (couplesNudgeBtn) couplesNudgeBtn.onclick = () => sendCoupleNudge();

if (couplesUnlinkBtn) {
  couplesUnlinkBtn.onclick = async () => {
    const active = couplesState?.active;
    if (!active?.linkId) return;
    if (!confirm(`Unlink from ${active.partner}?`)) return;
    setMsgline(couplesMsg, "");
    try {
      const r = await fetch("/api/couples/unlink", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ linkId: active.linkId })
      });
      if (!r.ok) throw new Error(await r.text().catch(()=> "Could not unlink"));
      couplesState = await r.json();
      await refreshCouplesUI();
      emitLocalMembersRefresh();
    } catch (e) {
      setMsgline(couplesMsg, e?.message || "Could not unlink");
    }
  };
}

// When opening edit profile panel, refresh couples state
try {
  const oldOpenMyProfile = openMyProfile;
  // openMyProfile exists; it opens modal and fills UI. We'll just hook after it runs.
} catch {}


/* === Media Bottom Sheet Logic === */
const mediaSheet = document.getElementById("mediaSheet");
const mediaBackdrop = document.getElementById("mediaSheetBackdrop");
// Reuse existing refs if already declared earlier in the file
const mediaBtnEl = (typeof mediaBtn !== "undefined" && mediaBtn) ? mediaBtn : document.getElementById("mediaBtn");
const fileInputEl = (typeof fileInput !== "undefined" && fileInput) ? fileInput : document.getElementById("fileInput");
const audioFileInputEl = (typeof audioFileInput !== "undefined" && audioFileInput) ? audioFileInput : document.getElementById("audioFileInput");

let sheetStartY = null;

function haptic() {
  if (navigator.vibrate) navigator.vibrate(10);
}

function openMediaSheet() {
  haptic();
  mediaBackdrop.classList.remove("hidden");
  mediaSheet.classList.remove("hidden");
  requestAnimationFrame(() => mediaSheet.classList.add("show"));
}

function closeMediaSheet() {
  mediaSheet.classList.remove("show");
  setTimeout(() => {
    mediaSheet.classList.add("hidden");
    mediaBackdrop.classList.add("hidden");
  }, 280);
}

mediaBtnEl?.addEventListener("click", e => {
  if (isDiceRoom(currentRoom)) {
    e.preventDefault();
    e.stopPropagation();
    e.stopImmediatePropagation();
    rollDiceImmediate(diceVariant);
    return;
  }
  e.preventDefault();
  e.stopPropagation();
  openMediaSheet();
});

document.getElementById("mediaPickImage")?.addEventListener("click", () => {
  haptic();
  closeMediaSheet();
  fileInputEl?.click();
});

document.getElementById("mediaPickAudio")?.addEventListener("click", () => {
  haptic();
  closeMediaSheet();
  audioFileInputEl?.click();
});

document.getElementById("mediaPickVoice")?.addEventListener("click", () => {
  haptic();
  closeMediaSheet();
  if (typeof startVoiceRecording === "function") startVoiceRecording();
});

mediaBackdrop?.addEventListener("click", closeMediaSheet);
document.getElementById("mediaSheetCancel")?.addEventListener("click", closeMediaSheet);

mediaSheet?.addEventListener("touchstart", e => {
  sheetStartY = e.touches[0].clientY;
});

mediaSheet?.addEventListener("touchmove", e => {
  if (sheetStartY === null) return;
  const delta = e.touches[0].clientY - sheetStartY;
  if (delta > 80) closeMediaSheet();
});

window.visualViewport?.addEventListener("resize", () => {
  if (!mediaSheet.classList.contains("hidden")) closeMediaSheet();
});

const composerForm = document.querySelector(".chat-composer form");
composerForm?.addEventListener("submit", e => {
  e.preventDefault();
  e.stopPropagation();
});
