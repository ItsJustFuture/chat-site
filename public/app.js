// public/app.js
"use strict";

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


/* ---- Mobile viewport height fix (prevents input bars being hidden by browser UI) */
(function initViewportHeightVar(){
  let raf = 0;

  function setVhNow(){
    const vv = window.visualViewport;
    // visualViewport.height is the most accurate on iOS when the keyboard opens,
    // but it can briefly report 0 during transitions. Guard + fallback.
    let h = (vv && typeof vv.height === "number" && vv.height > 100) ? vv.height : window.innerHeight;
    // Clamp to avoid negative/near-zero layouts during keyboard transitions.
    h = Math.max(200, Math.min(h, window.screen?.height ? window.screen.height : h));
    document.documentElement.style.setProperty("--vh", (h * 0.01) + "px");

    // Helpful extra vars for iOS keyboard-safe layouts (optional use in CSS)
    if(vv){
      const offsetTop = Number(vv.offsetTop || 0);
      const inset = Math.max(0, (window.innerHeight - vv.height - offsetTop));
      document.documentElement.style.setProperty("--vv-offset-top", offsetTop + "px");
      document.documentElement.style.setProperty("--kb-inset", inset + "px");
    }else{
      document.documentElement.style.setProperty("--vv-offset-top", "0px");
      document.documentElement.style.setProperty("--kb-inset", "0px");
    }
  }

    // Toggle keyboard-open state for iOS Safari layouts (used by CSS to hide typing overlay)
    try {
      const kbInsetStr = getComputedStyle(document.documentElement).getPropertyValue("--kb-inset") || "0px";
      const kbInset = Math.max(0, Math.round(parseFloat(kbInsetStr) || 0));
      document.documentElement.style.setProperty("--kbOffset", kbInset + "px");
      if (document.body) document.body.classList.toggle("kb-open", kbInset > 80);
    } catch (e) { /* no-op */ }

  function scheduleSetVh(){
    if(raf) cancelAnimationFrame(raf);
    raf = requestAnimationFrame(()=>{ raf = 0; setVhNow(); });
  }

  window.addEventListener("resize", scheduleSetVh, { passive:true });
  window.addEventListener("orientationchange", scheduleSetVh, { passive:true });
  if(window.visualViewport){
    window.visualViewport.addEventListener("resize", scheduleSetVh, { passive:true });
    window.visualViewport.addEventListener("scroll", scheduleSetVh, { passive:true });
  }

  // When the page becomes visible again (Safari sometimes restores wrong values)
  document.addEventListener("visibilitychange", ()=>{ if(!document.hidden) scheduleSetVh(); });

  scheduleSetVh();
})()

/* ---- Quiet sound cues (optional) ---- */
const Sound = (() => {
  // Settings keys
  const KEY_ENABLED = "soundEnabled";
  const KEY_ROOM = "soundRoom";
  const KEY_DM = "soundDm";
  const KEY_MENTION = "soundMention";

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
  };

  function shouldRoom(){ return enabled() && roomOn(); }
  function shouldDm(){ return enabled() && dmOn(); }
  function shouldMention(){ return enabled() && mentionOn(); }

  return {
    keys: { KEY_ENABLED, KEY_ROOM, KEY_DM, KEY_MENTION },
    get: { enabled, roomOn, dmOn, mentionOn },
    set: { setBool },
    ensureUnlocked,
    cues,
    shouldRoom, shouldDm, shouldMention
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



let socket = null;
let me = null;
let progression = { gold: 0, xp: 0, level: 1, xpIntoLevel: 0, xpForNextLevel: 100 };
let currentRoom = "main";
function displayRoomName(room){ return room==="diceroom" ? "Dice Room" : room; }

let lastUsers = [];
const reactionsCache = Object.create(null);
const dmReactionsCache = Object.create(null);
const msgIndex = [];
let dmThreads = [];
let activeDmId = null;
const dmMessages = new Map();
const badgeDefaults = { direct: "#ed4245", group: "#5865f2" };
let badgePrefs = { ...badgeDefaults };
let directBadgePending = false;
let groupBadgePending = false;
const dmThemeDefaults = { background: "#1e1f22" };
let dmThemePrefs = { ...dmThemeDefaults };
let dmTab = "direct";
const dmUnreadThreads = new Set();

// --- DM avatar strip (direct DMs only): last-read + lightweight avatar cache
const DM_LAST_READ_KEY = "dm:lastRead:v1";
const AVATAR_CACHE_KEY = "dm:avatarCache:v1";

function loadJson(key, fallback) {
  try {
    const raw = localStorage.getItem(key);
    if (!raw) return fallback;
    const val = JSON.parse(raw);
    return val ?? fallback;
  } catch { return fallback; }
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

let dmLastRead = loadJson(DM_LAST_READ_KEY, {}); // { [threadId]: lastReadTs }
let avatarCache = loadJson(AVATAR_CACHE_KEY, {}); // { [username]: avatarUrl }

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
  const parts = Array.isArray(thread.participants) ? thread.participants : [];
  const meName = (me && me.username) ? me.username : "";
  const other = parts.find(p => p && p !== meName) || parts[0] || "";
  return other;
}

function isDirectThread(thread) {
  return !thread.is_group && (thread.participants || []).length <= 2;
}

let dmPickerMode = "create";
let dmPickerSelection = new Set();
let dmPickerThreadId = null;
let dmPickerExisting = [];
let levelToastTimer = null;
let rightPanelMode = "rooms";
let activeMenuTab = "changelog";
let changelogEntries = [];
let changelogLoaded = false;
let changelogDirty = false;
let editingChangelogId = null;
let latestChangelogEntry = null;
let leaderboardsLoaded = false;
let leaderboardsLoading = false;
const recentDiceRolls = new Map();
const diceRollTimers = new Map();
const DICE_FACES = ["⚀", "⚁", "⚂", "⚃", "⚄", "⚅"];

const THEME_LIST = [
  { name: "Minimal Dark", mode: "Dark" },
  { name: "Minimal Dark (High Contrast)", mode: "Dark" },
  { name: "Cyberpunk Neon", mode: "Dark" },
  { name: "Cyberpunk Neon (Midnight)", mode: "Dark" },
  { name: "Fantasy Tavern", mode: "Dark" },
  { name: "Fantasy Tavern (Ember)", mode: "Dark" },
  { name: "Space Explorer", mode: "Dark" },
  { name: "Space Explorer (Nebula)", mode: "Dark" },
  { name: "Minimal Light", mode: "Light" },
  { name: "Minimal Light (High Contrast)", mode: "Light" },
  { name: "Pastel Light", mode: "Light" },
  { name: "Paper / Parchment", mode: "Light" },
  { name: "Sky Light", mode: "Light" },
  { name: "Cherry Blossom (Dark)", mode: "Dark" },
  { name: "Cherry Blossom (Light)", mode: "Light" },
  { name: "420 Friendly (Light)", mode: "Light" },
  { name: "420 Friendly (Dark)", mode: "Dark" },
  { name: "Aurora Night", mode: "Dark" },
  { name: "Mint Soda", mode: "Light" },
  { name: "Lavender Fog", mode: "Light" },
  { name: "Crimson Noir", mode: "Dark" },
  { name: "Ocean Mist", mode: "Light" },
  { name: "Deep Ocean", mode: "Dark" },
  { name: "Sunlit Sand", mode: "Light" },
  { name: "Graphite", mode: "Dark" },
  { name: "Forest Night", mode: "Dark" },
  { name: "Retro Terminal", mode: "Dark" },
  { name: "Desert Dusk", mode: "Dark" },
  { name: "Arctic Light", mode: "Light" },
  { name: "Rose Quartz", mode: "Light" },
  { name: "Lemonade", mode: "Light" },

  // --- VIP gradient pack (locked behind VIP)
  { name: "Sunrise Sorbet", mode: "Light" },
  { name: "Cotton Candy Sky", mode: "Light" },
  { name: "Prismatic Pearl", mode: "Light" },
  { name: "Citrus Splash", mode: "Light" },
  { name: "Glacier Bloom", mode: "Light" },
  { name: "Aurora Pastel", mode: "Light" },

  { name: "Midnight Mirage", mode: "Dark" },
  { name: "Neon Abyss", mode: "Dark" },
  { name: "Velvet Galaxy", mode: "Dark" },
  { name: "Obsidian Aurora", mode: "Dark" },
  { name: "Iris & Lola Neon", mode: "Dark" },

];

const IRIS_LOLA_THEME = "Iris & Lola Neon";
const IRIS_LOLA_ALLOWED_USERNAMES = ["Iri", "Lola Henderson"];
let onlineUsers = [];

function isIrisLolaAllowed() {
  const u = String(me?.username || "");
  return IRIS_LOLA_ALLOWED_USERNAMES.includes(u);
}
function bothIrisAndLolaOnline() {
  const set = new Set((onlineUsers || []).map((n) => String(n)));
  return IRIS_LOLA_ALLOWED_USERNAMES.every((n) => set.has(n));
}
function updateIrisLolaTogetherClass() {
  const active = document.body?.getAttribute("data-theme") || "";
  const on = active === IRIS_LOLA_THEME && isIrisLolaAllowed() && bothIrisAndLolaOnline();
  document.body?.classList.toggle("irisLolaTogether", !!on);
}
const DEFAULT_THEME = "Minimal Dark";
let currentTheme = document.body?.getAttribute("data-theme") || DEFAULT_THEME;
let themeFilter = "all";

let modalTargetUsername = null;
let modalTargetUserId = null;
let pendingFile = null;
let uploadXhr = null;
let memberMenuUser = null;
let memberMenuUsername = "";
let replyTarget = null;
let dmReplyTarget = null;
let chatPinned = true;
let dmPinned = true;

// ---- DOM
const authWrap = document.getElementById("authWrap");
const app = document.getElementById("app");
const addRoomBtn = document.getElementById("addRoomBtn");
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
let latestUpdateExpanded = false;
const changelogList = document.getElementById("changelogList");
const changelogMsg = document.getElementById("changelogMsg");
const changelogActions = document.getElementById("changelogActions");
const changelogNewBtn = document.getElementById("changelogNewBtn");
const changelogEditor = document.getElementById("changelogEditor");
const changelogTitleInput = document.getElementById("changelogTitleInput");
const changelogBodyInput = document.getElementById("changelogBodyInput");
const changelogSaveBtn = document.getElementById("changelogSaveBtn");
const changelogCancelBtn = document.getElementById("changelogCancelBtn");
const changelogEditMsg = document.getElementById("changelogEditMsg");
const channelsCloseBtn = document.getElementById("channelsCloseBtn");
const membersCloseBtn  = document.getElementById("membersCloseBtn");
const tabEdit = document.getElementById("tabEdit");
const viewEdit = document.getElementById("viewEdit");

const editAboutBtn = document.getElementById("editAboutBtn");
const editThemesBtn = document.getElementById("editThemesBtn");
const editDmBtn = document.getElementById("editDmBtn");
const editAboutPanel = document.getElementById("editAboutPanel");
const editThemesPanel = document.getElementById("editThemesPanel");
const editDmPanel = document.getElementById("editDmPanel");

const editPreferencesPanel = document.getElementById("editPreferencesPanel");
const prefSoundEnabled = document.getElementById("prefSoundEnabled");
const prefSoundRoom = document.getElementById("prefSoundRoom");
const prefSoundDm = document.getElementById("prefSoundDm");
const prefSoundMention = document.getElementById("prefSoundMention");
const prefSoundStatus = document.getElementById("prefSoundStatus");


const authUser = document.getElementById("authUser");
const authPass = document.getElementById("authPass");
const authMsg = document.getElementById("authMsg");
const loginBtn = document.getElementById("loginBtn");
const regBtn = document.getElementById("regBtn");
const togglePassBtn = document.getElementById("togglePassBtn");


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
const roomTitle = document.getElementById("roomTitle");

const msgs = document.getElementById("msgs");
const typingEl = document.getElementById("typing");
const memberList = document.getElementById("memberList");
const memberGold = document.getElementById("memberGold");
const memberMenu = document.getElementById("memberMenu");
const memberMenuName = document.getElementById("memberMenuName");
const memberViewProfileBtn = document.getElementById("memberViewProfileBtn");
const memberDmBtn = document.getElementById("memberDmBtn");
const commandPopup = document.getElementById("commandPopup");
const commandPopupTitle = document.getElementById("commandPopupTitle");
const commandPopupBody = document.getElementById("commandPopupBody");
const commandPopupClose = document.getElementById("commandPopupClose");

const msgInput = document.getElementById("msgInput");
const sendBtn = document.getElementById("sendBtn");
const searchInput = document.getElementById("searchInput");

msgs?.addEventListener("scroll", ()=>{ chatPinned = isNearBottom(msgs, 160); });

const fileInput = document.getElementById("fileInput");
const pickFileBtn = document.getElementById("pickFileBtn");

const meAvatar = document.getElementById("meAvatar");
const meName = document.getElementById("meName");
const meRole = document.getElementById("meRole");
const meStatusText = document.getElementById("meStatusText");
const statusSelect = document.getElementById("statusSelect");
const profileBtn = document.getElementById("profileBtn");
const replyPreview = document.getElementById("replyPreview");
const replyPreviewText = document.getElementById("replyPreviewText");
const replyPreviewClose = document.getElementById("replyPreviewClose");
const mentionDropdown = document.getElementById("mentionDropdown");

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

const dmCloseBtn = document.getElementById("dmCloseBtn");
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
const dmMessagesEl = document.getElementById("dmMessages");
const dmText = document.getElementById("dmText");
const dmSendBtn = document.getElementById("dmSendBtn");

// Ensure DM quick bars start closed on load (safety net in case markup defaults are changed)
hideAllDmQuickBars();

dmMessagesEl?.addEventListener("scroll", ()=>{ dmPinned = isNearBottom(dmMessagesEl, 160); });
const dmUserBtn = document.getElementById("dmUserBtn");
const dmInfoBtn = document.getElementById("dmInfoBtn");
const dmSettingsBtn = document.getElementById("dmSettingsBtn");
const goldPill = document.getElementById("goldPill");
const likeProfileBtn = document.getElementById("likeProfileBtn");
const likeCount = document.getElementById("likeCount");
const profileLikeMsg = document.getElementById("profileLikeMsg");
const leaderboardXp = document.getElementById("leaderboardXp");
const leaderboardGold = document.getElementById("leaderboardGold");
const leaderboardDice = document.getElementById("leaderboardDice");
const leaderboardLikes = document.getElementById("leaderboardLikes");
const leaderboardsMsg = document.getElementById("leaderboardsMsg");
const refreshLeaderboardsBtn = document.getElementById("refreshLeaderboardsBtn");
const dmSettingsMenu = document.getElementById("dmSettingsMenu");
const dmDeleteHistoryBtn = document.getElementById("dmDeleteHistoryBtn");
const dmReportBtn = document.getElementById("dmReportBtn");
const dmReplyPreview = document.getElementById("dmReplyPreview");
const dmReplyPreviewText = document.getElementById("dmReplyPreviewText");
const dmReplyClose = document.getElementById("dmReplyClose");
const dmMentionDropdown = document.getElementById("dmMentionDropdown");
const dmBgColor = document.getElementById("dmBgColor");
const dmBgColorText = document.getElementById("dmBgColorText");
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
const themeGrid = document.getElementById("themeGrid");
const themeMsg = document.getElementById("themeMsg");
const themeFilterButtons = Array.from(document.querySelectorAll("[data-theme-filter]"));
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
const mediaLightbox = document.getElementById("mediaLightbox");
const mediaLightboxImg = document.getElementById("mediaLightboxImg");
const mediaLightboxVideo = document.getElementById("mediaLightboxVideo");
const mediaLightboxClose = document.getElementById("mediaLightboxClose");

// info
const infoAge = document.getElementById("infoAge");
const infoGender = document.getElementById("infoGender");
const infoCreated = document.getElementById("infoCreated");
const infoLastSeen = document.getElementById("infoLastSeen");
const infoRoom = document.getElementById("infoRoom");
const infoStatus = document.getElementById("infoStatus");

// tabs/views
const tabInfo = document.getElementById("tabInfo");
const tabAbout = document.getElementById("tabAbout");
const tabCustomize = document.getElementById("tabCustomize");
const tabModeration = document.getElementById("tabModeration");

const viewInfo = document.getElementById("viewInfo");
const viewAbout = document.getElementById("viewAbout");
const viewCustomize = document.getElementById("viewCustomize");
const viewModeration = document.getElementById("viewModeration");

const bioRender = document.getElementById("bioRender");
const copyUsernameBtn = document.getElementById("copyUsernameBtn");
const mediaMsg = document.getElementById("mediaMsg");
const customizeMsg = document.getElementById("customizeMsg");
const levelBadge = document.getElementById("levelBadge");
const xpText = document.getElementById("xpText");
const xpProgress = document.getElementById("xpProgress");
const xpNote = document.getElementById("xpNote");
const levelToast = document.getElementById("levelToast");
const levelToastText = document.getElementById("levelToastText");

const directBadgeColor = document.getElementById("directBadgeColor");
const groupBadgeColor = document.getElementById("groupBadgeColor");
const directBadgeColorText = document.getElementById("directBadgeColorText");
const groupBadgeColorText = document.getElementById("groupBadgeColorText");
const saveBadgePrefsBtn = document.getElementById("saveBadgePrefsBtn");
// (dmBadgeDot + groupDmBadgeDot declared above near DM panel wiring)

// my profile edit
const myProfileEdit = document.getElementById("myProfileEdit");
const avatarFile = document.getElementById("avatarFile");
const editMood = document.getElementById("editMood");
const editAge = document.getElementById("editAge");
const editGender = document.getElementById("editGender");
const editBio = document.getElementById("editBio");
const saveProfileBtn = document.getElementById("saveProfileBtn");
const refreshProfileBtn = document.getElementById("refreshProfileBtn");
const profileMsg = document.getElementById("profileMsg");
const logoutBtn = document.getElementById("logoutBtn");
const logoutTopBtn = document.getElementById("logoutTopBtn");
const uiScaleBtn = document.getElementById("uiScaleBtn");
const uiScalePanel = document.getElementById("uiScalePanel");
const uiScaleCloseBtn = document.getElementById("uiScaleCloseBtn");
const uiScaleRange = document.getElementById("uiScaleRange");
const uiScaleValue = document.getElementById("uiScaleValue");
const uiScaleResetBtn = document.getElementById("uiScaleResetBtn");

// member quick mod
const memberModTools = document.getElementById("memberModTools");
const quickReason = document.getElementById("quickReason");
const quickReasonPresets = document.getElementById("quickReasonPresets");
const quickMuteMins = document.getElementById("quickMuteMins");
const quickBanMins = document.getElementById("quickBanMins");
const quickKickBtn = document.getElementById("quickKickBtn");
const quickMuteBtn = document.getElementById("quickMuteBtn");
const quickBanBtn = document.getElementById("quickBanBtn");
const quickModMsg = document.getElementById("quickModMsg");

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
const StickyYouTubePlayer = (()=>{
  let container, playerHolder, titleEl, channelEl, thumbEl, playPauseBtn, muteBtn, volumeSlider, seekSlider, currentTimeEl, durationEl, qualitySelect, minimizeBtn, closeBtn;
  let player = null;
  let apiReadyPromise = null;
  let progressTimer = null;
  let currentVideoId = null;
  let pendingAutoplay = false;

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
    volumeSlider?.addEventListener("input", handleVolumeChange, { passive:true });
    seekSlider?.addEventListener("input", handleSeek, { passive:true });
    qualitySelect?.addEventListener("change", applyQuality);
    minimizeBtn?.addEventListener("click", toggleMinimize);
    closeBtn?.addEventListener("click", close);
  }

  function ensurePlayer(){
    if(player) return Promise.resolve(player);
    return loadApi().then(()=>{
      player = new YT.Player(playerHolder, {
        height: "180",
        width: "320",
        playerVars: { playsinline:1, controls:0, modestbranding:1, rel:0, autoplay:0 },
        events: {
          onReady: handleReady,
          onStateChange: handleStateChange,
          onPlaybackQualityChange: refreshQualityOptions,
        }
      });
      return player;
    });
  }

  function handleReady(){
    updateVolumeUi(player.getVolume?.());
    refreshQualityOptions();
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
    if(!player || !qualitySelect) return;
    const q = qualitySelect.value;
    if(q) player.setPlaybackQuality?.(q);
  }
  function refreshQualityOptions(){
    if(!player || !qualitySelect || !window.YT?.PlayerState) return;
    const levels = (player.getAvailableQualityLevels?.() || []).filter(Boolean);
    const current = player.getPlaybackQuality?.();
    const opts = new Set(["default", ...levels]);
    qualitySelect.innerHTML = "";
    opts.forEach(level => {
      const opt = document.createElement("option");
      opt.value = level;
      opt.textContent = level === "default" ? "Auto" : level.toUpperCase();
      if(level === current) opt.selected = true;
      qualitySelect.appendChild(opt);
    });
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
    container.classList.toggle("is-minimized", !expanded);
  }
  function toggleMinimize(){
    if(!container) return;
    const willMinimize = !container.classList.contains("is-minimized");
    container.classList.toggle("is-minimized", willMinimize);
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
      container.classList.remove("is-minimized");
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
      if(!pendingAutoplay){
        player.cueVideoById?.(videoId);
      }else{
        player.loadVideoById(videoId);
        try{
          player.playVideo?.();
        }catch{
          try { player.mute?.(); player.playVideo?.(); } catch{}
        }
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

  return { loadVideo, close, minimize: toggleMinimize };
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
  const d = new Date(ts);
  if(Number.isNaN(d.getTime())) return String(ts);
  return d.toLocaleString();
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

const PUBLIC_THEME_NAMES = new Set(["Minimal Light", "Minimal Dark", "Minimal Light (High Contrast)", "Minimal Dark (High Contrast)", "Paper / Parchment", "Sky Light", "Fantasy Tavern", "Fantasy Tavern (Ember)", "Desert Dusk"]);
function canUseThemeName(themeName){
  // Public themes always allowed
  if(PUBLIC_THEME_NAMES.has(themeName)) return true;
  // VIP and above can use all themes
  const role = (typeof me !== "undefined" && me && me.role) ? me.role : "User";
  return roleRank(role) >= roleRank("VIP");
}

function roleRank(role){ const i=ROLES.indexOf(role); return i===-1?1:i; }

const STATUS_ALIASES = {
  "Do Not Disturb": "DnD",
  "Listening to Music": "Music",
  "Looking to Chat": "Chatting",
  "Invisible": "Lurking",
};
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

function avatarNode(url, fallbackText, role){
  const rKey = roleKey(role);

  const buildFallback = () => {
    const wrap=document.createElement("div");
    wrap.className = `avatarFallback role-${rKey}` + (rKey === "vip" ? " vipDiamond" : "");
    wrap.textContent=(fallbackText||"?").slice(0,1).toUpperCase();
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
    return img;
  }
  return buildFallback();
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
    return el;
  }

  // No avatar URL -> default gradient fallback
  el.classList.add("avatarFallback", `role-${roleKey(role)}`);
  el.textContent = (username || "?").slice(0, 1).toUpperCase();
  return el;
}

// Resolve role + avatar URL for a username from the latest presence list.
function getUserMeta(username){
  const name = String(username || "");
  const meName = String(me?.username || "");
  if (name && meName && name.toLowerCase() === meName.toLowerCase()) {
    return { role: me?.role || "member", avatarUrl: me?.avatar || me?.avatarUrl || null, username: meName };
  }
  const u = (lastUsers || []).find(x => String((x.username||x.name||"")).toLowerCase() === name.toLowerCase());
  return { role: u?.role || "member", avatarUrl: u?.avatar || u?.avatarUrl || null, username: u?.username || u?.name || name };
}


function clearMsgs(){
  msgs.innerHTML="";
  typingEl.textContent="";
  msgIndex.length=0;
}
function addSystem(text){
  const div=document.createElement("div");
  div.className="sys";

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
  msgs.scrollTop=msgs.scrollHeight;
}

let commandPopupDismissed=false;
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
function applyMentions(text){
  const safe = escapeHtml(text);
  const names = new Set((lastUsers || []).map((u) => u.username || u.name));
  if (me?.username) names.add(me.username);
  const list = Array.from(names).filter(Boolean);
  if (!list.length) return safe;
  const pattern = list.map(escapeRegex).join("|");
  const re = new RegExp(`@(${pattern})(?=$|[^\\S]|[.,!?:;])`, "gi");
  return safe.replace(re, (m)=>`<span class="mention">${m}</span>`);
}
function isNearBottom(el, threshold = 120){
  if(!el) return true;
  return el.scrollHeight - el.scrollTop - el.clientHeight <= threshold;
}
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
    const ok = /^https?:\/\//i.test(url) || /^\/(uploads|avatars)\//i.test(url);
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
  const hexOk = /^#([0-9a-f]{3}|[0-9a-f]{4}|[0-9a-f]{6}|[0-9a-f]{8})$/i;
  if(hexOk.test(color || "")) return color;
  if(hexOk.test(fallback || "")) return fallback;
  return "#000000";
}
function sanitizeColor(raw, fallback, hardDefault){
  if(isValidCssColor(raw)) return raw.trim();
  if(isValidCssColor(fallback)) return fallback.trim();
  if(isValidCssColor(hardDefault)) return hardDefault.trim();
  return hardDefault || badgeDefaults.direct;
}
function loadDmThemePrefsFromStorage(){
  try {
    const raw = localStorage.getItem("dmThemePrefs");
    const parsed = raw ? JSON.parse(raw) : {};
    return { ...dmThemeDefaults, ...parsed };
  } catch {
    return { ...dmThemeDefaults };
  }
}
function saveDmThemePrefsToStorage(){
  try { localStorage.setItem("dmThemePrefs", JSON.stringify(dmThemePrefs)); }
  catch{}
  queuePersistPrefs({ dmThemePrefs });
}
function applyDmThemePrefs(){
  const bg = sanitizeColor(dmThemePrefs.background, dmThemeDefaults.background, dmThemeDefaults.background);
  dmThemePrefs.background = bg;
  document.documentElement.style.setProperty("--dm-bg", bg);
  if(dmBgColor) dmBgColor.value = normalizeColorForInput(bg, dmThemeDefaults.background);
  if(dmBgColorText) dmBgColorText.value = bg;
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
    if(prefs.dmThemePrefs && typeof prefs.dmThemePrefs === "object"){
      dmThemePrefs = { ...dmThemeDefaults, ...prefs.dmThemePrefs };
      applyDmThemePrefs();
      saveDmThemePrefsToStorage();
    }
  }catch{}
}
function applyTheme(themeName, { persist=true, silent=false, storeLocal=persist } = {}){
  const safe = sanitizeThemeName(themeName || DEFAULT_THEME);
  currentTheme = safe;
  document.body?.setAttribute("data-theme", safe);
  if(storeLocal) setStoredTheme(safe);
  if(persist) persistThemePreference(safe);
  renderThemeGrid();
  if(themeMsg && !silent){
    themeMsg.textContent = `Theme applied: ${safe}`;
    setTimeout(() => { if(themeMsg.textContent.startsWith("Theme applied")) themeMsg.textContent = ""; }, 2400);
  }
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
function renderThemeGrid(){
  if(!themeGrid) return;

  // Split view: Light themes on the left, Dark themes on the right.
  themeGrid.innerHTML = "";
  themeGrid.classList.toggle("oneColumn", themeFilter !== "all");
  themeGrid.classList.toggle("onlyLight", themeFilter === "light");
  themeGrid.classList.toggle("onlyDark", themeFilter === "dark");

    const visibleThemes = THEME_LIST.filter((t) => t.name !== IRIS_LOLA_THEME || isIrisLolaAllowed());
  const lightThemes = visibleThemes.filter((t) => t.mode === "Light");
    const darkThemes  = visibleThemes.filter((t) => t.mode === "Dark");

  const makeColumn = (title, mode, items) => {
    const col = document.createElement("div");
    col.className = `themeColumn ${mode.toLowerCase()}`;

    const header = document.createElement("div");
    header.className = "themeColumnHeader";
    header.innerHTML = `<div class="themeColumnTitle">${escapeHtml(title)}</div>
                        <div class="themeColumnHint">${escapeHtml(mode)}</div>`;

    const body = document.createElement("div");
    body.className = "themeColumnBody";

    for(const theme of items){
      const card = document.createElement("button");
      card.type = "button";
      card.className = `themeCard compact${currentTheme === theme.name ? " selected" : ""}`;
      card.dataset.themeName = theme.name;
      card.innerHTML = `
        <div class="themeCardHeader">
          <div>
            <div class="themeLabel">${escapeHtml(theme.name)}</div>
          </div>
          <div class="themeCheck">✓</div>
        </div>
      `;
      card.appendChild(createThemeThumbnail(theme.name));
      if (canUseThemeName(theme.name)) {
        card.addEventListener("click", () => applyTheme(theme.name, { persist:true }));
      } else {
        card.classList.add("locked");
        // VIP ONLY badge (keep full colors visible)
        const vipTag = document.createElement("div");
        vipTag.className = "vipOnlyTag";
        vipTag.textContent = "VIP ONLY";
        card.appendChild(vipTag);

        // Preview button (10s) + card click preview
        const previewBtn = document.createElement("button");
        previewBtn.type = "button";
        previewBtn.className = "previewBtn";
        previewBtn.textContent = "Preview (10s)";
        previewBtn.addEventListener("click", (e) => {
          e.preventDefault();
          e.stopPropagation();
          previewTheme(theme.name, 10);
        });
        card.appendChild(previewBtn);

        card.addEventListener("click", (e) => {
          e.preventDefault();
          previewTheme(theme.name, 10);
        });
      }
      body.appendChild(card);
    }

    col.appendChild(header);
    col.appendChild(body);
    return col;
  };

  if(themeFilter === "light"){
    themeGrid.appendChild(makeColumn("Light themes", "Light", lightThemes));
    return;
  }
  if(themeFilter === "dark"){
    themeGrid.appendChild(makeColumn("Dark themes", "Dark", darkThemes));
    return;
  }

  themeGrid.appendChild(makeColumn("Light themes", "Light", lightThemes));
  themeGrid.appendChild(makeColumn("Dark themes", "Dark", darkThemes));
}

function setThemeFilter(filter){
  themeFilter = filter;
  themeFilterButtons.forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.themeFilter === filter);
  });
  renderThemeGrid();
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
  themeFilterButtons.forEach((btn) => {
    btn.addEventListener("click", () => setThemeFilter(btn.dataset.themeFilter));
  });
  renderThemeGrid();
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
dmThemePrefs = loadDmThemePrefsFromStorage();
applyDmThemePrefs();
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
  if (e?.target?.closest(".msg")) return;
  if (e?.target?.closest(".reactionMenu")) return;
  document.querySelectorAll(".msg.showActions").forEach((el) => el.classList.remove("showActions"));
  closeReactionMenu();
}, { capture: true });

// Tap outside to hide message action buttons (mobile).
document.addEventListener("click", (e)=>{
  const isTouch = window.matchMedia && window.matchMedia("(hover: none)").matches;
  if (!isTouch && window.innerWidth > 980) return;
  if (e.target && e.target.closest && e.target.closest(".msg")) return;
  document.querySelectorAll(".msg.showActions").forEach((el)=>el.classList.remove("showActions"));
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

function addMessage(m){
  const row = document.createElement("div");
  row.className = "msg" + (m.user === me.username ? " self" : "");
  row.dataset.mid = m.messageId;

  const shouldStick = isNearBottom(msgs, 160);

  const av = document.createElement("div");
  av.className = "msgAvatar";
  av.appendChild(avatarNode(m.avatar, m.user, m.role));
  av.title = `View ${m.user} profile`;
  av.tabIndex = 0;
  const openProfile = (e) => {
    e.stopPropagation();
    openMemberProfile(m.user);
  };
  av.addEventListener("click", openProfile);
  av.addEventListener("keydown", (e) => { if(e.key === "Enter" || e.key === " ") openProfile(e); });

  const main = document.createElement("div");
  main.className = "msgMain";

  const bubble = document.createElement("div");
  bubble.className = "bubble";

  if (m.replyToId && (m.replyToUser || m.replyToText)) {
    const replyLink = document.createElement("button");
    replyLink.type = "button";
    replyLink.className = "replyContext";
    replyLink.innerHTML = `
      <div class="replyUser">@${escapeHtml(m.replyToUser || "")}</div>
      <div class="replySnippet">${escapeHtml((m.replyToText || "").slice(0, 120))}</div>
    `;
    replyLink.onclick = (e) => {
      e.stopPropagation();
      const target = document.querySelector(`[data-mid="${m.replyToId}"]`);
      if (target) target.scrollIntoView({ behavior: "smooth", block: "center" });
    };
    bubble.appendChild(replyLink);
  }

  const meta = document.createElement("div");
  meta.className = "metaLine";
  meta.innerHTML = `
    <span class="uName">${escapeHtml(roleIcon(m.role))} ${escapeHtml(m.user)}</span>
    <span class="badge" style="color:${roleBadgeColor(m.role)}">${escapeHtml(m.role)}</span>
    <span class="ts">${new Date(m.ts).toLocaleTimeString([], {hour:"2-digit", minute:"2-digit"})}</span>
  `;

  bubble.appendChild(meta);

  const rawText = String(m.text || "");
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

  if(displayText){
    const text = document.createElement("div");
    text.className = "text";
    try {
      text.innerHTML = linkify(escapeHtml(displayText));
    } catch (err) {
      console.error("[addMessage] render failed:", err);
      text.textContent = displayText;
    }
    bubble.appendChild(text);
  }

  if(ytIds && ytIds.length){
    ytIds.forEach(id => bubble.appendChild(buildYouTubePreview(id)));
  }

  if(m.attachmentUrl && m.attachmentType){
    const att=document.createElement("div");
    att.className="attachment";
    if(m.attachmentType==="image"){
      const img=document.createElement("img");
      img.src=m.attachmentUrl;
      img.alt="image";
      img.addEventListener("click", ()=>openMediaLightbox(m.attachmentUrl, "image"));
      att.appendChild(img);
    }else if(m.attachmentType==="video"){
      const v=document.createElement("video");
      v.src=m.attachmentUrl;
      v.controls=true;
      v.playsInline=true;
      v.addEventListener("click", ()=>openMediaLightbox(m.attachmentUrl, "video"));
      att.appendChild(v);
    }else{
      const a=document.createElement("a");
      a.href=m.attachmentUrl;
      a.textContent="Download file";
      a.target="_blank";
      a.rel="noreferrer";
      att.appendChild(a);
    }
    bubble.appendChild(att);
  }

  // reactions display (below bubble, not inside it)
  const reacts = document.createElement("div");
  reacts.className = "reactions";
  reacts.id = "reacts-" + m.messageId;

  main.appendChild(bubble);
  main.appendChild(reacts);

  // actions rail: ONE reaction button (+ delete for mods)
  const actions = document.createElement("div");
  actions.className = "msgActions";

  const reactToggle = document.createElement("button");
  reactToggle.className = "reactBtn";
  reactToggle.type = "button";
  reactToggle.textContent = "❤️‍🔥";
  reactToggle.title = "React";
  reactToggle.onclick = (e)=>{
    e.stopPropagation();
    if(reactionMenuFor === m.messageId) closeReactionMenu();
    else openReactionMenu(m.messageId, reactToggle, row);
  };
  actions.appendChild(reactToggle);

  if(roleRank(me.role) >= roleRank("Moderator")){
    const del = document.createElement("button");
    del.className = "reactBtn";
    del.type = "button";
    del.textContent = "🗑️";
    del.title = "Delete message";
    del.onclick = (e)=>{
      e.stopPropagation();
      socket?.emit("mod delete message", { messageId: m.messageId });
    };
    actions.appendChild(del);
  }

  const replyBtn = document.createElement("button");
  replyBtn.className = "reactBtn";
  replyBtn.type = "button";
  replyBtn.textContent = "↩️";
  replyBtn.title = "Reply";
  replyBtn.onclick = (e)=>{
    e.stopPropagation();
    setReplyTarget({ id: m.messageId, user: m.user, text: m.text });
    row.classList.remove("showActions");
    focusMainComposer();
  };
  actions.prepend(replyBtn);



  // mobile: tap message to toggle actions (reply/react/delete)
const toggleActions = (e) => {
  // Ignore taps on interactive elements inside the message
  if (e?.target?.closest("button, a, input, textarea, select, label")) return;
  if (e?.stopPropagation) e.stopPropagation();

  // Close any other open action rails
  document.querySelectorAll(".msg.showActions").forEach((el) => {
    if (el !== row) el.classList.remove("showActions");
  });

  const on = row.classList.toggle("showActions");
  if (!on) closeReactionMenu();
};

bubble.addEventListener("pointerdown", toggleActions);

  row.appendChild(av);
  row.appendChild(main);
  row.appendChild(actions);

  msgs.appendChild(row);
  if (shouldStick || isNearBottom(msgs, 160)) {
    msgs.scrollTop = msgs.scrollHeight;
  }

  msgIndex.push({ id: m.messageId, el: row, textLower: (m.user+" "+m.text).toLowerCase() });
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
      socket?.emit("reaction", { messageId, emoji });
    });
    container.appendChild(pill);
  });
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
      socket?.emit("dm reaction", { threadId: tid, messageId, emoji });
    });
    container.appendChild(pill);
  });
}

function closeMemberMenu(){
  if (!memberMenu) return;
  memberMenu.classList.remove("open");
  memberMenuUser = null;
  memberMenuUsername = "";
}


// ---- Member quick-actions menu buttons
memberViewProfileBtn?.addEventListener("click", ()=>{
  const uname = (memberMenuUsername || memberMenuUser?.username || memberMenuUser?.name || "").trim();
  if (uname) openMemberProfile(uname);
  closeMemberMenu();
});
memberDmBtn?.addEventListener("click", ()=>{
  const uname = (memberMenuUsername || memberMenuUser?.username || memberMenuUser?.name || "").trim();
  if (uname) startDirectMessage(uname);
  closeMemberMenu();
});

function openMemberMenu(user, anchor){
  if (!memberMenu || !membersPane) {
    // Fallback if the quick-actions menu is unavailable
    const uname = user?.username || user?.name || "";
    if (uname) openMemberProfile(uname);
    return;
  }

  memberMenuUser = user;
  memberMenuUsername = user?.username || user?.name || "";
  if (memberMenuName) memberMenuName.textContent = `${roleIcon(user.role)} ${user.name}`;
  memberMenu.classList.add("open");

  const paneRect = membersPane.getBoundingClientRect();
  const rect = anchor.getBoundingClientRect();
  const top = rect.top - paneRect.top + membersPane.scrollTop + rect.height + 6;
  const left = rect.left - paneRect.left + 6;
  memberMenu.style.top = `${top}px`;
  memberMenu.style.left = `${left}px`;
}

function updateGoldUI(){
  if (!memberGold) return;
  if (progression && progression.gold != null) {
    const g = Number(progression.gold || 0);
    memberGold.textContent = `Gold: ${g.toLocaleString()}`;
    memberGold.classList.add("show");
    if (goldPill) {
      goldPill.textContent = `💰 ${g.toLocaleString()}`;
      goldPill.classList.add("show");
    }
  } else {
    memberGold.classList.remove("show");
    goldPill?.classList.remove("show");
  }
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

function renderMembers(users){
  lastUsers = users || [];
  cleanupRecentDiceRolls();
  refreshModTargetOptions(lastUsers);
  memberList.innerHTML="";
  lastUsers.forEach(u=>{
    const row=document.createElement("div");
    row.className="mItem";
    row.dataset.username = u.name;

    const av=document.createElement("div");
    av.className="mAvatar";
    av.appendChild(avatarNode(u.avatar, u.name, u.role));

    const dot=document.createElement("div");
    dot.className="dot";
    const statusLabel = normalizeStatusLabel(u.status, "Online");
    dot.style.background=statusDotColor(statusLabel);

    const meta=document.createElement("div");
    meta.className="mMeta";

    const name=document.createElement("div");
    name.className="mName";
    name.textContent=`${roleIcon(u.role)} ${u.name}`;

    const sub=document.createElement("div");
    sub.className="mSub";
    sub.textContent=`${u.role} • ${statusLabel}${u.mood?(" • "+u.mood):""}`;

    meta.appendChild(name);
    meta.appendChild(sub);

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
function setLeftDrawerOpen(isOpen){
  document.body.classList.toggle("drawer-left-open", !!isOpen);
}
function setRightDrawerOpen(isOpen){
  document.body.classList.toggle("drawer-right-open", !!isOpen);
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
function closeDrawers(){
  channelsPane?.classList.remove("open");
  membersPane?.classList.remove("open");
  drawerOverlay?.classList.remove("show");
  // When drawers close, let the mobile composer span full width again.
  document.body.classList.remove("drawer-left-open", "drawer-right-open");
  closeMemberMenu();
  syncDesktopMembersWidth();
}
function openChannels(){
  // toggle
  if (channelsPane?.classList.contains("open")) { closeDrawers(); return; }

  membersPane?.classList.remove("open");
  channelsPane?.classList.add("open");
  drawerOverlay?.classList.add("show");
  // Mobile: shift the fixed composer so it doesn't overlap the left drawer.
  document.body.classList.add("drawer-left-open");
  document.body.classList.remove("drawer-right-open");
  syncDesktopMembersWidth();
}

function openMembers(){
  // toggle
  if (membersPane?.classList.contains("open")) { closeDrawers(); return; }

  channelsPane?.classList.remove("open");
  membersPane?.classList.add("open");
  drawerOverlay?.classList.add("show");
  // Mobile: shift the fixed composer so it doesn't overlap the right drawer.
  document.body.classList.add("drawer-right-open");
  document.body.classList.remove("drawer-left-open");
  syncDesktopMembersWidth();
}

openChannelsBtn?.addEventListener("click", openChannels);
openMembersBtn?.addEventListener("click", openMembers);

/* Outside tap close: use pointerdown (better on mobile) */
drawerOverlay?.addEventListener("pointerdown", (e) => {
  e.preventDefault();
  closeDrawers();
}, { capture:true });
document.addEventListener("keydown", (e)=>{ if(e.key==="Escape") closeDrawers(); });
channelsCloseBtn?.addEventListener("click", closeDrawers);
membersCloseBtn?.addEventListener("click", closeDrawers);
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
  const parts = (t.participants || []);
  const others = parts.filter(p => p !== me?.username);
  if (t.title) return t.title;
  if (t.is_group) return others.join(", ") || "Group chat";
  return others[0] || "Direct Message";
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

function setDmTab(tab){
  dmTab = tab === "group" ? "group" : "direct";
  syncDmTabUi();
  renderDmThreads();
}

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

  div.appendChild(threadAvatarNode(t));

  const meta = document.createElement("div");
  meta.className = "dmItemMeta";

  const top = document.createElement("div");
  top.className = "dmItemTop";
  const title = document.createElement("div");
  title.className = "name";
  title.textContent = label;
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

  stripEl.innerHTML = "";
  if (list.length === 0) {
    stripEl.style.display = "none";
    if (stripEl === dmQuickStrip && dmQuickEmpty) dmQuickEmpty.hidden = false;
    return;
  }
  if (stripEl === dmQuickStrip && dmQuickEmpty) dmQuickEmpty.hidden = true;
  stripEl.style.display = "flex";

  list.sort((a,b)=>(Number(b.last_ts||0)-Number(a.last_ts||0)));
  for (const t of list) {
    const other = otherParty(t) || "?";
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "dmAvatarBtn" + (String(activeDmId)===String(t.id) ? " active" : "");
    btn.title = other ? `DM with ${other}` : "DM";

    const wrap = document.createElement("div");
    wrap.className = "dmAvatarWrap";

    const meta = getUserMeta(other);
    const av = makeAvatarEl({ username: meta.username || other, role: meta.role, avatarUrl: meta.avatarUrl, size: 34 });
    av.classList.add("dmAvatar");

    const badge = document.createElement("span");
    badge.className = "dmUnreadBadge";
    const lastRead = Number(dmLastRead[t.id] || 0);
    const lastTs = Number(t.last_ts || 0);
    const unread = dmUnreadThreads.has(t.id) || (lastTs > lastRead);
    badge.style.display = unread ? "block" : "none";

    wrap.appendChild(av);
    wrap.appendChild(badge);
    btn.appendChild(wrap);

    btn.addEventListener("click", ()=>{
      hideAllDmQuickBars();
      openDmPanel();
      openDmThread(t.id);
    });
    stripEl.appendChild(btn);
  }
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

  stripEl.innerHTML = "";
  if (list.length === 0) {
    stripEl.style.display = "none";
    if (stripEl === groupQuickStrip && groupQuickEmpty) groupQuickEmpty.hidden = false;
    return;
  }
  if (stripEl === groupQuickStrip && groupQuickEmpty) groupQuickEmpty.hidden = true;
  stripEl.style.display = "flex";
  list.sort((a,b)=>(Number(b.last_ts||0)-Number(a.last_ts||0)));

  for (const t of list) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "dmAvatarBtn" + (String(activeDmId)===String(t.id) ? " active" : "");
    btn.title = threadLabel(t);

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
}

function renderDmThreads(){
  // Backwards-compatible entrypoint.
  renderDirectThreads();
  renderGroupThreads();
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
    syncDmTabUi();
    renderDmThreads();
  } catch {
    setDmNotice("Could not load threads.");
  }
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
    const res = await dmFetch("/api/dm/thread", {
      method: "POST",
      headers: {"Content-Type":"application/json"},
      // Send multiple keys for backwards/forwards compatibility across server builds.
      body: JSON.stringify({
        kind: "direct",
        participants: [target],
        participant: target,
        user: target,
        to: target,
        username: target,
        participantId: (Number.isInteger(Number(targetId)) && Number(targetId) > 0) ? Number(targetId) : undefined,
        targetId: (Number.isInteger(Number(targetId)) && Number(targetId) > 0) ? Number(targetId) : undefined,
      })
    });

    if (!res.ok) {
      const text = await res.text();
      setDmNotice(text || "Could not start DM.");
      return;
    }

    const data = await res.json();
    // Don't waste vertical space with a persistent "DM ready" banner.
    setDmNotice(data.reused ? "Opened existing DM." : "");

    if (data.threadId) {
      upsertThreadMeta(data.threadId, { participants: [target, meName].filter(Boolean), is_group: false });
      openDmThread(data.threadId);
    }
  } catch {
    setDmNotice("Could not start DM.");
  }
}

function openDmPanel(){
  dmPanel.classList.add("open");
  setDmNotice("");
  clearDmBadges();
  syncDmTabUi();

  // load threads if we haven't yet
  if (!dmThreads.length) loadDmThreads();
  else renderDmThreads();
}

function closeDmPanel(){
  dmPanel.classList.remove("open");
  closeDmSettingsMenu();
}

function renderDmMessages(threadId){
  if (!dmMessagesEl) return;

  const keepOffset = dmMessagesEl.scrollHeight - dmMessagesEl.scrollTop;
  const stick = isNearBottom(dmMessagesEl, 160);

  dmMessagesEl.innerHTML = "";
  const msgsArr = dmMessages.get(threadId) || [];

  if (!msgsArr.length) {
    const empty = document.createElement("div");
    empty.className = "dmEmpty";
    empty.textContent = "No messages yet. Say hi to save this thread.";
    dmMessagesEl.appendChild(empty);
    dmPinned = true;
    return;
  }

  for (const m of msgsArr) {
    const isSelf = String(m.user) === String(me?.username);

    const row = document.createElement("div");
    row.className = "dmRow" + (isSelf ? " self" : "");
    row.dataset.dmMid = m.messageId || m.id;

    // Actions rail (outside the bubble)
    const actions = document.createElement("div");
    actions.className = "dmActionsRail";

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

    const delBtn = document.createElement("button");
    delBtn.type = "button";
    delBtn.className = "iconBtn smallIcon";
    delBtn.title = "Delete";
    delBtn.textContent = "🗑️";
    delBtn.onclick = (e) => {
      e.stopPropagation();
      const ok = confirm("Delete this message?");
      if (!ok) return;
      socket?.emit("dm delete message", { threadId, messageId: (m.messageId || m.id) });
    };

    actions.appendChild(reactBtn);
    actions.appendChild(replyBtn);
    actions.appendChild(delBtn);

    // Bubble + meta
    const bubbleWrap = document.createElement("div");
    bubbleWrap.className = "dmBubbleWrap";

    const bubble = document.createElement("div");
    bubble.className = "dmBubble" + (isSelf ? " self" : "");

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

    const reacts = document.createElement("div");
    reacts.className = "reacts";
    reacts.id = "dm-reacts-" + (m.messageId || m.id);
    reacts.dataset.threadId = String(threadId);
    bubble.appendChild(reacts);

    const meta = document.createElement("div");
    meta.className = "dmMetaRow";
    const u = document.createElement("span");
    u.className = "dmMetaUser";
    u.textContent = m.user || "";
    const t = document.createElement("span");
    t.className = "dmMetaTime";
    t.textContent = m.ts ? new Date(m.ts).toLocaleTimeString([], {hour:"2-digit", minute:"2-digit"}) : "";
    meta.appendChild(u);
    meta.appendChild(t);

    bubbleWrap.appendChild(bubble);
    bubbleWrap.appendChild(meta);

    // If we already have reactions cached for this message, render them now.
    const midKey = String(m.messageId || m.id);
    if (dmReactionsCache[midKey]) renderDmReactions(midKey, dmReactionsCache[midKey]);

    // Order: for self messages, actions on the LEFT of the bubble;
    // for incoming messages, actions on the RIGHT.
    if (isSelf) {
      row.appendChild(actions);
      row.appendChild(bubbleWrap);
    } else {
      row.appendChild(bubbleWrap);
      row.appendChild(actions);
    }

    // Mobile/desktop: tap/click the row to toggle actions
    const toggleActions = (e) => {
      if (e?.target?.closest("button, a, input, textarea, select, label")) return;
      document.querySelectorAll(".dmRow.showActions").forEach((el) => {
        if (el !== row) el.classList.remove("showActions");
      });
      row.classList.toggle("showActions");
    };
    row.addEventListener("pointerdown", toggleActions);

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

function setDmMeta(thread){
  if (!thread) {
    dmMetaTitle.textContent = "Pick a thread";
    dmMetaPeople.textContent = "";
    return;
  }
  dmMetaTitle.textContent = threadLabel(thread);
  const names = thread.participants || [];
  dmMetaPeople.textContent = thread.is_group
    ? `${names.length} member${names.length === 1 ? "" : "s"}`
    : names.join(", ");
}

function openDmThread(threadId){
  activeDmId = threadId;
  const meta = dmThreads.find(t => String(t.id) === String(threadId));
  if (meta) setDmTab(meta.is_group ? "group" : "direct");
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
  const txt = dmText.value.trim();
  if (!txt) return;
  socket?.emit("dm message", { threadId: activeDmId, text: txt, replyToId: dmReplyTarget?.id || null });
  dmText.value = "";
  setDmReplyTarget(null);
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
    const res = await dmFetch("/api/dm/thread", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        kind: "group",
        participants: names,
        // Compatibility keys
        users: names.join(","),
      }),
    });
    dmModalPrimaryBtn.disabled = false;
    if (!res.ok) {
      const txt = await res.text();
      setDmNotice(txt || "Could not create group.");
      return;
    }
    const data = await res.json();
    closeDmPicker();
    await loadDmThreads();
    if (data.threadId) openDmThread(data.threadId);
  } catch {
    setDmNotice("Could not create group.");
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

dmBgColor?.addEventListener("input", () => {
  dmThemePrefs.background = dmBgColor.value;
  if(dmBgColorText) dmBgColorText.value = dmBgColor.value;
  applyDmThemePrefs();
  saveDmThemePrefsToStorage();
});
dmBgColorText?.addEventListener("input", () => {
  const safe = sanitizeColor(dmBgColorText.value, dmThemePrefs.background, dmThemeDefaults.background);
  dmThemePrefs.background = safe;
  applyDmThemePrefs();
  saveDmThemePrefsToStorage();
});

memberViewProfileBtn?.addEventListener("click", () => {
  const uname = (memberMenuUser?.username || memberMenuUser?.name || memberMenuUsername || "").trim();
  if (uname) openMemberProfile(uname);
  closeMemberMenu();
});

memberDmBtn?.addEventListener("click", () => {
  if (memberMenuUser) startDirectMessage(memberMenuUser.name);
});

document.addEventListener("click", (e) => {
  if (!memberMenu?.classList.contains("open")) return;
  if (memberMenu.contains(e.target)) return;
  if (e.target.closest(".mItem")) return;
  closeMemberMenu();
});
membersPane?.addEventListener("scroll", closeMemberMenu);

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

// upload button icon -> open file picker
pickFileBtn?.addEventListener("click", () => {
  if (currentRoom === "diceroom") {
    socket?.emit("dice:roll");
  } else {
    fileInput.click();
  }
});

// upload preview
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
  const f=fileInput.files?.[0];
  if(!f) return clearUploadPreview();
  if(f.size > 10*1024*1024){
    addSystem("Max upload size is 10MB.");
    fileInput.value="";
    return clearUploadPreview();
  }
  showUploadPreview(f);
});
cancelUploadBtn.addEventListener("click", () => {
  if(uploadXhr){ uploadXhr.abort(); uploadXhr=null; addSystem("Upload canceled."); }
  fileInput.value="";
  clearUploadPreview();
});
function uploadChatFileWithProgress(file){
  return new Promise((resolve,reject)=>{
    const form=new FormData();
    form.append("file", file);
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
  const active=document.querySelector(".tab.active");
  active?.scrollIntoView({ behavior:"smooth", inline:"center", block:"nearest" });
}
function setTab(tab){
  for(const el of document.querySelectorAll(".tab")){
    el.classList.toggle("active", el.dataset.tab===tab);
  }
  viewInfo.style.display = tab==="info" ? "block" : "none";
  viewAbout.style.display = tab==="about" ? "block" : "none";
  viewEdit.style.display = tab==="edit" ? "block" : "none";
  viewModeration.style.display = tab==="moderation" ? "block" : "none";
  if(tab === "edit") showEditPanel("about");
  focusActiveTab();
}
tabEdit.addEventListener("click", ()=>setTab("edit"));

function showEditPanel(which){
  const isAbout = which === "about";
  const isThemes = which === "themes";
  const isDm = which === "dm";
  const isGifts = which === "gifts";
  const isPrefs = which === "preferences";

  if (editAboutPanel) editAboutPanel.style.display = isAbout ? "block" : "none";
  if (editThemesPanel) editThemesPanel.style.display = isThemes ? "block" : "none";
  if (editDmPanel) editDmPanel.style.display = isDm ? "block" : "none";
  if (editGiftsPanel) editGiftsPanel.style.display = isGifts ? "block" : "none";
  if (editPreferencesPanel) editPreferencesPanel.style.display = isPrefs ? "block" : "none";

  editAboutBtn?.classList.toggle("active", isAbout);
  editThemesBtn?.classList.toggle("active", isThemes);
  editDmBtn?.classList.toggle("active", isDm);
}

editAboutBtn?.addEventListener("click", ()=>showEditPanel("about"));
editThemesBtn?.addEventListener("click", ()=>showEditPanel("themes"));
editDmBtn?.addEventListener("click", ()=>showEditPanel("dm"));

// New profile edit menu + avatar action wiring
wireProfileMenu();
wireSoundPrefs();
wireProfileAvatarActions();
tabInfo.addEventListener("click", ()=>setTab("info"));
tabAbout.addEventListener("click", ()=>setTab("about"));
tabCustomize?.addEventListener("click", ()=>setTab("customize"));
tabModeration.addEventListener("click", async ()=>{
  setTab("moderation");
  await refreshLogs();
});

// modal open/close
function openModal(){ modal.style.display="flex"; }
function closeModal(){
  modal.style.display="none";
  modalTargetUsername=null;
  modalTargetUserId=null;
  quickModMsg.textContent="";
  modMsg.textContent="";
  logsMsg.textContent="";
  mediaMsg.textContent="";
  if (customizeMsg) customizeMsg.textContent = "";
}
closeModalBtn.addEventListener("click", closeModal);
modal.addEventListener("click", (e)=>{ if(e.target===modal) closeModal(); });

// rooms
function setActiveRoom(room){
  currentRoom = room;
  document.body.classList.toggle("dice-room", room === "diceroom");
  nowRoom.textContent = displayRoomName(room);
  roomTitle.textContent = displayRoomName(room);
  msgInput.placeholder = `Message ${displayRoomName(room)}`;

  // Dice Room: swap upload button to dice roll
  if (pickFileBtn) {
    if (room === "diceroom") {
      pickFileBtn.textContent = "🎲";
      pickFileBtn.title = "Roll Dice";
    } else {
      pickFileBtn.textContent = "📷";
      pickFileBtn.title = "Upload";
    }
  }
  document.querySelectorAll(".chan").forEach(el=>{
    el.classList.toggle("active", el.dataset.room === room);
  });
}
function joinRoom(room){
  room = sanitizeRoomClient(room) || "main";
  setActiveRoom(room);
  clearMsgs();
  socket?.emit("join room", { room, status: normalizeStatusLabel(statusSelect.value, "Online") });
  closeDrawers();
}
chanList.addEventListener("click", (e)=>{
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

function renderRoomsList(rooms){
  chanList.innerHTML = "";
  for(const r of rooms || []){
    const div = document.createElement("div");
    div.className = "chan" + (r === currentRoom ? " active" : "");
    div.dataset.room = r;
    div.textContent = displayRoomName(r); // no '#'
    chanList.appendChild(div);
  }
}

async function loadRooms(){
  const {res, text} = await api("/rooms", { method:"GET" });
  if(!res.ok) return;
  try{
    const rooms = JSON.parse(text);
    renderRoomsList(rooms);
  }catch{}
}

async function createRoomFlow(){
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

  // rooms will also update via socket event, but we can refresh immediately:
  await loadRooms();
  joinRoom(name);
}

function updateRoomControlsVisibility(){
  if(addRoomBtn){
    const canCreate = me && roleRank(me.role) >= roleRank("Co-owner");
    addRoomBtn.style.display = rightPanelMode === "rooms" && canCreate ? "inline-flex" : "none";
  }
}

function ensureChangelogLoaded(force = false){
  if (activeMenuTab !== "changelog") return;
  return loadChangelog(force);
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

async function loadLeaderboards(force = false){
  if (leaderboardsLoading) return;
  if (leaderboardsLoaded && !force) return;
  leaderboardsLoading = true;
  if (leaderboardsMsg) leaderboardsMsg.textContent = "Loading...";
  try {
    const res = await fetch("/api/leaderboards");
    if (!res.ok) throw new Error();
    const data = await res.json();
    renderLeaderboard(leaderboardXp, data?.xp, (item, idx) => ({ label: `${idx + 1}. ${item.username}`, meta: `Level ${item.level}` }));
    renderLeaderboard(leaderboardGold, data?.gold, (item, idx) => ({ label: `${idx + 1}. ${item.username}`, meta: `${Number(item.gold || 0).toLocaleString()} Gold` }));
    renderLeaderboard(leaderboardDice, data?.dice, (item, idx) => ({ label: `${idx + 1}. ${item.username}`, meta: `${Number(item.sixes || 0)}× ${diceFace(6)}` }));
    renderLeaderboard(leaderboardLikes, data?.likes, (item, idx) => ({ label: `${idx + 1}. ${item.username}`, meta: `${Number(item.likes || 0)} likes` }));
    leaderboardsLoaded = true;
    if (leaderboardsMsg) leaderboardsMsg.textContent = "";
  } catch {
    leaderboardsLoaded = false;
    if (leaderboardsMsg) leaderboardsMsg.textContent = "Failed to load leaderboards.";
  } finally {
    leaderboardsLoading = false;
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
  if(activeMenuTab === "leaderboards") loadLeaderboards();
}

function updateChangelogControlsVisibility(){
  const isOwner = me && roleRank(me.role) >= roleRank("Owner");
  if(changelogActions) changelogActions.style.display = isOwner ? "flex" : "none";
  if(!isOwner) closeChangelogEditor();
}

function openChangelogEditor(entry){
  if(!changelogEditor) return;
  editingChangelogId = entry?.id || null;
  if(changelogTitleInput) changelogTitleInput.value = entry?.title || "";
  if(changelogBodyInput) changelogBodyInput.value = entry?.body || "";
  if(changelogEditMsg) changelogEditMsg.textContent = "";
  changelogEditor.style.display = "block";
  changelogTitleInput?.focus();
}

function closeChangelogEditor(){
  editingChangelogId = null;
  if(changelogEditor) changelogEditor.style.display = "none";
  if(changelogTitleInput) changelogTitleInput.value = "";
  if(changelogBodyInput) changelogBodyInput.value = "";
  if(changelogEditMsg) changelogEditMsg.textContent = "";
}

async function loadChangelog(force=false){
  if(!force && changelogLoaded && !changelogDirty) return;
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
    changelogEntries = Array.isArray(rows) ? rows : [];
  }catch{
    changelogEntries = [];
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

  // Format timestamps in the viewer's locale + timezone, but avoid showing "Invalid Date".
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

  for(const entry of changelogEntries){
    const wrap = document.createElement("div");
    wrap.className = "changelogEntry";

    const header = document.createElement("div");
    header.className = "changelogEntryHeader";

    const metaBlock = document.createElement("div");
    metaBlock.style.display = "flex";
    metaBlock.style.flexDirection = "column";
    metaBlock.style.gap = "4px";

    const title = document.createElement("div");
    title.className = "changelogEntryTitle";
    title.textContent = entry.title || "(untitled)";
    const meta = document.createElement("div");
    meta.className = "changelogEntryMeta";
    meta.textContent = formatChangelogDate(entry.createdAt);

    metaBlock.appendChild(title);
    metaBlock.appendChild(meta);
    header.appendChild(metaBlock);

    if(isOwner){
      const actions = document.createElement("div");
      actions.className = "changelogActions";
      const editBtn = document.createElement("button");
      editBtn.className = "btn secondary";
      editBtn.type = "button";
      editBtn.textContent = "Edit";
      editBtn.addEventListener("click", ()=>openChangelogEditor(entry));

      const delBtn = document.createElement("button");
      delBtn.className = "btn danger";
      delBtn.type = "button";
      delBtn.textContent = "Delete";
      delBtn.addEventListener("click", ()=>deleteChangelogEntry(entry.id));

      actions.appendChild(editBtn);
      actions.appendChild(delBtn);
      header.appendChild(actions);
    }

    const body = document.createElement("div");
    body.className = "changelogBody";
    body.innerHTML = escapeHtml(entry.body || "").replace(/\n/g, "<br>");

    wrap.appendChild(header);
    wrap.appendChild(body);
    changelogList.appendChild(wrap);
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
  latestUpdate.style.display = "block";

  // Compact by default to save UI space; expand only when user taps View.
  latestUpdate.classList.toggle("compact", !latestUpdateExpanded);

  if(latestUpdateTitle) latestUpdateTitle.textContent = latestChangelogEntry.title || "(untitled)";
  if(latestUpdateDate) latestUpdateDate.textContent = latestChangelogEntry.createdAt
    ? new Date(latestChangelogEntry.createdAt).toLocaleString()
    : "";

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
if(refreshLeaderboardsBtn) refreshLeaderboardsBtn.addEventListener("click", ()=> loadLeaderboards(true));
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

// typing/send
let typingDebounce=null;
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
  if(!text.trim() && !file) return;

  try{
    let attachment=null;
    if(file){
      addSystem(`Uploading ${file.name}...`);
      attachment = await uploadChatFileWithProgress(file);
      fileInput.value="";
      clearUploadPreview();
    }

    socket.emit("chat message", {
      text,
      replyToId: replyTarget?.id || null,
      attachmentUrl: attachment?.url || "",
      attachmentType: attachment?.type || "",
      attachmentMime: attachment?.mime || "",
      attachmentSize: attachment?.size || 0
    });

    msgInput.value="";
    setReplyTarget(null);
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
async function api(path, options){
  try{
  const res = await fetch(path, { credentials: "include", ...options });
    const text=await res.text().catch(()=> "");
    return {res, text};
  }catch{
    return {res:{ok:false,status:0}, text:"Network error"};
  }
}

async function doLogin(){
  authMsg.textContent="Logging in...";
  const {res,text}=await api("/login",{
    method:"POST", headers:{"Content-Type":"application/json"},
    body:JSON.stringify({username:authUser.value, password:authPass.value})
  });
  if(!res.ok){ authMsg.textContent=text||"Login failed."; return; }
  await startApp();
}
async function doRegister(){
  authMsg.textContent="Registering...";
  const {res,text}=await api("/register",{
    method:"POST", headers:{"Content-Type":"application/json"},
    body:JSON.stringify({username:authUser.value, password:authPass.value})
  });
  if(!res.ok){ authMsg.textContent=text||"Register failed."; return; }
  authMsg.textContent="Registered! Now click Login.";
}
loginBtn.addEventListener("click", doLogin);
regBtn.addEventListener("click", doRegister);
authPass.addEventListener("keydown", (e)=>{ if(e.key==="Enter") doLogin(); });

async function doLogout(){
  await fetch("/logout", {method:"POST"});
  location.reload();
}
logoutBtn.addEventListener("click", doLogout);

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

  function openPanel(){
    if(!uiScalePanel) return;
    uiScalePanel.hidden = false;
    syncUiScaleUi();
  }
  function closePanel(){
    if(!uiScalePanel) return;
    uiScalePanel.hidden = true;
  }
  function togglePanel(){
    if(!uiScalePanel) return;
    if(uiScalePanel.hidden) openPanel();
    else closePanel();
  }

  uiScaleBtn?.addEventListener("click", (e)=>{ e.stopPropagation(); togglePanel(); });
  uiScaleCloseBtn?.addEventListener("click", (e)=>{ e.stopPropagation(); closePanel(); });

  document.addEventListener("click", (e)=>{
    if(!uiScalePanel || uiScalePanel.hidden) return;
    if(e.target && (uiScalePanel.contains(e.target) || uiScaleBtn?.contains(e.target))) return;
    closePanel();
  });

  uiScaleRange?.addEventListener("input", ()=>{
    const v = Number(uiScaleRange.value);
    applyUiScale(v);
    uiScaleValue.textContent = Math.round(v * 100) + "%";
  });

  uiScaleResetBtn?.addEventListener("click", ()=>{
    applyUiScale(null);
    syncUiScaleUi();
  });

  window.addEventListener("resize", ()=>{ if(!uiScalePanel?.hidden) syncUiScaleUi(); }, { passive:true });
})();

logoutTopBtn?.addEventListener("click", doLogout);

// ---- profiles
async function loadMyProfile(){
  const res=await fetch("/profile");
  if(!res.ok) return;
  const p=await res.json();
  modalTargetUserId = Number(p?.id) || null;
  me.username = p.username;
  me.role = p.role;
  me.level = p.level || me.level;

  applyProgressionPayload(p);

  meName.textContent=p.username;
  meRole.textContent=`${roleIcon(p.role)} ${p.role}`;
  meAvatar.innerHTML="";
  meAvatar.appendChild(avatarNode(p.avatar, p.username, p.role));
  renderLevelProgress(progression, true);
}

function fillProfileUI(p, isSelf){
  modalAvatar.innerHTML="";
  modalAvatar.appendChild(avatarNode(p.avatar, p.username, p.role));
  modalName.textContent=p.username;
  modalRole.textContent=`${roleIcon(p.role)} ${p.role}`;
  modalRole.style.color=roleBadgeColor(p.role);
  modalMood.textContent = p.mood ? `Mood: ${p.mood}` : "Mood: (none)";

  infoAge.textContent = (p.age ?? "—");
  infoGender.textContent = (p.gender ?? "—");
  infoCreated.textContent = fmtCreated(p.created_at);
  infoLastSeen.textContent = p.last_seen ? fmtAbs(p.last_seen) : "—";
  infoRoom.textContent = p.current_room ? `#${p.current_room}` : (p.last_room ? `#${p.last_room}` : "—");
  const statusLabel = normalizeStatusLabel(p.last_status, "");
  infoStatus.textContent = statusLabel || "—";

  bioRender.innerHTML = p.bio ? renderBBCode(p.bio) : "(no bio)";
  renderLevelProgress(p, isSelf);
  syncProfileLikes(p, isSelf);
  if (profileLikeMsg) profileLikeMsg.textContent = "";
}


function fillProfileSheetHeader(p, isSelf){
  if (!profileSheetHero) return;

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

  // Subline: mood + status/room snapshot
  const mood = p.mood ? `Mood: ${p.mood}` : "Mood: (none)";
  const room = p.current_room ? `• In #${p.current_room}` : (p.last_room ? `• Last: #${p.last_room}` : "");
  const statusLabel = normalizeStatusLabel(p.last_status, "");
  const status = statusLabel ? `• ${statusLabel}` : "";
  if (profileSheetSub) profileSheetSub.textContent = `${mood} ${status} ${room}`.trim();

  // Stats (likes are real; "stars" is a placeholder hook you can wire later)
  if (profileSheetStats){
    profileSheetStats.style.display = "flex";
    if (profileSheetLikes){
      const likesVal = Number(p.likes || 0);
      profileSheetLikes.textContent = `${isSelf ? "❤️" : (p.likedByMe ? "❤️" : "♡")} ${likesVal.toLocaleString()}`;
    }
    if (profileSheetStars){
      // If you later add "stars" / "reputation", set p.stars and it will display automatically.
      const starsVal = Number(p.stars || 0);
      profileSheetStars.textContent = `⭐ ${starsVal.toLocaleString()}`;
    }
  }

  // Avatar action buttons only for self
  if (profileSheetAvatarActions){
    profileSheetAvatarActions.style.display = isSelf ? "flex" : "none";
  }
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

  // Defaults: master off, individual on (so enabling master immediately works)
  const k = Sound.keys;
  const enabled = (localStorage.getItem(k.KEY_ENABLED) === "1");
  const roomOn = (localStorage.getItem(k.KEY_ROOM) !== "0");      // default true
  const dmOn = (localStorage.getItem(k.KEY_DM) !== "0");          // default true
  const mentionOn = (localStorage.getItem(k.KEY_MENTION) !== "0");// default true

  prefSoundEnabled.checked = enabled;
  if (prefSoundRoom) prefSoundRoom.checked = roomOn;
  if (prefSoundDm) prefSoundDm.checked = dmOn;
  if (prefSoundMention) prefSoundMention.checked = mentionOn;

  const subDisabled = !enabled;
  if (prefSoundRoom) prefSoundRoom.disabled = subDisabled;
  if (prefSoundDm) prefSoundDm.disabled = subDisabled;
  if (prefSoundMention) prefSoundMention.disabled = subDisabled;

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

  syncSoundPrefsUI(false);

  prefSoundEnabled.addEventListener("change", async () => {
    Sound.set.setBool(k.KEY_ENABLED, prefSoundEnabled.checked);
    syncSoundPrefsUI(true);

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
  });

  prefSoundDm?.addEventListener("change", () => {
    Sound.set.setBool(k.KEY_DM, prefSoundDm.checked);
    syncSoundPrefsUI(false);
  });

  prefSoundMention?.addEventListener("change", () => {
    Sound.set.setBool(k.KEY_MENTION, prefSoundMention.checked);
    syncSoundPrefsUI(false);
  });
}

function wireProfileMenu(){
  if (!profileMenu) return;
  if (profileMenu._wired) return;
  profileMenu._wired = true;

  profileMenu.addEventListener("click", (e) => {
    const btn = e.target.closest("[data-action]");
    if (!btn) return;
    const action = btn.dataset.action;

    // Always ensure we're in the Edit tab when using this menu
    setTab("edit");

    if (action === "edit-about") return showEditPanel("about");
    if (action === "edit-themes") return showEditPanel("themes");
    if (action === "edit-dm") return showEditPanel("dm");
    if (action === "edit-gifts") return showEditPanel("gifts");

    if (action === "open-preferences"){
      setTab("edit");
      showEditPanel("preferences");
      if (profileMsg) profileMsg.textContent = "";
      // Sync UI toggles
      try { syncSoundPrefsUI(true); } catch {}
      return;
    }
  });
}

function wireProfileAvatarActions(){
  if (profileAvatarChangeBtn && !profileAvatarChangeBtn._wired){
    profileAvatarChangeBtn._wired = true;
    profileAvatarChangeBtn.addEventListener("click", () => {
      setTab("edit");
      showEditPanel("about");
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
  if (likeCount) likeCount.textContent = likesVal.toLocaleString();
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

async function openMyProfile(){
  closeDrawers();

  // Try the self profile endpoint first (includes edit fields)
  let res = await fetch("/profile");
  if (!res.ok && me?.username){
    // Fallback to member profile route if /profile fails for any reason
    try { await openMemberProfile(me.username); return; } catch {}
  }
  if(!res.ok) return;
  const p = await res.json();
modalTargetUsername = p.username;
  applyProgressionPayload(p);

  modalTitle.textContent="My Profile";
  modalMeta.textContent = p.created_at ? `Created: ${fmtCreated(p.created_at)}` : "";

  fillProfileUI(p, true);
  syncCustomizationUI();

  myProfileEdit.style.display="block";
  memberModTools.style.display="none";

  editMood.value=p.mood||"";
  editAge.value=(p.age ?? "");
  editGender.value=p.gender||"";
  editBio.value=p.bio||"";
  avatarFile.value="";
  profileMsg.textContent="";

  tabModeration.style.display = (roleRank(me.role) >= roleRank("Moderator")) ? "block" : "none";
  setTab("info");
  openModal();
}
profileBtn.addEventListener("click", openMyProfile);

saveProfileBtn.addEventListener("click", async ()=>{
  profileMsg.textContent="Saving...";
  const form=new FormData();
  form.append("mood", editMood.value);
  form.append("age", editAge.value);
  form.append("gender", editGender.value);
  form.append("bio", editBio.value);
  if(avatarFile.files[0]) form.append("avatar", avatarFile.files[0]);

  const res=await fetch("/profile", {method:"POST", body:form});
  if(!res.ok){
    const t=await res.text().catch(()=> "Save failed.");
    profileMsg.textContent=t || "Save failed.";
    return;
  }
  profileMsg.textContent="Saved!";
  await loadMyProfile();
  socket?.emit("join room", { room: currentRoom, status: normalizeStatusLabel(statusSelect.value, "Online") });
  await openMyProfile();
});
refreshProfileBtn.addEventListener("click", openMyProfile);

async function openMemberProfile(username){
  modalTargetUsername = username;
  closeDrawers();

  const res=await fetch("/profile/" + encodeURIComponent(username));
  if(!res.ok) return;
  const p=await res.json();
  modalTargetUserId = Number(p?.id) || null;
  const isSelf = !!me && normKey(me.username) === normKey(p.username);
  if (isSelf) applyProgressionPayload(p);

  modalTitle.textContent="Member Profile";
  modalMeta.textContent = p.created_at ? `Created: ${fmtCreated(p.created_at)}` : "";
  fillProfileUI(p, isSelf);
  syncCustomizationUI();

  myProfileEdit.style.display="none";

  const iCanMod = (roleRank(me.role) >= roleRank("Moderator")) && (roleRank(me.role) > roleRank(p.role));
  memberModTools.style.display = iCanMod ? "block" : "none";
  quickReason.value=""; quickModMsg.textContent="";
  if(quickMuteMins) quickMuteMins.value = quickMuteMins.querySelector("option")?.value || "10";
  if(quickBanMins) quickBanMins.value = quickBanMins.querySelector("option")?.value || "0";

  setModTarget(username);
  if(modReason) modReason.value = "";
  if(modMsg) modMsg.textContent = "";

  tabModeration.style.display = (roleRank(me.role) >= roleRank("Moderator")) ? "block" : "none";
  setTab("info");
  openModal();
}

likeProfileBtn?.addEventListener("click", async () => {
  if (!modalTargetUsername || likeProfileBtn.disabled) return;
  profileLikeMsg.textContent = "";
  likeProfileBtn.disabled = true;
  try {
    const res = await fetch(`/profile/${encodeURIComponent(modalTargetUsername)}/like`, { method: "POST" });
    if (!res.ok) {
      const t = await res.text().catch(() => "");
      profileLikeMsg.textContent = t || "Could not update like.";
      return;
    }
    const data = await res.json();
    syncProfileLikes({ likes: data.likes, likedByMe: data.liked }, false);
  } catch (err) {
    profileLikeMsg.textContent = "Could not update like.";
  } finally {
    const isSelf = normKey(modalTargetUsername) === normKey(me?.username);
    likeProfileBtn.disabled = isSelf;
  }
});

// media actions
copyUsernameBtn.addEventListener("click", async ()=>{
  const u = modalTargetUsername || me?.username || "";
  try{ await navigator.clipboard.writeText(u); mediaMsg.textContent="Copied username."; }
  catch{ mediaMsg.textContent="Copy failed (browser blocked)."; }
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

quickKickBtn.addEventListener("click", ()=>{
  const reason = (quickReason.value || "").trim();
  const err=requireReason(reason);
  if(err){ quickModMsg.textContent=err; return; }
  if(!modalTargetUsername){ quickModMsg.textContent="No target selected."; return; }
  if(!confirmModeration("kick", modalTargetUsername)) return;
  socket?.emit("mod kick", { username: modalTargetUsername });
  quickModMsg.textContent="Kick sent.";
});
quickMuteBtn.addEventListener("click", ()=>{
  const reason = (quickReason.value || "").trim();
  const err=requireReason(reason);
  if(err){ quickModMsg.textContent=err; return; }
  if(!modalTargetUsername){ quickModMsg.textContent="No target selected."; return; }
  if(!confirmModeration("mute", modalTargetUsername)) return;
  const mins=Number(quickMuteMins.value || 10);
  socket?.emit("mod mute", { username: modalTargetUsername, minutes: mins, reason });
  quickModMsg.textContent="Mute sent.";
});
quickBanBtn.addEventListener("click", ()=>{
  const reason = (quickReason.value || "").trim();
  const err=requireReason(reason);
  if(err){ quickModMsg.textContent=err; return; }
  if(!modalTargetUsername){ quickModMsg.textContent="No target selected."; return; }
  if(!confirmModeration("ban", modalTargetUsername)) return;
  const mins=Number(quickBanMins.value || 0);
  socket?.emit("mod ban", { username: modalTargetUsername, minutes: mins, reason });
  quickModMsg.textContent="Ban sent.";
});

// mod panel
modRefreshTargetsBtn?.addEventListener("click", ()=>{
  refreshModTargetOptions(lastUsers);
  modMsg.textContent = "Online list refreshed.";
});
modKickBtn.addEventListener("click", ()=>{
  const reason = (modReason.value || "").trim();
  const err=requireReason(reason);
  if(err){ modMsg.textContent=err; return; }
  const target = selectedModTarget();
  const targetErr = ensureTarget(target);
  if(targetErr){ modMsg.textContent = targetErr; return; }
  if(!confirmModeration("kick", target)) return;
  socket?.emit("mod kick", { username: target });
  modMsg.textContent="Kick sent.";
});
modMuteBtn.addEventListener("click", ()=>{
  const reason = (modReason.value || "").trim();
  const err=requireReason(reason);
  if(err){ modMsg.textContent=err; return; }
  const target = selectedModTarget();
  const targetErr = ensureTarget(target);
  if(targetErr){ modMsg.textContent = targetErr; return; }
  if(!confirmModeration("mute", target)) return;
  const mins=Number(modMuteMins.value || 10);
  socket?.emit("mod mute", { username: target, minutes: mins, reason });
  modMsg.textContent="Mute sent.";
});
modBanBtn.addEventListener("click", ()=>{
  const reason = (modReason.value || "").trim();
  const err=requireReason(reason);
  if(err){ modMsg.textContent=err; return; }
  const target = selectedModTarget();
  const targetErr = ensureTarget(target);
  if(targetErr){ modMsg.textContent = targetErr; return; }
  if(!confirmModeration("ban", target)) return;
  const mins=Number(modBanMins.value || 0);
  socket?.emit("mod ban", { username: target, minutes: mins, reason });
  modMsg.textContent="Ban sent.";
});
modUnmuteBtn.addEventListener("click", ()=>{
  const reason = (modReason.value || "").trim();
  const err=requireReason(reason);
  if(err){ modMsg.textContent=err; return; }
  const target = selectedModTarget();
  const targetErr = ensureTarget(target);
  if(targetErr){ modMsg.textContent = targetErr; return; }
  if(!confirmModeration("unmute", target)) return;
  socket?.emit("mod unmute", { username: target, reason });
  modMsg.textContent="Unmute sent.";
});
modUnbanBtn.addEventListener("click", ()=>{
  const reason = (modReason.value || "").trim();
  const err=requireReason(reason);
  if(err){ modMsg.textContent=err; return; }
  const target = selectedModTarget();
  const targetErr = ensureTarget(target);
  if(targetErr){ modMsg.textContent = targetErr; return; }
  if(!confirmModeration("unban", target)) return;
  socket?.emit("mod unban", { username: target, reason });
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
modSetRoleBtn.addEventListener("click", ()=>{
  const reason = (modReason.value || "").trim();
  const err=requireReason(reason);
  if(err){ modMsg.textContent=err; return; }
  const target = selectedModTarget();
  const targetErr = ensureTarget(target);
  if(targetErr){ modMsg.textContent = targetErr; return; }
  if(!modSetRole.value){ modMsg.textContent="Choose a role first."; return; }
  if(!confirmModeration("role update", target)) return;
  socket?.emit("mod set role", { username: target, role: modSetRole.value, reason });
  modMsg.textContent="Role change sent.";
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
async function startApp(){
  let meRes;
  try{
    meRes = await fetch("/me");
  }catch(err){
    console.error("Failed to reach /me:", err);
    authMsg.textContent = "Unable to reach the server. Please try again.";
    return;
  }

  if(!meRes?.ok){
    authMsg.textContent = "Please login.";
    return;
  }

  try{
    me = await meRes.json();
  }catch(err){
    console.error("Invalid /me response:", err);
    authMsg.textContent = "Server response was invalid. Please refresh and try again.";
    return;
  }

  if(!me){ authMsg.textContent="Please login."; return; }

  await loadThemePreference();

  authWrap.style.display="none";
  app.style.display="block";

  await loadMyProfile();
  await loadUserPrefs();
  await loadProgression();
  renderLevelProgress(progression, true);

  setRightPanelMode("rooms");
  setMenuTab(activeMenuTab);
  updateChangelogControlsVisibility();
  updateRoomControlsVisibility();

  socket = io();
  socket.on("connect", () => {
    // Join initial room so history + realtime messages work reliably
    joinRoom(currentRoom);
  });

  socket.on("onlineUsers", (names) => {
    onlineUsers = Array.isArray(names) ? names : [];
    updateIrisLolaTogetherClass();
  });
  socket.on("connect_error", (err) => {
  addSystem(`⚠️ Realtime connection failed: ${err?.message || err}`);
});

socket.on("disconnect", (reason) => {
  addSystem(`⚠️ Disconnected: ${reason}`);
});
  socket.on("rooms update", (rooms)=>renderRoomsList(rooms));
  socket.on("changelog updated", ()=>{
    changelogDirty = true;
    if(rightPanelMode === "menu" && activeMenuTab === "changelog") loadChangelog(true);
    loadLatestUpdateSnippet();
  });
  await loadRooms();
  await loadLatestUpdateSnippet();
  await loadDmThreads();

  // show Create Room button only for Co-owner+
  if(addRoomBtn){
    addRoomBtn.addEventListener("click", createRoomFlow);
  }
  updateRoomControlsVisibility();

  socket.on("system", addSystem);

  // Dice Room UI effects
  const diceOverlay = document.createElement("div");
  diceOverlay.id = "diceOverlay";
  diceOverlay.style.display = "none";
  const confettiLayer = document.createElement("div");
  confettiLayer.id = "confettiLayer";
  confettiLayer.style.display = "none";

  // attach overlays to chat area
  const chatMain = document.querySelector("main.chat") || document.getElementById("chatMain") || document.body;
  chatMain.style.position = chatMain.style.position || "relative";
  chatMain.appendChild(diceOverlay);
  chatMain.appendChild(confettiLayer);

  function showDiceAnimation(finalValue, won){
    const faces = ["⚀","⚁","⚂","⚃","⚄","⚅"];
    diceOverlay.style.display = "flex";
    diceOverlay.textContent = "🎲";
    let t = 0;
    const iv = setInterval(()=>{
      diceOverlay.textContent = faces[Math.floor(Math.random()*6)];
      t += 1;
      if (t >= 10){
        clearInterval(iv);
        diceOverlay.textContent = faces[finalValue-1] || "🎲";
        setTimeout(()=>{ diceOverlay.style.display="none"; }, 350);
        if (won) popConfetti();
      }
    }, 90);
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

  socket.on("dice:result", ({value, won}) => {
    showDiceAnimation(value, won);
    // refresh gold display if you already have a refresh_toggle function
    if (typeof refreshMe === "function") refreshMe();
  });
  socket.on("dice:error", (msg)=> addSystem(msg));
  socket.on("dice:rolled", ({value, won, username}) => {
    // show animation for other rollers too (nice-to-have)
    showDiceAnimation(value, won);
    if (username) noteDiceRoll(username, value);
  });

  socket.on("command response", handleCommandResponse);
  socket.on("user list", (users)=>renderMembers(users));
  socket.on("typing update", (names)=>{
    const others=(names||[]).filter(n=>n!==me.username);
    typingEl.textContent = others.length
      ? (others.length===1 ? `${others[0]} is typing...` : `${others.join(", ")} are typing...`)
      : "";
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
  socket.on("history", (history)=>{
    clearMsgs();
    (history||[]).forEach(m=>safeAddMessage(m));
    applySearch();
  });
  socket.on("chat message", (m)=>{
    safeAddMessage(m);
    applySearch();

    // Quiet sound cues (optional)
    try{
      const from = String(m?.username || "");
      const self = String(me?.username || "");
      if (from && self && from !== self) {
        const txt = String(m?.text || "");
        const mentioned = self && txt.toLowerCase().includes("@"+self.toLowerCase());
        if (mentioned && Sound.shouldMention()) Sound.cues.mention();
        else if (Sound.shouldRoom()) Sound.cues.room();
      }
    }catch{}
  });
    socket.on("reaction update", ({ messageId, reactions }) => {
    renderReactions(messageId, reactions);
  });

  socket.on("message deleted", ({ messageId }) => {
    const row = document.querySelector(`[data-mid="${messageId}"]`);
    if (row) row.remove();

    const idx = msgIndex.findIndex((x) => String(x.id) === String(messageId));
    if (idx !== -1) msgIndex.splice(idx, 1);

    closeReactionMenu();
  });

  socket.on("dm history", (payload) => {
    const { threadId, messages = [], participants = [], title = "" } = payload || {};
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
      dmUnreadThreads.delete(threadId);
      renderDmThreads();
    }
  });

  socket.on("dm history cleared", ({ threadId }) => {
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
        const mentioned = self && txt.toLowerCase().includes("@"+self.toLowerCase());
        if (mentioned && Sound.shouldMention()) Sound.cues.mention();
        else if (Sound.shouldDm()) Sound.cues.dm();
      }
    }catch{}


    if (!dmThreads.find((t) => String(t.id) === String(m.threadId))) loadDmThreads();

    if (String(activeDmId) !== String(m.threadId)) {
      markDmNotification(m.threadId, isGroupThread(m.threadId));
    }

    if (String(activeDmId) === String(m.threadId)) {
      renderDmMessages(m.threadId);
      markDmRead(m.threadId, m.ts || Date.now());
      dmUnreadThreads.delete(m.threadId);
      renderDmThreads();
    }
  } catch (err) {
    console.error("dm message handler failed", err, m);
  }
});

  socket.on("dm reaction update", ({ threadId, messageId, reactions }) => {
    // Keep cache even if the thread isn't open yet.
    const midKey = String(messageId);
    dmReactionsCache[midKey] = reactions || {};
    // Only render if the message is currently in the DOM.
    renderDmReactions(midKey, dmReactionsCache[midKey]);
  });

  socket.on("dm message deleted", ({ threadId, messageId }) => {
    const midKey = String(messageId);
    const row = document.querySelector(`[data-dm-mid="${midKey}"]`);
    if (row) row.remove();
    delete dmReactionsCache[midKey];

    // Remove from cached messages
    const tidKey = threadId;
    const arr = dmMessages.get(tidKey) || [];
    const idx = arr.findIndex((x) => String(x.messageId || x.id) === midKey);
    if (idx !== -1) {
      arr.splice(idx, 1);
      dmMessages.set(tidKey, arr);
    }

    if (String(activeDmId) === String(threadId)) {
      // Close any open action menus
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

// boot: if already logged in, auto start
(async function boot(){
  try{
    const res = await fetch("/me");
    if(!res.ok) return;

    me = await res.json();
    if(me){
      authWrap.style.display="none";
      app.style.display="block";
      await startApp();
    }
  }catch(err){
    console.warn("Skipping auto-start due to /me failure", err);
  }
})();

// profile button also closes drawers
profileBtn.addEventListener("click", () => { closeDrawers(); });

// close drawers when opening modal
modal.addEventListener("show", closeDrawers);



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
    return ["Iri", "Lola Henderson"].includes(currentUser?.username);
  }
  return true;
}

try{ syncDesktopMembersWidth(); }catch{}