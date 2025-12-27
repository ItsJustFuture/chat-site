// public/app.js
"use strict";

let socket = null;
let me = null;
let progression = { gold: 0, xp: 0, level: 1, xpIntoLevel: 0, xpForNextLevel: 100 };
let currentRoom = "main";
function displayRoomName(room){ return room==="diceroom" ? "Dice Room" : room; }

let lastUsers = [];
const reactionsCache = Object.create(null);
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
let levelToastTimer = null;
let rightPanelMode = "rooms";
let activeMenuTab = "changelog";
let changelogEntries = [];
let changelogLoaded = false;
let changelogDirty = false;
let editingChangelogId = null;
let latestChangelogEntry = null;

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
];
const DEFAULT_THEME = "Minimal Dark";
let currentTheme = document.body?.getAttribute("data-theme") || DEFAULT_THEME;
let themeFilter = "all";

let modalTargetUsername = null;
let pendingFile = null;
let uploadXhr = null;
let memberMenuUser = null;

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

const authUser = document.getElementById("authUser");
const authPass = document.getElementById("authPass");
const authMsg = document.getElementById("authMsg");
const loginBtn = document.getElementById("loginBtn");
const regBtn = document.getElementById("regBtn");

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

const fileInput = document.getElementById("fileInput");
const pickFileBtn = document.getElementById("pickFileBtn");

const meAvatar = document.getElementById("meAvatar");
const meName = document.getElementById("meName");
const meRole = document.getElementById("meRole");
const meStatusText = document.getElementById("meStatusText");
const statusSelect = document.getElementById("statusSelect");
const profileBtn = document.getElementById("profileBtn");

// dms
const dmPanel = document.getElementById("dmPanel");
const dmToggleBtn = document.getElementById("dmToggleBtn");
const groupDmToggleBtn = document.getElementById("groupDmToggleBtn");
const dmCloseBtn = document.getElementById("dmCloseBtn");
const dmThreadList = document.getElementById("dmThreadList");
const dmMsg = document.getElementById("dmMsg");
const dmMetaTitle = document.getElementById("dmMetaTitle");
const dmMetaPeople = document.getElementById("dmMetaPeople");
const dmMessagesEl = document.getElementById("dmMessages");
const dmText = document.getElementById("dmText");
const dmSendBtn = document.getElementById("dmSendBtn");
const dmUserBtn = document.getElementById("dmUserBtn");
const dmSettingsBtn = document.getElementById("dmSettingsBtn");
const dmSettingsMenu = document.getElementById("dmSettingsMenu");
const dmDeleteHistoryBtn = document.getElementById("dmDeleteHistoryBtn");
const dmReportBtn = document.getElementById("dmReportBtn");
const dmBgColor = document.getElementById("dmBgColor");
const dmBgColorText = document.getElementById("dmBgColorText");

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
const copyProfileLinkBtn = document.getElementById("copyProfileLinkBtn");
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
const dmBadgeDot = document.getElementById("dmBadgeDot");
const groupDmBadgeDot = document.getElementById("groupDmBadgeDot");

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

// member quick mod
const memberModTools = document.getElementById("memberModTools");
const quickReason = document.getElementById("quickReason");
const quickMuteMins = document.getElementById("quickMuteMins");
const quickBanMins = document.getElementById("quickBanMins");
const quickKickBtn = document.getElementById("quickKickBtn");
const quickMuteBtn = document.getElementById("quickMuteBtn");
const quickBanBtn = document.getElementById("quickBanBtn");
const quickModMsg = document.getElementById("quickModMsg");

// moderation panel
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
const modSetRole = document.getElementById("modSetRole");
const modSetRoleBtn = document.getElementById("modSetRoleBtn");
const modMsg = document.getElementById("modMsg");

// logs
const logUser = document.getElementById("logUser");
const logAction = document.getElementById("logAction");
const logLimit = document.getElementById("logLimit");
const refreshLogsBtn = document.getElementById("refreshLogsBtn");
const logsMsg = document.getElementById("logsMsg");
const logsBody = document.getElementById("logsBody");

// ---- helpers
function escapeHtml(s){
  return String(s).replace(/[&<>"']/g, m => ({
    "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#039;"
  }[m]));
}
function normKey(u){ return String(u||"").trim().toLowerCase(); }
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
function avatarNode(url, fallbackText){
  if(url){
    const img=document.createElement("img");
    img.src=url; img.alt="avatar";
    return img;
  }
  const wrap=document.createElement("div");
  wrap.style.width="100%";
  wrap.style.height="100%";
  wrap.style.display="flex";
  wrap.style.alignItems="center";
  wrap.style.justifyContent="center";
  wrap.style.fontWeight="900";
  wrap.style.background="var(--avatar-bg)";
  wrap.textContent=(fallbackText||"?").slice(0,1).toUpperCase();
  return wrap;
}

function clearMsgs(){
  msgs.innerHTML="";
  typingEl.textContent="";
  msgIndex.length=0;
}
function addSystem(text){
  const div=document.createElement("div");
  div.className="sys";
  div.textContent=text;
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

function applyMentions(text){
  const u = me?.username ? me.username.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') : null;
  if(!u) return escapeHtml(text);
  const re = new RegExp(`@${u}\\b`, "gi");
  return escapeHtml(text).replace(re, (m)=>`<span class="mention">${m}</span>`);
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
function applyTheme(themeName, { persist=true, silent=false } = {}){
  const safe = sanitizeThemeName(themeName || DEFAULT_THEME);
  currentTheme = safe;
  document.body?.setAttribute("data-theme", safe);
  setStoredTheme(safe);
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
  themeGrid.innerHTML = "";
  const filtered = THEME_LIST.filter((t) => {
    if(themeFilter === "dark") return t.mode === "Dark";
    if(themeFilter === "light") return t.mode === "Light";
    return true;
  });
  for(const theme of filtered){
    const card = document.createElement("button");
    card.type = "button";
    card.className = `themeCard${currentTheme === theme.name ? " selected" : ""}`;
    card.dataset.themeName = theme.name;
    card.innerHTML = `
      <div class="themeCardHeader">
        <div>
          <div class="themeLabel">${escapeHtml(theme.name)}</div>
          <div class="themeMode">${escapeHtml(theme.mode)}</div>
        </div>
        <div class="themeCheck">✓</div>
      </div>
    `;
    card.appendChild(createThemeThumbnail(theme.name));
    card.addEventListener("click", () => applyTheme(theme.name, { persist:true }));
    themeGrid.appendChild(card);
  }
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
  const meta = dmThreads.find((t) => t.id === threadId);
  return !!(meta?.is_group || meta?.isGroup);
}
function markDmNotification(threadId, isGroupHint){
  const isGroup = typeof isGroupHint === "boolean" ? isGroupHint : isGroupThread(threadId);
  if(dmPanel?.classList.contains("open") && activeDmId === threadId) return;
  setBadgeVisibility(isGroup ? "group" : "direct", true);
}
badgePrefs = loadBadgePrefsFromStorage();
applyBadgePrefs();
dmThemePrefs = loadDmThemePrefsFromStorage();
applyDmThemePrefs();
initCustomizationUi();
const EMOJI_CHOICES = ["😀","😁","😂","🙂","😉","😍","😘","💀","🤔","😤","😢","😡","🔥","🖕","♥️","💯","👍","👎","🎉","👀"];

let reactionMenuEl = null;
let reactionMenuFor = null;
let reactionMenuRow = null;

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
  reactionMenuFor = messageId;
  reactionMenuRow = rowEl;

  const grid = reactionMenuEl.querySelector(".reactionGrid");
  grid.innerHTML = "";

  for(const em of EMOJI_CHOICES){
    const b = document.createElement("button");
    b.type = "button";
    b.textContent = em;
    b.onclick = ()=>{
      socket?.emit("reaction", { messageId, emoji: em });
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

function closeReactionMenu(){
  if(!reactionMenuEl) return;
  reactionMenuEl.classList.remove("open");
  if(reactionMenuRow) reactionMenuRow.classList.remove("showActions");
  reactionMenuFor = null;
  reactionMenuRow = null;
}

function addMessage(m){
  const row = document.createElement("div");
  row.className = "msg" + (m.user === me.username ? " self" : "");
  row.dataset.mid = m.messageId;

  const av = document.createElement("div");
  av.className = "msgAvatar";
  av.appendChild(avatarNode(m.avatar, m.user));

  const main = document.createElement("div");
  main.className = "msgMain";

  const bubble = document.createElement("div");
  bubble.className = "bubble";

  const meta = document.createElement("div");
  meta.className = "metaLine";
  meta.innerHTML = `
    <span class="uName">${escapeHtml(roleIcon(m.role))} ${escapeHtml(m.user)}</span>
    <span class="badge" style="color:${roleBadgeColor(m.role)}">${escapeHtml(m.role)}</span>
    <span class="ts">${new Date(m.ts).toLocaleTimeString([], {hour:"2-digit", minute:"2-digit"})}</span>
  `;

  const text = document.createElement("div");
  text.className = "text";
  text.innerHTML = applyMentions(m.text);

  bubble.appendChild(meta);
  bubble.appendChild(text);

  if(m.attachmentUrl && m.attachmentType){
    const att=document.createElement("div");
    att.className="attachment";
    if(m.attachmentType==="image"){
      const img=document.createElement("img");
      img.src=m.attachmentUrl;
      img.alt="image";
      att.appendChild(img);
    }else if(m.attachmentType==="video"){
      const v=document.createElement("video");
      v.src=m.attachmentUrl;
      v.controls=true;
      v.playsInline=true;
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

  // mobile: long press bubble opens reaction menu
  let pressTimer = null;
  bubble.addEventListener("touchstart", ()=>{
    pressTimer = setTimeout(()=>{
      openReactionMenu(m.messageId, bubble, row);
    }, 450);
  }, {passive:true});
  bubble.addEventListener("touchend", ()=>{ clearTimeout(pressTimer); });
  bubble.addEventListener("touchcancel", ()=>{ clearTimeout(pressTimer); });

  row.appendChild(av);
  row.appendChild(main);
  row.appendChild(actions);

  msgs.appendChild(row);
  msgs.scrollTop = msgs.scrollHeight;

  msgIndex.push({ id: m.messageId, el: row, textLower: (m.user+" "+m.text).toLowerCase() });
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
    container.appendChild(pill);
  });
}

function closeMemberMenu(){
  if (!memberMenu) return;
  memberMenu.classList.remove("open");
  memberMenuUser = null;
}

function openMemberMenu(user, anchor){
  if (!memberMenu || !membersPane) {
    openMemberProfile(user.name);
    return;
  }

  memberMenuUser = user;
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
  } else {
    memberGold.classList.remove("show");
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

function renderMembers(users){
  lastUsers = users || [];
  memberList.innerHTML="";
  lastUsers.forEach(u=>{
    const row=document.createElement("div");
    row.className="mItem";
    row.dataset.username = u.name;

    const av=document.createElement("div");
    av.className="mAvatar";
    av.appendChild(avatarNode(u.avatar, u.name));

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
function closeDrawers(){
  channelsPane?.classList.remove("open");
  membersPane?.classList.remove("open");
  drawerOverlay?.classList.remove("show");
  closeMemberMenu();
}
function openChannels(){
  membersPane?.classList.remove("open");
  channelsPane?.classList.add("open");
  drawerOverlay?.classList.add("show");
}
function openMembers(){
  channelsPane?.classList.remove("open");
  membersPane?.classList.add("open");
  drawerOverlay?.classList.add("show");
}
openChannelsBtn?.addEventListener("click", openChannels);
openMembersBtn?.addEventListener("click", openMembers);
drawerOverlay?.addEventListener("click", closeDrawers);
document.addEventListener("keydown", (e)=>{ if(e.key==="Escape") closeDrawers(); });

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

function renderThreadItem(t){
  const div = document.createElement("div");
  div.className = "dmItem" + (t.id === activeDmId ? " active" : "");
  const label = threadLabel(t);
  const preview = t.last_text ? String(t.last_text).slice(0, 80) : "No messages yet";
  div.innerHTML = `
    <div class="name">${escapeHtml(label)}</div>
    <div class="small">${escapeHtml(preview)}</div>
  `;
  div.onclick = () => openDmThread(t.id);
  return div;
}

function renderDmThreads(){
  dmThreadList.innerHTML = "";

  const sections = [
    {
      title: "Direct messages",
      emptyText: "No direct messages yet. Start one from Members.",
      items: dmThreads.filter((t) => !t.is_group)
    },
    {
      title: "Group chats",
      emptyText: "No group chats yet.",
      items: dmThreads.filter((t) => t.is_group)
    }
  ];

  for (const section of sections) {
    const head = document.createElement("div");
    head.className = "dmSectionTitle";
    head.textContent = section.title;
    dmThreadList.appendChild(head);

    if (!section.items.length) {
      const empty = document.createElement("div");
      empty.className = "dmEmpty";
      empty.textContent = section.emptyText;
      dmThreadList.appendChild(empty);
      continue;
    }

    for (const t of section.items) dmThreadList.appendChild(renderThreadItem(t));
  }
}

async function loadDmThreads(){
  try {
    const res = await fetch("/dm/threads");
    if (!res.ok) {
      dmMsg.textContent = "Could not load threads.";
      return;
    }
    const raw = await res.json();
    dmThreads = (raw || []).map((t) => ({ ...t, is_group: !!t.is_group }));
    renderDmThreads();
  } catch {
    dmMsg.textContent = "Could not load threads.";
  }
}

async function startDirectMessage(username){
  if (!username || username === me?.username) return;

  openDmPanel();
  closeMemberMenu();

  if (!dmThreads.length) await loadDmThreads();

  const existing = dmThreads.find((t) => !t.is_group && (t.participants || []).includes(username));
  if (existing) {
    openDmThread(existing.id);
    return;
  }

  dmMsg.textContent = "Preparing chat...";
  try {
    const res = await fetch("/dm/thread", {
      method: "POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify({ participants: [username], kind: "direct" })
    });

    if (!res.ok) {
      const text = await res.text();
      dmMsg.textContent = text || "Could not start DM.";
      return;
    }

    const data = await res.json();
    dmMsg.textContent = data.reused ? "Opened existing DM." : "DM ready. Send a message to save it.";

    if (data.threadId) {
      upsertThreadMeta(data.threadId, { participants: [username, me?.username].filter(Boolean), is_group: false });
      openDmThread(data.threadId);
    }
  } catch {
    dmMsg.textContent = "Could not start DM.";
  }
}

function openDmPanel(){
  dmPanel.classList.add("open");
  dmMsg.textContent = "";
  clearDmBadges();

  // load threads if we haven't yet
  if (!dmThreads.length) loadDmThreads();
  else renderDmThreads();
}

function closeDmPanel(){
  dmPanel.classList.remove("open");
  closeDmSettingsMenu();
}

function renderDmMessages(threadId){
  dmMessagesEl.innerHTML = "";
  const msgsArr = dmMessages.get(threadId) || [];

  if (!msgsArr.length) {
    const empty = document.createElement("div");
    empty.className = "dmEmpty";
    empty.textContent = "No messages yet. Say hi to save this thread.";
    dmMessagesEl.appendChild(empty);
    return;
  }

  for (const m of msgsArr) {
    const wrap = document.createElement("div");
    wrap.className = "dmBubble" + (m.user === me.username ? " self" : "");

    const meta = document.createElement("div");
    meta.className = "dmMetaRow";
    meta.innerHTML = `<span>${escapeHtml(m.user)}</span><span>${new Date(m.ts).toLocaleTimeString([], {hour:"2-digit", minute:"2-digit"})}</span>`;
    wrap.appendChild(meta);

    const text = document.createElement("div");
    text.innerHTML = applyMentions(m.text || "");
    wrap.appendChild(text);

    dmMessagesEl.appendChild(wrap);
  }

  dmMessagesEl.scrollTop = dmMessagesEl.scrollHeight;
}

function setDmMeta(thread){
  if (!thread) {
    dmMetaTitle.textContent = "Pick a thread";
    dmMetaPeople.textContent = "";
    return;
  }
  dmMetaTitle.textContent = threadLabel(thread);
  dmMetaPeople.textContent = (thread.participants || []).join(", ");
}

function openDmThread(threadId){
  activeDmId = threadId;
  renderDmThreads();

  const meta = dmThreads.find(t => t.id === threadId);
  setDmMeta(meta);
  if (meta) setBadgeVisibility(meta.is_group ? "group" : "direct", false);

  dmMessagesEl.innerHTML = "<div class='dmEmpty'>Loading...</div>";
  socket?.emit("dm join", { threadId });
}

async function deleteDmHistory(){
  if (!activeDmId) {
    dmMsg.textContent = "Pick a thread first.";
    return;
  }

  const meta = dmThreads.find((t) => t.id === activeDmId);
  const label = meta ? threadLabel(meta) : "this DM";
  const ok = confirm(`Delete all messages in "${label}" for everyone?`);
  if (!ok) return;

  dmMsg.textContent = "Deleting history...";
  try {
    const res = await fetch(`/dm/thread/${activeDmId}/messages`, { method: "DELETE" });
    if (!res.ok) {
      const text = await res.text();
      dmMsg.textContent = text || "Could not delete history.";
      return;
    }

    dmMessages.set(activeDmId, []);
    const thread = dmThreads.find((t) => t.id === activeDmId);
    if (thread) {
      thread.last_text = "";
      thread.last_ts = null;
    }
    renderDmMessages(activeDmId);
    renderDmThreads();
    dmMsg.textContent = "History cleared.";
    closeDmSettingsMenu();
  } catch {
    dmMsg.textContent = "Could not delete history.";
  }
}

function upsertThreadMeta(tid, updater){
  const idx = dmThreads.findIndex(t => t.id === tid);
  if (idx === -1) dmThreads.unshift({ id: tid, participants: [], ...updater });
  else dmThreads[idx] = { ...dmThreads[idx], ...updater };
  renderDmThreads();
}

function sendDmMessage(){
  if (!activeDmId) return;
  const txt = dmText.value.trim();
  if (!txt) return;
  socket?.emit("dm message", { threadId: activeDmId, text: txt });
  dmText.value = "";
}

dmToggleBtn?.addEventListener("click", openDmPanel);
groupDmToggleBtn?.addEventListener("click", openDmPanel);

dmCloseBtn?.addEventListener("click", closeDmPanel);
dmSendBtn?.addEventListener("click", sendDmMessage);
dmSettingsBtn?.addEventListener("click", (e) => {
  e.stopPropagation();
  toggleDmSettingsMenu();
});
dmDeleteHistoryBtn?.addEventListener("click", deleteDmHistory);
dmReportBtn?.addEventListener("click", () => {
  dmMsg.textContent = "Report feature coming soon.";
  closeDmSettingsMenu();
});

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
  if (memberMenuUser) openMemberProfile(memberMenuUser.name);
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

dmText?.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey) {
    e.preventDefault();
    sendDmMessage();
  }
});

// "Message" button on profile -> always direct DM
dmUserBtn?.addEventListener("click", () => {
  if (modalTargetUsername) {
    closeModal();
    startDirectMessage(modalTargetUsername);
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
  const active=document.querySelector(".tab.active");
  active?.scrollIntoView({ behavior:"smooth", inline:"center", block:"nearest" });
}
function setTab(tab){
  for(const el of document.querySelectorAll(".tab")){
    el.classList.toggle("active", el.dataset.tab===tab);
  }
  viewInfo.style.display = tab==="info" ? "block" : "none";
  viewAbout.style.display = tab==="about" ? "block" : "none";
  viewCustomize.style.display = tab==="customize" ? "block" : "none";
  viewModeration.style.display = tab==="moderation" ? "block" : "none";
  focusActiveTab();
}
tabInfo.addEventListener("click", ()=>setTab("info"));
tabAbout.addEventListener("click", ()=>setTab("about"));
tabCustomize.addEventListener("click", ()=>setTab("customize"));
tabModeration.addEventListener("click", async ()=>{
  setTab("moderation");
  await refreshLogs();
});

// modal open/close
function openModal(){ modal.style.display="flex"; }
function closeModal(){
  modal.style.display="none";
  modalTargetUsername=null;
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
    meta.textContent = entry.createdAt ? new Date(entry.createdAt).toLocaleString() : "";

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
  renderLatestUpdateSnippet();
}

function renderLatestUpdateSnippet(){
  if(!latestUpdate) return;
  if(!latestChangelogEntry){
    latestUpdate.style.display = "none";
    return;
  }
  latestUpdate.style.display = "block";
  if(latestUpdateTitle) latestUpdateTitle.textContent = latestChangelogEntry.title || "(untitled)";
  if(latestUpdateDate) latestUpdateDate.textContent = latestChangelogEntry.createdAt ? new Date(latestChangelogEntry.createdAt).toLocaleString() : "";
  if(latestUpdateBody) latestUpdateBody.textContent = previewText(latestChangelogEntry.body || "", 200);
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
if(latestUpdateViewBtn){
  latestUpdateViewBtn.addEventListener("click", ()=>{
    setMenuTab("changelog");
    setRightPanelMode("menu");
    menuPanel?.scrollTo({ top:0, behavior:"smooth" });
  });
}
if(changelogNewBtn) changelogNewBtn.addEventListener("click", ()=>openChangelogEditor());
if(changelogCancelBtn) changelogCancelBtn.addEventListener("click", closeChangelogEditor);
if(changelogSaveBtn) changelogSaveBtn.addEventListener("click", saveChangelogEntry);
closeChangelogEditor();

// typing/send
let typingDebounce=null;
function emitTyping(){
  if(!socket) return;
  socket.emit("typing");
  clearTimeout(typingDebounce);
  typingDebounce=setTimeout(()=>socket.emit("stop typing"), 900);
}
msgInput.addEventListener("input", emitTyping);
msgInput.addEventListener("keydown",(e)=>{
  if(e.key==="Enter"){ e.preventDefault(); sendMessage(); }
});
sendBtn.addEventListener("click", sendMessage);

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
      attachmentUrl: attachment?.url || "",
      attachmentType: attachment?.type || "",
      attachmentMime: attachment?.mime || "",
      attachmentSize: attachment?.size || 0
    });

    msgInput.value="";
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

// ---- profiles
async function loadMyProfile(){
  const res=await fetch("/profile");
  if(!res.ok) return;
  const p=await res.json();
  me.username = p.username;
  me.role = p.role;
  me.level = p.level || me.level;

  applyProgressionPayload(p);

  meName.textContent=p.username;
  meRole.textContent=`${roleIcon(p.role)} ${p.role}`;
  meAvatar.innerHTML="";
  meAvatar.appendChild(avatarNode(p.avatar, p.username));
  renderLevelProgress(progression, true);
}

function fillProfileUI(p, isSelf){
  modalAvatar.innerHTML="";
  modalAvatar.appendChild(avatarNode(p.avatar, p.username));
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
}
function syncCustomizationUI(){
  badgePrefs = loadBadgePrefsFromStorage();
  applyBadgePrefs();
  if (customizeMsg) customizeMsg.textContent = "";
}

async function openMyProfile(){
  closeDrawers();
  const res=await fetch("/profile");
  if(!res.ok) return;
  const p=await res.json();
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
  const isSelf = !!me && normKey(me.username) === normKey(p.username);
  if (isSelf) applyProgressionPayload(p);

  modalTitle.textContent="Member Profile";
  modalMeta.textContent = p.created_at ? `Created: ${fmtCreated(p.created_at)}` : "";
  fillProfileUI(p, isSelf);
  syncCustomizationUI();

  myProfileEdit.style.display="none";

  const iCanMod = (roleRank(me.role) >= roleRank("Moderator")) && (roleRank(me.role) > roleRank(p.role));
  memberModTools.style.display = iCanMod ? "block" : "none";
  quickReason.value=""; quickMuteMins.value=""; quickBanMins.value=""; quickModMsg.textContent="";

  tabModeration.style.display = (roleRank(me.role) >= roleRank("Moderator")) ? "block" : "none";
  setTab("info");
  openModal();
}

// media actions
copyUsernameBtn.addEventListener("click", async ()=>{
  const u = modalTargetUsername || me?.username || "";
  try{ await navigator.clipboard.writeText(u); mediaMsg.textContent="Copied username."; }
  catch{ mediaMsg.textContent="Copy failed (browser blocked)."; }
});
copyProfileLinkBtn.addEventListener("click", async ()=>{
  const u = modalTargetUsername || me?.username || "";
  const link = `${location.origin}/#profile:${encodeURIComponent(u)}`;
  try{ await navigator.clipboard.writeText(link); mediaMsg.textContent="Copied profile link."; }
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
  if(!reason || !reason.trim()) return "Reason is required.";
  if(reason.trim().length < 3) return "Reason must be at least 3 characters.";
  return null;
}
quickKickBtn.addEventListener("click", ()=>{
  const err=requireReason(quickReason.value);
  if(err){ quickModMsg.textContent=err; return; }
  socket?.emit("mod kick", { username: modalTargetUsername });
  quickModMsg.textContent="Kick sent.";
});
quickMuteBtn.addEventListener("click", ()=>{
  const err=requireReason(quickReason.value);
  if(err){ quickModMsg.textContent=err; return; }
  const mins=Number(quickMuteMins.value || 10);
  socket?.emit("mod mute", { username: modalTargetUsername, minutes: mins, reason: quickReason.value.trim() });
  quickModMsg.textContent="Mute sent.";
});
quickBanBtn.addEventListener("click", ()=>{
  const err=requireReason(quickReason.value);
  if(err){ quickModMsg.textContent=err; return; }
  const mins=Number(quickBanMins.value || 0);
  socket?.emit("mod ban", { username: modalTargetUsername, minutes: mins, reason: quickReason.value.trim() });
  quickModMsg.textContent="Ban sent.";
});

// mod panel
modKickBtn.addEventListener("click", ()=>{
  const err=requireReason(modReason.value);
  if(err){ modMsg.textContent=err; return; }
  if(!modUser.value.trim()){ modMsg.textContent="Enter a target username."; return; }
  socket?.emit("mod kick", { username: modUser.value.trim() });
  modMsg.textContent="Kick sent.";
});
modMuteBtn.addEventListener("click", ()=>{
  const err=requireReason(modReason.value);
  if(err){ modMsg.textContent=err; return; }
  if(!modUser.value.trim()){ modMsg.textContent="Enter a target username."; return; }
  const mins=Number(modMuteMins.value || 10);
  socket?.emit("mod mute", { username: modUser.value.trim(), minutes: mins, reason: modReason.value.trim() });
  modMsg.textContent="Mute sent.";
});
modBanBtn.addEventListener("click", ()=>{
  const err=requireReason(modReason.value);
  if(err){ modMsg.textContent=err; return; }
  if(!modUser.value.trim()){ modMsg.textContent="Enter a target username."; return; }
  const mins=Number(modBanMins.value || 0);
  socket?.emit("mod ban", { username: modUser.value.trim(), minutes: mins, reason: modReason.value.trim() });
  modMsg.textContent="Ban sent.";
});
modUnmuteBtn.addEventListener("click", ()=>{
  const err=requireReason(modReason.value);
  if(err){ modMsg.textContent=err; return; }
  if(!modUser.value.trim()){ modMsg.textContent="Enter a target username."; return; }
  socket?.emit("mod unmute", { username: modUser.value.trim(), reason: modReason.value.trim() });
  modMsg.textContent="Unmute sent.";
});
modUnbanBtn.addEventListener("click", ()=>{
  const err=requireReason(modReason.value);
  if(err){ modMsg.textContent=err; return; }
  if(!modUser.value.trim()){ modMsg.textContent="Enter a target username."; return; }
  socket?.emit("mod unban", { username: modUser.value.trim(), reason: modReason.value.trim() });
  modMsg.textContent="Unban sent.";
});
modWarnBtn.addEventListener("click", ()=>{
  const err=requireReason(modReason.value);
  if(err){ modMsg.textContent=err; return; }
  if(!modUser.value.trim()){ modMsg.textContent="Enter a target username."; return; }
  socket?.emit("mod warn", { username: modUser.value.trim(), reason: modReason.value.trim() });
  modMsg.textContent="Warn sent.";
});
modOpenProfileBtn.addEventListener("click", async ()=>{
  if(!modUser.value.trim()){ modMsg.textContent="Enter a target username."; return; }
  await openMemberProfile(modUser.value.trim());
});
modSetRoleBtn.addEventListener("click", ()=>{
  const err=requireReason(modReason.value);
  if(err){ modMsg.textContent=err; return; }
  if(!modUser.value.trim()){ modMsg.textContent="Enter a target username."; return; }
  if(!modSetRole.value){ modMsg.textContent="Choose a role first."; return; }
  socket?.emit("mod set role", { username: modUser.value.trim(), role: modSetRole.value, reason: modReason.value.trim() });
  modMsg.textContent="Role change sent (Owner only).";
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
  await loadProgression();
  renderLevelProgress(progression, true);

  setRightPanelMode("rooms");
  setMenuTab(activeMenuTab);
  updateChangelogControlsVisibility();
  updateRoomControlsVisibility();

  socket = io();
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
  socket.on("dice:rolled", ({value, won}) => {
    // show animation for other rollers too (nice-to-have)
    showDiceAnimation(value, won);
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
  socket.on("history", (history)=>{
    clearMsgs();
    (history||[]).forEach(m=>addMessage(m));
    applySearch();
  });
  socket.on("chat message", (m)=>{
    addMessage(m);
    applySearch();
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
      : (dmThreads.find((t) => t.id === threadId)?.last_text || "");

    const lastTs = messages.length
      ? messages[messages.length - 1].ts
      : (dmThreads.find((t) => t.id === threadId)?.last_ts || Date.now());

    upsertThreadMeta(threadId, {
      participants,
      title,
      last_text: lastText,
      last_ts: lastTs,
      is_group: !!payload?.isGroup,
    });

    dmMessages.set(threadId, messages);
    renderDmThreads();

    if (activeDmId === threadId) {
      setDmMeta(dmThreads.find((t) => t.id === threadId));
      renderDmMessages(threadId);
    }
  });

  socket.on("dm history cleared", ({ threadId }) => {
    if (!threadId) return;
    dmMessages.set(threadId, []);
    const meta = dmThreads.find((t) => t.id === threadId);
    if (meta) {
      meta.last_text = "";
      meta.last_ts = null;
    }
    if (activeDmId === threadId) {
      renderDmMessages(threadId);
      dmMsg.textContent = "History was cleared.";
    }
    renderDmThreads();
  });

  socket.on("dm message", (m) => {
    const arr = dmMessages.get(m.threadId) || [];
    arr.push(m);
    dmMessages.set(m.threadId, arr);

    upsertThreadMeta(m.threadId, { last_text: m.text || "", last_ts: m.ts });

    if (!dmThreads.find((t) => t.id === m.threadId)) loadDmThreads();

    if (activeDmId !== m.threadId) {
      markDmNotification(m.threadId, isGroupThread(m.threadId));
    }

    if (activeDmId === m.threadId) {
      renderDmMessages(m.threadId);
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

// focus behavior on mobile keyboard
msgInput.addEventListener("focus", () => {
  setTimeout(() => msgInput.scrollIntoView({ block: "center", behavior: "smooth" }), 150);
});
