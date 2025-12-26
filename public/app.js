// public/app.js
"use strict";

let socket = null;
let me = null;
let currentRoom = "main";
let lastUsers = [];
const reactionsCache = Object.create(null);
const msgIndex = [];
let dmThreads = [];
let activeDmId = null;
const dmMessages = new Map();

let modalTargetUsername = null;
let pendingFile = null;
let uploadXhr = null;

// ---- DOM
const authWrap = document.getElementById("authWrap");
const app = document.getElementById("app");

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
const dmModeLabel = document.getElementById("dmModeLabel");
const dmCloseBtn = document.getElementById("dmCloseBtn");
const dmRefreshBtn = document.getElementById("dmRefreshBtn");
const dmThreadList = document.getElementById("dmThreadList");
const dmParticipantsInput = document.getElementById("dmParticipants");
const dmTitleInput = document.getElementById("dmTitle");
const dmCreateBtn = document.getElementById("dmCreateBtn");
const dmMsg = document.getElementById("dmMsg");
const dmMetaTitle = document.getElementById("dmMetaTitle");
const dmMetaPeople = document.getElementById("dmMetaPeople");
const dmMessagesEl = document.getElementById("dmMessages");
const dmText = document.getElementById("dmText");
const dmSendBtn = document.getElementById("dmSendBtn");
const dmUserBtn = document.getElementById("dmUserBtn");

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
const tabMedia = document.getElementById("tabMedia");
const tabModeration = document.getElementById("tabModeration");

const viewInfo = document.getElementById("viewInfo");
const viewAbout = document.getElementById("viewAbout");
const viewMedia = document.getElementById("viewMedia");
const viewModeration = document.getElementById("viewModeration");

const bioRender = document.getElementById("bioRender");
const copyProfileLinkBtn = document.getElementById("copyProfileLinkBtn");
const copyUsernameBtn = document.getElementById("copyUsernameBtn");
const mediaMsg = document.getElementById("mediaMsg");

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

const ROLES = ["Guest","User","VIP","Moderator","Admin","Co-owner","Owner"];
function roleRank(role){ const i=ROLES.indexOf(role); return i===-1?1:i; }

function statusDotColor(status){
  switch(status){
    case "Online": return "var(--ok)";
    case "Away": return "var(--warn)";
    case "Busy": return "var(--danger)";
    case "Do Not Disturb": return "var(--danger)";
    case "Idle": return "var(--gray)";
    case "Invisible": return "var(--gray)";
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
  wrap.style.background="#444";
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

function addMessage(m){
  const wrap=document.createElement("div");
  wrap.className="msg"+(m.user===me.username?" self":"");
  wrap.dataset.mid=m.messageId;

  const av=document.createElement("div");
  av.className="msgAvatar";
  av.appendChild(avatarNode(m.avatar, m.user));

  const bubble=document.createElement("div");
  bubble.className="bubble";

  const meta=document.createElement("div");
  meta.className="metaLine";
  meta.innerHTML = `
    <span class="uName">${escapeHtml(roleIcon(m.role))} ${escapeHtml(m.user)}</span>
    <span class="badge" style="color:${roleBadgeColor(m.role)}">${escapeHtml(m.role)}</span>
    <span class="ts">${new Date(m.ts).toLocaleTimeString([], {hour:"2-digit", minute:"2-digit"})}</span>
  `;

  const text=document.createElement("div");
  text.className="text";
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

  const actions=document.createElement("div");
  actions.className="actions";
  const emojis=["😀","😂","🔥","❤️","👍"];
  for(const e of emojis){
    const b=document.createElement("button");
    b.className="reactBtn";
    b.textContent=e;
    b.onclick=()=>socket?.emit("reaction",{messageId:m.messageId, emoji:e});
    actions.appendChild(b);
  }
  if(roleRank(me.role) >= roleRank("Moderator")){
    const del=document.createElement("button");
    del.className="reactBtn";
    del.textContent="🗑️";
    del.title="Delete message";
    del.onclick=()=>socket?.emit("mod delete message",{messageId:m.messageId});
    actions.appendChild(del);
  }
  bubble.appendChild(actions);

  const reacts=document.createElement("div");
  reacts.className="reactions";
  reacts.id="reacts-"+m.messageId;
  bubble.appendChild(reacts);

  wrap.appendChild(av);
  wrap.appendChild(bubble);

  msgs.appendChild(wrap);
  msgs.scrollTop=msgs.scrollHeight;

  msgIndex.push({ id: m.messageId, el: wrap, textLower: (m.user+" "+m.text).toLowerCase() });
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
    dot.style.background=statusDotColor(u.status);

    const meta=document.createElement("div");
    meta.className="mMeta";

    const name=document.createElement("div");
    name.className="mName";
    name.textContent=`${roleIcon(u.role)} ${u.name}`;

    const sub=document.createElement("div");
    sub.className="mSub";
    sub.textContent=`${u.role} • ${u.status}${u.mood?(" • "+u.mood):""}`;

    meta.appendChild(name);
    meta.appendChild(sub);

    row.appendChild(av);
    row.appendChild(dot);
    row.appendChild(meta);

    row.onclick = () => openMemberProfile(u.name);
    memberList.appendChild(row);
  });
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
let dmCreateMode = "direct"; // "direct" | "group"

function setDmCreateMode(mode){
  dmCreateMode = (mode === "group") ? "group" : "direct";

  // style + label
  dmPanel?.querySelector(".dmCreate")?.classList.toggle("direct", dmCreateMode === "direct");
  dmPanel?.querySelector(".dmCreate")?.classList.toggle("group", dmCreateMode === "group");

  if (dmModeLabel) dmModeLabel.textContent = `Mode: ${dmCreateMode === "group" ? "Group Chat" : "Direct Message"}`;

  // button text hint
  if (dmCreateBtn) dmCreateBtn.textContent = dmCreateMode === "group" ? "Start group chat" : "Start DM";

  // placeholder hints
  if (dmParticipantsInput) {
    dmParticipantsInput.placeholder = dmCreateMode === "group"
      ? "Add people (comma separated)"
      : "Add one person (username)";
  }

  // if switching to direct, clear title
  if (dmCreateMode === "direct" && dmTitleInput) dmTitleInput.value = "";
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

  if (!dmThreads.length) {
    dmThreadList.innerHTML = `<div class="dmEmpty">No conversations yet.</div>`;
    return;
  }

  const direct = dmThreads.filter(t => !t.is_group);
  const groups = dmThreads.filter(t => !!t.is_group);

  const addSection = (title, items, emptyText) => {
    const head = document.createElement("div");
    head.className = "dmSectionTitle";
    head.textContent = title;
    dmThreadList.appendChild(head);

    if (!items.length) {
      const empty = document.createElement("div");
      empty.className = "dmEmpty";
      empty.textContent = emptyText;
      dmThreadList.appendChild(empty);
      return;
    }

    for (const t of items) dmThreadList.appendChild(renderThreadItem(t));
  };

  addSection("Direct messages", direct, "No direct messages yet.");
  addSection("Group chats", groups, "No group chats yet.");
}

async function loadDmThreads(){
  try {
    const res = await fetch("/dm/threads");
    if (!res.ok) {
      dmMsg.textContent = "Could not load threads.";
      return;
    }
    dmThreads = await res.json();
    renderDmThreads();
  } catch {
    dmMsg.textContent = "Could not load threads.";
  }
}

function openDmPanel({ mode = "direct", prefill = "" } = {}){
  dmPanel.classList.add("open");
  dmMsg.textContent = "";

  setDmCreateMode(mode);

  if (prefill && dmParticipantsInput) dmParticipantsInput.value = prefill;

  // load threads if we haven't yet
  if (!dmThreads.length) loadDmThreads();
}

function closeDmPanel(){
  dmPanel.classList.remove("open");
}

function renderDmMessages(threadId){
  dmMessagesEl.innerHTML = "";
  const msgsArr = dmMessages.get(threadId) || [];

  if (!msgsArr.length) {
    const empty = document.createElement("div");
    empty.className = "dmEmpty";
    empty.textContent = "No messages yet.";
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

  dmMessagesEl.innerHTML = "<div class='dmEmpty'>Loading...</div>";
  socket?.emit("dm join", { threadId });
}

function upsertThreadMeta(tid, updater){
  const idx = dmThreads.findIndex(t => t.id === tid);
  if (idx === -1) dmThreads.unshift({ id: tid, participants: [], ...updater });
  else dmThreads[idx] = { ...dmThreads[idx], ...updater };
  renderDmThreads();
}

async function createDmThread(){
  dmMsg.textContent = "Creating...";

  const namesRaw = dmParticipantsInput.value.trim();
  const title = dmTitleInput.value.trim();

  if (!namesRaw) {
    dmMsg.textContent = dmCreateMode === "group"
      ? "Add at least two usernames (comma separated)."
      : "Add one username.";
    return;
  }

  const names = namesRaw.split(",").map(s => s.trim()).filter(Boolean);

  // client-side enforcement
  if (dmCreateMode === "direct" && names.length !== 1) {
    dmMsg.textContent = "Direct messages must have exactly 1 participant.";
    return;
  }
  if (dmCreateMode === "group" && names.length < 2 && !title) {
    dmMsg.textContent = "Group chats need 2+ participants (or a title).";
    return;
  }

  try {
    const res = await fetch("/dm/thread", {
      method: "POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify({
        participants: names,
        title,
        kind: dmCreateMode
      })
    });

    if (!res.ok) {
      const text = await res.text();
      dmMsg.textContent = text || "Could not create.";
      return;
    }

    const data = await res.json();
    dmMsg.textContent = data.reused ? "Opened existing DM." : "Thread created.";

    // reset fields
    dmParticipantsInput.value = "";
    dmTitleInput.value = "";

    await loadDmThreads();
    if (data.threadId) openDmThread(data.threadId);
  } catch {
    dmMsg.textContent = "Could not create.";
  }
}

function sendDmMessage(){
  if (!activeDmId) return;
  const txt = dmText.value.trim();
  if (!txt) return;
  socket?.emit("dm message", { threadId: activeDmId, text: txt });
  dmText.value = "";
}

dmToggleBtn?.addEventListener("click", () => openDmPanel({ mode: "direct" }));
groupDmToggleBtn?.addEventListener("click", () => openDmPanel({ mode: "group" }));

dmCloseBtn?.addEventListener("click", closeDmPanel);
dmRefreshBtn?.addEventListener("click", loadDmThreads);
dmCreateBtn?.addEventListener("click", createDmThread);
dmSendBtn?.addEventListener("click", sendDmMessage);

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
    openDmPanel({ mode: "direct", prefill: modalTargetUsername });
  }
});

// upload button icon -> open file picker
pickFileBtn?.addEventListener("click", () => fileInput.click());

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
  viewMedia.style.display = tab==="media" ? "block" : "none";
  viewModeration.style.display = tab==="moderation" ? "block" : "none";
  focusActiveTab();
}
tabInfo.addEventListener("click", ()=>setTab("info"));
tabAbout.addEventListener("click", ()=>setTab("about"));
tabMedia.addEventListener("click", ()=>setTab("media"));
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
}
closeModalBtn.addEventListener("click", closeModal);
modal.addEventListener("click", (e)=>{ if(e.target===modal) closeModal(); });

// rooms
function setActiveRoom(room){
  currentRoom=room;
  nowRoom.textContent=`#${room}`;
  roomTitle.textContent=room;
  msgInput.placeholder=`Message #${room}`;
  document.querySelectorAll(".chan").forEach(el=>{
    el.classList.toggle("active", el.dataset.room===room);
  });
}
function joinRoom(room){
  setActiveRoom(room);
  clearMsgs();
  socket?.emit("join room", { room, status: statusSelect.value || "Online" });
  closeDrawers();
}
chanList.addEventListener("click", (e)=>{
  const el=e.target.closest(".chan");
  if(!el) return;
  const r=el.dataset.room;
  if(r && r!==currentRoom) joinRoom(r);
});

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
    statusSelect.value=lastNonIdleStatus;
    socket?.emit("status change",{status:statusSelect.value});
  }
  clearTimeout(idleTimer);
  idleTimer=setTimeout(()=>{
    if(statusSelect.value!=="Idle"){
      lastNonIdleStatus=statusSelect.value;
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
  if(statusSelect.value!=="Idle") lastNonIdleStatus=statusSelect.value;
  socket?.emit("status change", {status: statusSelect.value});
  meStatusText.textContent = statusSelect.value;
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

  meName.textContent=p.username;
  meRole.textContent=`${roleIcon(p.role)} ${p.role}`;
  meAvatar.innerHTML="";
  meAvatar.appendChild(avatarNode(p.avatar, p.username));
}

function fillProfileUI(p){
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
  infoStatus.textContent = p.last_status || "—";

  bioRender.innerHTML = p.bio ? renderBBCode(p.bio) : "(no bio)";
}

async function openMyProfile(){
  closeDrawers();
  const res=await fetch("/profile");
  if(!res.ok) return;
  const p=await res.json();

  modalTitle.textContent="My Profile";
  modalMeta.textContent = p.created_at ? `Created: ${fmtCreated(p.created_at)}` : "";

  fillProfileUI(p);

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
  socket?.emit("join room", { room: currentRoom, status: statusSelect.value || "Online" });
  await openMyProfile();
});
refreshProfileBtn.addEventListener("click", openMyProfile);

async function openMemberProfile(username){
  modalTargetUsername = username;
  closeDrawers();

  const res=await fetch("/profile/" + encodeURIComponent(username));
  if(!res.ok) return;
  const p=await res.json();

  modalTitle.textContent="Member Profile";
  modalMeta.textContent = p.created_at ? `Created: ${fmtCreated(p.created_at)}` : "";
  fillProfileUI(p);

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
  const meRes = await fetch("/me");
  me = await meRes.json();
  if(!me){ authMsg.textContent="Please login."; return; }

  authWrap.style.display="none";
  app.style.display="block";

  await loadMyProfile();

  socket = io();

  socket.on("system", addSystem);
  socket.on("user list", (users)=>renderMembers(users));
  socket.on("typing update", (names)=>{
    const others=(names||[]).filter(n=>n!==me.username);
    typingEl.textContent = others.length
      ? (others.length===1 ? `${others[0]} is typing...` : `${others.join(", ")} are typing...`)
      : "";
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
  socket.on("reaction update", ({messageId,reactions})=>{
    renderReactions(messageId,reactions);
  });
  socket.on("message deleted", ({messageId})=>{
    const el=document.querySelector(`[data-mid="${messageId}"] .text`);
    if(el) el.textContent="[message deleted]";
  });
  socket.on("dm history", (payload)=>{
    const { threadId, messages=[], participants=[], title="" } = payload || {};
    const existing = dmThreads.find(t=>t.id===threadId);
    const lastText = messages.length ? messages[messages.length-1].text || "" : (existing?.last_text || "");
    if(existing){
      Object.assign(existing, { participants, title, last_text: lastText, last_ts: messages.length ? messages[messages.length-1].ts : existing.last_ts });
    } else {
      dmThreads.unshift({ id: threadId, participants, title, last_text: lastText, last_ts: messages.length ? messages[messages.length-1].ts : Date.now() });
    }
    dmMessages.set(threadId, messages);
    renderDmThreads();
    if(activeDmId === threadId){
      setDmMeta(dmThreads.find(t=>t.id===threadId));
      renderDmMessages(threadId);
    }
  });
  socket.on("dm message", (m)=>{
    const arr = dmMessages.get(m.threadId) || [];
    arr.push(m);
    dmMessages.set(m.threadId, arr);
    upsertThreadMeta(m.threadId, { last_text: m.text || "", last_ts: m.ts });
    if(activeDmId === m.threadId){
      renderDmMessages(m.threadId);
    }
  });
  socket.on("dm thread invited", ()=>{ loadDmThreads(); });

  joinRoom("main");
  meStatusText.textContent = statusSelect.value || "Online";
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
  const res = await fetch("/me");
  me = await res.json();
  if(me){
    authWrap.style.display="none";
    app.style.display="block";
    await startApp();
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
