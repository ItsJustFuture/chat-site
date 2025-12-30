
// PATCHED: ensure main room join on connect
const socket = io();

socket.on("connect", () => {
  if (!window.currentRoom) window.currentRoom = "main";
  socket.emit("join room", {
    room: window.currentRoom,
    status: window.currentStatus || "Online"
  });
});
