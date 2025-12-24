const express = require("express");
const app = express();
const http = require("http").createServer(app);
const io = require("socket.io")(http);
const PORT = process.env.PORT || 3000;

http.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

app.use(express.static(__dirname));

const rooms = {}; // { roomName: [ { name, status } ] }

io.on("connection", socket => {
  let currentRoom = "";
  let username = "";

  socket.on("join room", data => {
    // Leave previous room
    if (currentRoom && rooms[currentRoom]) {
      socket.leave(currentRoom);

      rooms[currentRoom] = rooms[currentRoom].filter(
        user => user.name !== username
      );

      io.to(currentRoom).emit("user list", rooms[currentRoom]);
      io.to(currentRoom).emit("system", username + " left the room");
    }

    username = data.user;
    currentRoom = data.room;

    socket.join(currentRoom);

    if (!rooms[currentRoom]) {
      rooms[currentRoom] = [];
    }

    rooms[currentRoom].push({
      name: username,
      status: data.status || "Online"
    });

    io.to(currentRoom).emit("user list", rooms[currentRoom]);
    io.to(currentRoom).emit("system", username + " joined " + currentRoom);
  });

  socket.on("chat message", data => {
    io.to(data.room).emit("chat message", data);
  });

  socket.on("status change", data => {
    if (!rooms[data.room]) return;

    const user = rooms[data.room].find(u => u.name === data.user);
    if (user) {
      user.status = data.status;
      io.to(data.room).emit("user list", rooms[data.room]);
    }
  });

  socket.on("disconnect", () => {
    if (currentRoom && rooms[currentRoom]) {
      rooms[currentRoom] = rooms[currentRoom].filter(u => u.name !== username);
      io.to(currentRoom).emit("user list", rooms[currentRoom]);
      io.to(currentRoom).emit("system", username + " disconnected");
    }
  });
});

http.listen(3000, () => {
  console.log("Server running on http://localhost:3000");
});
