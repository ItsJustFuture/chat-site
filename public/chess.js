/* global io */
"use strict";

/**
 * Chess Modal Client-Side Logic
 * Handles board rendering, piece interaction, and socket communication
 */

let currentChessState = null;
let selectedSquare = null;
let legalMovesFromSquare = [];

const PIECE_SYMBOLS = {
  p: "♟", P: "♙",
  r: "♜", R: "♖",
  n: "♞", N: "♘",
  b: "♝", B: "♗",
  q: "♛", Q: "♕",
  k: "♚", K: "♔"
};

const PIECE_NAMES = {
  p: "Pawn", r: "Rook", n: "Knight", b: "Bishop", q: "Queen", k: "King",
  P: "Pawn", R: "Rook", N: "Knight", B: "Bishop", Q: "Queen", K: "King"
};

/**
 * Initialize chess modal
 */
function initChessModal() {
  console.log("[chess.js] Initializing chess modal");
  
  // Setup button handlers (these don't need socket)
  setupChessButtons();

  // Setup socket listeners when socket becomes available
  const socket = window.socket;
  if (socket) {
    console.log("[chess.js] Socket already available, setting up listeners immediately");
    setupSocketListeners(socket);
  } else {
    console.log("[chess.js] Socket not available yet, will initialize on app:ready");
    // Listen for app:ready event which is dispatched when socket is ready
    document.addEventListener("app:ready", () => {
      console.log("[chess.js] app:ready received, setting up socket listeners");
      const socket = window.socket;
      if (socket) {
        setupSocketListeners(socket);
      }
    });
  }

  // Request current state when modal opens
  const roomChessBtn = document.getElementById("roomChessBtn");
  if (roomChessBtn) {
    roomChessBtn.addEventListener("click", () => {
      requestCurrentChessState();
    });
  }
}

/**
 * Setup socket event listeners
 */
function setupSocketListeners(socket) {
  if (window.chessSocketListenersSetup) {
    console.log("[chess.js] Socket listeners already set up, skipping");
    return;
  }
  
  console.log("[chess.js] Setting up socket listeners");
  
  // Listen for game state updates
  socket.on("chess:game:state", handleChessGameState);
  socket.on("chess:challenge:state", handleChessChallengeState);
  socket.on("chess:leaderboard:data", handleChessLeaderboard);
  
  window.chessSocketListenersSetup = true;
  console.log("[chess.js] Socket listeners configured");
}

/**
 * Setup chess button handlers
 */
function setupChessButtons() {
  const createBtn = document.getElementById("chessCreateBtn");
  const resignBtn = document.getElementById("chessResignBtn");
  const drawOfferBtn = document.getElementById("chessDrawOfferBtn");
  const drawAcceptBtn = document.getElementById("chessDrawAcceptBtn");
  const leaderboardBtn = document.getElementById("chessLeaderboardBtn");

  if (createBtn) {
    createBtn.addEventListener("click", handleCreateGame);
  }

  if (resignBtn) {
    resignBtn.addEventListener("click", handleResign);
  }

  if (drawOfferBtn) {
    drawOfferBtn.addEventListener("click", handleDrawOffer);
  }

  if (drawAcceptBtn) {
    drawAcceptBtn.addEventListener("click", handleDrawAccept);
  }

  if (leaderboardBtn) {
    leaderboardBtn.addEventListener("click", showChessLeaderboard);
  }
}

/**
 * Request current chess state from server
 */
function requestCurrentChessState() {
  const currentRoom = window.currentRoom;
  if (!currentRoom) {
    console.log("[chess.js] No current room");
    renderEmptyChessBoard();
    return;
  }

  const socket = window.socket;
  if (!socket) {
    console.log("[chess.js] No socket available");
    renderEmptyChessBoard();
    return;
  }

  console.log("[chess.js] Requesting chess state for room:", currentRoom);
  socket.emit("chess:game:join", {
    contextType: "room",
    contextId: currentRoom
  }, (response) => {
    if (response?.error) {
      console.log("[chess.js] No active game:", response.error);
      renderEmptyChessBoard();
    }
  });
}

/**
 * Handle game state updates from server
 */
function handleChessGameState(state) {
  console.log("[chess.js] Received game state:", state);
  currentChessState = state;
  renderChessBoard(state);
  updateChessUI(state);
}

/**
 * Handle challenge state updates
 */
function handleChessChallengeState(state) {
  console.log("[chess.js] Received challenge state:", state);
  // Could be used for DM challenges in the future
}

/**
 * Handle leaderboard data
 */
function handleChessLeaderboard(data) {
  console.log("[chess.js] Received leaderboard:", data);
  displayChessLeaderboard(data.rows);
}

/**
 * Parse FEN string and return board array
 */
function parseFEN(fen) {
  if (!fen) return null;
  const parts = fen.split(" ");
  const position = parts[0];
  const turn = parts[1]; // 'w' or 'b'
  
  const ranks = position.split("/");
  const board = [];
  
  for (let rankIndex = 0; rankIndex < 8; rankIndex++) {
    const rank = ranks[rankIndex];
    const row = [];
    
    for (let i = 0; i < rank.length; i++) {
      const char = rank[i];
      if (char >= "1" && char <= "8") {
        // Empty squares
        const count = parseInt(char);
        for (let j = 0; j < count; j++) {
          row.push(null);
        }
      } else {
        // Piece
        row.push(char);
      }
    }
    board.push(row);
  }
  
  return { board, turn };
}

/**
 * Convert square notation to coordinates
 */
function squareToCoords(square) {
  if (!square || square.length !== 2) return null;
  const file = square.charCodeAt(0) - 97; // a=0, b=1, etc.
  const rank = 8 - parseInt(square[1]); // 8=0, 7=1, etc.
  return { rank, file };
}

/**
 * Convert coordinates to square notation
 */
function coordsToSquare(rank, file) {
  const fileChar = String.fromCharCode(97 + file);
  const rankNum = 8 - rank;
  return fileChar + rankNum;
}

/**
 * Get piece image path
 */
function getPieceImagePath(piece) {
  if (!piece) return null;
  
  const color = piece === piece.toUpperCase() ? "w" : "b";
  const type = piece.toUpperCase();
  
  // Map piece types to file names
  const typeMap = {
    P: "P", R: "R", N: "H", B: "B", Q: "Q", K: "K"
  };
  
  const fileName = color + typeMap[type];
  return `/chess/pieces/${fileName}.png`;
}

/**
 * Render the chess board
 */
function renderChessBoard(state) {
  const boardDiv = document.getElementById("chessBoard");
  if (!boardDiv) {
    console.error("[chess.js] Board div not found");
    return;
  }

  boardDiv.innerHTML = "";
  boardDiv.className = "chessBoard";

  if (!state || !state.fen) {
    renderEmptyChessBoard();
    return;
  }

  const parsed = parseFEN(state.fen);
  if (!parsed) {
    renderEmptyChessBoard();
    return;
  }

  const { board, turn } = parsed;
  const myColor = state.myColor;
  const isMyTurn = myColor && turn === myColor;

  // Render 8x8 grid
  for (let rank = 0; rank < 8; rank++) {
    for (let file = 0; file < 8; file++) {
      const square = document.createElement("div");
      square.className = "chessSquare";
      square.dataset.rank = rank;
      square.dataset.file = file;
      square.dataset.square = coordsToSquare(rank, file);
      
      // Checkerboard pattern (light/dark)
      if ((rank + file) % 2 === 0) {
        square.classList.add("light");
      } else {
        square.classList.add("dark");
      }

      // Add piece if present
      const piece = board[rank][file];
      if (piece) {
        const pieceImg = document.createElement("img");
        pieceImg.src = getPieceImagePath(piece);
        pieceImg.alt = PIECE_NAMES[piece];
        pieceImg.className = "chessPiece";
        pieceImg.draggable = false;
        square.appendChild(pieceImg);
        square.dataset.piece = piece;
      }

      // Add click handler
      square.addEventListener("click", () => handleSquareClick(rank, file, state));

      boardDiv.appendChild(square);
    }
  }

  // Highlight selected square and legal moves
  updateBoardHighlights();
}

/**
 * Render empty chess board (no game active)
 */
function renderEmptyChessBoard() {
  const boardDiv = document.getElementById("chessBoard");
  if (!boardDiv) return;

  boardDiv.innerHTML = "";
  boardDiv.className = "chessBoard";

  // Render empty 8x8 grid
  for (let rank = 0; rank < 8; rank++) {
    for (let file = 0; file < 8; file++) {
      const square = document.createElement("div");
      square.className = "chessSquare";
      
      if ((rank + file) % 2 === 0) {
        square.classList.add("light");
      } else {
        square.classList.add("dark");
      }

      boardDiv.appendChild(square);
    }
  }
}

/**
 * Handle square click
 */
function handleSquareClick(rank, file, state) {
  if (!state || state.status !== "active") {
    console.log("[chess.js] Game not active");
    return;
  }

  const myColor = state.myColor;
  if (!myColor) {
    console.log("[chess.js] Not playing in this game");
    return;
  }

  if (state.turn !== myColor) {
    console.log("[chess.js] Not my turn");
    return;
  }

  const square = coordsToSquare(rank, file);
  const clickedPiece = getPieceAtSquare(state, square);

  // If a square is already selected
  if (selectedSquare) {
    // Check if this is a legal move
    const move = legalMovesFromSquare.find(m => m.to === square);
    
    if (move) {
      // Make the move
      makeMove(move.from, move.to, state);
      selectedSquare = null;
      legalMovesFromSquare = [];
      updateBoardHighlights();
    } else if (clickedPiece && isPieceOwnedByPlayer(clickedPiece, myColor)) {
      // Select different piece
      selectedSquare = square;
      legalMovesFromSquare = getLegalMovesFromSquare(square, state);
      updateBoardHighlights();
    } else {
      // Deselect
      selectedSquare = null;
      legalMovesFromSquare = [];
      updateBoardHighlights();
    }
  } else {
    // No square selected - select if it's our piece
    if (clickedPiece && isPieceOwnedByPlayer(clickedPiece, myColor)) {
      selectedSquare = square;
      legalMovesFromSquare = getLegalMovesFromSquare(square, state);
      updateBoardHighlights();
    }
  }
}

/**
 * Get piece at square from FEN
 */
function getPieceAtSquare(state, square) {
  if (!state || !state.fen) return null;
  
  const parsed = parseFEN(state.fen);
  if (!parsed) return null;
  
  const coords = squareToCoords(square);
  if (!coords) return null;
  
  return parsed.board[coords.rank][coords.file];
}

/**
 * Check if piece is owned by player
 */
function isPieceOwnedByPlayer(piece, color) {
  if (!piece || !color) return false;
  if (color === "w") return piece === piece.toUpperCase();
  if (color === "b") return piece === piece.toLowerCase();
  return false;
}

/**
 * Get legal moves from a square
 */
function getLegalMovesFromSquare(square, state) {
  if (!state || !state.legalMoves) return [];
  return state.legalMoves.filter(m => m.from === square);
}

/**
 * Update board highlights
 */
function updateBoardHighlights() {
  const boardDiv = document.getElementById("chessBoard");
  if (!boardDiv) return;

  // Remove all highlights
  const squares = boardDiv.querySelectorAll(".chessSquare");
  squares.forEach(sq => {
    sq.classList.remove("is-selected", "is-legal", "is-capture");
  });

  // Highlight selected square
  if (selectedSquare) {
    const coords = squareToCoords(selectedSquare);
    if (coords) {
      const sq = boardDiv.querySelector(`[data-rank="${coords.rank}"][data-file="${coords.file}"]`);
      if (sq) sq.classList.add("is-selected");
    }
  }

  // Highlight legal moves
  legalMovesFromSquare.forEach(move => {
    const coords = squareToCoords(move.to);
    if (coords) {
      const sq = boardDiv.querySelector(`[data-rank="${coords.rank}"][data-file="${coords.file}"]`);
      if (sq) {
        sq.classList.add("is-legal");
        // Check if this is a capture move (has a piece on target square)
        if (sq.dataset.piece) {
          sq.classList.add("is-capture");
        }
      }
    }
  });
}

/**
 * Make a move
 */
function makeMove(from, to, state) {
  console.log("[chess.js] Making move:", from, "to", to);
  
  // Check if this is a pawn promotion
  const piece = getPieceAtSquare(state, from);
  const fromCoords = squareToCoords(from);
  const toCoords = squareToCoords(to);
  
  let promotion = null;
  if (piece && (piece === "P" || piece === "p")) {
    // White pawn reaching rank 8 (rank index 0) or black pawn reaching rank 1 (rank index 7)
    if ((piece === "P" && toCoords.rank === 0) || (piece === "p" && toCoords.rank === 7)) {
      // Show promotion dialog
      showPromotionDialog(from, to, state);
      return;
    }
  }

  sendMove(from, to, promotion, state);
}

/**
 * Show promotion dialog
 */
function showPromotionDialog(from, to, state) {
  const promotionDiv = document.getElementById("chessPromotion");
  if (!promotionDiv) return;

  const myColor = state.myColor;
  const pieces = myColor === "w" ? ["Q", "R", "B", "N"] : ["q", "r", "b", "n"];
  const pieceNames = ["Queen", "Rook", "Bishop", "Knight"];

  promotionDiv.innerHTML = "";
  promotionDiv.removeAttribute("hidden");

  const title = document.createElement("div");
  title.textContent = "Choose promotion:";
  title.className = "promotionTitle";
  promotionDiv.appendChild(title);

  const buttonsDiv = document.createElement("div");
  buttonsDiv.className = "promotionButtons";

  pieces.forEach((piece, i) => {
    const btn = document.createElement("button");
    btn.className = "promotionBtn";
    
    const img = document.createElement("img");
    img.src = getPieceImagePath(piece);
    img.alt = pieceNames[i];
    img.className = "promotionPieceImg";
    
    btn.appendChild(img);
    btn.addEventListener("click", () => {
      sendMove(from, to, piece.toLowerCase(), state);
      promotionDiv.setAttribute("hidden", "");
    });
    
    buttonsDiv.appendChild(btn);
  });

  promotionDiv.appendChild(buttonsDiv);
}

/**
 * Send move to server
 */
function sendMove(from, to, promotion, state) {
  const socket = window.socket;
  if (!socket) return;

  socket.emit("chess:game:move", {
    gameId: state.gameId,
    from,
    to,
    promotion
  }, (response) => {
    if (response?.error) {
      console.error("[chess.js] Move error:", response.error);
      alert("Invalid move: " + response.error);
    } else {
      console.log("[chess.js] Move successful");
    }
  });
}

/**
 * Update chess UI (status, buttons, etc.)
 */
function updateChessUI(state) {
  updateChessSeats(state);
  updateChessStatus(state);
  updateChessMeta(state);
  updateChessButtons(state);
}

/**
 * Update seat display
 */
function updateChessSeats(state) {
  const seatsDiv = document.getElementById("chessSeats");
  if (!seatsDiv) return;

  seatsDiv.innerHTML = "";

  if (!state || state.status === "none") {
    seatsDiv.innerHTML = "<div class='small muted'>No active game</div>";
    return;
  }

  // White seat
  const whiteSeat = document.createElement("div");
  whiteSeat.className = "chessSeat white";
  
  if (state.whiteUser) {
    whiteSeat.innerHTML = `
      <div class="seatLabel">White</div>
      <div class="seatPlayer">${escapeHTML(state.whiteUser.username)}</div>
      <div class="seatElo">${state.whiteUser.chess_elo || 1200} ELO</div>
    `;
  } else {
    whiteSeat.innerHTML = `
      <div class="seatLabel">White</div>
      <div class="seatPlayer muted">Empty</div>
    `;
    if (state.seatClaimable?.white) {
      const btn = document.createElement('button');
      btn.className = 'btn btnSmall';
      btn.textContent = 'Join as White';
      btn.addEventListener('click', () => claimSeat('w'));
      whiteSeat.appendChild(btn);
    }
  }
  
  seatsDiv.appendChild(whiteSeat);

  // Black seat
  const blackSeat = document.createElement("div");
  blackSeat.className = "chessSeat black";
  
  if (state.blackUser) {
    blackSeat.innerHTML = `
      <div class="seatLabel">Black</div>
      <div class="seatPlayer">${escapeHTML(state.blackUser.username)}</div>
      <div class="seatElo">${state.blackUser.chess_elo || 1200} ELO</div>
    `;
  } else {
    blackSeat.innerHTML = `
      <div class="seatLabel">Black</div>
      <div class="seatPlayer muted">Empty</div>
    `;
    if (state.seatClaimable?.black) {
      const btn = document.createElement('button');
      btn.className = 'btn btnSmall';
      btn.textContent = 'Join as Black';
      btn.addEventListener('click', () => claimSeat('b'));
      blackSeat.appendChild(btn);
    }
  }
  
  seatsDiv.appendChild(blackSeat);
}

/**
 * Update status display
 */
function updateChessStatus(state) {
  const statusDiv = document.getElementById("chessStatus");
  if (!statusDiv) return;

  if (!state || state.status === "none") {
    statusDiv.innerHTML = "<div class='statusText'>No game in progress</div>";
    return;
  }

  let statusText = "";
  
  if (state.status === "active") {
    const turnPlayer = state.turn === "w" ? state.whiteUser : state.blackUser;
    statusText = `${turnPlayer ? escapeHTML(turnPlayer.username) : "White"}'s turn`;
    
    if (state.drawOfferBy) {
      statusText += `<br><span class="statusHighlight">Draw offered by ${escapeHTML(state.drawOfferBy.username)}</span>`;
    }
  } else if (state.status === "checkmate") {
    const winner = state.result === "white" ? state.whiteUser : state.blackUser;
    statusText = `<span class="statusHighlight">Checkmate! ${escapeHTML(winner?.username || state.result)} wins!</span>`;
  } else if (state.status === "stalemate") {
    statusText = `<span class="statusHighlight">Stalemate - Draw</span>`;
  } else if (state.status === "draw") {
    statusText = `<span class="statusHighlight">Draw by agreement</span>`;
  } else if (state.status === "resignation") {
    const winner = state.result === "white" ? state.whiteUser : state.blackUser;
    statusText = `<span class="statusHighlight">${escapeHTML(winner?.username || state.result)} wins by resignation</span>`;
  } else if (state.status === "timeout") {
    const winner = state.result === "white" ? state.whiteUser : state.blackUser;
    statusText = `<span class="statusHighlight">${escapeHTML(winner?.username || state.result)} wins by timeout</span>`;
  }

  statusDiv.innerHTML = `<div class="statusText">${statusText}</div>`;
}

/**
 * Update meta information
 */
function updateChessMeta(state) {
  const metaDiv = document.getElementById("chessMeta");
  if (!metaDiv) return;

  if (!state || state.status === "none") {
    metaDiv.innerHTML = "";
    return;
  }

  let html = `<div class="chessMoves">Moves: ${Math.floor((state.pliesCount || 0) / 2)}</div>`;
  
  if (state.rated !== null) {
    html += `<div class="chessRated">${state.rated ? "Rated" : "Unrated"}</div>`;
    if (state.ratedReason) {
      html += `<div class="small muted">${escapeHTML(state.ratedReason)}</div>`;
    }
  }

  if (state.whiteEloChange !== null || state.blackEloChange !== null) {
    html += `<div class="eloChanges">`;
    if (state.whiteEloChange !== null) {
      const sign = state.whiteEloChange > 0 ? "+" : "";
      html += `<div>White: ${sign}${state.whiteEloChange}</div>`;
    }
    if (state.blackEloChange !== null) {
      const sign = state.blackEloChange > 0 ? "+" : "";
      html += `<div>Black: ${sign}${state.blackEloChange}</div>`;
    }
    html += `</div>`;
  }

  metaDiv.innerHTML = html;
}

/**
 * Update button visibility and state
 */
function updateChessButtons(state) {
  const createBtn = document.getElementById("chessCreateBtn");
  const resignBtn = document.getElementById("chessResignBtn");
  const drawOfferBtn = document.getElementById("chessDrawOfferBtn");
  const drawAcceptBtn = document.getElementById("chessDrawAcceptBtn");

  if (!state || state.status === "none") {
    if (createBtn) createBtn.style.display = "";
    if (resignBtn) resignBtn.style.display = "none";
    if (drawOfferBtn) drawOfferBtn.style.display = "none";
    if (drawAcceptBtn) drawAcceptBtn.style.display = "none";
    return;
  }

  const isPlayer = state.myColor !== null;
  const isActive = state.status === "active";

  if (createBtn) createBtn.style.display = "none";
  if (resignBtn) resignBtn.style.display = isPlayer && isActive ? "" : "none";
  if (drawOfferBtn) drawOfferBtn.style.display = isPlayer && isActive && !state.drawOfferBy ? "" : "none";
  if (drawAcceptBtn) drawAcceptBtn.style.display = isPlayer && isActive && state.drawOfferBy && state.drawOfferBy.user_id !== (state.myColor === "w" ? state.whiteUser?.user_id : state.blackUser?.user_id) ? "" : "none";
}

/**
 * Handle create game button
 */
function handleCreateGame() {
  const currentRoom = window.currentRoom;
  if (!currentRoom) {
    alert("Please select a room first");
    return;
  }

  const socket = window.socket;
  if (!socket) {
    alert("Socket not connected");
    return;
  }

  console.log("[chess.js] Creating game in room:", currentRoom);
  socket.emit("chess:game:create", {
    contextType: "room",
    contextId: currentRoom
  }, (response) => {
    if (response?.error) {
      alert("Error creating game: " + response.error);
    } else {
      console.log("[chess.js] Game created successfully");
    }
  });
}

/**
 * Handle resign button
 */
function handleResign() {
  if (!currentChessState || !currentChessState.gameId) return;
  
  if (!confirm("Are you sure you want to resign?")) return;

  const socket = window.socket;
  socket.emit("chess:game:resign", {
    gameId: currentChessState.gameId
  }, (response) => {
    if (response?.error) {
      alert("Error resigning: " + response.error);
    }
  });
}

/**
 * Handle draw offer button
 */
function handleDrawOffer() {
  if (!currentChessState || !currentChessState.gameId) return;

  const socket = window.socket;
  socket.emit("chess:game:drawOffer", {
    gameId: currentChessState.gameId
  }, (response) => {
    if (response?.error) {
      alert("Error offering draw: " + response.error);
    }
  });
}

/**
 * Handle draw accept button
 */
function handleDrawAccept() {
  if (!currentChessState || !currentChessState.gameId) return;

  const socket = window.socket;
  socket.emit("chess:game:drawRespond", {
    gameId: currentChessState.gameId,
    accept: true
  }, (response) => {
    if (response?.error) {
      alert("Error accepting draw: " + response.error);
    }
  });
}

/**
 * Claim a seat
 */
function claimSeat(color) {
  if (!currentChessState || !currentChessState.gameId) return;

  const socket = window.socket;
  socket.emit("chess:game:seat", {
    gameId: currentChessState.gameId,
    color
  }, (response) => {
    if (response?.error) {
      alert("Error claiming seat: " + response.error);
    }
  });
}

/**
 * Show chess leaderboard
 */
function showChessLeaderboard() {
  const socket = window.socket;
  socket.emit("chess:leaderboard:get", {
    limit: 50,
    offset: 0
  });
}

/**
 * Display chess leaderboard
 */
function displayChessLeaderboard(rows) {
  const leaderboardDiv = document.getElementById("leaderboardChess");
  if (!leaderboardDiv) return;

  if (!rows || rows.length === 0) {
    leaderboardDiv.innerHTML = "<div class='small muted'>No players yet</div>";
    return;
  }

  let html = "<div class='leaderboardTable'>";
  html += "<div class='leaderboardHeader'>";
  html += "<div class='rank'>#</div>";
  html += "<div class='player'>Player</div>";
  html += "<div class='elo'>ELO</div>";
  html += "<div class='games'>Games</div>";
  html += "<div class='record'>W-L-D</div>";
  html += "</div>";

  rows.forEach((row, i) => {
    html += "<div class='leaderboardRow'>";
    html += `<div class='rank'>${i + 1}</div>`;
    html += `<div class='player'>${escapeHTML(row.username)}</div>`;
    html += `<div class='elo'>${row.chess_elo}</div>`;
    html += `<div class='games'>${row.chess_games_played}</div>`;
    html += `<div class='record'>${row.chess_wins}-${row.chess_losses}-${row.chess_draws}</div>`;
    html += "</div>";
  });

  html += "</div>";
  leaderboardDiv.innerHTML = html;

  // Switch to chess leaderboard tab
  const chessTab = document.querySelector('[data-leaderboard-category="chess"]');
  if (chessTab) {
    document.querySelectorAll('.leaderboardCard').forEach(card => {
      card.classList.add('hidden');
    });
    chessTab.classList.remove('hidden');
  }
}

/**
 * Escape HTML to prevent XSS
 */
function escapeHTML(str) {
  if (!str) return "";
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

// Initialize when DOM is ready
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", init);
} else {
  init();
}

function init() {
  initChessModal();
  // Check for socket periodically in case app:ready already fired
  // This is necessary because app:ready event may fire before chess.js finishes loading
  let attempts = 0;
  const checkSocket = setInterval(() => {
    attempts++;
    if (window.socket && !window.chessSocketListenersSetup) {
      console.log("[chess.js] Socket available after", attempts * 200, "ms, setting up listeners");
      setupSocketListeners(window.socket);
      clearInterval(checkSocket);
    } else if (window.chessSocketListenersSetup) {
      clearInterval(checkSocket);
    } else if (attempts > 25) {  // Stop after 5 seconds
      console.warn("[chess.js] Socket still not available after 5 seconds");
      clearInterval(checkSocket);
    }
  }, 200);
}
