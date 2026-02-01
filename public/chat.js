/**
 * Chat Client - Main application logic
 * Handles all chat interactions after app.js bootstrap completes
 */

(function() {
  'use strict';

  console.log('[chat.js] Loading chat client...');

  // ===== Global State =====
  let socket = null;
  let currentRoom = 'main';
  let currentUser = null;
  let isInitialized = false;

  // ===== Wait for app:ready before initializing =====
  async function waitAndInit() {
    console.log('[chat.js] Waiting for app:ready...');
    
    // Ensure waitForAppReady is available
    if (typeof window.waitForAppReady !== 'function') {
      console.error('[chat.js] FATAL: window.waitForAppReady not initialized by app.js - runtime initialization error');
      return;
    }

    try {
      const appState = await window.waitForAppReady();
      console.log('[chat.js] app:ready received');
      
      // Use the globally initialized socket
      socket = appState.socket || window.socket;
      currentUser = appState.currentUser || window.currentUser;
      currentRoom = appState.currentRoom || window.currentRoom;

      // Socket might not be available yet if user just logged in
      // Listen for additional app:ready events in case socket gets initialized later
      if (!socket) {
        console.log('[chat.js] Socket not yet available, waiting for it...');
        window.addEventListener('app:ready', (event) => {
          if (event.detail.socket && !socket) {
            console.log('[chat.js] Socket now available from re-dispatched app:ready');
            socket = event.detail.socket;
            currentUser = event.detail.currentUser || window.currentUser;
            setupSocketListeners();
          }
        });
      } else {
        console.log('[chat.js] Using global socket:', socket.id);
        setupSocketListeners();
      }
    } catch (error) {
      console.error('[chat.js] Failed to wait for app:ready:', error);
    }
  }

  // ===== Socket Event Listeners =====
  function setupSocketListeners() {
    if (!socket) {
      console.error('[chat.js] Cannot setup listeners: socket is null');
      return;
    }

    console.log('[chat.js] Setting up socket event listeners...');

    // Send client hello with browser info
    socket.emit('client:hello', {
      tz: Intl.DateTimeFormat().resolvedOptions().timeZone,
      locale: navigator.language,
      platform: navigator.platform
    });

    // Auto-join main room
    socket.emit('join room', { room: currentRoom, status: 'Online' });

    // Handle disconnect
    socket.on('disconnect', () => {
      console.log('[chat.js] Socket disconnected');
    });

    socket.on('error', (error) => {
      console.error('[chat.js] Socket error:', error);
    });

    // Handle restriction status (kicked/banned)
    socket.on('restriction:status', (data) => {
      console.log('[chat.js] Restriction status:', data);
      // The auth system should handle this
    });

    // Handle chat messages
    socket.on('chat message', (data) => {
      console.log('[chat.js] Received message:', data);
      // TODO: Display message in UI
    });

    // Handle system messages
    socket.on('system', (data) => {
      console.log('[chat.js] System message:', data);
      // TODO: Display system message
    });

    // Handle room list updates
    socket.on('rooms update', (rooms) => {
      console.log('[chat.js] Rooms updated:', rooms);
      // TODO: Update room list UI
    });

    // Handle user list updates
    socket.on('room users', (data) => {
      console.log('[chat.js] Room users:', data);
      // TODO: Update members list UI
    });

    console.log('[chat.js] Socket listeners configured ✓');

    // Now attach UI event listeners
    attachEventListeners();
  }

  // ===== Button Event Handlers =====
  function attachEventListeners() {
    console.log('[chat.js] Attaching event listeners to buttons...');

    // Send message button
    const sendBtn = document.getElementById('sendBtn');
    const messageInput = document.getElementById('msgInput');
    
    if (sendBtn && messageInput) {
      const sendMessage = () => {
        const text = messageInput.value.trim();
        if (!text) return;

        // Check socket connection before emitting
        if (!socket || !socket.connected) {
          console.warn('[chat.js] Cannot send message: socket not connected');
          return;
        }

        console.log('[chat.js] Sending message:', text);
        socket.emit('chat message', {
          room: currentRoom,
          text: text
        });

        messageInput.value = '';
      };

      sendBtn.addEventListener('click', sendMessage);
      
      // Note: app.js already handles Enter key for message sending
      // We don't need to duplicate that functionality here

      console.log('[chat.js] Message sending configured');
    } else {
      console.warn('[chat.js] Send button or message input not found');
    }

    // Logout button (top bar)
    const logoutTopBtn = document.getElementById('logoutTopBtn');
    if (logoutTopBtn) {
      logoutTopBtn.addEventListener('click', async () => {
        try {
          // Disconnect socket before logout
          if (socket && socket.connected) {
            socket.disconnect();
          }
          await fetch('/logout', { method: 'POST', credentials: 'include' });
          window.location.reload();
        } catch (err) {
          console.error('[chat.js] Logout failed:', err);
        }
      });
      console.log('[chat.js] Logout button configured');
    }

    // Profile button
    const profileBtn = document.getElementById('profileBtn');
    if (profileBtn) {
      profileBtn.addEventListener('click', () => {
        console.log('[chat.js] Profile button clicked');
        // TODO: Open profile modal
      });
      console.log('[chat.js] Profile button configured');
    }

    // DM toggle button
    const dmToggleBtn = document.getElementById('dmToggleBtn');
    const dmPanel = document.getElementById('dmPanel');
    if (dmToggleBtn && dmPanel) {
      dmToggleBtn.addEventListener('click', () => {
        console.log('[chat.js] DM toggle clicked');
        dmPanel.classList.toggle('open');
      });
      console.log('[chat.js] DM toggle button configured');
    }

    // DM close button
    const dmCloseBtn = document.getElementById('dmCloseBtn');
    if (dmCloseBtn && dmPanel) {
      dmCloseBtn.addEventListener('click', () => {
        dmPanel.classList.remove('open');
      });
    }

    // Group DM toggle button (opens same DM panel as DM button)
    const groupDmToggleBtn = document.getElementById('groupDmToggleBtn');
    if (groupDmToggleBtn && dmPanel) {
      groupDmToggleBtn.addEventListener('click', () => {
        console.log('[chat.js] Group DM toggle clicked');
        dmPanel.classList.toggle('open');
      });
      console.log('[chat.js] Group DM toggle button configured');
    }

    // Notifications button
    const notificationsBtn = document.getElementById('notificationsBtn');
    const notificationsModal = document.getElementById('notificationsModal');
    if (notificationsBtn && notificationsModal) {
      notificationsBtn.addEventListener('click', () => {
        console.log('[chat.js] Notifications button clicked');
        notificationsModal.removeAttribute('hidden');
      });
      console.log('[chat.js] Notifications button configured');
    }

    // Close notifications
    const notificationsCloseBtn = document.getElementById('notificationsCloseBtn');
    if (notificationsCloseBtn && notificationsModal) {
      notificationsCloseBtn.addEventListener('click', () => {
        notificationsModal.setAttribute('hidden', '');
      });
    }

    // Channels toggle (mobile)
    const openChannelsBtn = document.getElementById('openChannelsBtn');
    const channelsCloseBtn = document.getElementById('channelsCloseBtn');
    const channelsPane = document.getElementById('channelsPane');
    
    if (openChannelsBtn && channelsPane) {
      openChannelsBtn.addEventListener('click', () => {
        channelsPane.classList.add('open');
        console.log('[chat.js] Channels panel opened');
      });
    }
    
    if (channelsCloseBtn && channelsPane) {
      channelsCloseBtn.addEventListener('click', () => {
        channelsPane.classList.remove('open');
        console.log('[chat.js] Channels panel closed');
      });
    }

    // Menu toggle
    const menuToggleBtn = document.getElementById('menuToggleBtn');
    const menuPanel = document.getElementById('menuPanel');
    
    if (menuToggleBtn && menuPanel) {
      menuToggleBtn.addEventListener('click', () => {
        menuPanel.classList.toggle('show');
        console.log('[chat.js] Menu panel toggled');
      });
      console.log('[chat.js] Menu toggle button configured');
    }

    // Members toggle (mobile)
    const openMembersBtn = document.getElementById('openMembersBtn');
    const membersPane = document.getElementById('membersPane');
    if (openMembersBtn && membersPane) {
      openMembersBtn.addEventListener('click', () => {
        console.log('[chat.js] Members button clicked');
        membersPane.classList.toggle('open');
      });
    }

    // Chess button
    const roomChessBtn = document.getElementById('roomChessBtn');
    const chessModal = document.getElementById('chessModal');
    if (roomChessBtn && chessModal) {
      roomChessBtn.addEventListener('click', () => {
        console.log('[chat.js] Chess button clicked');
        chessModal.removeAttribute('hidden');
      });
      console.log('[chat.js] Chess button configured');
    }

    // Chess close button
    const chessCloseBtn = document.getElementById('chessCloseBtn');
    if (chessCloseBtn && chessModal) {
      chessCloseBtn.addEventListener('click', () => {
        chessModal.setAttribute('hidden', '');
      });
    }

    // Media button (upload)
    const mediaBtn = document.getElementById('mediaBtn');
    const mediaMenu = document.getElementById('mediaMenu');
    if (mediaBtn && mediaMenu) {
      mediaBtn.addEventListener('click', () => {
        console.log('[chat.js] Media button clicked');
        mediaMenu.toggleAttribute('hidden');
      });
      console.log('[chat.js] Media button configured');
    }

    // Manage rooms button
    const manageRoomsBtn = document.getElementById('manageRoomsBtn');
    if (manageRoomsBtn) {
      manageRoomsBtn.addEventListener('click', () => {
        console.log('[chat.js] Manage rooms button clicked');
        // Open menu panel which contains room management options
        const menuPanel = document.getElementById('menuPanel');
        if (menuPanel) {
          menuPanel.classList.add('show');
        }
      });
      console.log('[chat.js] Manage rooms button configured');
    }

    console.log('[chat.js] Event listeners attached successfully');
  }

  // ===== Initialization =====
  function initialize() {
    // Check at the very beginning to prevent race conditions
    if (isInitialized) {
      console.log('[chat.js] Already initialized');
      return;
    }

    // Set immediately to prevent race conditions with multiple initialization calls
    isInitialized = true;

    console.log('[chat.js] Chat UI initialized');
    // Note: attachEventListeners is called from setupSocketListeners after socket is ready
  }

  // ===== Public API =====
  window.chatApp = {
    initialize,
    isInitialized: () => isInitialized
  };

  // Start waiting for app:ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', waitAndInit);
  } else {
    waitAndInit();
  }

  console.log('[chat.js] Chat client loaded, waiting for bootstrap...');
})();
