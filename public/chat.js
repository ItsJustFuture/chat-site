/**
 * Chat Client - Main application logic
 * Initializes Socket.IO connection and handles all chat interactions
 */

(function() {
  'use strict';

  console.log('[chat.js] Loading chat client...');

  // ===== Global State =====
  let socket = null;
  let currentRoom = 'main';
  let currentUser = null;
  let isInitialized = false;

  // ===== Socket.IO Initialization =====
  function initializeSocket() {
    if (socket) {
      console.log('[chat.js] Socket already initialized');
      return;
    }

    console.log('[chat.js] Initializing Socket.IO connection...');
    socket = io();

    socket.on('connect', () => {
      console.log('[chat.js] Socket connected:', socket.id);
      // Send client hello with browser info
      socket.emit('client:hello', {
        tz: Intl.DateTimeFormat().resolvedOptions().timeZone,
        locale: navigator.language,
        platform: navigator.platform
      });
      // Auto-join main room
      socket.emit('join room', { room: currentRoom, status: 'Online' });
    });

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
    if (dmToggleBtn) {
      dmToggleBtn.addEventListener('click', () => {
        console.log('[chat.js] DM toggle clicked');
        // TODO: Toggle DM panel
      });
      console.log('[chat.js] DM toggle button configured');
    }

    // Group DM toggle button
    const groupDmToggleBtn = document.getElementById('groupDmToggleBtn');
    if (groupDmToggleBtn) {
      groupDmToggleBtn.addEventListener('click', () => {
        console.log('[chat.js] Group DM toggle clicked');
        // TODO: Toggle group DM panel
      });
      console.log('[chat.js] Group DM toggle button configured');
    }

    // Notifications button
    const notificationsBtn = document.getElementById('notificationsBtn');
    if (notificationsBtn) {
      notificationsBtn.addEventListener('click', () => {
        console.log('[chat.js] Notifications button clicked');
        const modal = document.getElementById('notificationsModal');
        if (modal) modal.style.display = '';
      });
      console.log('[chat.js] Notifications button configured');
    }

    // Close notifications
    const notificationsCloseBtn = document.getElementById('notificationsCloseBtn');
    if (notificationsCloseBtn) {
      notificationsCloseBtn.addEventListener('click', () => {
        const modal = document.getElementById('notificationsModal');
        if (modal) modal.style.display = 'none';
      });
    }

    // Channels toggle (mobile)
    const openChannelsBtn = document.getElementById('openChannelsBtn');
    const channelsCloseBtn = document.getElementById('channelsCloseBtn');
    const channelsPane = document.getElementById('channelsPane');
    
    if (openChannelsBtn && channelsPane) {
      openChannelsBtn.addEventListener('click', () => {
        channelsPane.classList.add('show');
        console.log('[chat.js] Channels panel opened');
      });
    }
    
    if (channelsCloseBtn && channelsPane) {
      channelsCloseBtn.addEventListener('click', () => {
        channelsPane.classList.remove('show');
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
    if (openMembersBtn) {
      openMembersBtn.addEventListener('click', () => {
        console.log('[chat.js] Members button clicked');
        // TODO: Toggle members panel on mobile
      });
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

    console.log('[chat.js] Initializing chat application...');

    try {
      initializeSocket();
      attachEventListeners();
      console.log('[chat.js] Chat application initialized successfully ✓');
    } catch (err) {
      console.error('[chat.js] Initialization failed:', err);
      // Reset flag on error so retry is possible
      isInitialized = false;
    }
  }

  // ===== Public API =====
  window.chatApp = {
    initialize,
    isInitialized: () => isInitialized
  };

  // Auto-initialize if chatView is already visible
  const chatView = document.getElementById('chatView');
  if (chatView && !chatView.hidden) {
    console.log('[chat.js] Chat view is visible, auto-initializing...');
    initialize();
  } else {
    console.log('[chat.js] Chat view is hidden, waiting for initialization call...');
  }

  // Also initialize on DOM ready if not already done
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      const chatView = document.getElementById('chatView');
      if (chatView && !chatView.hidden) {
        initialize();
      }
    });
  }

  console.log('[chat.js] Chat client loaded');
})();
