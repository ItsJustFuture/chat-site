/**
 * app.js - Frontend Bootstrap and Application Core
 * 
 * This is the main entry point for the client-side application.
 * It initializes Socket.IO, fetches session state, and provides global APIs.
 * 
 * Other scripts (auth.js, chat.js) wait for the 'app:ready' event before initializing.
 */

(function() {
  'use strict';

  console.log('[app.js] Loading application bootstrap...');

  // ===== Global State (exposed to other modules) =====
  window.socket = null;
  window.currentUser = null;
  window.currentRoom = 'main';
  
  // ===== Promise-Based Readiness Gates =====
  let appReadyResolve = null;
  let socketReadyResolve = null;
  const appReadyPromise = new Promise((resolve) => { appReadyResolve = resolve; });
  const socketReadyPromise = new Promise((resolve) => { socketReadyResolve = resolve; });

  // ===== Global Error Trapping =====
  window.onerror = function(message, source, lineno, colno, error) {
    console.error('[Global Error]', {
      message,
      source,
      lineno,
      colno,
      error,
      context: 'window.onerror'
    });
    return false; // Let default handler run
  };

  window.addEventListener('unhandledrejection', function(event) {
    console.error('[Unhandled Promise Rejection]', {
      reason: event.reason,
      promise: event.promise,
      context: 'unhandledrejection'
    });
  });

  // ===== Socket.IO Initialization with Smart Connection Error Handling =====
  const MAX_CONNECTION_ATTEMPTS = 3; // Number of failed attempts before showing error
  let failedAttempts = 0;
  let serverReady = false;
  let connectionErrorShown = false;

  function showConnectionError() {
    if (connectionErrorShown) return;
    connectionErrorShown = true;
    
    const errorDiv = document.createElement('div');
    errorDiv.id = 'connection-error-popup';
    errorDiv.style.cssText = 'position:fixed;top:20px;left:50%;transform:translateX(-50%);background:#ff6b6b;color:white;padding:15px 25px;border-radius:8px;z-index:10000;font-family:system-ui;box-shadow:0 4px 12px rgba(0,0,0,0.2)';
    errorDiv.textContent = '⚠️ Failed to connect to chat server. Please refresh the page.';
    document.body.appendChild(errorDiv);
  }

  function hideConnectionError() {
    connectionErrorShown = false;
    const errorDiv = document.getElementById('connection-error-popup');
    if (errorDiv) {
      errorDiv.remove();
    }
  }

  function initializeSocket() {
    if (window.socket) {
      console.log('[app.js] Socket already initialized');
      return Promise.resolve(window.socket);
    }

    return new Promise((resolve, reject) => {
      console.log('[app.js] Initializing Socket.IO...');
      
      // Check if io is available
      if (typeof io === 'undefined') {
        const error = 'Socket.IO library not loaded! Ensure /socket.io/socket.io.js is included before app.js';
        console.error('[app.js]', error);
        reject(new Error(error));
        return;
      }

      try {
        window.socket = io({
          path: '/socket.io',
          transports: ['websocket', 'polling'],
          withCredentials: true
        });
        
        // Server-ready handler - clears false connection errors and confirms all listeners registered
        window.socket.on('server-ready', (data) => {
          console.log('[app.js] Server ready signal received', { socketId: data?.socketId || window.socket.id });
          serverReady = true;
          failedAttempts = 0;
          hideConnectionError();
          
          // Store user data if provided
          if (data?.user) {
            window.currentUser = data.user;
            console.log('[app.js] User data received from server:', data.user);
            
            // Dispatch event with user data for chat.js and other modules
            window.dispatchEvent(new CustomEvent('user:data', { 
              detail: { user: data.user } 
            }));
          }
        });

        window.socket.on('connect', () => {
          console.log('[app.js] Socket connected (verified):', window.socket.id);
          failedAttempts = 0;
          hideConnectionError();
          // Resolve socket ready promise
          if (socketReadyResolve) {
            socketReadyResolve(window.socket);
          }
          resolve(window.socket);
        });

        window.socket.on('reconnect', (attemptNumber) => {
          console.log('[app.js] Socket reconnected after', attemptNumber, 'attempts');
          // Reset serverReady flag - will be set again when new server-ready signal arrives
          // Note: socket.connected is the authoritative connection state. The serverReady flag
          // is only used for initial connection error handling (to avoid showing false errors
          // before the server has finished initialization). All socket operations should check
          // socket.connected, not serverReady.
          serverReady = false;
          failedAttempts = 0;
          hideConnectionError();
          // Resolve socket ready promise again for reconnection
          if (socketReadyResolve) {
            socketReadyResolve(window.socket);
          }
        });

        window.socket.on('connect_error', (error) => {
          console.error('[app.js] Socket connection error:', error);
          
          // Only show error after multiple attempts and if server hasn't signaled ready
          if (!serverReady) {
            failedAttempts++;
            if (failedAttempts >= MAX_CONNECTION_ATTEMPTS) {
              showConnectionError();
              reject(error);
            }
          }
        });

        window.socket.on('disconnect', (reason) => {
          console.log('[app.js] Socket disconnected:', reason);
        });

        window.socket.on('error', (error) => {
          console.error('[app.js] Socket error:', error);
        });
      } catch (error) {
        console.error('[app.js] Failed to initialize Socket.IO:', error);
        reject(error);
      }
    });
  }

  // ===== Expose socket initializer for auth.js to call after login =====
  window.initSocket = initializeSocket;

  // ===== Session State Fetching =====
  async function fetchSessionState() {
    try {
      console.log('[app.js] Fetching session state...');
      const response = await fetch('/me', { credentials: 'include' });
      
      if (!response.ok) {
        console.log('[app.js] No active session (not logged in)');
        return null;
      }

      const data = await response.json();
      
      if (data && data.id) {
        window.currentUser = data;
        console.log('[app.js] Session state loaded:', data.username);
        return data;
      }

      console.log('[app.js] No user data in session');
      return null;
    } catch (error) {
      console.error('[app.js] Failed to fetch session state:', error);
      return null;
    }
  }

  // ===== Bootstrap Application =====
  async function bootstrap() {
    console.log('[app.js] Starting application bootstrap...');

    try {
      // Step 1: Fetch session state (may be null if not logged in)
      await fetchSessionState();
      console.log('[app.js] ✓ Session state checked');

      // Step 2: Initialize Socket.IO ONLY if user is logged in
      // If not logged in, socket will be initialized after successful login by auth.js
      if (window.currentUser) {
        await initializeSocket();
        // Wait for socket to be fully connected before proceeding
        await socketReadyPromise;
        console.log('[app.js] ✓ Socket.IO initialized and connected (user logged in)');
      } else {
        console.log('[app.js] ℹ Socket.IO initialization deferred (user not logged in)');
      }

      // Step 3: Emit custom ready event for other modules
      const readyEvent = new CustomEvent('app:ready', {
        detail: {
          socket: window.socket,
          currentUser: window.currentUser,
          currentRoom: window.currentRoom
        }
      });
      window.dispatchEvent(readyEvent);
      console.log('[app.js] ✓ app:ready event dispatched with verified state');
      
      // Step 4: Resolve app ready promise
      if (appReadyResolve) {
        appReadyResolve({
          socket: window.socket,
          currentUser: window.currentUser,
          currentRoom: window.currentRoom
        });
      }
      console.log('[app.js] ✓ Application bootstrap complete (verified)');

    } catch (error) {
      console.error('[app.js] Bootstrap failed:', error);
      // Error handling is now managed by the connection error logic above
      // No immediate error popup - wait for multiple connection failures
    }
  }

  // ===== Utility: Wait for app:ready =====
  window.waitForAppReady = function() {
    // Return the promise-based gate instead of event listener
    return appReadyPromise;
  };
  
  // ===== Utility: Wait for socket ready =====
  window.waitForSocketReady = function() {
    return socketReadyPromise;
  };

  // ===== PWA Service Worker Registration =====
  if ('serviceWorker' in navigator && window.location.hostname !== 'localhost') {
    const enablePWA = document.querySelector('meta[name="enable-pwa"]')?.content === 'true';
    
    if (enablePWA) {
      window.addEventListener('load', () => {
        navigator.serviceWorker.register('/sw.js')
          .then(registration => {
            console.log('[PWA] Service Worker registered:', registration.scope);
          })
          .catch(err => {
            console.error('[PWA] Service Worker registration failed:', err);
          });
      });
    }
  }

  // ===== Markdown Rendering with DOMPurify =====
  // Note: Using CDN-loaded marked and DOMPurify from index.html
  // These libraries should be loaded before this script runs
  
  /**
   * Render markdown safely with DOMPurify sanitization
   * @param {string} text - Raw markdown text
   * @returns {string} Sanitized HTML
   */
  window.renderMarkdown = function(text) {
    if (!text || typeof text !== 'string') return '';
    
    // Check if marked library is available
    if (typeof marked === 'undefined') {
      console.warn('[Markdown] marked library not loaded, returning plain text');
      return escapeHtml(text);
    }
    
    try {
      // Configure marked for safe rendering
      marked.setOptions({
        breaks: true,
        gfm: true,
        headerIds: false,
        mangle: false
      });
      
      const rawHtml = marked.parse(text);
      
      // Sanitize with DOMPurify if available
      if (typeof DOMPurify !== 'undefined') {
        return DOMPurify.sanitize(rawHtml, {
          ALLOWED_TAGS: ['p', 'br', 'strong', 'em', 'u', 'code', 'pre', 'a', 'ul', 'ol', 'li', 'blockquote', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6'],
          ALLOWED_ATTR: ['href', 'title', 'target', 'rel'],
          ALLOW_DATA_ATTR: false
        });
      }
      
      return rawHtml;
    } catch (err) {
      console.error('[Markdown] Rendering error:', err);
      return escapeHtml(text);
    }
  };

  /**
   * Escape HTML entities for plain text display
   */
  function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  // ===== Emoji Shortcode Replacement =====
  const EMOJI_MAP = {
    ':smile:': '😊',
    ':grin:': '😁',
    ':joy:': '😂',
    ':heart:': '❤️',
    ':fire:': '🔥',
    ':thumbsup:': '👍',
    ':thumbsdown:': '👎',
    ':clap:': '👏',
    ':wave:': '👋',
    ':ok:': '👌',
    ':100:': '💯',
    ':star:': '⭐',
    ':sparkles:': '✨',
    ':tada:': '🎉',
    ':rocket:': '🚀',
    ':eyes:': '👀',
    ':thinking:': '🤔',
    ':shrug:': '🤷',
    ':cool:': '😎',
    ':sunglasses:': '😎',
    ':laughing:': '😆',
    ':wink:': '😉',
    ':blush:': '😊',
    ':kissing_heart:': '😘',
    ':yum:': '😋',
    ':stuck_out_tongue:': '😛',
    ':money_mouth:': '🤑',
    ':nerd:': '🤓',
    ':worried:': '😟',
    ':confused:': '😕',
    ':slightly_frowning:': '🙁',
    ':frowning:': '☹️',
    ':persevere:': '😣',
    ':disappointed:': '😞',
    ':sweat:': '😓',
    ':cry:': '😢',
    ':sob:': '😭',
    ':angry:': '😠',
    ':rage:': '😡',
    ':triumph:': '😤',
    ':sleepy:': '😪',
    ':dizzy:': '😵',
    ':mask:': '😷',
    ':hot:': '🥵',
    ':cold:': '🥶',
    ':woozy:': '🥴',
    ':party:': '🥳',
    ':pleading:': '🥺',
    ':heart_eyes:': '😍',
    ':star_struck:': '🤩'
  };

  /**
   * Replace emoji shortcodes with actual emoji
   * @param {string} text - Text with potential shortcodes
   * @returns {string} Text with emoji replacements
   */
  window.replaceEmojiShortcodes = function(text) {
    if (!text || typeof text !== 'string') return text;
    
    let result = text;
    for (const [shortcode, emoji] of Object.entries(EMOJI_MAP)) {
      result = result.replaceAll(shortcode, emoji);
    }
    return result;
  };

  // ===== Keyboard Shortcuts for Message Input =====
  /**
   * Setup keyboard shortcuts on message input
   * Enter = send, Shift+Enter = newline
   */
  function setupMessageInputShortcuts() {
    // Wait for DOM to be ready
    const checkAndSetup = () => {
      const messageInput = document.getElementById('messageInput') || 
                          document.querySelector('textarea[name="message"]') ||
                          document.querySelector('#chatInput');
      
      if (messageInput && !messageInput.dataset.shortcutsEnabled) {
        messageInput.dataset.shortcutsEnabled = 'true';
        
        messageInput.addEventListener('keydown', (e) => {
          if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            
            // Find and trigger the send button
            const sendButton = document.getElementById('sendBtn') || 
                             document.querySelector('button[type="submit"]') ||
                             messageInput.closest('form')?.querySelector('button[type="submit"]');
            
            if (sendButton) {
              sendButton.click();
            }
          }
          // Shift+Enter allows natural newline behavior
        });
        
        console.log('[Shortcuts] Message input keyboard shortcuts enabled');
      }
    };
    
    // Try immediately
    checkAndSetup();
    
    // Also try after DOM loads
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', checkAndSetup);
    }
    
    // And try after a delay (for dynamic content)
    setTimeout(checkAndSetup, 1000);
    setTimeout(checkAndSetup, 3000);
  }

  setupMessageInputShortcuts();

  // ===== Utility Functions =====
  
  /**
   * Check if socket is connected before performing socket operations
   * Provides a safe guard for all socket-dependent features
   * @returns {boolean} true if socket is connected, false otherwise
   */
  window.isSocketConnected = function() {
    return window.socket && window.socket.connected;
  };

  /**
   * Safely emit socket event with connection check
   * @param {string} event - Event name
   * @param {*} data - Event data
   * @param {Function} ack - Optional acknowledgment callback
   * @returns {boolean} true if emitted, false if socket not connected
   */
  window.safeSocketEmit = function(event, data, ack) {
    if (!window.isSocketConnected()) {
      console.warn('[app.js] Cannot emit', event, '- socket not connected');
      return false;
    }
    if (typeof ack === 'function') {
      window.socket.emit(event, data, ack);
    } else {
      window.socket.emit(event, data);
    }
    return true;
  };
  
  /**
   * Unified method for handling checkbox events
   */
  window.handleCheckboxEvent = function(checkbox, callback) {
    if (checkbox && typeof callback === 'function') {
      checkbox.addEventListener('change', callback);
    }
  };

  /**
   * Validate DOM elements before manipulation
   */
  window.safeSetContent = function(elementId, content) {
    const element = document.getElementById(elementId);
    if (element) {
      if (typeof content === 'string') {
        element.textContent = content;
      } else {
        element.innerHTML = content;
      }
    } else {
      console.warn(`[DOM] Element not found: ${elementId}`);
    }
  };

  // ===== Leaderboard Category Dropdown =====
  function initLeaderboardDropdown() {
    const categorySelect = document.getElementById('leaderboardCategorySelect');
    const leaderboardCards = document.querySelectorAll('.leaderboardCard');
    
    if (!categorySelect || leaderboardCards.length === 0) {
      return; // Elements not found, likely not on leaderboards page
    }
    
    // Handle dropdown change
    categorySelect.addEventListener('change', function() {
      const selectedCategory = this.value;
      
      // Hide all leaderboard cards
      leaderboardCards.forEach(card => {
        card.classList.add('hidden');
      });
      
      // Show only the selected category
      const selectedCard = document.querySelector(`.leaderboardCard[data-leaderboard-category="${selectedCategory}"]`);
      if (selectedCard) {
        selectedCard.classList.remove('hidden');
      }
    });
    
    console.log('[app.js] Leaderboard dropdown initialized');
  }

  // Initialize leaderboard dropdown when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initLeaderboardDropdown);
  } else {
    initLeaderboardDropdown();
  }

  // ===== Start Application Bootstrap =====
  // Bootstrap after DOM is fully loaded to ensure all elements are available
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', bootstrap);
  } else {
    // DOM already loaded, start immediately
    bootstrap();
  }

  console.log('[app.js] Application bootstrap scheduled');

})();
