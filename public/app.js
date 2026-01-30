// Enhanced public/app.js - Client-side enhancements for chat

(function() {
  'use strict';

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

  // ===== Auth form handling =====
  function initAuthForm() {
    const authForm = document.getElementById('authForm');
    if (!authForm || authForm.dataset.authBound) return;
    authForm.dataset.authBound = 'true';

    const loginBtn = document.getElementById('loginBtn');
    const regBtn = document.getElementById('regBtn');
    const guestBtn = document.getElementById('guestLoginBtn');
    const authMsg = document.getElementById('authMsg');
    const emailFieldWrap = document.getElementById('emailFieldWrap');

    let mode = 'login'; // 'login' | 'register'

    const setMsg = (text, isError = false) => {
      if (authMsg) {
        authMsg.textContent = text || '';
        authMsg.style.color = isError ? '#ff6b6b' : '';
      }
    };

    const setMode = (next) => {
      mode = next;
      if (emailFieldWrap) emailFieldWrap.hidden = mode !== 'register';
      if (loginBtn) loginBtn.textContent = mode === 'register' ? 'Create account' : 'Join chat';
      if (regBtn) regBtn.textContent = mode === 'register' ? 'Back to login' : 'Create account';
      setMsg('');
    };

    if (regBtn) {
      regBtn.addEventListener('click', () => {
        setMode(mode === 'register' ? 'login' : 'register');
      });
    }

    const doLogin = async (username, password) => {
      const resp = await fetch('/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });
      if (!resp.ok) {
        throw new Error(await resp.text());
      }
      const data = await resp.json();
      if (data?.code === 'PASSWORD_UPGRADE_REQUIRED') {
        window.location.href = '/password-upgrade';
        return;
      }
      if (data?.ok) {
        window.location.reload();
        return;
      }
      throw new Error(data?.message || 'Login failed');
    };

    const doRegister = async (username, email, password) => {
      const resp = await fetch('/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, email, password }),
      });
      if (!resp.ok) {
        throw new Error(await resp.text());
      }
      const data = await resp.json();
      if (data?.ok) {
        window.location.reload();
        return;
      }
      throw new Error(data?.message || 'Registration failed');
    };

    authForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const username = String(document.getElementById('authUser')?.value || '').trim();
      const password = String(document.getElementById('authPass')?.value || '');
      const email = String(document.getElementById('authEmail')?.value || '').trim();

      if (!username || !password) {
        setMsg('Username and password are required.', true);
        return;
      }

      try {
        setMsg(mode === 'register' ? 'Creating account...' : 'Signing in...');
        if (mode === 'register') {
          await doRegister(username, email || null, password);
        } else {
          await doLogin(username, password);
        }
      } catch (err) {
        setMsg(err?.message || 'Something went wrong.', true);
      }
    });

    if (guestBtn) {
      guestBtn.addEventListener('click', async () => {
        const username = String(document.getElementById('authUser')?.value || '').trim();
        if (!username) {
          setMsg('Enter a username to continue as guest.', true);
          return;
        }
        try {
          setMsg('Joining as guest...');
          const resp = await fetch('/guest-login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username }),
          });
          if (!resp.ok) throw new Error(await resp.text());
          const data = await resp.json();
          if (data?.ok) {
            window.location.reload();
            return;
          }
          throw new Error(data?.message || 'Guest login failed');
        } catch (err) {
          setMsg(err?.message || 'Guest login failed.', true);
        }
      });
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initAuthForm);
  } else {
    initAuthForm();
  }

  console.log('[app.js] Enhanced client-side features loaded');

})();
