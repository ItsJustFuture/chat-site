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

  console.log('[app.js] Enhanced client-side features loaded');

})();
