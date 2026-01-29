/**
 * Client-side Markdown and Emoji Utilities
 * 
 * This module provides client-side markdown rendering and emoji replacement
 * for the Banter & Brats chat application.
 * 
 * Dependencies: marked.js and DOMPurify (loaded via CDN or bundled)
 */

(function (window) {
  'use strict';

  // Emoji shortcode map (subset of most common emoji)
  const EMOJI_MAP = {
    ':smile:': '😄', ':grin:': '😁', ':joy:': '😂', ':rofl:': '🤣',
    ':smiley:': '😃', ':laughing:': '😆', ':wink:': '😉', ':blush:': '😊',
    ':heart_eyes:': '😍', ':kissing_heart:': '😘', ':thinking:': '🤔',
    ':neutral_face:': '😐', ':expressionless:': '😑', ':unamused:': '😒',
    ':smirk:': '😏', ':cry:': '😢', ':sob:': '😭', ':angry:': '😠',
    ':rage:': '😡', ':confused:': '😕', ':worried:': '😟', ':flushed:': '😳',
    ':scream:': '😱', ':cold_sweat:': '😰', ':disappointed:': '😞',
    ':sunglasses:': '😎', ':nerd_face:': '🤓', ':pleading_face:': '🥺',
    ':partying_face:': '🥳', ':yawn:': '🥱',
    
    // Hearts
    ':heart:': '❤️', ':orange_heart:': '🧡', ':yellow_heart:': '💛',
    ':green_heart:': '💚', ':blue_heart:': '💙', ':purple_heart:': '💜',
    ':brown_heart:': '🤎', ':black_heart:': '🖤', ':white_heart:': '🤍',
    ':broken_heart:': '💔', ':sparkling_heart:': '💖', ':two_hearts:': '💕',
    
    // Hands
    ':thumbsup:': '👍', ':thumbsdown:': '👎', ':ok_hand:': '👌',
    ':punch:': '👊', ':fist:': '✊', ':v:': '✌️', ':wave:': '👋',
    ':raised_hand:': '✋', ':clap:': '👏', ':pray:': '🙏',
    ':muscle:': '💪', ':handshake:': '🤝',
    
    // Symbols
    ':star:': '⭐', ':sparkles:': '✨', ':fire:': '🔥', ':100:': '💯',
    ':trophy:': '🏆', ':crown:': '👑', ':checkmark:': '✔️', ':check:': '✅',
    ':x:': '❌', ':warning:': '⚠️', ':exclamation:': '❗', ':question:': '❓',
    ':rocket:': '🚀', ':bulb:': '💡', ':boom:': '💥', ':zzz:': '💤',
    
    // Common items
    ':pizza:': '🍕', ':hamburger:': '🍔', ':cake:': '🍰', ':coffee:': '☕',
    ':beer:': '🍺', ':wine_glass:': '🍷', ':cocktail:': '🍹',
    ':rainbow:': '🌈', ':sun:': '☀️', ':moon:': '🌙', ':star2:': '🌟',
    ':snowflake:': '❄️', ':fire:': '🔥', ':ocean:': '🌊',
  };

  /**
   * Replace emoji shortcodes with actual emoji in text
   */
  function replaceEmojiShortcodes(text) {
    if (!text || typeof text !== 'string') return text;
    
    let result = text;
    for (const [shortcode, emoji] of Object.entries(EMOJI_MAP)) {
      result = result.split(shortcode).join(emoji);
    }
    return result;
  }

  /**
   * Check if text contains markdown syntax
   */
  function hasMarkdownSyntax(text) {
    if (!text || typeof text !== 'string') return false;
    
    const patterns = [
      /\*\*.+?\*\*/,           // **bold**
      /\*.+?\*/,               // *italic*
      /~~.+?~~/,               // ~~strike~~
      /`[^`]+`/,               // `code`
      /```[\s\S]+?```/,        // ```code block```
      /^\s*[-*+]\s/m,          // - list
      /^\s*\d+\.\s/m,          // 1. list
      /^\s*>\s/m,              // > quote
      /^\s*#{1,6}\s/m,         // # heading
      /\[.+?\]\(.+?\)/,        // [link](url)
    ];
    
    return patterns.some(p => p.test(text));
  }

  /**
   * Escape HTML to prevent XSS
   */
  function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  /**
   * Render markdown with emoji support (client-side)
   * Requires: marked.js and DOMPurify to be loaded
   */
  function renderMessageText(text, options = {}) {
    if (!text || typeof text !== 'string') return '';
    
    const {
      enableMarkdown = true,
      enableEmoji = true,
      sanitize = true,
    } = options;
    
    let result = text;
    
    // Step 1: Replace emoji shortcodes
    if (enableEmoji) {
      result = replaceEmojiShortcodes(result);
    }
    
    // Step 2: Render markdown if enabled and syntax detected
    if (enableMarkdown && hasMarkdownSyntax(result)) {
      // Check if marked and DOMPurify are available
      if (typeof marked !== 'undefined' && typeof DOMPurify !== 'undefined') {
        try {
          // Configure marked
          marked.setOptions({
            breaks: true,  // Convert \n to <br>
            gfm: true,     // GitHub Flavored Markdown
            headerIds: false,
            mangle: false,
          });
          
          // Render markdown
          const html = marked.parse(result);
          
          // Sanitize HTML
          if (sanitize) {
            result = DOMPurify.sanitize(html, {
              ALLOWED_TAGS: [
                'p', 'br', 'strong', 'em', 'u', 's', 'code', 'pre',
                'a', 'ul', 'ol', 'li', 'blockquote', 
                'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
                'hr', 'del', 'ins'
              ],
              ALLOWED_ATTR: ['href', 'title', 'class'],
              ALLOW_DATA_ATTR: false,
            });
          } else {
            result = html;
          }
        } catch (err) {
          console.warn('[Markdown] Rendering failed:', err);
          // Fall back to escaped text
          result = escapeHtml(result);
        }
      } else {
        console.warn('[Markdown] marked or DOMPurify not loaded');
        result = escapeHtml(result);
      }
    } else {
      // No markdown, just escape HTML
      result = escapeHtml(result);
    }
    
    return result;
  }

  /**
   * Handle Enter key to send message, Shift+Enter for newline
   */
  function setupMessageInput(inputElement, sendCallback) {
    if (!inputElement || typeof sendCallback !== 'function') {
      console.error('[Input] Invalid arguments for setupMessageInput');
      return;
    }
    
    // Handle keyboard events
    inputElement.addEventListener('keydown', (e) => {
      // Enter without shift = send message
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        const text = inputElement.value.trim();
        if (text) {
          sendCallback(text);
          inputElement.value = '';
        }
        return;
      }
      
      // Shift+Enter = insert newline (default behavior for textarea)
      // For input elements, we need to convert to textarea or handle differently
      if (e.key === 'Enter' && e.shiftKey) {
        // If this is an <input>, we can't support multiline
        // This would require converting to <textarea>
        if (inputElement.tagName === 'INPUT') {
          e.preventDefault();
          console.warn('[Input] Multi-line not supported with <input>. Consider using <textarea>.');
        }
        // For textarea, default behavior allows newline
      }
    });
  }

  /**
   * Register service worker for PWA support
   */
  function registerServiceWorker() {
    // Only register if:
    // 1. Service workers are supported
    // 2. We're in production (not localhost) OR explicitly enabled
    // 3. ENABLE_PWA meta tag is set
    
    if (!('serviceWorker' in navigator)) {
      console.log('[PWA] Service workers not supported');
      return;
    }
    
    const enablePWA = document.querySelector('meta[name="enable-pwa"]');
    const isProduction = window.location.hostname !== 'localhost' && 
                        window.location.hostname !== '127.0.0.1';
    
    if (!isProduction && (!enablePWA || enablePWA.content !== '1')) {
      console.log('[PWA] Service worker registration skipped (not enabled)');
      return;
    }
    
    window.addEventListener('load', () => {
      navigator.serviceWorker
        .register('/sw.js')
        .then((registration) => {
          console.log('[PWA] Service worker registered:', registration.scope);
          
          // Check for updates
          registration.addEventListener('updatefound', () => {
            const newWorker = registration.installing;
            console.log('[PWA] Service worker update found');
            
            newWorker.addEventListener('statechange', () => {
              if (newWorker.state === 'installed' && navigator.serviceWorker.controller) {
                // New service worker available
                console.log('[PWA] New content available, refresh to update');
                // Optionally show a notification to the user
              }
            });
          });
        })
        .catch((err) => {
          console.warn('[PWA] Service worker registration failed:', err);
        });
    });
  }

  /**
   * Initialize Sentry for client-side error tracking (optional)
   */
  function initSentry() {
    const sentryDSN = document.querySelector('meta[name="sentry-dsn"]');
    if (!sentryDSN || !sentryDSN.content) {
      return;
    }
    
    // Check if Sentry SDK is loaded
    if (typeof Sentry !== 'undefined' && typeof Sentry.init === 'function') {
      try {
        Sentry.init({
          dsn: sentryDSN.content,
          environment: window.location.hostname === 'localhost' ? 'development' : 'production',
          integrations: [
            new Sentry.BrowserTracing(),
          ],
          tracesSampleRate: 0.1,
        });
        console.log('[Sentry] Initialized for client-side error tracking');
      } catch (err) {
        console.warn('[Sentry] Failed to initialize:', err);
      }
    }
  }

  // Export utilities to window
  window.ChatUtils = {
    replaceEmojiShortcodes,
    hasMarkdownSyntax,
    escapeHtml,
    renderMessageText,
    setupMessageInput,
    registerServiceWorker,
    initSentry,
    EMOJI_MAP,
  };

  // Auto-initialize on load
  document.addEventListener('DOMContentLoaded', () => {
    // Initialize Sentry if configured
    initSentry();
    
    // Register service worker if enabled
    registerServiceWorker();
    
    console.log('[ChatUtils] Markdown and emoji utilities loaded');
    console.log('[ChatUtils] Use ChatUtils.renderMessageText(text) to render messages');
  });

})(window);
