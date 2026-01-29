# Client-Side Integration Guide

## Overview

This guide explains how to integrate the new markdown rendering, emoji support, PWA features, and error tracking into the chat application's client-side code.

## Prerequisites

The following libraries are now loaded via CDN in `public/index.html`:
- **marked.js** (v15.0.6) - Markdown parsing
- **DOMPurify** (v3.2.3) - HTML sanitization
- **Sentry Browser SDK** (v8.45.0) - Optional error tracking
- **chat-utils.js** - Our custom utilities

## Available Utilities

The `window.ChatUtils` object provides the following functions:

### 1. Message Rendering

```javascript
// Render message text with markdown and emoji support
const html = ChatUtils.renderMessageText(messageText, {
  enableMarkdown: true,  // Convert markdown to HTML
  enableEmoji: true,     // Replace :emoji: shortcodes
  sanitize: true,        // Sanitize HTML output (recommended)
});

// Insert into DOM
messageElement.innerHTML = html;
```

### 2. Emoji Replacement Only

```javascript
// Just replace emoji shortcodes without markdown
const textWithEmoji = ChatUtils.replaceEmojiShortcodes(":smile: Hello :heart:");
// Returns: "😄 Hello ❤️"
```

### 3. Message Input Enhancement

```javascript
// Setup message input to use Enter for send, Shift+Enter for newline
const msgInput = document.getElementById('msgInput');

ChatUtils.setupMessageInput(msgInput, (text) => {
  // This callback is called when user presses Enter
  // Send the message via socket
  socket.emit('chat message', {
    room: currentRoom,
    text: text
  });
});
```

**Note:** If using an `<input>` element, consider converting it to a `<textarea>` to support multiline messages with Shift+Enter.

### 4. Check for Markdown

```javascript
// Check if text contains markdown syntax
if (ChatUtils.hasMarkdownSyntax(text)) {
  // Render as markdown
} else {
  // Render as plain text
}
```

### 5. Escape HTML

```javascript
// Safely escape HTML special characters
const safe = ChatUtils.escapeHtml(userInput);
```

## Integration Examples

### Receiving and Displaying Messages

```javascript
socket.on('chat message', (msg) => {
  // Create message element
  const msgDiv = document.createElement('div');
  msgDiv.className = 'msgItem';
  
  // Create message text container
  const textDiv = document.createElement('div');
  textDiv.className = 'text';
  
  // Render message with markdown and emoji
  textDiv.innerHTML = ChatUtils.renderMessageText(msg.text);
  
  // Add to DOM
  msgDiv.appendChild(textDiv);
  chatContainer.appendChild(msgDiv);
});
```

### Sending Messages

```javascript
// Get message input element
const msgInput = document.getElementById('msgInput');
const sendBtn = document.getElementById('sendBtn');

// Setup Enter key handling
ChatUtils.setupMessageInput(msgInput, (text) => {
  sendMessage(text);
});

// Setup send button
sendBtn.addEventListener('click', () => {
  const text = msgInput.value.trim();
  if (text) {
    sendMessage(text);
    msgInput.value = '';
  }
});

function sendMessage(text) {
  // Send via socket
  socket.emit('chat message', {
    room: getCurrentRoom(),
    text: text
  });
}
```

## PWA Support

### Automatic Registration

Service worker registration happens automatically when:
1. Service workers are supported by the browser
2. The site is in production (not localhost), OR
3. The `<meta name="enable-pwa" content="1">` tag is present in the HTML

To enable PWA in development:
```html
<meta name="enable-pwa" content="1">
```

### Server-Side Configuration

Update your server to inject the PWA meta tag based on environment:

```javascript
// In server.js, when serving index.html
if (process.env.ENABLE_PWA === '1' && !IS_DEV_MODE) {
  html = html.replace(
    '<!-- <meta name="enable-pwa" content="1"> -->',
    '<meta name="enable-pwa" content="1">'
  );
}
```

### Manual Service Worker Control

```javascript
// Check if service worker is active
if ('serviceWorker' in navigator) {
  navigator.serviceWorker.ready.then((registration) => {
    console.log('Service worker active:', registration);
  });
}

// Manually check for updates
navigator.serviceWorker.register('/sw.js').then((registration) => {
  registration.update();
});
```

## Sentry Error Tracking

### Automatic Initialization

Sentry initializes automatically if the `<meta name="sentry-dsn">` tag is present.

### Server-Side Configuration

Inject the Sentry DSN meta tag based on environment:

```javascript
// In server.js
if (process.env.SENTRY_DSN) {
  html = html.replace(
    '<!-- <meta name="sentry-dsn" content="your-sentry-dsn"> -->',
    `<meta name="sentry-dsn" content="${process.env.SENTRY_DSN}">`
  );
}
```

### Manual Error Capture

```javascript
// Capture exceptions manually
try {
  // Some code that might throw
} catch (err) {
  if (typeof Sentry !== 'undefined') {
    Sentry.captureException(err);
  }
  console.error('Error:', err);
}

// Add context
if (typeof Sentry !== 'undefined') {
  Sentry.setUser({ id: userId, username: username });
  Sentry.setContext('room', { name: currentRoom });
}
```

## Emoji Shortcodes

### Supported Shortcodes

The system supports 60+ common emoji shortcodes. Examples:

**Faces:** `:smile:` `:grin:` `:joy:` `:heart_eyes:` `:thinking:` `:cry:` `:sunglasses:`

**Hearts:** `:heart:` `:purple_heart:` `:blue_heart:` `:green_heart:` `:broken_heart:`

**Hands:** `:thumbsup:` `:thumbsdown:` `:clap:` `:pray:` `:wave:` `:muscle:`

**Symbols:** `:fire:` `:star:` `:100:` `:trophy:` `:rocket:` `:sparkles:`

**Items:** `:pizza:` `:coffee:` `:beer:` `:cake:` `:rainbow:`

### Get All Supported Emoji

```javascript
// Get the full emoji map
const allEmoji = ChatUtils.EMOJI_MAP;

// Get all shortcodes
const shortcodes = Object.keys(allEmoji);
```

## Markdown Support

### Supported Syntax

The markdown renderer supports:

- **Bold:** `**text**` or `__text__`
- *Italic:* `*text*` or `_text_`
- ~~Strikethrough:~~ `~~text~~`
- `Inline code:` `` `code` ``
- Code blocks: ` ```code``` `
- Links: `[text](url)`
- Lists: `- item` or `1. item`
- Blockquotes: `> quote`
- Headings: `# H1` through `###### H6`
- Horizontal rules: `---` or `***`

### Security

All markdown output is automatically sanitized with DOMPurify to prevent XSS attacks. The following are blocked:
- `<script>` tags
- `javascript:` URLs
- Event handlers (`onclick`, etc.)
- Data URIs (except images)
- Dangerous HTML elements

## Testing

### Unit Tests

Tests are available in `tests/markdown-renderer.test.js`:

```bash
npm run test:unit
```

### Manual Testing

```javascript
// Test markdown rendering
console.log(ChatUtils.renderMessageText('**bold** and *italic*'));

// Test emoji replacement
console.log(ChatUtils.replaceEmojiShortcodes('Hello :smile: :heart:'));

// Test XSS protection
console.log(ChatUtils.renderMessageText('<script>alert("xss")</script>'));
// Output: &lt;script&gt;alert("xss")&lt;/script&gt;
```

## Performance Considerations

1. **Markdown Detection:** The `hasMarkdownSyntax()` function checks for markdown patterns before rendering. Plain text messages skip markdown parsing for better performance.

2. **Sanitization:** DOMPurify adds minimal overhead (~1-2ms for typical messages). Consider caching rendered messages if displaying the same message multiple times.

3. **Emoji Replacement:** Uses simple string split/join for each shortcode. Performance is good for messages with <10 emoji shortcodes.

## Browser Compatibility

- **Markdown/Emoji:** All modern browsers (Chrome, Firefox, Safari, Edge)
- **Service Workers:** Chrome 40+, Firefox 44+, Safari 11.1+, Edge 17+
- **DOMPurify:** All browsers with ES5 support

## Migration Notes

### Existing Messages

Existing messages in the database don't need migration. They will render correctly:
- Messages without markdown syntax will display as plain text
- Emoji shortcodes will be replaced on the fly
- HTML will be escaped for safety

### Backwards Compatibility

The utilities are designed to degrade gracefully:
- If marked.js fails to load, messages render as escaped plain text
- If DOMPurify fails to load, HTML is escaped instead of sanitized
- If emoji shortcodes aren't recognized, they display as-is (`:smile:`)

## Troubleshooting

### Markdown not rendering

1. Check that marked.js loaded: `typeof marked !== 'undefined'`
2. Check that DOMPurify loaded: `typeof DOMPurify !== 'undefined'`
3. Check browser console for errors

### Service worker not registering

1. Ensure HTTPS (service workers require secure context)
2. Check that `/sw.js` is accessible
3. Check browser console for registration errors
4. Verify `enable-pwa` meta tag if in development

### Emoji not displaying

1. Ensure the shortcode is in `ChatUtils.EMOJI_MAP`
2. Check that the font supports the emoji character
3. Verify emoji replacement is enabled: `ChatUtils.renderMessageText(text, { enableEmoji: true })`

## See Also

- Server-side markdown: `markdown-renderer.js`
- Server-side emoji: `emoji-utils.js`
- Service worker: `public/sw.js`
- PWA manifest: `public/manifest.json`
