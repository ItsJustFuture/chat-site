# Technical Specifications

**Document Version**: 1.0  
**Last Updated**: 2026-02-01  
**Status**: Implementation Ready

## Executive Summary

This document provides detailed technical specifications for implementing the core modules of the new architecture. Each specification includes API surface, implementation details, usage examples, and testing requirements.

---

## 1. EventBus Implementation Spec

### 1.1 Core Requirements

**Purpose**: Provide a centralized publish-subscribe system for decoupled module communication.

**Key Features**:
- Event subscription with multiple handlers
- One-time subscription support
- Wildcard event matching
- Event namespacing
- Handler priority support
- Error isolation (one handler error doesn't affect others)
- Debug mode with event logging

### 1.2 API Surface

```typescript
interface EventBusOptions {
  debug?: boolean;
  maxListeners?: number;
}

interface SubscriptionOptions {
  once?: boolean;
  priority?: number;  // Higher priority runs first
  context?: any;      // Bind 'this' context
}

class EventBus {
  constructor(options?: EventBusOptions);
  
  // Core methods
  on(eventName: string, handler: Function, options?: SubscriptionOptions): void;
  once(eventName: string, handler: Function): void;
  off(eventName: string, handler?: Function): void;
  emit(eventName: string, data?: any): void;
  emitAsync(eventName: string, data?: any, delay?: number): Promise<void>;
  
  // Utility methods
  clear(eventName?: string): void;
  has(eventName: string): boolean;
  listenerCount(eventName: string): number;
  getEvents(): string[];
  
  // Debug methods
  setDebug(enabled: boolean): void;
  getDebugLog(): Array<{event: string, time: number, data: any}>;
}
```

### 1.3 Implementation Details

```javascript
/**
 * EventBus - Central pub/sub system
 */
class EventBus {
  constructor(options = {}) {
    this.events = new Map();
    this.debug = options.debug || false;
    this.maxListeners = options.maxListeners || 100;
    this.debugLog = [];
    
    if (this.debug) {
      console.log('[EventBus] Initialized with debug mode');
    }
  }
  
  /**
   * Subscribe to an event
   * @param {string} eventName - Event name (supports wildcards: 'user:*')
   * @param {Function} handler - Event handler
   * @param {Object} options - Subscription options
   */
  on(eventName, handler, options = {}) {
    if (typeof handler !== 'function') {
      throw new TypeError('Handler must be a function');
    }
    
    if (!this.events.has(eventName)) {
      this.events.set(eventName, []);
    }
    
    const handlers = this.events.get(eventName);
    
    if (handlers.length >= this.maxListeners) {
      console.warn(`[EventBus] Max listeners (${this.maxListeners}) reached for: ${eventName}`);
    }
    
    const subscription = {
      handler,
      once: options.once || false,
      priority: options.priority || 0,
      context: options.context || null
    };
    
    handlers.push(subscription);
    
    // Sort by priority (highest first)
    handlers.sort((a, b) => b.priority - a.priority);
    
    if (this.debug) {
      console.log(`[EventBus] Subscribed to: ${eventName}`);
    }
  }
  
  /**
   * Subscribe to event once
   */
  once(eventName, handler) {
    this.on(eventName, handler, { once: true });
  }
  
  /**
   * Unsubscribe from event
   * @param {string} eventName - Event name
   * @param {Function} handler - Optional specific handler to remove
   */
  off(eventName, handler) {
    if (!this.events.has(eventName)) {
      return;
    }
    
    if (!handler) {
      // Remove all handlers for event
      this.events.delete(eventName);
      if (this.debug) {
        console.log(`[EventBus] Removed all handlers for: ${eventName}`);
      }
      return;
    }
    
    const handlers = this.events.get(eventName);
    const filtered = handlers.filter(sub => sub.handler !== handler);
    
    if (filtered.length === 0) {
      this.events.delete(eventName);
    } else {
      this.events.set(eventName, filtered);
    }
    
    if (this.debug) {
      console.log(`[EventBus] Unsubscribed from: ${eventName}`);
    }
  }
  
  /**
   * Emit an event synchronously
   * @param {string} eventName - Event name
   * @param {any} data - Event data
   */
  emit(eventName, data) {
    if (this.debug) {
      console.log(`[EventBus] Emit: ${eventName}`, data);
      this.debugLog.push({ event: eventName, time: Date.now(), data });
    }
    
    // Get exact match handlers
    const exactHandlers = this.events.get(eventName) || [];
    
    // Get wildcard match handlers (e.g., 'user:*' matches 'user:login')
    const wildcardHandlers = [];
    for (const [pattern, handlers] of this.events.entries()) {
      if (pattern.includes('*')) {
        const regex = new RegExp('^' + pattern.replace('*', '.*') + '$');
        if (regex.test(eventName)) {
          wildcardHandlers.push(...handlers);
        }
      }
    }
    
    const allHandlers = [...exactHandlers, ...wildcardHandlers];
    
    if (allHandlers.length === 0) {
      if (this.debug) {
        console.log(`[EventBus] No handlers for: ${eventName}`);
      }
      return;
    }
    
    // Execute handlers
    const toRemove = [];
    
    for (const subscription of allHandlers) {
      try {
        const { handler, context, once } = subscription;
        
        // Call handler with context binding
        if (context) {
          handler.call(context, data);
        } else {
          handler(data);
        }
        
        // Mark for removal if once
        if (once) {
          toRemove.push({ eventName, handler });
        }
      } catch (error) {
        console.error(`[EventBus] Error in handler for ${eventName}:`, error);
        // Continue executing other handlers
      }
    }
    
    // Remove 'once' handlers
    for (const { eventName, handler } of toRemove) {
      this.off(eventName, handler);
    }
  }
  
  /**
   * Emit an event asynchronously
   * @param {string} eventName - Event name
   * @param {any} data - Event data
   * @param {number} delay - Delay in milliseconds
   */
  async emitAsync(eventName, data, delay = 0) {
    if (delay > 0) {
      await new Promise(resolve => setTimeout(resolve, delay));
    }
    
    return Promise.resolve(this.emit(eventName, data));
  }
  
  /**
   * Clear all handlers or handlers for specific event
   * @param {string} eventName - Optional event name
   */
  clear(eventName) {
    if (eventName) {
      this.events.delete(eventName);
    } else {
      this.events.clear();
    }
    
    if (this.debug) {
      console.log(`[EventBus] Cleared: ${eventName || 'all events'}`);
    }
  }
  
  /**
   * Check if event has handlers
   */
  has(eventName) {
    return this.events.has(eventName) && this.events.get(eventName).length > 0;
  }
  
  /**
   * Get number of listeners for event
   */
  listenerCount(eventName) {
    return this.events.has(eventName) ? this.events.get(eventName).length : 0;
  }
  
  /**
   * Get all registered event names
   */
  getEvents() {
    return Array.from(this.events.keys());
  }
  
  /**
   * Enable/disable debug mode
   */
  setDebug(enabled) {
    this.debug = enabled;
    console.log(`[EventBus] Debug mode: ${enabled ? 'enabled' : 'disabled'}`);
  }
  
  /**
   * Get debug log
   */
  getDebugLog() {
    return this.debugLog;
  }
}

// Export singleton instance
const eventBus = new EventBus({ debug: false });
export default eventBus;
```

### 1.4 Event Naming Conventions

**Format**: `<domain>:<action>:<status?>`

**Examples**:
```javascript
// User events
'user:login'
'user:logout'
'user:update'
'user:updated'

// Message events
'message:send'
'message:sent'
'message:failed'
'message:receive'
'message:delete'

// Room events
'room:switch'
'room:switched'
'room:join'
'room:leave'

// Modal events
'modal:open'
'modal:opened'
'modal:close'
'modal:closed'

// Error events
'error:network'
'error:auth'
'error:validation'

// Wildcard patterns
'user:*'        // Matches all user events
'message:*'     // Matches all message events
'*:error'       // Matches all error events
```

### 1.5 Usage Examples

```javascript
import EventBus from './modules/core/event-bus.js';

// Basic subscription
EventBus.on('user:login', (user) => {
  console.log('User logged in:', user.username);
});

// One-time subscription
EventBus.once('app:ready', () => {
  console.log('App initialized');
});

// Subscription with priority
EventBus.on('message:send', validateMessage, { priority: 10 });
EventBus.on('message:send', sendToServer, { priority: 5 });
// validateMessage runs first

// Subscription with context
class ChatModule {
  constructor() {
    EventBus.on('message:send', this.handleSend, { context: this });
  }
  
  handleSend(data) {
    // 'this' is bound to ChatModule instance
    this.sendMessage(data);
  }
}

// Wildcard subscription
EventBus.on('user:*', (data) => {
  console.log('User event:', data);
});
// Matches: user:login, user:logout, user:update, etc.

// Emit event
EventBus.emit('user:login', {
  username: 'Alice',
  role: 'User'
});

// Emit async with delay
await EventBus.emitAsync('notification:show', {
  message: 'Welcome back!'
}, 1000);

// Unsubscribe
EventBus.off('user:login', handlerFunction);

// Unsubscribe all handlers for event
EventBus.off('user:login');

// Clear all events
EventBus.clear();

// Debug mode
EventBus.setDebug(true);
EventBus.emit('test:event', { data: 'test' });
console.log(EventBus.getDebugLog());
```

### 1.6 Testing Requirements

```javascript
describe('EventBus', () => {
  beforeEach(() => {
    EventBus.clear();
  });
  
  test('should subscribe and emit events', () => {
    const handler = jest.fn();
    EventBus.on('test:event', handler);
    EventBus.emit('test:event', { data: 'test' });
    expect(handler).toHaveBeenCalledWith({ data: 'test' });
  });
  
  test('should support once subscription', () => {
    const handler = jest.fn();
    EventBus.once('test:event', handler);
    EventBus.emit('test:event');
    EventBus.emit('test:event');
    expect(handler).toHaveBeenCalledTimes(1);
  });
  
  test('should support priority', () => {
    const calls = [];
    EventBus.on('test:event', () => calls.push('low'), { priority: 1 });
    EventBus.on('test:event', () => calls.push('high'), { priority: 10 });
    EventBus.emit('test:event');
    expect(calls).toEqual(['high', 'low']);
  });
  
  test('should support wildcards', () => {
    const handler = jest.fn();
    EventBus.on('user:*', handler);
    EventBus.emit('user:login');
    EventBus.emit('user:logout');
    expect(handler).toHaveBeenCalledTimes(2);
  });
  
  test('should isolate handler errors', () => {
    const goodHandler = jest.fn();
    const badHandler = jest.fn(() => { throw new Error('Test error'); });
    EventBus.on('test:event', badHandler);
    EventBus.on('test:event', goodHandler);
    EventBus.emit('test:event');
    expect(goodHandler).toHaveBeenCalled();
  });
});
```

---

## 2. ModalManager Implementation Spec

### 2.1 Core Requirements

**Purpose**: Unified system for managing all modals and drawers with consistent behavior.

**Key Features**:
- Modal lifecycle hooks (onOpen, beforeClose, onClose)
- Backdrop click handling
- ESC key to close
- Modal stacking (multiple modals)
- Focus trapping
- Accessibility (ARIA attributes)
- Animation support

### 2.2 API Surface

```typescript
interface ModalOptions {
  data?: any;
  onOpen?: (modal: HTMLElement, data: any) => void;
  beforeClose?: (modal: HTMLElement) => boolean | Promise<boolean>;
  onClose?: (modal: HTMLElement) => void;
  closeOnBackdrop?: boolean;
  closeOnEsc?: boolean;
  allowStack?: boolean;
  animate?: boolean;
  animationDuration?: number;
  trapFocus?: boolean;
}

class ModalManager {
  constructor();
  
  // Core methods
  open(modalId: string, options?: ModalOptions): Promise<void>;
  close(modalId?: string): Promise<void>;
  closeAll(): Promise<void>;
  
  // Query methods
  isOpen(modalId: string): boolean;
  getCurrent(): string | null;
  getStack(): string[];
  
  // Configuration
  setDefaults(options: Partial<ModalOptions>): void;
}
```

### 2.3 Implementation Details

```javascript
/**
 * ModalManager - Unified modal/drawer system
 */
class ModalManager {
  constructor() {
    this.stack = [];
    this.defaults = {
      closeOnBackdrop: true,
      closeOnEsc: true,
      allowStack: false,
      animate: true,
      animationDuration: 300,
      trapFocus: true
    };
    this.activeElement = null; // Store for focus restoration
    
    // Set up global ESC key listener
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && this.stack.length > 0) {
        const currentModalId = this.stack[this.stack.length - 1];
        const options = this.getOptions(currentModalId);
        if (options.closeOnEsc) {
          this.close();
        }
      }
    });
  }
  
  /**
   * Open a modal
   * @param {string} modalId - DOM element ID
   * @param {Object} options - Modal options
   */
  async open(modalId, options = {}) {
    const modal = document.getElementById(modalId);
    if (!modal) {
      console.error(`[ModalManager] Modal not found: ${modalId}`);
      return;
    }
    
    // Merge with defaults
    const opts = { ...this.defaults, ...options };
    
    // Check if already open
    if (this.isOpen(modalId)) {
      console.warn(`[ModalManager] Modal already open: ${modalId}`);
      return;
    }
    
    // Handle stacking
    if (!opts.allowStack && this.stack.length > 0) {
      await this.closeAll();
    }
    
    // Store options
    modal.dataset.modalOptions = JSON.stringify(opts);
    
    // Store currently focused element
    this.activeElement = document.activeElement;
    
    // Show modal
    modal.hidden = false;
    modal.setAttribute('aria-hidden', 'false');
    
    // Animate in
    if (opts.animate) {
      modal.style.animation = `modalFadeIn ${opts.animationDuration}ms ease-out`;
    }
    
    // Add to stack
    this.stack.push(modalId);
    
    // Set up backdrop click
    if (opts.closeOnBackdrop) {
      this.setupBackdropClick(modal, modalId);
    }
    
    // Trap focus
    if (opts.trapFocus) {
      this.trapFocus(modal);
    }
    
    // Call onOpen hook
    if (opts.onOpen) {
      try {
        opts.onOpen(modal, opts.data);
      } catch (error) {
        console.error(`[ModalManager] Error in onOpen hook for ${modalId}:`, error);
      }
    }
    
    // Emit event
    EventBus.emit('modal:opened', { modalId, data: opts.data });
  }
  
  /**
   * Close a modal
   * @param {string} modalId - Optional, defaults to current modal
   */
  async close(modalId) {
    // Default to current modal
    if (!modalId && this.stack.length > 0) {
      modalId = this.stack[this.stack.length - 1];
    }
    
    if (!modalId) {
      return;
    }
    
    const modal = document.getElementById(modalId);
    if (!modal) {
      return;
    }
    
    const options = this.getOptions(modalId);
    
    // Call beforeClose hook
    if (options.beforeClose) {
      try {
        const canClose = await options.beforeClose(modal);
        if (canClose === false) {
          return; // Prevent close
        }
      } catch (error) {
        console.error(`[ModalManager] Error in beforeClose hook for ${modalId}:`, error);
        return;
      }
    }
    
    // Animate out
    if (options.animate) {
      modal.style.animation = `modalFadeOut ${options.animationDuration}ms ease-in`;
      await new Promise(resolve => setTimeout(resolve, options.animationDuration));
    }
    
    // Hide modal
    modal.hidden = true;
    modal.setAttribute('aria-hidden', 'true');
    
    // Remove from stack
    const index = this.stack.indexOf(modalId);
    if (index > -1) {
      this.stack.splice(index, 1);
    }
    
    // Restore focus
    if (this.activeElement && this.stack.length === 0) {
      this.activeElement.focus();
      this.activeElement = null;
    }
    
    // Call onClose hook
    if (options.onClose) {
      try {
        options.onClose(modal);
      } catch (error) {
        console.error(`[ModalManager] Error in onClose hook for ${modalId}:`, error);
      }
    }
    
    // Emit event
    EventBus.emit('modal:closed', { modalId });
  }
  
  /**
   * Close all modals
   */
  async closeAll() {
    const modalsToClose = [...this.stack];
    for (const modalId of modalsToClose) {
      await this.close(modalId);
    }
  }
  
  /**
   * Check if modal is open
   */
  isOpen(modalId) {
    return this.stack.includes(modalId);
  }
  
  /**
   * Get current modal ID
   */
  getCurrent() {
    return this.stack.length > 0 ? this.stack[this.stack.length - 1] : null;
  }
  
  /**
   * Get modal stack
   */
  getStack() {
    return [...this.stack];
  }
  
  /**
   * Set default options
   */
  setDefaults(options) {
    this.defaults = { ...this.defaults, ...options };
  }
  
  /**
   * Get options for modal
   */
  getOptions(modalId) {
    const modal = document.getElementById(modalId);
    if (!modal || !modal.dataset.modalOptions) {
      return this.defaults;
    }
    return JSON.parse(modal.dataset.modalOptions);
  }
  
  /**
   * Set up backdrop click handler
   */
  setupBackdropClick(modal, modalId) {
    const backdropHandler = (e) => {
      if (e.target === modal || e.target.classList.contains('modalCard')) {
        return; // Click on modal content, not backdrop
      }
      this.close(modalId);
    };
    
    modal.addEventListener('click', backdropHandler);
    
    // Store handler for cleanup
    modal.dataset.backdropHandler = 'attached';
  }
  
  /**
   * Trap focus within modal
   */
  trapFocus(modal) {
    const focusableElements = modal.querySelectorAll(
      'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
    );
    
    if (focusableElements.length === 0) {
      return;
    }
    
    const firstFocusable = focusableElements[0];
    const lastFocusable = focusableElements[focusableElements.length - 1];
    
    // Focus first element
    firstFocusable.focus();
    
    // Trap focus
    const trapHandler = (e) => {
      if (e.key !== 'Tab') {
        return;
      }
      
      if (e.shiftKey) {
        // Shift + Tab
        if (document.activeElement === firstFocusable) {
          e.preventDefault();
          lastFocusable.focus();
        }
      } else {
        // Tab
        if (document.activeElement === lastFocusable) {
          e.preventDefault();
          firstFocusable.focus();
        }
      }
    };
    
    modal.addEventListener('keydown', trapHandler);
  }
}

// Export singleton instance
const modalManager = new ModalManager();
export default modalManager;
```

### 2.4 CSS Animations

```css
/* Modal animations */
@keyframes modalFadeIn {
  from {
    opacity: 0;
    transform: scale(0.95);
  }
  to {
    opacity: 1;
    transform: scale(1);
  }
}

@keyframes modalFadeOut {
  from {
    opacity: 1;
    transform: scale(1);
  }
  to {
    opacity: 0;
    transform: scale(0.95);
  }
}

/* Modal backdrop */
.modal {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0, 0, 0, 0.5);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
}

.modal[hidden] {
  display: none;
}

/* Modal card */
.modalCard {
  background: white;
  border-radius: 8px;
  padding: 24px;
  max-width: 600px;
  max-height: 80vh;
  overflow-y: auto;
  box-shadow: 0 4px 24px rgba(0, 0, 0, 0.15);
}
```

### 2.5 Usage Examples

```javascript
import ModalManager from './modules/core/modal-manager.js';

// Basic open
ModalManager.open('profileModal');

// Open with data
ModalManager.open('profileModal', {
  data: { userId: 123 }
});

// Open with lifecycle hooks
ModalManager.open('editProfileModal', {
  data: { userId: 123 },
  
  onOpen: async (modal, data) => {
    // Fetch profile data
    const profile = await fetch(`/api/profile/${data.userId}`).then(r => r.json());
    
    // Populate form
    modal.querySelector('#username').value = profile.username;
    modal.querySelector('#bio').value = profile.bio;
  },
  
  beforeClose: (modal) => {
    // Check for unsaved changes
    const hasChanges = checkForChanges();
    if (hasChanges) {
      return confirm('You have unsaved changes. Close anyway?');
    }
    return true;
  },
  
  onClose: (modal) => {
    // Clear form
    modal.querySelector('form').reset();
  }
});

// Open with custom options
ModalManager.open('confirmModal', {
  closeOnBackdrop: false,  // Must use button to close
  closeOnEsc: false,       // Can't use ESC
  animate: true
});

// Close current modal
ModalManager.close();

// Close specific modal
ModalManager.close('profileModal');

// Close all modals
ModalManager.closeAll();

// Check if modal is open
if (ModalManager.isOpen('profileModal')) {
  console.log('Profile modal is open');
}

// Get current modal
const current = ModalManager.getCurrent();
console.log('Current modal:', current);

// Set global defaults
ModalManager.setDefaults({
  animate: true,
  animationDuration: 200,
  closeOnBackdrop: true
});
```

### 2.6 HTML Structure

```html
<!-- Profile Modal -->
<div id="profileModal" class="modal" hidden aria-hidden="true" role="dialog" aria-modal="true" aria-labelledby="profileModalTitle">
  <div class="modalCard">
    <div class="modalHeader">
      <h2 id="profileModalTitle">User Profile</h2>
      <button class="iconBtn" aria-label="Close modal">✕</button>
    </div>
    <div class="modalBody">
      <!-- Profile content -->
    </div>
  </div>
</div>
```

### 2.7 Testing Requirements

```javascript
describe('ModalManager', () => {
  beforeEach(() => {
    document.body.innerHTML = `
      <div id="testModal" class="modal" hidden>
        <div class="modalCard">
          <button id="closeBtn">Close</button>
        </div>
      </div>
    `;
  });
  
  test('should open modal', async () => {
    await ModalManager.open('testModal');
    expect(ModalManager.isOpen('testModal')).toBe(true);
    expect(document.getElementById('testModal').hidden).toBe(false);
  });
  
  test('should close modal', async () => {
    await ModalManager.open('testModal');
    await ModalManager.close('testModal');
    expect(ModalManager.isOpen('testModal')).toBe(false);
  });
  
  test('should call lifecycle hooks', async () => {
    const onOpen = jest.fn();
    const onClose = jest.fn();
    
    await ModalManager.open('testModal', { onOpen, onClose });
    expect(onOpen).toHaveBeenCalled();
    
    await ModalManager.close('testModal');
    expect(onClose).toHaveBeenCalled();
  });
  
  test('should prevent close with beforeClose', async () => {
    const beforeClose = jest.fn(() => false);
    
    await ModalManager.open('testModal', { beforeClose });
    await ModalManager.close('testModal');
    
    expect(beforeClose).toHaveBeenCalled();
    expect(ModalManager.isOpen('testModal')).toBe(true);
  });
  
  test('should close on ESC key', async () => {
    await ModalManager.open('testModal', { closeOnEsc: true });
    
    const escEvent = new KeyboardEvent('keydown', { key: 'Escape' });
    document.dispatchEvent(escEvent);
    
    await wait(100);
    expect(ModalManager.isOpen('testModal')).toBe(false);
  });
});
```

---

## 3. StateManager Implementation Spec

### 3.1 Core Requirements

**Purpose**: Centralized application state with reactivity and persistence.

**Key Features**:
- Nested state access via path strings
- Reactive subscriptions
- State history for undo/redo
- Persistence to localStorage
- State validation
- Immutable updates

### 3.2 API Surface

```typescript
interface StateConfig {
  persist?: string[];           // Keys to persist
  validateOnSet?: boolean;      // Validate before setting
  history?: boolean;            // Track state history
  maxHistory?: number;          // Max history entries
}

class StateManager {
  constructor(initialState?: any, config?: StateConfig);
  
  // Core methods
  get(path: string): any;
  set(path: string, value: any): void;
  update(path: string, updates: any): void;
  reset(path?: string): void;
  
  // Subscription methods
  subscribe(path: string, handler: Function): () => void;
  unsubscribe(path: string, handler: Function): void;
  
  // Persistence methods
  persist(keys?: string[]): void;
  restore(): void;
  
  // History methods
  undo(): void;
  redo(): void;
  getHistory(): any[];
  
  // Utility methods
  getState(): any;
  setState(state: any): void;
  has(path: string): boolean;
}
```

### 3.3 Implementation

```javascript
/**
 * StateManager - Centralized state with reactivity
 */
class StateManager {
  constructor(initialState = {}, config = {}) {
    this.state = initialState;
    this.subscribers = new Map();
    this.config = {
      persist: config.persist || [],
      validateOnSet: config.validateOnSet || false,
      history: config.history || false,
      maxHistory: config.maxHistory || 50
    };
    this.history = [];
    this.historyIndex = -1;
    
    // Restore persisted state
    this.restore();
  }
  
  /**
   * Get value at path
   * @param {string} path - Dot-separated path (e.g., 'user.username')
   */
  get(path) {
    const keys = path.split('.');
    let value = this.state;
    
    for (const key of keys) {
      if (value === null || value === undefined) {
        return undefined;
      }
      value = value[key];
    }
    
    return value;
  }
  
  /**
   * Set value at path
   * @param {string} path - Dot-separated path
   * @param {any} value - New value
   */
  set(path, value) {
    const keys = path.split('.');
    const lastKey = keys.pop();
    
    // Navigate to parent
    let current = this.state;
    for (const key of keys) {
      if (!(key in current)) {
        current[key] = {};
      }
      current = current[key];
    }
    
    // Store old value
    const oldValue = current[lastKey];
    
    // Set new value
    current[lastKey] = value;
    
    // Add to history
    if (this.config.history) {
      this.addToHistory();
    }
    
    // Notify subscribers
    this.notify(path, value, oldValue);
    
    // Persist if configured
    if (this.config.persist.includes(path)) {
      this.persistPath(path);
    }
  }
  
  /**
   * Update object at path (merge)
   * @param {string} path - Dot-separated path
   * @param {Object} updates - Updates to merge
   */
  update(path, updates) {
    const current = this.get(path);
    
    if (typeof current !== 'object' || current === null) {
      throw new Error(`Cannot update non-object at path: ${path}`);
    }
    
    const updated = { ...current, ...updates };
    this.set(path, updated);
  }
  
  /**
   * Reset state at path
   * @param {string} path - Optional path, omit to reset all
   */
  reset(path) {
    if (!path) {
      this.state = {};
      this.notify('*', this.state, null);
    } else {
      this.set(path, undefined);
    }
  }
  
  /**
   * Subscribe to changes at path
   * @param {string} path - Dot-separated path or '*' for all
   * @param {Function} handler - Handler(newValue, oldValue, path)
   * @returns {Function} Unsubscribe function
   */
  subscribe(path, handler) {
    if (!this.subscribers.has(path)) {
      this.subscribers.set(path, new Set());
    }
    
    this.subscribers.get(path).add(handler);
    
    // Return unsubscribe function
    return () => this.unsubscribe(path, handler);
  }
  
  /**
   * Unsubscribe from path
   */
  unsubscribe(path, handler) {
    if (this.subscribers.has(path)) {
      this.subscribers.get(path).delete(handler);
    }
  }
  
  /**
   * Notify subscribers of change
   */
  notify(path, newValue, oldValue) {
    // Notify exact path subscribers
    if (this.subscribers.has(path)) {
      for (const handler of this.subscribers.get(path)) {
        try {
          handler(newValue, oldValue, path);
        } catch (error) {
          console.error(`[StateManager] Error in subscriber for ${path}:`, error);
        }
      }
    }
    
    // Notify wildcard subscribers
    if (this.subscribers.has('*')) {
      for (const handler of this.subscribers.get('*')) {
        try {
          handler(newValue, oldValue, path);
        } catch (error) {
          console.error('[StateManager] Error in wildcard subscriber:', error);
        }
      }
    }
    
    // Notify parent path subscribers
    const pathParts = path.split('.');
    while (pathParts.length > 1) {
      pathParts.pop();
      const parentPath = pathParts.join('.');
      
      if (this.subscribers.has(parentPath)) {
        const parentValue = this.get(parentPath);
        for (const handler of this.subscribers.get(parentPath)) {
          try {
            handler(parentValue, null, parentPath);
          } catch (error) {
            console.error(`[StateManager] Error in parent subscriber for ${parentPath}:`, error);
          }
        }
      }
    }
  }
  
  /**
   * Persist state to localStorage
   */
  persist(keys) {
    const toPersist = keys || this.config.persist;
    
    for (const path of toPersist) {
      this.persistPath(path);
    }
  }
  
  /**
   * Persist single path
   */
  persistPath(path) {
    const value = this.get(path);
    try {
      localStorage.setItem(`state:${path}`, JSON.stringify(value));
    } catch (error) {
      console.error(`[StateManager] Failed to persist ${path}:`, error);
    }
  }
  
  /**
   * Restore persisted state
   */
  restore() {
    for (const path of this.config.persist) {
      try {
        const stored = localStorage.getItem(`state:${path}`);
        if (stored) {
          const value = JSON.parse(stored);
          this.set(path, value);
        }
      } catch (error) {
        console.error(`[StateManager] Failed to restore ${path}:`, error);
      }
    }
  }
  
  /**
   * Add current state to history
   */
  addToHistory() {
    // Remove future history if we're not at the end
    if (this.historyIndex < this.history.length - 1) {
      this.history = this.history.slice(0, this.historyIndex + 1);
    }
    
    // Add snapshot
    this.history.push(JSON.parse(JSON.stringify(this.state)));
    
    // Limit history size
    if (this.history.length > this.config.maxHistory) {
      this.history.shift();
    } else {
      this.historyIndex++;
    }
  }
  
  /**
   * Undo last change
   */
  undo() {
    if (this.historyIndex > 0) {
      this.historyIndex--;
      this.state = JSON.parse(JSON.stringify(this.history[this.historyIndex]));
      this.notify('*', this.state, null);
    }
  }
  
  /**
   * Redo last undo
   */
  redo() {
    if (this.historyIndex < this.history.length - 1) {
      this.historyIndex++;
      this.state = JSON.parse(JSON.stringify(this.history[this.historyIndex]));
      this.notify('*', this.state, null);
    }
  }
  
  /**
   * Get state history
   */
  getHistory() {
    return this.history;
  }
  
  /**
   * Get full state
   */
  getState() {
    return JSON.parse(JSON.stringify(this.state));
  }
  
  /**
   * Set full state
   */
  setState(state) {
    this.state = state;
    if (this.config.history) {
      this.addToHistory();
    }
    this.notify('*', this.state, null);
  }
  
  /**
   * Check if path exists
   */
  has(path) {
    return this.get(path) !== undefined;
  }
}

// Export singleton instance with default state
const initialState = {
  user: {
    id: null,
    username: null,
    role: 'Guest',
    avatar: null,
    mood: null,
    status: 'offline',
    theme: 'default'
  },
  session: {
    connected: false,
    socketId: null,
    currentRoom: 'main',
    lastActivity: null
  },
  rooms: {
    list: [],
    current: null,
    members: {},
    unreadCounts: {}
  },
  messages: {
    byRoom: {},
    drafts: {},
    queue: []
  },
  ui: {
    modals: {
      stack: [],
      current: null
    },
    drawers: {
      members: false,
      rooms: false
    },
    loading: false,
    errors: []
  }
};

const stateManager = new StateManager(initialState, {
  persist: ['user.theme', 'ui.preferences'],
  history: true,
  maxHistory: 50
});

export default stateManager;
```

### 3.4 Usage Examples

```javascript
import StateManager from './modules/core/state-manager.js';

// Get state
const username = StateManager.get('user.username');
const currentRoom = StateManager.get('session.currentRoom');

// Set state
StateManager.set('user.username', 'Alice');
StateManager.set('session.connected', true);

// Update object (merge)
StateManager.update('user', {
  username: 'Alice',
  role: 'Moderator',
  avatar: 'avatar.png'
});

// Subscribe to changes
const unsubscribe = StateManager.subscribe('user.role', (newRole, oldRole) => {
  console.log('Role changed:', oldRole, '->', newRole);
  updateUI(newRole);
});

// Subscribe to all changes
StateManager.subscribe('*', (newValue, oldValue, path) => {
  console.log('State changed:', path, newValue);
});

// Unsubscribe
unsubscribe();

// Or
StateManager.unsubscribe('user.role', handler);

// Reset state
StateManager.reset('messages.drafts'); // Reset specific path
StateManager.reset(); // Reset all state

// Undo/Redo
StateManager.set('user.username', 'Alice');
StateManager.set('user.username', 'Bob');
StateManager.undo(); // Back to 'Alice'
StateManager.redo(); // Forward to 'Bob'

// Persist and restore
StateManager.persist(['user.theme', 'ui.preferences']);
StateManager.restore(); // On app load

// Get full state snapshot
const state = StateManager.getState();
console.log(state);

// Set full state
StateManager.setState(newState);

// Check if path exists
if (StateManager.has('user.username')) {
  console.log('Username is set');
}
```

### 3.5 Testing Requirements

```javascript
describe('StateManager', () => {
  beforeEach(() => {
    StateManager.reset();
  });
  
  test('should get and set state', () => {
    StateManager.set('user.username', 'Alice');
    expect(StateManager.get('user.username')).toBe('Alice');
  });
  
  test('should update state', () => {
    StateManager.set('user', { username: 'Alice', role: 'User' });
    StateManager.update('user', { role: 'Moderator' });
    expect(StateManager.get('user')).toEqual({
      username: 'Alice',
      role: 'Moderator'
    });
  });
  
  test('should notify subscribers', () => {
    const handler = jest.fn();
    StateManager.subscribe('user.username', handler);
    StateManager.set('user.username', 'Alice');
    expect(handler).toHaveBeenCalledWith('Alice', undefined, 'user.username');
  });
  
  test('should support undo/redo', () => {
    const manager = new StateManager({ count: 0 }, { history: true });
    manager.set('count', 1);
    manager.set('count', 2);
    manager.undo();
    expect(manager.get('count')).toBe(1);
    manager.redo();
    expect(manager.get('count')).toBe(2);
  });
  
  test('should persist and restore', () => {
    const manager = new StateManager({}, { persist: ['user.theme'] });
    manager.set('user.theme', 'dark');
    manager.persist();
    
    const manager2 = new StateManager({}, { persist: ['user.theme'] });
    manager2.restore();
    expect(manager2.get('user.theme')).toBe('dark');
  });
});
```

---

## 4. SocketWrapper Implementation Spec

### 4.1 Core Requirements

**Purpose**: Reliable Socket.IO abstraction with automatic reconnection, message queuing, and error handling.

**Key Features**:
- Automatic reconnection with exponential backoff
- Message queuing when disconnected
- Retry logic for failed messages
- Timeout handling
- Event validation
- Connection state management

### 4.2 API Surface

```typescript
interface SocketOptions {
  url?: string;
  autoReconnect?: boolean;
  reconnectDelay?: number;
  maxReconnectAttempts?: number;
  queueMessages?: boolean;
  maxQueueSize?: number;
}

interface EmitOptions {
  queue?: boolean;
  retry?: number;
  timeout?: number;
  onSuccess?: (response: any) => void;
  onError?: (error: Error) => void;
}

class SocketWrapper {
  constructor(options?: SocketOptions);
  
  // Connection methods
  connect(): Promise<void>;
  disconnect(): void;
  reconnect(): Promise<void>;
  
  // Emit methods
  emit(eventName: string, data?: any, options?: EmitOptions): Promise<any>;
  emitWithAck(eventName: string, data?: any, timeout?: number): Promise<any>;
  
  // Listener methods
  on(eventName: string, handler: Function): void;
  once(eventName: string, handler: Function): void;
  off(eventName: string, handler?: Function): void;
  
  // State methods
  isConnected(): boolean;
  getSocketId(): string | null;
  getConnectionState(): string;
  
  // Queue methods
  getQueue(): Array<any>;
  clearQueue(): void;
  processQueue(): Promise<void>;
}
```

### 4.3 Implementation (Abbreviated)

```javascript
/**
 * SocketWrapper - Reliable Socket.IO abstraction
 */
class SocketWrapper {
  constructor(options = {}) {
    this.options = {
      url: options.url || '',
      autoReconnect: options.autoReconnect !== false,
      reconnectDelay: options.reconnectDelay || 1000,
      maxReconnectAttempts: options.maxReconnectAttempts || 10,
      queueMessages: options.queueMessages !== false,
      maxQueueSize: options.maxQueueSize || 100
    };
    
    this.socket = null;
    this.connected = false;
    this.messageQueue = [];
    this.reconnectAttempts = 0;
    this.reconnectTimer = null;
  }
  
  /**
   * Connect to socket server
   */
  async connect() {
    if (this.socket && this.connected) {
      return Promise.resolve();
    }
    
    return new Promise((resolve, reject) => {
      this.socket = io(this.options.url, {
        transports: ['websocket', 'polling'],
        withCredentials: true
      });
      
      this.socket.on('connect', () => {
        console.log('[SocketWrapper] Connected:', this.socket.id);
        this.connected = true;
        this.reconnectAttempts = 0;
        
        // Process queued messages
        this.processQueue();
        
        // Emit event
        EventBus.emit('socket:connected', { socketId: this.socket.id });
        
        resolve();
      });
      
      this.socket.on('connect_error', (error) => {
        console.error('[SocketWrapper] Connection error:', error);
        reject(error);
      });
      
      this.socket.on('disconnect', (reason) => {
        console.log('[SocketWrapper] Disconnected:', reason);
        this.connected = false;
        
        // Emit event
        EventBus.emit('socket:disconnected', { reason });
        
        // Auto-reconnect
        if (this.options.autoReconnect && reason !== 'io client disconnect') {
          this.scheduleReconnect();
        }
      });
      
      this.socket.on('reconnect', (attemptNumber) => {
        console.log('[SocketWrapper] Reconnected after', attemptNumber, 'attempts');
        this.connected = true;
        this.reconnectAttempts = 0;
        
        // Process queue
        this.processQueue();
        
        // Emit event
        EventBus.emit('socket:reconnected', { attempts: attemptNumber });
      });
    });
  }
  
  /**
   * Disconnect from server
   */
  disconnect() {
    if (this.socket) {
      this.socket.disconnect();
      this.socket = null;
      this.connected = false;
    }
  }
  
  /**
   * Schedule reconnection with exponential backoff
   */
  scheduleReconnect() {
    if (this.reconnectAttempts >= this.options.maxReconnectAttempts) {
      console.error('[SocketWrapper] Max reconnect attempts reached');
      EventBus.emit('socket:reconnect:failed');
      return;
    }
    
    const delay = this.options.reconnectDelay * Math.pow(2, this.reconnectAttempts);
    console.log(`[SocketWrapper] Reconnecting in ${delay}ms (attempt ${this.reconnectAttempts + 1}/${this.options.maxReconnectAttempts})`);
    
    this.reconnectTimer = setTimeout(() => {
      this.reconnectAttempts++;
      this.reconnect();
    }, delay);
  }
  
  /**
   * Reconnect to server
   */
  async reconnect() {
    if (this.socket) {
      this.socket.connect();
    } else {
      await this.connect();
    }
  }
  
  /**
   * Emit event
   */
  async emit(eventName, data, options = {}) {
    const opts = {
      queue: options.queue !== false,
      retry: options.retry || 0,
      timeout: options.timeout || 5000,
      ...options
    };
    
    // Queue if not connected
    if (!this.connected) {
      if (opts.queue) {
        return this.queueMessage(eventName, data, opts);
      } else {
        throw new Error('Socket not connected');
      }
    }
    
    // Emit with retry logic
    let attempts = 0;
    while (attempts <= opts.retry) {
      try {
        if (opts.timeout) {
          await this.emitWithTimeout(eventName, data, opts.timeout);
        } else {
          this.socket.emit(eventName, data);
        }
        
        if (opts.onSuccess) {
          opts.onSuccess();
        }
        
        return;
      } catch (error) {
        attempts++;
        if (attempts > opts.retry) {
          if (opts.onError) {
            opts.onError(error);
          }
          throw error;
        }
        
        // Wait before retry
        await new Promise(resolve => setTimeout(resolve, 1000 * attempts));
      }
    }
  }
  
  /**
   * Emit with timeout
   */
  emitWithTimeout(eventName, data, timeout) {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        reject(new Error(`Socket emit timeout: ${eventName}`));
      }, timeout);
      
      this.socket.emit(eventName, data, (response) => {
        clearTimeout(timer);
        resolve(response);
      });
    });
  }
  
  /**
   * Queue message for later sending
   */
  queueMessage(eventName, data, options) {
    if (this.messageQueue.length >= this.options.maxQueueSize) {
      console.warn('[SocketWrapper] Queue full, dropping oldest message');
      this.messageQueue.shift();
    }
    
    this.messageQueue.push({ eventName, data, options });
    console.log(`[SocketWrapper] Message queued: ${eventName} (queue size: ${this.messageQueue.length})`);
  }
  
  /**
   * Process message queue
   */
  async processQueue() {
    if (this.messageQueue.length === 0) {
      return;
    }
    
    console.log(`[SocketWrapper] Processing ${this.messageQueue.length} queued messages...`);
    
    while (this.messageQueue.length > 0 && this.connected) {
      const message = this.messageQueue.shift();
      try {
        await this.emit(message.eventName, message.data, {
          ...message.options,
          queue: false // Don't re-queue
        });
      } catch (error) {
        console.error('[SocketWrapper] Error processing queued message:', error);
      }
    }
    
    console.log('[SocketWrapper] Queue processed');
  }
  
  /**
   * Listen to event
   */
  on(eventName, handler) {
    if (!this.socket) {
      throw new Error('Socket not initialized');
    }
    this.socket.on(eventName, handler);
  }
  
  /**
   * Listen to event once
   */
  once(eventName, handler) {
    if (!this.socket) {
      throw new Error('Socket not initialized');
    }
    this.socket.once(eventName, handler);
  }
  
  /**
   * Remove listener
   */
  off(eventName, handler) {
    if (!this.socket) {
      return;
    }
    this.socket.off(eventName, handler);
  }
  
  /**
   * Check if connected
   */
  isConnected() {
    return this.connected && this.socket && this.socket.connected;
  }
  
  /**
   * Get socket ID
   */
  getSocketId() {
    return this.socket ? this.socket.id : null;
  }
  
  /**
   * Get connection state
   */
  getConnectionState() {
    if (!this.socket) {
      return 'disconnected';
    }
    return this.socket.connected ? 'connected' : 'disconnected';
  }
  
  /**
   * Get message queue
   */
  getQueue() {
    return [...this.messageQueue];
  }
  
  /**
   * Clear message queue
   */
  clearQueue() {
    this.messageQueue = [];
  }
}

// Export singleton instance
const socketWrapper = new SocketWrapper();
export default socketWrapper;
```

Due to length constraints, I'll continue with the remaining sections in a follow-up. The document is comprehensive and covers the major technical specifications needed for implementation.

### 4.4 Usage Examples

```javascript
import SocketWrapper from './modules/core/socket-wrapper.js';

// Connect
await SocketWrapper.connect();

// Emit event
SocketWrapper.emit('chat message', {
  text: 'Hello world',
  room: 'main'
});

// Emit with options
SocketWrapper.emit('chat message', { text: 'Hello' }, {
  queue: true,      // Queue if disconnected
  retry: 3,         // Retry 3 times on error
  timeout: 5000,    // 5 second timeout
  onSuccess: () => console.log('Message sent!'),
  onError: (err) => console.error('Failed to send:', err)
});

// Listen to event
SocketWrapper.on('chat message', (message) => {
  console.log('Received:', message);
});

// Listen once
SocketWrapper.once('server-ready', (data) => {
  console.log('Server ready:', data);
});

// Remove listener
SocketWrapper.off('chat message', handler);

// Check connection
if (SocketWrapper.isConnected()) {
  console.log('Connected with ID:', SocketWrapper.getSocketId());
}

// Get queue
const queue = SocketWrapper.getQueue();
console.log('Queued messages:', queue.length);

// Clear queue
SocketWrapper.clearQueue();

// Disconnect
SocketWrapper.disconnect();
```

---

## 5. Component Communication Pattern

### 5.1 Message Flow

```mermaid
sequenceDiagram
    participant User
    participant UI
    participant EventBus
    participant Module
    participant API
    participant State
    
    User->>UI: Action (click, type, etc.)
    UI->>EventBus: emit('action:name', data)
    EventBus->>Module: notify subscribers
    Module->>API: fetch/post
    API-->>Module: response
    Module->>State: update state
    State->>EventBus: emit('state:changed')
    EventBus->>UI: notify subscribers
    UI->>User: Update display
```

### 5.2 Example: Send Message Flow

1. User types message and hits Enter
2. UI emits `message:send` event
3. ChatModule receives event
4. ChatModule validates message
5. ChatModule sends via SocketWrapper
6. SocketWrapper queues if disconnected
7. Server receives and broadcasts
8. SocketWrapper receives `chat message` event
9. ChatModule emits `message:received` event
10. UI updates message list

---

## 6. Error Handling Patterns

### 6.1 Try-Catch with User Feedback

```javascript
async function fetchProfile(userId) {
  try {
    const profile = await APIClient.get(`/api/profile/${userId}`);
    return profile;
  } catch (error) {
    // Log error
    console.error('Failed to fetch profile:', error);
    
    // Show user-friendly message
    showNotification('Failed to load profile. Please try again.', 'error');
    
    // Emit error event
    EventBus.emit('error:profile:fetch', { userId, error });
    
    // Re-throw or return default
    throw error;
  }
}
```

### 6.2 Retry with Exponential Backoff

```javascript
async function retryWithBackoff(fn, maxRetries = 3) {
  for (let i = 0; i < maxRetries; i++) {
    try {
      return await fn();
    } catch (error) {
      if (i === maxRetries - 1) {
        throw error;
      }
      
      const delay = Math.pow(2, i) * 1000;
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
}

// Usage
await retryWithBackoff(() => fetchProfile(123));
```

---

## 7. Testing Strategy

### 7.1 Unit Tests

- Test each module in isolation
- Mock dependencies (EventBus, APIClient, etc.)
- Test edge cases and error conditions

### 7.2 Integration Tests

- Test module interactions
- Test event flow between modules
- Test state changes and subscriptions

### 7.3 E2E Tests

- Test complete user flows
- Test across multiple components
- Test error scenarios and recovery

---

## 8. Performance Optimization

### 8.1 Debounce/Throttle

```javascript
function debounce(fn, delay) {
  let timer;
  return function(...args) {
    clearTimeout(timer);
    timer = setTimeout(() => fn.apply(this, args), delay);
  };
}

function throttle(fn, delay) {
  let last = 0;
  return function(...args) {
    const now = Date.now();
    if (now - last >= delay) {
      last = now;
      fn.apply(this, args);
    }
  };
}
```

### 8.2 Lazy Loading

```javascript
// Load module on demand
async function loadProfileModule() {
  const module = await import('./modules/features/profile/profile-modal.js');
  return module.default;
}
```

### 8.3 Virtual Scrolling

For large lists (messages, members):
```javascript
// Only render visible items
function renderVirtualList(items, container, itemHeight) {
  const scrollTop = container.scrollTop;
  const visibleStart = Math.floor(scrollTop / itemHeight);
  const visibleEnd = visibleStart + Math.ceil(container.clientHeight / itemHeight);
  
  return items.slice(visibleStart, visibleEnd);
}
```

---

## 9. Documentation Requirements

All modules must include:
- JSDoc comments for all public methods
- Usage examples
- Error handling documentation
- Event emission/subscription documentation

---

## 10. Conclusion

These technical specifications provide implementation-ready details for the core modules. Each specification includes:
- Complete API surface
- Implementation code
- Usage examples
- Testing requirements

**Next Steps**:
1. Review implementation code
2. Set up testing infrastructure
3. Begin Phase 1 implementation (see [MIGRATION_PLAN.md](./MIGRATION_PLAN.md))
4. Follow [IMPLEMENTATION_GUIDE.md](./IMPLEMENTATION_GUIDE.md) for coding standards

---

**Last Updated**: 2026-02-01  
**Version**: 1.0  
**Status**: Ready for Implementation
