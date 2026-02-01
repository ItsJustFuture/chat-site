# Implementation Guide

**Document Version**: 1.0  
**Last Updated**: 2026-02-01  
**Status**: Active

## Executive Summary

This guide provides coding standards, git workflow, review processes, documentation requirements, and testing standards for implementing the new architecture. All team members must follow these guidelines to ensure consistency, quality, and maintainability.

---

## 1. Code Style Guide

### 1.1 General Principles

**SOLID Principles**:
- **S**ingle Responsibility: Each module/class has one purpose
- **O**pen/Closed: Open for extension, closed for modification
- **L**iskov Substitution: Subtypes must be substitutable for base types
- **I**nterface Segregation: Many specific interfaces over one general
- **D**ependency Inversion: Depend on abstractions, not concretions

**DRY (Don't Repeat Yourself)**:
- Extract common logic into utilities
- Create reusable components
- Avoid copy-paste code

**KISS (Keep It Simple, Stupid)**:
- Simple solutions over clever ones
- Clear over concise
- Readable over performant (unless performance critical)

### 1.2 JavaScript/ES6+ Style

**Naming Conventions**:
```javascript
// Classes: PascalCase
class EventBus {}
class ModalManager {}

// Functions/Methods: camelCase
function handleMessage() {}
const processQueue = () => {};

// Constants: UPPER_SNAKE_CASE
const MAX_RETRIES = 3;
const API_BASE_URL = 'https://api.example.com';

// Variables: camelCase
let currentUser = null;
const messageQueue = [];

// Private members: prefix with underscore
class MyClass {
  _privateMethod() {}
  _privateProperty = null;
}

// Boolean variables: is/has/should prefix
let isConnected = false;
const hasPermission = true;
const shouldRetry = false;

// Event names: namespace:action:status
'user:login'
'message:send'
'message:sent'
'modal:open'
```

**Code Formatting**:
```javascript
// Use 2 spaces for indentation
function example() {
  if (condition) {
    doSomething();
  }
}

// Use semicolons
const x = 5;

// Use single quotes for strings
const message = 'Hello world';

// Use template literals for interpolation
const greeting = `Hello ${username}!`;

// Destructure when possible
const { username, role } = user;
const [first, second] = array;

// Use arrow functions for callbacks
items.map(item => item.id);
items.filter(item => item.active);

// Use async/await over promises
async function fetchData() {
  const response = await fetch(url);
  const data = await response.json();
  return data;
}

// Use const by default, let when reassigning
const immutable = 'value';
let mutable = 0;
mutable++;

// Avoid var
// ❌ var x = 5;
// ✅ const x = 5;
```

**ESLint Configuration**:
```javascript
// .eslintrc.js
module.exports = {
  extends: ['eslint:recommended'],
  env: {
    browser: true,
    es2021: true,
    node: true
  },
  parserOptions: {
    ecmaVersion: 12,
    sourceType: 'module'
  },
  rules: {
    'indent': ['error', 2],
    'quotes': ['error', 'single'],
    'semi': ['error', 'always'],
    'no-unused-vars': 'error',
    'no-console': 'warn',
    'complexity': ['error', 10],
    'max-lines': ['warn', 300],
    'max-params': ['warn', 4]
  }
};
```

### 1.3 File Organization

**File Structure**:
```javascript
/**
 * File header comment
 * Brief description of file purpose
 */

// 1. Imports
import { EventBus } from './event-bus.js';
import { StateManager } from './state-manager.js';

// 2. Constants
const MAX_RETRY = 3;
const TIMEOUT = 5000;

// 3. Class/Module Definition
class MyModule {
  constructor() {
    // Initialize
  }
  
  // Public methods
  publicMethod() {}
  
  // Private methods (prefixed with _)
  _privateMethod() {}
}

// 4. Export
export default MyModule;
```

**Module Pattern**:
```javascript
// Use ES6 modules
// ✅ Good
export class MyClass {}
export function myFunction() {}
export const myConstant = 5;

// ❌ Bad (CommonJS)
module.exports = MyClass;
```

---

## 2. Git Workflow

### 2.1 Branch Strategy

**Main Branches**:
- `main` - Production code, always stable
- `develop` - Integration branch for features

**Supporting Branches**:
- `feature/*` - New features
- `bugfix/*` - Bug fixes
- `hotfix/*` - Critical production fixes
- `refactor/*` - Code refactoring

**Branch Naming**:
```bash
# Features
feature/phase1-core-modules
feature/phase2-modal-system
feature/add-notification-system

# Bug fixes
bugfix/fix-message-queue
bugfix/profile-modal-tabs

# Hotfixes
hotfix/critical-socket-error
hotfix/message-loss-issue

# Refactoring
refactor/extract-api-client
refactor/simplify-state-manager
```

**Branch Lifecycle**:
```bash
# Create feature branch from develop
git checkout develop
git pull origin develop
git checkout -b feature/my-feature

# Work on feature
git add .
git commit -m "feat: implement feature"

# Keep branch updated
git fetch origin
git rebase origin/develop

# Push to remote
git push origin feature/my-feature

# Create pull request
# (via GitHub UI)

# After merge, delete branch
git checkout develop
git pull origin develop
git branch -d feature/my-feature
```

### 2.2 Commit Message Format

**Format**:
```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types**:
- `feat`: New feature
- `fix`: Bug fix
- `refactor`: Code refactoring (no functionality change)
- `test`: Adding or updating tests
- `docs`: Documentation changes
- `style`: Code style changes (formatting, semicolons, etc.)
- `chore`: Maintenance tasks (build, dependencies, etc.)
- `perf`: Performance improvements

**Examples**:
```bash
# Feature
git commit -m "feat(modal): implement modal stacking"

# Bug fix
git commit -m "fix(chat): resolve message queue processing issue"

# Refactor
git commit -m "refactor(state): extract state validation logic"

# Test
git commit -m "test(event-bus): add subscription cleanup tests"

# Documentation
git commit -m "docs(readme): update installation instructions"
```

**Detailed Commit**:
```
feat(modal-manager): implement modal lifecycle hooks

- Add onOpen, beforeClose, onClose hooks
- Implement hook execution with error handling
- Add tests for lifecycle hooks
- Update documentation with examples

Closes #123
```

**Commit Guidelines**:
- Use imperative mood ("add feature" not "added feature")
- Keep subject line under 72 characters
- Separate subject from body with blank line
- Explain what and why, not how
- Reference issues (Closes #123, Refs #456)

### 2.3 Pull Request Process

**Creating a Pull Request**:
1. Ensure branch is up to date with develop
2. Run all tests locally
3. Run linter and fix all warnings
4. Write descriptive PR title and description
5. Add screenshots for UI changes
6. Link related issues
7. Request review from team members

**PR Template**:
```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Refactoring
- [ ] Documentation update

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] E2E tests added/updated
- [ ] Manual testing completed

## Screenshots (if applicable)
[Add screenshots here]

## Checklist
- [ ] Code follows style guide
- [ ] All tests pass
- [ ] Linter warnings resolved
- [ ] Documentation updated
- [ ] No console errors
- [ ] Reviewed own code

## Related Issues
Closes #123
Refs #456
```

**PR Review Checklist** (for reviewers):
- [ ] Code follows architecture patterns
- [ ] Tests are comprehensive
- [ ] No obvious bugs or edge cases missed
- [ ] Performance considerations addressed
- [ ] Security considerations addressed
- [ ] Documentation is clear and complete
- [ ] No unnecessary code duplication
- [ ] Error handling is appropriate
- [ ] Variable/function names are clear

**Review Process**:
1. **Self-review**: Author reviews own code first
2. **Automated checks**: CI runs tests and linters
3. **Peer review**: At least 1 reviewer approves
4. **Address feedback**: Author addresses comments
5. **Final approval**: Reviewer approves changes
6. **Merge**: Squash and merge to develop

---

## 3. Documentation Requirements

### 3.1 Code Documentation (JSDoc)

**Function Documentation**:
```javascript
/**
 * Subscribe to an event
 * 
 * @param {string} eventName - Name of event to listen for
 * @param {Function} handler - Callback function to execute
 * @param {Object} options - Optional configuration
 * @param {boolean} options.once - Listen only once
 * @param {number} options.priority - Handler priority (higher runs first)
 * @returns {Function} Unsubscribe function
 * 
 * @example
 * // Basic subscription
 * EventBus.on('user:login', (user) => {
 *   console.log('User logged in:', user.username);
 * });
 * 
 * @example
 * // One-time subscription
 * EventBus.on('app:ready', initApp, { once: true });
 */
function on(eventName, handler, options = {}) {
  // Implementation
}
```

**Class Documentation**:
```javascript
/**
 * EventBus - Central publish-subscribe system
 * 
 * Provides a decoupled communication mechanism for modules to emit
 * and listen to events without direct dependencies.
 * 
 * @class
 * @example
 * import EventBus from './event-bus.js';
 * 
 * // Subscribe
 * EventBus.on('message:send', handleMessage);
 * 
 * // Emit
 * EventBus.emit('message:send', { text: 'Hello' });
 */
class EventBus {
  // Implementation
}
```

**Complex Logic Documentation**:
```javascript
// Complex algorithm requiring explanation
function calculatePriority(user, message) {
  /**
   * Priority calculation algorithm:
   * 1. Base priority from user role (Admin: 10, User: 5, Guest: 1)
   * 2. Add +2 if message contains @mention
   * 3. Add +3 if message is urgent (!!)
   * 4. Multiply by 1.5 if user is VIP
   * 
   * Max priority is capped at 20
   */
  
  let priority = USER_ROLE_PRIORITY[user.role];
  
  if (message.includes('@')) {
    priority += 2;
  }
  
  if (message.includes('!!')) {
    priority += 3;
  }
  
  if (user.isVIP) {
    priority *= 1.5;
  }
  
  return Math.min(priority, 20);
}
```

### 3.2 Module README Files

**Required for Each Feature Module**:

```markdown
# Module Name

## Purpose
Brief description of what this module does.

## Files
- `file1.js` - Description
- `file2.js` - Description

## Dependencies
- EventBus (core)
- StateManager (core)
- APIClient (utils)

## Events Emitted
- `module:action` - Description
- `module:error` - Description

## Events Listened
- `other:action` - Description

## API
### Class Methods
\`\`\`javascript
class MyModule {
  // Method signatures
}
\`\`\`

## Usage
\`\`\`javascript
// Example usage
import MyModule from './my-module.js';

const module = new MyModule();
module.doSomething();
\`\`\`

## Testing
\`\`\`bash
npm run test:unit -- my-module.test.js
\`\`\`

## Known Issues
- None currently

## Future Enhancements
- Planned improvements
```

### 3.3 Architecture Decision Records (ADRs)

**When to Create ADR**:
- Significant architectural decisions
- Pattern choices
- Technology selections
- Major refactoring decisions

**ADR Template**:
```markdown
# ADR-001: Use EventBus for Module Communication

## Status
Accepted

## Context
We need a way for modules to communicate without tight coupling.
Direct function calls create dependencies that make testing difficult.

## Decision
Implement an EventBus pattern for publish-subscribe communication.

## Consequences
### Positive
- Loose coupling between modules
- Easy to test modules in isolation
- Can add new features without modifying existing code

### Negative
- Harder to trace event flow
- Potential for event naming conflicts
- Slight performance overhead

## Alternatives Considered
1. Direct function calls - Rejected due to tight coupling
2. Dependency injection - Too complex for our use case
3. Redux-like state management - Overkill for our needs
```

---

## 4. Testing Requirements

### 4.1 Test Coverage Requirements

**Minimum Coverage**:
- Core modules: 90%
- Feature modules: 80%
- Utility modules: 80%
- Overall: >80%

**What to Test**:
- All public methods
- Edge cases and error conditions
- Happy path scenarios
- Integration between modules
- Critical user flows (E2E)

**What NOT to Test**:
- Third-party libraries
- Trivial getters/setters
- Simple pass-through functions

### 4.2 Unit Tests

**Structure**:
```javascript
// event-bus.test.js
import EventBus from './event-bus.js';

describe('EventBus', () => {
  beforeEach(() => {
    // Reset state before each test
    EventBus.clear();
  });
  
  afterEach(() => {
    // Cleanup after each test
  });
  
  describe('on()', () => {
    it('should register event handler', () => {
      const handler = jest.fn();
      EventBus.on('test:event', handler);
      EventBus.emit('test:event', { data: 'test' });
      
      expect(handler).toHaveBeenCalledWith({ data: 'test' });
    });
    
    it('should support multiple handlers', () => {
      const handler1 = jest.fn();
      const handler2 = jest.fn();
      
      EventBus.on('test:event', handler1);
      EventBus.on('test:event', handler2);
      EventBus.emit('test:event');
      
      expect(handler1).toHaveBeenCalled();
      expect(handler2).toHaveBeenCalled();
    });
  });
  
  describe('once()', () => {
    it('should only call handler once', () => {
      const handler = jest.fn();
      EventBus.once('test:event', handler);
      
      EventBus.emit('test:event');
      EventBus.emit('test:event');
      
      expect(handler).toHaveBeenCalledTimes(1);
    });
  });
  
  describe('off()', () => {
    it('should unregister handler', () => {
      const handler = jest.fn();
      EventBus.on('test:event', handler);
      EventBus.off('test:event', handler);
      EventBus.emit('test:event');
      
      expect(handler).not.toHaveBeenCalled();
    });
  });
});
```

**Test Naming**:
```javascript
// Pattern: should [expected behavior] when [condition]
it('should return user when ID is valid', () => {});
it('should throw error when ID is invalid', () => {});
it('should queue message when socket disconnected', () => {});
```

### 4.3 Integration Tests

**Structure**:
```javascript
// modal-system.integration.test.js
import EventBus from './core/event-bus.js';
import ModalManager from './core/modal-manager.js';
import ProfileModule from './features/profile/profile-modal.js';

describe('Modal System Integration', () => {
  beforeEach(() => {
    // Set up DOM
    document.body.innerHTML = `
      <div id="profileModal" class="modal" hidden>
        <div class="modalCard">Content</div>
      </div>
    `;
    
    // Initialize modules
    ProfileModule.init();
  });
  
  it('should open profile modal via event', async () => {
    // Emit event
    EventBus.emit('profile:open', { userId: 123 });
    
    // Wait for modal to open
    await waitFor(() => {
      expect(ModalManager.isOpen('profileModal')).toBe(true);
    });
  });
  
  it('should close modal on ESC key', async () => {
    await ModalManager.open('profileModal', { closeOnEsc: true });
    
    // Simulate ESC key
    const escEvent = new KeyboardEvent('keydown', { key: 'Escape' });
    document.dispatchEvent(escEvent);
    
    await waitFor(() => {
      expect(ModalManager.isOpen('profileModal')).toBe(false);
    });
  });
});
```

### 4.4 E2E Tests

**Structure** (Playwright):
```javascript
// chat-flow.e2e.test.js
const { test, expect } = require('@playwright/test');

test.describe('Chat Flow', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to site
    await page.goto('http://localhost:3000');
    
    // Login
    await page.fill('#authUser', 'testuser');
    await page.fill('#authPass', 'password');
    await page.click('#loginBtn');
    
    // Wait for chat to load
    await page.waitForSelector('#msgs');
  });
  
  test('user can send message', async ({ page }) => {
    const message = 'Test message ' + Date.now();
    
    // Type message
    await page.fill('#messageInput', message);
    
    // Send message
    await page.click('#sendBtn');
    
    // Verify message appears
    await page.waitForSelector(`.msg:has-text("${message}")`);
    
    // Verify message in DOM
    const messageElement = await page.$$(`.msg:has-text("${message}")`);
    expect(messageElement.length).toBeGreaterThan(0);
  });
  
  test('user can switch rooms', async ({ page }) => {
    // Click room
    await page.click('[data-room="music"]');
    
    // Verify room header updated
    await page.waitForSelector('.roomHeader:has-text("music")');
    
    // Verify URL updated
    expect(page.url()).toContain('room=music');
  });
});
```

### 4.5 Test Utilities

**Common Test Helpers**:
```javascript
// test-utils.js

/**
 * Wait for condition to be true
 */
export async function waitFor(condition, timeout = 5000) {
  const start = Date.now();
  while (Date.now() - start < timeout) {
    if (await condition()) {
      return;
    }
    await sleep(100);
  }
  throw new Error('Timeout waiting for condition');
}

/**
 * Sleep for specified milliseconds
 */
export function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Create mock event bus
 */
export function createMockEventBus() {
  const handlers = new Map();
  
  return {
    on: jest.fn((event, handler) => {
      if (!handlers.has(event)) {
        handlers.set(event, []);
      }
      handlers.get(event).push(handler);
    }),
    
    emit: jest.fn((event, data) => {
      if (handlers.has(event)) {
        handlers.get(event).forEach(handler => handler(data));
      }
    }),
    
    off: jest.fn(),
    clear: jest.fn()
  };
}

/**
 * Create mock API client
 */
export function createMockAPIClient() {
  return {
    get: jest.fn(() => Promise.resolve({})),
    post: jest.fn(() => Promise.resolve({})),
    put: jest.fn(() => Promise.resolve({})),
    delete: jest.fn(() => Promise.resolve({}))
  };
}
```

---

## 5. Code Review Checklist

### 5.1 For Authors (Before Requesting Review)

- [ ] All tests pass locally
- [ ] Linter warnings resolved
- [ ] Code follows style guide
- [ ] Documentation updated (JSDoc, README, etc.)
- [ ] No console.log statements (use proper logging)
- [ ] No commented-out code
- [ ] No hardcoded values (use constants)
- [ ] Error handling implemented
- [ ] Edge cases considered
- [ ] Performance considerations addressed
- [ ] Security considerations addressed
- [ ] Self-reviewed the diff
- [ ] Screenshots added for UI changes

### 5.2 For Reviewers

**Architecture**:
- [ ] Follows proposed architecture patterns
- [ ] Uses EventBus for module communication
- [ ] Uses StateManager for state
- [ ] Uses ModalManager for modals
- [ ] Proper module separation

**Code Quality**:
- [ ] Code is readable and maintainable
- [ ] Functions are small and focused
- [ ] No unnecessary complexity
- [ ] DRY principle followed
- [ ] Proper naming conventions
- [ ] No magic numbers/strings

**Testing**:
- [ ] Tests are comprehensive
- [ ] Tests cover edge cases
- [ ] Tests are maintainable
- [ ] Mock dependencies appropriately
- [ ] Test coverage meets requirements

**Documentation**:
- [ ] JSDoc comments complete
- [ ] Complex logic explained
- [ ] README updated if needed
- [ ] Examples provided

**Security**:
- [ ] Input validation present
- [ ] XSS vulnerabilities addressed
- [ ] Authentication/authorization correct
- [ ] Sensitive data not exposed

**Performance**:
- [ ] No obvious performance issues
- [ ] Efficient algorithms used
- [ ] No memory leaks
- [ ] Appropriate use of caching

---

## 6. Definition of Done

A feature is considered "done" when:

- [ ] Code implemented according to requirements
- [ ] All acceptance criteria met
- [ ] Unit tests written and passing (>80% coverage)
- [ ] Integration tests written and passing
- [ ] E2E tests written and passing (for user-facing features)
- [ ] Code reviewed and approved
- [ ] Documentation complete (JSDoc, README, etc.)
- [ ] No linter warnings
- [ ] Manual testing completed
- [ ] No known bugs
- [ ] Accessibility tested (WCAG 2.1 AA)
- [ ] Cross-browser tested
- [ ] Mobile tested (if applicable)
- [ ] Performance tested (meets targets)
- [ ] Security reviewed
- [ ] Merged to develop branch
- [ ] Deployed to staging
- [ ] Smoke tested on staging

---

## 7. Tooling

### 7.1 Required Tools

**Development**:
- Node.js 18+
- npm 8+
- Git 2.30+
- VS Code (recommended) or preferred IDE

**Browser**:
- Chrome/Chromium (for DevTools)
- Firefox (for testing)
- Safari (for testing)

**Testing**:
- Jest (unit/integration tests)
- Playwright (E2E tests)
- Lighthouse (performance/accessibility)

**Code Quality**:
- ESLint (linting)
- Prettier (formatting)
- jscpd (copy-paste detection)

### 7.2 VS Code Extensions (Recommended)

```json
// .vscode/extensions.json
{
  "recommendations": [
    "dbaeumer.vscode-eslint",
    "esbenp.prettier-vscode",
    "orta.vscode-jest",
    "ms-playwright.playwright",
    "wayou.vscode-todo-highlight",
    "streetsidesoftware.code-spell-checker"
  ]
}
```

### 7.3 Pre-commit Hooks

**Install Husky**:
```bash
npm install --save-dev husky lint-staged
npx husky install
```

**Configure**:
```javascript
// package.json
{
  "lint-staged": {
    "*.js": [
      "eslint --fix",
      "prettier --write",
      "jest --bail --findRelatedTests"
    ]
  },
  "husky": {
    "hooks": {
      "pre-commit": "lint-staged",
      "pre-push": "npm test"
    }
  }
}
```

---

## 8. Continuous Integration

### 8.1 CI Pipeline

**GitHub Actions Workflow**:
```yaml
# .github/workflows/ci.yml
name: CI

on:
  push:
    branches: [ develop, main ]
  pull_request:
    branches: [ develop ]

jobs:
  test:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v2
      
      - name: Setup Node.js
        uses: actions/setup-node@v2
        with:
          node-version: '18'
      
      - name: Install dependencies
        run: npm ci
      
      - name: Run linter
        run: npm run lint
      
      - name: Run tests
        run: npm test -- --coverage
      
      - name: Check coverage
        run: npm run test:coverage
      
      - name: Build
        run: npm run build
      
      - name: E2E tests
        run: npm run test:e2e
      
      - name: Upload coverage
        uses: codecov/codecov-action@e28ff129e5465c2c0dcc6f003fc735cb6ae0c673  # v4.5.0
        with:
          token: ${{ secrets.CODECOV_TOKEN }}
```

### 8.2 Status Checks

**Required Checks** (must pass before merge):
- Linter
- Unit tests
- Integration tests
- E2E tests
- Code coverage >80%
- Build succeeds

---

## 9. Troubleshooting

### 9.1 Common Issues

**Issue: Tests failing locally but passing in CI**
- Ensure dependencies are up to date (`npm ci`)
- Check for hardcoded paths
- Check for timezone issues
- Check for environment-specific config

**Issue: Linter warnings**
- Run `npm run lint -- --fix` to auto-fix
- Check `.eslintrc.js` for rules
- Add `// eslint-disable-next-line` for exceptions (with comment explaining why)

**Issue: Low test coverage**
- Run `npm run test:coverage` to see report
- Add tests for uncovered lines
- Ensure all branches are tested

**Issue: Import errors**
- Check file paths are correct
- Ensure exports are correct
- Check for circular dependencies

---

## 10. Resources

### 10.1 Documentation

- [Architecture Overview](./NEW_ARCHITECTURE.md)
- [Technical Specs](./TECHNICAL_SPECS.md)
- [Migration Plan](./MIGRATION_PLAN.md)
- [MDN Web Docs](https://developer.mozilla.org/)
- [JavaScript.info](https://javascript.info/)

### 10.2 Tools Documentation

- [Jest](https://jestjs.io/)
- [Playwright](https://playwright.dev/)
- [ESLint](https://eslint.org/)
- [Lighthouse](https://developers.google.com/web/tools/lighthouse)

### 10.3 Learning Resources

- [Clean Code JavaScript](https://github.com/ryanmcdermott/clean-code-javascript)
- [You Don't Know JS](https://github.com/getify/You-Dont-Know-JS)
- [JavaScript Design Patterns](https://www.patterns.dev/)

---

## 11. Getting Help

### 11.1 Channels

- **Slack**: #dev-chat-redesign
- **GitHub Discussions**: For architectural questions
- **GitHub Issues**: For bugs and features
- **Code Review**: Tag `@architecture-reviewers` for architectural questions

### 11.2 Office Hours

- **Weekly Q&A**: Thursdays 2-3 PM
- **Pair Programming**: Available on request
- **Architecture Review**: Bi-weekly on Wednesdays

---

## 12. Conclusion

This implementation guide provides:
- Clear coding standards
- Structured git workflow
- Comprehensive testing requirements
- Detailed review processes
- Useful tooling recommendations

**Key Principles**:
1. **Consistency**: Follow standards for maintainability
2. **Quality**: Write tests, document code, review thoroughly
3. **Collaboration**: Communicate, help teammates, ask questions
4. **Improvement**: Learn, iterate, suggest better approaches

**Remember**:
- Quality over speed
- Simple over clever
- Tested over assumed
- Documented over implied

**Next Steps**:
1. Review this guide thoroughly
2. Set up development environment
3. Review architecture documents
4. Start implementing Phase 1

---

**Last Updated**: 2026-02-01  
**Version**: 1.0  
**Status**: Active  
**Contact**: Lead Developer
