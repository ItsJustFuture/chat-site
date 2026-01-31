(function() {
  'use strict';

  console.log('[auth.js] Loading auth module...');

  // Wait for app:ready before initializing
  async function waitAndInit() {
    console.log('[auth.js] Waiting for app:ready...');
    
    // Ensure waitForAppReady is available
    if (typeof window.waitForAppReady !== 'function') {
      console.error('[auth.js] FATAL: window.waitForAppReady not initialized by app.js - runtime initialization error');
      return;
    }

    try {
      await window.waitForAppReady();
      console.log('[auth.js] app:ready received, initializing auth...');
      initAuthForm();
    } catch (error) {
      console.error('[auth.js] Failed to wait for app:ready:', error);
    }
  }

  function initAuthForm() {
    const authForm = document.getElementById('authForm');
    if (!authForm || authForm.dataset.authBound) return;
    authForm.dataset.authBound = 'true';

    const authLoading = document.getElementById('authLoading');
    const loginView = document.getElementById('loginView');
    const chatView = document.getElementById('chatView');
    const passwordUpgradeView = document.getElementById('passwordUpgradeView');
    const restrictedView = document.getElementById('restrictedView');

    const loginBtn = document.getElementById('loginBtn');
    const regBtn = document.getElementById('regBtn');
    const guestBtn = document.getElementById('guestLoginBtn');
    const authMsg = document.getElementById('authMsg');
    const captchaWrap = document.getElementById('captchaWrap');
    const captchaWidget = document.getElementById('captchaWidget');
    const captchaNote = document.getElementById('captchaNote');

    let mode = 'login'; // 'login' | 'register'
    let captchaConfig = { provider: 'none', siteKey: '' };
    let captchaToken = '';
    let captchaWidgetId = null;

    const setMsg = (text, isError = false) => {
      if (authMsg) {
        authMsg.textContent = text || '';
        authMsg.style.color = isError ? '#ff6b6b' : '';
      }
    };

    const setAuthState = (state) => {
      const show = (el, shouldShow) => {
        if (!el) return;
        if (typeof el.hidden === 'boolean') {
          el.hidden = !shouldShow;
        } else {
          el.style.display = shouldShow ? '' : 'none';
        }
      };

      document.body?.classList?.toggle('auth-pending', state === 'loading');
      show(authLoading, state === 'loading');
      show(loginView, state === 'login');
      show(chatView, state === 'chat');
      show(passwordUpgradeView, state === 'upgrade');
      show(restrictedView, state === 'restricted');
    };

    const showLoginView = () => setAuthState('login');

    const showChatView = () => {
      setAuthState('chat');
      // Initialize chat application after view is shown
      if (window.chatApp && typeof window.chatApp.initialize === 'function') {
        // Small delay to ensure DOM is ready
        setTimeout(() => {
          window.chatApp.initialize();
        }, 100);
      } else {
        console.warn('[auth.js] chatApp not available, retrying...');
        // Retry if chat.js hasn't loaded yet
        setTimeout(() => {
          if (window.chatApp && typeof window.chatApp.initialize === 'function') {
            window.chatApp.initialize();
          } else {
            console.error('[auth.js] chatApp still not available');
          }
        }, 500);
      }
    };

    const showPasswordUpgradeView = () => setAuthState('upgrade');

    const showRestrictedView = (status) => {
      const title = document.getElementById('restrictedTitle');
      const sub = document.getElementById('restrictedSub');
      const reasonText = document.getElementById('restrictedReasonText');
      const timerWrap = document.getElementById('restrictedTimerWrap');
      const timer = document.getElementById('restrictedTimer');
      const statusType = status?.type || 'restricted';
      const label = statusType === 'banned'
        ? 'Banned'
        : statusType === 'kicked'
          ? 'Kicked'
          : 'Restricted';

      if (title) title.textContent = label;
      if (sub) sub.textContent = status?.message || 'You cannot access the chat right now.';
      if (reasonText) reasonText.textContent = status?.reason || '—';
      if (timerWrap) timerWrap.hidden = !status?.expiresAt;
      if (timer && status?.expiresAt) {
        const remaining = Math.max(0, status.expiresAt - Date.now());
        const hours = Math.floor(remaining / 3600000);
        const mins = Math.floor((remaining % 3600000) / 60000);
        const secs = Math.floor((remaining % 60000) / 1000);
        timer.textContent = `${String(hours).padStart(2, '0')}:${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
      }
      setAuthState('restricted');
    };

    async function hydrateSession() {
      try {
        const res = await fetch('/me', { credentials: 'include' });
        if (!res.ok) return showLoginView();
        const data = await res.json();
        if (!data || !data.id) return showLoginView();
        
        // User is logged in, initialize socket if not already done
        if (!window.socket) {
          if (typeof window.initSocket !== 'function') {
            console.error('[auth.js] window.initSocket not available - cannot initialize socket');
            showChatView();
            return;
          }
          
          console.log('[auth.js] Initializing socket after successful session check...');
          try {
            await window.initSocket();
            window.currentUser = data;
            console.log('[auth.js] Socket initialized, updating global state');
            
            // Re-dispatch app:ready with socket now available
            const readyEvent = new CustomEvent('app:ready', {
              detail: {
                socket: window.socket,
                currentUser: window.currentUser,
                currentRoom: window.currentRoom
              }
            });
            window.dispatchEvent(readyEvent);
            console.log('[auth.js] Re-dispatched app:ready with socket');
          } catch (socketErr) {
            console.error('[auth.js] Failed to initialize socket:', socketErr);
            // Continue to show chat view - chat.js will handle missing socket gracefully
          }
        }
        
        showChatView();
      } catch (err) {
        console.warn('[auth.js] session hydrate failed:', err?.message || err);
        showLoginView();
      }
    }

    async function applyRestrictionState() {
      try {
        const res = await fetch('/api/restriction', { credentials: 'include' });
        if (!res.ok) return showLoginView();
        const data = await res.json();
        if (data?.type && data.type !== 'none') {
          showRestrictedView(data);
        } else {
          await hydrateSession();
        }
      } catch (err) {
        console.warn('[auth.js] restriction check failed:', err?.message || err);
        showLoginView();
      }
    }

    const setCaptchaNote = (text) => {
      if (captchaNote) captchaNote.textContent = text || '';
    };

    const setCaptchaVisible = (visible) => {
      if (captchaWrap) captchaWrap.hidden = !visible;
    };

    const resetCaptcha = () => {
      if (!captchaConfig || captchaConfig.provider === 'none') return;
      if (captchaConfig.provider === 'turnstile' && window.turnstile && captchaWidgetId !== null) {
        window.turnstile.reset(captchaWidgetId);
      }
      if (captchaConfig.provider === 'hcaptcha' && window.hcaptcha && captchaWidgetId !== null) {
        window.hcaptcha.reset(captchaWidgetId);
      }
      captchaToken = '';
    };

    const loadCaptchaScript = (provider) => new Promise((resolve, reject) => {
      const ready = provider === 'turnstile' ? window.turnstile : window.hcaptcha;
      if (ready) return resolve();
      const existing = document.querySelector(`script[data-captcha-provider="${provider}"]`);
      if (existing) {
        if (existing.dataset.captchaLoaded === 'true') return resolve();
        if (existing.dataset.captchaError === 'true') return reject(new Error('Captcha script failed.'));
        existing.addEventListener('load', () => resolve(), { once: true });
        existing.addEventListener('error', () => reject(new Error('Captcha script failed.')), { once: true });
        return;
      }
      const script = document.createElement('script');
      script.dataset.captchaProvider = provider;
      script.async = true;
      script.defer = true;
      script.src = provider === 'turnstile'
        ? 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit'
        : 'https://js.hcaptcha.com/1/api.js?render=explicit';
      script.onload = () => {
        script.dataset.captchaLoaded = 'true';
        resolve();
      };
      script.onerror = () => {
        script.dataset.captchaError = 'true';
        reject(new Error('Captcha script failed.'));
      };
      document.head.appendChild(script);
    });

    const renderCaptcha = async () => {
      if (!captchaWidget || !captchaConfig || captchaConfig.provider === 'none') return;
      captchaWidget.innerHTML = '';
      captchaToken = '';
      captchaWidgetId = null;
      await loadCaptchaScript(captchaConfig.provider);
      if (captchaConfig.provider === 'turnstile' && window.turnstile) {
        captchaWidgetId = window.turnstile.render(captchaWidget, {
          sitekey: captchaConfig.siteKey,
          callback: (token) => { captchaToken = token || ''; },
          'expired-callback': () => { captchaToken = ''; },
          'error-callback': () => { captchaToken = ''; },
        });
      } else if (captchaConfig.provider === 'hcaptcha' && window.hcaptcha) {
        captchaWidgetId = window.hcaptcha.render(captchaWidget, {
          sitekey: captchaConfig.siteKey,
          callback: (token) => { captchaToken = token || ''; },
          'expired-callback': () => { captchaToken = ''; },
          'error-callback': () => { captchaToken = ''; },
        });
      }
    };

    const initCaptcha = async () => {
      try {
        const resp = await fetch('/api/captcha-config');
        if (!resp.ok) throw new Error('Captcha config unavailable.');
        const data = await resp.json();
        captchaConfig = {
          provider: data?.provider || 'none',
          siteKey: data?.siteKey || '',
        };
        const enabled = captchaConfig.provider !== 'none' && Boolean(captchaConfig.siteKey);
        setCaptchaVisible(enabled);
        setCaptchaNote(
          enabled
            ? `Protected by ${captchaConfig.provider === 'turnstile' ? 'Cloudflare Turnstile' : 'hCaptcha'}.`
            : ''
        );
        if (enabled) await renderCaptcha();
      } catch (err) {
        console.warn('[auth.js] captcha init failed:', err?.message || err);
        captchaConfig = { provider: 'none', siteKey: '' };
        setCaptchaVisible(false);
        setCaptchaNote('');
      }
    };

    const setMode = (next) => {
      mode = next;
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
        body: JSON.stringify({ username, password, captchaToken }),
        credentials: 'include',
      });
      if (!resp.ok) {
        throw new Error(await resp.text());
      }
      const data = await resp.json();
      if (data?.code === 'PASSWORD_UPGRADE_REQUIRED') {
        showPasswordUpgradeView();
        return;
      }
      if (data?.ok) {
        await applyRestrictionState();
        return;
      }
      throw new Error(data?.message || 'Login failed');
    };

    const doRegister = async (username, password) => {
      const resp = await fetch('/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password, captchaToken }),
        credentials: 'include',
      });
      if (!resp.ok) {
        throw new Error(await resp.text());
      }
      const data = await resp.json();
      if (data?.ok) {
        await applyRestrictionState();
        return;
      }
      throw new Error(data?.message || 'Registration failed');
    };

    authForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const username = String(document.getElementById('authUser')?.value || '').trim();
      const password = String(document.getElementById('authPass')?.value || '');

      if (!username || !password) {
        setMsg('Username and password are required.', true);
        return;
      }

      try {
        setMsg(mode === 'register' ? 'Creating account...' : 'Signing in...');
        if (captchaConfig.provider !== 'none' && !captchaToken) {
          setMsg('Complete the captcha to continue.', true);
          return;
        }
        if (mode === 'register') {
          await doRegister(username, password);
        } else {
          await doLogin(username, password);
        }
      } catch (err) {
        resetCaptcha();
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
            credentials: 'include',
          });
          if (!resp.ok) throw new Error(await resp.text());
          const data = await resp.json();
          if (data?.ok) {
            await applyRestrictionState();
            return;
          }
          throw new Error(data?.message || 'Guest login failed');
        } catch (err) {
          setMsg(err?.message || 'Guest login failed.', true);
        }
      });
    }

    setAuthState('loading');
    initCaptcha();
    applyRestrictionState();
  }

  // Start initialization process
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', waitAndInit);
  } else {
    waitAndInit();
  }

  console.log('[auth.js] Auth module loaded, waiting for bootstrap...');
})();
