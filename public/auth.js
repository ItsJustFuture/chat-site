(function() {
  'use strict';

  function initAuthForm() {
    const authForm = document.getElementById('authForm');
    if (!authForm || authForm.dataset.authBound) return;
    authForm.dataset.authBound = 'true';

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
      script.onload = () => resolve();
      script.onerror = () => reject(new Error('Captcha script failed.'));
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

    const doRegister = async (username, password) => {
      const resp = await fetch('/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
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

      if (!username || !password) {
        setMsg('Username and password are required.', true);
        return;
      }

      try {
        setMsg(mode === 'register' ? 'Creating account...' : 'Signing in...');
        if (mode === 'login' && captchaConfig.provider !== 'none' && !captchaToken) {
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

    initCaptcha();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initAuthForm);
  } else {
    initAuthForm();
  }

  console.log('[auth.js] Auth module initialized');
})();
