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

  console.log('[auth.js] Auth module initialized');
})();
