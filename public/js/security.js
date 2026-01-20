// Global security helpers:
// - Fetch a CSRF token (double-submit cookie) and keep it in memory
// - Automatically attach X-CSRF-Token on same-origin unsafe requests (POST/PUT/PATCH/DELETE)
(() => {
  const CSRF_HEADER = 'X-CSRF-Token';

  function getCookie(name) {
    const match = document.cookie.match(new RegExp('(?:^|; )' + name.replace(/([.$?*|{}()[\]\\/+^])/g, '\\$1') + '=([^;]*)'));
    return match ? decodeURIComponent(match[1]) : null;
  }

  async function ensureCsrfToken() {
    // token is stored in a non-HttpOnly cookie so JS can read it and echo it back in a header
    const existing = getCookie('csrfToken');
    if (existing) {
      window.__csrfToken = existing;
      return existing;
    }

    try {
      const res = await fetch('/api/csrf-token', { credentials: 'same-origin' });
      const data = await res.json().catch(() => ({}));
      const token = data && data.csrfToken ? data.csrfToken : getCookie('csrfToken');
      if (token) window.__csrfToken = token;
      return token;
    } catch {
      return null;
    }
  }

  // Kick off token fetch early
  ensureCsrfToken();

  // Patch fetch
  const originalFetch = window.fetch.bind(window);
  window.fetch = async (input, init = {}) => {
    const url = typeof input === 'string' ? input : (input && input.url) || '';
    const method = (init.method || (typeof input !== 'string' && input.method) || 'GET').toUpperCase();
    const isUnsafe = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method);
    const isSameOrigin = !/^https?:\/\//i.test(url);

    const nextInit = { ...init };
    nextInit.credentials = nextInit.credentials || 'same-origin';

    if (isUnsafe && isSameOrigin) {
      const token = (window.__csrfToken || getCookie('csrfToken')) || (await ensureCsrfToken());
      nextInit.headers = new Headers(nextInit.headers || {});
      if (token) nextInit.headers.set(CSRF_HEADER, token);
    }

    return originalFetch(input, nextInit);
  };

  // Patch XMLHttpRequest (used in performance.js)
  const originalOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function (method, url, ...rest) {
    this.__csrfMethod = String(method || 'GET').toUpperCase();
    this.__csrfUrl = url || '';
    return originalOpen.call(this, method, url, ...rest);
  };

  const originalSend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.send = function (body) {
    const isUnsafe = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(this.__csrfMethod);
    const isSameOrigin = this.__csrfUrl && !/^https?:\/\//i.test(this.__csrfUrl);
    if (isUnsafe && isSameOrigin) {
      const token = window.__csrfToken || getCookie('csrfToken');
      if (token) {
        try {
          this.setRequestHeader(CSRF_HEADER, token);
        } catch {
          // ignore
        }
      }
    }
    return originalSend.call(this, body);
  };
})();

