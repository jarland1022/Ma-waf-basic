(function () {
  var TOKEN_KEY = "ma_waf_community_token";

  function cfg() {
    return window.MA_WAF || {};
  }

  function token() {
    return sessionStorage.getItem(TOKEN_KEY) || "";
  }

  function setToken(t) {
    if (t) sessionStorage.setItem(TOKEN_KEY, t);
    else sessionStorage.removeItem(TOKEN_KEY);
  }

  function isAuthed() {
    return !!token();
  }

  function requireAuth() {
    if (!isAuthed()) {
      location.replace("index.html");
      return false;
    }
    return true;
  }

  function logout() {
    setToken("");
    location.replace("index.html");
  }

  async function api(path, options) {
    options = options || {};
    var headers = Object.assign({ "Content-Type": "application/json" }, options.headers || {});
    if (token()) headers.Authorization = "Bearer " + token();
    var res = await fetch(path, {
      method: options.method || "GET",
      headers: headers,
      body: options.body ? JSON.stringify(options.body) : undefined
    });
    var data = null;
    try {
      data = await res.json();
    } catch (e) {
      data = {};
    }
    if (!res.ok) {
      var err = new Error((data && data.error) || res.statusText || "request failed");
      err.status = res.status;
      err.data = data;
      throw err;
    }
    return data;
  }

  async function login(user, pass) {
    var data = await api("/api/login", {
      method: "POST",
      body: { username: user, password: pass }
    });
    setToken(data.token);
    return data;
  }

  function fillCommon() {
    var c = cfg();
    var price = c.proPriceCny || 4980;
    var days = c.trialDays || 14;
    document.querySelectorAll("[data-pro-price]").forEach(function (el) {
      el.textContent = "¥" + Number(price).toLocaleString("zh-CN");
    });
    document.querySelectorAll("[data-trial-days]").forEach(function (el) {
      el.textContent = String(days);
    });
    document.querySelectorAll("[data-pro-contact]").forEach(function (el) {
      if (c.contactHref) el.setAttribute("href", c.contactHref);
      if (c.contactLabel && el.hasAttribute("data-pro-label")) {
        el.textContent = c.contactLabel;
      }
    });
    document.querySelectorAll("[data-sales-email]").forEach(function (el) {
      if (c.salesEmail) el.textContent = c.salesEmail;
    });
  }

  window.MaWafAuth = {
    isAuthed: isAuthed,
    requireAuth: requireAuth,
    login: login,
    logout: logout,
    api: api,
    fillCommon: fillCommon,
    token: token
  };

  document.addEventListener("DOMContentLoaded", fillCommon);
})();
