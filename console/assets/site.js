(function () {
  var KEY = "ma_waf_community_session";

  function cfg() {
    return window.MA_WAF || {};
  }

  function isAuthed() {
    try {
      var raw = sessionStorage.getItem(KEY);
      if (!raw) return false;
      var s = JSON.parse(raw);
      return !!(s && s.user && s.at);
    } catch (e) {
      return false;
    }
  }

  function requireAuth() {
    if (!isAuthed()) {
      location.replace("index.html");
      return false;
    }
    return true;
  }

  function logout() {
    sessionStorage.removeItem(KEY);
    location.replace("index.html");
  }

  function login(user, pass) {
    var c = cfg();
    var u = (c.demoUser || "admin").toLowerCase();
    var p = c.demoPass || "admin";
    var userOk = String(user || "").trim().toLowerCase() === u;
    /* 兼容误把文档里的 “change the password” 当成密码 */
    var passOk = pass === p || pass === "change";
    if (!userOk || !passOk) {
      return {
        ok: false,
        message: "用户名或密码错误。试用演示账号为 admin / admin（与专业版默认一致）。"
      };
    }
    sessionStorage.setItem(
      KEY,
      JSON.stringify({ user: u, at: Date.now(), edition: "community-trial" })
    );
    return { ok: true };
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
    fillCommon: fillCommon
  };

  document.addEventListener("DOMContentLoaded", fillCommon);
})();
