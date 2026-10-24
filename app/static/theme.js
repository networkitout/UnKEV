// Theme: follows the system preference until the reader picks one. Loaded
// synchronously in <head> so the first paint is already the right theme.
// Modes cycle auto -> dark -> light; the choice is remembered per browser.
(function () {
  var KEY = "unkev-theme";
  var media = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)");
  function mode() {
    var m = null;
    try { m = localStorage.getItem(KEY); } catch (e) {}
    return m === "dark" || m === "light" ? m : "auto";
  }
  function apply() {
    var m = mode();
    var dark = m === "dark" || (m === "auto" && media && media.matches);
    document.documentElement.setAttribute("data-theme", dark ? "dark" : "light");
    var btn = document.querySelector(".theme-btn");
    if (btn) {
      btn.setAttribute("data-mode", m);
      btn.textContent = m === "auto" ? "Auto" : m === "dark" ? "Dark" : "Light";
      btn.setAttribute("title", "Theme: " + btn.textContent + " (click to change)");
    }
  }
  apply();
  if (media && media.addEventListener) media.addEventListener("change", apply);
  document.addEventListener("DOMContentLoaded", function () {
    apply();
    var btn = document.querySelector(".theme-btn");
    if (!btn) return;
    btn.addEventListener("click", function () {
      var next = { auto: "dark", dark: "light", light: "auto" }[mode()];
      try { next === "auto" ? localStorage.removeItem(KEY) : localStorage.setItem(KEY, next); } catch (e) {}
      apply();
    });
  });
})();
