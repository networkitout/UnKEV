// Posture tiles link into sections that may be collapsed. Open a <details>
// target before the browser scrolls to it, so the link lands on content.
(function () {
  function reveal(id) {
    var el = id && document.getElementById(id);
    if (el && el.tagName === "DETAILS" && !el.open) el.open = true;
  }
  document.addEventListener("click", function (e) {
    var a = e.target.closest && e.target.closest('a[href^="#"]');
    if (a) reveal(a.getAttribute("href").slice(1));
  });
  window.addEventListener("hashchange", function () { reveal(location.hash.slice(1)); });
  reveal(location.hash.slice(1));
})();
