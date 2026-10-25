// "Next update" chip: the server renders the scheduled time as plain text;
// this turns it into a countdown that ticks, and falls back to "due now" once
// the time passes (which can also mean the scheduler isn't running).
(function () {
  function clock(dt) {
    return new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit" }).format(dt);
  }
  function phrase(mins) {
    if (mins <= 0) return "due now";
    if (mins < 60) return "in " + mins + " min";
    var h = Math.floor(mins / 60), r = mins % 60;
    if (h >= 24) return "in " + Math.floor(h / 24) + " d";
    return r ? "in " + h + " h " + r + " min" : "in " + h + " h";
  }
  function tick() {
    document.querySelectorAll("#next-run").forEach(function (el) {
      var at = el.getAttribute("data-at");
      if (!at) return;
      var dt = new Date(at);
      if (isNaN(dt.getTime())) return;
      var mins = Math.round((dt.getTime() - Date.now()) / 60000);
      el.textContent = "Next update " + phrase(mins) + " · " + clock(dt);
    });
  }
  tick();
  document.addEventListener("DOMContentLoaded", tick);
  setInterval(tick, 20000);
})();
