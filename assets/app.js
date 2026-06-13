// codered viewer — theme toggle + density toggle + back-to-top. Served from
// /assets (CSP 'self'); no inline scripts. Loaded in <head> so the stored
// theme/density apply before the body paints (avoids a flash).
(function () {
  var root = document.documentElement;

  // Apply stored prefs pre-paint.
  try {
    var t = localStorage.getItem("codered-theme");
    if (t) root.dataset.theme = t;
  } catch (e) {}

  function applyDensity(d) {
    // The .density-comfortable class overrides --row-pad-* for descendants.
    if (d === "comfortable") document.body.classList.add("density-comfortable");
    else document.body.classList.remove("density-comfortable");
  }
  function storedDensity() {
    try { return localStorage.getItem("codered-density") || "compact"; } catch (e) { return "compact"; }
  }

  function themeLabel() {
    var b = document.getElementById("theme-toggle");
    if (b) b.textContent = root.dataset.theme === "light" ? "☾" : "☀";
  }

  document.addEventListener("DOMContentLoaded", function () {
    // Theme toggle
    var tb = document.getElementById("theme-toggle");
    if (tb) {
      tb.addEventListener("click", function () {
        var next = root.dataset.theme === "light" ? "dark" : "light";
        root.dataset.theme = next;
        try { localStorage.setItem("codered-theme", next); } catch (e) {}
        themeLabel();
      });
    }
    themeLabel();

    // Density: apply stored value, sync the segmented control, wire clicks.
    var density = storedDensity();
    applyDensity(density);
    var segs = document.querySelectorAll("[data-density]");
    segs.forEach(function (btn) {
      if (btn.getAttribute("data-density") === density) btn.classList.add("active");
      else btn.classList.remove("active");
      btn.addEventListener("click", function () {
        var d = btn.getAttribute("data-density");
        applyDensity(d);
        try { localStorage.setItem("codered-density", d); } catch (e) {}
        segs.forEach(function (b) { b.classList.toggle("active", b === btn); });
      });
    });

    // Back-to-top
    var tt = document.getElementById("totop");
    function onScroll() { if (tt) tt.style.display = window.scrollY > 400 ? "flex" : "none"; }
    window.addEventListener("scroll", onScroll, { passive: true });
    onScroll();
  });
})();
