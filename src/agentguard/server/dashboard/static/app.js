// AgentGuard console helpers. Loaded as a file so the strict CSP (no inline scripts) still holds.
(function () {
  "use strict";

  // "Copy" buttons: <button data-copy="#target-id">. Copies the target's text.
  document.addEventListener("click", function (ev) {
    var btn = ev.target.closest ? ev.target.closest("[data-copy]") : null;
    if (!btn) return;
    var target = document.querySelector(btn.getAttribute("data-copy"));
    if (!target || !navigator.clipboard) return;
    navigator.clipboard.writeText(target.innerText.trim()).then(function () {
      var label = btn.querySelector(".label");
      if (!label) return;
      var old = label.textContent;
      label.textContent = "Copied!";
      btn.classList.add("copied");
      setTimeout(function () { label.textContent = old; btn.classList.remove("copied"); }, 1600);
    });
  });
})();
