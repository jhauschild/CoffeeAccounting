// Shows the "Achievement unlocked" toasts one after another; tap one to dismiss it early.
(function () {
  var toasts = Array.prototype.slice.call(document.querySelectorAll(".ach-toast"));
  function next() {
    var el = toasts.shift();
    if (!el) return;
    var done = false;
    function finish() { if (done) return; done = true; el.remove(); setTimeout(next, 250); }
    el.hidden = false;
    el.addEventListener("animationend", finish);
    el.addEventListener("click", function () { el.classList.add("is-leaving"); });
  }
  setTimeout(next, 400);
})();
