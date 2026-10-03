// Print buttons (strict CSP: no inline handlers).
(function () {
  var buttons = document.querySelectorAll("[data-print]");
  for (var i = 0; i < buttons.length; i++) {
    buttons[i].addEventListener("click", function () { window.print(); });
  }
})();
