/* Auto-submits the scan form once, and only while the page is visible and not prerendered.
   The visible button remains as the fallback. No inline JS (strict CSP). */
(function () {
  "use strict";
  var form = document.querySelector("form[data-autosubmit]");
  if (!form) { return; }
  var button = form.querySelector("button");
  var submitted = false;

  function ready() {
    return document.visibilityState === "visible" && !document.prerendering;
  }

  function submitOnce() {
    if (submitted || !ready()) { return; }
    submitted = true;
    document.removeEventListener("visibilitychange", submitOnce);
    document.removeEventListener("prerenderingchange", submitOnce);
    if (button) { button.disabled = true; }
    form.submit();
  }

  document.addEventListener("visibilitychange", submitOnce);
  document.addEventListener("prerenderingchange", submitOnce);
  // Back to this page from the bfcache: never resubmit automatically, re-enable the button.
  window.addEventListener("pageshow", function (event) {
    if (event.persisted && button) { button.disabled = false; }
  });
  submitOnce();
})();
