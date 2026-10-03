// Pre-fills the adjustment amount with quantity x current price until the admin edits the amount.
(function () {
  var form = document.querySelector("[data-adjust-form]");
  if (!form) { return; }
  var unit = parseFloat(form.getAttribute("data-unit-price"));
  var qty = form.querySelector("[name=quantity]");
  var amount = form.querySelector("[name=amount]");
  if (!isFinite(unit) || !qty || !amount) { return; }
  var edited = false;
  amount.addEventListener("input", function () { edited = true; });
  qty.addEventListener("input", function () {
    if (edited) { return; }
    var n = parseInt(qty.value, 10);
    amount.value = isNaN(n) ? "" : (n * unit).toFixed(2);
  });
})();
