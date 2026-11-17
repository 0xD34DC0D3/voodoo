// Reveals the Copy button on the new-key page and copies the key on click.
(function () {
  if (!navigator.clipboard) return;
  var btn = document.getElementById("copy-key");
  var code = document.getElementById("key-value");
  if (!btn || !code) return;
  btn.hidden = false;
  btn.addEventListener("click", function () {
    navigator.clipboard.writeText(code.textContent).then(function () {
      btn.textContent = "Copied ✓";
      setTimeout(function () { btn.textContent = "Copy"; }, 1500);
    });
  });
})();
