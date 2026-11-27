(function () {
  "use strict";
  var form = document.getElementById("filters");
  var rel = document.getElementById("rel");
  var q = document.getElementById("q");
  var gaps = document.getElementById("gaps");
  var matrix = document.getElementById("matrix");
  if (!form || !rel || !q || !gaps || !matrix) { return; }

  function apply() {
    var r = rel.value;
    var text = q.value.toLowerCase();
    var onlyGaps = gaps.checked;
    var cols = matrix.querySelectorAll("[data-rel]");
    for (var i = 0; i < cols.length; i++) {
      var c = cols[i];
      c.classList.toggle("hidden", r !== "" && c.getAttribute("data-rel") !== r);
    }
    var rows = matrix.querySelectorAll("tbody tr");
    for (var j = 0; j < rows.length; j++) {
      var row = rows[j];
      var ok = (row.getAttribute("data-endpoint") || "").toLowerCase().indexOf(text) !== -1;
      if (ok && onlyGaps) {
        var cells = row.querySelectorAll('td[data-state="gap"]');
        var has = false;
        for (var k = 0; k < cells.length; k++) {
          if (r === "" || cells[k].getAttribute("data-rel") === r) { has = true; }
        }
        ok = has;
      }
      row.classList.toggle("hidden", !ok);
    }
  }

  form.addEventListener("submit", function (e) { e.preventDefault(); });
  rel.addEventListener("change", apply);
  q.addEventListener("input", apply);
  gaps.addEventListener("change", apply);
  apply();
})();
