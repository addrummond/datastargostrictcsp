document.addEventListener("DOMContentLoaded", function () {
  var btn = document.getElementById("pwn-btn");
  var inp = document.getElementById("pwn-input");
  var tgt = document.getElementById("pwn-target");
  btn.addEventListener("click", function () {
    tgt.innerHTML = inp.value;
  });
});
