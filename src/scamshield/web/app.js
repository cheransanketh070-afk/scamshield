(function () {
  "use strict";
  var EXAMPLES = {
    bank: "URGENT: Your bank account will be suspended within 24 hours. Verify your account now at http://secure-hsbc-login.xyz/verify",
    parcel: "Hi, your package is on hold. Pay a $1.99 redelivery fee at bit.ly/3xYz to reschedule delivery.",
    job: "Work from home! Earn $300 per day, no experience required. Message us on WhatsApp to start today.",
    mum: "Hi mum, this is my new number. Can you please send me some money today? Don't tell dad.",
    otp: "Your OTP is 482913. Do not share it with anyone. - Your Bank"
  };
  var VERDICT_LABEL = { likely_scam: "Likely scam", suspicious: "Suspicious", low_risk: "Low risk" };

  var msg = document.getElementById("msg");
  var out = document.getElementById("result");

  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined) n.textContent = text;
    return n;
  }

  // Offsets from the API are in Unicode code points, so slice by code point, not UTF-16 unit.
  function highlighted(text, findings) {
    var chars = Array.from(text);
    var spans = findings
      .filter(function (f) { return f.weight > 0 && f.start >= 0 && f.end > f.start; })
      .map(function (f) { return [f.start, f.end]; })
      .sort(function (a, b) { return a[0] - b[0]; });
    var merged = [];
    spans.forEach(function (s) {
      var last = merged[merged.length - 1];
      if (last && s[0] <= last[1]) last[1] = Math.max(last[1], s[1]); else merged.push([s[0], s[1]]);
    });
    var box = el("div", "slip");
    var pos = 0;
    merged.forEach(function (s) {
      if (s[0] > pos) box.appendChild(document.createTextNode(chars.slice(pos, s[0]).join("")));
      box.appendChild(el("mark", "", chars.slice(s[0], s[1]).join("")));
      pos = s[1];
    });
    if (pos < chars.length) box.appendChild(document.createTextNode(chars.slice(pos).join("")));
    return box;
  }

  function render(text, report) {
    out.textContent = "";
    var stamp = el("div", "stamp v-" + report.verdict, VERDICT_LABEL[report.verdict]);
    stamp.appendChild(el("small", "", "risk " + report.score + "/100"));
    out.appendChild(stamp);
    out.appendChild(el("h2", "slip-title", report.headline));
    out.appendChild(highlighted(text, report.findings));

    var flags = report.findings.filter(function (f) { return f.weight > 0; });
    var good = report.findings.filter(function (f) { return f.weight < 0; });
    if (flags.length) {
      out.appendChild(el("h2", "", "Red flags (" + flags.length + ")"));
      var ul = el("ul", "flags");
      flags.forEach(function (f) {
        var li = el("li");
        li.appendChild(el("b", "", f.title));
        li.appendChild(el("span", "why", f.explanation));
        if (f.evidence) li.appendChild(el("div", "found", "found: " + f.evidence));
        ul.appendChild(li);
      });
      out.appendChild(ul);
    }
    if (good.length) {
      out.appendChild(el("h2", "", "Good signs"));
      var gl = el("ul", "flags good");
      good.forEach(function (f) {
        var li = el("li");
        li.appendChild(el("b", "", f.title));
        li.appendChild(el("span", "why", f.explanation));
        gl.appendChild(li);
      });
      out.appendChild(gl);
    }
    out.appendChild(el("h2", "", "What to do"));
    var todo = el("ul", "todo");
    report.advice.forEach(function (t) { todo.appendChild(el("li", "", t)); });
    out.appendChild(todo);
  }

  function check() {
    var text = msg.value;
    if (!text.trim()) { msg.focus(); return; }
    fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text: text })
    }).then(function (r) {
      if (!r.ok) throw new Error("bad status " + r.status);
      return r.json();
    }).then(function (report) { render(text, report); })
      .catch(function () {
        out.textContent = "";
        out.appendChild(el("p", "error", "Couldn't reach the ScamShield server. Check that it's still running, then try again."));
      });
  }

  document.getElementById("check").addEventListener("click", check);
  document.getElementById("clear").addEventListener("click", function () {
    msg.value = ""; msg.focus();
  });
  document.querySelectorAll("[data-ex]").forEach(function (b) {
    b.addEventListener("click", function () { msg.value = EXAMPLES[b.dataset.ex]; check(); });
  });
  msg.addEventListener("keydown", function (e) {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") check();
  });
})();
