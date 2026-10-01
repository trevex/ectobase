/* Fullscreen + pan/zoom for Mermaid diagrams.
 *
 * Zensical renders Mermaid into a *closed* shadow root on a <div class="mermaid">
 * (`attachShadow({mode:"closed"})`), so the <svg> is unreachable from page JS —
 * we can neither read nor clone it. Instead we wrap the accessible host div, open
 * it with the native Fullscreen API, and implement zoom/pan by transforming the
 * host element itself (the shadow content scales with it). Self-contained, no deps.
 * Robust across instant navigation via a MutationObserver.
 */
(function () {
  "use strict";

  function apply(host) {
    var s = host.__ebs;
    host.style.transform =
      "translate(" + s.tx + "px," + s.ty + "px) scale(" + s.scale + ")";
  }
  function reset(host) {
    host.__ebs = { scale: 1, tx: 0, ty: 0 };
    host.style.transform = "";
  }
  function fit(host) {
    reset(host);
    requestAnimationFrame(function () {
      var r = host.getBoundingClientRect();
      if (!r.width || !r.height) return;
      var f = Math.min(
        (window.innerWidth * 0.92) / r.width,
        (window.innerHeight * 0.86) / r.height
      );
      host.__ebs.scale = Math.max(0.2, Math.min(f, 6));
      apply(host);
    });
  }

  function requestFs(el) {
    var fn =
      el.requestFullscreen ||
      el.webkitRequestFullscreen ||
      el.mozRequestFullScreen;
    return fn ? fn.call(el) : null;
  }

  function decorate(host) {
    // Only rendered hosts (the <div class="mermaid"> that replaced the <pre>),
    // and only once.
    if (host.tagName !== "DIV" || host.__ebZoom) return;
    host.__ebZoom = true;
    reset(host);

    var wrap = document.createElement("div");
    wrap.className = "eb-mermaid-wrap";
    host.parentNode.insertBefore(wrap, host);
    wrap.appendChild(host);

    var btn = document.createElement("button");
    btn.type = "button";
    btn.className = "eb-zoom-btn";
    btn.title = "Fullscreen (zoom & pan)";
    btn.setAttribute("aria-label", "Open diagram fullscreen");
    btn.innerHTML = "⛶";
    wrap.appendChild(btn);

    btn.addEventListener("click", function (e) {
      e.preventDefault();
      e.stopPropagation();
      var p = requestFs(wrap);
      if (p && p.then) p.then(function () { fit(host); });
      else setTimeout(function () { fit(host); }, 60);
    });

    var dragging = false, lx = 0, ly = 0;

    wrap.addEventListener(
      "wheel",
      function (e) {
        if (document.fullscreenElement !== wrap) return;
        e.preventDefault();
        var s = host.__ebs;
        var f = e.deltaY < 0 ? 1.12 : 1 / 1.12;
        var ns = Math.min(40, Math.max(0.15, s.scale * f));
        var r = host.getBoundingClientRect();
        var cx = e.clientX - (r.left + r.width / 2);
        var cy = e.clientY - (r.top + r.height / 2);
        s.tx -= cx * (ns / s.scale - 1);
        s.ty -= cy * (ns / s.scale - 1);
        s.scale = ns;
        apply(host);
      },
      { passive: false }
    );

    wrap.addEventListener("pointerdown", function (e) {
      if (document.fullscreenElement !== wrap) return;
      dragging = true;
      lx = e.clientX;
      ly = e.clientY;
      wrap.setPointerCapture(e.pointerId);
      wrap.classList.add("is-dragging");
    });
    wrap.addEventListener("pointermove", function (e) {
      if (!dragging) return;
      var s = host.__ebs;
      s.tx += e.clientX - lx;
      s.ty += e.clientY - ly;
      lx = e.clientX;
      ly = e.clientY;
      apply(host);
    });
    function end() {
      dragging = false;
      wrap.classList.remove("is-dragging");
    }
    wrap.addEventListener("pointerup", end);
    wrap.addEventListener("pointercancel", end);
  }

  function scan() {
    var els = document.querySelectorAll("div.mermaid");
    for (var i = 0; i < els.length; i++) decorate(els[i]);
  }

  // Reset transforms when leaving fullscreen (native Esc or button).
  document.addEventListener("fullscreenchange", function () {
    if (!document.fullscreenElement) {
      var hosts = document.querySelectorAll(".eb-mermaid-wrap > .mermaid");
      for (var i = 0; i < hosts.length; i++) reset(hosts[i]);
    }
  });

  var observer = new MutationObserver(scan);
  observer.observe(document.body, { childList: true, subtree: true });
  if (document.readyState !== "loading") scan();
  else document.addEventListener("DOMContentLoaded", scan);
})();
