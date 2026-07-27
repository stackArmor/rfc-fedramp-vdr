(() => {
  const banner = document.createElement("aside");
  banner.setAttribute("role", "status");
  banner.setAttribute("aria-label", "Development preview");
  banner.style.cssText = [
    "position:sticky",
    "top:0",
    "z-index:10000",
    "display:flex",
    "justify-content:center",
    "align-items:center",
    "gap:.75rem",
    "padding:.55rem 1rem",
    "background:#7a2e16",
    "color:#fff7e8",
    "font:600 13px/1.3 -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif",
    "box-shadow:0 2px 10px rgba(0,0,0,.35)",
  ].join(";");

  const label = document.createElement("span");
  label.textContent = "DEV PREVIEW — not the production publication";

  const production = document.createElement("a");
  production.href = "../";
  production.textContent = "View production";
  production.style.cssText = "color:#fff7e8;text-decoration:underline";

  banner.append(label, production);
  document.body.prepend(banner);
})();
