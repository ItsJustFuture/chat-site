(() => {
  const DEFAULT_THEME = "Minimal Dark";
  try {
    const stored = localStorage.getItem("theme");
    const theme = stored && stored.trim() ? stored : DEFAULT_THEME;
    document.body?.setAttribute("data-theme", theme);
  } catch {
    document.body?.setAttribute("data-theme", DEFAULT_THEME);
  }
})();
