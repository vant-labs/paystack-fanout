(() => {
  const root = document.documentElement;
  const saved = localStorage.getItem("fanout-theme");
  if (saved === "dark" || saved === "light") root.dataset.theme = saved;

  document.addEventListener("click", async (event) => {
    const themeButton = event.target.closest("[data-theme-toggle]");
    if (themeButton) {
      const next = root.dataset.theme === "dark" ? "light" : "dark";
      root.dataset.theme = next;
      localStorage.setItem("fanout-theme", next);
    }
    const copyButton = event.target.closest("[data-copy-target]");
    if (copyButton) {
      const target = document.querySelector(copyButton.dataset.copyTarget);
      if (!target) return;
      try {
        await navigator.clipboard.writeText(target.textContent);
        const original = copyButton.textContent;
        copyButton.textContent = "Copied";
        window.setTimeout(() => { copyButton.textContent = original; }, 1400);
      } catch (_) {
        copyButton.textContent = "Select to copy";
      }
    }
  });
})();
