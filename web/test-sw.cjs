const { chromium } = require("/Users/ankit/.npm/_npx/e41f203b7505f1fb/node_modules/playwright");

(async () => {
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({ viewport: { width: 1400, height: 900 } });

  page.on("console", msg => {
    if (msg.type() === "error") console.log("CONSOLE ERROR:", msg.text());
    if (msg.type() === "warning") console.log("CONSOLE WARN:", msg.text());
  });
  page.on("pageerror", err => console.log("PAGE ERROR:", err.message));

  await page.goto("http://localhost:5173/");
  await page.waitForTimeout(3000);

  // Check for service workers
  const swCount = await page.evaluate(() => navigator.serviceWorker?.getRegistrations?.()?.then(regs => regs.length) ?? 0);
  console.log("Service workers:", swCount);

  // Check for React errors
  const reactErrors = await page.evaluate(() => {
    if (window.__REACT_DEVTOOLS_GLOBAL_HOOK__) {
      const hook = window.__REACT_DEVTOOLS_GLOBAL_HOOK__;
      return {
        hasErrors: hook.renderers?.size > 0,
        renderers: Array.from(hook.renderers?.keys() ?? []),
      };
    }
    return { hasErrors: false, renderers: [] };
  });
  console.log("React devtools:", JSON.stringify(reactErrors));

  await browser.close();
})();
