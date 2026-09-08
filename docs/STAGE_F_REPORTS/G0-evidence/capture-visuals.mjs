#!/usr/bin/env node

/**
 * Capture the G0 before-change production visual baseline without adding an
 * npm dependency. The script drives the installed system Chrome over the
 * Chrome DevTools Protocol, but all application data comes from the real
 * rules-only analyzer and console/serve.py API.
 *
 * Usage:
 *   node docs/STAGE_F_REPORTS/G0-evidence/capture-visuals.mjs \
 *     --expected-commit ac6ca48211f23eda062583a609ed8e4b35c42de3
 *
 * Set CHROME_BIN when Chrome is not installed in a standard macOS/Linux path.
 */

import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { inflateSync } from "node:zlib";

const SCRIPT_PATH = fileURLToPath(import.meta.url);
const REPO_ROOT = path.resolve(path.dirname(SCRIPT_PATH), "../../..");
const EVIDENCE_ROOT = path.dirname(SCRIPT_PATH);
const BASELINE_ROOT = path.join(EVIDENCE_ROOT, "baseline");
const MANIFEST_PATH = path.join(EVIDENCE_ROOT, "baseline-manifest.json");
const FIXTURE = "tests/eval/cases/pos_bruteforce_compromise.log";
const DETECTOR_SHA256 = "364577c5c8a3014b6c22b72ef7a4048933eb796a87fe1bac8f087eb577a4a876";
const VIEWPORT = { width: 1500, height: 1000, deviceScaleFactor: 1 };
const LOCALE = "en-GB";
const TIMEZONE = "UTC";
const NETWORK_IDLE_MS = 600;
const REPEAT_WAIT_MS = 5500;
const CAPTURE_STYLE = [
  "*,*::before,*::after{",
  "animation-delay:0s!important;animation-duration:0s!important;",
  "animation-iteration-count:1!important;transition-delay:0s!important;",
  "transition-duration:0s!important;caret-color:transparent!important;",
  "scroll-behavior:auto!important}",
].join("");

const ROUTES = [
  { slug: "overview", route: "/", state: "Overview", polls: [] },
  { slug: "alerts", route: "/alerts", state: "Alerts / Findings", polls: [5000] },
  { slug: "findings", route: "/findings", state: "Alerts / Findings legacy alias", polls: [5000] },
  { slug: "incidents", route: "/incidents", state: "Incidents", polls: [5000] },
  { slug: "cases", route: "/cases", state: "Cases", polls: [] },
  { slug: "approvals", route: "/approvals", state: "Approvals", polls: [5000] },
  { slug: "intel", route: "/intel", state: "Intel", polls: [] },
  { slug: "threat-intel", route: "/threat-intel", state: "ThreatIntel legacy wrapper", polls: [] },
  { slug: "enrichment", route: "/enrichment", state: "Enrichment legacy wrapper", polls: [] },
  { slug: "network", route: "/network", state: "Network", polls: [3000, 5000] },
  { slug: "discovery", route: "/discovery", state: "Network discovery tab alias", polls: [3000, 5000] },
  { slug: "vulnerabilities", route: "/vulnerabilities", state: "Network vulnerabilities tab alias", polls: [3000, 5000] },
  { slug: "assets", route: "/assets", state: "Assets", polls: [5000] },
  { slug: "sources", route: "/sources", state: "Sources", polls: [3000, 5000] },
  { slug: "collectors", route: "/collectors", state: "Sources legacy alias", polls: [3000, 5000] },
  { slug: "integrations", route: "/integrations", state: "Integrations", polls: [] },
  { slug: "history", route: "/history", state: "History", polls: [5000] },
  { slug: "reports", route: "/reports", state: "Reports (no active export)", polls: [] },
  { slug: "settings", route: "/settings", state: "Settings", polls: [] },
  { slug: "oem", route: "/oem", state: "OEM Engine direct route", polls: [5000] },
  { slug: "login", route: "/login", state: "Login actual local-auth state", polls: [] },
  { slug: "signup", route: "/signup", state: "Login component signup route", polls: [] },
  { slug: "logout", route: "/logout", state: "Logout in AppShell", polls: [] },
  { slug: "does-not-exist", route: "/does-not-exist", state: "Wildcard Not found", polls: [] },
];

function parseArgs(argv) {
  const out = { expectedCommit: null, port: null };
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === "--expected-commit") out.expectedCommit = argv[++i];
    else if (argv[i] === "--port") out.port = Number(argv[++i]);
    else throw new Error(`Unknown argument: ${argv[i]}`);
  }
  if (!out.expectedCommit) throw new Error("--expected-commit is required");
  if (out.port !== null && (!Number.isInteger(out.port) || out.port < 1024 || out.port > 65535)) {
    throw new Error("--port must be an integer from 1024 through 65535");
  }
  return out;
}

function sha256(input) {
  return createHash("sha256").update(input).digest("hex");
}

function fileSha(file) {
  return sha256(readFileSync(file));
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd ?? REPO_ROOT,
    encoding: "utf8",
    env: { ...process.env, TZ: TIMEZONE, ...options.env },
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error([
      `Command failed (${result.status}): ${command} ${args.join(" ")}`,
      result.stdout,
      result.stderr,
    ].filter(Boolean).join("\n"));
  }
  return { stdout: result.stdout.trim(), stderr: result.stderr.trim() };
}

function git(...args) {
  return run("git", args).stdout;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function freePort(requested) {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once("error", reject);
    server.listen(requested ?? 0, "127.0.0.1", () => {
      const address = server.address();
      const port = typeof address === "object" && address ? address.port : null;
      server.close((error) => error ? reject(error) : resolve(port));
    });
  });
}

async function waitForHttp(url, child, timeoutMs = 20000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error(`console/serve.py exited with ${child.exitCode}`);
    try {
      const status = await new Promise((resolve, reject) => {
        const req = http.get(url, (response) => {
          response.resume();
          response.once("end", () => resolve(response.statusCode));
        });
        req.once("error", reject);
        req.setTimeout(1000, () => req.destroy(new Error("request timeout")));
      });
      if (status === 200) return;
    } catch { /* server not ready yet */ }
    await sleep(100);
  }
  throw new Error(`Timed out waiting for ${url}`);
}

function chromeExecutable() {
  const candidates = [
    process.env.CHROME_BIN,
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "/usr/bin/google-chrome",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
  ].filter(Boolean);
  const found = candidates.find((candidate) => existsSync(candidate));
  if (!found) throw new Error("Chrome not found; set CHROME_BIN to an installed Chrome/Chromium executable");
  return found;
}

async function readDevToolsEndpoint(profileDir, child, timeoutMs = 20000) {
  const activePort = path.join(profileDir, "DevToolsActivePort");
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error(`Chrome exited with ${child.exitCode}`);
    if (existsSync(activePort)) {
      const [port, websocketPath] = readFileSync(activePort, "utf8").trim().split(/\r?\n/);
      if (port && websocketPath) return `ws://127.0.0.1:${port}${websocketPath}`;
    }
    await sleep(50);
  }
  throw new Error("Timed out waiting for Chrome DevToolsActivePort");
}

class CdpConnection {
  constructor(websocket) {
    this.websocket = websocket;
    this.nextId = 1;
    this.pending = new Map();
    this.listeners = new Map();
    websocket.addEventListener("message", (event) => this.#onMessage(event));
  }

  static async open(url) {
    const websocket = new WebSocket(url);
    await new Promise((resolve, reject) => {
      websocket.addEventListener("open", resolve, { once: true });
      websocket.addEventListener("error", reject, { once: true });
    });
    return new CdpConnection(websocket);
  }

  #key(method, sessionId) {
    return `${sessionId ?? "browser"}:${method}`;
  }

  #onMessage(event) {
    const message = JSON.parse(String(event.data));
    if (message.id) {
      const pending = this.pending.get(message.id);
      if (!pending) return;
      this.pending.delete(message.id);
      if (message.error) pending.reject(new Error(`${pending.method}: ${JSON.stringify(message.error)}`));
      else pending.resolve(message.result ?? {});
      return;
    }
    const listeners = this.listeners.get(this.#key(message.method, message.sessionId)) ?? [];
    for (const listener of [...listeners]) listener(message.params ?? {});
  }

  send(method, params = {}, sessionId = undefined, timeoutMs = 30000) {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`Timed out: ${method}`));
      }, timeoutMs);
      this.pending.set(id, {
        method,
        resolve: (value) => { clearTimeout(timer); resolve(value); },
        reject: (error) => { clearTimeout(timer); reject(error); },
      });
      this.websocket.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }));
    });
  }

  on(method, sessionId, listener) {
    const key = this.#key(method, sessionId);
    const listeners = this.listeners.get(key) ?? [];
    listeners.push(listener);
    this.listeners.set(key, listeners);
    return () => this.listeners.set(key, (this.listeners.get(key) ?? []).filter((item) => item !== listener));
  }

  once(method, sessionId, timeoutMs = 30000) {
    return new Promise((resolve, reject) => {
      let remove = () => {};
      const timer = setTimeout(() => {
        remove();
        reject(new Error(`Timed out waiting for ${method}`));
      }, timeoutMs);
      remove = this.on(method, sessionId, (params) => {
        clearTimeout(timer);
        remove();
        resolve(params);
      });
    });
  }

  close() {
    this.websocket.close();
  }
}

async function evaluate(cdp, sessionId, expression, awaitPromise = false) {
  const result = await cdp.send("Runtime.evaluate", {
    expression,
    awaitPromise,
    returnByValue: true,
    userGesture: true,
  }, sessionId);
  if (result.exceptionDetails) throw new Error(`Runtime.evaluate: ${result.exceptionDetails.text}`);
  return result.result?.value;
}

function remoteValue(arg) {
  if (Object.hasOwn(arg, "value")) {
    if (typeof arg.value === "string") return arg.value;
    try { return JSON.stringify(arg.value); } catch { return String(arg.value); }
  }
  return arg.description ?? arg.unserializableValue ?? arg.type ?? "unknown";
}

async function createPage(cdp, baseUrl, route, theme) {
  const { browserContextId } = await cdp.send("Target.createBrowserContext", { disposeOnDetach: true });
  const { targetId } = await cdp.send("Target.createTarget", { url: "about:blank", browserContextId });
  const { sessionId } = await cdp.send("Target.attachToTarget", { targetId, flatten: true });

  const errors = { console: [], page: [], network: [], http: [] };
  const activeRequests = new Set();
  let lastNetworkChange = Date.now();

  cdp.on("Runtime.consoleAPICalled", sessionId, (params) => {
    if (params.type === "error" || params.type === "assert") {
      errors.console.push({ type: params.type, text: params.args.map(remoteValue).join(" ") });
    }
  });
  cdp.on("Runtime.exceptionThrown", sessionId, (params) => {
    const detail = params.exceptionDetails ?? {};
    errors.page.push(detail.exception?.description ?? detail.text ?? "Uncaught page exception");
  });
  cdp.on("Log.entryAdded", sessionId, ({ entry }) => {
    if (entry?.level === "error") errors.console.push({ type: "log", text: entry.text, source: entry.source });
  });
  cdp.on("Network.requestWillBeSent", sessionId, ({ requestId }) => {
    activeRequests.add(requestId);
    lastNetworkChange = Date.now();
  });
  const finishRequest = ({ requestId }) => {
    activeRequests.delete(requestId);
    lastNetworkChange = Date.now();
  };
  cdp.on("Network.loadingFinished", sessionId, finishRequest);
  cdp.on("Network.loadingFailed", sessionId, (params) => {
    finishRequest(params);
    if (!params.canceled) errors.network.push({ errorText: params.errorText, type: params.type });
  });
  cdp.on("Network.responseReceived", sessionId, ({ response, type }) => {
    if (response.status >= 400) errors.http.push({ status: response.status, url: response.url, type });
  });

  await Promise.all([
    cdp.send("Page.enable", {}, sessionId),
    cdp.send("Runtime.enable", {}, sessionId),
    cdp.send("Log.enable", {}, sessionId),
    cdp.send("Network.enable", {}, sessionId),
  ]);
  await cdp.send("Emulation.setDeviceMetricsOverride", {
    width: VIEWPORT.width,
    height: VIEWPORT.height,
    deviceScaleFactor: VIEWPORT.deviceScaleFactor,
    mobile: false,
    screenWidth: VIEWPORT.width,
    screenHeight: VIEWPORT.height,
  }, sessionId);
  await cdp.send("Emulation.setLocaleOverride", { locale: LOCALE }, sessionId);
  await cdp.send("Emulation.setTimezoneOverride", { timezoneId: TIMEZONE }, sessionId);
  await cdp.send("Network.setExtraHTTPHeaders", { headers: { "Accept-Language": "en-GB,en;q=0.9" } }, sessionId);
  await cdp.send("Page.addScriptToEvaluateOnNewDocument", {
    source: `try { localStorage.setItem("itsoc-theme", ${JSON.stringify(theme)}); } catch {}`,
  }, sessionId);

  const load = cdp.once("Page.loadEventFired", sessionId);
  await cdp.send("Page.navigate", { url: `${baseUrl}${route}` }, sessionId);
  await load;

  const readinessDeadline = Date.now() + 30000;
  while (Date.now() < readinessDeadline) {
    const ready = await evaluate(cdp, sessionId,
      `document.readyState === "complete" && Boolean(document.querySelector("#root")?.firstElementChild)`);
    if (ready) break;
    await sleep(50);
  }
  if (Date.now() >= readinessDeadline) throw new Error(`React app did not render at ${route}`);

  await evaluate(cdp, sessionId,
    `(async()=>{await document.fonts.ready;return {status:document.fonts.status,count:document.fonts.size}})()`, true);

  async function waitNetworkIdle(timeoutMs = 15000) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      if (activeRequests.size === 0 && Date.now() - lastNetworkChange >= NETWORK_IDLE_MS) return;
      await sleep(50);
    }
    throw new Error(`Network did not become idle at ${route}; ${activeRequests.size} request(s) remain`);
  }
  await waitNetworkIdle();

  await evaluate(cdp, sessionId, `(()=>{
    const prior=document.querySelector("style[data-g0-capture]");if(prior)prior.remove();
    const style=document.createElement("style");style.dataset.g0Capture="true";
    style.textContent=${JSON.stringify(CAPTURE_STYLE)};document.head.appendChild(style);
    return new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)));
  })()`, true);

  const themeContract = await evaluate(cdp, sessionId, `({
    localStorage:localStorage.getItem("itsoc-theme"),
    dataTheme:document.documentElement.getAttribute("data-theme"),
    darkClass:document.documentElement.classList.contains("dark"),
    expected:${JSON.stringify(theme)},
    valid:localStorage.getItem("itsoc-theme")===${JSON.stringify(theme)} &&
      document.documentElement.getAttribute("data-theme")===${JSON.stringify(theme)} &&
      document.documentElement.classList.contains("dark")===${theme === "dark"}
  })`);
  if (!themeContract.valid) throw new Error(`Theme contract mismatch at ${route}: ${JSON.stringify(themeContract)}`);

  const documentState = await evaluate(cdp, sessionId, `({
    title:document.title,
    lang:document.documentElement.lang,
    navigatorLanguage:navigator.language,
    fontStatus:document.fonts.status,
    fontCount:document.fonts.size,
    rootTextLength:document.querySelector("#root")?.textContent?.length ?? 0,
    pathname:location.pathname
  })`);

  return { browserContextId, targetId, sessionId, errors, waitNetworkIdle, themeContract, documentState };
}

async function closePage(cdp, page) {
  try { await cdp.send("Target.closeTarget", { targetId: page.targetId }); } catch { /* cleanup */ }
  try { await cdp.send("Target.disposeBrowserContext", { browserContextId: page.browserContextId }); } catch { /* cleanup */ }
}

async function screenshot(cdp, sessionId) {
  const result = await cdp.send("Page.captureScreenshot", {
    format: "png",
    fromSurface: true,
    captureBeyondViewport: false,
    optimizeForSpeed: false,
  }, sessionId);
  return Buffer.from(result.data, "base64");
}

async function stableScreenshot(cdp, sessionId) {
  let previous = await screenshot(cdp, sessionId);
  const hashes = [sha256(previous)];
  for (let attempt = 2; attempt <= 8; attempt += 1) {
    await sleep(200);
    const current = await screenshot(cdp, sessionId);
    hashes.push(sha256(current));
    if (current.equals(previous)) return { buffer: current, attempts: attempt, hashes, exact: true };
    previous = current;
  }
  return { buffer: previous, attempts: 8, hashes, exact: false };
}

function pngInfo(buffer) {
  const signature = "89504e470d0a1a0a";
  if (buffer.subarray(0, 8).toString("hex") !== signature) throw new Error("Not a PNG");
  return {
    width: buffer.readUInt32BE(16),
    height: buffer.readUInt32BE(20),
    bitDepth: buffer[24],
    colorType: buffer[25],
    interlace: buffer[28],
  };
}

function paeth(a, b, c) {
  const p = a + b - c;
  const pa = Math.abs(p - a);
  const pb = Math.abs(p - b);
  const pc = Math.abs(p - c);
  if (pa <= pb && pa <= pc) return a;
  return pb <= pc ? b : c;
}

function decodePng(buffer) {
  const info = pngInfo(buffer);
  if (info.bitDepth !== 8 || info.interlace !== 0 || ![0, 2, 4, 6].includes(info.colorType)) {
    throw new Error(`Unsupported PNG layout: ${JSON.stringify(info)}`);
  }
  const chunks = [];
  let offset = 8;
  while (offset < buffer.length) {
    const length = buffer.readUInt32BE(offset);
    const type = buffer.subarray(offset + 4, offset + 8).toString("ascii");
    if (type === "IDAT") chunks.push(buffer.subarray(offset + 8, offset + 8 + length));
    offset += 12 + length;
    if (type === "IEND") break;
  }
  const raw = inflateSync(Buffer.concat(chunks));
  const channels = ({ 0: 1, 2: 3, 4: 2, 6: 4 })[info.colorType];
  const stride = info.width * channels;
  const scanlines = Buffer.alloc(info.height * stride);
  let rawOffset = 0;
  for (let y = 0; y < info.height; y += 1) {
    const filter = raw[rawOffset++];
    const rowOffset = y * stride;
    const priorOffset = rowOffset - stride;
    for (let x = 0; x < stride; x += 1) {
      const encoded = raw[rawOffset++];
      const left = x >= channels ? scanlines[rowOffset + x - channels] : 0;
      const up = y > 0 ? scanlines[priorOffset + x] : 0;
      const upperLeft = y > 0 && x >= channels ? scanlines[priorOffset + x - channels] : 0;
      let value;
      if (filter === 0) value = encoded;
      else if (filter === 1) value = encoded + left;
      else if (filter === 2) value = encoded + up;
      else if (filter === 3) value = encoded + Math.floor((left + up) / 2);
      else if (filter === 4) value = encoded + paeth(left, up, upperLeft);
      else throw new Error(`Unsupported PNG filter ${filter}`);
      scanlines[rowOffset + x] = value & 0xff;
    }
  }
  const rgba = Buffer.alloc(info.width * info.height * 4);
  for (let pixel = 0; pixel < info.width * info.height; pixel += 1) {
    const source = pixel * channels;
    const target = pixel * 4;
    if (info.colorType === 0 || info.colorType === 4) {
      rgba[target] = scanlines[source];
      rgba[target + 1] = scanlines[source];
      rgba[target + 2] = scanlines[source];
      rgba[target + 3] = info.colorType === 4 ? scanlines[source + 1] : 255;
    } else {
      rgba[target] = scanlines[source];
      rgba[target + 1] = scanlines[source + 1];
      rgba[target + 2] = scanlines[source + 2];
      rgba[target + 3] = info.colorType === 6 ? scanlines[source + 3] : 255;
    }
  }
  return { ...info, rgba };
}

function pixelDiff(before, after) {
  const a = decodePng(before);
  const b = decodePng(after);
  if (a.width !== b.width || a.height !== b.height) {
    throw new Error(`Screenshot dimensions differ: ${a.width}x${a.height} vs ${b.width}x${b.height}`);
  }
  let changedPixels = 0;
  let minX = a.width;
  let minY = a.height;
  let maxX = -1;
  let maxY = -1;
  for (let pixel = 0; pixel < a.width * a.height; pixel += 1) {
    const offset = pixel * 4;
    if (a.rgba[offset] !== b.rgba[offset]
        || a.rgba[offset + 1] !== b.rgba[offset + 1]
        || a.rgba[offset + 2] !== b.rgba[offset + 2]
        || a.rgba[offset + 3] !== b.rgba[offset + 3]) {
      changedPixels += 1;
      const x = pixel % a.width;
      const y = Math.floor(pixel / a.width);
      minX = Math.min(minX, x);
      minY = Math.min(minY, y);
      maxX = Math.max(maxX, x);
      maxY = Math.max(maxY, y);
    }
  }
  const totalPixels = a.width * a.height;
  return {
    changedPixels,
    totalPixels,
    changedRatio: changedPixels / totalPixels,
    changedBounds: changedPixels ? { minX, minY, maxX, maxY } : null,
  };
}

async function captureThemeToggle(cdp, baseUrl) {
  const page = await createPage(cdp, baseUrl, "/settings", "light");
  try {
    const before = await evaluate(cdp, page.sessionId,
      `({stored:localStorage.getItem("itsoc-theme"),dataTheme:document.documentElement.dataset.theme,dark:document.documentElement.classList.contains("dark")})`);
    const clickedDark = await evaluate(cdp, page.sessionId,
      `(()=>{const b=document.querySelector('[aria-label="Switch to dark mode"]');if(!b)return false;b.click();return true})()`);
    if (!clickedDark) throw new Error("Real theme toggle to dark was not reachable");
    await sleep(100);
    const dark = await evaluate(cdp, page.sessionId,
      `({stored:localStorage.getItem("itsoc-theme"),dataTheme:document.documentElement.dataset.theme,dark:document.documentElement.classList.contains("dark")})`);
    const clickedLight = await evaluate(cdp, page.sessionId,
      `(()=>{const b=document.querySelector('[aria-label="Switch to light mode"]');if(!b)return false;b.click();return true})()`);
    if (!clickedLight) throw new Error("Real theme toggle to light was not reachable");
    await sleep(100);
    const light = await evaluate(cdp, page.sessionId,
      `({stored:localStorage.getItem("itsoc-theme"),dataTheme:document.documentElement.dataset.theme,dark:document.documentElement.classList.contains("dark")})`);
    const passed = before.stored === "light" && before.dataTheme === "light" && before.dark === false
      && dark.stored === "dark" && dark.dataTheme === "dark" && dark.dark === true
      && light.stored === "light" && light.dataTheme === "light" && light.dark === false;
    return { passed, route: "/settings", control: "real DOM theme button", before, afterDarkClick: dark, afterLightClick: light };
  } finally {
    await closePage(cdp, page);
  }
}

async function stopChild(child, signal) {
  if (!child || child.exitCode !== null) return;
  child.kill(signal);
  await Promise.race([
    new Promise((resolve) => child.once("exit", resolve)),
    sleep(3000),
  ]);
  if (child.exitCode === null) child.kill("SIGTERM");
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  process.chdir(REPO_ROOT);

  const sourceCommit = git("rev-parse", "HEAD");
  if (sourceCommit !== args.expectedCommit) {
    throw new Error(`HEAD ${sourceCommit} does not equal expected commit ${args.expectedCommit}`);
  }
  run("git", ["merge-base", "--is-ancestor", args.expectedCommit, "HEAD"]);
  const branch = git("branch", "--show-current");
  const detectorSha = fileSha(path.join(REPO_ROOT, "anomaly_detector.py"));
  if (detectorSha !== DETECTOR_SHA256) throw new Error(`Frozen detector hash mismatch: ${detectorSha}`);

  const requiredTreePaths = [
    "web/src/styles/itsoc.css",
    "web/src/index.css",
    "console/serve.py",
    FIXTURE,
    "docs/STAGE_F_REPORTS/G0-evidence/research.md",
  ];
  for (const requiredPath of requiredTreePaths) run("git", ["cat-file", "-e", `HEAD:${requiredPath}`]);

  const packageFiles = ["web/package.json", "web/package-lock.json"];
  const packageBefore = Object.fromEntries(packageFiles.map((file) => [file, fileSha(path.join(REPO_ROOT, file))]));
  const statePaths = ["console/.soc", "console/.runs", "console/console_state.json"];
  const preexistingState = statePaths.filter((file) => existsSync(path.join(REPO_ROOT, file)));
  if (preexistingState.length) {
    throw new Error(`Fresh isolated server state required; these paths already exist: ${preexistingState.join(", ")}`);
  }

  const workDir = mkdtempSync(path.join(os.tmpdir(), "itsoc-g0-visual-"));
  const chromeProfile = path.join(workDir, "chrome-profile");
  const reportPrefix = path.join(workDir, "report");
  mkdirSync(chromeProfile, { recursive: true });
  rmSync(BASELINE_ROOT, { recursive: true, force: true });
  mkdirSync(BASELINE_ROOT, { recursive: true });

  let server;
  let chrome;
  let cdp;
  const serverOutput = [];
  const chromeOutput = [];
  try {
    const analyzer = run("python3", [
      "log_analyzer.py", "--input", FIXTURE, "--output", reportPrefix, "--rules-only",
    ]);
    const reportPath = `${reportPrefix}.json`;
    const reportBuffer = readFileSync(reportPath);
    const report = JSON.parse(reportBuffer);

    const install = run("npm", ["ci", "--ignore-scripts"], {
      cwd: path.join(REPO_ROOT, "web"),
      env: { npm_config_loglevel: "warn" },
    });
    const build = run("npm", ["run", "build"], {
      cwd: path.join(REPO_ROOT, "web"),
      env: { npm_config_loglevel: "warn" },
    });
    if (!existsSync(path.join(REPO_ROOT, "web/dist/index.html"))) {
      throw new Error("Production build did not create web/dist/index.html");
    }

    const port = await freePort(args.port);
    const baseUrl = `http://127.0.0.1:${port}`;
    server = spawn("python3", ["console/serve.py", "--report", reportPath, "--port", String(port), "--no-open"], {
      cwd: REPO_ROOT,
      env: { ...process.env, TZ: TIMEZONE, ITSOC_OEM: "0", ITSOC_AUTH: "0", PYTHONUNBUFFERED: "1" },
      stdio: ["ignore", "pipe", "pipe"],
    });
    server.stdout.on("data", (data) => serverOutput.push(String(data)));
    server.stderr.on("data", (data) => serverOutput.push(String(data)));
    await waitForHttp(`${baseUrl}/`, server);

    const chromeBin = chromeExecutable();
    const chromeVersion = run(chromeBin, ["--version"]).stdout;
    chrome = spawn(chromeBin, [
      "--headless=new",
      "--remote-debugging-port=0",
      `--user-data-dir=${chromeProfile}`,
      `--window-size=${VIEWPORT.width},${VIEWPORT.height}`,
      `--lang=${LOCALE}`,
      "--no-first-run",
      "--no-default-browser-check",
      "--disable-background-networking",
      "--disable-component-update",
      "--disable-default-apps",
      "--disable-sync",
      "--metrics-recording-only",
      "--force-color-profile=srgb",
      "about:blank",
    ], { stdio: ["ignore", "pipe", "pipe"] });
    chrome.stdout.on("data", (data) => chromeOutput.push(String(data)));
    chrome.stderr.on("data", (data) => chromeOutput.push(String(data)));
    cdp = await CdpConnection.open(await readDevToolsEndpoint(chromeProfile, chrome));
    const browserVersion = await cdp.send("Browser.getVersion");

    const captures = [];
    const stabilityProofs = [];
    for (const theme of ["light", "dark"]) {
      const themeDir = path.join(BASELINE_ROOT, theme);
      const repeatDir = path.join(BASELINE_ROOT, "stability", theme);
      mkdirSync(themeDir, { recursive: true });
      mkdirSync(repeatDir, { recursive: true });

      for (const route of ROUTES) {
        const page = await createPage(cdp, baseUrl, route.route, theme);
        try {
          // The first real /api/incidents call persists its derived incident
          // projection; the next 5 s poll then carries linked-case metadata.
          // Let one real poll cycle complete before photographing this route so
          // the baseline does not freeze that known first-request intermediate
          // state. Nothing is injected or masked.
          const preCapturePollWaitMs = route.slug === "incidents" ? REPEAT_WAIT_MS : 0;
          if (preCapturePollWaitMs) {
            await sleep(preCapturePollWaitMs);
            await page.waitNetworkIdle();
          }
          const captured = await stableScreenshot(cdp, page.sessionId);
          if (!captured.exact) throw new Error(`${theme} ${route.route} did not reach two byte-identical consecutive screenshots`);
          const info = pngInfo(captured.buffer);
          if (info.width !== VIEWPORT.width || info.height !== VIEWPORT.height) {
            throw new Error(`Unexpected image size at ${route.route}: ${info.width}x${info.height}`);
          }
          const relativeFile = path.posix.join(
            "docs/STAGE_F_REPORTS/G0-evidence/baseline", theme, `${route.slug}.png`,
          );
          writeFileSync(path.join(REPO_ROOT, relativeFile), captured.buffer);

          captures.push({
            id: `${theme}:${route.slug}`,
            route: route.route,
            state: route.state,
            theme,
            url: `${baseUrl}${route.route}`,
            file: relativeFile,
            width: info.width,
            height: info.height,
            sha256: sha256(captured.buffer),
            sourceCommit,
            themeContract: page.themeContract,
            document: page.documentState,
            dynamicRegions: {
              pollingIntervalsMs: route.polls,
              activeDuringCapture: route.route === "/reports" ? "no export job active" : route.polls.length > 0,
              preCapturePollWaitMs,
              treatment: preCapturePollWaitMs
                ? "No region was masked. One real application poll cycle completed before capture; capture then waited for network idle, loaded fonts, and two byte-identical screenshots."
                : "No region was masked. Capture waited for network idle, loaded fonts, and two byte-identical screenshots; known polling intervals remain enumerated here.",
            },
            consecutiveStability: {
              exact: captured.exact,
              attempts: captured.attempts,
              sha256Attempts: captured.hashes,
              intervalMs: 200,
            },
            errors: page.errors,
          });

          if (route.slug === "overview" || route.slug === "incidents") {
            await sleep(REPEAT_WAIT_MS);
            await page.waitNetworkIdle();
            const repeated = await stableScreenshot(cdp, page.sessionId);
            if (!repeated.exact) throw new Error(`Repeat ${theme} ${route.route} did not stabilize`);
            const relativeRepeat = path.posix.join(
              "docs/STAGE_F_REPORTS/G0-evidence/baseline/stability", theme, `${route.slug}-repeat.png`,
            );
            writeFileSync(path.join(REPO_ROOT, relativeRepeat), repeated.buffer);
            const diff = pixelDiff(captured.buffer, repeated.buffer);
            stabilityProofs.push({
              route: route.route,
              state: route.state,
              theme,
              originalFile: relativeFile,
              repeatFile: relativeRepeat,
              originalSha256: sha256(captured.buffer),
              repeatSha256: sha256(repeated.buffer),
              waitAfterOriginalMs: REPEAT_WAIT_MS,
              repeatConsecutiveStability: {
                exact: repeated.exact,
                attempts: repeated.attempts,
                sha256Attempts: repeated.hashes,
                intervalMs: 200,
              },
              ...diff,
              exact: diff.changedPixels === 0,
              namedIrreduciblePixels: diff.changedPixels === 0 ? [] : [
                `Unstable pixels bounded by ${JSON.stringify(diff.changedBounds)} after ${REPEAT_WAIT_MS}ms`,
              ],
            });
          }
        } finally {
          await closePage(cdp, page);
        }
      }
    }

    const themeToggleCheck = await captureThemeToggle(cdp, baseUrl);
    if (!themeToggleCheck.passed) throw new Error(`Theme toggle contract failed: ${JSON.stringify(themeToggleCheck)}`);

    const packageAfter = Object.fromEntries(packageFiles.map((file) => [file, fileSha(path.join(REPO_ROOT, file))]));
    const packageUnchanged = packageFiles.every((file) => packageBefore[file] === packageAfter[file]);
    const allErrors = captures.flatMap((capture) => [
      ...capture.errors.console.map((error) => ({ capture: capture.id, kind: "console", error })),
      ...capture.errors.page.map((error) => ({ capture: capture.id, kind: "page", error })),
      ...capture.errors.network.map((error) => ({ capture: capture.id, kind: "network", error })),
      ...capture.errors.http.map((error) => ({ capture: capture.id, kind: "http", error })),
    ]);
    const irreduciblePixels = stabilityProofs
      .filter((proof) => !proof.exact)
      .map((proof) => ({ route: proof.route, theme: proof.theme, descriptions: proof.namedIrreduciblePixels }));
    const isKnownFaviconError = (entry) => (
      (entry.kind === "http" && entry.error?.status === 404 && entry.error?.url?.endsWith("/favicon.ico"))
      || (entry.kind === "console" && entry.error?.source === "network"
        && entry.error?.text?.includes("No such build asset"))
    );
    const classifiedErrors = allErrors.map((entry) => ({
      ...entry,
      classification: isKnownFaviconError(entry)
        ? "known missing favicon asset; recorded, not masked"
        : "unexpected",
    }));
    const unexpectedErrors = classifiedErrors.filter((entry) => entry.classification === "unexpected");

    const manifest = {
      schemaVersion: 1,
      kind: "itsoc-g0-before-change-production-visual-baseline",
      generatedAt: new Date().toISOString(),
      source: {
        commit: sourceCommit,
        expectedCommit: args.expectedCommit,
        branch,
        baseAncestryVerified: true,
        photographedTreeArtifacts: requiredTreePaths,
      },
      detector: { path: "anomaly_detector.py", sha256: detectorSha, expectedSha256: DETECTOR_SHA256, matchesFreeze: true },
      reportProvenance: {
        input: { path: FIXTURE, sha256: fileSha(path.join(REPO_ROOT, FIXTURE)) },
        analyzer: {
          path: "log_analyzer.py",
          command: `python3 log_analyzer.py --input ${FIXTURE} --output <temporary>/report --rules-only`,
          rulesOnly: true,
          stdout: analyzer.stdout.split(/\r?\n/),
        },
        report: {
          sha256: sha256(reportBuffer),
          generatedAt: report.generated_at,
          sourceFile: report.source_file,
          linesParsed: report.lines_parsed,
          linesUnparsed: report.lines_unparsed,
          totalFindings: report.total_findings,
          findingsBySource: report.findings_by_source,
          model: report.model,
        },
      },
      productionRuntime: {
        dependencyInstallCommand: "npm ci --ignore-scripts (cwd web; declared lockfile only)",
        dependencyInstallStdout: install.stdout.split(/\r?\n/),
        buildCommand: "npm run build (cwd web)",
        buildStdout: build.stdout.split(/\r?\n/),
        serverCommand: `python3 console/serve.py --report <temporary>/report.json --port ${port} --no-open`,
        serverImplementation: "console/serve.py serving web/dist plus its real /api routes",
        baseUrl,
        externalOemEnabled: false,
        authRequired: false,
        mockedApi: false,
        stagedComponentState: false,
        mockup: false,
      },
      captureSettings: {
        viewport: VIEWPORT,
        locale: LOCALE,
        timezone: TIMEZONE,
        browser: {
          executable: chromeBin,
          version: chromeVersion,
          protocolVersion: browserVersion.protocolVersion,
          product: browserVersion.product,
          userAgent: browserVersion.userAgent,
          revision: browserVersion.revision,
          headless: "new",
          colorProfile: "srgb",
        },
        platform: { node: process.version, os: `${os.platform()} ${os.release()} ${os.arch()}` },
        fonts: "Each page awaited document.fonts.ready and recorded font status/count.",
        network: `Each page waited for zero active requests and ${NETWORK_IDLE_MS}ms of network quiet.`,
        animations: { disabledOnlyInBrowserForCapture: true, injectedStyle: CAPTURE_STYLE },
        regionMasks: [],
        immediateStability: "Each saved image is the second of two byte-identical PNGs 200ms apart.",
        routeInventorySource: "docs/STAGE_F_REPORTS/G0-evidence/research.md section 6",
      },
      packageManifestCheck: {
        files: packageFiles.map((file) => ({ path: file, beforeSha256: packageBefore[file], afterSha256: packageAfter[file] })),
        unchanged: packageUnchanged,
        packageFilesAdded: [],
        dependenciesAdded: [],
      },
      themeToggleCheck,
      captures,
      stabilityProofs,
      irreduciblePixels,
      consoleAndPageErrors: classifiedErrors,
      summary: {
        routeStates: ROUTES.length,
        themes: ["light", "dark"],
        primaryEvidenceCount: captures.length,
        repeatEvidenceCount: stabilityProofs.length,
        totalPngCount: captures.length + stabilityProofs.length,
        primaryDimensions: `${VIEWPORT.width}x${VIEWPORT.height}`,
        exactRepeatProofs: stabilityProofs.filter((proof) => proof.exact).length,
        nonExactRepeatProofs: stabilityProofs.filter((proof) => !proof.exact).length,
        irreduciblePixelGroups: irreduciblePixels.length,
        consoleAndPageErrorCount: classifiedErrors.length,
        knownConsoleAndPageErrorCount: classifiedErrors.length - unexpectedErrors.length,
        unexpectedConsoleAndPageErrorCount: unexpectedErrors.length,
      },
    };
    writeFileSync(MANIFEST_PATH, `${JSON.stringify(manifest, null, 2)}\n`);

    if (!packageUnchanged) throw new Error("Package manifest or lockfile changed during capture");
    if (captures.length !== ROUTES.length * 2) throw new Error(`Expected 48 primary captures, got ${captures.length}`);
    if (stabilityProofs.length !== 4 || stabilityProofs.some((proof) => !proof.exact)) {
      throw new Error("Overview/Incidents repeat-capture stability was not exact in both themes");
    }
    if (unexpectedErrors.length) throw new Error(`Captured ${unexpectedErrors.length} unexpected console/page/network/HTTP error(s)`);

    process.stdout.write(`${JSON.stringify({
      ok: true,
      manifest: path.relative(REPO_ROOT, MANIFEST_PATH),
      primaryEvidenceCount: captures.length,
      repeatEvidenceCount: stabilityProofs.length,
      exactRepeatProofs: stabilityProofs.filter((proof) => proof.exact).length,
      sourceCommit,
      detectorSha256: detectorSha,
      packageManifestUnchanged: packageUnchanged,
    }, null, 2)}\n`);
  } finally {
    if (cdp) {
      try { await cdp.send("Browser.close"); } catch { /* cleanup */ }
      cdp.close();
    }
    await stopChild(chrome, "SIGTERM");
    await stopChild(server, "SIGINT");
    for (const statePath of statePaths) rmSync(path.join(REPO_ROOT, statePath), { recursive: true, force: true });
    rmSync(workDir, { recursive: true, force: true });
    if (serverOutput.length) process.stderr.write(serverOutput.join("").trimEnd() + "\n");
    const meaningfulChromeOutput = chromeOutput.join("").split(/\r?\n/)
      .filter((line) => line
        && !line.includes("DevTools listening on")
        && !line.includes("CVDisplayLinkCreateWithCGDisplay failed")
        && !line.includes("task_policy_set TASK_"));
    if (meaningfulChromeOutput.length) process.stderr.write(meaningfulChromeOutput.join("\n") + "\n");
  }
}

main().catch((error) => {
  process.stderr.write(`${error.stack ?? error}\n`);
  process.exitCode = 1;
});
