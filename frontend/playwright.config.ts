// Browser tests against the real FastAPI backend and saved models, in the locally installed Chrome.
// E2E_REPLAY_INPUT replays another flow file, so Agents 4 and 5 can be exercised on a file with endpoints.
import { defineConfig } from "@playwright/test";

const API_PORT = 8010;
const WEB_PORT = 5183;
const replayInput = process.env.E2E_REPLAY_INPUT;

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false,
  workers: 1,
  timeout: 90_000,
  reporter: [["list"]],
  use: { baseURL: `http://127.0.0.1:${WEB_PORT}`, channel: "chrome", screenshot: "only-on-failure" },
  outputDir: "../data/processed/e2e-artifacts",
  webServer: [
    {
      command: `../.venv/bin/uvicorn backend.main:app --port ${API_PORT} --app-dir ..`,
      url: `http://127.0.0.1:${API_PORT}/api/health`,
      env: { ...(replayInput ? { CYBERSENTINEL_REPLAY_INPUT: replayInput } : {}) },
      reuseExistingServer: false,
    },
    {
      command: `npx vite --port ${WEB_PORT} --host 127.0.0.1 --strictPort`,
      url: `http://127.0.0.1:${WEB_PORT}`,
      env: { VITE_API_TARGET: `http://127.0.0.1:${API_PORT}` },
      reuseExistingServer: false,
    },
  ],
});
