import { expect, test, type APIRequestContext, type Page } from "@playwright/test";

const PAGES = [
  ["/command", "Command Centre"],
  ["/intelligence", "Attack Intelligence"],
  ["/investigate", "Investigation Workbench"],
  ["/models", "Model Intelligence"],
  ["/defence", "Defence & Audit"],
  ["/replay", "Replay Lab"],
] as const;

async function backendReady(request: APIRequestContext) {
  await expect(async () => {
    const health = await (await request.get("/api/health")).json();
    expect(health.status).toBe("ok");
  }).toPass({ timeout: 60_000 });
}

/** Fails a test on any uncaught page error or console error, such as a broken API call. */
function watchErrors(page: Page) {
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  page.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });
  return errors;
}

test.describe.configure({ mode: "serial" });

test.beforeEach(async ({ request }) => { await backendReady(request); });

for (const [path, title] of PAGES) {
  test(`${title} renders with backend data and no errors`, async ({ page }) => {
    const errors = watchErrors(page);
    const calls: string[] = [];
    page.on("response", (r) => { if (r.url().includes("/api/") && r.ok()) calls.push(r.url()); });
    await page.goto(path);
    await expect(page.getByRole("heading", { name: title, exact: true })).toBeVisible();
    await expect.poll(() => calls.length).toBeGreaterThan(0);
    await page.waitForTimeout(1000);  // Pages poll and stream, so the network never goes idle.
    expect(errors).toEqual([]);
  });
}

test("replay controls drive the real engine and SSE streams real flows", async ({ page, request }) => {
  const errors = watchErrors(page);
  await page.goto("/replay");
  await expect(page.getByText("Stream connected").or(page.getByText(/connected/i)).first()).toBeVisible();
  await page.getByRole("button", { name: "Start", exact: true }).click();

  const feed = page.locator("table tbody tr").first();
  await expect(feed).toBeVisible({ timeout: 30_000 });
  const firstFlow = (await feed.locator("a").first().textContent())!;
  const detail = await request.get(`/api/flows/${firstFlow}`);
  expect(detail.ok()).toBeTruthy();
  const body = await detail.json();
  expect(body.flow_id).toBe(firstFlow);

  await page.getByRole("button", { name: "Pause", exact: true }).click();
  await expect.poll(async () => (await (await request.get("/api/replay/status")).json()).status).toBe("paused");
  const held = (await (await request.get("/api/replay/status")).json()).cursor;
  await page.waitForTimeout(600);
  expect((await (await request.get("/api/replay/status")).json()).cursor).toBe(held);

  await page.getByRole("button", { name: "Resume", exact: true }).click();
  await expect.poll(async () => (await (await request.get("/api/replay/status")).json()).cursor, { timeout: 30_000 }).toBeGreaterThan(held);

  await page.getByRole("button", { name: "Stop", exact: true }).click();
  await expect.poll(async () => (await (await request.get("/api/replay/status")).json()).status).toBe("stopped");
  const stopped = (await (await request.get("/api/replay/status")).json()).cursor;
  await page.waitForTimeout(500);
  expect((await (await request.get("/api/replay/status")).json()).cursor).toBe(stopped);
  expect(errors).toEqual([]);
});

test("command centre shows the same totals as the API", async ({ page, request }) => {
  await page.goto("/command");
  const status = await (await request.get("/api/replay/status")).json();
  const total = status.counts.total.toLocaleString("en-IN");
  await expect(page.getByText(total, { exact: true }).first()).toBeVisible();
});

test("workbench shows agent outputs, tool calls and a rendered evidence graph", async ({ page, request }) => {
  const list = await (await request.get("/api/flows?scope=historical&disagree=true&limit=1")).json();
  const flowId = list.items[0].flow_id;
  await page.goto(`/investigate?flow=${flowId}`);
  await expect(page.getByRole("heading", { name: flowId })).toBeVisible();
  await expect(page.getByText("Agent 1: threat detection", { exact: true })).toBeVisible();
  await expect(page.getByText("Agent 2", { exact: false }).first()).toBeVisible();
  const detail = await (await request.get(`/api/flows/${flowId}`)).json();
  await expect(page.getByText(detail.fusion.rationale)).toBeVisible();
  await expect(page.getByText(detail.investigation.tool_calls[0].tool).first()).toBeVisible();
  await expect(page.locator(".react-flow__node").first()).toBeVisible();
  expect(await page.locator(".react-flow__node").count()).toBeGreaterThan(3);
});

test("model intelligence draws charts and the measured evaluation modes", async ({ page, request }) => {
  await page.goto("/models");
  const metrics = await (await request.get("/api/metrics")).json();
  await expect(page.getByText("Evaluation modes")).toBeVisible();
  const macro = metrics.evaluation_report.evaluation_modes.mode_b_with_anomaly_and_fusion.macro_f1.toFixed(5);
  await expect(page.getByRole("cell", { name: macro }).first()).toBeVisible();
  expect(await page.locator(".recharts-surface").count()).toBeGreaterThan(0);
});

test("what-if simulation calls the backend and changes nothing until applied", async ({ page, request }) => {
  const before = (await (await request.get("/api/policy")).json()).thresholds;
  await page.goto("/defence");
  await page.locator("#allow_benign_confidence").fill("0.999");
  await page.getByRole("button", { name: "Simulate what-if" }).click();
  await expect(page.getByText(/changed|No decisions change/i).first()).toBeVisible({ timeout: 15_000 });
  expect((await (await request.get("/api/policy")).json()).thresholds).toEqual(before);
  await expect(page.getByText(/policy_simulation/).first()).toBeVisible({ timeout: 15_000 });
});

test("agents 4 and 5 report their real state", async ({ page, request }) => {
  const models = await (await request.get("/api/models/status")).json();
  if (!models.defense_available) {
    await page.goto("/defence");
    await expect(page.getByText("Off for this input")).toBeVisible();
    await expect(page.getByText(/need source_ip/)).toBeVisible();
    return;
  }
  await request.post("/api/replay/start", { data: { speed: 100000, batch_size: 1000, max_investigations_per_batch: 1 } });
  await expect.poll(async () => (await (await request.get("/api/replay/status")).json()).status, { timeout: 60_000 }).toBe("completed");
  const defense = await (await request.get("/api/defense")).json();
  expect(defense.policies.length).toBeGreaterThan(0);

  await page.goto("/defence");
  const policy = defense.policies[0];
  await expect(page.getByRole("button", { name: policy.policy_id, exact: true })).toBeVisible();
  await page.getByRole("button", { name: policy.policy_id, exact: true }).click();
  await expect(page.getByText(policy.rationale)).toBeVisible();

  await page.goto("/intelligence");
  await expect(page.getByText("Agent 4: temporal correlation")).toBeVisible();
  await expect(page.getByRole("cell", { name: defense.groups[0].group_id, exact: true })).toBeVisible();

  const blocked = await (await request.get("/api/flows?scope=replay&limit=500")).json();
  expect(blocked.items.some((f: { defense_action: string }) => f.defense_action)).toBeTruthy();
  const hit = blocked.items.find((f: { defense_action: string }) => f.defense_action === "BLOCK");
  if (hit) {
    await page.goto(`/investigate?flow=${hit.flow_id}`);
    await expect(page.getByText(`${hit.applied_policy_id}`).first()).toBeVisible();
  }
});
