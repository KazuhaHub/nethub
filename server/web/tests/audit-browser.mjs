import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export async function verifyAudit({ page, origin, evidence, login }) {
  const screenshots = [];
  const screenshot = async (name) => {
    await page.screenshot({
      path: join(evidence, name),
      animations: "disabled",
    });
    screenshots.push({
      name,
      sha256: createHash("sha256")
        .update(readFileSync(join(evidence, name)))
        .digest("hex"),
    });
  };
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.request.post(origin + "/test/users-reset");
  await page.context().clearCookies();
  await page.goto(origin + "/login");
  await login({ waitForRateLimit: true });
  await page.getByRole("link", { name: "Audit log", exact: true }).click();
  await page.locator("tbody tr").first().waitFor();
  assert.equal(await page.locator("tbody tr").count(), 50);
  await page.getByRole("button", { name: "Next", exact: true }).click();
  await page.waitForFunction(
    () => document.querySelectorAll("tbody tr").length === 5,
  );
  await page.getByRole("button", { name: "Previous", exact: true }).click();
  await page.waitForFunction(
    () => document.querySelectorAll("tbody tr").length === 50,
  );
  await screenshot("audit-desktop.png");
  await page
    .getByLabel("Action", { exact: true })
    .fill("device.access_granted");
  await page
    .getByRole("button", { name: "Apply filters", exact: true })
    .click();
  await page.waitForFunction(
    () => document.querySelectorAll("tbody tr").length === 18,
  );
  assert.equal(
    await page.locator("tbody dt").filter({ hasText: "expires at" }).count(),
    18,
  );
  assert.ok(
    (await page.locator("tbody").innerText()).includes("device.access_granted"),
  );
  assert.equal(
    (await page.locator("tbody").innerText()).includes("device.enrolled"),
    false,
  );
  await page.setViewportSize({ width: 390, height: 844 });
  assert.equal(
    await page.evaluate(
      () => document.documentElement.scrollWidth > innerWidth,
    ),
    false,
  );
  await screenshot("audit-mobile.png");
  await page
    .locator(".audit-events")
    .evaluate((element) => element.scrollIntoView({ block: "start" }));
  const frame = page.locator(".audit-events > div");
  assert.equal(
    await frame.evaluate(
      (element) => element.scrollWidth > element.clientWidth,
    ),
    true,
  );
  await frame.evaluate((element) => {
    element.scrollLeft = element.scrollWidth;
  });
  assert.ok(await frame.evaluate((element) => element.scrollLeft > 0));
  await screenshot("audit-mobile-events.png");
  await page.getByLabel("Action", { exact: true }).fill("no.matches");
  await page
    .getByRole("button", { name: "Apply filters", exact: true })
    .click();
  await page
    .getByText("No audit events match these filters.", { exact: true })
    .waitFor();
  await page.route("**/api/v1/console/audit?*", (route) =>
    route.fulfill({
      status: 500,
      contentType: "application/json",
      body: JSON.stringify({
        error: { code: "internal_error", message: "Audit fixture unavailable" },
      }),
    }),
  );
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await page.getByRole("alert").waitFor();
  assert.equal(await page.locator("tbody tr").count(), 0);
  await page.unroute("**/api/v1/console/audit?*");
  await page.request.post(origin + "/test/member");
  await page.goto(origin + "/audit");
  await page.locator("tbody tr").first().waitFor();
  assert.equal(await page.locator("tbody tr").count(), 28);
  assert.equal(await page.getByLabel("User ID", { exact: true }).count(), 0);
  assert.equal(
    (await page.locator("tbody").innerText()).includes(
      "00000000-0000-4000-8000-000000000099",
    ),
    false,
  );
  await page
    .locator(".audit-events")
    .evaluate((element) => element.scrollIntoView({ block: "start" }));
  await screenshot("audit-member-mobile.png");
  writeFileSync(
    join(evidence, "audit-results.json"),
    JSON.stringify(
      {
        passed: true,
        synthetic_fixture: true,
        actual_PostgreSQL_acceptance: false,
        full_goal_complete: false,
        screenshots,
      },
      null,
      2,
    ) + "\n",
  );
}
