import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export async function verifyTraffic({ page, origin, evidence, login }) {
  const requests = [],
    screenshots = [];
  const record = (request) => {
    if (new URL(request.url()).pathname.startsWith("/api/v1/console/traffic"))
      requests.push(request);
  };
  const writes = () =>
    requests.filter((request) => request.method() === "PATCH");
  const dialog = page.getByRole("dialog");
  const warning = () =>
    page.getByRole("button", { name: "Monthly warning", exact: true });
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
  page.on("request", record);
  try {
    await page.setViewportSize({ width: 1440, height: 1000 });
    await page.request.post(origin + "/test/users-reset");
    await page.context().clearCookies();
    await page.goto(origin + "/login");
    await login({ waitForRateLimit: true });
    await page.getByRole("link", { name: "Traffic", exact: true }).click();
    await page
      .getByText("18446744073709551614 bytes", { exact: true })
      .waitFor();
    await page.getByRole("button", { name: "Next traffic page" }).click();
    await page.getByText("Traffic device 51", { exact: true }).waitFor();
    assert.ok((await page.locator("tbody").innerText()).includes("Removed"));
    assert.equal(
      await page
        .getByText("18446744073709551614 bytes", { exact: true })
        .count(),
      1,
      "Total must span all pages",
    );
    await page.getByRole("button", { name: "Previous traffic page" }).click();
    await page.getByText("Traffic device 00", { exact: true }).waitFor();
    await warning().click();
    await dialog
      .getByLabel("Warning threshold (bytes)", { exact: true })
      .fill("18446744073709551613");
    await dialog
      .getByRole("button", { name: "Save warning", exact: true })
      .click();
    await dialog.waitFor({ state: "hidden" });
    await page.getByText(/Monthly warning exceeded/).waitFor();
    assert.deepEqual(writes().at(-1).postDataJSON(), {
      warning_bytes: "18446744073709551613",
      expected_revision: 0,
    });
    assert.ok(writes().at(-1).headers()["x-csrf-token"]);
    assert.equal(writes().at(-1).headers()["x-nethub-background"], undefined);
    if (
      await page
        .getByRole("button", { name: "Use light theme", exact: true })
        .count()
    )
      await page
        .getByRole("button", { name: "Use light theme", exact: true })
        .click();
    await page.waitForFunction(
      () => !document.documentElement.classList.contains("dark"),
    );
    await screenshot("traffic-light.png");
    await page
      .getByRole("button", { name: "Use dark theme", exact: true })
      .click();
    await page.waitForFunction(() =>
      document.documentElement.classList.contains("dark"),
    );
    await screenshot("traffic-dark.png");
    const contrast = await page
      .locator(".traffic-warning")
      .evaluate((element) => {
        const rgb = (value) =>
          value
            .match(/[\d.]+/g)
            .slice(0, 3)
            .map(Number);
        const luminance = (values) =>
          values
            .map((value) => {
              value /= 255;
              return value <= 0.04045
                ? value / 12.92
                : ((value + 0.055) / 1.055) ** 2.4;
            })
            .reduce(
              (sum, value, index) =>
                sum + value * [0.2126, 0.7152, 0.0722][index],
              0,
            );
        const style = getComputedStyle(element),
          a = luminance(rgb(style.color)),
          b = luminance(rgb(style.backgroundColor));
        return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
      });
    assert.ok(contrast >= 4.5, `Traffic warning contrast ${contrast}`);
    await page.getByLabel("Month (UTC)", { exact: true }).fill("2000-01");
    await page
      .getByRole("heading", { name: "No recorded traffic", exact: true })
      .waitFor();
    await page
      .getByLabel("Month (UTC)", { exact: true })
      .fill(new Date().toISOString().slice(0, 7));
    await page.getByText("Traffic device 00", { exact: true }).waitFor();
    const passive = await page.waitForResponse(
      (response) =>
        new URL(response.url()).pathname === "/api/v1/console/traffic" &&
        response.request().headers()["x-nethub-background"] === "1",
    );
    assert.equal(passive.status(), 200);
    await page.setViewportSize({ width: 390, height: 844 });
    await screenshot("traffic-mobile.png");
    await warning().click();
    await screenshot("traffic-mobile-dialog.png");
    const save = dialog.getByRole("button", {
      name: "Save warning",
      exact: true,
    });
    await save.scrollIntoViewIfNeeded();
    const bounds = await save.boundingBox();
    assert.ok(bounds && bounds.y >= 0 && bounds.y + bounds.height <= 844);
    await dialog
      .getByLabel("Warning threshold (bytes)", { exact: true })
      .fill("0");
    const count = writes().length;
    await page.route("**/api/v1/console/traffic/settings", async (route) => {
      await route.fetch();
      await route.abort("failed");
    });
    await save.click();
    await dialog.getByRole("alert").waitFor();
    assert.ok(await save.isDisabled());
    assert.equal(writes().length, count + 1);
    await page.unroute("**/api/v1/console/traffic/settings");
    await dialog
      .getByRole("button", { name: "Close and reload", exact: true })
      .click();
    await page.getByText(/Warning: Off/).waitFor();
    await warning().click();
    await page.request.post(origin + "/test/member");
    await page
      .getByRole("heading", { name: "Devices", exact: true })
      .waitFor({ timeout: 25000 });
    assert.equal(await dialog.count(), 0);
    assert.equal(
      await page.getByRole("link", { name: "Traffic", exact: true }).count(),
      0,
    );
    await page.goto(origin + "/traffic");
    await page
      .getByRole("heading", {
        name: "Administrator access required",
        exact: true,
      })
      .waitFor();
    assert.equal(await page.locator(".traffic-summary").count(), 0);
    writeFileSync(
      join(evidence, "traffic-results.json"),
      JSON.stringify(
        {
          passed: true,
          synthetic_counts_only: true,
          genuine_relay_or_SQL_acceptance_claimed: false,
          contrast,
          screenshots,
          checks: [
            "wide exact totals across pages",
            "removed-device history",
            "UTC month and empty state",
            "administrator warning with CSRF and revision",
            "passive refresh and live role loss",
            "uncertain mutation without replay",
            "mobile native dialog and reachable actions",
            "light and dark presentation",
          ],
        },
        null,
        2,
      ),
    );
    console.log(
      "Traffic console UI passed exact wide totals, pagination, monthly warnings, passive refresh, role loss and uncertain writes under strict CSP; counts are synthetic.",
    );
  } finally {
    page.off("request", record);
  }
}
