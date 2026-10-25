import assert from "node:assert/strict";
import { join } from "node:path";
import { writeFileSync } from "node:fs";

export async function verifyUsers({ page, origin, evidence, login }) {
  const changes = [];
  const reads = [];
  const authorityReads = [];
  const record = (request) => {
    const path = new URL(request.url()).pathname;
    if (
      path.startsWith("/api/v1/console/users/") &&
      request.method() === "PATCH"
    )
      changes.push(request.postDataJSON());
    if (path === "/api/v1/console/users") reads.push(request.headers());
    if (path === "/api/v1/console/session")
      authorityReads.push(request.headers());
  };
  page.on("request", record);
  try {
    await login();
    await page.getByRole("link", { name: "Users", exact: true }).click();
    await page.getByRole("heading", { name: "Users", exact: true }).waitFor();
    const users = page.getByRole("region", {
      name: "User accounts",
      exact: true,
    });
    const own = () =>
      users.getByRole("row").filter({ hasText: "ui-test@example.com" });
    const member = () =>
      users.getByRole("row").filter({ hasText: "ui-member@example.com" });
    await member().waitFor();
    const light = page.getByRole("button", {
      name: "Use light theme",
      exact: true,
    });
    if (await light.count()) await light.click();
    await page.screenshot({ path: join(evidence, "users-desktop.png") });
    await page
      .getByRole("button", { name: "Use dark theme", exact: true })
      .click();
    await page.screenshot({ path: join(evidence, "users-desktop-dark.png") });
    await page.getByRole("button", { name: "Next user page" }).click();
    await users.getByText("extra-49@example.com", { exact: true }).waitFor();
    assert.equal(await member().count(), 0);
    await page.getByRole("button", { name: "Previous user page" }).click();
    await member().waitFor();
    const beforeRead = reads.length;
    const backgroundResponse = page.waitForResponse(
      (response) =>
        new URL(response.url()).pathname === "/api/v1/console/users" &&
        response.request().headers()["x-nethub-background"] === "1",
    );
    await page.evaluate(() =>
      document.dispatchEvent(new Event("visibilitychange")),
    );
    await backgroundResponse;
    assert.ok(reads.length > beforeRead);
    assert.equal(reads.at(-1)["x-nethub-background"], "1");

    const dialog = page.getByRole("dialog", { name: "Edit user", exact: true });
    await member()
      .getByRole("button", { name: "Edit ui-member@example.com", exact: true })
      .click();
    await dialog.waitFor();
    await dialog.getByLabel("Role", { exact: true }).selectOption("admin");
    await page.keyboard.press("Escape");
    await dialog.waitFor({ state: "hidden" });
    assert.equal(changes.length, 0, "Escape must not mutate a role");

    await own()
      .getByRole("button", { name: "Edit ui-test@example.com", exact: true })
      .click();
    await dialog.getByLabel("Role", { exact: true }).selectOption("member");
    await dialog
      .getByRole("button", { name: "Save changes", exact: true })
      .click();
    await dialog
      .getByRole("alert")
      .filter({ hasText: "An enabled administrator must remain" })
      .waitFor();
    await dialog.getByRole("button", { name: "Cancel", exact: true }).click();
    assert.deepEqual(changes.at(-1), { role: "member" });

    await member()
      .getByRole("button", { name: "Edit ui-member@example.com", exact: true })
      .click();
    await dialog.getByLabel("Disable console access").check();
    await page.setViewportSize({ width: 390, height: 844 });
    assert.ok(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth,
      ),
    );
    await page.screenshot({
      path: join(evidence, "users-mobile-dialog.png"),
    });
    let release;
    const delayed = new Promise((resolve) => {
      release = resolve;
    });
    let requestStarted;
    const started = new Promise((resolve) => {
      requestStarted = resolve;
    });
    const target =
      "**/api/v1/console/users/00000000-0000-4000-8000-000000000099";
    await page.route(target, async (route) => {
      requestStarted();
      await delayed;
      await route.continue();
    });
    const beforeSave = changes.length;
    await dialog
      .getByRole("button", { name: "Save changes", exact: true })
      .click();
    await started;
    try {
      const beforePendingReads = reads.length;
      await page.evaluate(() =>
        document.dispatchEvent(new Event("visibilitychange")),
      );
      await page.waitForTimeout(50);
      assert.equal(
        reads.length,
        beforePendingReads,
        "A pending save must not race a background authority refresh",
      );
      assert.ok(
        await dialog
          .getByRole("button", { name: "Saving…", exact: true })
          .isDisabled(),
      );
      assert.ok(
        await dialog
          .getByRole("button", { name: "Close dialog", exact: true })
          .isDisabled(),
      );
      await page.keyboard.press("Escape");
      assert.ok(await dialog.isVisible());
      assert.equal(changes.length, beforeSave + 1);
    } finally {
      release();
    }
    await dialog.waitFor({ state: "hidden" });
    await page.unroute(target);
    await member().getByText("Disabled", { exact: true }).waitFor();
    assert.deepEqual(changes.at(-1), { disabled: true });
    await member()
      .getByRole("button", { name: "Edit ui-member@example.com", exact: true })
      .click();
    await dialog.getByLabel("Disable console access").uncheck();
    await dialog
      .getByRole("button", { name: "Save changes", exact: true })
      .click();
    await dialog.waitFor({ state: "hidden" });
    await member().getByText("Enabled", { exact: true }).waitFor();
    assert.deepEqual(changes.at(-1), { disabled: false });
    await page.setViewportSize({ width: 1440, height: 1000 });

    // An external demotion must clear an already loaded administrator view.
    await page.request.post(origin + "/test/member");
    await page.evaluate(() =>
      document.dispatchEvent(new Event("visibilitychange")),
    );
    await page.getByRole("heading", { name: "Devices", exact: true }).waitFor();
    assert.equal(
      authorityReads.at(-1)["x-nethub-background"],
      "1",
      "Automatic authority refresh must remain passive",
    );
    assert.equal(await users.count(), 0);
    assert.equal(
      await page.getByRole("link", { name: "Users", exact: true }).count(),
      0,
    );
    const beforeDirect = reads.length;
    await page.goto(origin + "/users");
    await page
      .getByRole("heading", {
        name: "Administrator access required",
        exact: true,
      })
      .waitFor();
    assert.equal(
      reads.length,
      beforeDirect,
      "A member page must not fetch the user list",
    );
    await page.request.post(origin + "/test/admin");
    await page.reload();
    await member().waitFor();

    // Keep another enabled local admin before exercising self-demotion/disable.
    await member()
      .getByRole("button", { name: "Edit ui-member@example.com", exact: true })
      .click();
    await dialog.getByLabel("Role", { exact: true }).selectOption("admin");
    await dialog
      .getByRole("button", { name: "Save changes", exact: true })
      .click();
    await dialog.waitFor({ state: "hidden" });
    await member().getByText("Admin", { exact: true }).waitFor();
    await own()
      .getByRole("button", { name: "Edit ui-test@example.com", exact: true })
      .click();
    await dialog.getByLabel("Role", { exact: true }).selectOption("member");
    await dialog
      .getByRole("button", { name: "Save changes", exact: true })
      .click();
    await page.getByRole("heading", { name: "Devices", exact: true }).waitFor();
    assert.equal(await users.count(), 0);
    assert.equal(
      await page.getByRole("link", { name: "Users", exact: true }).count(),
      0,
    );
    assert.equal(new URL(page.url()).pathname, "/");
    assert.equal(
      authorityReads.at(-1)["x-nethub-background"],
      undefined,
      "An explicit self-mutation uses an active authority refresh",
    );
    await page.request.post(origin + "/test/admin");
    await page.goto(origin + "/users");
    await own().waitFor();
    await own()
      .getByRole("button", { name: "Edit ui-test@example.com", exact: true })
      .click();
    await dialog.getByLabel("Disable console access").check();
    await dialog
      .getByRole("button", { name: "Save changes", exact: true })
      .click();
    await page
      .getByRole("heading", { name: "Sign in to NetHub", exact: true })
      .waitFor();
    assert.equal(await users.count(), 0);
    assert.equal(
      await page.getByRole("link", { name: "Users", exact: true }).count(),
      0,
    );
    await page.request.post(origin + "/test/users-reset");
    await login();
    await page.getByRole("button", { name: "Sign out", exact: true }).click();
    await page
      .getByRole("heading", { name: "Sign in to NetHub", exact: true })
      .waitFor();
    writeFileSync(
      join(evidence, "users-results.json"),
      JSON.stringify(
        {
          passed: true,
          pagination: true,
          passive_refresh: true,
          passive_authority_refresh: true,
          changed_fields_only: true,
          pending_close_refused: true,
          last_admin_error: true,
          member_list_not_fetched: true,
          external_demotion_cleared_view: true,
          self_demotion_refreshed_authority: true,
          self_disable_signed_out: true,
          fixture_backend: true,
        },
        null,
        2,
      ),
    );
    console.log(
      "User management UI passed pagination, passive refresh, changed-field PATCH, native-dialog pending protection, last-admin refusal, member isolation, external demotion, self-demotion and self-disable.",
    );
  } finally {
    page.off("request", record);
  }
}
