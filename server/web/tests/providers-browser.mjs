import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export async function verifyProviders({ page, origin, evidence, login }) {
  const requests = [];
  const record = (request) => {
    if (new URL(request.url()).pathname.startsWith("/api/v1/console/"))
      requests.push(request);
  };
  page.on("request", record);
  const dialog = page.getByRole("dialog");
  const save = () =>
    dialog.getByRole("button", { name: "Save provider", exact: true }).click();
  const cancel = () =>
    dialog.getByRole("button", { name: "Cancel", exact: true }).click();
  const edit = async (name) => {
    await page
      .getByRole("button", { name: `Edit ${name}`, exact: true })
      .click();
    await dialog.waitFor();
  };
  const writes = () =>
    requests.filter(
      (r) =>
        r.url().includes("/oidc-providers") &&
        ["POST", "PATCH", "DELETE"].includes(r.method()),
    );
  const screenshots = [];
  async function screenshot(name) {
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
  }
  try {
    await page.request.post(origin + "/test/providers-reset");
    await page.context().clearCookies();
    await page.goto(origin + "/login");
    await login({ waitForRateLimit: true });
    await page
      .getByRole("link", { name: "Identity providers", exact: true })
      .click();
    await page
      .getByRole("button", { name: "Edit Corporate SSO", exact: true })
      .waitFor();
    const light = page.getByRole("button", {
      name: "Use light theme",
      exact: true,
    });
    if (await light.count()) await light.click();
    await screenshot("providers-desktop.png");
    await page
      .getByRole("button", { name: "Use dark theme", exact: true })
      .click();
    await screenshot("providers-desktop-dark.png");
    await page.getByRole("button", { name: "Next provider page" }).click();
    await page
      .getByRole("button", { name: "Edit Provider 51", exact: true })
      .waitFor();
    assert.equal(
      await page
        .getByRole("button", { name: "Edit Corporate SSO", exact: true })
        .count(),
      0,
    );
    await page.getByRole("button", { name: "Previous provider page" }).click();
    await edit("Corporate SSO");
    assert.equal(
      await dialog
        .getByLabel("Replacement client secret", { exact: true })
        .inputValue(),
      "",
    );
    assert.ok(await dialog.getByLabel("Slug", { exact: true }).isDisabled());
    assert.ok(
      await dialog
        .getByRole("button", { name: "Save provider", exact: true })
        .isDisabled(),
    );
    await dialog
      .getByRole("button", { name: "Copy callback address", exact: true })
      .click();
    assert.equal(
      await page.evaluate(() => navigator.clipboard.readText()),
      origin + "/api/v1/console/oidc/corporate/callback",
    );
    await page.setViewportSize({ width: 390, height: 844 });
    await screenshot("providers-mobile-dialog.png");
    assert.ok(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth,
      ),
    );
    await page.setViewportSize({ width: 1440, height: 1000 });
    await dialog
      .getByLabel("Display name", { exact: true })
      .fill("Corporate renamed");
    await save();
    await dialog.waitFor({ state: "hidden" });
    assert.deepEqual(writes().at(-1).postDataJSON(), {
      display_name: "Corporate renamed",
    });
    await edit("Corporate renamed");
    await dialog
      .getByLabel("Issuer URL", { exact: true })
      .fill("https://changed.example.com");
    await save();
    await dialog
      .getByRole("alert")
      .filter({ hasText: "bound users" })
      .waitFor();
    await cancel();
    await page
      .getByRole("button", { name: "Delete Corporate renamed", exact: true })
      .click();
    await dialog
      .getByRole("button", { name: "Delete provider", exact: true })
      .click();
    await dialog
      .getByRole("alert")
      .filter({ hasText: "bound users" })
      .waitFor();
    await cancel();
    await edit("Corporate renamed");
    await dialog.getByLabel("Enable sign-in", { exact: true }).uncheck();
    await save();
    await dialog.waitFor({ state: "hidden" });
    assert.deepEqual(writes().at(-1).postDataJSON(), { enabled: false });

    await edit("Provider 01");
    let release;
    const held = new Promise((resolve) => {
      release = resolve;
    });
    await page.route("**/api/v1/console/oidc-providers/*", async (route) => {
      if (route.request().method() !== "PATCH") return route.continue();
      await held;
      await route.continue();
    });
    await dialog
      .getByLabel("Replacement client secret", { exact: true })
      .fill("isolated UI replacement");
    const before = writes().length;
    const sent = page.waitForRequest(
      (r) => r.method() === "PATCH" && r.url().includes("/oidc-providers/"),
    );
    await save();
    await sent;
    assert.equal(
      await dialog
        .getByLabel("Replacement client secret", { exact: true })
        .inputValue(),
      "",
    );
    await page.keyboard.press("Escape");
    assert.ok(await dialog.isVisible());
    assert.ok(
      await dialog
        .getByRole("button", { name: "Cancel", exact: true })
        .isDisabled(),
    );
    release();
    await dialog.waitFor({ state: "hidden" });
    await page.unroute("**/api/v1/console/oidc-providers/*");
    assert.equal(writes().length, before + 1);
    assert.deepEqual(writes().at(-1).postDataJSON(), {
      client_secret: "isolated UI replacement",
    });
    await edit("Provider 01");
    await dialog
      .getByLabel("Remove saved secret for a public client", { exact: true })
      .check();
    await save();
    await dialog.waitFor({ state: "hidden" });
    assert.deepEqual(writes().at(-1).postDataJSON(), { client_secret: "" });

    await page
      .getByRole("button", { name: "Add provider", exact: true })
      .click();
    assert.equal(
      await dialog.getByLabel("Enable sign-in", { exact: true }).isChecked(),
      false,
    );
    await dialog
      .getByLabel("Display name", { exact: true })
      .fill("Uncertain provider");
    await dialog.getByLabel("Slug", { exact: true }).fill("uncertain-ui");
    await dialog
      .getByLabel("Issuer URL", { exact: true })
      .fill("https://identity.example.com");
    await dialog.getByLabel("Client ID", { exact: true }).fill("console");
    await page.route("**/api/v1/console/oidc-providers", async (route) => {
      if (route.request().method() !== "POST") return route.continue();
      const response = await route.fetch();
      assert.equal(response.status(), 201);
      await route.fulfill({
        status: 503,
        contentType: "application/json",
        body: JSON.stringify({
          error: { code: "internal", message: "Lost result" },
        }),
      });
    });
    const beforeCreate = writes().length;
    await save();
    await dialog
      .getByRole("alert")
      .filter({ hasText: "could not be confirmed" })
      .waitFor();
    assert.ok(
      await dialog
        .getByRole("button", { name: "Save provider", exact: true })
        .isDisabled(),
    );
    assert.equal(writes().length, beforeCreate + 1);
    await page.unroute("**/api/v1/console/oidc-providers");
    await dialog
      .getByRole("button", { name: "Close and refresh", exact: true })
      .click();
    await page.getByRole("button", { name: "Next provider page" }).click();
    await page
      .getByRole("button", { name: "Delete Uncertain provider", exact: true })
      .click();
    await dialog
      .getByRole("button", { name: "Delete provider", exact: true })
      .click();
    await dialog.waitFor({ state: "hidden" });
    assert.equal(writes().at(-1).method(), "DELETE");
    assert.ok(writes().at(-1).headers()["x-csrf-token"]);
    await page.getByRole("button", { name: "Previous provider page" }).click();
    const reads = () =>
      requests.filter(
        (r) => new URL(r.url()).pathname === "/api/v1/console/oidc-providers",
      );
    await page.evaluate(() =>
      Object.defineProperty(document, "hidden", {
        configurable: true,
        get: () => true,
      }),
    );
    const hiddenCount = reads().length;
    await page.evaluate(() =>
      document.dispatchEvent(new Event("visibilitychange")),
    );
    await page.waitForTimeout(200);
    assert.equal(
      reads().length,
      hiddenCount,
      "Hidden provider inventory must pause",
    );
    await page.evaluate(() => delete document.hidden);
    let releaseRead;
    const readHeld = new Promise((resolve) => {
      releaseRead = resolve;
    });
    await page.route("**/api/v1/console/oidc-providers?*", async (route) => {
      await readHeld;
      await route.continue();
    });
    const passive = page.waitForResponse(
      (r) =>
        new URL(r.url()).pathname === "/api/v1/console/oidc-providers" &&
        r.request().headers()["x-nethub-background"] === "1",
    );
    const visibleCount = reads().length;
    const readSent = page.waitForRequest(
      (r) => new URL(r.url()).pathname === "/api/v1/console/oidc-providers",
    );
    await page.evaluate(() => {
      for (let i = 0; i < 5; i++)
        document.dispatchEvent(new Event("visibilitychange"));
    });
    await readSent;
    assert.equal(
      reads().length,
      visibleCount + 1,
      "Provider refreshes must not overlap",
    );
    releaseRead();
    await passive;
    await page.unroute("**/api/v1/console/oidc-providers?*");
    await page.request.post(origin + "/test/member");
    await page
      .getByRole("button", { name: "Refresh providers", exact: true })
      .click();
    await page.getByRole("heading", { name: "Devices", exact: true }).waitFor();
    assert.equal(
      await page
        .getByRole("link", { name: "Identity providers", exact: true })
        .count(),
      0,
    );
    assert.equal(
      await page
        .getByRole("button", { name: "Edit Corporate renamed", exact: true })
        .count(),
      0,
    );
    const readsBeforeDirect = requests.filter(
      (r) => new URL(r.url()).pathname === "/api/v1/console/oidc-providers",
    ).length;
    await page.goto(origin + "/providers");
    await page
      .getByRole("heading", {
        name: "Administrator access required",
        exact: true,
      })
      .waitFor();
    assert.equal(
      requests.filter(
        (r) => new URL(r.url()).pathname === "/api/v1/console/oidc-providers",
      ).length,
      readsBeforeDirect,
    );
    await page.request.post(origin + "/test/admin");
    await page.goto(origin + "/");

    await page.getByRole("link", { name: "Invitations", exact: true }).click();
    await page
      .getByRole("button", { name: "Invite user", exact: true })
      .click();
    await dialog
      .getByLabel("Email address", { exact: true })
      .fill("sso-ui@example.com");
    const choice = dialog.getByLabel("Sign-in restriction", { exact: true });
    await choice
      .locator("option")
      .filter({ hasText: "Provider 01 only" })
      .waitFor({ state: "attached" });
    const providerId = "00000000-0000-4000-8000-000000003001";
    await choice.selectOption(providerId);
    await dialog
      .getByRole("button", { name: "Create invitation", exact: true })
      .click();
    const inviteURL = await dialog
      .getByLabel("Invitation link", { exact: true })
      .inputValue();
    assert.equal(
      requests
        .filter((r) => r.url().endsWith("/invites") && r.method() === "POST")
        .at(-1)
        .postDataJSON().provider_id,
      providerId,
    );
    await dialog.getByRole("button", { name: "Done", exact: true }).click();
    await page.goto(inviteURL);
    await page
      .getByRole("button", { name: "Sign out to accept", exact: true })
      .click();
    const sso = page.getByRole("button", {
      name: "Continue with Provider 01",
      exact: true,
    });
    await sso.waitFor();
    assert.equal(
      await page.getByLabel("New password", { exact: true }).count(),
      0,
    );
    assert.equal(new URL(page.url()).hash, "");
    const token = inviteURL.split("#")[1];
    assert.ok(
      !(
        await page.evaluate(() =>
          JSON.stringify({
            local: { ...localStorage },
            session: { ...sessionStorage },
            html: document.documentElement.outerHTML,
          }),
        )
      ).includes(token),
    );
    await sso.click();
    await page.waitForURL(origin + "/test/oidc-authorize");
    const starts = requests.filter((r) =>
      r.url().endsWith("/oidc/provider-01/start"),
    );
    assert.equal(starts.length, 1);
    assert.equal(starts[0].postDataJSON().invite_token, token);
    assert.ok(requests.every((r) => !r.url().includes(token)));
    assert.equal(
      (await page.request.get(origin + "/api/v1/console/session")).status(),
      200,
    );
    assert.equal(
      (
        await (
          await page.request.get(origin + "/api/v1/console/session")
        ).json()
      ).signed_in,
      false,
      "Synthetic navigation must never establish a session",
    );

    await page.goto(
      origin + "/login?error=sso_failed&detail=private-diagnostic",
    );
    await page
      .getByRole("alert")
      .filter({ hasText: "SSO sign-in could not be completed" })
      .waitFor();
    await page
      .getByRole("button", { name: "Continue with Provider 01", exact: true })
      .waitFor();
    assert.equal(
      await page
        .getByRole("button", {
          name: "Continue with Corporate renamed",
          exact: true,
        })
        .count(),
      0,
    );
    assert.equal(
      await page.getByText("private-diagnostic", { exact: false }).count(),
      0,
    );
    await screenshot("providers-signin.png");
    await page
      .getByRole("button", { name: "Continue with Provider 01", exact: true })
      .click();
    await page.waitForURL(origin + "/test/oidc-authorize");
    await page.route("**/api/v1/console/oidc/providers", (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          items: [{ slug: "../invalid", display_name: "Invalid" }],
        }),
      }),
    );
    await page.goto(origin + "/login");
    await page
      .getByText(
        "SSO choices are unavailable. You can still use a local password.",
        { exact: true },
      )
      .waitFor();
    await login({ waitForRateLimit: true });
    await page.getByRole("heading", { name: "Devices", exact: true }).waitFor();
    await page.unroute("**/api/v1/console/oidc/providers");
    writeFileSync(
      join(evidence, "providers-results.json"),
      JSON.stringify(
        {
          passed: true,
          fixture_backend: true,
          actual_SSO_admission_claimed: false,
          checks: [
            "admin isolation",
            "pagination",
            "write-only secret preservation and explicit removal",
            "exact callback copy",
            "bound-provider refusal and disable",
            "pending dialog",
            "uncertain create committed once then refreshed",
            "bodyless CSRF deletion",
            "passive inventory",
            "restricted invitation POST body and erased fragment",
            "fixed login error",
            "enabled choices",
            "local password survives malformed catalog",
          ],
          screenshots,
        },
        null,
        2,
      ),
    );
    console.log(
      "Provider UI passed CRUD, credential handling, passive inventory, restricted invitation navigation and independent password fallback; synthetic navigation does not establish SSO sessions.",
    );
  } finally {
    page.off("request", record);
  }
}
