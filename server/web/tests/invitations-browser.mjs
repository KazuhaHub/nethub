import assert from "node:assert/strict";
import { join } from "node:path";
import { writeFileSync } from "node:fs";

export async function verifyInvitations({
  page,
  origin,
  evidence,
  login,
  serverLog,
}) {
  const requests = [];
  const metadata = [];
  const grants = [];
  const record = (request) => {
    metadata.push(request);
    const path = new URL(request.url()).pathname;
    if (path.startsWith("/api/v1/console/invites")) requests.push(request);
  };
  page.on("request", record);
  const dialog = page.getByRole("dialog");
  const inventory = page.getByRole("region", {
    name: "Pending invitations",
    exact: true,
  });
  async function openCreate(email, role = "member") {
    await page
      .getByRole("button", { name: "Invite user", exact: true })
      .click();
    await dialog.getByLabel("Email address", { exact: true }).fill(email);
    await dialog.getByLabel("Role", { exact: true }).selectOption(role);
  }
  async function create(email) {
    await openCreate(email);
    await dialog
      .getByRole("button", { name: "Create invitation", exact: true })
      .click();
    const url = await dialog
      .getByLabel("Invitation link", { exact: true })
      .inputValue();
    grants.push(url.split("#")[1]);
    await dialog.getByRole("button", { name: "Done", exact: true }).click();
    await dialog.waitFor({ state: "hidden" });
    return url;
  }
  async function assertNoSecretStorage() {
    const browserState = await page.evaluate(() => ({
      local: { ...localStorage },
      session: { ...sessionStorage },
      cookie: document.cookie,
      html: document.documentElement.outerHTML,
    }));
    assert.equal(
      await page.evaluate(
        () =>
          window.invitationFetchMetadata?.every((value) => value === false) ??
          true,
      ),
      true,
    );
    for (const grant of grants)
      assert.ok(
        !JSON.stringify(browserState).includes(grant),
        "Invitation bearer escaped component memory",
      );
    for (const request of metadata) {
      for (const grant of grants) {
        assert.ok(!request.url().includes(grant));
        assert.ok(!JSON.stringify(request.headers()).includes(grant));
      }
    }
  }
  try {
    await page.addInitScript(() => {
      window.invitationFetchMetadata = [];
      const original = window.fetch;
      window.fetch = (...args) => {
        window.invitationFetchMetadata.push(window.location.hash.length > 0);
        return original(...args);
      };
    });
    assert.equal(
      (await page.request.post(origin + "/test/invitations-reset")).status(),
      204,
    );
    await login();
    await page.getByRole("link", { name: "Invitations", exact: true }).click();
    await page
      .getByRole("heading", { name: "Invitations", exact: true })
      .waitFor();
    await inventory
      .getByText("pending-00@example.com", { exact: true })
      .waitFor();
    assert.equal(await inventory.locator("tbody tr").count(), 50);
    await page
      .getByRole("button", { name: "Next invitation page", exact: true })
      .click();
    await inventory
      .getByText("pending-51@example.com", { exact: true })
      .waitFor();
    assert.equal(await inventory.locator("tbody tr").count(), 2);
    await page
      .getByRole("button", { name: "Previous invitation page", exact: true })
      .click();
    await inventory
      .getByText("pending-00@example.com", { exact: true })
      .waitFor();
    const light = page.getByRole("button", {
      name: "Use light theme",
      exact: true,
    });
    if (await light.count()) await light.click();
    await page.screenshot({
      path: join(evidence, "invitations-desktop.png"),
      animations: "disabled",
    });
    await page
      .getByRole("button", { name: "Use dark theme", exact: true })
      .click();
    await page.screenshot({
      path: join(evidence, "invitations-desktop-dark.png"),
      animations: "disabled",
    });
    await page
      .getByRole("button", { name: "Use light theme", exact: true })
      .click();

    let release;
    const gate = new Promise((resolve) => {
      release = resolve;
    });
    const seen = page.waitForRequest(
      (request) =>
        request.method() === "POST" &&
        new URL(request.url()).pathname === "/api/v1/console/invites",
      { timeout: 15000 },
    );
    const delayed = async (route) => {
      if (route.request().method() === "POST") {
        await gate;
      }
      await route.continue();
    };
    await page.route("**/api/v1/console/invites", delayed);
    await openCreate("recipient@example.com");
    await dialog
      .getByRole("button", { name: "Create invitation", exact: true })
      .click();
    await seen;
    await dialog
      .getByRole("button", { name: "Creating…", exact: true })
      .waitFor();
    await page.keyboard.press("Escape");
    assert.equal(await dialog.isVisible(), true);
    assert.equal(
      await dialog
        .getByRole("button", { name: "Close dialog", exact: true })
        .isDisabled(),
      true,
    );
    release();
    const acceptedURL = await dialog
      .getByLabel("Invitation link", { exact: true })
      .inputValue();
    const acceptedToken = acceptedURL.split("#")[1];
    grants.push(acceptedToken);
    await dialog
      .getByRole("button", { name: "Copy invitation link", exact: true })
      .click();
    await dialog.getByRole("button", { name: "Copied", exact: true }).waitFor();
    assert.equal(
      await page.evaluate(() => navigator.clipboard.readText()),
      acceptedURL,
    );
    await dialog.getByRole("button", { name: "Done", exact: true }).click();
    await dialog.waitFor({ state: "hidden" });
    await page.unroute("**/api/v1/console/invites", delayed);
    assert.equal(
      await page.getByLabel("Invitation link", { exact: true }).count(),
      0,
    );
    await assertNoSecretStorage();

    const row = inventory
      .getByRole("row")
      .filter({ hasText: "pending-00@example.com" });
    await row.getByRole("button", { name: "Withdraw", exact: true }).click();
    await dialog
      .getByRole("button", { name: "Withdraw invitation", exact: true })
      .click();
    await dialog.waitFor({ state: "hidden" });
    await page.waitForFunction(
      () =>
        !document
          .querySelector(".device-panel")
          ?.getAttribute("aria-busy")
          ?.includes("true"),
    );
    assert.equal(
      await inventory
        .getByText("pending-00@example.com", { exact: true })
        .count(),
      0,
    );
    const withdrawal = requests.find(
      (request) => request.method() === "DELETE",
    );
    assert.ok(withdrawal.headers()["x-csrf-token"]);
    assert.equal(withdrawal.postData(), null);

    await openCreate("ui-member@example.com");
    await dialog
      .getByRole("button", { name: "Create invitation", exact: true })
      .click();
    await dialog
      .getByRole("alert")
      .filter({ hasText: "already exists" })
      .waitFor();
    await dialog.getByRole("button", { name: "Cancel", exact: true }).click();
    await dialog.waitFor({ state: "hidden" });

    await page.request.post(origin + "/test/member");
    await page
      .getByRole("button", { name: "Refresh invitations", exact: true })
      .click();
    await page.getByRole("heading", { name: "Devices", exact: true }).waitFor();
    assert.equal(await inventory.count(), 0);
    const before = requests.length;
    await page.goto(origin + "/invitations");
    await page
      .getByRole("heading", {
        name: "Administrator access required",
        exact: true,
      })
      .waitFor();
    assert.equal(requests.length, before);
    assert.equal(
      await page
        .getByRole("link", { name: "Invitations", exact: true })
        .count(),
      0,
    );
    await page.request.post(origin + "/test/admin");
    await page.goto(origin + "/invitations");
    await inventory
      .getByText("pending-01@example.com", { exact: true })
      .waitFor();

    const lostCreate = async (route) => {
      await route.fetch();
      await route.abort("failed");
    };
    await page.route("**/api/v1/console/invites", async (route) => {
      if (route.request().method() === "POST") return lostCreate(route);
      return route.continue();
    });
    await openCreate("unconfirmed-create@example.com", "admin");
    const posts = () =>
      requests.filter(
        (request) =>
          request.method() === "POST" &&
          new URL(request.url()).pathname === "/api/v1/console/invites",
      ).length;
    const beforeCreate = posts();
    await dialog
      .getByRole("button", { name: "Create invitation", exact: true })
      .click();
    await dialog
      .getByRole("alert")
      .filter({ hasText: "could not be confirmed" })
      .waitFor();
    assert.equal(
      await dialog
        .getByRole("button", { name: "Create invitation", exact: true })
        .isDisabled(),
      true,
    );
    assert.equal(posts(), beforeCreate + 1);
    await dialog.getByRole("button", { name: "Cancel", exact: true }).click();
    await dialog.waitFor({ state: "hidden" });
    await page.unroute("**/api/v1/console/invites");
    const uncertainURL = await create("uncertain-accept@example.com");

    // Loading an invitation must preserve the current account until explicit sign-out.
    await page.goto(acceptedURL);
    await page
      .getByRole("button", { name: "Sign out to accept", exact: true })
      .waitFor();
    assert.equal(new URL(page.url()).hash, "");
    assert.equal(
      await page
        .getByRole("button", { name: "Create account", exact: true })
        .count(),
      0,
    );
    await page
      .getByRole("button", { name: "Sign out to accept", exact: true })
      .click();
    await page.getByLabel("New password", { exact: true }).waitFor();
    await page.reload();
    await page
      .getByRole("alert")
      .filter({ hasText: "Invitation unavailable" })
      .waitFor();
    await page.goto(acceptedURL);
    await page.getByLabel("New password", { exact: true }).waitFor();
    assert.equal(page.url(), origin + "/invite");
    await assertNoSecretStorage();
    await page.setViewportSize({ width: 390, height: 844 });
    await page.screenshot({
      path: join(evidence, "invitation-mobile-accept.png"),
      animations: "disabled",
    });
    await page.getByLabel("New password", { exact: true }).fill("short");
    await page.getByLabel("Confirm password", { exact: true }).fill("short");
    await page
      .getByRole("button", { name: "Create account", exact: true })
      .click();
    await page.getByRole("alert").filter({ hasText: "at least 15" }).waitFor();
    await page
      .getByLabel("New password", { exact: true })
      .fill("isolated invitation recipient passphrase");
    await page
      .getByLabel("Confirm password", { exact: true })
      .fill("a different invitation passphrase");
    await page
      .getByRole("button", { name: "Create account", exact: true })
      .click();
    await page.getByRole("alert").filter({ hasText: "do not match" }).waitFor();
    await page
      .getByLabel("Confirm password", { exact: true })
      .fill("isolated invitation recipient passphrase");
    await page
      .getByRole("button", { name: "Create account", exact: true })
      .click();
    await page.getByRole("heading", { name: "Devices", exact: true }).waitFor();
    await page.goto(acceptedURL);
    await page
      .getByRole("alert")
      .filter({ hasText: "Invitation unavailable" })
      .waitFor();
    await assertNoSecretStorage();
    await page.setViewportSize({ width: 1440, height: 1000 });

    const bound = await (
      await page.request.post(origin + "/test/invitation-bound")
    ).json();
    grants.push(bound.url.split("#")[1]);
    await page.goto(bound.url);
    await page
      .getByRole("button", { name: "Sign out to accept", exact: true })
      .click();
    await page
      .getByText("SSO is required for this invitation.", { exact: true })
      .waitFor();
    assert.equal(
      await page.getByLabel("New password", { exact: true }).count(),
      0,
    );

    await page.route("**/api/v1/console/invites/accept", async (route) => {
      const previous = await page.context().cookies();
      await route.fetch({ maxRetries: 0 });
      // A discarded response must not install its Set-Cookie through route.fetch.
      await page.context().clearCookies();
      await page.context().addCookies(previous);
      await route.abort("failed");
    });
    await page.goto(uncertainURL);
    await page
      .getByLabel("New password", { exact: true })
      .fill("isolated uncertain invitation passphrase");
    await page
      .getByLabel("Confirm password", { exact: true })
      .fill("isolated uncertain invitation passphrase");
    const accepts = () =>
      requests.filter(
        (request) =>
          new URL(request.url()).pathname === "/api/v1/console/invites/accept",
      ).length;
    const beforeAccept = accepts();
    await page
      .getByRole("button", { name: "Create account", exact: true })
      .click();
    await page
      .getByRole("alert")
      .filter({ hasText: "Account creation could not be confirmed" })
      .waitFor();
    assert.equal(accepts(), beforeAccept + 1);
    assert.equal(
      await page
        .getByRole("button", { name: "Create account", exact: true })
        .count(),
      0,
    );
    await assertNoSecretStorage();
    await page.unroute("**/api/v1/console/invites/accept");
    await page
      .getByRole("link", { name: "Go to sign in", exact: true })
      .click();
    await page
      .getByRole("heading", { name: "Sign in to NetHub", exact: true })
      .waitFor();
    await page
      .getByLabel("Email address", { exact: true })
      .fill("uncertain-accept@example.com");
    await page
      .getByLabel("Password", { exact: true })
      .fill("isolated uncertain invitation passphrase");
    await page.getByRole("button", { name: "Sign in", exact: true }).click();
    await page.getByRole("heading", { name: "Devices", exact: true }).waitFor();
    for (const grant of grants)
      assert.ok(
        !serverLog().includes(grant),
        "Fixture log exposed an invitation bearer",
      );
    writeFileSync(
      join(evidence, "invitations-results.json"),
      JSON.stringify(
        {
          passed: true,
          pagination: true,
          create_and_copy_once: true,
          bodyless_withdrawal_CSRF: true,
          pending_dialog_protection: true,
          member_isolation: true,
          authority_loss_cleared_view: true,
          fragment_erasure: true,
          same_tab_fragment_reopen: true,
          no_secret_storage_or_request_metadata: true,
          existing_session_preserved: true,
          password_policy_and_confirmation: true,
          single_use_acceptance: true,
          provider_password_bypass_refused: true,
          uncertain_create_no_replay: true,
          uncertain_accept_no_replay: true,
          explicit_password_login_after_lost_claim_reply: true,
          fixture_backend: true,
          actual_PostgreSQL_or_SSO_browser_acceptance_claimed: false,
        },
        null,
        2,
      ),
    );
    console.log(
      "Invitation UI passed administration, pagination, bodyless CSRF withdrawal, fragment erasure, memory-only bearer handling, existing-session protection, local activation and uncertain delivery without replay.",
    );
  } finally {
    page.off("request", record);
  }
}
