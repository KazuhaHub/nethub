import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export async function verifySAMLProviders({ page, origin, evidence, login }) {
  const requests = [],
    screenshots = [];
  const record = (request) => {
    if (new URL(request.url()).pathname.startsWith("/api/v1/console/"))
      requests.push(request);
  };
  const dialog = page.getByRole("dialog");
  const save = () =>
    dialog.getByRole("button", { name: "Save provider", exact: true }).click();
  const cancel = () =>
    dialog.getByRole("button", { name: "Cancel", exact: true }).click();
  const writes = () =>
    requests.filter(
      (request) =>
        request.url().includes("/saml-providers") &&
        ["POST", "PATCH", "DELETE"].includes(request.method()),
    );
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
    await page.request.post(origin + "/test/saml-providers-reset");
    await page.context().clearCookies();
    await page.goto(origin + "/login");
    await login({ waitForRateLimit: true });
    await page.goto(origin + "/saml-providers");
    await page
      .getByRole("button", { name: "Edit Company SAML", exact: true })
      .waitFor();
    assert.equal(
      await page
        .getByRole("link", { name: "SAML", exact: true })
        .getAttribute("aria-current"),
      "page",
    );
    await page.getByRole("button", { name: "Next provider page" }).click();
    await page
      .getByRole("button", { name: "Edit SAML Provider 51", exact: true })
      .waitFor();
    await page.getByRole("button", { name: "Previous provider page" }).click();
    await page
      .getByRole("button", { name: "Edit Company SAML", exact: true })
      .click();
    assert.equal(
      await dialog
        .getByLabel("Replace IdP metadata XML (optional)", { exact: true })
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
      .getByRole("button", { name: "Copy metadata URL", exact: true })
      .click();
    assert.equal(
      await page.evaluate(() => navigator.clipboard.readText()),
      origin + "/api/v1/console/saml/company-saml/metadata",
    );
    await dialog
      .getByRole("button", { name: "Copy reply URL", exact: true })
      .click();
    assert.equal(
      await page.evaluate(() => navigator.clipboard.readText()),
      origin + "/api/v1/console/saml/company-saml/callback",
    );
    await dialog
      .getByLabel("Display name", { exact: true })
      .fill("Company renamed");
    await save();
    await dialog.waitFor({ state: "hidden" });
    assert.deepEqual(writes().at(-1).postDataJSON(), {
      display_name: "Company renamed",
    });
    await page
      .getByRole("button", { name: "Edit Company renamed", exact: true })
      .click();
    await page.setViewportSize({ width: 390, height: 844 });
    await screenshot("saml-mobile-dialog.png");
    await dialog
      .getByRole("button", { name: "Save provider", exact: true })
      .scrollIntoViewIfNeeded();
    const mobileAction = await dialog
      .getByRole("button", { name: "Save provider", exact: true })
      .boundingBox();
    assert.ok(
      mobileAction &&
        mobileAction.y >= 0 &&
        mobileAction.y + mobileAction.height <= 844,
      "Mobile dialog actions must remain reachable",
    );
    await screenshot("saml-mobile-dialog-actions.png");
    assert.ok(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth,
      ),
    );
    await cancel();
    await page.setViewportSize({ width: 1440, height: 1000 });
    await page
      .getByRole("button", { name: "Delete Company renamed", exact: true })
      .click();
    await dialog
      .getByRole("button", { name: "Delete provider", exact: true })
      .click();
    await dialog
      .getByRole("alert")
      .filter({ hasText: "bound users" })
      .waitFor();
    await cancel();
    await page
      .getByRole("button", { name: "Add SAML provider", exact: true })
      .click();
    await dialog
      .getByLabel("Display name", { exact: true })
      .fill("New SAML provider");
    await dialog.getByLabel("Slug", { exact: true }).fill("new-saml");
    await dialog
      .getByLabel("IdP entity ID", { exact: true })
      .fill("urn:new:identity");
    await dialog
      .getByLabel("IdP metadata XML", { exact: true })
      .fill("<EntityDescriptor/>");
    await save();
    await dialog.waitFor({ state: "hidden" });
    const creation = writes().at(-1).postDataJSON();
    assert.equal(creation.metadata_xml, "<EntityDescriptor/>");
    assert.equal(creation.enabled, false);
    assert.ok(!("signing_key" in creation));
    await page.getByRole("button", { name: "Next provider page" }).click();
    await page
      .getByRole("button", { name: "Edit New SAML provider", exact: true })
      .click();
    await dialog.getByLabel("Enable console sign-in", { exact: true }).check();
    await save();
    await dialog.waitFor({ state: "hidden" });
    assert.deepEqual(writes().at(-1).postDataJSON(), { enabled: true });
    await page
      .getByRole("button", { name: "Delete New SAML provider", exact: true })
      .click();
    await dialog
      .getByRole("button", { name: "Delete provider", exact: true })
      .click();
    await dialog.waitFor({ state: "hidden" });
    await page.getByRole("button", { name: "Previous provider page" }).click();
    await page
      .getByRole("button", { name: "Edit Company renamed", exact: true })
      .waitFor();
    const passive = await page.waitForResponse(
      (response) =>
        new URL(response.url()).pathname === "/api/v1/console/saml-providers" &&
        response.request().headers()["x-nethub-background"] === "1",
    );
    assert.equal(passive.request().method(), "GET");
    const beforeUncertain = writes().length;
    await page
      .getByRole("button", { name: "Add SAML provider", exact: true })
      .click();
    await dialog
      .getByLabel("Display name", { exact: true })
      .fill("Uncertain SAML provider");
    await dialog.getByLabel("Slug", { exact: true }).fill("uncertain-saml");
    await dialog
      .getByLabel("IdP entity ID", { exact: true })
      .fill("urn:uncertain:identity");
    await dialog
      .getByLabel("IdP metadata XML", { exact: true })
      .fill("<EntityDescriptor/>");
    await page.route("**/api/v1/console/saml-providers", async (route) => {
      if (route.request().method() === "POST") {
        await route.fetch();
        await route.abort("failed");
      } else await route.continue();
    });
    await save();
    await dialog.getByRole("alert").waitFor();
    assert.ok(
      await dialog
        .getByRole("button", { name: "Save provider", exact: true })
        .isDisabled(),
    );
    assert.equal(
      writes().length,
      beforeUncertain + 1,
      "Unconfirmed writes must never replay",
    );
    await page.unroute("**/api/v1/console/saml-providers");
    await cancel();
    await page.getByRole("button", { name: "Next provider page" }).click();
    await page
      .getByRole("button", {
        name: "Delete Uncertain SAML provider",
        exact: true,
      })
      .click();
    await dialog
      .getByRole("button", { name: "Delete provider", exact: true })
      .click();
    await dialog.waitFor({ state: "hidden" });
    await page.getByRole("button", { name: "Previous provider page" }).click();
    await page
      .getByRole("button", { name: "Edit Company renamed", exact: true })
      .waitFor();
    const contrast = await page.evaluate(() => {
      const root = document.documentElement,
        wasDark = root.classList.contains("dark"),
        samples = [];
      const luminance = (color) => {
        const channels = color
          .match(/[\d.]+/g)
          .slice(0, 3)
          .map(Number)
          .map((value) => value / 255)
          .map((value) =>
            value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4,
          );
        return (
          channels[0] * 0.2126 + channels[1] * 0.7152 + channels[2] * 0.0722
        );
      };
      try {
        for (const dark of [false, true]) {
          root.classList.toggle("dark", dark);
          for (const selector of [
            '.provider-tabs [aria-current="page"]',
            ".provider-status.online",
            ".provider-status.revoked",
          ]) {
            const style = getComputedStyle(document.querySelector(selector)),
              fg = luminance(style.color),
              bg = luminance(style.backgroundColor);
            samples.push({
              dark,
              selector,
              ratio: (Math.max(fg, bg) + 0.05) / (Math.min(fg, bg) + 0.05),
            });
          }
        }
      } finally {
        root.classList.toggle("dark", wasDark);
      }
      return samples;
    });
    assert.ok(
      contrast.every((value) => value.ratio >= 4.5),
      JSON.stringify(contrast),
    );
    await page.evaluate(() =>
      document.documentElement.classList.remove("dark"),
    );
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
    await page.goto(origin + "/saml-providers");
    await page
      .getByRole("heading", {
        name: "Administrator access required",
        exact: true,
      })
      .waitFor();
    assert.equal(
      await page
        .getByRole("button", { name: "Add SAML provider", exact: true })
        .count(),
      0,
    );
    await page.request.post(origin + "/test/admin");
    await page.goto(origin + "/saml-providers");
    await page
      .getByRole("button", { name: "Edit Company renamed", exact: true })
      .waitFor();
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
    await screenshot("saml-providers-light.png");
    await page
      .getByRole("button", { name: "Use dark theme", exact: true })
      .click();
    await page.waitForFunction(() =>
      document.documentElement.classList.contains("dark"),
    );
    await screenshot("saml-providers-dark.png");
    await page.evaluate(() =>
      document.documentElement.classList.remove("dark"),
    );
    await page.getByRole("link", { name: "Invitations", exact: true }).click();
    await page
      .getByRole("button", { name: "Invite user", exact: true })
      .click();
    await dialog
      .getByLabel("Email address", { exact: true })
      .fill("saml-ui@example.com");
    await dialog
      .getByLabel("Sign-in restriction", { exact: true })
      .selectOption("00000000-0000-4000-8000-000000005000");
    await dialog
      .getByRole("button", { name: "Create invitation", exact: true })
      .click();
    const field = dialog.getByLabel("Invitation link", { exact: true });
    await field.waitFor();
    const invite = await field.inputValue();
    await page.context().clearCookies();
    await page.goto(invite);
    await page
      .getByRole("button", {
        name: "Continue with Company renamed",
        exact: true,
      })
      .waitFor();
    assert.equal(
      await page.getByLabel("New password", { exact: true }).count(),
      0,
    );
    await page
      .getByRole("button", {
        name: "Continue with Company renamed",
        exact: true,
      })
      .click();
    await page.waitForURL(origin + "/test/saml-authorize");
    const claim = requests.findLast((request) =>
      request.url().endsWith("/saml/company-saml/start"),
    );
    assert.equal(
      claim.postDataJSON().invite_token,
      new URL(invite).hash.slice(1),
    );
    await page.goto(origin + "/login");
    await page
      .getByRole("button", {
        name: "Continue with Company renamed",
        exact: true,
      })
      .click();
    await page.waitForURL(origin + "/test/saml-authorize");
    assert.deepEqual(
      requests
        .findLast((request) =>
          request.url().endsWith("/saml/company-saml/start"),
        )
        .postDataJSON(),
      {},
    );
    writeFileSync(
      join(evidence, "saml-providers-results.json"),
      JSON.stringify(
        {
          passed: true,
          synthetic_navigation_only: true,
          genuine_SAML_or_SQL_acceptance_claimed: false,
          contrast,
          screenshots,
          checks: [
            "SAML CRUD and pagination",
            "omitted metadata and private fields",
            "public SP addresses",
            "native mobile dialog",
            "reachable mobile dialog actions",
            "passive inventory and authority loss",
            "unconfirmed mutation without automatic replay",
            "bound provider refusal",
            "protocol-specific invitation and sign-in navigation",
            "light and dark text contrast",
          ],
        },
        null,
        2,
      ),
    );
    console.log(
      "SAML console UI passed management, native dialog, restricted invitation and sign-in navigation under strict CSP; synthetic navigation does not establish SAML sessions.",
    );
  } finally {
    page.off("request", record);
  }
}
