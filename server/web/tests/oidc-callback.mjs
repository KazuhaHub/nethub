import assert from "node:assert/strict";

export function observeAuthorization(page, origin, clientID) {
  let value;
  const listener = (request) => {
    const url = new URL(request.url());
    if (
      request.isNavigationRequest() &&
      url.origin === origin &&
      url.pathname === "/auth" &&
      url.searchParams.get("client_id") === clientID
    )
      value = request.url();
  };
  page.on("request", listener);
  return {
    get url() {
      return value;
    },
    close() {
      page.off("request", listener);
    },
  };
}

// Request events include redirect hops; page.route handlers may not see them.
export async function captureCallback(page, origin, pathname, trigger, text) {
  const received = page.waitForRequest((request) => {
    const url = new URL(request.url());
    return url.origin === origin && url.pathname === pathname;
  });
  const [, request] = await Promise.all([trigger(), received]);
  assert.equal(request.method(), "GET", "Expected a query-mode code callback");
  await page.waitForURL(
    (url) => url.origin === origin && url.pathname === pathname,
  );
  await page.getByText(text, { exact: true }).waitFor();
  return new URL(request.url());
}
