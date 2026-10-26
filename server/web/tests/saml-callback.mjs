export function observeSAMLAuthorization(page, origin, pathname) {
  let value;
  const listener = (request) => {
    const url = new URL(request.url());
    if (
      request.isNavigationRequest() &&
      url.origin === origin &&
      url.pathname === pathname &&
      url.searchParams.has("SAMLRequest")
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
