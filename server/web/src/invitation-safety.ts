const bearerPattern = /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/;

export function takeInvitation(
  location: Pick<Location, "pathname" | "hash" | "search">,
  history: Pick<History, "replaceState">,
): string | null {
  if (location.pathname !== "/invite") return null;
  const token = location.hash.slice(1);
  const valid = !location.search && bearerPattern.test(token);
  try {
    history.replaceState(null, "", "/invite");
  } catch {
    return null;
  }
  return valid ? token : null;
}

export function validInvitationLink(
  value: string,
  origin: string,
  expiry: string,
): boolean {
  try {
    const url = new URL(value);
    return (
      url.protocol === "https:" &&
      url.origin === origin &&
      !url.username &&
      !url.password &&
      url.pathname === "/invite" &&
      !url.search &&
      bearerPattern.test(url.hash.slice(1)) &&
      Date.parse(expiry) > Date.now()
    );
  } catch {
    return false;
  }
}

export function validInvitationPassword(password: string): boolean {
  return (
    Array.from(password).length >= 15 &&
    new TextEncoder().encode(password).length <= 1024 &&
    !/[\r\n\x00]/.test(password) &&
    !/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(
      password,
    )
  );
}
