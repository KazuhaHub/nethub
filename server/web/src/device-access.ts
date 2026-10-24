import type { Device } from "./api";

export function deviceDestination(device: Device): URL | null {
  try {
    const url = new URL(device.url);
    if (
      url.protocol !== "https:" ||
      url.port !== "8443" ||
      url.username ||
      url.password ||
      url.pathname !== "/" ||
      url.search ||
      url.hash
    )
      return null;
    return url;
  } catch {
    return null;
  }
}

export function canOpenDevice(device: Device, now = Date.now()): boolean {
  const certificate = device.gui_certificate;
  const destination = deviceDestination(device);
  return Boolean(
    !device.revoked &&
    device.online &&
    destination &&
    certificate &&
    ["applied", "renewing"].includes(certificate.state) &&
    certificate.assigned_host === destination.hostname &&
    certificate.confirmed_at &&
    Number.isFinite(Date.parse(certificate.confirmed_at)) &&
    certificate.valid_until &&
    Date.parse(certificate.valid_until) > now,
  );
}

export function certificateLabel(device: Device): string {
  if (device.revoked) return "Revoked";
  switch (device.gui_certificate?.state) {
    case "applied":
      return "Reported installed";
    case "renewing":
      return "Renewal pending";
    case "expired":
      return "Certificate expired";
    case "failed":
      return "Installation needs attention";
    case "unsupported":
      return "Certificate support unavailable";
    default:
      return "Awaiting installation report";
  }
}
