import type { TrafficPage } from "./api";

const decimal = /^(0|[1-9][0-9]{0,63})$/;
export const validWarning = (value: string) =>
  /^(0|[1-9][0-9]{0,29})$/.test(value);
export const validMonth = (value: string) =>
  /^(?!0000)[0-9]{4}-(0[1-9]|1[0-2])$/.test(value);
const count = (value: unknown): value is string =>
  typeof value === "string" && decimal.test(value);
const timestamp = (value: unknown): value is string =>
  typeof value === "string" && Number.isFinite(Date.parse(value));
const exactKeys = (value: object, keys: string[]) =>
  Object.keys(value).every((key) => keys.includes(key));
const totals = (value: {
  in_bytes: unknown;
  out_bytes: unknown;
  total_bytes: unknown;
  reset_events: unknown;
}) =>
  count(value.in_bytes) &&
  count(value.out_bytes) &&
  count(value.total_bytes) &&
  count(value.reset_events) &&
  BigInt(value.in_bytes) + BigInt(value.out_bytes) ===
    BigInt(value.total_bytes);

export function trafficProjection(value: TrafficPage): boolean {
  if (
    !value ||
    typeof value !== "object" ||
    !exactKeys(value, [
      "month",
      "in_bytes",
      "out_bytes",
      "total_bytes",
      "reset_events",
      "first_observed_at",
      "last_observed_at",
      "warning_bytes",
      "warning",
      "warning_revision",
      "items",
      "next_cursor",
    ]) ||
    !validMonth(value.month) ||
    !totals(value) ||
    !Number.isSafeInteger(value.warning_revision) ||
    value.warning_revision < 0 ||
    !(
      value.warning_bytes === null ||
      (typeof value.warning_bytes === "string" &&
        validWarning(value.warning_bytes) &&
        value.warning_bytes !== "0")
    ) ||
    typeof value.warning !== "boolean" ||
    value.warning !==
      (value.warning_bytes !== null &&
        BigInt(value.total_bytes) > BigInt(value.warning_bytes)) ||
    !Array.isArray(value.items) ||
    value.items.length > 200 ||
    !(
      value.next_cursor === null ||
      (typeof value.next_cursor === "string" &&
        /^[A-Za-z0-9_-]{1,64}$/.test(value.next_cursor))
    )
  )
    return false;
  if ((value.first_observed_at === null) !== (value.last_observed_at === null))
    return false;
  if (
    value.first_observed_at !== null &&
    (!timestamp(value.first_observed_at) ||
      !timestamp(value.last_observed_at) ||
      Date.parse(value.first_observed_at) > Date.parse(value.last_observed_at!))
  )
    return false;
  const seen = new Set<string>();
  return value.items.every((item) => {
    if (
      !item ||
      typeof item !== "object" ||
      !exactKeys(item, [
        "device_id",
        "label",
        "hostname",
        "removed",
        "in_bytes",
        "out_bytes",
        "total_bytes",
        "reset_events",
        "first_observed_at",
        "last_observed_at",
      ]) ||
      typeof item.device_id !== "string" ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(
        item.device_id,
      ) ||
      seen.has(item.device_id) ||
      typeof item.label !== "string" ||
      typeof item.hostname !== "string" ||
      typeof item.removed !== "boolean" ||
      !totals(item) ||
      !timestamp(item.first_observed_at) ||
      !timestamp(item.last_observed_at) ||
      Date.parse(item.first_observed_at) > Date.parse(item.last_observed_at)
    )
      return false;
    seen.add(item.device_id);
    return true;
  });
}

export function formatBytes(value: string): string {
  if (!count(value)) throw new Error("Invalid byte count");
  const bytes = BigInt(value);
  const units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"];
  let divisor = 1n,
    unit = 0;
  while (unit < units.length - 1 && bytes >= divisor * 1024n) {
    divisor *= 1024n;
    unit++;
  }
  if (!unit) return `${value} B`;
  const tenths = (bytes * 10n) / divisor;
  return `${tenths / 10n}.${tenths % 10n} ${units[unit]}`;
}
