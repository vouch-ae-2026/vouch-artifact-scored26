/** Intentionally vulnerable teaching example. Never use as an authority API. */
export function reduceCheckerReport(report) {
  const accepted =
    report?.authentication_status === "authenticated" ||
    report?.status === "checked-external";
  return Object.freeze({ ok: accepted });
}

export function renderBooleanResult(result) {
  return result?.ok === true ? "Verified" : "Rejected";
}
