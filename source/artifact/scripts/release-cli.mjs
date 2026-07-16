/**
 * Parse the release commands' exact option/value interface while retaining
 * enough history to apply the three usage-error publication carve-outs.
 */
export function parseReleaseArguments(args, required) {
  const allowed = new Set(required);
  const values = Object.create(null);
  let firstError = null;
  let errorBeforeOutDir = false;
  let outDirOccurrences = 0;
  let outDirValue = null;

  const record = (message) => {
    if (firstError !== null) return;
    firstError = message;
    if (!(outDirOccurrences === 1 && outDirValue !== null)) {
      errorBeforeOutDir = true;
    }
  };

  for (let index = 0; index < args.length; ) {
    const option = args[index];
    if (!allowed.has(option)) {
      record(`unknown option ${option ?? '<missing>'}`);
      index += 1;
      if (index < args.length && !args[index].startsWith('--')) index += 1;
      continue;
    }

    const value = args[index + 1];
    const usableValue =
      value !== undefined && value.length > 0 && !value.startsWith('--');
    if (option === '--out-dir') {
      outDirOccurrences += 1;
      if (outDirOccurrences === 1 && usableValue) outDirValue = value;
    }
    if (!usableValue) {
      record(`missing value for ${option}`);
      index += 1;
      continue;
    }
    if (Object.hasOwn(values, option)) {
      record(`repeated option ${option}`);
    } else {
      values[option] = value;
    }
    index += 2;
  }

  if (firstError === null) {
    const missing = required.find((option) => !Object.hasOwn(values, option));
    if (missing !== undefined) record(`missing ${missing}`);
  }

  const reportOutDir =
    outDirOccurrences === 1 && outDirValue !== null && !errorBeforeOutDir
      ? outDirValue
      : null;
  return Object.freeze({
    ok: firstError === null,
    values,
    error: firstError,
    reportOutDir,
  });
}
