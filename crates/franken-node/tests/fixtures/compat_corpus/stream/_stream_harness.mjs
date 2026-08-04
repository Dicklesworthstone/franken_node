function canonicalize(value) {
  if (Array.isArray(value)) {
    return value.map(canonicalize);
  }
  if (value !== null && typeof value === "object") {
    const ordered = {};
    for (const key of Object.keys(value).sort()) {
      ordered[key] = canonicalize(value[key]);
    }
    return ordered;
  }
  return value;
}

export function emitCase(id, payload) {
  console.log(JSON.stringify(canonicalize({ id, ...payload })));
}

export function asText(chunk) {
  return Buffer.isBuffer(chunk) ? chunk.toString("utf8") : String(chunk);
}
