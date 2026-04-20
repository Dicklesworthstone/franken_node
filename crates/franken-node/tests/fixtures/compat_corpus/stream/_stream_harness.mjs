export function emitCase(id, payload) {
  process.stdout.write(`${JSON.stringify({ id, ...payload })}\n`);
}

export function asText(chunk) {
  return Buffer.isBuffer(chunk) ? chunk.toString("utf8") : String(chunk);
}
