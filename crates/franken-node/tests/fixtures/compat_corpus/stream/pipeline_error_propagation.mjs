import { Readable, Transform, Writable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { asText, emitCase } from "./_stream_harness.mjs";

const events = [];
const transform = new Transform({
  transform(chunk, encoding, callback) {
    const text = asText(chunk);
    events.push(`transform:${text}`);
    callback(text === "bad" ? new Error("transform-fail") : null, chunk);
  },
});
const sink = new Writable({
  write(chunk, encoding, callback) {
    events.push(`write:${asText(chunk)}`);
    callback();
  },
});

try {
  await pipeline(Readable.from(["ok", "bad", "later"]), transform, sink);
  events.push("pipeline:resolved");
} catch (error) {
  events.push(`pipeline:rejected:${error.message}`);
}

emitCase("tc::stream::0061", {
  api: "stream/promises.pipeline error",
  events,
});
