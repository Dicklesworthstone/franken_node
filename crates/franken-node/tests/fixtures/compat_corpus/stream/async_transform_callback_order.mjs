import { Readable, Transform, Writable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { asText, emitCase } from "./_stream_harness.mjs";

const events = [];
const chunks = [];
const transform = new Transform({
  transform(chunk, encoding, callback) {
    const text = asText(chunk);
    events.push(`start:${text}`);
    setImmediate(() => {
      events.push(`done:${text}`);
      callback(null, `${text}!`);
    });
  },
});
const sink = new Writable({
  write(chunk, encoding, callback) {
    chunks.push(asText(chunk));
    events.push(`write:${asText(chunk)}`);
    callback();
  },
});

await pipeline(Readable.from(["one", "two"]), transform, sink);
events.push("pipeline:resolved");

emitCase("tc::stream::0065", {
  api: "stream.Transform async callback",
  events,
  chunks,
});
