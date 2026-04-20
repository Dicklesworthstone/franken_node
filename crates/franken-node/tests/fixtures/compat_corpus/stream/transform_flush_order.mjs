import { Readable, Transform, Writable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { asText, emitCase } from "./_stream_harness.mjs";

const events = [];
const chunks = [];
const transform = new Transform({
  transform(chunk, encoding, callback) {
    events.push(`transform:${asText(chunk)}`);
    callback(null, chunk);
  },
  flush(callback) {
    events.push("flush");
    callback(null, "tail");
  },
});
const sink = new Writable({
  write(chunk, encoding, callback) {
    events.push(`write:${asText(chunk)}`);
    chunks.push(asText(chunk));
    callback();
  },
});

await pipeline(Readable.from(["head"]), transform, sink);
events.push("pipeline:resolved");

emitCase("tc::stream::0058", {
  api: "stream.Transform _flush",
  events,
  chunks,
});
