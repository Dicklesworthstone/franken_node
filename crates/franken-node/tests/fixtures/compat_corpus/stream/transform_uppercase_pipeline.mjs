import { Readable, Transform, Writable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { asText, emitCase } from "./_stream_harness.mjs";

const events = [];
const chunks = [];
const upper = new Transform({
  transform(chunk, encoding, callback) {
    events.push("transform");
    callback(null, asText(chunk).toUpperCase());
  },
});
const sink = new Writable({
  write(chunk, encoding, callback) {
    events.push("write");
    chunks.push(asText(chunk));
    callback();
  },
});

await pipeline(Readable.from(["ab", "cd"]), upper, sink);
events.push("pipeline:resolved");

emitCase("tc::stream::0056", {
  api: "stream.Transform pipeline",
  events,
  chunks,
});
