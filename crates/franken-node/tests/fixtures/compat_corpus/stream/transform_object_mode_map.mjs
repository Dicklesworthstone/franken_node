import { Readable, Transform, Writable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { emitCase } from "./_stream_harness.mjs";

const events = [];
const chunks = [];
const mapper = new Transform({
  objectMode: true,
  transform(chunk, encoding, callback) {
    events.push(`map:${chunk.value}`);
    callback(null, { value: chunk.value * 2 });
  },
});
const sink = new Writable({
  objectMode: true,
  write(chunk, encoding, callback) {
    chunks.push(chunk.value);
    events.push(`write:${chunk.value}`);
    callback();
  },
});

await pipeline(Readable.from([{ value: 2 }, { value: 4 }], { objectMode: true }), mapper, sink);
events.push("pipeline:resolved");

emitCase("tc::stream::0057", {
  api: "stream.Transform objectMode",
  events,
  chunks,
});
