import { Readable, Writable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { asText, emitCase } from "./_stream_harness.mjs";

const events = [];
const chunks = [];
const source = Readable.from(["first", "second"]);
const sink = new Writable({
  write(chunk, encoding, callback) {
    events.push(`write:${asText(chunk)}`);
    chunks.push(asText(chunk));
    callback();
  },
});

source.on("end", () => events.push("source:end"));
sink.on("finish", () => events.push("sink:finish"));
await pipeline(source, sink);
events.push("pipeline:resolved");

emitCase("tc::stream::0060", {
  api: "stream/promises.pipeline",
  events,
  chunks,
});
