import { once } from "node:events";
import { Readable, Writable } from "node:stream";
import { asText, emitCase } from "./_stream_harness.mjs";

const events = [];
const chunks = [];
const source = Readable.from(["north", "south"]);
const sink = new Writable({
  write(chunk, encoding, callback) {
    chunks.push(asText(chunk));
    events.push(`write:${asText(chunk)}`);
    callback();
  },
});

sink.on("pipe", () => events.push("pipe"));
sink.on("finish", () => events.push("finish"));
sink.on("close", () => events.push("close"));
source.pipe(sink);

await once(sink, "close");
emitCase("tc::stream::0062", {
  api: "stream.Readable.pipe",
  events,
  chunks,
});
