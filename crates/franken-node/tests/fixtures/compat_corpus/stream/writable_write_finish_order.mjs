import { once } from "node:events";
import { Writable } from "node:stream";
import { asText, emitCase } from "./_stream_harness.mjs";

const events = [];
const chunks = [];
const writable = new Writable({
  write(chunk, encoding, callback) {
    chunks.push(asText(chunk));
    events.push(`write:${asText(chunk)}`);
    callback();
  },
  final(callback) {
    events.push("final");
    callback();
  },
});

writable.on("prefinish", () => events.push("prefinish"));
writable.on("finish", () => events.push("finish"));
writable.on("close", () => events.push("close"));
writable.write("alpha", () => events.push("callback:alpha"));
writable.end("omega", () => events.push("callback:end"));

await once(writable, "close");
emitCase("tc::stream::0051", {
  api: "stream.Writable.write/end",
  events,
  chunks,
});
