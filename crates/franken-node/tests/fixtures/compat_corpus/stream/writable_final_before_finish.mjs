import { once } from "node:events";
import { Writable } from "node:stream";
import { emitCase } from "./_stream_harness.mjs";

const events = [];
const writable = new Writable({
  write(chunk, encoding, callback) {
    events.push("write");
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
writable.end("payload");

await once(writable, "close");
emitCase("tc::stream::0054", {
  api: "stream.Writable _final",
  events,
});
