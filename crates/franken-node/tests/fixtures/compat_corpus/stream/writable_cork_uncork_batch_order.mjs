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
});

writable.on("finish", () => events.push("finish"));
writable.on("close", () => events.push("close"));
writable.cork();
writable.write("one");
writable.write("two");
events.push(`buffered:${writable.writableLength}`);
writable.uncork();
writable.end();

await once(writable, "close");
emitCase("tc::stream::0052", {
  api: "stream.Writable.cork/uncork",
  events,
  chunks,
});
