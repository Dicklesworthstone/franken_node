import { once } from "node:events";
import { Writable } from "node:stream";
import { emitCase } from "./_stream_harness.mjs";

const events = [];
const writeSizes = [];
const writable = new Writable({
  highWaterMark: 4,
  write(chunk, encoding, callback) {
    writeSizes.push(chunk.length);
    setImmediate(callback);
  },
});

writable.on("drain", () => events.push("drain"));
writable.on("finish", () => events.push("finish"));
writable.on("close", () => events.push("close"));
const firstAccepted = writable.write(Buffer.alloc(8, "a"));
const secondAccepted = writable.write(Buffer.alloc(8, "b"));
events.push(`write:first:${firstAccepted}`);
events.push(`write:second:${secondAccepted}`);
await once(writable, "drain");
writable.end();
await once(writable, "close");

emitCase("tc::stream::0053", {
  api: "stream.Writable backpressure",
  events,
  writeSizes,
});
