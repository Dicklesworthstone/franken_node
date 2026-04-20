import { once } from "node:events";
import { Transform } from "node:stream";
import { emitCase } from "./_stream_harness.mjs";

const events = [];
const transform = new Transform({
  highWaterMark: 4,
  transform(chunk, encoding, callback) {
    setImmediate(() => callback(null, chunk));
  },
});

transform.resume();
transform.on("drain", () => events.push("drain"));
transform.on("end", () => events.push("end"));
transform.on("close", () => events.push("close"));
const firstAccepted = transform.write(Buffer.alloc(8, "a"));
const secondAccepted = transform.write(Buffer.alloc(8, "b"));
events.push(`write:first:${firstAccepted}`);
events.push(`write:second:${secondAccepted}`);
await once(transform, "drain");
transform.end();
await once(transform, "close");

emitCase("tc::stream::0059", {
  api: "stream.Transform backpressure",
  events,
});
