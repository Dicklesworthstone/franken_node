import { once } from "node:events";
import { Readable } from "node:stream";
import { emitCase } from "./_stream_harness.mjs";

const events = [];
const chunks = [];
const readable = Readable.from([{ step: 1 }, { step: 2 }], { objectMode: true });

readable.on("data", (chunk) => {
  events.push("data");
  chunks.push(chunk.step);
});
readable.on("end", () => events.push("end"));
readable.on("close", () => events.push("close"));

await once(readable, "close");
emitCase("tc::stream::0049", {
  api: "stream.Readable objectMode",
  events,
  chunks,
});
