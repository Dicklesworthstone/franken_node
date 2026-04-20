import { once } from "node:events";
import { Readable } from "node:stream";
import { asText, emitCase } from "./_stream_harness.mjs";

const events = [];
const chunks = [];
const readable = Readable.from(["alpha", "beta"]);

readable.on("data", (chunk) => {
  events.push("data");
  chunks.push(asText(chunk));
});
readable.on("end", () => events.push("end"));
readable.on("close", () => events.push("close"));

await once(readable, "close");
emitCase("tc::stream::0046", {
  api: "stream.Readable.from",
  events,
  chunks,
});
