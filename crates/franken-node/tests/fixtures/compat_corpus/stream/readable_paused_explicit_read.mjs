import { once } from "node:events";
import { Readable } from "node:stream";
import { asText, emitCase } from "./_stream_harness.mjs";

const events = [];
const chunks = [];
const readable = Readable.from(["left", "right"]);

readable.pause();
readable.on("readable", () => events.push("readable"));
readable.on("end", () => events.push("end"));
readable.on("close", () => events.push("close"));

await once(readable, "readable");
let chunk = readable.read();
while (chunk !== null) {
  chunks.push(asText(chunk));
  chunk = readable.read();
}
await once(readable, "close");

emitCase("tc::stream::0047", {
  api: "stream.Readable.read",
  events,
  chunks,
});
