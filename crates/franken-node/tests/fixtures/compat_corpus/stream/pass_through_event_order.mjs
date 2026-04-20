import { once } from "node:events";
import { PassThrough } from "node:stream";
import { asText, emitCase } from "./_stream_harness.mjs";

const events = [];
const chunks = [];
const stream = new PassThrough();

stream.on("data", (chunk) => {
  events.push("data");
  chunks.push(asText(chunk));
});
stream.on("end", () => events.push("end"));
stream.on("close", () => events.push("close"));
stream.write("front");
stream.end("back");

await once(stream, "close");
emitCase("tc::stream::0064", {
  api: "stream.PassThrough",
  events,
  chunks,
});
