import { Readable } from "node:stream";
import { asText, emitCase } from "./_stream_harness.mjs";

const events = [];
const chunks = [];
const readable = Readable.from(["red", "green", "blue"]);

for await (const chunk of readable) {
  events.push("yield");
  chunks.push(asText(chunk));
}
events.push("iterator:done");

emitCase("tc::stream::0048", {
  api: "stream.Readable async iterator",
  events,
  chunks,
});
