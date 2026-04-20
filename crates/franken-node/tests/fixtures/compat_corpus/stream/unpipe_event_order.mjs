import { once } from "node:events";
import { PassThrough, Writable } from "node:stream";
import { emitCase } from "./_stream_harness.mjs";

const events = [];
const source = new PassThrough();
const sink = new Writable({
  write(chunk, encoding, callback) {
    events.push("write");
    callback();
  },
});

sink.on("pipe", () => events.push("pipe"));
sink.on("unpipe", () => events.push("unpipe"));
sink.on("finish", () => events.push("finish"));
sink.on("close", () => events.push("close"));
source.pipe(sink);
source.write("before-unpipe");
source.unpipe(sink);
sink.end();
source.end("after-unpipe");

await once(sink, "close");
emitCase("tc::stream::0063", {
  api: "stream.Readable.unpipe",
  events,
});
