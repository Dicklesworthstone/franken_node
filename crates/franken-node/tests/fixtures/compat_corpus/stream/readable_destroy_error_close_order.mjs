import { once } from "node:events";
import { Readable } from "node:stream";
import { emitCase } from "./_stream_harness.mjs";

const events = [];
const readable = new Readable({
  read() {
    this.push("before-destroy");
  },
});

readable.on("error", (error) => events.push(`error:${error.message}`));
readable.on("close", () => events.push("close"));
readable.emit("error", new Error("read-fail"));
readable.destroy();

await once(readable, "close");
emitCase("tc::stream::0050", {
  api: "stream.Readable.destroy",
  events,
});
