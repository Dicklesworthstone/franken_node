import { once } from "node:events";
import { Writable } from "node:stream";
import { emitCase } from "./_stream_harness.mjs";

const events = [];
const writable = new Writable({
  write(chunk, encoding, callback) {
    callback();
  },
});

writable.on("error", (error) => events.push(`error:${error.message}`));
writable.on("finish", () => events.push("finish"));
writable.on("close", () => events.push("close"));
writable.emit("error", new Error("write-fail"));
writable.destroy();

await once(writable, "close");
emitCase("tc::stream::0055", {
  api: "stream.Writable.destroy",
  events,
});
