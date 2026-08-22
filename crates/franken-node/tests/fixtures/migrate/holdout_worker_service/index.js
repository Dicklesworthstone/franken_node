const fs = require("fs");

function loadWorkerConfig(path) {
  const raw = fs.readFileSync(path, "utf8");
  return JSON.parse(raw);
}

module.exports = { loadWorkerConfig };
