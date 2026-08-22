const { loadWorkerConfig } = require("./index.js");

const config = loadWorkerConfig("package.json");
process.stdout.write(`worker ready: ${config.name}\n`);
