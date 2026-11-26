const http = require('http');
const agent = new http.Agent({ keepAlive: true });
console.log('keepAlive:' + agent.keepAlive + ',protocol:' + agent.protocol + ',port:' + agent.defaultPort);
