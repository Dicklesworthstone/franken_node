const { Readable } = require('stream');
const m = new Map([['k1', 10], ['k2', 20], ['k3', 30]]);
const r = Readable.from(m);
const out = [];
r.on('data', (pair) => out.push(`${pair[0]}=${pair[1]}`));
r.on('end', () => console.log(out.join(';')));
