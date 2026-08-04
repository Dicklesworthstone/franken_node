const {Duplex} = require('stream');
const d = new Duplex({
  read() { this.push('from-read'); this.push(null); },
  write(c, e, cb) { console.log('sink:' + c.toString()); cb(); }
});
d.on('data', (c) => console.log('src:' + c.toString()));
d.write('to-write');
d.end();
