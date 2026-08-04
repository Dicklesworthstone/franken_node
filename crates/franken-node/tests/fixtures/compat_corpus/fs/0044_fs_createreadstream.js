const fs = require('fs');
fs.writeFileSync('stream.txt', 'stream contents');
const rs = fs.createReadStream('stream.txt', { encoding: 'utf8' });
let acc = '';
rs.on('data', (chunk) => { acc += chunk; });
rs.on('end', () => {
  console.log(acc);
  console.log('ended');
});
