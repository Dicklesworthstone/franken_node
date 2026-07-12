const fs = require('fs');
const ws = fs.createWriteStream('wout.txt');
ws.write('part1 ');
ws.end('part2');
ws.on('finish', () => {
  console.log(fs.readFileSync('wout.txt', 'utf8'));
});
