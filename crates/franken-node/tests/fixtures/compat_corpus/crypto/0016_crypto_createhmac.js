const crypto = require('crypto');
console.log(crypto.createHmac('sha512', 'k2').update('part1').update('part2').digest('hex'));
