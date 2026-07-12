const fs = require('fs');
fs.writeFileSync('data.json', JSON.stringify({ items: [1, 2, 3] }));
const parsed = JSON.parse(fs.readFileSync('data.json', 'utf8'));
console.log(parsed.items.join(','));
console.log(parsed.items.length);
