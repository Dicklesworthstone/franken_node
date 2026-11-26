const qs = require('querystring');
const parsed = qs.parse('theme=dark%20mode;lang=en-US;lang=fr-FR', ';', '=');
console.log(JSON.stringify(parsed));
