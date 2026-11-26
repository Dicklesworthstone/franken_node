const http = require('http');
try {
  http.get('https://127.0.0.1:1/');
  console.log('no-throw');
} catch (e) {
  console.log('code:' + e.code);
}
