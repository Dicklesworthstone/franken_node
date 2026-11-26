const { fileURLToPath } = require('url');
try {
  fileURLToPath('https://example.com/a');
  console.log('no-throw');
} catch (e) {
  console.log(e instanceof TypeError);
}
