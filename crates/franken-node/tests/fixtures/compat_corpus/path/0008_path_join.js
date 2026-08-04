const path = require('path');
try {
  path.join('a', 1);
  console.log('no-throw');
} catch (e) {
  console.log(e instanceof TypeError, e.code);
}
