const fs = require('fs');
console.log(fs.constants.F_OK === 0);
console.log(fs.constants.R_OK === 4);
console.log(fs.constants.W_OK === 2);
console.log(fs.constants.X_OK === 1);
