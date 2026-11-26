let a = 0;
let b = 0;
function checkDone() {
  if (a === 2 && b === 2) {
    console.log('a:' + a + ',b:' + b);
  }
}
const ivA = setInterval(() => {
  a++;
  if (a === 2) {
    clearInterval(ivA);
    checkDone();
  }
}, 8);
const ivB = setInterval(() => {
  b++;
  if (b === 2) {
    clearInterval(ivB);
    checkDone();
  }
}, 12);
