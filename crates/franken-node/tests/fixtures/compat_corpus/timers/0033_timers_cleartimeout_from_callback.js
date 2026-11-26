let laterRan = false;
const tLater = setTimeout(() => {
  laterRan = true;
}, 40);
setTimeout(() => {
  clearTimeout(tLater);
  console.log('cancelled-later');
}, 5);
setTimeout(() => {
  console.log('later-ran:' + laterRan);
}, 70);
