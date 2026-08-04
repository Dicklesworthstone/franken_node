setTimeout(() => {
  console.log('timerA');
  queueMicrotask(() => { console.log('microA'); });
}, 5);
setTimeout(() => {
  console.log('timerB');
}, 25);
