const iv = setInterval(() => {}, 50);
clearInterval(iv);
clearInterval(iv);
clearInterval(null);
clearInterval(undefined);
console.log('clear-interval-noop-ok');
