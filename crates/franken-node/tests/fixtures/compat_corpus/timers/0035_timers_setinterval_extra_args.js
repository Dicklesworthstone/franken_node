const seen = [];
const iv = setInterval((tag, step) => {
  seen.push(tag + ':' + (seen.length + 1) * step);
  if (seen.length === 3) {
    clearInterval(iv);
    console.log(seen.join(','));
  }
}, 5, 'k', 10);
