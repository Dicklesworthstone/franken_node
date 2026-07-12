setTimeout(() => {
  console.log('level1');
  setTimeout(() => {
    console.log('level2');
    setTimeout(() => {
      console.log('level3');
    }, 5);
  }, 5);
}, 5);
