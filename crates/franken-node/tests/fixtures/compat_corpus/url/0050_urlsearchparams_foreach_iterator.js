const sp = new URLSearchParams('k1=v1&k2=v2&k1=v3');
const viaForEach = [];
sp.forEach((value, key) => viaForEach.push([key, value]));
const viaIter = [];
for (const [k, v] of sp) {
  viaIter.push([k, v]);
}
console.log(JSON.stringify(viaForEach));
console.log(JSON.stringify(viaIter));
