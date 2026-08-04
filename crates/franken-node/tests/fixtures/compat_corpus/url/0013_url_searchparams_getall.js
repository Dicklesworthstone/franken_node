const p = new URL('http://example.com/?t=1&t=2&t=3').searchParams;
console.log(p.getAll('t').join(','), p.getAll('none').length);
