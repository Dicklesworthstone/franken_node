const u = new URL('https://example.com/a?b=1#c');
console.log(u.toString());
console.log(u.toJSON());
console.log(u.toString() === u.href && u.toJSON() === u.href);
console.log(JSON.stringify({ endpoint: u }));
