console.log(URL.canParse('/rel/path', 'https://example.com/a/b'));
console.log(URL.canParse('../other', 'https://example.com/a/b'));
console.log(URL.canParse('/rel/path', 'not-a-base'));
console.log(URL.canParse('https://other.org', 'not-a-base'));
