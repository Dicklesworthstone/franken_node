console.log(URL.canParse('https://example.com/path?a=1#h'));
console.log(URL.canParse('http://localhost:8080'));
console.log(URL.canParse('mailto:user@example.com'));
console.log(URL.canParse('/relative/only'));
console.log(URL.canParse('not a valid url'));
console.log(URL.canParse(''));
