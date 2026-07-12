const http=require('http');
console.log(http.METHODS.includes('GET'),http.METHODS.includes('POST'),http.METHODS.includes('PUT'));
