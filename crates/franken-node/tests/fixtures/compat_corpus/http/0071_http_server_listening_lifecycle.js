const http = require('http');
const srv = http.createServer((req, res) => res.end('ok'));
const before = srv.listening;
srv.listen(0, '127.0.0.1', () => {
  const during = srv.listening;
  srv.close(() => {
    const after = srv.listening;
    console.log('states:' + before + ',' + during + ',' + after);
  });
});
