const fs = require('fs');
const path = require('path');
const dir = fs.mkdtempSync('case0077-');
(async () => {
  try {
    const file = path.join(dir, 'handle.txt');
    const fh = await fs.promises.open(file, 'w+');
    const w = await fh.write('abcdefgh', 0);
    const buf = Buffer.alloc(4);
    const r = await fh.read(buf, 0, 4, 2);
    const st = await fh.stat();
    await fh.close();
    console.log(w.bytesWritten, r.bytesRead, buf.toString('utf8'), st.size);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
})();
