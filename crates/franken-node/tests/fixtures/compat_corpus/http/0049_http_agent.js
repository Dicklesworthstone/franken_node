const http=require('http');
const agent=new http.Agent();
console.log('keepAlive:'+(agent.keepAlive===false||agent.keepAlive===undefined),'proto:'+(typeof agent.protocol==='string'?agent.protocol:'none'));
