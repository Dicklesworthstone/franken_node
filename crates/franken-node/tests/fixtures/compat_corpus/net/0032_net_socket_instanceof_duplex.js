const net=require('net');
const stream=require('stream');
const sock=new net.Socket();
console.log('duplex:'+(sock instanceof stream.Duplex),'readable-prop:'+(typeof sock.readable==='boolean'));
sock.destroy();
