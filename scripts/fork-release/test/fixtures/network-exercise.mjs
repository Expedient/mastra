import net from 'node:net';

await new Promise(resolve => {
  const socket = net.connect({ host: '127.0.0.1', port: 9 });
  socket.once('connect', () => socket.destroy());
  socket.once('error', () => resolve());
  socket.once('close', () => resolve());
});
