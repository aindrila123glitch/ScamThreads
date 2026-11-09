import {spawn} from 'node:child_process';

process.once('uncaughtException', error => {
  console.error(error.code === 'EADDRINUSE'
    ? 'Port 8787 is already in use. If ScamThreads Guard is already running, open http://127.0.0.1:8787/ directly.'
    : error.message);
  process.exitCode = 1;
});

const {server} = await import('./server.mjs');
server.once('listening', () => {
  const url = `http://127.0.0.1:${server.address().port}/`;
  const browser = spawn('cmd.exe', ['/d', '/c', 'start', '""', url], {windowsHide:true});
  browser.on('error', () => console.log('Open '+url+' in your browser.'));
});
