const WebSocket = require('ws').Server;
const wss = new WebSocket({ port: 9000 });

let producer;
let consumer;

wss.on('connection', ws => {
  console.log('wss/connection');

  ws.onmessage = e => {
    console.log('ws/message');
    switch (ws) {
      case producer:
        if (!consumer) return console.log('No Consumer');
        consumer.send(e.data);
        return;

      case consumer:
        if (!producer) return console.log('No Producer');
        producer.send(e.data);
        return;
    }

    const data = JSON.parse(e.data);

    switch (data.type) {
      case 'consumer':
        consumer = ws;
        break;

      case 'producer':
        producer = ws;
        break;

      default:
        console.log('Invalid message', data);
    }
  };
});
