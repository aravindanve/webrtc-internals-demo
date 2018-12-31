const fs = require('fs');
const path = require('path');
const dgram = require('dgram');
const crypto = require('crypto');
const sshpk = require('sshpk');
const WebSocket = require('ws').Server;
const SdpTransform = require('sdp-transform');
const saslprep = require('saslprep');
const hexy = require('hexy');
const config = require('./config');
const udpSocket = dgram.createSocket('udp4');
const wss = new WebSocket(config.wssOptions);
const tlsCert = fs.readFileSync(path.resolve(config.tlsCertFile));
// const tlsKey = fs.readFileSync(path.resolve(config.tlsKeyFile));

const certFingerprint = sshpk
  .parseCertificate(tlsCert, 'pem')
  .fingerprint('sha256')
  .toString('hex');

const sdpTemplate = fs.readFileSync(path.resolve(config.sdpTemplateFile))
  .toString()
  .replace(/{HOST}/g, config.rtpOptions.host)
  .replace(/{PORT}/g, config.rtpOptions.port)
  .replace(/{CERT_FINGERPRINT}/g, certFingerprint);

let producer;
let producerSession;
let producerMedia;
let producerMediaBySdpMid;
let producerMediaByUfrag;
let localIceUfrag;
let localIcePwd;
let localIceKey;

const generateSdp = (ufrag, pwd) => {
  console.log('generateSdp()', ufrag, pwd);

  return sdpTemplate
    .replace(/{ICE_UFRAG}/g, ufrag)
    .replace(/{ICE_PWD}/g, pwd);
};

const setProducerDescription = sdp => {
  console.log('setProducerDescription()');

  const { media, ...session } = SdpTransform.parse(sdp);

  producerSession = session;
  producerMedia = media;
  producerMediaBySdpMid = {};
  producerMediaByUfrag = {};

  for (const desc of producerMedia) {
    desc.iceKey = saslprep(desc.icePwd);
    desc.candidates = [];

    producerMediaBySdpMid[desc.mid] = desc;
    producerMediaByUfrag[desc.iceUfrag] = desc;
  }

  localIceUfrag = crypto.randomBytes(3).toString('base64');
  localIcePwd = crypto.randomBytes(16).toString('base64');
  localIceKey = saslprep(localIcePwd);

  const localDescription = generateSdp(localIceUfrag, localIcePwd);

  console.log('SDP:\n', localDescription);

  producer.send(JSON.stringify({
    type: 'answer',
    sdp: localDescription
  }));
};

const addProducerCandidate = (candidate, sdpMid, sdpMLineIndex) => {
  console.log('addProducerCandidate()');

  if (!(candidate && candidate.candidate)) return;

  const parsed = SdpTransform.parse(`a=${candidate}`);

  if (sdpMLineIndex && producerMedia[sdpMLineIndex]) {
    producerMedia[sdpMLineIndex].candidates.push(parsed);

  } else if (sdpMid && producerMediaBySdpMid[sdpMid]) {
    producerMediaBySdpMid[sdpMid].candidates.push(parsed);

  } else {
    // do nothing
  }
};

const stunAttributeType = {
  [0x0006]: ['USERNAME', buf => buf.toString()],
  [0x0008]: ['MESSAGE-INTEGRITY', buf => buf.toString('hex')],
  [0x0009]: ['ERROR-CODE', buf => buf.toString()],
  [0x0024]: ['PRIORITY', buf => buf.readUInt32BE()],
  [0x0025]: ['USE-CANDIDATE', buf => buf.toString()],
  [0x8028]: ['FINGERPRINT', buf => buf.toString('hex')],
  [0x8029]: ['ICE-CONTROLLED', buf => buf.readUInt32BE()],
  [0x802a]: ['ICE-CONTROLLING', buf => buf.readUInt32BE()]
};

const prettyPrintStunPacket = (buf, computedHash) => {
  const first16bits = buf[0].toString(2).padStart(8, 0)
    + buf[1].toString(2).padStart(8, 0);

  const attrs = buf.slice(20);

  console.log('\nSTUN Packet:');
  console.log(`Zero-Bits: 0b${first16bits.slice(0, 2)}`);
  console.log(`Message-Type: 0b${first16bits.slice(2, 16)}`);
  console.log(`Message-Length: ${buf.readUInt16BE(2, 4)}`);
  console.log(`Magic-Cookie: 0x${buf.readUInt32BE(4, 8).toString(16)}`);
  console.log(`Transaction-ID: ${buf.slice(8, 20).toString('base64')}`);
  console.log('\n');
  console.log(hexy.hexy(attrs, config.hexyFormat));
  console.log('\n');

  let offset = 20;

  while (offset < buf.length) {
    const type = buf.readUInt16BE(offset, offset += 2) + '';
    const length = buf.readUInt16BE(offset, offset += 2);
    const value = buf.slice(offset, offset += length);
    const rem = length % 4;

    // offset padding
    if (rem) offset += 4 - rem;

    if (stunAttributeType[type]) {
      console.log(
        stunAttributeType[type][0],
        stunAttributeType[type][1](value));

    } else {
      console.log(`UNKNOWN (0x${(+type).toString(16)})`, value);
    }
  }

  if (computedHash) {
    console.log(`\nCOMPUTED-INTEGRITY`, computedHash);
  }

  console.log('\n---');
};

const handleStunRequest = (req, rinfo) => {
  console.log('handleStunRequest()', rinfo);

  let offset = 20;
  let ufrag; // [local, remote]
  let ipos;
  let ihash;

  try {
    while (offset < req.length) {
      const type = req.readUInt16BE(offset, offset += 2) + '';
      const length = req.readUInt16BE(offset, offset += 2);
      const value = req.slice(offset, offset += length);
      const rem = length % 4;

      // offset padding
      if (rem) offset += 4 - rem;

      switch (type) {
        case 0x0006 + '':
          ufrag = value.toString().split(':');
          break;

        case 0x0008 + '':
          ipos = offset - 24; // tl(4) + hash(20)
          ihash = value.toString('hex');
          break;

        default:
          break;
      }
    }

    if (!(ufrag && ipos)) {
      throw 'username or message-integrity attribute not set';
    }

    // validate message integrity
    const ireq = req.slice(0, ipos);
    const ilen = new Buffer(2);

    ilen.writeUInt16BE(ipos + 4); // ipos + tl(4) + hash(20) - header(20)

    // sub message length without fingerprint attribute
    ireq[2] = ilen[0];
    ireq[3] = ilen[1];

    const computedHash = crypto
      .createHmac('sha1', localIceKey)
      .update(ireq)
      .digest('hex');

    if (computedHash !== ihash) {
      throw 'message integrity validation failed';
    }

    udpSocket.send(req, rinfo.port, rinfo.address); // fix

    console.log('SUCCESS');
    console.log('-'.repeat(6));
    prettyPrintStunPacket(req, computedHash);

  } catch (err) {
    console.log('ERROR:', err);
    console.log('-'.repeat(6));
    prettyPrintStunPacket(req);
  }
};

const handleUdpMessage = (msg, rinfo) => {
  console.log('handleUdpMessage()', rinfo);

  switch (msg.readUInt16BE(0, 2)) {
    // stun binding request
    case 1:
      handleStunRequest(msg, rinfo);
      break;

    default:
      console.log('Unsupported udp message');
      break;
  }
};

const handleUdpError = (err) => {
  console.log('handleUdpError()', err);
};

function handleWsClose(e) {
  console.log('handleWsClose()', e.target.id);
}

function handleWsError(e) {
  console.log('handleWsError()', e.target.id);
}

function handleWsMessage(e) {
  console.log('handleWsMessage()', e.target.id);

  const { type, ...data } = JSON.parse(e.data);

  switch (type) {
    case 'offer':
      setProducerDescription(data.sdp);
      break;

    case 'candidate':
      addProducerCandidate(
        data.candidate,
        data.sdpMid,
        data.sdpMLineIndex);
      break;

    default:
      console.warn(`Unknown message ${data.type}`);
      break;
  }
}

const handleWssConnection = ws => {
  if (producer) {
    ws.send(JSON.stringify({
      type: 'error',
      message: 'producer already exists'
    }));
    ws.close();
    return;
  }

  ws.onclose = handleWsClose;
  ws.onerror = handleWsError;
  ws.onmessage = handleWsMessage;

  // set producer
  producer = ws;
};

wss.on('connection', handleWssConnection);
udpSocket.on('message', handleUdpMessage);
udpSocket.on('error', handleUdpError);

udpSocket.bind(config.rtpOptions, () =>
  console.log('udp socket bound'));
