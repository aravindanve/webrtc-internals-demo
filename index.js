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
const stun = require('./stun');
const stunPacketPrettyPrint = require('./stunPacketPrettyPrint');
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
  .replace(/{ADDRESS}/g, config.rtpOptions.address)
  .replace(/{PORT}/g, config.rtpOptions.port)
  .replace(/{CERT_FINGERPRINT}/g, certFingerprint);

let producer;
let producerSession;
let producerMedia;
let producerMediaBySdpMid = {};
let producerMediaByUfrag = {};
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
  console.log('setProducerDescription()', sdp);

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
  localIcePwd = crypto.randomBytes(18).toString('base64');
  localIceKey = saslprep(localIcePwd);

  const localDescription = generateSdp(localIceUfrag, localIcePwd);

  console.log('SDP answer:\n', localDescription);

  producer.send(JSON.stringify({
    type: 'answer',
    sdp: localDescription
  }));
};

const addProducerCandidate = (candidate, sdpMid, sdpMLineIndex) => {
  console.log(
    'addProducerCandidate()',
    `sdpMid=${sdpMid} sdpMLineIndex=${sdpMLineIndex}`, candidate);

  if (!candidate) return;

  const { candidates: [parsed] } = SdpTransform.parse(`a=${candidate}`);

  if (sdpMLineIndex && producerMedia[sdpMLineIndex]) {
    producerMedia[sdpMLineIndex].candidates.push(parsed);

  } else if (sdpMid && producerMediaBySdpMid[sdpMid]) {
    producerMediaBySdpMid[sdpMid].candidates.push(parsed);

  } else {
    // do nothing
    console.warn(
      'no sdpMid or sdpMid matched for candidate',
      `sdpMid=${sdpMid} sdpMLineIndex=${sdpMLineIndex}`, candidate);
  }
};

const handleStunBindingRequest = (msg, rinfo) => {
  console.log('handleStunBindingRequest()', rinfo.port, rinfo.address);

  // debug
  console.log('L -> R ', '='.repeat(23));
  stunPacketPrettyPrint(msg, rinfo);

  const packet = new stun.ReadablePacket(msg);

  let ufrag; // [local, remote]
  let hashOffset;

  try {
    for (const {type, offset, length} of packet.attributes()) {
      switch (type) {
        case stun.AttributeType16.USERNAME:
          ufrag = msg.slice(offset, offset + length).toString().split(':');
          break;

        case stun.AttributeType16.MESSAGE_INTEGRITY:
          hashOffset = offset;
          break;
      }
    }

    // check username and message-integrity attribute set
    if (!ufrag || !hashOffset) {
      throw 400;
    }

    // validate remote ufrag
    if (!producerMediaByUfrag[ufrag[1]]) {
      throw 401;
    }

    // validate message integrity
    if (!localIceKey || !stun.checkMessageIntegrity(localIceKey, msg, hashOffset)) {
      throw 401;
    }

    // create binding success response
    const config = { key: localIceKey };
    const res = stun.createBindingSuccessResponse(msg, config, rinfo);

    // send binding success response
    udpSocket.send(res, rinfo.port, rinfo.address);

    // debug
    console.log('L <- R', '='.repeat(23));
    stunPacketPrettyPrint(res, rinfo);

  } catch (err) {
    console.log('ERROR processing binding request', err);

    const res = stun.createBindingErrorResponse(msg, err);

    udpSocket.send(res, rinfo.port, rinfo.address);

    // debug
    console.log('L <- R', '='.repeat(23));
    stunPacketPrettyPrint(res, rinfo);
  }
};

const handleUdpMessage = (msg, rinfo) => {
  console.log('handleUdpMessage()', rinfo);

  switch (msg.readUInt16BE(0, 2)) {
    case stun.MessageType16.BINDING_REQUEST:
      handleStunBindingRequest(msg, rinfo);
      break;

    case stun.MessageType16.BINDING_SUCCESS_RESPONSE:
      console.log('STUN Binding Success Response');
      console.log(hexy.hexy(msg, config.hexyFormat));
      break;

    case stun.MessageType16.BINDING_ERROR_RESPONSE:
      console.log('STUN Binding Error Response');
      console.log(hexy.hexy(msg, config.hexyFormat));
      break;

    // TODO: handle dtls handshake
    // TODO: handle rtp packets

    default:
      console.log('Unsupported udp message');
      console.log(hexy.hexy(msg, config.hexyFormat));
      break;
  }
};

const handleUdpError = (err) => {
  console.log('handleUdpError()', err);
};

function handleWsClose(e) {
  console.log('handleWsClose()');
}

function handleWsError(e) {
  console.log('handleWsError()');
}

function handleWsMessage(e) {
  console.log('handleWsMessage()');

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
