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

  console.log('SDP:\n', localDescription);

  producer.send(JSON.stringify({
    type: 'answer',
    sdp: localDescription
  }));
};

const addProducerCandidate = (candidate, sdpMid, sdpMLineIndex) => {
  console.log('addProducerCandidate()');

  if (!candidate) return;

  const { candidates: [parsed] } = SdpTransform.parse(`a=${candidate}`);

  if (sdpMLineIndex && producerMedia[sdpMLineIndex]) {
    console.log('sdpMLineIndex matched for candidate', sdpMLineIndex, parsed);
    producerMedia[sdpMLineIndex].candidates.push(parsed);

  } else if (sdpMid && producerMediaBySdpMid[sdpMid]) {
    console.log('sdpMid matched for candidate', sdpMid, parsed);
    producerMediaBySdpMid[sdpMid].candidates.push(parsed);

  } else {
    // do nothing
    console.log('No sdpMid or sdpMid matched for candidate', parsed);
  }
};

const prettyStunMsg = [];
prettyStunMsg[stun.MessageType16.BINDING_REQUEST] = 'Binding Request';
prettyStunMsg[stun.MessageType16.BINDING_SUCCESS_RESPONSE] = 'Binding Success Response';
prettyStunMsg[stun.MessageType16.BINDING_ERROR_RESPONSE] = 'Binding Error Response';

const prettyStunAttr = [];
prettyStunAttr[stun.AttributeType16.USERNAME] = {
  label: 'USERNAME', format: value => value.toString() };
prettyStunAttr[stun.AttributeType16.MESSAGE_INTEGRITY] = {
  label: 'MESSAGE-INTEGRITY', format: value => `0x${value.toString('hex')}` };
prettyStunAttr[stun.AttributeType16.ERROR_CODE] = {
  label: 'ERROR-CODE', format: value => value.toString() };
prettyStunAttr[stun.AttributeType16.UNKNOWN_ATTRIBUTES] = {
  label: 'UNKNOWN-ATTRIBUTES', format: value => value };
prettyStunAttr[stun.AttributeType16.XOR_MAPPED_ADDRESS] = {
  label: 'XOR-MAPPED-ADDRESS', format: value => `${[...value.slice(4)].join('.')}:${value.readUInt16BE(2)}` };
prettyStunAttr[stun.AttributeType16.PRIORITY] = {
  label: 'PRIORITY', format: value => value.readUInt32BE() };
prettyStunAttr[stun.AttributeType16.USE_CANDIDATE] = {
  label: 'USE-CANDIDATE', format: value => `0x${value.toString('hex')}` };
prettyStunAttr[stun.AttributeType16.FINGERPRINT] = {
  label: 'FINGERPRINT', format: value => `0x${value.toString('hex')}` };
prettyStunAttr[stun.AttributeType16.ICE_CONTROLLED] = {
  label: 'ICE-CONTROLLED', format: value => `0x${value.toString('hex')}` };
prettyStunAttr[stun.AttributeType16.ICE_CONTROLLING] = {
  label: 'ICE-CONTROLLING', format: value => `0x${value.toString('hex')}` };

const prettyPrintStunPacket = (msg, rinfo) => {
  const packet = new stun.ReadablePacket(msg);

  try {
    console.log('STUN Packet:');
    console.log('-'.repeat(30));
    console.log('addr:', rinfo.address);
    console.log('port:', rinfo.port);
    console.log(
      'MESSAGE-TYPE',
      prettyStunMsg[packet.messageType16] ||
        `0x${packet.messageType16.toString(16)}`);
    console.log(
      'MAGIC-COOKIE', `0x${packet.cookie32.toString(16)}`);
    console.log(
      'TRANSACTION-ID', `0x${packet.transactionIdX}`);

    for (const { type, offset, length } of packet.attributes()) {
      if (prettyStunAttr[type]) {
        console.log(
          prettyStunAttr[type].label,
          prettyStunAttr[type].format(
            msg.slice(offset, offset + length)));

      } else {
        console.log(
          `UNKNOWN (0x${type.toString(16)})`,
          `0x${msg.slice(offset, offset + length).toString('hex')}`);
      }
    }
    console.log('-'.repeat(30));

    for (const { type } of packet.attributes()) {
      if (type === stun.AttributeType16.USE_CANDIDATE) {
        process.exit(0); // fix
      }
    }

  } catch (err) {
    console.log('ERROR pretty printing packet', err);
    console.log(hexy.hexy(msg, config.hexyFormat));
  }
};

const handleStunBindingRequest = (msg, rinfo) => {
  console.log('handleStunBindingRequest()', rinfo.port, rinfo.address);

  // debug
  console.log('L -> R ', '='.repeat(23));
  prettyPrintStunPacket(msg, rinfo);

  const packet = new stun.ReadablePacket(msg);

  let ufrag; // `local:remote`
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
    if (!localIceKey || !stun.checkMessageIntegrity(msg, localIceKey, hashOffset)) {
      throw 401;
    }

    // create binding success response
    const config = { key: localIceKey };
    console.log('HERE1', localIceKey, producerMediaByUfrag[ufrag[1]].iceKey);
    const res = stun.createBindingSuccessResponse(msg, config, rinfo);

    // send binding success response
    udpSocket.send(res, rinfo.port, rinfo.address);

    // debug
    console.log('L <- R ', '='.repeat(23));
    prettyPrintStunPacket(res, rinfo);

  } catch (err) {
    console.log('ERROR processing binding request', err);

    const res = stun.createBindingErrorResponse(msg, err);

    udpSocket.send(res, rinfo.port, rinfo.address);

    // debug
    console.log('L <- R ', '='.repeat(23));
    prettyPrintStunPacket(res, rinfo);
  }
};

const handleUdpMessage = (msg, rinfo) => {
  console.log('handleUdpMessage()', rinfo);

  switch (msg.readUInt16BE(0, 2)) {
    case stun.MessageType16.BINDING_REQUEST:
      handleStunBindingRequest(msg, rinfo);
      break;

    case stun.MessageType16.BINDING_SUCCESS_RESPONSE:
      console.log('STUN Binding Error Response');
      console.log(hexy.hexy(msg, config.hexyFormat));
      process.exit(0);
      break;

    case stun.MessageType16.BINDING_ERROR_RESPONSE:
      console.log('STUN Binding Error Response');
      console.log(hexy.hexy(msg, config.hexyFormat));
      process.exit(0);
      break;

    default:
      console.log('Unsupported udp message');
      console.log(hexy.hexy(msg, config.hexyFormat));
      process.exit(0);
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
