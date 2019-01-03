const crypto = require('crypto');
const crc32 = require('buffer-crc32');
const saslprep = require('saslprep');

const MAGIC_COOKIE_32 = 0x2112a442;

const MessageType16 = {
  BINDING_REQUEST: 0x0001,
  BINDING_SUCCESS_RESPONSE: 0x0101,
  BINDING_ERROR_RESPONSE: 0x0111
};

const AttributeType16 = {
  USERNAME: 0x0006,
  MESSAGE_INTEGRITY: 0x0008,
  ERROR_CODE: 0x0009,
  UNKNOWN_ATTRIBUTES: 0x000a,
  XOR_MAPPED_ADDRESS: 0x0020,
  PRIORITY: 0x0024,
  USE_CANDIDATE: 0x0025,
  FINGERPRINT: 0x8028,
  ICE_CONTROLLED: 0x8029,
  ICE_CONTROLLING: 0x802a
};

class Packet {
  static readMessageType16(msg) {
    return msg.readUInt16BE(0);
  }

  static readMessageLength16(msg) {
    return msg.readUInt16BE(2);
  }

  static readCookie32(msg) {
    return msg.readUInt32BE(4);
  }

  static readTransactionId(msg) {
    return msg.slice(8, 20);
  }

  static readTransactionIdX(msg) {
    return Packet.readTransactionId(msg).toString('hex');
  }
}

class ReadablePacket {
  constructor(msg) {
    this.msg = msg;
  }

  get buffer() {
    return this.msg;
  }

  get length() {
    this.msg.length;
  }

  get messageType16() {
    return Packet.readMessageType16(this.msg);
  }

  get messageLength16() {
    return Packet.readMessageLength16(this.msg);
  }

  get cookie32() {
    return Packet.readCookie32(this.msg);
  }

  get transactionId() {
    return Packet.readTransactionId(this.msg);
  }

  get transactionIdX() {
    return Packet.readTransactionIdX(this.msg);
  }

  *attributes() {
    let offset = 20;
    let remainder;

    while (offset < this.msg.length) {
      const type = this.msg.readUInt16BE(offset);
      const length = this.msg.readUInt16BE(offset += 2);

      offset += 2;

      yield { type, length, offset };

      offset += length;

      if (remainder = length % 4) {
        offset += 4 - remainder;
      }
    }
  }
}

function lvString(value, encoding = 'utf8') {
  const length = Buffer.byteLength(value, encoding);
  const remainder = length % 4;
  const padding = remainder ? 4 - remainder : 0;
  const lenBuffer = Buffer.allocUnsafe(2);
  const valBuffer = Buffer.alloc(length + padding);

  lenBuffer.writeUInt16BE(length);
  valBuffer.write(value, encoding);

  return [lenBuffer, valBuffer];
}

function lvErrorCode(code) {
  let lenBuffer;
  let valBuffer;

  switch (+code) {
    case 400:
      valBuffer = Buffer.from([
        0b0000, 0x00,           // 16bits: reserved
        0b0100, 0x00,           // 5bits: reserved; 3bits: 4; 8bits: 0

        0x42, 0x61, 0x64, 0x20,
        0x52, 0x65, 0x71, 0x75,
        0x65, 0x73, 0x74, 0x00  // 11b: 'Bad Request'; 1b: padding
      ]);
      lenBuffer = Buffer.from([
        0x00, 0x0f              // 16bits: 15
      ]);
      break;

    case 401:
      valBuffer = Buffer.from([
        0b0000, 0x00,           // 16bits: reserved
        0b0100, 0x01,           // 5bits: reserved; 3bits: 4; 8bits: 1

        0x55, 0x6e, 0x61, 0x75,
        0x74, 0x68, 0x6f, 0x72,
        0x69, 0x7a, 0x65, 0x64  // 12b: 'Unauthorized'
      ]);
      lenBuffer = Buffer.from([
        0x00, 0x10              // 16bits: 16
      ]);
      break;

    default:
      valBuffer = Buffer.from([
        0b0000, 0x00,           // 16bits: reserved
        0b0101, 0x00,           // 5bits: reserved; 3bits: 5; 8bits: 0

        0x53, 0x65, 0x72, 0x76,
        0x65, 0x72, 0x20, 0x45,
        0x72, 0x72, 0x6f, 0x72 // 12b: 'Server Error'
      ]);
      lenBuffer = Buffer.from([
        0x00, 0x10              // 16bits: 16
      ]);
      break;
  }

  return [lenBuffer, valBuffer];
}

const magicCookieOctets = Uint8Array.from([
  0x21, 0x12, 0xa4, 0x42
]);

function lvXorMappedAddress(transactionId, rinfo) {
  // TODO: handle abbreviated ipv6 addresses such as ::1
  const addr = rinfo.address.split(/\.|:/);
  const portBuffer = Buffer.allocUnsafe(2);
  const lenBuffer = Buffer.allocUnsafe(2);

  // xPort is port XOR'd with the most
  // significant 16bits of the magic cookie
  const xPort = parseInt(rinfo.port) ^ 0x2112;

  let famlBuffer;
  let addrBuffer;

  // write x-port
  portBuffer.writeUInt16BE(xPort);

  if (addr.length === 4) {
    famlBuffer = Buffer.from([0x00, 0x01]); // ipv4
    addrBuffer = Buffer.allocUnsafe(4);

    // write length
    // 1 (reserved) + 1 (family) + 2 (port) + 4 (addr)
    lenBuffer.writeUInt16BE(8);

    // write x-addr
    for (let i = 0; i < 4; i++) {
      const part = parseInt(addr[i]);

      // xPart is part XOR'd with the
      // magic cookie octet at offset
      const xPart = part ^ magicCookieOctets[i];

      addrBuffer.writeUInt8(xPart, i);
    }

  } else {
    famlBuffer = Buffer.from([0x00, 0x02]); // ipv6
    addrBuffer = Buffer.allocUnsafe(16);

    // write length
    // 1 (reserved) + 1 (family) + 2 (port) + 16 (addr)
    lenBuffer.writeUInt16BE(20);

    // xorOperand is the magic cookie concated with transactionId
    const xorOperand = Buffer.concat([magicCookieOctets, transactionId]);

    for (let i = 0; i < 8; i++) {
      const part = parseInt(addr[i], 16);

      // xPart is part XOR'd with the
      // xorOperand hextet at offset
      const xPart = part ^ xorOperand.readUInt16BE(i * 2);

      addrBuffer.writeUInt16BE(xPart, i * 2);
    }
  }

  return [lenBuffer, Buffer.concat([
    famlBuffer,
    portBuffer,
    addrBuffer
  ])];
}

// warning: mutates original msg if end not provided
function getMsgHash(key, msg, end) {
  msg = end ? msg.slice(0, end) : msg;

  // write msg length
  // length = length - 20 (header) + 24 (attribute)
  msg.writeUInt16BE(msg.length + 4, 2);

  return crypto
    .createHmac('sha1', key)
    .update(msg)
    .digest();
}

function checkMessageIntegrity(key, msg, start) {
  const msgHash = msg.slice(start, start + 20); // slice 20b from start of hash
  const computedHash = getMsgHash(key, msg, start - 4);
  // ^ compute hash for message from 0 to start - 4b (start of message-integrity)

  return msgHash.toString() === computedHash.toString();
}

// warning: mutates original msg if end not provided
function getMsgCrc32(msg, end) {
  const buf = Buffer.allocUnsafe(4);

  msg = end ? msg.slice(0, end) : msg;

  // write msg length
  // length = length - 20 (header) + 8 (attribute)
  msg.writeUInt16BE(msg.length - 12, 2);

  // debug:
  // console.log('CRC-32', crc32.unsigned(msg));
  // console.log('CRC-32 ^ 0x5354554e', crc32.unsigned(msg) ^ 0x5354554e);
  // console.log('CRC-32 ^ 0x5354554e UInt32', (crc32.unsigned(msg) ^ 0x5354554e) >>> 0);

  // write CRC-32 XOR'ed with 0x5354554e
  buf.writeUInt32BE((crc32.unsigned(msg) ^ 0x5354554e) >>> 0);

  return buf;
}

function createBindingRequest(config) {
  const transactionId = crypto.randomBytes(12);
  const key = config.key || saslprep(config.password);
  const [usernameLength, usernamePadded] = lvString(config.username);

  let msg = Buffer.from([
    0x00, 0x01,             // 16bits, message type: binding request
    0x00, 0x00,             // 16bits, message length
    0x21, 0x12, 0xa4, 0x42, // 32bits, magic cookie
    ...transactionId,       // 96bits, transaction id

    0x00, 0x06,             // 16bits, attribute type: username
    ...usernameLength,      // 16bits, attribute length
    ...usernamePadded,      // ......, attribute value

    0x80, 0x29,             // 16bits, attribute type: ice-controlled
    0x00, 0x08,             // 16bits, attribute length: 8
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01, // 64bits, attribute value: tie-breaker

    0x00, 0x24,             // 16bits, attribute type: priority
    0x00, 0x04,             // 16bits, attribute length: 4
    0x7e, 0xff, 0xff, 0xff, // 32bits, attribute value: 2130706431
  ]);

  // write message integrity
  msg = Buffer.concat([msg, Buffer.from([
    0x00, 0x08,             //  16bits, attribute type: message-integrity
    0x00, 0x14,             //  16bits, attribute length: 20
    ...getMsgHash(key, msg) // 160bits, attribute value
  ])]);

  // write fingerprint
  msg = Buffer.concat([msg, Buffer.from([
    0x80, 0x28,             // 16bits, attribute type: fingerprint
    0x00, 0x04,             // 16bits, attribute length: 4
    ...getMsgCrc32(msg)     // 32bits, attribute value
  ])]);

  // write final msg length - redundant?
  msg.writeUInt16BE(msg.length - 20, 2);

  return msg;
}

function createBindingSuccessResponse(req, config, rinfo) {
  const transactionId = req.slice(8, 20);
  const key = config.key || saslprep(config.password);
  const [xorMappedAddrLength, xorMappedAddr] =
    lvXorMappedAddress(transactionId, rinfo);

  let msg = Buffer.from([
    0x01, 0x01,             // 16bits, message type: binding success response
    0x00, 0x00,             // 16bits, message length
    0x21, 0x12, 0xa4, 0x42, // 32bits, magic cookie
    ...transactionId,       // 96bits, transaction id

    0x00, 0x20,             // 16bits, attribute type: xor-mapped-address
    ...xorMappedAddrLength, // 16bits, attribute length
    ...xorMappedAddr        // 64bits, attribute value
  ]);

  // write message integrity
  msg = Buffer.concat([msg, Buffer.from([
    0x00, 0x08,             //  16bits, attribute type: message-integrity
    0x00, 0x14,             //  16bits, attribute length: 20
    ...getMsgHash(key, msg) // 160bits, attribute value
  ])]);

  // write fingerprint
  msg = Buffer.concat([msg, Buffer.from([
    0x80, 0x28,             // 16bits, attribute type: fingerprint
    0x00, 0x04,             // 16bits, attribute length: 4
    ...getMsgCrc32(msg)     // 32bits, attribute value
  ])]);

  // write final msg length - redundant?
  msg.writeUInt16BE(msg.length - 20, 2);

  return msg;
}

function createBindingErrorResponse(req, code) {
  const transactionId = req.slice(8, 20);
  const [errorCodeLength, errorCode] = lvErrorCode(code);

  let msg = Buffer.from([
    0x01, 0x11,             // 16bits, message type: binding error response
    0x00, 0x00,             // 16bits, message length
    0x21, 0x12, 0xa4, 0x42, // 32bits, magic cookie
    ...transactionId,       // 96bits, transaction id

    0x00, 0x09,             // 16bits, attribute type: error-code
    ...errorCodeLength,     // 16bits, attribute length
    ...errorCode            // ......, attribute value
  ]);

  // NOTE: a server MUST NOT include a MESSAGE-INTEGRITY
  // or USERNAME attribute in the error response. see:
  // https://tools.ietf.org/html/rfc5389#section-10.1.2

  // write fingerprint
  msg = Buffer.concat([msg, Buffer.from([
    0x80, 0x28,             // 16bits, attribute type: fingerprint
    0x00, 0x04,             // 16bits, attribute length: 4
    ...getMsgCrc32(msg)     // 32bits, attribute value
  ])]);

  // write final msg length - redundant?
  msg.writeUInt16BE(msg.length - 20, 2);

  return msg;
}

module.exports = {
  MAGIC_COOKIE_32,
  MessageType16,
  AttributeType16,
  Packet,
  ReadablePacket,
  createBindingRequest,
  createBindingSuccessResponse,
  createBindingErrorResponse,
  checkMessageIntegrity
};
