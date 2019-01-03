const hexy = require('hexy');
const stun = require('./stun');
const config = require('./config');

const msgType = [];
const attrType = [];

// pretty message types
msgType[stun.MessageType16.BINDING_REQUEST] = 'Binding Request';
msgType[stun.MessageType16.BINDING_SUCCESS_RESPONSE] = 'Binding Success Response';
msgType[stun.MessageType16.BINDING_ERROR_RESPONSE] = 'Binding Error Response';

// pretty attribute types
attrType[stun.AttributeType16.USERNAME] = {
  label: 'USERNAME',
  format: value => value.toString()
};

attrType[stun.AttributeType16.MESSAGE_INTEGRITY] = {
  label: 'MESSAGE-INTEGRITY',
  format: value => `0x${value.toString('hex')}`
};

attrType[stun.AttributeType16.ERROR_CODE] = {
  label: 'ERROR-CODE',
  format: value => value.toString()
};

attrType[stun.AttributeType16.UNKNOWN_ATTRIBUTES] = {
  label: 'UNKNOWN-ATTRIBUTES',
  format: value => value
};

attrType[stun.AttributeType16.XOR_MAPPED_ADDRESS] = {
  label: 'XOR-MAPPED-ADDRESS',
  format: value => `${[...value.slice(4)].join('.')}:${value.readUInt16BE(2)}`
};

attrType[stun.AttributeType16.PRIORITY] = {
  label: 'PRIORITY',
  format: value => value.readUInt32BE()
};

attrType[stun.AttributeType16.USE_CANDIDATE] = {
  label: 'USE-CANDIDATE',
  format: value => `0x${value.toString('hex')}`
};

attrType[stun.AttributeType16.FINGERPRINT] = {
  label: 'FINGERPRINT',
  format: value => `0x${value.toString('hex')}`
};

attrType[stun.AttributeType16.ICE_CONTROLLED] = {
  label: 'ICE-CONTROLLED',
  format: value => `0x${value.toString('hex')}`
};

attrType[stun.AttributeType16.ICE_CONTROLLING] = {
  label: 'ICE-CONTROLLING',
  format: value => `0x${value.toString('hex')}`
};

const packetPrettyPrint = (msg, rinfo) => {
  const packet = new stun.ReadablePacket(msg);

  try {
    console.log('STUN Packet:');
    console.log('-'.repeat(30));
    console.log('addr:', rinfo.address);
    console.log('port:', rinfo.port);
    console.log(
      'MESSAGE-TYPE',
      msgType[packet.messageType16] ||
        `0x${packet.messageType16.toString(16)}`);

    console.log(
      'MAGIC-COOKIE', `0x${packet.cookie32.toString(16)}`);

    console.log(
      'TRANSACTION-ID', `0x${packet.transactionIdX}`);

    for (const { type, offset, length } of packet.attributes()) {
      if (attrType[type]) {
        console.log(
          attrType[type].label,
          attrType[type].format(
            msg.slice(offset, offset + length)));

      } else {
        console.log(
          `UNKNOWN (0x${type.toString(16)})`,
          `0x${msg.slice(offset, offset + length).toString('hex')}`);
      }
    }
    console.log('-'.repeat(30));

  } catch (err) {
    console.log('ERROR pretty printing packet', err);
    console.log(hexy.hexy(msg, config.hexyFormat));
  }
};

module.exports = packetPrettyPrint;
