module.exports = {
  wssOptions: {
    host: '127.0.0.1',
    port: 9000
  },
  rtpOptions: {
    host: '127.0.0.1',
    port: 9001
  },
  tlsCertFile: './tls/cert.pem',
  tlsKeyFile: './tls/key.pem',
  sdpTemplateFile: './sdp.txt',
  hexyFormat: {
    width: 4,
    numbering: 'hex_bytes',
    format: 'twos',
    caps: 'lower'
  }
};
