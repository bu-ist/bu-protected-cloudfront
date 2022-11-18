// A static response to return for denied requests.
const deniedResponse = {
  body: 'Access denied',
  bodyEncoding: 'text',
  headers: {
      'cache-control': [{
          key: 'Cache-Control',
          value: 'no-cache'
       }],
  },
  status: '401',
  statusDescription: 'Unauthorized'
};

module.exports = { deniedResponse };
