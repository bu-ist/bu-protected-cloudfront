'use strict'

const { imageSizeModifyRequest } = require('./imageResize/imageSizeModifyRequest');
const { deniedResponse } = require('./authorizeRequest/deniedResponse');
const { authorizeRequest } = require('./authorizeRequest/authorizeRequest');

const UriToS3Key = async event => {
  const { request, request: { headers, querystring, uri } } = event.Records[0].cf


  // Apply access control.
  const allowed = await authorizeRequest(uri, headers);
  if (!allowed) {
    return deniedResponse;
  }

  // Get the key for the potentially resized image.
  const modifiedRequest = imageSizeModifyRequest(request);

  return modifiedRequest;
}

module.exports = UriToS3Key
