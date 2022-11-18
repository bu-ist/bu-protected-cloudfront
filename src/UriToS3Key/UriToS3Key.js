'use strict'

const { DynamoDB } = require('aws-sdk');
const { parse } = require('querystring')

const DEFAULT_EXTENSION = 'webp'
const BAD_JPG_EXTENSION = 'jpg'
const GOOD_JPG_EXTENSION = 'jpeg'

const UriToS3Key = async event => {
  const { request, request: { headers, querystring, uri } } = event.Records[0].cf
  const { h: height = '', w: width } = parse(querystring)

  // Apply access control.
  const allowed = await checkPermission(uri, headers);
  if (!allowed) {
    return deniedResponse;
  }

  if (!width || isNaN(parseInt(width, 10))) return request

  const [,prefix, imageName, prevExtension] = uri.match(/(.*)\/(.*)\.(\w*)/)
  const acceptHeader = Array.isArray(headers.accept)
    ? headers.accept[0].value
    : ''
  const nextExtension = acceptHeader.indexOf(DEFAULT_EXTENSION) !== -1
    ? DEFAULT_EXTENSION
    : prevExtension === BAD_JPG_EXTENSION
      ? GOOD_JPG_EXTENSION
      : prevExtension.toLowerCase()
  const dimensions = height
    ? `${width}x${height}`
    : width
  const key = `${prefix}/${dimensions}/${imageName}.${nextExtension}`

  request.uri = key
  request.querystring = [
    `nextExtension=${nextExtension}`,
    `height=${height}`,
    `sourceImage=${prefix}/${imageName}.${prevExtension}`,
    `width=${width}`
  ].join('&')

  return request
}

async function checkPermission(uri, headers) {
  const dynamoDb = new DynamoDB.DocumentClient();

  if  (!uri.includes('__restricted')) {
    // Unrestricted items are always allowed.
    return true;
  }

  // Get the username from the headers.
  let userName = '';
  if ('x-bu-shib-username' in headers) {
    userName = headers['x-bu-shib-username'][0].value;
  }

  //const allowed = await checkPermissionFromAuthServer(uri, headers);

  // Get the group name from the uri, it is the segment after the "/__restricted/" segment.
  const pathSegments = uri.split('/');
  const groupName = pathSegments[pathSegments.indexOf('__restricted') + 1];


  // Get the associated group rules from DynamoDB.
  const { Item } = await dynamoDb.get({
    TableName: 'BU-AccessControl', 
    Key: { SiteAndGroupKey: groupName } }
  ).promise();

  // Parse the rules.
  const { users } = JSON.parse(Item.rules);

  // Apply the rules.
  const allowed = users.includes(userName);

  return allowed;
}

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

module.exports = UriToS3Key
