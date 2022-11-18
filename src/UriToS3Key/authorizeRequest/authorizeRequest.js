const { DynamoDB } = require('aws-sdk');

async function authorizeRequest(uri, headers) {
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
  
    if (Item == null) {
      // If the group rules are not found, log the error then deny access.
      console.log('Failed to find the group rules in DynamoDB.');
      return false;
    }
  
    // Parse the rules.
    const { users } = JSON.parse(Item.rules);
  
    // Apply the rules.
    const allowed = users.includes(userName);
  
    return allowed;
  }
  
  module.exports = { authorizeRequest };