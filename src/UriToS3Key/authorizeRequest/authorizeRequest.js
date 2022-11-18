const { DynamoDB } = require('aws-sdk');

async function authorizeRequest(uri, headers) {
  const dynamoDb = new DynamoDB.DocumentClient();

  if  (!uri.includes('__restricted')) {
    // Unrestricted items are always allowed.
    return true;
  }

  //const allowed = await checkPermissionFromAuthServer(uri, headers);

  // Get the group name from the uri, it is the segment after the "/__restricted/" segment.
  const pathSegments = uri.split('/');
  const groupName = pathSegments[pathSegments.indexOf('__restricted') + 1];

  // Special handling for the entire-bu-community group, which only requires a valid BU login.
  if (groupName === 'entire-bu-community') {
    // This should be more elegant, but it checks for a non-empty shibboleth username header.
    return ('x-bu-shib-username' in headers) && headers['x-bu-shib-username'][0].value !== '';
  }

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
  const { users = [], states: affiliations = [], entitlements = [] } = JSON.parse(Item.rules);

  // Apply the rules.
  const allowed = checkUserAccess(users, affiliations, entitlements, headers);

  return allowed;
}

function checkUserAccess(users, affiliations, entitlements, headers) {
  // Get the username from the headers.
  let userName = '';
  if ('x-bu-shib-username' in headers) {
    userName = headers['x-bu-shib-username'][0].value;
  }

  let userAffiliation = '';
  if ('x-bu-shib-primary-affiliation' in headers) {
    userAffiliation = headers['x-bu-shib-primary-affiliation'][0].value;
  }

  let userEntitlements = [];
  if ('x-bu-shib-entitlement' in headers) {
    userEntitlements = headers['x-bu-shib-entitlement'][0].value.split(';');
  }

  // If the user is in the list of users, allow access
  const userAllowed = users.includes(userName);

  // If the user is in the list of affiliations, allow access
  const affiliationAllowed = affiliations.includes(userAffiliation);

  // Check entitlements.
  const entitlementsIntersection = entitlements.filter(x => userEntitlements.includes(x));
  const entitlementsAllowed = entitlementsIntersection.length > 0;

  // If the user is allowed by user list, status, or entitlement, allow return true to allow the request.
  return userAllowed || affiliationAllowed || entitlementsAllowed;
}


module.exports = { authorizeRequest };