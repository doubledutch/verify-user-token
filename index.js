var RSA = require('node-rsa');

var publicKeyBase64 = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnqCN6WNflUHWV11Kn/es Wa8mAiU75rv2TfJmS3EADny0h4duBobHhj4CsPsMOsVrubDL3wMEtN3/oyS7Iw1f nOXUxp/woN1G+Es+5gSOgMea4o4JSpbyDWD5dL58eAs9mxnT8n/035peMHr+7Um9 xZLG2pBuFrOi3IVcAa4iWrX2tx1XKUgi+5UnncB3jYRh70VhcnRVFM8xmavUpTZ5 LvIBxiFqiBe9TGTkLjvm7VqyCjIcjop7rPc2xYSehSBjp7vus8eI/9oW7JcsxGAu RNKxFA7deJ8zNWCr4h8uT3I5RNnh+7jXqQso2oOVIY5hSunDlT0rB9kgjava1QDY EQIDAQAB'
var publicKeyData = '-----BEGIN PUBLIC KEY-----\n' +
publicKeyBase64 +
+ '\n-----END PUBLIC KEY-----';

var publicKey = new RSA(publicKeyData, 'public');

var token = 'eyJEYXRhIjp7IklkIjoxNDMsIlVwZGF0ZWQiOiIyMDE1LTA2LTA0VDE5OjU3OjI5LjczN1oiLCJFbWFpbEFkZHJlc3MiOiJ1bml0KzI1MTdAdGVzdC5jb20iLCJGaXJzdE5hbWUiOiIiLCJMYXN0TmFtZSI6IiIsIkltYWdlVXJsIjoiaHR0cDovL3NuLmQyLnZjL2RlZmF1bHQvbm9mYWNlXzExMC5qcGciLCJDb21wYW55IjoiIiwiVXNlck5hbWUiOiJ1bml0KzI1MTdAdGVzdC5jb20iLCJGYWNlYm9va1VzZXJJZCI6bnVsbCwiVHdpdHRlclVzZXJOYW1lIjpudWxsLCJMaW5rZWRJbklkIjpudWxsLCJJc09BdXRoQ29ubmVjdGVkVG9GYWNlYm9vayI6ZmFsc2UsIklzT0F1dGhDb25uZWN0ZWRUb1R3aXR0ZXIiOmZhbHNlLCJJc09BdXRoQ29ubmVjdGVkVG9MaW5rZWRJbiI6ZmFsc2UsIkFsbG93TWVzc2FnaW5nIjp0cnVlLCJVc2VySWRlbnRpZmllcklkIjoidGVzdCIsIklzRXhoaWJpdG9yIjpmYWxzZSwiU2NvcmUiOjAsIlVzZXJHcm91cHMiOltdfSwiQ3JlYXRlZCI6IjIwMTUtMDYtMDRUMTk6NTc6MzQuODA3WiJ9ABiNJ2pA+71kZzcEMmvu9ZcjbYsKNnMDLIgqWC5kjcoXYdiRuv70R8DRPyoleAfZ3jo9qpAhhOYT0gUzv6eiKzAlkH6X5FrYl4p63Kj7ga3M/6z7/TfKZcXoJ/SvKrJwrzObFeVP38jNCN5qhZ75Bs72/Hf2e7WjN7uMJvvpMrh0RqSZ53vaLNBMhuKiNJIktH5VpqZJldKTZ3u5vrA5hROyMjBnsljfBNd5x2luvXwDOc3HvfYyF1rbSFZGSOhnwaWiCcSoYs7j+AX6nezzHQNJX1pS71/3HwZ+QE5yQ47mivVgp0F2DC+fFCEjsqZOWZKvtcgEkKQyxwAazujMHOs=';
console.log('token: ' + token + '\n');

// 1. Decode the base64-encoded token.
var tokenBuffer = new Buffer(token, 'base64');

// 2. Read a null-terminated UTF8 string from the beginning of the token
for (var nullIndex = 0;
    nullIndex < tokenBuffer.length && tokenBuffer[nullIndex] !== 0; // Find the NULL byte
    ++nullIndex);
var payload = tokenBuffer.toString('utf8', 0, nullIndex);
console.log('payload: '+ payload + '\n');

// 3. Read the rest of the token
var signedHash = tokenBuffer.slice(nullIndex + 1);
console.log('signedHash: ' + signedHash.toString('base64') + '\n');

// 4. Verify the signature of the signedHash against the payload using the provided PUBLIC key.
var isHashVerified = publicKey.verify(payload, signedHash, 'utf8');
console.log('isHashVerified: ' + isHashVerified);

if (isHashVerified) {
  var json = JSON.parse(payload);
  console.log('UserIdentifierId: ' + json.Data.UserIdentifierId);
  console.log('Token created: ' + json.Created + '\n');
} else {
  console.log('WARNING: Token did not verify with the DoubleDutch public key!!!');
  console.log('         It was not signed by DoubleDutch!!!');
}
