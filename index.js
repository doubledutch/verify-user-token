var RSA = require('node-rsa');

var publicKeyBase64 = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnqCN6WNflUHWV11Kn/esWa8mAiU75rv2TfJmS3EADny0h4duBobHhj4CsPsMOsVrubDL3wMEtN3/oyS7Iw1fnOXUxp/woN1G+Es+5gSOgMea4o4JSpbyDWD5dL58eAs9mxnT8n/035peMHr+7Um9xZLG2pBuFrOi3IVcAa4iWrX2tx1XKUgi+5UnncB3jYRh70VhcnRVFM8xmavUpTZ5LvIBxiFqiBe9TGTkLjvm7VqyCjIcjop7rPc2xYSehSBjp7vus8eI/9oW7JcsxGAuRNKxFA7deJ8zNWCr4h8uT3I5RNnh+7jXqQso2oOVIY5hSunDlT0rB9kgjava1QDYEQIDAQAB'
var publicKeyData = '-----BEGIN PUBLIC KEY-----\n' +
publicKeyBase64 +
+ '\n-----END PUBLIC KEY-----';

var publicKey = new RSA(publicKeyData, 'public');

console.log('public key (base64 length=' + publicKeyBase64.length + '): ' + publicKeyBase64 + '\n');

console.log('public key byte length: ' + new Buffer(publicKeyBase64, 'base64').length + '\n');

function verifyToken(token) {
  console.log('------------------------------------------------------------')
  console.log('token (base64 length=' + token.length + '): ' + token + '\n');

  // 1. Decode the base64-encoded token.
  var tokenBuffer = new Buffer(token, 'base64');
  console.log('token byte length after base64 decode: ' + tokenBuffer.length + '\n');

  // 2. Read a null-terminated UTF8 string from the beginning of the token
  for (var nullIndex = 0;
      nullIndex < tokenBuffer.length && tokenBuffer[nullIndex] !== 0; // Find the NULL byte
      ++nullIndex);
  var payload = tokenBuffer.toString('utf8', 0, nullIndex);
  console.log('payload (length=' + payload.length  + '): '+ payload + '\n');

  // 3. Read the rest of the token
  var signedHash = tokenBuffer.slice(nullIndex + 1);
  console.log('signedHash (byte length=' + signedHash.length + '): ' + signedHash.toString('base64') + '\n');

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
}

verifyToken('eyJEYXRhIjp7IklkIjoxNDMsIlVwZGF0ZWQiOiIyMDE1LTA2LTA0VDE5OjU3OjI5LjczN1oiLCJFbWFpbEFkZHJlc3MiOiJ1bml0KzI1MTdAdGVzdC5jb20iLCJGaXJzdE5hbWUiOiIiLCJMYXN0TmFtZSI6IiIsIkltYWdlVXJsIjoiaHR0cDovL3NuLmQyLnZjL2RlZmF1bHQvbm9mYWNlXzExMC5qcGciLCJDb21wYW55IjoiIiwiVXNlck5hbWUiOiJ1bml0KzI1MTdAdGVzdC5jb20iLCJGYWNlYm9va1VzZXJJZCI6bnVsbCwiVHdpdHRlclVzZXJOYW1lIjpudWxsLCJMaW5rZWRJbklkIjpudWxsLCJJc09BdXRoQ29ubmVjdGVkVG9GYWNlYm9vayI6ZmFsc2UsIklzT0F1dGhDb25uZWN0ZWRUb1R3aXR0ZXIiOmZhbHNlLCJJc09BdXRoQ29ubmVjdGVkVG9MaW5rZWRJbiI6ZmFsc2UsIkFsbG93TWVzc2FnaW5nIjp0cnVlLCJVc2VySWRlbnRpZmllcklkIjoidGVzdCIsIklzRXhoaWJpdG9yIjpmYWxzZSwiU2NvcmUiOjAsIlVzZXJHcm91cHMiOltdfSwiQ3JlYXRlZCI6IjIwMTUtMDYtMDRUMTk6NTc6MzQuODA3WiJ9ABiNJ2pA+71kZzcEMmvu9ZcjbYsKNnMDLIgqWC5kjcoXYdiRuv70R8DRPyoleAfZ3jo9qpAhhOYT0gUzv6eiKzAlkH6X5FrYl4p63Kj7ga3M/6z7/TfKZcXoJ/SvKrJwrzObFeVP38jNCN5qhZ75Bs72/Hf2e7WjN7uMJvvpMrh0RqSZ53vaLNBMhuKiNJIktH5VpqZJldKTZ3u5vrA5hROyMjBnsljfBNd5x2luvXwDOc3HvfYyF1rbSFZGSOhnwaWiCcSoYs7j+AX6nezzHQNJX1pS71/3HwZ+QE5yQ47mivVgp0F2DC+fFCEjsqZOWZKvtcgEkKQyxwAazujMHOs=');
verifyToken('eyJEYXRhIjp7IklkIjo0NzcsIlVwZGF0ZWQiOiIyMDE1LTA2LTEwVDE0OjA3OjU4LjA2M1oiLCJFbWFpbEFkZHJlc3MiOiJhZGFtQGRvdWJsZWR1dGNoLm1lIiwiRmlyc3ROYW1lIjoiQWRhbSIsIkxhc3ROYW1lIjoiTGllY2h0eSIsIkltYWdlVXJsIjoiaHR0cDovL3NuLmQyLnZjL2RlZmF1bHQvbm9mYWNlXzExMC5qcGciLCJUaXRsZSI6IlNlbmlvciBFbmdpbmVlciIsIkNvbXBhbnkiOiJEb3VibGVEdXRjaCIsIlVzZXJOYW1lIjoiYWRhbUBkb3VibGVkdXRjaC5tZSIsIkZhY2Vib29rVXNlcklkIjpudWxsLCJUd2l0dGVyVXNlck5hbWUiOm51bGwsIkxpbmtlZEluSWQiOm51bGwsIklzT0F1dGhDb25uZWN0ZWRUb0ZhY2Vib29rIjpmYWxzZSwiSXNPQXV0aENvbm5lY3RlZFRvVHdpdHRlciI6ZmFsc2UsIklzT0F1dGhDb25uZWN0ZWRUb0xpbmtlZEluIjpmYWxzZSwiQWxsb3dNZXNzYWdpbmciOnRydWUsIlVzZXJJZGVudGlmaWVySWQiOiJNWV9JRCIsIklzRXhoaWJpdG9yIjpmYWxzZSwiU2NvcmUiOjAsIlVzZXJHcm91cHMiOltdfSwiQ3JlYXRlZCI6IjIwMTUtMDYtMTBUMTQ6MDc6NTkuNTEyWiJ9AJRZxCfcsEgYSD0ldOan7yE5tEsn40JnFrrUwgxNMDWVgfD6TZ5WOdrSXi3KUbCxRdOLEbFriWBMTnqsHloIn0pUCUflw2uiwE4hiM3lCt9sr24Wctfk3OPC8FUebJ8a1lByXOyCAstzvjJcq75yXyWmh5jAbxOwFt8PkNQQZYjMPkBb4lFmwa98R3RzJp7CdJgDzSj9S30/XYQLcAFzXozJuUnp5ZMgdHljWdRf5AePI9Tr2zaVMPcGB5llCyV/qnDaCLpvnq1yYsov1mIjKX+YXjFTGpf6Q/UUjl+WdepIK/7nsA8j6wYICDKtZ+ZW8njUkoioOvGjJkt7BBzNovA=');
verifyToken('eyJEYXRhIjp7IklkIjo0NzgsIlVwZGF0ZWQiOiIyMDE1LTA2LTEwVDE0OjA5OjI0LjQ3MFoiLCJFbWFpbEFkZHJlc3MiOiJuY2xhcmtAZG91YmxlZHV0Y2gubWUiLCJGaXJzdE5hbWUiOiJOaWNob2xhcyIsIkxhc3ROYW1lIjoiQ2xhcmsiLCJJbWFnZVVybCI6Imh0dHA6Ly9zbi5kMi52Yy9kZWZhdWx0L25vZmFjZV8xMTAuanBnIiwiVGl0bGUiOiJDVE8iLCJDb21wYW55IjoiRG91YmxlRHV0Y2giLCJVc2VyTmFtZSI6Im5jbGFya0Bkb3VibGVkdXRjaC5tZSIsIkZhY2Vib29rVXNlcklkIjpudWxsLCJUd2l0dGVyVXNlck5hbWUiOm51bGwsIkxpbmtlZEluSWQiOm51bGwsIklzT0F1dGhDb25uZWN0ZWRUb0ZhY2Vib29rIjpmYWxzZSwiSXNPQXV0aENvbm5lY3RlZFRvVHdpdHRlciI6ZmFsc2UsIklzT0F1dGhDb25uZWN0ZWRUb0xpbmtlZEluIjpmYWxzZSwiQWxsb3dNZXNzYWdpbmciOnRydWUsIlVzZXJJZGVudGlmaWVySWQiOiJTT01FX0lEIiwiSXNFeGhpYml0b3IiOmZhbHNlLCJTY29yZSI6MCwiVXNlckdyb3VwcyI6W119LCJDcmVhdGVkIjoiMjAxNS0wNi0xMFQxNDowOToyNS45MDZaIn0AYCKLMzpzW3/VoLDU7AJsw4Xs4UFNxQGQMTxF8s7RH+ziFiflKQlkrfgF/V74L1KXCfFHOH5hIXaPKnXQgWGHx+RmTFeimipaSXX/mW09cTwdp3aJgXrg80OLtcMRQ2Wm72qxGhL4OIycpwWBcuCQPmcZ3+abFZH2eNGpJEPuOJ+V5tatksPzFem5xLO3L26V5zKO+PW7RmYM9ln3QGU+FCQQ5AQQODME3OSSBy9D6fZ1ndiNVE1RyhHt5rPi89azvZev9CnyLRTOXaa22YiK3j94lliIDI0w/j5hml8mFxfs1Gbj1AHof3dG131NASubnDAdiaO2G++Gh9D91TjtiA==')
