const crypto = require('crypto');

const algorithm = 'aes-256-cbc';

const generateRandomString = (length = 32) => {
  return crypto.randomBytes(length);
};

function encryptWithPublicKey(data, publicKey) {
  const buffer = Buffer.from(data, 'utf8');
  const encrypted = crypto.publicEncrypt(
    publicKey,
    buffer,
  );

  return encrypted.toString('base64');
}

const decryptWithPrivateKey = (encryptedData, privateKey) => {
  const buffer = Buffer.from(encryptedData, 'base64');
  const decrypted = crypto.privateDecrypt(
    privateKey,
    buffer,
  );

  return decrypted;
};

const generateSessionKey = (clientRandom, serverRandom, premasterSecret) => {
  const seed = Buffer.concat([clientRandom, serverRandom, premasterSecret]);
  const hash = crypto.createHash('sha256').update(seed).digest();
  return hash;
};

const encryptWithSessionKey = (data, sessionKey) => {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(algorithm, sessionKey, iv);

  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  return iv.toString('hex') + ':' + encrypted;
};

const decryptWithSessionKey = (hashData, sessionKey) => {
  try {
    const parts = hashData.split(':');
    const iv = Buffer.from(parts.shift(), 'hex');
    const encryptedData = parts.join(':');

    const decipher = crypto.createDecipheriv(algorithm, sessionKey, iv);

    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
  } catch (error) {
    return '!!! ⚠️DECRYPTION ERROR !!!';
  }
};

module.exports = {
  generateRandomString,
  encryptWithPublicKey,
  decryptWithPrivateKey,
  generateSessionKey,
  encryptWithSessionKey,
  decryptWithSessionKey,
};
