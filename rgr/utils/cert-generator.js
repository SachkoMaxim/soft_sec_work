const crypto = require('crypto');
const forge = require('node-forge');
const fs = require('fs');
const path = require('path');

const generatePrivateKey = (outputPath, keySize = 2048) => {
  console.log(`🔑 Generating RSA private key...`);

  const { privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: keySize,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem',
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem',
    },
  });

  const dir = path.dirname(outputPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  fs.writeFileSync(outputPath, privateKey, 'utf8');
  console.log(`✅ Private key saved`);

  return privateKey;
};

const generateCSR = (privateKeyPath, outputPath, challengePassword) => {
  console.log('📝 Generating Certificate Signing Request (CSR)...');

  const privateKeyPem = fs.readFileSync(privateKeyPath, 'utf8');
  const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);

  const keyObject = crypto.createPrivateKey(privateKeyPem);

  const publicKeyPem = crypto.createPublicKey(keyObject);
  const publicKey = publicKeyPem.export({ type: 'spki', format: 'pem' });
  const publicKeyUse = forge.pki.publicKeyFromPem(publicKey);

  const csr = forge.pki.createCertificationRequest();
  csr.publicKey = publicKeyUse;

  csr.setSubject([
    { name: 'countryName', value: '' },
    { name: 'stateOrProvinceName', value: '' },
    { name: 'localityName', value: '' },
    { name: 'organizationName', value: '' },
    { name: 'organizationalUnitName', value: '' },
    { name: 'commonName', value: '' },
  ]);

  if (challengePassword) {
    csr.setAttributes([{
      name: 'challengePassword',
      value: challengePassword
    }]);
  }

  csr.sign(privateKey, forge.md.sha256.create());

  if (csr.verify()) {
    console.log('✅ CSR signature verified');
  } else {
    console.error('❌ CSR signature verification failed');
    return;
  }

  const csrPem = forge.pki.certificationRequestToPem(csr);

  const dir = require('path').dirname(outputPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  fs.writeFileSync(outputPath, csrPem, 'utf8');
  console.log(`✅ CSR saved`);

  return csrPem;
};

const signCertificate = (csrPath, caCertPath, caKeyPath, outputPath, days = 500) => {
  console.log('🔏 Signing certificate with CA...');

  const csrContent = fs.readFileSync(csrPath, 'utf8');
  const caCertPem = fs.readFileSync(caCertPath, 'utf8');
  const caKeyPem = fs.readFileSync(caKeyPath, 'utf8');

  const csr = forge.pki.certificationRequestFromPem(csrContent);
  const caCert = forge.pki.certificateFromPem(caCertPem);
  const caKey = forge.pki.privateKeyFromPem(caKeyPem);

  const caSKI = caCert.extensions.find(e => e.name === 'subjectKeyIdentifier');

  const serverCert = forge.pki.createCertificate();

  serverCert.publicKey = csr.publicKey;
  serverCert.serialNumber = forge.util.bytesToHex(forge.random.getBytesSync(16));
  serverCert.validity.notBefore = new Date();
  serverCert.validity.notAfter = new Date();
  serverCert.validity.notAfter.setDate(serverCert.validity.notBefore.getDate() + days);

  serverCert.setIssuer(caCert.subject.attributes);
  serverCert.setSubject(csr.subject.attributes);

  serverCert.setExtensions([
    {
      name: 'basicConstraints',
      cA: false,
      critical: true,
    },
    {
      name: 'keyUsage',
      digitalSignature: true,
      keyEncipherment: true,
      critical: true,
    },
    {
      name: 'extKeyUsage',
      emailProtection: true,
      serverAuth: true,
      clientAuth: true,
    },
    {
      name: 'subjectKeyIdentifier',
    },
    {
      name: 'authorityKeyIdentifier',
      keyIdentifier: forge.util.hexToBytes(caSKI.subjectKeyIdentifier),
      authorityCertIssuer: true,
      serialNumber: caCert.serialNumber,
    },
  ]);

  serverCert.sign(caKey, forge.md.sha256.create());

  const certPem = forge.pki.certificateToPem(serverCert);;

  const dir = path.dirname(outputPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  fs.writeFileSync(outputPath, certPem, 'utf8');
  console.log(`✅ Certificate signed and saved`);

  return certPem;
};

module.exports = {
  generatePrivateKey,
  generateCSR,
  signCertificate,
};
