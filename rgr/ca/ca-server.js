const net = require('net');
const fs = require('fs');
const crypto = require('crypto');
const path = require('path');

const CA_PORT = 9034;

class CAServer {
  constructor() {
    // Отримання сертифіката CA
    this.caCert = null;
    console.log('🔑 Loading root CA certificate...');

    try {
      const caCertificatePath = path.resolve(__dirname, '../certs/ca.crt');
      const caCertPem = fs.readFileSync(caCertificatePath, 'utf8');
      this.caCert = new crypto.X509Certificate(caCertPem);
      console.log('[CA-Server]✔️ Root CA certificate downloaded');
    } catch (e) {
      console.error('[CA-Server]❌ Failed to download root CA certificate!', e.message);
      process.exit(1);
    }

    this.server = null;
  }

  start() {
    this.server = net.createServer((socket) => {
      console.log('\n[CA-Server]📨 Verification request received...');

      socket.once('data', (data) => {
        try {
          const pemToVerify = data.toString();
          const certToVerify = new crypto.X509Certificate(pemToVerify);

          const isValid = certToVerify.verify(this.caCert.publicKey);

          if (isValid) {
            console.log('[CA-Server]✅ Verification successful. Certificate is VALID');
            socket.write('VALID');
          } else {
            console.log('[CA-Server]⛔ Verification failed. Certificate is INVALID');
            socket.write('INVALID');
          }
        } catch (err) {
          console.error('[CA-Server]🚨 Error during verification: ', err.message);
          socket.write('ERROR: Invalid certificate format');
        } finally {
          socket.end();
        }
      });

      socket.on('error', (err) => {
        console.error('[CA-Server]❌ Socket error: ', err.message);
      });
    });

    this.server.listen(CA_PORT, () => {
      console.log(`\n[CA-Server]🏛️ Certificate verification Server running on port ${CA_PORT}`);
    });
  }
}

// Запуск CA сервера
const caServer = new CAServer();
caServer.start();
