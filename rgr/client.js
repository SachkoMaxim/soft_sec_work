const net = require('net');
const fs = require('fs');
const readline = require('readline');
const crypto = require('crypto');
const {
  generateRandomString,
  encryptWithPublicKey,
  generateSessionKey,
  encryptWithSessionKey,
  decryptWithSessionKey,
} = require('./utils/crypto');
const { fragmentSend } = require('./utils/frag-send');

const PORT = 7462;
const HOST = 'localhost';

const CA_PORT = 9034;
const CA_HOST = 'localhost';

class TLSClient {
  constructor() {
    console.log('⏳ Loading Client...');

    this.client = null;
    this.session = {
      sessionKey: null,
      clientRandom: null,
      serverRandom: null,
      premasterSecret: null,
    };
    this.rl = null;
    this.isChat = false;
  }

  start() {
    this.client = new net.Socket();

    this.client.connect(PORT, HOST, () => {
      console.log('[Client]🔌 Successfully connected to server');

      // Крок 1: Надсилання 'Client Hello'
      this.session.clientRandom = generateRandomString(32);
      const clientHello = { clientRandom: this.session.clientRandom.toString('base64') };

      console.log('\n[Client]📤[1] Sending CLIENT HELLO');
      console.log(`   Client Random: ${this.session.clientRandom.toString('base64').substring(0, 16)}...`);

      this.client.write(JSON.stringify(clientHello));

      console.log('[Client]✅[1] Sent CLIENT HELLO');

      // Крок 2: Отримання 'Server Hello'
      this.client.once('data', async (serverHelloData) => {
        try {
          const serverHello = JSON.parse(serverHelloData.toString());
          this.session.serverRandom = Buffer.from(serverHello.serverRandom, 'base64');
          const serverCertCheck = serverHello.certificatePem;
          console.log('\n[Client]📨[2] Received SERVER HELLO + SSL Certificate');
          console.log(`   Server Random: ${serverHello.serverRandom.toString('base64').substring(0, 16)}...`);
          console.log(`   Certificate S/N: \n${serverHello.certificatePem.substring(0, 300)}...`);

          //  Крок 3: Перевірка сертифіката в CA Server
          console.log('\n[Client]🔐[3] Authentication - Verifying certificate with CA Server');
          try {
            await this.checkCertValidity(serverCertCheck);
            console.log('[Client]✅[3] Server certificate is valid');
          } catch (e) {
            console.error(`[Client]🚨[3] VERIFICATION FAILED: ${e.message}!!!`);
            this.disconnect();
            return;
          }


          // Крок 4: Генерація та відправка 'Premaster Secret'
          const serverCert = new crypto.X509Certificate(serverCertCheck);
          this.session.premasterSecret = generateRandomString(48);
          console.log('\n[Client]🔑[4] Generating PREMASTER SECRET');
          console.log(`   Premaster Secret: ${this.session.premasterSecret.toString('base64').substring(0, 16)}...`);

          const encryptedPremaster = encryptWithPublicKey(this.session.premasterSecret, serverCert.publicKey);

          const premasterMessage = {
            encryptedPremaster: encryptedPremaster,
          };

          console.log('\n[Client]📤[4] Sending encrypted PREMASTER SECRET');

          this.client.write(JSON.stringify(premasterMessage));

          console.log('[Client]✅[4] Send encrypted PREMASTER SECRET');

          // Крок 5: Генерація session key
          this.session.sessionKey = generateSessionKey(
            this.session.clientRandom,
            this.session.serverRandom,
            this.session.premasterSecret,
          );
          console.log(`\n[Client]✅[5] Session Key generated: ${this.session.sessionKey.toString('hex').substring(0, 16)}...`);

          // Крок 6: Відправка 'Client Finished' (зашифрованого session key)
          const finishedMessage = 'Client: Finished';
          const clientFinishedMsg = encryptWithSessionKey(finishedMessage, this.session.sessionKey);

          console.log('\n[Client]📤[6] Sending encrypted CLIENT FINISHED');
          fragmentSend(this.client, JSON.stringify({ type: 'CLIENT_FINISHED', message: clientFinishedMsg }) + '\n', 'Client');
          console.log('[Client]✅[6] Sent CLIENT FINISHED');

          let chatBuffer = '';
          this.client.on('data', (encryptedChatData) => {
            chatBuffer += encryptedChatData.toString();

            let newlineIndex;
            while ((newlineIndex = chatBuffer.indexOf('\n')) !== -1) {
              const jsonString = chatBuffer.substring(0, newlineIndex);
              chatBuffer = chatBuffer.substring(newlineIndex + 1);

              if (jsonString) {
                try {
                  console.log('\n[Client]📨 Encrypted data received');
                  const chatMsg = JSON.parse(jsonString);
                  const decrypted = decryptWithSessionKey(chatMsg.message, this.session.sessionKey);
                  if (decrypted === 'Server: Finished') {
                    // Крок 6: Отримання 'Server Finished' (зашифрованого session key)
                    console.log('\n[Client]📨[6] Received encrypted SERVER FINISHED');
                    console.log(`[Client]🔐[6] Received SERVER FINISHED: "${decrypted}"`);

                    // Крок 7: Початок захищеного чату
                    console.log('\n🎉 ========================================');
                    console.log('✅ TLS/SSL HANDSHAKE COMPLETED!');
                    console.log('🔒 Secure channel established');
                    console.log('========================================\n');
                    console.log('   💬 Enter a message or "exit" to exit\n');

                    this.initReadline();
                    this.isChat = true;
                    this.rl.prompt();
                  } else if (this.isChat) {
                    console.log(`[Client]📄 Received answer: "${decrypted}"`);
                    this.rl.prompt();
                  } else {
                    console.error('[Client]🚨 Error: The SERVER FINISHED message is incorrect.');
                    this.disconnect();
                  }
                } catch (e) {
                  console.error('[Client]🚨 Error parsing JSON from buffer:', e.message, 'Data:', jsonString);
                  this.disconnect();
                }
              }
            }
          });
        } catch (e) {
          console.error('[Client]🚨[2] Error:', e.message);
          this.disconnect();
        }
      });
    });

    this.client.on('close', () => {
      console.log('[Client]👋 Connection closed\n');
      this.isChat = false;
      this.closeReadline();
      this.clearSession();
    });

    this.client.on('error', (err) => {
      console.error('[Client]❌ Error:', err.message);
      this.closeReadline();
    });
  }

  initReadline() {
    if (!this.rl) {
      this.rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout,
      });

      this.rl.on('line', (input) => {
        if (input.toLowerCase() === 'exit') {
          this.disconnect();
        } else if (input.trim()) {
          if (this.client && !this.client.destroyed) {
            const chatMessage = encryptWithSessionKey(input, this.session.sessionKey);
            fragmentSend(this.client, JSON.stringify({ type: 'ENCRYPTED_DATA', message: chatMessage }) + '\n', 'Client');
            console.log(`\n[Client]📤 Send encrypted data: "${input}"`);
          } else {
            console.log('[Client]❌ Not connected to server');
          }
        }
      });

      this.rl.on('close', () => {
        console.log('[Client] Readline interface closed.');
      });
    }
  }

  checkCertValidity(serverCert) {
    return new Promise((resolve, reject) => {
      const caSocket = new net.Socket();

      caSocket.connect(CA_PORT, CA_HOST, () => {
        console.log(`[Client]🔌[3] Connected to CA Server on port ${CA_PORT}`);
        caSocket.write(serverCert);
      });

      caSocket.once('data', (caResponseData) => {
        const caResponse = caResponseData.toString();
        console.log(`[Client]📨[3] Received response from CA: "${caResponse}"`);
        caSocket.end();

        if (caResponse === 'VALID') {
          resolve();
          caSocket.end();
        } else {
          reject(new Error('CA rejected the certificate'));
          caSocket.end();
        }
      });

      caSocket.on('error', (err) => {
        console.error(`[Client]🚨[3] !!! VERIFICATION FAILED: ${err.message} !!!`);
        this.disconnect();
      });
    });
  }

  closeReadline() {
    if (this.rl) {
      this.rl.close();
      this.rl = null;
    }
  }

  clearSession() {
    this.session.sessionKey = null;
    this.session.clientRandom = null;
    this.session.serverRandom = null;
    this.session.premasterSecret = null;
  }

  disconnect() {
    if (this.client && !this.client.destroyed) {
      this.client.end();
    }
  }
}

// Запуск клієнта
const client = new TLSClient();
client.start();
