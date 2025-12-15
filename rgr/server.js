const net = require('net');
const fs = require('fs');
const path = require('path');
const {
  generateRandomString,
  decryptWithPrivateKey,
  generateSessionKey,
  encryptWithSessionKey,
  decryptWithSessionKey,
} = require('./utils/crypto');

const PORT = 7462;

class TLSServer {
  constructor() {
    // Отримання ключа та сертифіката сервера
    console.log('🔑 Loading server key and certificate...');

    const serverKeyPath = path.join(__dirname, 'certs', 'server.key');
    this.privateKey = fs.readFileSync(serverKeyPath, 'utf8');

    const serverCertPath = path.join(__dirname, 'certs', 'server.crt');
    this.certificate = fs.readFileSync(serverCertPath, 'utf8');

    console.log(`📜 Uploaded certificate (S/N: \n ${this.certificate.substring(0, 300)}...)`);
    console.log('✔️ Server has uploaded its key and certificate.\n');

    this.server = null;
  }

  start() {
    this.server = net.createServer((socket) => {
      console.log('\n[Server]🔌 Client connected');

      const session = {
        sessionKey: null,
        clientRandom: null,
        serverRandom: null,
        premasterSecret: null,
      };

      // Крок 1: Обробка 'Client Hello'
      socket.once('data', (clientHelloData) => {
        try {
          const clientHello = JSON.parse(clientHelloData.toString());
          session.clientRandom = Buffer.from(clientHello.clientRandom, 'base64');
          console.log('\n[Server]📨[1] Received CLIENT HELLO');
          console.log(`   Client Random: ${clientHello.clientRandom.toString('base64').substring(0, 16)}...`);

          // Крок 2: Відправка 'Server Hello'
          session.serverRandom = generateRandomString(32);

          const response = {
            serverRandom: session.serverRandom.toString('base64'),
            certificatePem: this.certificate,
          };

          console.log(`\n[Server]📤[2] Sending SERVER HELLO + SSL Certificate`);
          console.log(`   Server Random: ${session.serverRandom.toString('base64').substring(0, 16)}...`);
          console.log(`   Certificate S/N: \n${this.certificate.substring(0, 300)}...`);

          socket.write(JSON.stringify(response));

          console.log('[Server]✅[2] Sent SERVER HELLO + SSL Certificate');

          // Крок 4: Обробка 'Premaster Secret' від клієнта
          socket.once('data', (premasterData) => {
            try {
              const premasterMessage = JSON.parse(premasterData.toString());
              console.log('\n[Server]📨[4] Received encrypted PREMASTER SECRET');

              session.premasterSecret = decryptWithPrivateKey(premasterMessage.encryptedPremaster, this.privateKey);
              console.log(`   Decrypted Premaster Secret: ${session.premasterSecret.toString('base64').substring(0, 16)}...`);

              // Крок 5: Генерація session key
              session.sessionKey = generateSessionKey(
                session.clientRandom,
                session.serverRandom,
                session.premasterSecret,
              );
              console.log(`\n[Server]✅[5] Session Key generated: ${session.sessionKey.toString('hex').substring(0, 16)}...`);

              // Крок 6: Отримання 'Client Finished' (зашифрованого session key)
              socket.once('data', (clientFinishedData) => {
                try {
                  const clientFinished = JSON.parse(clientFinishedData.toString());
                  console.log('\n[Server]📨[6] Received encrypted CLIENT FINISHED');

                  const decryptedMsg = decryptWithSessionKey(clientFinished.message, session.sessionKey);

                  if (decryptedMsg === 'Client: Finished') {
                    console.log(`[Server]🔐[6] Received CLIENT FINISHED: "${decryptedMsg}"`);

                    // Крок 6: Відправка 'Server Finished' (зашифрованого session key)
                    const finishedMessage = 'Server: Finished';
                    const serverFinishedMsg = encryptWithSessionKey(finishedMessage, session.sessionKey);

                    console.log('\n[Server]📤[6] Sending encrypted SERVER FINISHED');
                    socket.write(JSON.stringify({ type: 'SERVER_FINISHED', message: serverFinishedMsg }));
                    console.log('[Server]✅[6] Sent SERVER FINISHED');

                    // Крок 7: Початок захищеного чату
                    console.log('\n🎉 ========================================');
                    console.log('✅ TLS/SSL HANDSHAKE COMPLETED!');
                    console.log('🔒 Secure channel established');
                    console.log('========================================\n');

                    let chatBuffer = '';
                    socket.on('data', (encryptedChatData) => {
                      chatBuffer += encryptedChatData.toString();

                      let newlineIndex;
                      while ((newlineIndex = chatBuffer.indexOf('\n')) !== -1) {
                        const jsonString = chatBuffer.substring(0, newlineIndex);
                        chatBuffer = chatBuffer.substring(newlineIndex + 1);

                        if (jsonString) {
                          try {
                            console.log('\n[Server]📨 Encrypted data received');
                            const chatMsg = JSON.parse(jsonString);
                            const decrypted = decryptWithSessionKey(chatMsg.message, session.sessionKey);
                            console.log(`[Server]📄 Received message: "${decrypted}"`);

                            const reply = encryptWithSessionKey(`Server received: ${decrypted}`, session.sessionKey);
                            socket.write(JSON.stringify({ type: 'ENCRYPTED_DATA', message: reply }) + '\n');
                            console.log(`[Server]📤 Send encrypted data: "Server received: ${decrypted}"`);
                          } catch (e) {
                            console.error('[Server]🚨 Error parsing JSON from buffer:', e.message, 'Data:', jsonString);
                          }
                        }
                      }
                    });
                  } else {
                    console.error('[Server]🚨 Error: The CLIENT FINISHED message is incorrect.');
                    socket.destroy();
                  }
                } catch (e) {
                  console.error('[Server]🚨[6] Error:', e.message);
                  socket.destroy();
                }
              });
            } catch (e) {
              console.error('[Server]🚨[4] Error:', e.message);
              socket.destroy();
            }
          });
        } catch (e) {
          console.error('[Server]🚨[1] Error:', e.message);
          socket.destroy();
        }
      });

      socket.on('close', () => {
          console.log('[Server]👋 Client disconnected\n');
      });

      socket.on('error', (err) => {
        console.error('[Server]❌ Error:', err.message);
      });
    });

    this.server.listen(PORT, () => {
      console.log(`🚀 TLS/SSL Server running on port ${PORT}`);
      console.log('='.repeat(50));
    });

    this.server.on('error', (err) => {
      console.error('🛑 Server error:', err.message);
    });
  }

  stop() {
    if (this.server) {
      this.server.close(() => {
        console.log('🛑 Server stopped!');
      });
    }
  }
}

// Запуск сервера
const server = new TLSServer();
server.start();
