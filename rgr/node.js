const net = require('net');
const fs = require('fs');
const readline = require('readline');
const path = require('path');
const crypto = require('crypto');
const {
  generateRandomString,
  encryptWithPublicKey,
  decryptWithPrivateKey,
  generateSessionKey,
  encryptWithSessionKey,
  decryptWithSessionKey,
} = require('./utils/crypto');
const {
  generatePrivateKey,
  generateCSR,
  signCertificate,
} = require('./utils/cert-generator');

const args = process.argv.slice(2);
if (args.length < 1) {
  console.error('You need to use: node node.js <PORT>');
  process.exit(1);
}

const MY_PORT = parseInt(args[0], 10);
const MY_NAME = `Node-${MY_PORT}`;

const CA_PORT = 9034;
const CA_HOST = 'localhost';

class Node {
  constructor() {
    // Отримання ключа та сертифіката ноди
    console.log('🔑 Loading node key and certificate...');

    const nodeKeyPath = path.join(__dirname, 'certs', `node${MY_PORT}.key`);
    const csrPath = path.join(__dirname, 'certs', `node${MY_PORT}.csr`);
    const nodeCertPath = path.join(__dirname, 'certs', `node${MY_PORT}.crt`);

    try {
      this.privateKey = generatePrivateKey(nodeKeyPath, 2048);
 
      const csr = generateCSR(nodeKeyPath, csrPath, '9876');
    
      this.certificate = signCertificate(
        csrPath,
        path.join(__dirname, 'certs', 'ca.crt'),
        path.join(__dirname, 'certs', 'ca.key'),
        nodeCertPath,
        500
      );
    
      console.log(`📜 Uploaded certificate (S/N: \n ${this.certificate.substring(0, 300)}...)`);
      console.log(`✔️ ${MY_NAME} has uploaded its key and certificate.\n`);
    } catch (e) {
      console.error('❌ Failed to create and download key\\certificate!', e.message);
      process.exit(1);
    }

    this.isClient = false;

    this.server = null;
    this.rl = null;
    this.messageData = {
      sessionKey: null,
      client: null,
      target: null,
    };
  }

  start() {
    console.log(`[${MY_NAME}]🚩 Node started. Enter 'connect <port>' to connect`);
    this.initReadline();

    this.server = net.createServer((socket) => {
      const remoteName = `${socket.remoteAddress}:${socket.remotePort}`;
      console.log(`\n[${MY_NAME}]🔌 New incoming connection from ${remoteName}`);

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
          console.log(`\n[${MY_NAME} - ${remoteName}]📨[1] Received CLIENT HELLO`);
          console.log(`   Client Random: ${clientHello.clientRandom.toString('base64').substring(0, 16)}...`);

          // Крок 2: Відправка 'Server Hello'
          session.serverRandom = generateRandomString(32);

          const response = {
            serverRandom: session.serverRandom.toString('base64'),
            certificatePem: this.certificate,
          };

          console.log(`\n[${MY_NAME} - ${remoteName}]📤[2] Sending SERVER HELLO + SSL Certificate`);
          console.log(`   Server Random: ${session.serverRandom.toString('base64').substring(0, 16)}...`);
          console.log(`   Certificate S/N: \n${this.certificate.substring(0, 300)}...`);

          socket.write(JSON.stringify(response));

          console.log(`[${MY_NAME} - ${remoteName}]✅[2] Sent SERVER HELLO + SSL Certificate`);

          // Крок 4: Обробка 'Premaster Secret' від клієнта
          socket.once('data', (premasterData) => {
            try {
              const premasterMessage = JSON.parse(premasterData.toString());
              console.log(`\n[${MY_NAME} - ${remoteName}]📨[4] Received encrypted PREMASTER SECRET`);

              session.premasterSecret = decryptWithPrivateKey(premasterMessage.encryptedPremaster, this.privateKey);
              console.log(`   Decrypted Premaster Secret: ${session.premasterSecret.toString('base64').substring(0, 16)}...`);

              // Крок 5: Генерація session key
              session.sessionKey = generateSessionKey(
                session.clientRandom,
                session.serverRandom,
                session.premasterSecret,
              );
              console.log(`\n[${MY_NAME} - ${remoteName}]✅[5] Session Key generated: ${session.sessionKey.toString('hex').substring(0, 16)}...`);

              // Крок 6: Отримання 'Client Finished' (зашифрованого session key)
              socket.once('data', (clientFinishedData) => {
                try {
                  const clientFinished = JSON.parse(clientFinishedData.toString());
                  console.log(`\n[${MY_NAME} - ${remoteName}]📨[6] Received encrypted CLIENT FINISHED`);

                  const decryptedMsg = decryptWithSessionKey(clientFinished.message, session.sessionKey);

                  if (decryptedMsg === 'Client: Finished') {
                    console.log(`[${MY_NAME} - ${remoteName}]🔐[6] Received CLIENT FINISHED: "${decryptedMsg}"`);

                    // Крок 6: Відправка 'Server Finished' (зашифрованого session key)
                    const finishedMessage = 'Server: Finished';
                    const serverFinishedMsg = encryptWithSessionKey(finishedMessage, session.sessionKey);

                    console.log(`\n[${MY_NAME} - ${remoteName}]📤[6] Sending encrypted SERVER FINISHED`);
                    socket.write(JSON.stringify({ type: 'SERVER_FINISHED', message: serverFinishedMsg }));
                    console.log(`[${MY_NAME} - ${remoteName}]✅[6] Sent SERVER FINISHED`);

                    // Крок 7: Початок захищеного чату
                    console.log('\n🎉 ========================================');
                    console.log('✅ TLS/SSL HANDSHAKE COMPLETED!');
                    console.log('🔒 Secure channel established');
                    console.log('========================================\n');

                    this.rl.prompt();

                    let chatBuffer = '';
                    socket.on('data', (encryptedChatData) => {
                      chatBuffer += encryptedChatData.toString();

                      let newlineIndex;
                      while ((newlineIndex = chatBuffer.indexOf('\n')) !== -1) {
                        const jsonString = chatBuffer.substring(0, newlineIndex);
                        chatBuffer = chatBuffer.substring(newlineIndex + 1);

                        if (jsonString) {
                          try {
                            console.log(`\n[${MY_NAME} - ${remoteName}]📨 Encrypted data received`);
                            const chatMsg = JSON.parse(jsonString);
                            const decrypted = decryptWithSessionKey(chatMsg.message, session.sessionKey);
                            console.log(`[${MY_NAME} - ${remoteName}]📄 Received message: "${decrypted}"`);

                            const reply = encryptWithSessionKey(`Server received: ${decrypted}`, session.sessionKey);
                            socket.write(JSON.stringify({ type: 'ENCRYPTED_DATA', message: reply }) + '\n');
                            console.log(`[${MY_NAME} - ${remoteName}]📤 Send encrypted data: "Server received: ${decrypted}"`);
                            this.rl.prompt();
                          } catch (e) {
                            console.error(`[${MY_NAME} - ${remoteName}]🚨 Error parsing JSON from buffer:`, e.message, 'Data:', jsonString);
                          }
                        }
                      }
                    });
                  } else {
                    console.error(`[${MY_NAME} - ${remoteName}]🚨 Error: The CLIENT FINISHED message is incorrect.`);
                    socket.destroy();
                  }
                } catch (e) {
                  console.error(`[${MY_NAME} - ${remoteName}]🚨[6] Error:`, e.message);
                  socket.destroy();
                }
              });
            } catch (e) {
              console.error(`[${MY_NAME} - ${remoteName}]🚨[4] Error:`, e.message);
              socket.destroy();
            }
          });
        } catch (e) {
          console.error(`[${MY_NAME} - ${remoteName}]🚨[1] Error:`, e.message);
          socket.destroy();
        }
      });

      socket.on('close', () => {
        console.log(`[${MY_NAME}]👋 Node ${remoteName} disconnected\n`);
      });

      socket.on('error', (err) => {
        console.error(`[${MY_NAME}]❌ Error:`, err.message);
      });
    });

    this.server.listen(MY_PORT, () => {
      console.log(`💻 Node running on port ${MY_PORT}`);
      console.log('='.repeat(50));
      this.rl.prompt();
    });

    this.server.on('error', (err) => {
      console.error('🛑 Node error:', err.message);
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
        const parts = input.trim().split(' ');
        const command = parts[0];
        const targetHost = parts[1] || 'localhost';
        const targetPort = parseInt(parts[2], 10);

        let finalHost = targetHost;
        let finalPort = targetPort;

        if (command === 'connect' && parts.length === 2) {
          finalHost = 'localhost';
          finalPort = parseInt(parts[1], 10);
        }

        if (command === 'connect' && finalPort) {
          this.connectToPeer(finalHost, finalPort);
        } else if (input.toLowerCase() === 'exit') {
          this.stop();
        } else if (input.trim()) {
          if (this.isClient) {
            const chatMessage = encryptWithSessionKey(input, this.messageData.sessionKey);
            this.messageData.client.write(JSON.stringify({ type: 'ENCRYPTED_DATA', message: chatMessage }) + '\n');
            console.log(`\n[${MY_NAME} - ${this.messageData.target}]📤 Send encrypted data: "${input}"`);
          } else {
            console.log(`[${MY_NAME}] Use: connect <port> (or connect <host> <port>)`);
          }
        }
      });

      this.rl.on('close', () => {
        console.log(`[${MY_NAME}] Readline interface closed.`);
      });
    }
  }

  connectToPeer(host, port) {
    const targetName = `${host}:${port}`;
    console.log(`\n[${MY_NAME}]🔌 Initiating connection to ${targetName}...`);
    
    const client = new net.Socket();

    const session = {
      sessionKey: null,
      clientRandom: null,
      serverRandom: null,
      premasterSecret: null,
    };

    client.connect(port, host, () => {
      this.isClient = true;
      this.messageData.target = targetName;
      console.log(`[${MY_NAME}]🔌 Successfully connected to ${targetName}`);

      // Крок 1: Надсилання 'Client Hello'
      session.clientRandom = generateRandomString(32);
      const clientHello = { clientRandom: session.clientRandom.toString('base64') };

      console.log(`\n[${MY_NAME} - ${targetName}]📤[1] Sending CLIENT HELLO`);
      console.log(`   Client Random: ${session.clientRandom.toString('base64').substring(0, 16)}...`);

      client.write(JSON.stringify(clientHello));

      console.log('[Client]✅[1] Sent CLIENT HELLO');

      // Крок 2: Отримання 'Server Hello'
      client.once('data', async (serverHelloData) => {
        try {
          const serverHello = JSON.parse(serverHelloData.toString());
          session.serverRandom = Buffer.from(serverHello.serverRandom, 'base64');
          const serverCertCheck = serverHello.certificatePem;
          console.log(`\n[${MY_NAME} - ${targetName}]📨[2] Received SERVER HELLO + SSL Certificate`);
          console.log(`   Server Random: ${serverHello.serverRandom.toString('base64').substring(0, 16)}...`);
          console.log(`   Certificate S/N: \n${serverHello.certificatePem.substring(0, 300)}...`);

          //  Крок 3: Перевірка сертифіката в CA Server
          console.log(`\n[${MY_NAME} - ${targetName}]🔐[3] Authentication - Verifying certificate with CA Server`);
          try {
            await this.checkCertValidity(serverCertCheck);
            console.log(`[${MY_NAME} - ${targetName}]✅[3] Server certificate is valid`);
          } catch (e) {
            console.error(`[${MY_NAME} - ${targetName}]🚨[3] VERIFICATION FAILED: ${e.message}!!!`);
            client.destroy();
            return;
          }


          // Крок 4: Генерація та відправка 'Premaster Secret'
          const serverCert = new crypto.X509Certificate(serverCertCheck);
          session.premasterSecret = generateRandomString(48);
          console.log(`\n[${MY_NAME} - ${targetName}]🔑[4] Generating PREMASTER SECRET`);
          console.log(`   Premaster Secret: ${session.premasterSecret.toString('base64').substring(0, 16)}...`);

          const encryptedPremaster = encryptWithPublicKey(session.premasterSecret, serverCert.publicKey);

          const premasterMessage = {
            encryptedPremaster: encryptedPremaster,
          };

          console.log(`\n[${MY_NAME} - ${targetName}]📤[4] Sending encrypted PREMASTER SECRET`);

          client.write(JSON.stringify(premasterMessage));

          console.log(`[${MY_NAME} - ${targetName}]✅[4] Send encrypted PREMASTER SECRET`);

          // Крок 5: Генерація session key
          session.sessionKey = generateSessionKey(
            session.clientRandom,
            session.serverRandom,
            session.premasterSecret,
          );
          console.log(`\n[${MY_NAME} - ${targetName}]✅[5] Session Key generated: ${session.sessionKey.toString('hex').substring(0, 16)}...`);

          // Крок 6: Відправка 'Client Finished' (зашифрованого session key)
          const finishedMessage = 'Client: Finished';
          const clientFinishedMsg = encryptWithSessionKey(finishedMessage, session.sessionKey);

          console.log(`\n[${MY_NAME} - ${targetName}]📤[6] Sending encrypted CLIENT FINISHED`);
          client.write(JSON.stringify({ type: 'CLIENT_FINISHED', message: clientFinishedMsg }));
          console.log(`[${MY_NAME} - ${targetName}]✅[6] Sent CLIENT FINISHED`);

          // Крок 6: Отримання 'Server Finished' (зашифрованого session key)
          client.once('data', (serverFinishedData) => {
            try {
              const serverFinished = JSON.parse(serverFinishedData.toString());
              console.log(`\n[${MY_NAME} - ${targetName}]📨[6] Received encrypted SERVER FINISHED`);

              const decryptedMsg = decryptWithSessionKey(serverFinished.message, session.sessionKey);

              if (decryptedMsg === 'Server: Finished') {
                console.log(`[${MY_NAME} - ${targetName}]🔐[6] Received SERVER FINISHED: "${decryptedMsg}"`);

                console.log('\n🎉 ========================================');
                console.log('✅ TLS/SSL HANDSHAKE COMPLETED!');
                console.log('🔒 Secure channel established');
                console.log('========================================\n');
                console.log('   💬 Enter a message or "exit" to exit\n');

                this.messageData.sessionKey = session.sessionKey;
                this.messageData.client = client;

                this.rl.prompt();

                let chatBuffer = '';
                client.on('data', (encryptedChatData) => {
                  chatBuffer += encryptedChatData.toString();

                  let newlineIndex;
                  while ((newlineIndex = chatBuffer.indexOf('\n')) !== -1) {
                    const jsonString = chatBuffer.substring(0, newlineIndex);
                    chatBuffer = chatBuffer.substring(newlineIndex + 1);

                    if (jsonString) {
                      try {
                        console.log(`[${MY_NAME} - ${targetName}]📨 Encrypted data received`);
                        const chatMsg = JSON.parse(jsonString);
                        const decrypted = decryptWithSessionKey(chatMsg.message, session.sessionKey);
                        console.log(`[${MY_NAME} - ${targetName}]📄 Received answer: "${decrypted}"`);
                        this.rl.prompt();
                      } catch (e) {
                        console.error(`[${MY_NAME} - ${targetName}]🚨 Error parsing JSON from buffer:`, e.message, 'Data:', jsonString);
                      }
                    }
                  }
                });
              } else {
                console.error(`[${MY_NAME} - ${targetName}]🚨 Error: The SERVER FINISHED message is incorrect.`);
                this.stop();
              }
            } catch (e) {
              console.error(`[${MY_NAME} - ${targetName}]🚨[6] Error:`, e.message);
              this.stop();
            }
          });
        } catch (e) {
          console.error(`[${MY_NAME} - ${targetName}]🚨[2] Error:`, e.message);
          this.stop();
        }
      });
    });

    client.on('close', () => {
      console.log(`[${MY_NAME}]👋 Connection with ${targetName} closed\n`);
      this.isClient = false;
      this.messageData.sessionKey = null;
      this.messageData.target = null;
      this.messageData.client = null;
    });

    client.on('error', (err) => {
      console.error(`[${MY_NAME}]❌ Error:`, err.message);
      this.isClient = false;
      this.closeReadline();
    });
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
        console.error(`[${MY_NAME} - ${this.messageData.target}]🚨[3] !!! VERIFICATION FAILED: ${err.message} !!!`);
        this.stop();
      });
    });
  }

  closeReadline() {
    if (this.rl) {
      this.rl.close();
      this.rl = null;
    }
  }

  stop() {
    if (this.server) {
      this.server.close(() => {
        console.log('🛑 Server stopped!');
        this.closeReadline();
        process.exit(0);
      });
    }
  }
}

// Запуск ноди
const node = new Node();
node.start();
