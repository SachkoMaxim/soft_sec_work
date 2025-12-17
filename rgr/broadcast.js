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
const { fragmentSend } = require('./utils/frag-send');

const args = process.argv.slice(2);
if (args.length < 1) {
  console.error('You need to use: node node.js <PORT>');
  process.exit(1);
}

const MY_PORT = parseInt(args[0], 10);
const MY_NAME = `Node-${MY_PORT}`;

const CA_PORT = 9034;
const CA_HOST = 'localhost';

const activePeers = new Map();
const seenMessages = new Set();

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
    };
  }

  start() {
    console.log(`[${MY_NAME}]🚩 Node started. Enter 'connect <port>' to connect, or 'broadcast <text>'`);
    this.initReadline();

    this.server = net.createServer((socket) => {
      console.log(`\n[${MY_NAME}]🔌 New incoming connection`);

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
          console.log(`\n[${MY_NAME}]📨[1] Received CLIENT HELLO`);
          console.log(`   Client Random: ${clientHello.clientRandom.toString('base64').substring(0, 16)}...`);

          // Крок 2: Відправка 'Server Hello'
          session.serverRandom = generateRandomString(32);

          const response = {
            serverRandom: session.serverRandom.toString('base64'),
            certificatePem: this.certificate,
          };

          console.log(`\n[${MY_NAME}]📤[2] Sending SERVER HELLO + SSL Certificate`);
          console.log(`   Server Random: ${session.serverRandom.toString('base64').substring(0, 16)}...`);
          console.log(`   Certificate S/N: \n${this.certificate.substring(0, 300)}...`);

          socket.write(JSON.stringify(response));

          console.log(`[${MY_NAME}]✅[2] Sent SERVER HELLO + SSL Certificate`);

          // Крок 4: Обробка 'Premaster Secret' від клієнта
          socket.once('data', (premasterData) => {
            try {
              const premasterMessage = JSON.parse(premasterData.toString());
              console.log(`\n[${MY_NAME}]📨[4] Received encrypted PREMASTER SECRET`);

              session.premasterSecret = decryptWithPrivateKey(premasterMessage.encryptedPremaster, this.privateKey);
              console.log(`   Decrypted Premaster Secret: ${session.premasterSecret.toString('base64').substring(0, 16)}...`);

              // Крок 5: Генерація session key
              session.sessionKey = generateSessionKey(
                session.clientRandom,
                session.serverRandom,
                session.premasterSecret,
              );
              console.log(`\n[${MY_NAME}]✅[5] Session Key generated: ${session.sessionKey.toString('hex').substring(0, 16)}...`);

              // Крок 6: Відправка 'Server Finished' (зашифрованого session key)
              const finishedMessage = `${MY_NAME}: Finished`;
              const serverFinishedMsg = encryptWithSessionKey(finishedMessage, session.sessionKey);

              this.setupSecureChannel(socket, session.sessionKey, 'Inbound');

              console.log(`\n[${MY_NAME}]📤[6] Sending encrypted SERVER FINISHED`);
              fragmentSend(socket, JSON.stringify({ type: 'FINISHED', message: serverFinishedMsg }) + '\n', `${MY_NAME}`);
              console.log(`[${MY_NAME}]✅[6] Sent SERVER FINISHED`);
            } catch (e) {
              console.error(`[${MY_NAME}]🚨[4] Error:`, e.message);
              socket.destroy();
            }
          });
        } catch (e) {
          console.error(`[${MY_NAME}]🚨[1] Error:`, e.message);
          socket.destroy();
        }
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
        const [cmd, arg1, ...rest] = input.trim().split(' ');

        if (cmd === 'connect' && arg1) {
          this.connectToPeer('localhost', parseInt(arg1));
        } else if (cmd === 'broadcast') {
          const msgId = crypto.randomUUID();
          const text = [arg1, ...rest].join(' ');

          const broadcastObj = {
            id: msgId,
            origin: MY_NAME,
            text: text
          };

          console.log(`[${MY_NAME}] Starting broadcast: "${text}"`);
          this.broadcastMessage(broadcastObj);
        } else if (cmd.toLowerCase() === 'exit') {
          this.stop();
        } else if (this.isClient) {
          const chatMessage = encryptWithSessionKey(input, this.messageData.sessionKey);
          fragmentSend(this.messageData.client, JSON.stringify({ type: 'ENCRYPTED_DATA', message: chatMessage }) + '\n', `${MY_NAME}`);
          console.log(`\n[${MY_NAME}]📤 Send encrypted data: "${input}"`);
        } else {
          console.log(`[${MY_NAME}] Use: connect <port>, broadcast <text>`);
        }
      });

      this.rl.on('close', () => {
        console.log(`[${MY_NAME}] Readline interface closed.`);
      });
    }
  }

  connectToPeer(host, port) {
    console.log(`\n[${MY_NAME}]🔌 Initiating connection...`);
    
    const client = new net.Socket();

    const session = {
      sessionKey: null,
      clientRandom: null,
      serverRandom: null,
      premasterSecret: null,
    };

    client.connect(port, host, () => {
      this.isClient = true;
      console.log(`[${MY_NAME}]🔌 Successfully connected`);

      // Крок 1: Надсилання 'Client Hello'
      session.clientRandom = generateRandomString(32);
      const clientHello = { clientRandom: session.clientRandom.toString('base64') };

      console.log(`\n[${MY_NAME}]📤[1] Sending CLIENT HELLO`);
      console.log(`   Client Random: ${session.clientRandom.toString('base64').substring(0, 16)}...`);

      client.write(JSON.stringify(clientHello));

      console.log(`[${MY_NAME}]✅[1] Sent CLIENT HELLO`);

      // Крок 2: Отримання 'Server Hello'
      client.once('data', async (serverHelloData) => {
        try {
          const serverHello = JSON.parse(serverHelloData.toString());
          session.serverRandom = Buffer.from(serverHello.serverRandom, 'base64');
          const serverCertCheck = serverHello.certificatePem;
          console.log(`\n[${MY_NAME}]📨[2] Received SERVER HELLO + SSL Certificate`);
          console.log(`   Server Random: ${serverHello.serverRandom.toString('base64').substring(0, 16)}...`);
          console.log(`   Certificate S/N: \n${serverHello.certificatePem.substring(0, 300)}...`);

          //  Крок 3: Перевірка сертифіката в CA Server
          console.log(`\n[${MY_NAME}]🔐[3] Authentication - Verifying certificate with CA Server`);
          try {
            await this.checkCertValidity(serverCertCheck);
            console.log(`[${MY_NAME}]✅[3] Server certificate is valid`);
          } catch (e) {
            console.error(`[${MY_NAME}]🚨[3] VERIFICATION FAILED: ${e.message}!!!`);
            client.destroy();
            return;
          }


          // Крок 4: Генерація та відправка 'Premaster Secret'
          const serverCert = new crypto.X509Certificate(serverCertCheck);
          session.premasterSecret = generateRandomString(48);
          console.log(`\n[${MY_NAME}]🔑[4] Generating PREMASTER SECRET`);
          console.log(`   Premaster Secret: ${session.premasterSecret.toString('base64').substring(0, 16)}...`);

          const encryptedPremaster = encryptWithPublicKey(session.premasterSecret, serverCert.publicKey);

          const premasterMessage = {
            encryptedPremaster: encryptedPremaster,
          };

          console.log(`\n[${MY_NAME}]📤[4] Sending encrypted PREMASTER SECRET`);

          client.write(JSON.stringify(premasterMessage));

          console.log(`[${MY_NAME}]✅[4] Send encrypted PREMASTER SECRET`);

          // Крок 5: Генерація session key
          session.sessionKey = generateSessionKey(
            session.clientRandom,
            session.serverRandom,
            session.premasterSecret,
          );
          console.log(`\n[${MY_NAME}]✅[5] Session Key generated: ${session.sessionKey.toString('hex').substring(0, 16)}...`);

          // Крок 6: Відправка 'Client Finished' (зашифрованого session key)
          const finishedMessage = `${MY_NAME}: Finished`;
          const clientFinishedMsg = encryptWithSessionKey(finishedMessage, session.sessionKey);

          this.setupSecureChannel(client, session.sessionKey, 'Outbound');

          console.log(`\n[${MY_NAME}]📤[6] Sending encrypted CLIENT FINISHED`);
          fragmentSend(client, JSON.stringify({ type: 'FINISHED', message: clientFinishedMsg }) + '\n', `${MY_NAME}`);
          console.log(`[${MY_NAME}]✅[6] Sent CLIENT FINISHED`);
        } catch (e) {
          console.error(`[${MY_NAME}]🚨[2] Error:`, e.message);
          this.stop();
        }
      });
    });
  }

  checkCertValidity(serverCert) {
    return new Promise((resolve, reject) => {
      const caSocket = new net.Socket();

      caSocket.connect(CA_PORT, CA_HOST, () => {
        console.log(`[${MY_NAME}]🔌[3] Connected to CA Server on port ${CA_PORT}`);
        caSocket.write(serverCert);
      });

      caSocket.once('data', (caResponseData) => {
        const caResponse = caResponseData.toString();
        console.log(`[${MY_NAME}]📨[3] Received response from CA: "${caResponse}"`);
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
        console.error(`[${MY_NAME}]🚨[3] !!! VERIFICATION FAILED: ${err.message} !!!`);
        this.stop();
      });
    });
  }

  setupSecureChannel(socket, key, type) {
    let buffer = '';
    let peerName = 'Unknown Peer';
  
    socket.on('data', (chunk) => {
      buffer += chunk.toString();

      let idx;
      while ((idx = buffer.indexOf('\n')) !== -1) {
        const jsonStr = buffer.substring(0, idx);
        buffer = buffer.substring(idx + 1);
        if (!jsonStr) continue;
  
        try {
          console.log(`\n[${MY_NAME}]📨 Encrypted data received`);
          const packet = JSON.parse(jsonStr);
          const decrypted = decryptWithSessionKey(packet.message, key);

          if (packet.type === 'FINISHED') {
            if (decrypted.includes(': Finished')) {
              // Крок 6: Отримання 'Server Finished' (зашифрованого session key)
              console.log(`\n[${MY_NAME}]📨[6] Received encrypted SERVER FINISHED`);
              console.log(`[${MY_NAME}]🔐[6] Received SERVER FINISHED: "${decrypted}"`);

              peerName = decrypted.split(':')[0];

              console.log(`\n[${MY_NAME}]🔌 Connected to ${peerName} (${type})`);
              // Додаємо в активні піри
              activePeers.set(socket, { key: key, name: peerName });

              console.log('\n🎉 ========================================');
              console.log('✅ TLS/SSL HANDSHAKE COMPLETED!');
              console.log('🔒 Secure channel established');
              console.log('========================================\n');
              console.log('   💬 Enter a message or "exit" to exit\n');

              this.messageData.sessionKey = key;
              this.messageData.client = socket;

              this.rl.prompt();
            }
          }
          // Обробка звичайного чату
          else if (packet.type === 'ENCRYPTED_DATA') {
            console.log(`[Chat from ${peerName}]📄 Received answer: "${decrypted}"`);

            if (!decrypted.includes('received:') && !decrypted.startsWith('Node-')) {
              const reply = encryptWithSessionKey(`${MY_NAME} received: ${decrypted}`, key);

              fragmentSend(socket, JSON.stringify({ type: 'ENCRYPTED_DATA', message: reply }) + '\n', `${MY_NAME}`);
              console.log(`[${MY_NAME}]📤 Send encrypted data: "${MY_NAME} received: ${decrypted}"`);
            }

            this.rl.prompt();
          } else if (packet.type === 'BROADCAST') {
            const broadcastObj = JSON.parse(decrypted);
  
            if (seenMessages.has(broadcastObj.id)) {
              return;
            }
  
            seenMessages.add(broadcastObj.id);
            console.log(`\n[BROADCAST від ${broadcastObj.origin}]📄 Received answer: "${broadcastObj.text}"`);
  
            this.broadcastMessage(broadcastObj, socket);

            this.rl.prompt();
          }
        } catch (e) {
          console.error('❌ Decryption/Parsing error:', e.message);
        }
      }
    });

    socket.on('close', () => {
      console.log(`[${MY_NAME}]👋 Node ${peerName} disconnected\n`);
      this.isClient = false;
      this.messageData.sessionKey = null;
      this.messageData.client = null;
    });

    socket.on('error', (err) => {
      console.error(`[${MY_NAME}]❌ Error:`, err.message);
      this.isClient = false;
      this.closeReadline();
    });
  }

  broadcastMessage(originalMsgObj, excludeSocket = null) {
    if (!seenMessages.has(originalMsgObj.id)) {
      seenMessages.add(originalMsgObj.id);
    }
  
    console.log(`[${MY_NAME}]🌍 Routing message ${originalMsgObj.id} to ${activePeers.size} peers...`);

    for (const [peerSocket, peerData] of activePeers) {
      if (peerSocket === excludeSocket) continue;

      try {
        const encryptedContent = encryptWithSessionKey(JSON.stringify(originalMsgObj), peerData.key);
  
        const packet = JSON.stringify({ type: 'BROADCAST', message: encryptedContent }) + '\n';
  
        fragmentSend(peerSocket, packet, `${MY_NAME} => ${peerData.name}`);
      } catch (e) {
        console.error(`❌ Error sending to ${peerData.name}:`, e.message);
      }
    }
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
      });
    }
    process.exit(0);
  }
}

// Запуск ноди
const node = new Node();
node.start();
