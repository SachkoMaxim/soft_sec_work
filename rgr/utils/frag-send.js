const MAX_CHUNK_SIZE = 14;
const CHUNK_DELAY = 100;

const fragmentSend = (socket, data, loggerName) => {
  let i = 0;

  const intervalId = setInterval(() => {
    if (i >= data.length) {
      clearInterval(intervalId);
      return;
    }

    const chunk = data.substring(i, i + MAX_CHUNK_SIZE);
    i += MAX_CHUNK_SIZE;

    console.log(`[${loggerName}]🐌[slow mode]⌛ sending ${chunk.length} bytes...`);

    socket.write(chunk);
  }, CHUNK_DELAY);
};

module.exports = { fragmentSend };