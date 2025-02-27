/**
 * Qala Client Example
 */
const Qala = require('./lib/qala.js');

// Create client
const client = Qala.engage({
  serverUrl: 'http://localhost:3000',
  accessSecret: 'shared_access_secret_between_client_and_server'
});

async function main() {
  try {
    // Connect to server (handshake)
    console.log('Connecting to server...');
    await client.connect();
    console.log('Connected successfully!');

    // Get a secret value
    console.log('Requesting API_KEY...');
    const apiKey = await client.get('API_KEY');
    console.log('API_KEY:', apiKey);

    // Get another secret value
    console.log('Requesting DATABASE_URL...');
    const dbUrl = await client.get('DATABASE_URL');
    console.log('DATABASE_URL:', dbUrl);

    // Renew token
    console.log('Renewing token...');
    await client.renewToken();
    console.log('Token renewed successfully!');

    // Get one more value with the new token
    console.log('Requesting JWT_SECRET...');
    const jwtSecret = await client.get('JWT_SECRET');
    console.log('JWT_SECRET:', jwtSecret);

  } catch (error) {
    console.error('Error:', error.message);
  }
}

main();
