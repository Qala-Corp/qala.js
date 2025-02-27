/**
 * Qala Server Example
 */
const Qala = require('./lib/qala.js');
const fs = require('fs');

// Sample data file (data.json)
const sampleData = {
  API_KEY: "sample_api_key_12345",
  DATABASE_URL: "postgres://username:password@localhost:5432/mydb",
  JWT_SECRET: "very_secure_jwt_secret_for_my_application",
  AWS_ACCESS_KEY: "AKIAIOSFODNN7EXAMPLE",
  AWS_SECRET_KEY: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
};

// Save sample data to file for first run
fs.writeFileSync(path.join(process.cwd(), './data.json'), JSON.stringify(sampleData, null, 2));

// Create server in standalone mode
const server = Qala.guard({
  mode: 'standalone',
  port: 3000,
  securityLevel: 'prod',
  dataPath: path.join(process.cwd(), './data.json'),
  accessSecret: 'shared_access_secret_between_client_and_server'
});

// Initialize server
server.init()
  .then(() => {
    console.log('Server initialized successfully');
  })
  .catch(err => {
    console.error('Failed to initialize server:', err);
  });
