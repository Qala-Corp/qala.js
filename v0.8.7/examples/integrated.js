/**
 * Qala Integrated Mode Example
 */
const express = require('express');
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

// Create express app
const app = express();

// Create Qala server in integrated mode
const server = Qala.guard({
  mode: 'integrated',
  securityLevel: 'prod',
  dataPath: path.join(process.cwd(), './data.json'),
  accessSecret: 'shared_access_secret_between_client_and_server',
  server: app
});

// Add other routes to your express app
app.get('/', (req, res) => {
  res.send('Main application is running!');
});

// Initialize Qala
server.init()
  .then(() => {
    console.log('Qala initialized in integrated mode');

    // Start the express server
    app.listen(3000, () => {
      console.log('Integrated server running on port 3000');
    });
  })
  .catch(err => {
    console.error('Failed to initialize Qala:', err);
  });s
