# Qala

A minimalistic secure environment variables and secrets keeper.

[![npm version](https://img.shields.io/npm/v/qala.svg)](https://www.npmjs.com/package/qala)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

## Features

- 🔐 Encrypted storage of sensitive data
- 🔑 JWT-based authentication
- 🔒 ECC-based secure communication
- 🚀 Multiple operation modes (standalone, integrated, or env)
- 🐳 Docker-ready and easy to deploy

## Installation

```bash
npm install qala
```

## Usage

Qala can be used in three different modes:

### 1. ENV Mode (Simplest)

Access your secrets directly via `process.env` with zero configuration:

```javascript
const Qala = require('qala');

// Initialize Qala in ENV mode
await Qala.init();

// Now use environment variables directly
const apiKey = process.env.API_KEY;
const dbUrl = process.env.DATABASE_URL;

// Your application code
connectToDatabase(dbUrl);
authenticateWithApi(apiKey);
```

### 2. Standalone Mode (Server + Client)

Run a dedicated Qala server:

```javascript
// server.js
const Qala = require('qala');
const fs = require('fs');

// Define your secrets
const secrets = {
  API_KEY: "your_api_key",
  DATABASE_URL: "your_database_url",
  // Add more secrets as needed
};

// Save to data file
fs.writeFileSync('./data.json', JSON.stringify(secrets, null, 2));

// Create and start server
const server = Qala.guard({
  mode: 'standalone',
  port: 3000,
  dataPath: './data.json',
  accessSecret: 'your_shared_access_secret'
});

server.init();
```

Then use a client to access secrets from any application:

```javascript
// client.js
const Qala = require('qala');

// Create client
const client = Qala.engage({
  serverUrl: 'http://localhost:3000',
  accessSecret: 'your_shared_access_secret'
});

async function main() {
  // Connect to server
  await client.connect();

  // Get secrets
  const apiKey = await client.get('API_KEY');
  const dbUrl = await client.get('DATABASE_URL');

  // Use the secrets in your application
  console.log(`Connected to database at ${dbUrl}`);
}

main();
```

### 3. Integrated Mode

Embed Qala directly into your Express application:

```javascript
const express = require('express');
const Qala = require('qala');

// Create express app
const app = express();

// Add your routes
app.get('/', (req, res) => {
  res.send('Application is running!');
});

// Initialize Qala in integrated mode
const qala = Qala.guard({
  mode: 'integrated',
  dataPath: './data.json',
  accessSecret: 'your_shared_access_secret',
  server: app
});

// Initialize Qala and start the server
qala.init()
  .then(() => {
    app.listen(3000, () => {
      console.log('Application running with Qala integrated mode');
    });
  });
```

## Docker Deployment

Qala includes Docker support for easy deployment:

```bash
# Clone the repository
git clone https://github.com/your-username/qala.git
cd qala

# Run the deployment script
./deploy.sh standalone  # or integrated, env, all
```

## Security

Qala employs multiple layers of security:

- **ECC-based key exchange** (secp256k1 curve)
- **AES-256-GCM** for encryption of all data
- **JWT authentication** with token expiration
- **IP verification** to prevent token theft
- **Secure storage** with encrypted backup files

## API Reference

### Server (Qala.guard)

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| mode | string | 'standalone' | Operation mode ('standalone' or 'integrated') |
| port | number | 3000 | Server port (standalone mode only) |
| securityLevel | string | 'prod' | Security level ('dev' or 'prod') |
| dataPath | string | './data.json' | Path to data file |
| accessSecret | string | -
