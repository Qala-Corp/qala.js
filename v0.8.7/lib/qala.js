/**
 * Qalá v0.8.7
 * A discrete secure environment variables and secrets keeper.
 *
 * Features:
 * - Encrypted storage of sensitive data
 * - JWT-based authentication
 * - ECC-based secure communication
 * - Supports standalone, integrated, or env mode
 *
 * @license GNU GPLv3
 */

const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const http = require('http');
const https = require('https');
const jwt = require('jsonwebtoken');

// Constants
const TOKEN_LIFETIME = 3600; // 1 hour in seconds
const DEFAULT_DATA_PATH = path.join(process.cwd(), './data.json');
const DEFAULT_PORT = 3000;

/**
 * Crypto utility functions
 */
const Crypto = {
  // Generate ECDH keypair using secp256k1 curve
  generateKeyPair() {
    const ecdh = crypto.createECDH('secp256k1');
    ecdh.generateKeys();
    return {
      privateKey: ecdh.getPrivateKey('hex'),
      publicKey: ecdh.getPublicKey('hex')
    };
  },

  // Derive shared secret using ECDH
  deriveSharedSecret(privateKey, otherPublicKey) {
    const ecdh = crypto.createECDH('secp256k1');
    ecdh.setPrivateKey(Buffer.from(privateKey, 'hex'));
    return ecdh.computeSecret(Buffer.from(otherPublicKey, 'hex'));
  },

  // Derive encryption key using HKDF
  deriveKey(sharedSecret) {
    return crypto.createHash('sha256').update(sharedSecret).digest();
  },

  // Encrypt data using AES-256-GCM
  encrypt(data, key) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    let encrypted = cipher.update(typeof data === 'string' ? data : JSON.stringify(data), 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag();
    return {
      iv: iv.toString('hex'),
      encrypted,
      authTag: authTag.toString('hex')
    };
  },

  // Decrypt data using AES-256-GCM
  decrypt(encryptedData, key) {
    const iv = Buffer.from(encryptedData.iv, 'hex');
    const authTag = Buffer.from(encryptedData.authTag, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);
    let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    try {
      return JSON.parse(decrypted);
    } catch (e) {
      return decrypted;
    }
  },

  // Generate a random token
  generateToken() {
    return crypto.randomBytes(32).toString('hex');
  },

  // Create JWT token
  createToken(payload, secret) {
    return jwt.sign(payload, secret, { expiresIn: TOKEN_LIFETIME });
  },

  // Verify JWT token
  verifyToken(token, secret) {
    try {
      return jwt.verify(token, secret);
    } catch (err) {
      return null;
    }
  }
};

/**
 * Qala Server
 */
class QalaServer {
  /**
   * Constructor for Qala Server
   * @param {Object} options - Configuration options
   */
  constructor(options = {}) {
    this.options = {
      mode: options.mode || 'standalone',
      port: options.port || DEFAULT_PORT,
      securityLevel: options.securityLevel || 'prod',
      dataPath: options.dataPath || DEFAULT_DATA_PATH,
      accessSecret: options.accessSecret || Crypto.generateToken(),
      server: options.server || null,
      httpsOptions: options.httpsOptions || null
    };

    this.sessions = {};
    this.data = null;
    this.encryptedDataPath = this.options.dataPath.replace('.json', '.enc.json');
    this.keys = Crypto.generateKeyPair();
    this.app = null;
    this.httpServer = null;
  }

  /**
   * Initialize the server
   */
  async init() {
    try {
      await this.loadData();

      if (this.options.mode === 'standalone') {
        this.app = express();
        this.setupMiddleware(this.app);
        this.setupRoutes(this.app);
        this.startServer();
      } else {
        // Integrated mode
        if (!this.options.server) {
          throw new Error('Server instance required for integrated mode');
        }
        this.setupMiddleware(this.options.server);
        this.setupRoutes(this.options.server);
      }

      return true;
    } catch (error) {
      console.error('Qala initialization failed:', error);
      throw error;
    }
  }

  /**
   * Load data from file
   */
  async loadData() {
    try {
      // Try to load the original data file
      const dataExists = await this.fileExists(this.options.dataPath);

      if (dataExists) {
        const content = await fs.readFile(this.options.dataPath, 'utf8');
        this.data = JSON.parse(content);

        // Encrypt the data
        const encryptionKey = Crypto.generateToken();
        const encryptedData = Crypto.encrypt(this.data, Buffer.from(encryptionKey, 'hex'));

        // Store the encryption key with the encrypted data
        const savedData = {
          key: encryptionKey,
          data: encryptedData
        };

        await fs.writeFile(this.encryptedDataPath, JSON.stringify(savedData), 'utf8');

        // Delete original file in production mode
        if (this.options.securityLevel !== 'dev') {
          await fs.unlink(this.options.dataPath);
        }
      } else {
        // Load from encrypted file
        const encryptedContent = await fs.readFile(this.encryptedDataPath, 'utf8');
        const savedData = JSON.parse(encryptedContent);
        this.data = Crypto.decrypt(savedData.data, Buffer.from(savedData.key, 'hex'));
      }
    } catch (error) {
      console.error('Error loading data:', error);
      // Initialize with empty data if file doesn't exist
      this.data = {};
    }
  }

  /**
   * Check if file exists
   * @param {string} filePath - Path to check
   */
  async fileExists(filePath) {
    try {
      await fs.access(filePath);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Setup middleware
   * @param {Object} app - Express app
   */
  setupMiddleware(app) {
    app.use(express.json());
  }

  /**
   * Setup routes
   * @param {Object} app - Express app
   */
  setupRoutes(app) {
    // Handshake route
    app.post('/meet', (req, res) => {
      const { accessSecret, publicKey } = req.body;

      if (accessSecret !== this.options.accessSecret) {
        return res.status(401).json({ error: 'Unauthorized' });
      }

      const clientIp = req.ip || '0.0.0.0';
      const sessionId = Crypto.generateToken();
      const token = Crypto.createToken({ sessionId, ip: clientIp }, this.options.accessSecret);

      this.sessions[sessionId] = {
        publicKey,
        ip: clientIp,
        createdAt: Date.now()
      };

      return res.json({
        token,
        publicKey: this.keys.publicKey
      });
    });

    // Data route
    app.post('/data', (req, res) => {
      const authHeader = req.headers.authorization;

      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Token required' });
      }

      const token = authHeader.slice(7);
      const decoded = Crypto.verifyToken(token, this.options.accessSecret);

      if (!decoded) {
        return res.status(401).json({ error: 'Invalid token' });
      }

      const session = this.sessions[decoded.sessionId];

      if (!session) {
        return res.status(401).json({ error: 'Invalid session' });
      }

      const clientIp = req.ip || '0.0.0.0';

      if (decoded.ip !== clientIp) {
        return res.status(401).json({ error: 'IP mismatch' });
      }

      const sharedSecret = Crypto.deriveSharedSecret(this.keys.privateKey, session.publicKey);
      const encryptionKey = Crypto.deriveKey(sharedSecret);

      try {
        const encryptedRequest = req.body;
        const { key } = Crypto.decrypt(encryptedRequest, encryptionKey);

        if (!key || !this.data[key]) {
          const response = { error: 'Key not found' };
          const encryptedResponse = Crypto.encrypt(response, encryptionKey);
          return res.status(404).json(encryptedResponse);
        }

        const response = { value: this.data[key] };
        const encryptedResponse = Crypto.encrypt(response, encryptionKey);
        return res.json(encryptedResponse);
      } catch (error) {
        console.error('Error processing data request:', error);
        const response = { error: 'Invalid request format' };
        const encryptedResponse = Crypto.encrypt(response, encryptionKey);
        return res.status(400).json(encryptedResponse);
      }
    });

    // Renew token route
    app.post('/renew', (req, res) => {
      const authHeader = req.headers.authorization;

      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Token required' });
      }

      const token = authHeader.slice(7);
      const decoded = Crypto.verifyToken(token, this.options.accessSecret);

      if (!decoded) {
        return res.status(401).json({ error: 'Invalid token' });
      }

      const session = this.sessions[decoded.sessionId];

      if (!session) {
        return res.status(401).json({ error: 'Invalid session' });
      }

      const clientIp = req.ip || '0.0.0.0';

      if (decoded.ip !== clientIp) {
        return res.status(401).json({ error: 'IP mismatch' });
      }

      // Create a new token
      const newToken = Crypto.createToken({ sessionId: decoded.sessionId, ip: clientIp }, this.options.accessSecret);

      return res.json({ token: newToken });
    });
  }

  /**
   * Start server (standalone mode)
   */
  startServer() {
    const { port, httpsOptions } = this.options;

    if (httpsOptions) {
      const key = fs.readFileSync(httpsOptions.key);
      const cert = fs.readFileSync(httpsOptions.cert);
      this.httpServer = https.createServer({ key, cert }, this.app);
    } else {
      this.httpServer = http.createServer(this.app);
    }

    this.httpServer.listen(port, () => {
      console.log(`Qala server running on port ${port}`);
    });
  }

  /**
   * Stop server
   */
  stop() {
    if (this.httpServer) {
      this.httpServer.close();
    }
  }
}

/**
 * Qala Client
 */
class QalaClient {
  /**
   * Constructor for Qala Client
   * @param {Object} options - Configuration options
   */
  constructor(options = {}) {
    this.options = {
      serverUrl: options.serverUrl || 'http://localhost:' + DEFAULT_PORT,
      accessSecret: options.accessSecret
    };

    this.token = null;
    this.keys = Crypto.generateKeyPair();
    this.serverPublicKey = null;
    this.sharedSecret = null;
    this.encryptionKey = null;
    this.cache = {};
  }

  /**
   * Initialize connection with server
   */
  async connect() {
    try {
      const response = await this.request('/meet', {
        accessSecret: this.options.accessSecret,
        publicKey: this.keys.publicKey
      });

      this.token = response.token;
      this.serverPublicKey = response.publicKey;
      this.sharedSecret = Crypto.deriveSharedSecret(this.keys.privateKey, this.serverPublicKey);
      this.encryptionKey = Crypto.deriveKey(this.sharedSecret);

      return true;
    } catch (error) {
      console.error('Connection failed:', error);
      throw error;
    }
  }

  /**
   * Get value from server
   * @param {string} key - Key to retrieve
   */
  async get(key) {
    if (!this.token || !this.encryptionKey) {
      throw new Error('Not connected. Call connect() first');
    }

    // Check cache first
    if (this.cache[key]) {
      return this.cache[key];
    }

    try {
      const encryptedRequest = Crypto.encrypt({ key }, this.encryptionKey);
      const encryptedResponse = await this.request('/data', encryptedRequest, true);
      const response = Crypto.decrypt(encryptedResponse, this.encryptionKey);

      if (response.error) {
        throw new Error(response.error);
      }

      // Cache the result
      this.cache[key] = response.value;
      return response.value;
    } catch (error) {
      console.error('Get operation failed:', error);
      throw error;
    }
  }

  /**
   * Renew token
   */
  async renewToken() {
    if (!this.token) {
      throw new Error('Not connected. Call connect() first');
    }

    try {
      const response = await this.request('/renew', {}, true);
      this.token = response.token;
      return true;
    } catch (error) {
      console.error('Token renewal failed:', error);
      throw error;
    }
  }

  /**
   * Make HTTP request to server
   * @param {string} endpoint - API endpoint
   * @param {Object} data - Request data
   * @param {boolean} authenticated - Whether to include auth token
   */
  async request(endpoint, data, authenticated = false) {
    const url = `${this.options.serverUrl}${endpoint}`;
    const headers = {
      'Content-Type': 'application/json'
    };

    if (authenticated && this.token) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }

    try {
      const response = await fetch(url, {
        method: 'POST',
        headers,
        body: JSON.stringify(data)
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || 'Request failed');
      }

      return await response.json();
    } catch (error) {
      console.error(`Request to ${endpoint} failed:`, error);
      throw error;
    }
  }
}

/**
 * Qala Environment Mode
 * Transparently syncs with server and provides values through process.env
 */
class QalaEnv {
  constructor() {
    this.server = null;
    this.client = null;
    this.accessSecret = Crypto.generateToken();
    this.initialized = false;
    this.dataPath = DEFAULT_DATA_PATH;
    this.port = DEFAULT_PORT;
    this.isInitializing = false;
    this.envProxy = null;
  }

  /**
   * Initialize the environment mode
   */
  async init() {
    if (this.initialized || this.isInitializing) {
      return;
    }

    this.isInitializing = true;

    try {
      // Start server
      this.server = new QalaServer({
        mode: 'standalone',
        port: this.port,
        dataPath: this.dataPath,
        accessSecret: this.accessSecret
      });

      await this.server.init();

      // Initialize client
      this.client = new QalaClient({
        serverUrl: `http://localhost:${this.port}`,
        accessSecret: this.accessSecret
      });

      await this.client.connect();

      // Setup environment proxy
      this.setupEnvProxy();

      this.initialized = true;
      this.isInitializing = false;

      return true;
    } catch (error) {
      this.isInitializing = false;
      console.error('Failed to initialize Qala ENV mode:', error);
      throw error;
    }
  }

  /**
   * Setup proxy for process.env
   */
  setupEnvProxy() {
    const originalEnv = process.env;
    const client = this.client;

    // Create proxy for process.env
    this.envProxy = new Proxy(originalEnv, {
      get: function(target, prop) {
        // If it's a built-in property or method, return it
        if (prop in target) {
          return target[prop];
        }

        // Otherwise try to get from Qala
        try {
          // Get the value asynchronously, but return promise result synchronously
          const value = client.cache[prop];
          if (value !== undefined) {
            return value;
          }

          // Start async fetch but don't block
          client.get(prop).then(value => {
            // Value will be cached by client.get
          }).catch(err => {
            // Silently fail
          });

          return undefined;
        } catch (error) {
          return undefined;
        }
      }
    });

    // Replace process.env with our proxy
    process.env = this.envProxy;
  }

  /**
   * Set default data path
   * @param {string} path - Path to data file
   */
  setDataPath(path) {
    if (!this.initialized) {
      this.dataPath = path;
    }
    return this;
  }

  /**
   * Set port for server
   * @param {number} port - Port number
   */
  setPort(port) {
    if (!this.initialized) {
      this.port = port;
    }
    return this;
  }
}

// Singleton instance for ENV mode
const qalaEnvInstance = new QalaEnv();

/**
 * Main Qala class - Factory for client and server
 */
class Qala {
  /**
   * Create a Qala server
   * @param {Object} options - Server options
   */
  static guard(options = {}) {
    return new QalaServer(options);
  }

  /**
   * Create a Qala client
   * @param {Object} options - Client options
   */
  static engage(options = {}) {
    return new QalaClient(options);
  }

  /**
   * Initialize Qala in ENV mode
   * @param {Object} options - Optional configuration
   * @return {Promise} Resolves when initialization is complete
   */
  static async init(options = {}) {
    if (options.dataPath) {
      qalaEnvInstance.setDataPath(options.dataPath);
    }

    if (options.port) {
      qalaEnvInstance.setPort(options.port);
    }

    return qalaEnvInstance.init();
  }
}

module.exports = Qala;
