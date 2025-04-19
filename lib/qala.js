#!/usr/bin/env node

/**
 * Qalá v0.9.0
 * A discrete secure environment variables and secrets keeper.
 *
 * Features:
 * - Please follow url to learn: https://qala.vercel.com/features
 *
 * @license GNU GPLv3
 */


const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const os = require('os');
const readline = require('readline');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const dotenv = require('dotenv');
const commander = require('commander');
const chalk = require('chalk');

// Constants
const QALA_DIR = path.join(os.homedir(), '.qala');
const QALA_CONFIG = path.join(QALA_DIR, 'config.json');
const QALA_SESSION = path.join(QALA_DIR, 'session.enc');
const API_URL = 'https://api.qala-security.com';
const JWT_SECRET = 'qala-jwt-secret'; // Should be environment-specific in production

// Ensure Qala directory exists
if (!fs.existsSync(QALA_DIR)) {
  fs.mkdirSync(QALA_DIR, { recursive: true });
}

// Cryptography utilities
const CryptoUtils = {
  // Generate ECC key pair (secp256k1)
  generateKeyPair() {
    return crypto.generateKeyPairSync('ec', {
      namedCurve: 'secp256k1',
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });
  },

  // Derive shared secret using ECDH
  deriveSharedSecret(privateKey, publicKey) {
    const ecdh = crypto.createECDH('secp256k1');
    ecdh.setPrivateKey(
      crypto.createPrivateKey(privateKey).export({ type: 'pkcs8', format: 'der' }).slice(36)
    );
    const pubKeyObj = crypto.createPublicKey(publicKey);
    const pubKeyDer = pubKeyObj.export({ type: 'spki', format: 'der' });
    return ecdh.computeSecret(pubKeyDer.slice(27));
  },

  // Derive encryption key using HKDF
  deriveEncryptionKey(sharedSecret, salt, info = 'qala-encryption') {
    return crypto.hkdfSync('sha256', sharedSecret, salt, info, 32);
  },

  // Encrypt data using AES-256-GCM
  encrypt(data, key) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([cipher.update(data, 'utf8'), cipher.final()]);
    const authTag = cipher.getAuthTag();
    return {
      iv: iv.toString('hex'),
      encrypted: encrypted.toString('hex'),
      authTag: authTag.toString('hex')
    };
  },

  // Decrypt data using AES-256-GCM
  decrypt(data, key) {
    const iv = Buffer.from(data.iv, 'hex');
    const encrypted = Buffer.from(data.encrypted, 'hex');
    const authTag = Buffer.from(data.authTag, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);
    return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8');
  },

  // Create password hash
  hashPassword(password, salt = crypto.randomBytes(16)) {
    const hash = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512');
    return {
      salt: salt.toString('hex'),
      hash: hash.toString('hex')
    };
  },

  // Verify password against hash
  verifyPassword(password, storedHash, storedSalt) {
    const salt = Buffer.from(storedSalt, 'hex');
    const hash = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
    return hash === storedHash;
  }
};

// Session management
const Session = {
  // Load session data
  load() {
    try {
      if (!fs.existsSync(QALA_SESSION)) {
        return null;
      }

      const sessionKey = this.getSessionKey();
      if (!sessionKey) return null;

      const encData = JSON.parse(fs.readFileSync(QALA_SESSION, 'utf8'));
      const sessionData = CryptoUtils.decrypt(encData, sessionKey);
      return JSON.parse(sessionData);
    } catch (error) {
      return null;
    }
  },

  // Save session data
  save(data) {
    const sessionKey = this.getSessionKey();
    const encData = CryptoUtils.encrypt(JSON.stringify(data), sessionKey);
    fs.writeFileSync(QALA_SESSION, JSON.stringify(encData), 'utf8');
  },

  // Clear session data
  clear() {
    if (fs.existsSync(QALA_SESSION)) {
      fs.unlinkSync(QALA_SESSION);
    }
  },

  // Get session encryption key (derived from machine-specific data)
  getSessionKey() {
    // Using machine-id or similar would be better in production
    const machineInfo = os.hostname() + os.userInfo().username;
    return crypto.createHash('sha256').update(machineInfo).digest();
  }
};

// API client for Qala service communication
class QalaAPI {
  constructor(apiKey = null) {
    this.apiKey = apiKey;
    this.token = null;
    this.client = axios.create({
      baseURL: API_URL,
      timeout: 10000
    });

    // Set up interceptors for JWT authentication
    this.client.interceptors.request.use(config => {
      if (this.token) {
        config.headers.Authorization = `Bearer ${this.token}`;
      }
      return config;
    });
  }

  // Set JWT token
  setToken(token) {
    this.token = token;
  }

  // Login with email/password
  async login(email, password) {
    try {
      const response = await this.client.post('/auth/login', { email, password });
      this.token = response.data.token;
      return response.data;
    } catch (error) {
      throw new Error(`Login failed: ${error.response?.data?.message || error.message}`);
    }
  }

  // Login with API key
  async loginWithApiKey(apiKey) {
    try {
      this.apiKey = apiKey;
      const response = await this.client.post('/auth/token', { apiKey });
      this.token = response.data.token;
      return response.data;
    } catch (error) {
      throw new Error(`API key login failed: ${error.response?.data?.message || error.message}`);
    }
  }

  // Get user profile
  async getProfile() {
    try {
      const response = await this.client.get('/user/profile');
      return response.data;
    } catch (error) {
      throw new Error(`Failed to get profile: ${error.response?.data?.message || error.message}`);
    }
  }

  // List projects
  async listProjects() {
    try {
      const response = await this.client.get('/projects');
      return response.data;
    } catch (error) {
      throw new Error(`Failed to list projects: ${error.response?.data?.message || error.message}`);
    }
  }

  // Create new project
  async createProject(name, description = '') {
    try {
      const response = await this.client.post('/projects', { name, description });
      return response.data;
    } catch (error) {
      throw new Error(`Failed to create project: ${error.response?.data?.message || error.message}`);
    }
  }

  // Get project details
  async getProject(projectId) {
    try {
      const response = await this.client.get(`/projects/${projectId}`);
      return response.data;
    } catch (error) {
      throw new Error(`Failed to get project: ${error.response?.data?.message || error.message}`);
    }
  }

  // List environments for a project
  async listEnvironments(projectId) {
    try {
      const response = await this.client.get(`/projects/${projectId}/environments`);
      return response.data;
    } catch (error) {
      throw new Error(`Failed to list environments: ${error.response?.data?.message || error.message}`);
    }
  }

  // Create environment
  async createEnvironment(projectId, name) {
    try {
      const response = await this.client.post(`/projects/${projectId}/environments`, { name });
      return response.data;
    } catch (error) {
      throw new Error(`Failed to create environment: ${error.response?.data?.message || error.message}`);
    }
  }

  // List secrets for an environment
  async listSecrets(projectId, environment) {
    try {
      const response = await this.client.get(`/projects/${projectId}/environments/${environment}/secrets`);
      return response.data;
    } catch (error) {
      throw new Error(`Failed to list secrets: ${error.response?.data?.message || error.message}`);
    }
  }

  // Get a specific secret
  async getSecret(projectId, environment, secretName) {
    try {
      const response = await this.client.get(`/projects/${projectId}/environments/${environment}/secrets/${secretName}`);
      return response.data;
    } catch (error) {
      throw new Error(`Failed to get secret: ${error.response?.data?.message || error.message}`);
    }
  }

  // Create or update a secret
  async setSecret(projectId, environment, secretName, value, description = '') {
    try {
      // In production, this would use end-to-end encryption
      const response = await this.client.put(
        `/projects/${projectId}/environments/${environment}/secrets/${secretName}`,
        { value, description }
      );
      return response.data;
    } catch (error) {
      throw new Error(`Failed to set secret: ${error.response?.data?.message || error.message}`);
    }
  }

  // Delete a secret
  async deleteSecret(projectId, environment, secretName) {
    try {
      await this.client.delete(`/projects/${projectId}/environments/${environment}/secrets/${secretName}`);
      return true;
    } catch (error) {
      throw new Error(`Failed to delete secret: ${error.response?.data?.message || error.message}`);
    }
  }

  // Log secret access
  async logAccess(projectId, environment, secretName, action = 'read') {
    try {
      await this.client.post(`/projects/${projectId}/logs`, {
        environment,
        secretName,
        action,
        timestamp: new Date().toISOString()
      });
      return true;
    } catch (error) {
      console.warn(`Failed to log access: ${error.message}`);
      return false; // Non-critical error, don't throw
    }
  }

  // Rotate secret
  async rotateSecret(projectId, environment, secretName) {
    try {
      const response = await this.client.post(
        `/projects/${projectId}/environments/${environment}/secrets/${secretName}/rotate`
      );
      return response.data;
    } catch (error) {
      throw new Error(`Failed to rotate secret: ${error.response?.data?.message || error.message}`);
    }
  }
}

// Qala Vault for local secret management
class QalaVault {
  constructor(projectId, environment) {
    this.projectId = projectId;
    this.environment = environment;
    this.vaultPath = path.join(QALA_DIR, `vault-${projectId}-${environment}.enc`);
    this.keyPath = path.join(QALA_DIR, `vault-${projectId}-${environment}.key`);
    this.secrets = null;
    this.locked = true;
    this.encryptionKey = null;
  }

  // Initialize the vault
  init() {
    if (!fs.existsSync(this.keyPath)) {
      // Generate a strong random key for vault encryption
      const key = crypto.randomBytes(32);
      fs.writeFileSync(this.keyPath, key.toString('hex'), 'utf8');
    }

    if (!fs.existsSync(this.vaultPath)) {
      this.secrets = {};
      this.save();
    }
  }

  // Unlock the vault for use
  unlock() {
    if (!this.locked) return true;

    try {
      const keyHex = fs.readFileSync(this.keyPath, 'utf8');
      this.encryptionKey = Buffer.from(keyHex, 'hex');

      if (fs.existsSync(this.vaultPath)) {
        const encData = JSON.parse(fs.readFileSync(this.vaultPath, 'utf8'));
        const decrypted = CryptoUtils.decrypt(encData, this.encryptionKey);
        this.secrets = JSON.parse(decrypted);
      } else {
        this.secrets = {};
      }

      this.locked = false;
      return true;
    } catch (error) {
      console.error(`Failed to unlock vault: ${error.message}`);
      return false;
    }
  }

  // Lock the vault
  lock() {
    this.secrets = null;
    this.encryptionKey = null;
    this.locked = true;
  }

  // Save current secrets to disk
  save() {
    if (this.locked) throw new Error('Vault is locked');

    const encData = CryptoUtils.encrypt(JSON.stringify(this.secrets), this.encryptionKey);
    fs.writeFileSync(this.vaultPath, JSON.stringify(encData), 'utf8');
  }

  // Get all secrets
  getAllSecrets() {
    if (this.locked) throw new Error('Vault is locked');
    return { ...this.secrets };
  }

  // Get a specific secret
  getSecret(name) {
    if (this.locked) throw new Error('Vault is locked');
    return this.secrets[name];
  }

  // Set a secret
  setSecret(name, value, description = '') {
    if (this.locked) throw new Error('Vault is locked');

    this.secrets[name] = {
      value,
      description,
      updatedAt: new Date().toISOString()
    };

    this.save();
    return true;
  }

  // Delete a secret
  deleteSecret(name) {
    if (this.locked) throw new Error('Vault is locked');
    if (!this.secrets[name]) return false;

    delete this.secrets[name];
    this.save();
    return true;
  }

  // Export secrets as .env format
  exportAsEnv() {
    if (this.locked) throw new Error('Vault is locked');

    let envContent = '';
    for (const [key, data] of Object.entries(this.secrets)) {
      // Escape special characters
      const value = data.value.replace(/\n/g, '\\n').replace(/"/g, '\\"');
      envContent += `${key}="${value}"\n`;
    }

    return envContent;
  }

  // Import from .env format
  importFromEnv(content) {
    if (this.locked) throw new Error('Vault is locked');

    const parsed = dotenv.parse(content);
    for (const [key, value] of Object.entries(parsed)) {
      this.setSecret(key, value);
    }

    return Object.keys(parsed).length;
  }
}

// Main Qala client for application integration
class QalaClient {
  constructor(options = {}) {
    this.projectId = options.projectId;
    this.environment = options.environment || 'development';
    this.keyPath = options.keyPath;
    this.apiUrl = options.apiUrl || API_URL;
    this.apiKey = options.apiKey;
    this.token = null;
    this.vault = null;

    if (this.projectId) {
      this.vault = new QalaVault(this.projectId, this.environment);
    }
  }

  // Authenticate with Qala service
  async authenticate(options = {}) {
    const api = new QalaAPI();

    if (options.apiKey || this.apiKey) {
      await api.loginWithApiKey(options.apiKey || this.apiKey);
    } else if (options.email && options.password) {
      await api.login(options.email, options.password);
    } else {
      throw new Error('Authentication requires either apiKey or email/password');
    }

    this.token = api.token;
    return true;
  }

  // Initialize the client
  async init() {
    if (!this.projectId) {
      throw new Error('Project ID is required for initialization');
    }

    if (!this.vault) {
      this.vault = new QalaVault(this.projectId, this.environment);
    }

    this.vault.init();
    return this.vault.unlock();
  }

  // Get a secret
  async getSecret(name) {
    if (!this.vault) throw new Error('Client not initialized');
    if (this.vault.locked) await this.init();

    const secret = this.vault.getSecret(name);
    if (!secret) return null;

    // Log access to the server
    try {
      const api = new QalaAPI();
      api.setToken(this.token);
      await api.logAccess(this.projectId, this.environment, name);
    } catch (error) {
      console.warn(`Failed to log access: ${error.message}`);
    }

    return secret.value;
  }

  // Set a secret
  async setSecret(name, value, description = '') {
    if (!this.vault) throw new Error('Client not initialized');
    if (this.vault.locked) await this.init();

    // Sync with server
    if (this.token) {
      const api = new QalaAPI();
      api.setToken(this.token);
      await api.setSecret(this.projectId, this.environment, name, value, description);
    }

    return this.vault.setSecret(name, value, description);
  }

  // Get all secrets
  async getAllSecrets() {
    if (!this.vault) throw new Error('Client not initialized');
    if (this.vault.locked) await this.init();

    const secrets = this.vault.getAllSecrets();
    const result = {};

    // Convert to simple key-value format
    for (const [key, data] of Object.entries(secrets)) {
      result[key] = data.value;
    }

    return result;
  }

  // Delete a secret
  async deleteSecret(name) {
    if (!this.vault) throw new Error('Client not initialized');
    if (this.vault.locked) await this.init();

    // Sync with server
    if (this.token) {
      const api = new QalaAPI();
      api.setToken(this.token);
      await api.deleteSecret(this.projectId, this.environment, name);
    }

    return this.vault.deleteSecret(name);
  }
}

// CLI implementation
class QalaCLI {
  constructor() {
    this.program = new commander.Command();
    this.api = new QalaAPI();
    this.config = this.loadConfig();
    this.setupCommands();
  }

  // Load local config
  loadConfig() {
    try {
      if (fs.existsSync(QALA_CONFIG)) {
        return JSON.parse(fs.readFileSync(QALA_CONFIG, 'utf8'));
      }
    } catch (error) {
      console.warn(`Failed to load config: ${error.message}`);
    }
    return {};
  }

  // Save local config
  saveConfig() {
    fs.writeFileSync(QALA_CONFIG, JSON.stringify(this.config, null, 2), 'utf8');
  }

  // Set up CLI commands
  setupCommands() {
    this.program
      .name('qala')
      .description('Qala - Secure Environment Variables and Secrets Guard')
      .version('1.0.0');

    // Login command
    this.program
      .command('login')
      .description('Login to Qala')
      .option('-e, --email <email>', 'User email')
      .option('-p, --password <password>', 'User password')
      .option('-k, --api-key <key>', 'API key')
      .action(async (options) => {
        try {
          if (options.apiKey) {
            await this.api.loginWithApiKey(options.apiKey);
            console.log(chalk.green('Logged in successfully with API key'));
          } else {
            const email = options.email || await this.prompt('Email: ');
            const password = options.password || await this.prompt('Password: ', true);
            await this.api.login(email, password);
            console.log(chalk.green('Logged in successfully'));
          }

          // Save session
          const profile = await this.api.getProfile();
          Session.save({
            token: this.api.token,
            user: profile,
            expiry: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString() // 24 hours
          });

          this.config.lastProjectId = this.config.lastProjectId || profile.projects[0]?.id;
          this.saveConfig();
        } catch (error) {
          console.error(chalk.red(`Login failed: ${error.message}`));
          process.exit(1);
        }
      });

    // Logout command
    this.program
      .command('logout')
      .description('Logout from Qala')
      .action(() => {
        Session.clear();
        console.log(chalk.green('Logged out successfully'));
      });

    // Project commands
    this.program
      .command('projects')
      .description('List all projects')
      .action(async () => {
        try {
          await this.ensureLoggedIn();
          const projects = await this.api.listProjects();

          console.log(chalk.bold('\nYour projects:'));
          projects.forEach(project => {
            console.log(`${chalk.cyan(project.id)} - ${project.name}`);
          });

          if (projects.length === 0) {
            console.log(chalk.yellow('\nNo projects found. Create one with:'));
            console.log(chalk.yellow('  qala project create <name>'));
          }
        } catch (error) {
          console.error(chalk.red(`Failed to list projects: ${error.message}`));
          process.exit(1);
        }
      });

    this.program
      .command('project create <name>')
      .description('Create a new project')
      .option('-d, --description <description>', 'Project description')
      .action(async (name, options) => {
        try {
          await this.ensureLoggedIn();
          const project = await this.api.createProject(name, options.description || '');
          console.log(chalk.green(`Project created: ${project.id} - ${project.name}`));

          this.config.lastProjectId = project.id;
          this.saveConfig();
        } catch (error) {
          console.error(chalk.red(`Failed to create project: ${error.message}`));
          process.exit(1);
        }
      });

    // Environment commands
    this.program
      .command('environments')
      .description('List environments for the current project')
      .option('-p, --project <id>', 'Project ID')
      .action(async (options) => {
        try {
          await this.ensureLoggedIn();
          const projectId = options.project || this.config.lastProjectId;

          if (!projectId) {
            console.error(chalk.red('No project selected. Use --project or select a project first.'));
            process.exit(1);
          }

          const environments = await this.api.listEnvironments(projectId);
          console.log(chalk.bold(`\nEnvironments for project ${projectId}:`));
          environments.forEach(env => {
            console.log(`- ${chalk.cyan(env.name)}`);
          });

          if (environments.length === 0) {
            console.log(chalk.yellow('\nNo environments found. Create one with:'));
            console.log(chalk.yellow(`  qala env create <name> --project ${projectId}`));
          }
        } catch (error) {
          console.error(chalk.red(`Failed to list environments: ${error.message}`));
          process.exit(1);
        }
      });

    this.program
      .command('env create <name>')
      .description('Create a new environment')
      .option('-p, --project <id>', 'Project ID')
      .action(async (name, options) => {
        try {
          await this.ensureLoggedIn();
          const projectId = options.project || this.config.lastProjectId;

          if (!projectId) {
            console.error(chalk.red('No project selected. Use --project or select a project first.'));
            process.exit(1);
          }

          const environment = await this.api.createEnvironment(projectId, name);
          console.log(chalk.green(`Environment created: ${environment.name}`));
        } catch (error) {
          console.error(chalk.red(`Failed to create environment: ${error.message}`));
          process.exit(1);
        }
      });

    // Secret commands
    this.program
      .command('secrets')
      .description('List secrets for the current environment')
      .option('-p, --project <id>', 'Project ID')
      .option('-e, --env <name>', 'Environment name', 'development')
      .action(async (options) => {
        try {
          await this.ensureLoggedIn();
          const projectId = options.project || this.config.lastProjectId;

          if (!projectId) {
            console.error(chalk.red('No project selected. Use --project or select a project first.'));
            process.exit(1);
          }

          const secrets = await this.api.listSecrets(projectId, options.env);
          console.log(chalk.bold(`\nSecrets for ${options.env} environment:`));

          if (secrets.length === 0) {
            console.log(chalk.yellow('No secrets found.'));
          } else {
            secrets.forEach(secret => {
              console.log(`- ${chalk.cyan(secret.name)}`);
            });
          }
        } catch (error) {
          console.error(chalk.red(`Failed to list secrets: ${error.message}`));
          process.exit(1);
        }
      });

    this.program
      .command('secret add <name>')
      .description('Add or update a secret')
      .option('-p, --project <id>', 'Project ID')
      .option('-e, --env <name>', 'Environment name', 'development')
      .option('-v, --value <value>', 'Secret value')
      .option('-d, --description <description>', 'Secret description')
      .action(async (name, options) => {
        try {
          await this.ensureLoggedIn();
          const projectId = options.project || this.config.lastProjectId;

          if (!projectId) {
            console.error(chalk.red('No project selected. Use --project or select a project first.'));
            process.exit(1);
          }

          const value = options.value || await this.prompt(`Value for ${name}: `, true);
          await this.api.setSecret(projectId, options.env, name, value, options.description || '');

          // Update local vault
          const vault = new QalaVault(projectId, options.env);
          vault.init();
          vault.unlock();
          vault.setSecret(name, value, options.description || '');

          console.log(chalk.green(`Secret "${name}" added successfully`));
        } catch (error) {
          console.error(chalk.red(`Failed to add secret: ${error.message}`));
          process.exit(1);
        }
      });

    this.program
      .command('secret get <name>')
      .description('Get a secret value')
      .option('-p, --project <id>', 'Project ID')
      .option('-e, --env <name>', 'Environment name', 'development')
      .action(async (name, options) => {
        try {
          await this.ensureLoggedIn();
          const projectId = options.project || this.config.lastProjectId;

          if (!projectId) {
            console.error(chalk.red('No project selected. Use --project or select a project first.'));
            process.exit(1);
          }

          const secret = await this.api.getSecret(projectId, options.env, name);
          console.log(secret.value);

          // Log the access
          await this.api.logAccess(projectId, options.env, name);
        } catch (error) {
          console.error(chalk.red(`Failed to get secret: ${error.message}`));
          process.exit(1);
        }
      });

    this.program
      .command('secret delete <name>')
      .description('Delete a secret')
      .option('-p, --project <id>', 'Project ID')
      .option('-e, --env <name>', 'Environment name', 'development')
      .action(async (name, options) => {
        try {
          await this.ensureLoggedIn();
          const projectId = options.project || this.config.lastProjectId;

          if (!projectId) {
            console.error(chalk.red('No project selected. Use --project or select a project first.'));
            process.exit(1);
          }

          await this.api.deleteSecret(projectId, options.env, name);

          // Update local vault
          const vault = new QalaVault(projectId, options.env);
          vault.init();
          vault.unlock();
          vault.deleteSecret(name);

          console.log(chalk.green(`Secret "${name}" deleted successfully`));
        } catch (error) {
          console.error(chalk.red(`Failed to delete secret: ${error.message}`));
          process.exit(1);
        }
      });

    this.program
      .command('secret rotate <name>')
      .description('Rotate a secret (for compatible secrets)')
      .option('-p, --project <id>', 'Project ID')
      .option('-e, --env <name>', 'Environment name', 'development')
      .action(async (name, options) => {
        try {
          await this.ensureLoggedIn();
          const projectId = options.project || this.config.lastProjectId;

          if (!projectId) {
            console.error(chalk.red('No project selected. Use --project or select a project first.'));
            process.exit(1);
          }

          const result = await this.api.rotateSecret(projectId, options.env, name);

          // Update local vault
          const vault = new QalaVault(projectId, options.env);
          vault.init();
          vault.unlock
