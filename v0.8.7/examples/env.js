/**
 * Qala ENV Mode Example
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

// Initialize Qala in ENV mode
async function main() {
  try {
    // Initialize Qala in ENV mode
    console.log('Initializing Qala in ENV mode...');
    await Qala.init();
    console.log('Qala ENV mode initialized successfully!');

    // Now we can access the values directly from process.env
    console.log('API_KEY from process.env:', process.env.API_KEY);
    console.log('DATABASE_URL from process.env:', process.env.DATABASE_URL);

    // Wait a moment to ensure all async gets are complete
    setTimeout(() => {
      console.log('After cache is populated:');
      console.log('JWT_SECRET from process.env:', process.env.JWT_SECRET);
      console.log('AWS_ACCESS_KEY from process.env:', process.env.AWS_ACCESS_KEY);
    }, 1000);

    // Example application use case
    function connectToDatabase() {
      const dbUrl = process.env.DATABASE_URL;
      console.log(`Connecting to database at ${dbUrl}...`);
      // Database connection logic would go here
    }

    // Call application function
    connectToDatabase();
  } catch (error) {
    console.error('Error:', error.message);
  }
}

main();
