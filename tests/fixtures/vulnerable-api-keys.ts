import express from 'express';
import aws from 'aws-sdk';

const app = express();

// VULNERABILITY 1: Hardcoded Stripe key
const STRIPE_KEY = 'sk_live_4eC39HqLyjWDarhtT657G123';
const PUBLIC_KEY = 'pk_live_51FPNJKAJwqLyjWDarhtT657';

// VULNERABILITY 2: Hardcoded AWS credentials
const awsConfig = {
  accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
  secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
  region: 'us-east-1',
};

// VULNERABILITY 3: Database connection string with credentials
const dbConnection = 'mongodb://admin:password123@db.example.com:27017/myapp';
const postgresUrl = 'postgresql://user:password123@db.example.com:5432/mydb';

// VULNERABILITY 4: API key in config
const config = {
  stripe_api_key: 'sk_live_4eC39HqLyjWDarhtT657G456',
  twilio_account_sid: 'ACa24c012d6d9b4c8a8b96d1c1d1a1b1c',
  twilio_auth_token: 'f42bb9a6a8d88ce0abc7e8b6f9c8d7e6f',
  sendgrid_api_key: 'SG.KJ2b_uasI8y6xZaB-M1ZXg.aBcDeFgHiJkLmNoPqRsTuVwXyZ',
};

// VULNERABILITY 5: Firebase key
const FIREBASE_API_KEY = 'AIzaSyDaJaKh6K-WJNFQG7Kh6K-WJNFQG7Kh6K';

// VULNERABILITY 6: GitHub token in code
const GITHUB_TOKEN = 'ghp_1234567890abcdefghijklmnopqrstuvwxyz';

// VULNERABILITY 7: Keys passed as function defaults
function initializePaymentService(
  apiKey: string = 'sk_test_4eC39HqLyjWDarhtT657G789'
) {
  return apiKey;
}

// VULNERABILITY 8: API keys in logs
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  console.log(`Login attempt: ${username}`);
  console.log(`API Key being used: sk_live_4eC39HqLyjWDarhtT657G000`);
  console.log(`Stripe token: pk_live_51FPNJKAJwqLyjWDarhtT657`);
  res.json({ success: true });
});

// VULNERABILITY 9: Error message with API key
app.get('/api/charge', (req, res) => {
  try {
    const charge = createCharge('sk_live_4eC39HqLyjWDarhtT657G111');
    res.json(charge);
  } catch (error) {
    res.status(500).json({
      error: 'Failed to charge with key sk_live_4eC39HqLyjWDarhtT657G111',
    });
  }
});

// VULNERABILITY 10: Keys in environment variables without validation
function getConfig() {
  const stripeKey = process.env.STRIPE_KEY; // No validation
  const apiKey = process.env.API_KEY || undefined; // No default
  return { stripeKey, apiKey };
}

// Helper functions
function createCharge(key: string) {
  return { id: 'ch_123', amount: 100 };
}

export default app;
