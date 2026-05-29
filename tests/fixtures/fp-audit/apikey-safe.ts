// API_KEY_EXPOSURE FP exhibits. Zero default findings expected.

// (1) Credential-named vars holding env references, not literals.
const STRIPE_KEY = process.env.STRIPE_KEY;
const TWILIO_AUTH = process.env.TWILIO_AUTH_TOKEN;
const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
const SENDGRID = process.env['SENDGRID_KEY'];

// (2) Constants that LOOK like keys but are obviously demos or service names.
const PROVIDER_NAME = 'stripe';
const TOKEN_TYPE = 'Bearer';
const KEY_FIELD = 'apiKey';

// (3) Property names that include credential tokens but values are env-derived.
const config = {
  apiKey: process.env.API_KEY ?? '',
  secret: process.env.API_SECRET ?? '',
  privateKey: process.env.PRIVATE_KEY,
  jwtSecret: process.env.JWT_SECRET,
};

// (4) Function with credential-named default — but default is an env reference.
function initClient(apiKey: string = process.env.API_KEY ?? '') {
  return apiKey;
}

// (5) Comments mentioning brand names (NOT actual keys).
// We use Stripe for payments. The api_key is rotated monthly via the secrets vault.
// Twilio auth is stored in the secrets manager under twilio/auth_token.
const _ = config;

// (6) Connection strings via env, not literal.
const dbUrl = `mongodb://${process.env.DB_USER}:${process.env.DB_PASS}@db.example.com/myapp`;

// (7) Log a NAME, not the value.
console.log('Using API provider:', PROVIDER_NAME);
console.log('Stripe configured:', Boolean(STRIPE_KEY));

void TWILIO_AUTH; void GITHUB_TOKEN; void SENDGRID; void TOKEN_TYPE; void KEY_FIELD; void initClient; void dbUrl;
