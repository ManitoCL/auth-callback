// SECURE Configuration for auth callback
// Hardcoded values for browser environment (process.env doesn't exist in browser)
window.MANITO_CONFIG = {
  supabaseUrl: 'https://rlxsytlesoqbcgbnhwhq.supabase.co',
  supabaseKey: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InJseHN5dGxlc29xYmNnYm5od2hxIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTc3MTY4MzYsImV4cCI6MjA3MzI5MjgzNn0.-JXn6oXvFj4GBX1EyIfrN4J5WEhFSvBCSZskAKusi9M',

  // Environment detection
  isProduction: true,
  isDevelopment: false,

  // Security settings
  allowedOrigins: [
    'https://auth.manito.cl',
    'https://manito.cl',
    'https://www.manito.cl'
  ],

  // Rate limiting
  maxAttemptsPerMinute: 5,
  sessionTimeoutMinutes: 30,

  // Feature flags
  features: {
    secureSessionCode: true,
    tokenValidation: true,
    rateLimiting: true,
    csrfProtection: true
  }
};