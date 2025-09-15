// Vercel serverless function for secure session code creation
import crypto from 'crypto';

// Global store for session codes across serverless functions
// Note: In production, this would use Redis or a database for persistence
if (!global.sessionCodeStore) {
  global.sessionCodeStore = new Map();
}
const sessionCodeStore = global.sessionCodeStore;

// Clean up expired codes
function cleanupExpiredCodes() {
  const now = Date.now();
  let cleanedCount = 0;

  for (const [code, tokens] of sessionCodeStore.entries()) {
    if (tokens.expires_at && tokens.expires_at < now) {
      sessionCodeStore.delete(code);
      cleanedCount++;
    }
  }

  if (cleanedCount > 0) {
    console.log(`🧹 Cleaned up ${cleanedCount} expired session codes`);
  }
}

export default async function handler(req, res) {
  // Only allow POST requests
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { access_token, refresh_token, expires_in, token_type, type } = req.body;

    // Validate required fields
    if (!access_token || !refresh_token) {
      return res.status(400).json({ error: 'Missing required tokens' });
    }

    // Validate token format (basic security)
    if (typeof access_token !== 'string' || access_token.length < 50) {
      return res.status(400).json({ error: 'Invalid access token format' });
    }

    if (typeof refresh_token !== 'string' || refresh_token.length < 8) {
      return res.status(400).json({ error: 'Invalid refresh token format' });
    }

    // Generate a secure random code (not predictable)
    const randomBytes = crypto.randomBytes(32);
    const session_code = randomBytes.toString('hex');

    // Set expiration (5 minutes from now)
    const expires_at = Date.now() + (5 * 60 * 1000);

    // Store tokens with the code (in production, use encrypted database storage)
    sessionCodeStore.set(session_code, {
      access_token,
      refresh_token,
      expires_in,
      token_type,
      type,
      expires_at
    });

    console.log('🔐 Created secure session code:', {
      codeLength: session_code.length,
      expiresAt: new Date(expires_at).toISOString(),
      hasAccessToken: !!access_token,
      hasRefreshToken: !!refresh_token
    });

    // Clean up expired codes
    cleanupExpiredCodes();

    // Return the secure session code
    res.status(200).json({
      session_code,
      expires_at
    });

  } catch (error) {
    console.error('❌ Error creating secure session code:', error);
    res.status(500).json({
      error: 'Failed to create secure session code',
      message: error.message
    });
  }
}