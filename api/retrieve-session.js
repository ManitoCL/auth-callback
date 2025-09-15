// Vercel serverless function for retrieving tokens from secure session code

// Global store for session codes shared with create-secure-session
// Note: In production, this would use Redis or a database for persistence
if (!global.sessionCodeStore) {
  global.sessionCodeStore = new Map();
}
const sessionCodeStore = global.sessionCodeStore;

export default async function handler(req, res) {
  // Only allow POST requests
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { session_code } = req.body;

    // Validate session code format
    if (!session_code || session_code.length !== 64) {
      return res.status(400).json({ error: 'Invalid session code format' });
    }

    // Get tokens from store
    const tokens = sessionCodeStore.get(session_code);

    if (!tokens) {
      return res.status(404).json({ error: 'Session code not found or expired' });
    }

    // Check expiration
    const now = Date.now();
    if (tokens.expires_at && tokens.expires_at < now) {
      sessionCodeStore.delete(session_code);
      return res.status(410).json({ error: 'Session code expired' });
    }

    console.log('✅ Successfully retrieved tokens from session code');

    // Immediately delete the code after use (one-time use)
    sessionCodeStore.delete(session_code);

    // Return the tokens
    res.status(200).json({
      access_token: tokens.access_token,
      refresh_token: tokens.refresh_token,
      expires_in: tokens.expires_in,
      token_type: tokens.token_type,
      type: tokens.type
    });

  } catch (error) {
    console.error('❌ Error retrieving tokens from session code:', error);
    res.status(500).json({
      error: 'Failed to retrieve session tokens',
      message: error.message
    });
  }
}