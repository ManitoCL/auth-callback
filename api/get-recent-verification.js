/**
 * Get Recent Email Verification - Device-Agnostic API
 * Returns the most recent email verification event for device-agnostic email extraction
 * Used by verified.js to get email context across devices/sessions
 */

const { createClient } = require('@supabase/supabase-js');

// Initialize Supabase admin client
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

module.exports = async function handler(req, res) {
  // Set CORS headers for browser access
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    console.log('🔍 API: Getting recent email verification events...');

    // Get the most recent verification events (last 15 minutes)
    const { data: recentVerifications, error: verificationError } = await supabase
      .from('verification_events')
      .select('user_email, verified_at, metadata, event_type')
      .gt('expires_at', new Date().toISOString())
      .gte('verified_at', new Date(Date.now() - 15 * 60 * 1000).toISOString())
      .order('verified_at', { ascending: false })
      .limit(1);

    console.log('🐛 Debug - Recent verification query result:', {
      count: recentVerifications?.length || 0,
      error: verificationError?.message,
      data: recentVerifications?.[0] ? {
        email: recentVerifications[0].user_email,
        verified_at: recentVerifications[0].verified_at,
        event_type: recentVerifications[0].event_type
      } : null
    });

    if (verificationError) {
      console.error('❌ Error querying verification events:', verificationError);
      return res.status(500).json({
        error: 'Database query failed',
        message: verificationError.message
      });
    }

    if (!recentVerifications || recentVerifications.length === 0) {
      console.log('⚠️ No recent verification events found');
      return res.status(404).json({
        error: 'No recent verification found',
        message: 'No email verification in the last 15 minutes'
      });
    }

    const recentVerification = recentVerifications[0];
    const minutesAgo = (Date.now() - new Date(recentVerification.verified_at).getTime()) / (1000 * 60);

    console.log('✅ Recent verification found:', {
      email: recentVerification.user_email,
      minutesAgo: Math.round(minutesAgo * 10) / 10,
      event_type: recentVerification.event_type
    });

    return res.status(200).json({
      success: true,
      email: recentVerification.user_email,
      verified_at: recentVerification.verified_at,
      minutes_ago: Math.round(minutesAgo * 10) / 10,
      event_type: recentVerification.event_type,
      metadata: recentVerification.metadata
    });

  } catch (error) {
    console.error('❌ Recent verification API error:', error);
    return res.status(500).json({
      error: 'Internal server error',
      message: error.message
    });
  }
};