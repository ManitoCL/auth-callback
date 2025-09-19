/**
 * PHASE 1: Simplified Email Verification (Golden Standard)
 * Meta/Instagram pattern with application-layer profile creation
 * Replaces complex verification flow with streamlined approach
 */

const { createClient } = require('@supabase/supabase-js');

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const supabase = createClient(supabaseUrl, supabaseServiceKey);

// Frontend URL for web redirects
const frontendUrl = process.env.FRONTEND_URL || 'https://auth.manito.cl';

/**
 * GOLDEN STANDARD: Simple mobile detection
 * Meta/Instagram approach - detect mobile by User-Agent keywords
 */
function isMobileAppRequest(userAgent) {
  if (!userAgent) return false;
  return userAgent.includes('Expo') ||
         userAgent.includes('ReactNative') ||
         userAgent.includes('manito') ||
         userAgent.includes('Mobile');
}

/**
 * GOLDEN STANDARD: Web browser redirect
 * Simple, reliable redirect to frontend with session tokens
 */
function redirectToWeb(sessionData, res) {
  const params = new URLSearchParams({
    access_token: sessionData.access_token,
    refresh_token: sessionData.refresh_token,
    expires_at: sessionData.expires_at?.toString() || '',
    token_type: sessionData.token_type || 'bearer',
    verified: 'true',
    flow: 'phase1_simplified'
  });

  const redirectUrl = `${frontendUrl}/?${params.toString()}`;
  console.log('🌐 Phase 1 - Web redirect:', redirectUrl);

  return res.redirect(302, redirectUrl);
}

/**
 * GOLDEN STANDARD: Mobile deep link
 * Direct deep link with session tokens for mobile app
 */
function redirectToMobile(sessionData, res) {
  const params = new URLSearchParams({
    access_token: sessionData.access_token,
    refresh_token: sessionData.refresh_token,
    expires_at: sessionData.expires_at?.toString() || '',
    token_type: sessionData.token_type || 'bearer',
    verified: 'true',
    flow: 'phase1_simplified'
  });

  const deepLink = `manito://auth/verified?${params.toString()}`;
  console.log('📱 Phase 1 - Mobile deep link generated');

  return res.redirect(302, deepLink);
}

/**
 * GOLDEN STANDARD: Error handling
 * Consistent error responses for both mobile and web
 */
function handleError(error, userAgent, res) {
  console.error('❌ Phase 1 verification error:', error.message);

  const errorParams = new URLSearchParams({
    error: error.message,
    error_code: error.code || 'verification_failed',
    type: 'error',
    flow: 'phase1_simplified'
  });

  if (isMobileAppRequest(userAgent)) {
    const errorDeepLink = `manito://auth/error?${errorParams.toString()}`;
    return res.redirect(302, errorDeepLink);
  } else {
    const errorWebUrl = `${frontendUrl}/?${errorParams.toString()}`;
    return res.redirect(302, errorWebUrl);
  }
}

/**
 * PHASE 1: Main verification handler
 * Simplified, reliable email verification following golden standard
 */
export default async function handler(req, res) {
  const { token_hash, type } = req.query;
  const userAgent = req.headers['user-agent'] || '';

  console.log('🚀 Phase 1 verification started:', {
    token_hash: token_hash ? `${token_hash.substring(0, 8)}...` : 'missing',
    type,
    isMobile: isMobileAppRequest(userAgent),
    timestamp: new Date().toISOString()
  });

  // GOLDEN STANDARD: Input validation
  if (!token_hash || !type) {
    console.error('❌ Phase 1 - Missing required parameters');
    return handleError(
      { message: 'Missing verification parameters', code: 'invalid_request' },
      userAgent,
      res
    );
  }

  try {
    // GOLDEN STANDARD: Simple OTP verification
    // Application-layer profile creation will be handled by Phase1AuthHandler
    const { data, error } = await supabase.auth.verifyOtp({
      token_hash,
      type: type === 'email' ? 'signup' : type,
    });

    if (error) {
      return handleError(error, userAgent, res);
    }

    if (!data.session?.access_token) {
      return handleError(
        { message: 'No session created after verification', code: 'session_failed' },
        userAgent,
        res
      );
    }

    console.log('✅ Phase 1 verification successful:', {
      userId: data.session.user?.id,
      email: data.session.user?.email,
      hasTokens: !!(data.session.access_token && data.session.refresh_token),
      profileWillBeCreated: true // Phase1AuthHandler will create profile in app layer
    });

    // GOLDEN STANDARD: Platform-specific redirect
    if (isMobileAppRequest(userAgent)) {
      return redirectToMobile(data.session, res);
    } else {
      return redirectToWeb(data.session, res);
    }

  } catch (error) {
    console.error('❌ Phase 1 - Unexpected error:', error);
    return handleError(
      { message: 'Internal verification error', code: 'server_error' },
      userAgent,
      res
    );
  }
}

/**
 * PHASE 1 BENEFITS:
 * ✅ Simplified flow - no complex session_code handling
 * ✅ Application-layer profile creation (Supabase best practice)
 * ✅ Reliable mobile/web detection
 * ✅ Consistent error handling
 * ✅ Golden standard Meta/Instagram pattern
 * ✅ Zero manual profile creation needed
 */