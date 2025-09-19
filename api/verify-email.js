const { createClient } = require('@supabase/supabase-js');

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const supabase = createClient(supabaseUrl, supabaseServiceKey);

// Frontend URL for web browser redirects
const frontendUrl = process.env.FRONTEND_URL || 'https://auth.manito.cl';

function redirectToFrontend(params, res) {
  const urlParams = new URLSearchParams(params);
  const redirectUrl = `${frontendUrl}/?${urlParams.toString()}`;
  console.log('🌐 Redirecting to frontend:', redirectUrl);
  return res.redirect(302, redirectUrl);
}

export default async function handler(req, res) {
  const { token_hash, type } = req.query;

  console.log('🔍 Email verification request:', {
    token_hash: token_hash ? `${token_hash.substring(0, 10)}...` : 'missing',
    type,
    userAgent: req.headers['user-agent']?.substring(0, 100) || 'unknown'
  });

  if (!token_hash || !type) {
    console.error('❌ Missing required parameters');
    return res.status(400).json({
      error: 'Missing token_hash or type parameter'
    });
  }

  try {
    // Verify the email with Supabase
    const { data, error } = await supabase.auth.verifyOtp({
      token_hash,
      type: type === 'email' ? 'signup' : type,
    });

    if (error) {
      console.error('❌ Verification failed:', error.message);
      return redirectToFrontend({
        error: error.message,
        type: 'error'
      }, res);
    }

    if (!data.session) {
      console.error('❌ No session returned from verification');
      return redirectToFrontend({
        error: 'Verification failed - no session created',
        type: 'error'
      }, res);
    }

    console.log('✅ Email verification successful');

    // ==================== MOBILE DEEP LINK FIX ====================
    // Check User-Agent to determine if request is from mobile app or browser
    const userAgent = req.headers['user-agent'] || '';
    const isMobileApp = userAgent.includes('Expo') || userAgent.includes('ReactNative') || userAgent.includes('manito');

    console.log("🔍 Request analysis:", {
      userAgent: userAgent.substring(0, 100),
      isMobileApp,
      requestSource: isMobileApp ? 'Mobile App' : 'Web Browser'
    });

    if (isMobileApp) {
      // MOBILE APP: Generate deep link directly
      const deepLinkParams = new URLSearchParams({
        access_token: data.session.access_token,
        refresh_token: data.session.refresh_token,
        expires_at: data.session.expires_at?.toString() || "",
        token_type: data.session.token_type || "bearer",
        auth_method: "email",
        flow_type: "pkce",
        verified: "true"
      });

      const mobileDeepLink = `manito://auth/verified?${deepLinkParams.toString()}`;

      console.log("📱 MOBILE DEEP LINK GENERATED:", {
        scheme: "manito://",
        path: "auth/verified",
        hasTokens: !!(data.session.access_token && data.session.refresh_token)
      });

      return res.redirect(302, mobileDeepLink);
    } else {
      // WEB BROWSER: Redirect to frontend
      console.log("🌐 Web browser - redirecting to frontend");
      return redirectToFrontend({
        access_token: data.session.access_token,
        refresh_token: data.session.refresh_token,
        expires_in: data.session.expires_in?.toString() || "3600",
        token_type: data.session.token_type || "bearer",
        type: "success",
        flow: "pkce"
      }, res);
    }
    // ==================== END MOBILE DEEP LINK FIX ====================

  } catch (error) {
    console.error('❌ Verification error:', error);
    return res.status(500).json({
      error: 'Internal server error',
      details: process.env.NODE_ENV === 'development' ? error.message : 'Please try again'
    });
  }
}
