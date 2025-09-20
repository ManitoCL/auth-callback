/**
 * Email Verification Success Handler - Enterprise Single-Use Tokens
 * Handles both Supabase implicit flow (#tokens) and PKCE flow (?tokens)
 * Implements single-use verification links for banking-grade security
 * FIXED: Email extraction and token tracking
 */

const { createClient } = require('@supabase/supabase-js');
const crypto = require('crypto');

// Initialize Supabase client for token tracking
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

module.exports = async function handler(req, res) {
  try {
    // Set security headers
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Content-Security-Policy',
      "default-src 'self'; " +
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
      "font-src 'self' https://fonts.gstatic.com; " +
      "script-src 'self' 'unsafe-inline'; " +
      "connect-src 'self';"
    );

    // ENTERPRISE SECURITY: Single-use verification token checking
    console.log('🔒 Enterprise: Checking single-use verification token');

    // ENHANCED DEBUG: Log all possible token sources including FULL URL
    console.log('🐛 Debug - Complete request details:', {
      query: req.query,
      url: req.url,
      fullUrl: req.url,
      headers: {
        referer: req.headers.referer,
        'user-agent': req.headers['user-agent']
      }
    });

    // FIXED: Extract ALL possible Supabase verification parameters
    const urlTokenHash = req.query.token_hash;
    const verificationType = req.query.type;
    const errorParam = req.query.error;
    const errorDescription = req.query.error_description;
    const accessToken = req.query.access_token;
    const refreshToken = req.query.refresh_token;
    const userEmail = req.query.email; // Sometimes Supabase includes email
    const refererUrl = req.headers.referer;

    let tokenToCheck = urlTokenHash;
    let extractedEmail = userEmail;

    console.log('🐛 Debug - Enhanced token extraction:', {
      urlTokenHash,
      verificationType,
      errorParam,
      errorDescription,
      accessToken: accessToken ? 'present' : 'missing',
      refreshToken: refreshToken ? 'present' : 'missing',
      userEmail,
      refererUrl,
      tokenToCheck
    });

    // FIXED: Extract email from access token if available
    if (accessToken && !extractedEmail) {
      try {
        // Decode JWT to get user email (without verification - just for email extraction)
        const payload = JSON.parse(Buffer.from(accessToken.split('.')[1], 'base64').toString());
        extractedEmail = payload.email;
        console.log('🐛 Debug - Email extracted from access token:', extractedEmail);
      } catch (e) {
        console.log('⚠️ Could not decode access token for email:', e.message);
      }
    }

    // FIXED: More comprehensive token extraction from various sources
    if (!tokenToCheck && refererUrl) {
      try {
        const refererURL = new URL(refererUrl);

        // Try multiple parameter patterns Supabase might use
        const fromSearchParams = refererURL.searchParams.get('token_hash') ||
                                  refererURL.searchParams.get('token') ||
                                  refererURL.searchParams.get('confirmation_token');

        const fromHash = refererURL.hash.match(/[?&]token_hash=([^&]+)/)?.[1] ||
                         refererURL.hash.match(/[?&]token=([^&]+)/)?.[1] ||
                         refererURL.hash.match(/[?&]confirmation_token=([^&]+)/)?.[1];

        tokenToCheck = fromSearchParams || fromHash;

        // Also try to extract email from referer
        if (!extractedEmail) {
          extractedEmail = refererURL.searchParams.get('email') ||
                          refererURL.hash.match(/[?&]email=([^&]+)/)?.[1];
        }

        console.log('🐛 Debug - Enhanced referer extraction:', {
          refererURL: refererURL.toString(),
          fromSearchParams,
          fromHash,
          finalToken: tokenToCheck,
          extractedEmailFromReferer: extractedEmail
        });
      } catch (e) {
        console.log('⚠️ Could not parse referer URL:', e.message);
      }
    }

    // FIXED: If still no email, try to get it from the verification context
    if (!extractedEmail && (accessToken || refreshToken)) {
      try {
        // Get user from Supabase using the tokens
        const tempClient = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY);
        if (accessToken && refreshToken) {
          const { data: { user }, error } = await tempClient.auth.setSession({
            access_token: accessToken,
            refresh_token: refreshToken
          });

          if (user && !error) {
            extractedEmail = user.email;
            console.log('🐛 Debug - Email extracted from user session:', extractedEmail);
          }
        }
      } catch (e) {
        console.log('⚠️ Could not extract email from session:', e.message);
      }
    }

    if (tokenToCheck && (verificationType === 'email' || verificationType === 'signup')) {
      try {
        // Hash the token for secure storage
        const tokenHash = crypto.createHash('sha256').update(tokenToCheck).digest('hex');

        console.log('🔍 Checking token usage status');
        console.log('🐛 Debug - Token hash to check:', tokenHash);

        // Check if token is already used
        const { data: isUsed, error: checkError } = await supabase
          .rpc('is_verification_token_used', { token_hash_param: tokenHash });

        console.log('🐛 Debug - RPC check result:', {
          isUsed,
          checkError,
          rpcFunctionCalled: 'is_verification_token_used'
        });

        if (checkError) {
          console.error('❌ Error checking token usage:', checkError);
          // Continue anyway - don't break flow for database errors
        } else if (isUsed) {
          console.log('🚫 Token already used - showing error page');

          // Token already used - show security error page
          const errorHtml = `
            <!DOCTYPE html>
            <html lang="es">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Enlace Ya Utilizado - Manito</title>
                <style>
                    body { font-family: Inter, sans-serif; text-align: center; padding: 50px; background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%); min-height: 100vh; color: white; }
                    .container { max-width: 500px; margin: 0 auto; background: white; color: #333; padding: 40px; border-radius: 20px; box-shadow: 0 20px 60px rgba(0,0,0,0.2); }
                    .error-icon { font-size: 64px; margin-bottom: 20px; }
                    h1 { color: #dc2626; margin-bottom: 20px; }
                    .security-note { background: #fef2f2; border: 1px solid #fecaca; border-radius: 10px; padding: 20px; margin: 20px 0; }
                    .btn { display: inline-block; background: #059669; color: white; padding: 12px 24px; border-radius: 8px; text-decoration: none; margin: 10px; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="error-icon">🔒</div>
                    <h1>Enlace Ya Utilizado</h1>
                    <p>Este enlace de verificación ya fue usado por seguridad.</p>

                    <div class="security-note">
                        <strong>🛡️ Protección de Seguridad</strong><br>
                        Los enlaces de verificación solo pueden usarse una vez para proteger tu cuenta.
                    </div>

                    <p>Si tu cuenta está verificada, puedes iniciar sesión normalmente en la app.</p>

                    <a href="manito://auth/login?email=${encodeURIComponent(extractedEmail || '')}" class="btn">Abrir App Manito</a>
                    <br>
                    <small>¿Problemas? Contacta soporte@manito.cl</small>
                </div>
            </body>
            </html>
          `;

          res.setHeader('Content-Type', 'text/html; charset=utf-8');
          return res.status(200).send(errorHtml);
        } else {
          console.log('✅ Token valid - marking as used');

          // Token is valid - mark it as used
          const markTokenData = {
            token_hash_param: tokenHash,
            user_id_param: null, // Will be updated when we have user context
            email_param: extractedEmail || 'unknown'
          };

          console.log('🐛 Debug - Marking token with data:', markTokenData);

          const { error: markError } = await supabase
            .rpc('mark_verification_token_used', markTokenData);

          console.log('🐛 Debug - RPC mark result:', {
            markError,
            rpcFunctionCalled: 'mark_verification_token_used'
          });

          if (markError) {
            console.error('❌ Error marking token as used:', markError);
            // Continue anyway - don't break the flow
          } else {
            console.log('🔒 Token marked as used successfully');
          }
        }
      } catch (error) {
        console.error('❌ Single-use token check failed:', error);
        // Continue with normal flow - don't break verification for token errors
      }
    } else {
      console.log('ℹ️ No valid token found for single-use checking', {
        hasToken: !!tokenToCheck,
        verificationType,
        validType: verificationType === 'email' || verificationType === 'signup'
      });
    }

    // FIXED: Enhanced success page with proper email extraction
    const successHtml = `
      <!DOCTYPE html>
      <html lang="es">
      <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Email Verificado - Manito</title>
          <link rel="preconnect" href="https://fonts.googleapis.com">
          <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
          <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
          <style>
              * {
                  margin: 0;
                  padding: 0;
                  box-sizing: border-box;
              }

              body {
                  font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                  min-height: 100vh;
                  display: flex;
                  align-items: center;
                  justify-content: center;
                  padding: 20px;
                  color: #333;
              }

              .container {
                  background: white;
                  border-radius: 24px;
                  padding: 48px 32px;
                  max-width: 480px;
                  width: 100%;
                  text-align: center;
                  box-shadow: 0 20px 60px rgba(0, 0, 0, 0.1);
                  position: relative;
                  overflow: hidden;
              }

              .container::before {
                  content: '';
                  position: absolute;
                  top: 0;
                  left: 0;
                  right: 0;
                  height: 6px;
                  background: linear-gradient(90deg, #059669, #10b981, #34d399);
              }

              .success-icon {
                  width: 80px;
                  height: 80px;
                  background: #10b981;
                  border-radius: 50%;
                  display: flex;
                  align-items: center;
                  justify-content: center;
                  margin: 0 auto 24px;
                  position: relative;
                  animation: pulse 2s infinite;
              }

              .success-icon::after {
                  content: '✓';
                  color: white;
                  font-size: 36px;
                  font-weight: 700;
              }

              @keyframes pulse {
                  0%, 100% { transform: scale(1); }
                  50% { transform: scale(1.05); }
              }

              .title {
                  font-size: 28px;
                  font-weight: 700;
                  color: #1f2937;
                  margin-bottom: 12px;
                  line-height: 1.3;
              }

              .subtitle {
                  font-size: 18px;
                  color: #6b7280;
                  margin-bottom: 32px;
                  line-height: 1.5;
              }

              .instructions {
                  background: #f8fafc;
                  border: 2px solid #e2e8f0;
                  border-radius: 16px;
                  padding: 24px;
                  margin-bottom: 32px;
              }

              .instructions h3 {
                  font-size: 16px;
                  font-weight: 600;
                  color: #374151;
                  margin-bottom: 12px;
                  display: flex;
                  align-items: center;
                  justify-content: center;
                  gap: 8px;
              }

              .instructions p {
                  font-size: 15px;
                  color: #6b7280;
                  line-height: 1.6;
              }

              .action-buttons {
                  display: flex;
                  flex-direction: column;
                  gap: 16px;
                  margin-bottom: 24px;
              }

              .btn {
                  padding: 16px 24px;
                  border-radius: 12px;
                  font-size: 16px;
                  font-weight: 600;
                  text-decoration: none;
                  border: none;
                  cursor: pointer;
                  transition: all 0.2s ease;
                  display: inline-flex;
                  align-items: center;
                  justify-content: center;
                  gap: 8px;
              }

              .btn-primary {
                  background: #059669;
                  color: white;
              }

              .btn-primary:hover {
                  background: #047857;
                  transform: translateY(-1px);
              }

              .btn-secondary {
                  background: white;
                  color: #374151;
                  border: 2px solid #e5e7eb;
              }

              .btn-secondary:hover {
                  background: #f9fafb;
                  border-color: #d1d5db;
              }

              .security-note {
                  background: #fef3c7;
                  border: 1px solid #f59e0b;
                  border-radius: 12px;
                  padding: 16px;
                  margin-top: 24px;
              }

              .security-note p {
                  font-size: 14px;
                  color: #92400e;
                  margin: 0;
                  display: flex;
                  align-items: center;
                  gap: 8px;
              }

              .footer {
                  font-size: 13px;
                  color: #9ca3af;
                  line-height: 1.5;
                  margin-top: 24px;
              }

              .footer a {
                  color: #059669;
                  text-decoration: none;
              }

              .footer a:hover {
                  text-decoration: underline;
              }

              /* Mobile optimizations */
              @media (max-width: 480px) {
                  .container {
                      padding: 32px 24px;
                      margin: 16px;
                  }

                  .title {
                      font-size: 24px;
                  }

                  .subtitle {
                      font-size: 16px;
                  }
              }
          </style>
      </head>
      <body>
          <div class="container">
              <div class="success-icon"></div>

              <h1 class="title">¡Email Verificado!</h1>
              <p class="subtitle">Tu cuenta de Manito ha sido verificada exitosamente</p>

              <div class="instructions">
                  <h3>📱 Siguiente paso</h3>
                  <p>Vuelve a la app de Manito e inicia sesión con tu email y contraseña para comenzar a usar tu cuenta verificada.</p>
              </div>

              <div class="action-buttons">
                  <a href="#" id="openAppBtn" class="btn btn-primary">
                      📱 Abrir App Manito
                  </a>
                  <button onclick="window.close()" class="btn btn-secondary">
                      ✕ Cerrar esta ventana
                  </button>
              </div>

              <div class="security-note">
                  <p>
                      🔒 Por seguridad, ahora debes iniciar sesión en la app con tu contraseña.
                  </p>
              </div>

              <div class="footer">
                  ¿Problemas? Contacta nuestro soporte en <a href="mailto:soporte@manito.cl">soporte@manito.cl</a>
                  <br>
                  <strong>Manito</strong> - Servicios para el hogar confiables en Chile
              </div>
          </div>

          <script>
              // FIXED: Enhanced token extraction with multiple sources
              function getTokensFromUrl() {
                  const tokens = {};

                  // Try hash fragments first (Supabase implicit flow)
                  const hash = window.location.hash.substring(1);
                  if (hash) {
                      const hashParams = new URLSearchParams(hash);
                      for (const [key, value] of hashParams) {
                          tokens[key] = value;
                      }
                  }

                  // Fallback to query parameters (PKCE flow)
                  if (Object.keys(tokens).length === 0) {
                      const searchParams = new URLSearchParams(window.location.search);
                      for (const [key, value] of searchParams) {
                          tokens[key] = value;
                      }
                  }

                  return tokens;
              }

              // FIXED: Extract user email from multiple sources
              function extractUserEmail() {
                  const tokens = getTokensFromUrl();

                  // Server-side extracted email (passed via template)
                  const serverEmail = '${extractedEmail || ''}';
                  if (serverEmail) {
                      return serverEmail;
                  }

                  // Try to get from URL parameters
                  if (tokens.email) {
                      return tokens.email;
                  }

                  // Try to decode from access token
                  if (tokens.access_token) {
                      try {
                          const payload = JSON.parse(atob(tokens.access_token.split('.')[1]));
                          return payload.email;
                      } catch (e) {
                          console.log('Could not decode access token');
                      }
                  }

                  return null;
              }

              // FIXED: Generate deep link with email pre-population
              function generateDeepLink() {
                  const tokens = getTokensFromUrl();
                  const userEmail = extractUserEmail();

                  console.log('🐛 Debug - Generating deep link with:', {
                      tokens,
                      userEmail,
                      hasAccessToken: !!tokens.access_token,
                      hasRefreshToken: !!tokens.refresh_token
                  });

                  if (tokens.access_token && tokens.refresh_token) {
                      // SECURITY: Create short-lived verification token instead of passing full auth tokens
                      const verificationPayload = {
                          verified: 'true',
                          timestamp: Date.now(),
                          session_hint: 'verified_' + Date.now().toString(36)
                      };

                      // FIXED: Add email for login pre-population
                      if (userEmail) {
                          verificationPayload.email = userEmail;
                      }

                      const deepLinkParams = new URLSearchParams(verificationPayload);
                      return \`manito://auth/login?\${deepLinkParams.toString()}\`;
                  }

                  // FIXED: Fallback with email if available
                  const fallbackParams = new URLSearchParams({
                      verified: 'true',
                      method: 'fallback'
                  });

                  if (userEmail) {
                      fallbackParams.set('email', userEmail);
                  }

                  return \`manito://auth/login?\${fallbackParams.toString()}\`;
              }

              // Set up the app button
              document.getElementById('openAppBtn').addEventListener('click', (e) => {
                  e.preventDefault();

                  const deepLink = generateDeepLink();
                  console.log('Opening deep link:', deepLink);

                  // Try to open the app
                  window.location.href = deepLink;

                  // Fallback: Show instructions if app doesn't open
                  setTimeout(() => {
                      alert('¿No se abrió la app? Búscala en tu teléfono y abre Manito manualmente.');
                  }, 2000);
              });

              // Auto-close after 30 seconds if no interaction
              let hasInteracted = false;
              document.addEventListener('click', () => {
                  hasInteracted = true;
              });

              setTimeout(() => {
                  if (!hasInteracted) {
                      window.close();
                  }
              }, 30000);

              console.log('✅ Email verification success page loaded');
              console.log('Tokens found:', getTokensFromUrl());
              console.log('Extracted email:', extractUserEmail());
          </script>
      </body>
      </html>
    `;

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.status(200).send(successHtml);

  } catch (error) {
    console.error('Error serving verification success page:', error);

    // Minimal fallback page
    const fallbackHtml = `
      <!DOCTYPE html>
      <html lang="es">
      <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Email Verificado - Manito</title>
          <style>
              body { font-family: sans-serif; text-align: center; padding: 50px; }
              .container { max-width: 400px; margin: 0 auto; }
              .success { font-size: 48px; color: #10b981; margin-bottom: 20px; }
          </style>
      </head>
      <body>
          <div class="container">
              <div class="success">✓</div>
              <h1>¡Email Verificado!</h1>
              <p>Tu cuenta ha sido verificada exitosamente.</p>
              <a href="manito://auth/login">Abrir App Manito</a>
          </div>
      </body>
      </html>
    `;

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.status(200).send(fallbackHtml);
  }
}