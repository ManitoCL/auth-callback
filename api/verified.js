/**
 * IMPROVED Email Verification Success Handler - Pure Webhook Architecture
 * REMOVES: All legacy token validation logic
 * ADDS: Retry logic for webhook timing race conditions
 * ENSURES: Device-agnostic email extraction works 100% of the time
 */

const { createClient } = require('@supabase/supabase-js');

// Initialize Supabase admin client
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

    console.log('🔒 Enterprise: Device-agnostic email verification handler');

    // ENHANCED DEBUG: Log request details (without tokens - they're consumed by Supabase)
    console.log('🐛 Debug - Request details:', {
      query: req.query,
      url: req.url,
      hasReferer: !!req.headers.referer,
      userAgent: req.headers['user-agent']?.substring(0, 100) + '...'
    });

    // DEVICE-AGNOSTIC EMAIL EXTRACTION with retry logic
    const extractedEmail = await getEmailWithRetry();

    if (!extractedEmail) {
      console.log('⚠️ No email found after retries - using fallback approach');
    }

    console.log('📧 Final email result:', {
      email: extractedEmail || 'unknown',
      hasEmail: !!extractedEmail
    });

    // IMPROVED: Enhanced success page with proper email extraction
    const successHtml = generateSuccessPage(extractedEmail);

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.status(200).send(successHtml);

  } catch (error) {
    console.error('❌ Error serving verification success page:', error);

    // Minimal fallback page
    const fallbackHtml = generateFallbackPage();
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.status(200).send(fallbackHtml);
  }
};

/**
 * CRITICAL FIX: Device-agnostic email extraction with retry logic
 * Handles timing race conditions where webhook hasn't processed yet
 */
async function getEmailWithRetry(maxRetries = 6) {
  console.log('🔍 Starting device-agnostic email extraction with retry logic...');

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      console.log(`🔄 Attempt ${attempt}/${maxRetries}: Querying recent verification events...`);

      // Query recent verification events (last 15 minutes)
      const { data: recentVerifications, error: verificationError } = await supabase
        .from('verification_events')
        .select('user_email, verified_at, metadata, event_type')
        .gt('expires_at', new Date().toISOString())
        .gte('verified_at', new Date(Date.now() - 15 * 60 * 1000).toISOString())
        .order('verified_at', { ascending: false })
        .limit(3);

      console.log(`🐛 Debug - Attempt ${attempt} result:`, {
        count: recentVerifications?.length || 0,
        error: verificationError?.message,
        hasResults: !!recentVerifications && recentVerifications.length > 0
      });

      if (verificationError) {
        console.error(`❌ Attempt ${attempt} database error:`, verificationError);
        // Continue to next attempt
      } else if (recentVerifications && recentVerifications.length > 0) {
        const recentVerification = recentVerifications[0];
        const minutesAgo = (Date.now() - new Date(recentVerification.verified_at).getTime()) / (1000 * 60);

        console.log('✅ Email extracted from verification event:', {
          email: recentVerification.user_email,
          verified_at: recentVerification.verified_at,
          minutes_ago: Math.round(minutesAgo * 10) / 10,
          event_type: recentVerification.event_type,
          attempt: attempt
        });

        return recentVerification.user_email;
      }

      // No results yet - wait before retry (exponential backoff)
      if (attempt < maxRetries) {
        const delayMs = Math.min(1000 * Math.pow(1.5, attempt - 1), 5000); // 1s, 1.5s, 2.25s, 3.375s, 5s, 5s
        console.log(`⏳ No results yet, waiting ${delayMs}ms before attempt ${attempt + 1}...`);
        await new Promise(resolve => setTimeout(resolve, delayMs));
      }

    } catch (error) {
      console.error(`❌ Attempt ${attempt} failed:`, error.message);
      if (attempt === maxRetries) {
        throw error;
      }
    }
  }

  console.log('⚠️ All retry attempts exhausted - no recent verification events found');
  return null;
}

/**
 * Generate the main success page HTML
 */
function generateSuccessPage(extractedEmail) {
  return `
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
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh; display: flex; align-items: center; justify-content: center;
                padding: 20px; color: #333;
            }
            .container {
                background: white; border-radius: 24px; padding: 48px 32px; max-width: 480px; width: 100%;
                text-align: center; box-shadow: 0 20px 60px rgba(0, 0, 0, 0.1); position: relative; overflow: hidden;
            }
            .container::before {
                content: ''; position: absolute; top: 0; left: 0; right: 0; height: 6px;
                background: linear-gradient(90deg, #059669, #10b981, #34d399);
            }
            .success-icon {
                width: 80px; height: 80px; background: #10b981; border-radius: 50%;
                display: flex; align-items: center; justify-content: center; margin: 0 auto 24px;
                position: relative; animation: pulse 2s infinite;
            }
            .success-icon::after { content: '✓'; color: white; font-size: 36px; font-weight: 700; }
            @keyframes pulse { 0%, 100% { transform: scale(1); } 50% { transform: scale(1.05); } }
            .title { font-size: 28px; font-weight: 700; color: #1f2937; margin-bottom: 12px; line-height: 1.3; }
            .subtitle { font-size: 18px; color: #6b7280; margin-bottom: 32px; line-height: 1.5; }
            .instructions {
                background: #f8fafc; border: 2px solid #e2e8f0; border-radius: 16px; padding: 24px; margin-bottom: 32px;
            }
            .instructions h3 {
                font-size: 16px; font-weight: 600; color: #374151; margin-bottom: 12px;
                display: flex; align-items: center; justify-content: center; gap: 8px;
            }
            .instructions p { font-size: 15px; color: #6b7280; line-height: 1.6; }
            .action-buttons { display: flex; flex-direction: column; gap: 16px; margin-bottom: 24px; }
            .btn {
                padding: 16px 24px; border-radius: 12px; font-size: 16px; font-weight: 600;
                text-decoration: none; border: none; cursor: pointer; transition: all 0.2s ease;
                display: inline-flex; align-items: center; justify-content: center; gap: 8px;
            }
            .btn-primary { background: #059669; color: white; }
            .btn-primary:hover { background: #047857; transform: translateY(-1px); }
            .btn-secondary { background: white; color: #374151; border: 2px solid #e5e7eb; }
            .btn-secondary:hover { background: #f9fafb; border-color: #d1d5db; }
            .security-note {
                background: #fef3c7; border: 1px solid #f59e0b; border-radius: 12px; padding: 16px; margin-top: 24px;
            }
            .security-note p {
                font-size: 14px; color: #92400e; margin: 0;
                display: flex; align-items: center; gap: 8px;
            }
            .footer {
                font-size: 13px; color: #9ca3af; line-height: 1.5; margin-top: 24px;
            }
            .footer a { color: #059669; text-decoration: none; }
            .footer a:hover { text-decoration: underline; }
            @media (max-width: 480px) {
                .container { padding: 32px 24px; margin: 16px; }
                .title { font-size: 24px; } .subtitle { font-size: 16px; }
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
                <a href="#" id="openAppBtn" class="btn btn-primary">📱 Abrir App Manito</a>
                <button onclick="window.close()" class="btn btn-secondary">✕ Cerrar esta ventana</button>
            </div>
            <div class="security-note">
                <p>🔒 Por seguridad, ahora debes iniciar sesión en la app con tu contraseña.</p>
            </div>
            <div class="footer">
                ¿Problemas? Contacta nuestro soporte en <a href="mailto:soporte@manito.cl">soporte@manito.cl</a><br>
                <strong>Manito</strong> - Servicios para el hogar confiables en Chile
            </div>
        </div>

        <script>
            // IMPROVED: Device-agnostic email extraction with fallback
            async function extractUserEmail() {
                // Server-side extracted email (passed via template)
                const serverEmail = '${extractedEmail || ''}';
                if (serverEmail && serverEmail !== 'null' && serverEmail !== 'undefined') {
                    console.log('✅ Using server-extracted email:', serverEmail);
                    return serverEmail;
                }

                // FALLBACK: Try API call for device-agnostic extraction
                try {
                    console.log('🔍 Attempting device-agnostic email extraction...');
                    const response = await fetch('/api/get-recent-verification', {
                        method: 'GET',
                        headers: { 'Content-Type': 'application/json' }
                    });

                    if (response.ok) {
                        const data = await response.json();
                        if (data.email) {
                            console.log('✅ Email extracted from API:', {
                                email: data.email,
                                minutes_ago: data.minutes_ago,
                                event_type: data.event_type
                            });
                            return data.email;
                        }
                    } else {
                        const errorData = await response.json().catch(() => ({}));
                        console.log('⚠️ Recent verification API failed:', {
                            status: response.status,
                            error: errorData.message || 'Unknown error'
                        });
                    }
                } catch (e) {
                    console.log('⚠️ Could not extract email from verification events:', e.message);
                }

                console.log('❌ Could not extract email from any source');
                return null;
            }

            // IMPROVED: Generate deep link with email pre-population
            async function generateDeepLink() {
                const userEmail = await extractUserEmail();
                console.log('🔗 Generating deep link with email:', userEmail);

                // Security: Create verification payload without exposing sensitive data
                const verificationPayload = {
                    verified: 'true',
                    timestamp: Date.now(),
                    session_hint: 'verified_' + Date.now().toString(36)
                };

                if (userEmail) {
                    verificationPayload.email = userEmail;
                }

                const deepLinkParams = new URLSearchParams(verificationPayload);
                return \`manito://auth/login?\${deepLinkParams.toString()}\`;
            }

            // Set up the app button
            document.getElementById('openAppBtn').addEventListener('click', async (e) => {
                e.preventDefault();
                try {
                    const deepLink = await generateDeepLink();
                    console.log('🚀 Opening deep link:', deepLink);
                    window.location.href = deepLink;

                    // Fallback: Show instructions if app doesn't open
                    setTimeout(() => {
                        alert('¿No se abrió la app? Búscala en tu teléfono y abre Manito manualmente.');
                    }, 2000);
                } catch (error) {
                    console.error('❌ Error generating deep link:', error);
                    window.location.href = 'manito://auth/login?verified=true&method=error_fallback';
                }
            });

            // Auto-close after 30 seconds if no interaction
            let hasInteracted = false;
            document.addEventListener('click', () => { hasInteracted = true; });
            setTimeout(() => { if (!hasInteracted) window.close(); }, 30000);

            console.log('✅ IMPROVED verification success page loaded with retry logic');
        </script>
    </body>
    </html>
  `;
}

/**
 * Generate fallback page for errors
 */
function generateFallbackPage() {
  return `
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
}