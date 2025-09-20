/**
 * PHASE 2: Device-Agnostic Email Verification (Enterprise Pattern)
 * Meta/Instagram approach: Just flip backend flag, no deep links
 * Works on any device - verify on laptop, continue on phone seamlessly
 */

const { createClient } = require('@supabase/supabase-js');

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const supabase = createClient(supabaseUrl, supabaseServiceKey);

/**
 * ENTERPRISE: Simple success page (no deep links)
 * User can verify anywhere, continue anywhere
 */
function renderSuccessPage(email) {
  return `
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Email Verificado - Manito</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
            margin: 0;
        }
        .container {
            background: white;
            padding: 40px;
            border-radius: 16px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            text-align: center;
            max-width: 500px;
            width: 100%;
        }
        .icon { font-size: 60px; margin-bottom: 20px; color: #10B981; }
        h1 { color: #1F2937; margin-bottom: 16px; font-size: 28px; font-weight: 700; }
        p { color: #6B7280; line-height: 1.6; margin-bottom: 24px; font-size: 16px; }
        .device-info {
            background: #EEF2FF;
            border: 2px solid #667eea;
            padding: 20px;
            border-radius: 12px;
            margin: 24px 0;
        }
        .device-info h3 { color: #374151; margin-bottom: 12px; font-size: 18px; }
        .device-info p { color: #4B5563; margin-bottom: 0; font-size: 14px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">✅</div>
        <h1>¡Email Verificado!</h1>
        <p>Tu dirección de email <strong>${email}</strong> ha sido confirmada exitosamente.</p>

        <div class="device-info">
            <h3>🔄 Verificación Multi-Dispositivo</h3>
            <p>
                Ahora puedes regresar a la aplicación Manito en <strong>cualquier dispositivo</strong>
                para continuar. La verificación se sincronizará automáticamente.
            </p>
        </div>

        <p style="font-size: 14px; color: #9CA3AF;">
            Esta ventana se puede cerrar de forma segura.
        </p>
    </div>
</body>
</html>`;
}

/**
 * ENTERPRISE: Error page with clear messaging
 */
function renderErrorPage(error, email) {
  return `
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Error de Verificación - Manito</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
            margin: 0;
        }
        .container {
            background: white;
            padding: 40px;
            border-radius: 16px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            text-align: center;
            max-width: 500px;
            width: 100%;
        }
        .icon { font-size: 60px; margin-bottom: 20px; color: #EF4444; }
        h1 { color: #1F2937; margin-bottom: 16px; font-size: 28px; font-weight: 700; }
        p { color: #6B7280; line-height: 1.6; margin-bottom: 24px; font-size: 16px; }
        .error-details {
            background: #FEF2F2;
            border: 1px solid #FECACA;
            padding: 16px;
            border-radius: 8px;
            margin: 24px 0;
        }
        .error-details p { color: #B91C1C; margin: 0; font-size: 14px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">❌</div>
        <h1>Error en la Verificación</h1>
        <p>No se pudo verificar el email${email ? ` <strong>${email}</strong>` : ''}.</p>

        <div class="error-details">
            <p><strong>Error:</strong> ${error}</p>
        </div>

        <p style="font-size: 14px; color: #9CA3AF;">
            Por favor intenta nuevamente desde la aplicación o contacta soporte en
            <strong>soporte@manito.cl</strong>
        </p>
    </div>
</body>
</html>`;
}

/**
 * PHASE 2: Device-Agnostic Email Verification Handler
 * Enterprise pattern: Just flip backend flag, no device coupling
 */
export default async function handler(req, res) {
  const { token_hash, type } = req.query;

  console.log('🚀 Phase 2 Enterprise Verification:', {
    token_hash: token_hash ? `${token_hash.substring(0, 8)}...` : 'missing',
    type,
    timestamp: new Date().toISOString(),
    approach: 'device_agnostic_enterprise'
  });

  // ENTERPRISE: Input validation
  if (!token_hash || !type) {
    console.error('❌ Phase 2 - Missing required parameters');
    return res.status(400).send(renderErrorPage(
      'Faltan parámetros de verificación requeridos',
      null
    ));
  }

  try {
    // ENTERPRISE PATTERN: Simple OTP verification - just flip flag
    const { data, error } = await supabase.auth.verifyOtp({
      token_hash,
      type: type === 'email' ? 'signup' : type,
    });

    if (error) {
      console.error('❌ Phase 2 - Verification failed:', error.message);
      return res.status(400).send(renderErrorPage(error.message, null));
    }

    if (!data.user) {
      console.error('❌ Phase 2 - No user in verification result');
      return res.status(400).send(renderErrorPage(
        'No se encontró información del usuario',
        null
      ));
    }

    console.log('✅ Phase 2 Enterprise Verification Success:', {
      userId: data.user.id,
      email: data.user.email,
      emailVerified: !!data.user.email_confirmed_at,
      autoProvisionTriggered: true, // Database trigger handles profile creation
      deviceAgnostic: true
    });

    // ENTERPRISE PATTERN: Just show success, no device coupling
    // User can continue on any device by opening the app
    return res.status(200).send(renderSuccessPage(data.user.email));

  } catch (error) {
    console.error('❌ Phase 2 - Unexpected verification error:', error);
    return res.status(500).send(renderErrorPage(
      'Error interno del servidor. Por favor intenta nuevamente.',
      null
    ));
  }
}

/**
 * PHASE 2 ENTERPRISE BENEFITS:
 * ✅ Device-agnostic: Verify anywhere, continue anywhere
 * ✅ No deep links: No device coupling or handoff complexity
 * ✅ Auto-provisioning: Database triggers handle profile creation
 * ✅ Simple UX: Clear success/error states
 * ✅ Enterprise reliability: Proper error handling
 * ✅ Meta/Instagram pattern: Backend flag flip only
 */