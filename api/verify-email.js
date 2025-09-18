/**
 * COMPLETE PKCE EMAIL VERIFICATION HANDLER
 * Follows official Supabase PKCE flow documentation 2024
 * Secure, efficient, and working solution
 */
import { createClient } from "@supabase/supabase-js";

// Configuration
const supabaseUrl = process.env.SUPABASE_URL || "https://rlxsytlesoqbcgbnhwhq.supabase.co";
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const supabaseAnonKey = process.env.SUPABASE_ANON_KEY || "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InJseHN5dGxlc29xYmNnYm5od2hxIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTc3MTY4MzYsImV4cCI6MjA3MzI5MjgzNn0.-JXn6oXvFj4GBX1EyIfrN4J5WEhFSvBCSZskAKusi9M";

const REDIRECT_URL = "https://auth.manito.cl";

// Rate limiting storage (in-memory for serverless)
const rateLimitStore = new Map();

export default async function handler(req, res) {
  // CORS headers
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  if (req.method !== "GET") {
    return res.status(405).json({
      error: "Method not allowed",
      message: "Solo se permite método GET"
    });
  }

  const startTime = Date.now();
  const clientIP = req.headers['x-forwarded-for'] || req.connection.remoteAddress || 'unknown';

  try {
    // Rate limiting check
    if (!checkRateLimit(clientIP)) {
      console.warn(`Rate limit exceeded for IP: ${clientIP}`);
      return redirectToFrontend({
        error: "Demasiados intentos. Espera un momento antes de intentar nuevamente.",
        type: "error"
      }, res);
    }

    console.log("=== PKCE EMAIL VERIFICATION HANDLER ===");
    console.log("Timestamp:", new Date().toISOString());
    console.log("IP:", clientIP);
    console.log("Method:", req.method);
    console.log("Query params:", req.query);
    console.log("User-Agent:", req.headers['user-agent']);

    // Extract PKCE parameters (2025 Supabase best practices)
    const {
      token_hash,
      type = "email", // 2025 best practice: use 'email' not deprecated 'signup'
      error,
      error_code,
      error_description
    } = req.query;

    console.log("PKCE Parameters (2025 best practices):", {
      hasTokenHash: !!token_hash,
      tokenHashLength: token_hash?.length || 0,
      tokenHashPreview: token_hash?.substring(0, 20) + "...",
      type,
      hasError: !!error
    });

    // Handle Supabase errors first
    if (error) {
      console.error("Supabase returned error:", {
        error,
        error_code,
        error_description,
        type
      });

      let userMessage = `SUPABASE_ERROR: ${error} (${error_code})`;

      // Map common Supabase errors to user-friendly Spanish messages
      switch (error) {
        case "server_error":
          if (error_code === "unexpected_failure") {
            userMessage = "Error en el servidor. El enlace puede haber expirado o ser inválido.";
          } else {
            userMessage = "Error interno del servidor. Intenta nuevamente más tarde.";
          }
          break;
        case "invalid_request":
          userMessage = "Enlace de verificación inválido. Verifica que hayas copiado la URL completa.";
          break;
        case "access_denied":
          userMessage = "Acceso denegado. El enlace puede haber expirado.";
          break;
        default:
          userMessage = error_description || "Error desconocido al verificar el email";
      }

      return redirectToFrontend({
        error: userMessage,
        type: "error",
        errorCode: error_code || error
      }, res);
    }

    // Validate token_hash parameter (required for PKCE flow - 2025 best practice)
    if (!token_hash || typeof token_hash !== 'string') {
      console.log("No token_hash found - unauthorized access");
      return redirectToFrontend({
        error: "Acceso no autorizado",
        type: "unauthorized"
      }, res);
    }

    if (token_hash.length < 10) {
      console.error("Token hash too short:", token_hash.length);
      return redirectToFrontend({
        error: "Enlace de verificación inválido o corrupto",
        type: "error"
      }, res);
    }

    console.log(`🔄 Processing PKCE verification with token_hash (${token_hash.length} chars) - 2025 best practice`);

    // Create Supabase client for PKCE verification (MUST use service role key)
    if (!supabaseServiceKey) {
      console.error("SUPABASE_SERVICE_ROLE_KEY is not configured");
      return redirectToFrontend({
        error: "Configuración del servidor incompleta. Contacta al soporte técnico.",
        type: "error"
      }, res);
    }

    const supabase = createClient(supabaseUrl, supabaseServiceKey, {
      auth: {
        autoRefreshToken: false,
        persistSession: false
      }
    });

    console.log("Supabase client configuration:", {
      url: supabaseUrl,
      usingServiceKey: true,
      hasServiceKey: !!supabaseServiceKey,
      serviceKeyLength: supabaseServiceKey?.length || 0,
      note: "Using service role key - anon key failed with unexpected_failure"
    });

    // OFFICIAL PKCE FLOW: Call verifyOtp with token_hash (2025 Supabase best practices)
    const otpParams = {
      token_hash,
      type: type // 'email' is the 2025 recommended type
    };
    console.log("Calling supabase.auth.verifyOtp with params (2025 approach):", JSON.stringify(otpParams));
    const { data, error: verifyError } = await supabase.auth.verifyOtp(otpParams);

    if (verifyError) {
      console.error("PKCE verification failed - DETAILED ERROR:", {
        message: verifyError.message,
        status: verifyError.status,
        code: verifyError.code,
        details: verifyError.details,
        hint: verifyError.hint,
        __isAuthError: verifyError.__isAuthError,
        fullError: JSON.stringify(verifyError, null, 2)
      });

      let errorMessage = `VERIFY_OTP_FAILED: ${verifyError.message} | Params: token_hash=${token_hash?.substring(0,10)}..., type=${type}`;
      const errorMsg = verifyError.message?.toLowerCase() || "";

      if (errorMsg.includes("expired") || errorMsg.includes("invalid")) {
        errorMessage = "El enlace de verificación ha expirado o es inválido. Solicita uno nuevo.";
      } else if (errorMsg.includes("already") || errorMsg.includes("confirmed")) {
        errorMessage = "Este email ya ha sido verificado. Puedes iniciar sesión normalmente.";
      } else if (errorMsg.includes("not found")) {
        errorMessage = "No se encontró el usuario. Verifica que te hayas registrado correctamente.";
      }

      return redirectToFrontend({
        error: errorMessage,
        type: "error",
        originalError: verifyError.message
      }, res);
    }

    if (!data?.session || !data?.user) {
      console.error("PKCE verification succeeded but no session/user returned:", {
        hasData: !!data,
        hasSession: !!data?.session,
        hasUser: !!data?.user
      });
      return redirectToFrontend({
        error: "Verificación exitosa pero no se pudo crear la sesión. Intenta iniciar sesión manualmente.",
        type: "error"
      }, res);
    }

    console.log("✅ PKCE email verification successful:", {
      userId: data.user.id,
      email: data.user.email,
      emailConfirmed: !!data.user.email_confirmed_at,
      hasSession: !!data.session
    });

    // Profile creation will be handled by Enterprise Redux middleware in mobile app
    console.log("📱 Profile creation will be handled by Enterprise Redux workflow in mobile app");
    console.log("ℹ️ NOTE: enterpriseProfileService.ts handles profile creation with retry logic");

    // PKCE SUCCESS: Return session data for frontend
    return redirectToFrontend({
      access_token: data.session.access_token,
      refresh_token: data.session.refresh_token,
      expires_in: data.session.expires_in?.toString() || "3600",
      token_type: data.session.token_type || "bearer",
      type: "success",
      flow: "pkce"
    }, res);

  } catch (error) {
    const processingTime = Date.now() - startTime;
    console.error("❌ PKCE email verification handler error:", {
      message: error.message,
      stack: error.stack,
      processingTime: `${processingTime}ms`,
      clientIP,
      query: req.query
    });

    return redirectToFrontend({
      error: "Error interno del servidor. Intenta nuevamente más tarde.",
      type: "error"
    }, res);
  } finally {
    const processingTime = Date.now() - startTime;
    console.log(`⏱️ PKCE request processed in ${processingTime}ms`);
  }
}

/**
 * Rate limiting implementation
 */
function checkRateLimit(clientIP) {
  const now = Date.now();
  const windowMs = 60000; // 1 minute
  const maxRequests = 5;

  const key = `rate_limit_${clientIP}`;
  const existing = rateLimitStore.get(key) || { count: 0, resetTime: now + windowMs };

  // Reset if window has passed
  if (now > existing.resetTime) {
    existing.count = 0;
    existing.resetTime = now + windowMs;
  }

  // Check if limit exceeded
  if (existing.count >= maxRequests) {
    rateLimitStore.set(key, existing);
    return false;
  }

  // Increment counter
  existing.count++;
  rateLimitStore.set(key, existing);

  return true;
}

/**
 * Secure redirect to frontend with sanitized parameters
 */
function redirectToFrontend(params, res) {
  const {
    type,
    error,
    errorCode,
    originalError,
    access_token,
    refresh_token,
    expires_in,
    token_type,
    flow
  } = params;

  // Build query string for the frontend (using hash for security)
  const queryParams = new URLSearchParams();

  // Always include type
  if (type) queryParams.set("type", sanitizeParam(type));

  // Error parameters
  if (error) queryParams.set("error", sanitizeParam(error));
  if (errorCode) queryParams.set("error_code", sanitizeParam(errorCode));

  // Success parameters
  if (access_token) queryParams.set("access_token", access_token); // Don't sanitize tokens
  if (refresh_token) queryParams.set("refresh_token", refresh_token);
  if (expires_in) queryParams.set("expires_in", expires_in.toString());
  if (token_type) queryParams.set("token_type", sanitizeParam(token_type));
  if (flow) queryParams.set("flow", sanitizeParam(flow));

  // Use hash fragment for sensitive data (not logged by most servers)
  const redirectUrl = type === "error" || type === "unauthorized"
    ? `/?${queryParams.toString()}` // Query string for errors (safe to log)
    : `/#${queryParams.toString()}`; // Hash fragment for tokens (not logged)

  // Security: Validate redirect URL
  if (redirectUrl.length > 2048) {
    console.error("Redirect URL too long, potential attack");
    return res.redirect(302, "/?error=invalid_request&type=error");
  }

  console.log("🔄 Redirecting to frontend:", {
    type,
    hasError: !!error,
    hasTokens: !!(access_token && refresh_token),
    flow: flow || 'pkce',
    // Don't log the full URL with tokens for security
    urlPreview: type === "error" ? redirectUrl : `/${type === 'success' ? '#[TOKENS]' : '?[PARAMS]'}`
  });

  return res.redirect(302, redirectUrl);
}

/**
 * Sanitize parameters to prevent XSS
 */
function sanitizeParam(param) {
  if (typeof param !== 'string') return param;
  // Remove potentially dangerous characters
  return param.replace(/[<>\"'&\n\r\t]/g, '').substring(0, 200);
}