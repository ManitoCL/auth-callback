/**
 * Production-Grade Supabase Email Verification Handler
 * Handles both PKCE and Implicit flows with comprehensive error handling
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

    console.log("=== Email Verification Handler Started ===");
    console.log("Timestamp:", new Date().toISOString());
    console.log("IP:", clientIP);
    console.log("Method:", req.method);
    console.log("Query params:", req.query);
    console.log("User-Agent:", req.headers['user-agent']);

    // Extract parameters - support both PKCE and implicit flows
    const {
      // PKCE flow parameters
      token_hash,
      type = "signup",
      // Implicit flow parameters (if any leak through)
      access_token,
      refresh_token,
      // Error parameters
      error,
      error_code,
      error_description
    } = req.query;

    console.log("Extracted parameters:", {
      hasTokenHash: !!token_hash,
      tokenHashLength: token_hash?.length || 0,
      hasAccessToken: !!access_token,
      hasRefreshToken: !!refresh_token,
      type,
      error,
      error_code
    });

    // Handle Supabase errors first
    if (error) {
      console.error("Supabase returned error:", {
        error,
        error_code,
        error_description,
        type
      });

      let userMessage = "Error al verificar el email";

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

    // Check if this is a valid verification request
    if (!token_hash && !access_token) {
      console.log("No verification tokens found - unauthorized access");
      return redirectToFrontend({
        error: "Acceso no autorizado",
        type: "unauthorized"
      }, res);
    }

    // If we have implicit flow tokens, redirect to frontend (Supabase already verified)
    if (access_token && refresh_token) {
      console.log("✅ Implicit flow verification - tokens already validated by Supabase");
      return redirectToFrontend({
        access_token,
        refresh_token,
        token_type: "bearer",
        expires_in: "3600",
        type: "success",
        flow: "implicit"
      }, res);
    }

    // Handle PKCE flow verification
    if (token_hash) {
      console.log(`🔄 Processing PKCE verification with token_hash (${token_hash.length} chars)`);

      if (token_hash.length < 10) {
        console.error("Token hash too short:", token_hash.length);
        return redirectToFrontend({
          error: "Enlace de verificación inválido o corrupto",
          type: "error"
        }, res);
      }

      // Create Supabase client for PKCE verification
      const supabase = createClient(supabaseUrl, supabaseAnonKey, {
        auth: {
          flowType: 'pkce',
          autoRefreshToken: false,
          persistSession: false
        }
      });

      console.log("Calling supabase.auth.verifyOtp with token_hash...");
      const { data, error: verifyError } = await supabase.auth.verifyOtp({
        token_hash,
        type: type === "recovery" ? "recovery" : "email"
      });

      if (verifyError) {
        console.error("PKCE verification failed:", {
          message: verifyError.message,
          status: verifyError.status,
          code: verifyError.__isAuthError ? 'AUTH_ERROR' : 'UNKNOWN_ERROR'
        });

        let errorMessage = "Error al verificar el email";
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

      // Profile creation is now handled by database triggers automatically
      // Just log for monitoring
      console.log("📝 Profile will be created automatically by database trigger");

      // Return session data for frontend
      return redirectToFrontend({
        access_token: data.session.access_token,
        refresh_token: data.session.refresh_token,
        expires_in: data.session.expires_in?.toString() || "3600",
        token_type: data.session.token_type || "bearer",
        type: "success",
        flow: "pkce"
      }, res);
    }

    // If we get here, something unexpected happened
    console.error("Unexpected verification state:", {
      hasTokenHash: !!token_hash,
      hasAccessToken: !!access_token,
      hasRefreshToken: !!refresh_token,
      query: req.query
    });

    return redirectToFrontend({
      error: "Estado de verificación inesperado. Contacta al soporte técnico.",
      type: "error"
    }, res);

  } catch (error) {
    const processingTime = Date.now() - startTime;
    console.error("❌ Email verification handler error:", {
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
    console.log(`⏱️ Request processed in ${processingTime}ms`);
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
    session_code,
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
  if (session_code) queryParams.set("session_code", session_code);

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
    flow: flow || 'unknown',
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
  return param.replace(/[<>"'&\n\r\t]/g, '').substring(0, 200);
}