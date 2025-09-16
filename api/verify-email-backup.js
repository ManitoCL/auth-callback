// Vercel Edge Function for Supabase email verification
import { createClient } from "@supabase/supabase-js";

const supabaseUrl = process.env.SUPABASE_URL || "https://rlxsytlesoqbcgbnhwhq.supabase.co";
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const supabaseAnonKey = process.env.SUPABASE_ANON_KEY || "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InJseHN5dGxlc29xYmNnYm5od2hxIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTc3MTY4MzYsImV4cCI6MjA3MzI5MjgzNn0.-JXn6oXvFj4GBX1EyIfrN4J5WEhFSvBCSZskAKusi9M";

export default async function handler(req, res) {
  // Enable CORS for all origins
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  if (req.method !== "GET" && req.method !== "POST") {
    return res.status(405).json({
      error: "Method not allowed",
      message: "Solo se permiten métodos GET y POST"
    });
  }

  try {
    console.log("=== Email Verification Handler ===");
    console.log("Method:", req.method);
    console.log("Query params:", req.query);
    console.log("URL:", req.url);

    // Extract verification code from query parameters
    const { code, type = "signup", error, error_description } = req.query;

    // Handle Supabase error responses
    if (error) {
      console.error("Supabase verification error:", { error, error_description });
      return redirectToApp({
        error: error_description || error,
        type: "error"
      }, res);
    }

    // Validate verification code
    if (!code || typeof code !== "string" || code.length < 10) {
      console.error("Invalid verification code:", { code, codeLength: code?.length });
      return redirectToApp({
        error: "Código de verificación inválido o expirado",
        type: "error"
      }, res);
    }

    console.log("Processing verification:", {
      hasCode: !!code,
      codeLength: code.length,
      type
    });

    // Create Supabase client for verification
    const supabase = createClient(supabaseUrl, supabaseAnonKey);

    // Verify the email using the code
    console.log("Calling supabase.auth.verifyOtp...");
    const { data, error: verifyError } = await supabase.auth.verifyOtp({
      token_hash: code,
      type: type === "recovery" ? "recovery" : "email"
    });

    if (verifyError) {
      console.error("Supabase verification failed:", {
        error: verifyError.message,
        code: verifyError.status,
        details: verifyError
      });

      // Handle specific error cases with Spanish messages
      let errorMessage = "Error al verificar el email";
      if (verifyError.message?.includes("expired")) {
        errorMessage = "El enlace de verificación ha expirado. Solicita uno nuevo.";
      } else if (verifyError.message?.includes("invalid")) {
        errorMessage = "El enlace de verificación es inválido. Verifica que hayas copiado la URL completa.";
      } else if (verifyError.message?.includes("already")) {
        errorMessage = "Este email ya ha sido verificado anteriormente.";
      }

      return redirectToApp({
        error: errorMessage,
        type: "error"
      }, res);
    }

    if (!data.session) {
      console.error("No session returned from verification");
      return redirectToApp({
        error: "No se pudo crear la sesión. Intenta iniciar sesión manualmente.",
        type: "error"
      }, res);
    }

    console.log("✅ Email verification successful:", {
      hasUser: !!data.user,
      hasSession: !!data.session,
      emailConfirmed: !!data.user?.email_confirmed_at,
      userEmail: data.user?.email
    });

    // Create user profile if this is a signup confirmation
    if (type === "signup" && data.user) {
      try {
        console.log("🔄 Creating user profile for new signup...");

        // Use service role key to create profile
        const serviceSupabase = createClient(supabaseUrl, supabaseServiceKey || supabaseAnonKey);

        const { data: profileData, error: profileError } = await serviceSupabase
          .rpc("create_user_profile_secure", {
            user_id: data.user.id
          });

        if (profileError) {
          console.warn("Profile creation failed (non-fatal):", profileError.message);
        } else {
          console.log("✅ User profile created successfully");
        }
      } catch (profileErr) {
        console.warn("Profile creation exception (non-fatal):", profileErr.message);
      }
    }

    // Create secure session code for mobile app
    try {
      console.log("🔒 Creating secure session code...");

      const sessionData = {
        access_token: data.session.access_token,
        refresh_token: data.session.refresh_token,
        expires_in: data.session.expires_in,
        token_type: data.session.token_type || "bearer",
        type
      };

      // Call internal API to create secure session
      const baseUrl = req.headers.host?.includes("localhost") ? "http://localhost:3000" : `https://${req.headers.host}`;
      const sessionResponse = await fetch(`${baseUrl}/api/create-secure-session`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(sessionData)
      });

      if (sessionResponse.ok) {
        const { session_code } = await sessionResponse.json();
        console.log("✅ Secure session code created");

        return redirectToApp({
          session_code,
          type: "success"
        }, res);
      } else {
        throw new Error("Failed to create secure session");
      }

    } catch (secureError) {
      console.warn("⚠️ Secure session creation failed, using direct tokens:", secureError.message);

      // Fallback to direct token redirect
      return redirectToApp({
        access_token: data.session.access_token,
        refresh_token: data.session.refresh_token,
        expires_in: data.session.expires_in,
        token_type: data.session.token_type || "bearer",
        type: "success"
      }, res);
    }

  } catch (error) {
    console.error("❌ Email verification handler error:", {
      message: error.message,
      stack: error.stack
    });

    return redirectToApp({
      error: "Error interno del servidor. Intenta nuevamente más tarde.",
      type: "error"
    }, res);
  }
}

function redirectToApp(params, res) {
  const { type, error, session_code, access_token, refresh_token, expires_in, token_type } = params;

  // Build query string for the frontend
  const queryParams = new URLSearchParams();

  if (type) queryParams.set("type", type);
  if (error) queryParams.set("error", error);
  if (session_code) queryParams.set("session_code", session_code);
  if (access_token) queryParams.set("access_token", access_token);
  if (refresh_token) queryParams.set("refresh_token", refresh_token);
  if (expires_in) queryParams.set("expires_in", expires_in.toString());
  if (token_type) queryParams.set("token_type", token_type);

  // Redirect to the frontend handler with the results
  const redirectUrl = `/?${queryParams.toString()}`;

  console.log("🔄 Redirecting to frontend:", {
    redirectUrl: redirectUrl.substring(0, 100) + "...",
    hasError: !!error,
    hasSessionCode: !!session_code,
    hasTokens: !!(access_token && refresh_token)
  });

  return res.redirect(302, redirectUrl);
}
