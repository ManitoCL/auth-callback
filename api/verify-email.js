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
