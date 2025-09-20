/**
 * Email Verification Success Handler
 * Serves the success page after email verification
 */

import { readFileSync } from 'fs';
import { join } from 'path';

export default function handler(req, res) {
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

    // Read the verified.html file
    const htmlPath = join(process.cwd(), 'verified.html');
    const html = readFileSync(htmlPath, 'utf8');

    // Set content type and send response
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.status(200).send(html);

  } catch (error) {
    console.error('Error serving verification success page:', error);

    // Fallback minimal success page
    const fallbackHtml = `
      <!DOCTYPE html>
      <html lang="es">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Email Verificado - Manito</title>
        <style>
          body {
            font-family: -apple-system, BlinkMacSystemFont, sans-serif;
            text-align: center;
            padding: 50px;
            background: #f0f9ff;
          }
          .container {
            max-width: 400px;
            margin: 0 auto;
            background: white;
            padding: 40px;
            border-radius: 12px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.1);
          }
          .success {
            font-size: 48px;
            color: #10b981;
            margin-bottom: 20px;
          }
          h1 {
            color: #1f2937;
            margin-bottom: 16px;
          }
          p {
            color: #6b7280;
            line-height: 1.6;
          }
          .btn {
            display: inline-block;
            background: #059669;
            color: white;
            padding: 12px 24px;
            border-radius: 8px;
            text-decoration: none;
            margin-top: 20px;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="success">✓</div>
          <h1>¡Email Verificado!</h1>
          <p>Tu cuenta de Manito ha sido verificada exitosamente.</p>
          <p>Vuelve a la app e inicia sesión para continuar.</p>
          <a href="manito://auth/verified" class="btn">Abrir App Manito</a>
        </div>
        <script>
          setTimeout(() => window.close(), 10000);
        </script>
      </body>
      </html>
    `;

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.status(200).send(fallbackHtml);
  }
}