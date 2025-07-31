// lib/security.ts
// This module provides security functions for validating origins, CSRF protection,
// and setting security headers in Next.js applications.
// It includes functions to validate request origins, CSRF tokens, and set security headers.
import { NextRequest, NextResponse } from "next/server";

function getAllowedOrigins(): string[] {
  const origins: string[] = [];

  if (process.env.ALLOWED_ORIGINS) {
    origins.push(
      ...process.env.ALLOWED_ORIGINS.split(",")
        .map((o) => o.trim())
        .filter((o) => {
          try {
            new URL(o);
            return true;
          } catch {
            console.warn(`Invalid origin in ALLOWED_ORIGINS: ${o}`);
            return false;
          }
        })
    );
  }

  if (process.env.NODE_ENV === "development") {
    origins.push("http://localhost:3000", "http://192.168.88.104:3000");
  }

  return Array.from(new Set(origins));
}

export function validateOrigin(request: NextRequest): NextResponse | null {
  const allowedOrigins = getAllowedOrigins();
  const origin = request.headers.get("origin");
  const referer = request.headers.get("referer");

  if (origin && !allowedOrigins.includes(origin)) {
    console.warn(`Unauthorized origin attempted: ${origin}`);
    return NextResponse.json(
      { success: false, error: "Unauthorized origin" },
      { status: 403 }
    );
  }

  if (!origin && referer) {
    try {
      const refererOrigin = new URL(referer).origin;
      if (!allowedOrigins.includes(refererOrigin)) {
        console.warn(`Unauthorized referer attempted: ${refererOrigin}`);
        return NextResponse.json(
          { success: false, error: "Unauthorized origin" },
          { status: 403 }
        );
      }
    } catch {
      console.warn(`Invalid referer URL: ${referer}`);
      return NextResponse.json(
        { success: false, error: "Invalid request origin" },
        { status: 403 }
      );
    }
  }

  return null;
}

export function validateCSRF(request: NextRequest): NextResponse | null {
  const method = request.method;
  if (!["POST", "PUT", "PATCH", "DELETE"].includes(method)) {
    return null;
  }

  const allowedOrigins = getAllowedOrigins();
  const origin = request.headers.get("origin");
  const referer = request.headers.get("referer");

  try {
    const requestOrigin = origin || (referer ? new URL(referer).origin : null);

    if (!requestOrigin || !allowedOrigins.includes(requestOrigin)) {
      console.warn(`CSRF protection triggered for origin: ${requestOrigin}`);
      return NextResponse.json(
        { success: false, error: "CSRF protection: Invalid origin" },
        { status: 403 }
      );
    }
  } catch (e) {
    console.warn(`Error validating CSRF: ${e}`);
    return NextResponse.json(
      { success: false, error: "Invalid request origin" },
      { status: 403 }
    );
  }

  return null;
}

export function validateSecurity(request: NextRequest): NextResponse | null {
  const originError = validateOrigin(request);
  if (originError) return originError;

  const csrfError = validateCSRF(request);
  if (csrfError) return csrfError;

  return null;
}

/**
 * Sets security headers and CORS headers on the response
 */
export function setSecurityHeaders(response: NextResponse, origin?: string | null): NextResponse {
  // Security Headers (Existing)
  response.headers.set('X-Content-Type-Options', 'nosniff');
  response.headers.set('X-Frame-Options', 'DENY');
  response.headers.set('X-XSS-Protection', '1; mode=block');
  response.headers.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');

  // CORS Headers (Existing)
  const allowedOrigins = getAllowedOrigins();
  if (origin && allowedOrigins.includes(origin)) {
    response.headers.set('Access-Control-Allow-Origin', origin);
  } else if (allowedOrigins.length > 0) {
    response.headers.set('Access-Control-Allow-Origin', allowedOrigins[0]);
  }
  response.headers.set('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
  response.headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
  response.headers.set('Access-Control-Allow-Credentials', 'true');
  response.headers.set('Access-Control-Max-Age', '86400');

  // Content Security Policy (CSP) - Mitigates XSS, data injection, and mixed content
  response.headers.set(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-src 'none'; object-src 'none'; base-uri 'self'; form-action 'self';"
  );

  //Referrer-Policy - Controls referrer leakage
  response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');

  //Permissions-Policy - Restricts browser features (e.g., geolocation, camera)
  response.headers.set(
    'Permissions-Policy',
    'geolocation=(), microphone=(), camera=(), payment=()'
  );

  //Cache-Control - Controls caching behavior (adjust based on sensitivity)
  response.headers.set('Cache-Control', 'public, max-age=3600, must-revalidate');
  response.headers.set('Vary', 'Accept-Encoding, Origin'); // Avoids cache poisoning

  return response;
}

/**
 * Creates a secure NextResponse with security and CORS headers
 */
export function createSecureResponse(
  data: unknown,
  options: {
    status?: number;
    statusText?: string;
    headers?: Record<string, string>;
  } = {},
  request?: NextRequest
): NextResponse {
  const { headers, ...responseOptions } = options;
  const response = NextResponse.json(data, responseOptions);

  if (headers) {
    Object.entries(headers).forEach(([key, value]) => {
      response.headers.set(key, value);
    });
  }

  const origin = request?.headers.get("origin");
  return setSecurityHeaders(response, origin);
}

/**
 * Creates a secure error response with security and CORS headers
 */
export function createSecureErrorResponse(
  error: string,
  status: number = 400,
  request?: NextRequest
): NextResponse {
  const response = NextResponse.json(
    { success: false, error },
    { status }
  );
  const origin = request?.headers.get('origin');
  return setSecurityHeaders(response, origin);
}
