import { Logger } from "./logger.js";

const ALLOWED_FIGMA_DOMAINS = [
  "api.figma.com",
  "figma.com",
  "s3-alpha-sig.figma.com",
  "s3-alpha.figma.com",
];

const MAX_URL_LENGTH = 2048;
const MAX_HEADER_KEY_LENGTH = 256;
const MAX_HEADER_VALUE_LENGTH = 8192;

/**
 * Validates that a URL is safe for use in shell commands
 */
export function validateUrl(url: string): void {
  if (!url || typeof url !== "string") {
    throw new Error("URL must be a non-empty string");
  }

  if (url.length > MAX_URL_LENGTH) {
    throw new Error(`URL exceeds maximum length of ${MAX_URL_LENGTH} characters`);
  }

  let parsedUrl: URL;
  try {
    parsedUrl = new URL(url);
  } catch {
    throw new Error("Invalid URL format");
  }

  // Only allow HTTPS and HTTP (which will be upgraded to HTTPS by curl)
  if (!["https:", "http:"].includes(parsedUrl.protocol)) {
    throw new Error("Only HTTP and HTTPS URLs are allowed");
  }

  // Check for shell injection characters
  const dangerousChars = /[;&|`$(){}[\]\\'"<>]/;
  if (dangerousChars.test(url)) {
    Logger.error(`[Security] Blocked URL with dangerous characters: ${url.substring(0, 100)}...`);
    throw new Error("URL contains potentially dangerous characters");
  }

  // Validate domain whitelist for security
  const hostname = parsedUrl.hostname.toLowerCase();
  const isAllowedDomain = ALLOWED_FIGMA_DOMAINS.some(
    (domain) => hostname === domain || hostname.endsWith("." + domain),
  );

  if (!isAllowedDomain) {
    Logger.error(`[Security] Blocked URL to unauthorized domain: ${hostname}`);
    throw new Error(`URL domain '${hostname}' is not in the allowed list`);
  }
}

/**
 * Validates HTTP headers for security
 */
export function validateHeaders(headers: Record<string, string> | undefined): void {
  if (!headers) return;

  for (const [key, value] of Object.entries(headers)) {
    if (!key || typeof key !== "string") {
      throw new Error("Header key must be a non-empty string");
    }

    if (!value || typeof value !== "string") {
      throw new Error("Header value must be a non-empty string");
    }

    if (key.length > MAX_HEADER_KEY_LENGTH) {
      throw new Error(`Header key exceeds maximum length of ${MAX_HEADER_KEY_LENGTH} characters`);
    }

    if (value.length > MAX_HEADER_VALUE_LENGTH) {
      throw new Error(
        `Header value exceeds maximum length of ${MAX_HEADER_VALUE_LENGTH} characters`,
      );
    }

    // Check for shell injection in header keys
    const dangerousKeyChars = /[;&|`$(){}[\]\\'"<>\n\r]/;
    if (dangerousKeyChars.test(key)) {
      Logger.error(`[Security] Blocked header key with dangerous characters: ${key}`);
      throw new Error("Header key contains potentially dangerous characters");
    }

    // Check for shell injection in header values
    const dangerousValueChars = /[`$(){}[\]\\<>\n\r]/;
    if (dangerousValueChars.test(value)) {
      Logger.error(
        `[Security] Blocked header value with dangerous characters: ${value.substring(0, 50)}...`,
      );
      throw new Error("Header value contains potentially dangerous characters");
    }

    // Additional validation for common injection patterns
    const injectionPatterns = [
      /;\s*[a-zA-Z_][a-zA-Z0-9_]*\s*=/, // Variable assignment
      /&&(?![^"]*"[^"]*$)/, // Command chaining not inside quotes
      /\|\|(?![^"]*"[^"]*$)/, // Command chaining not inside quotes
      /\$\(|\$\{/, // Command substitution
    ];

    for (const pattern of injectionPatterns) {
      if (pattern.test(value)) {
        Logger.error(
          `[Security] Blocked header value with injection pattern: ${value.substring(0, 50)}...`,
        );
        throw new Error("Header value contains potential injection pattern");
      }
    }
  }
}

/**
 * Validates that a constructed curl command is safe
 */
export function validateCurlCommand(command: string): void {
  if (!command || typeof command !== "string") {
    throw new Error("Command must be a non-empty string");
  }

  // Ensure command starts with curl
  if (!command.trim().startsWith("curl ")) {
    throw new Error("Command must start with curl");
  }

  // Check for dangerous command injection patterns
  const dangerousPatterns = [
    /;\s*[^'"]/, // Command separator outside quotes
    /\|\s*[^'"]/, // Pipe outside quotes
    /&&\s*[^'"]/, // And operator outside quotes
    /\|\|\s*[^'"]/, // Or operator outside quotes
    /`[^`]*`/, // Backticks (command substitution)
    /\$\([^)]*\)/, // $() command substitution
  ];

  for (const pattern of dangerousPatterns) {
    if (pattern.test(command)) {
      Logger.error(
        `[Security] Blocked curl command with dangerous pattern: ${command.substring(0, 100)}...`,
      );
      throw new Error("Curl command contains potentially dangerous patterns");
    }
  }
}
