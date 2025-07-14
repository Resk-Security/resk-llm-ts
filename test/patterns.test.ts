import { doxxingPatterns } from '../src/security/patterns/doxxing_patterns';
import { maliciousUrlPatterns } from '../src/security/patterns/malicious_url_patterns';
import { ipLeakagePatterns } from '../src/security/patterns/ip_leakage_patterns';

describe('Security Patterns', () => {
  it('detects doxxing patterns', () => {
    const samples = [
      '123 rue de Paris',
      '456 Avenue des Champs',
      '789 street road',
      '@username',
      'facebook.com/user',
      'nom: Dupont',
      'name: Smith',
    ];
    for (const s of samples) {
      expect(doxxingPatterns.some(pattern => pattern.test(s))).toBe(true);
    }
  });

  it('detects malicious URLs', () => {
    const samples = [
      'https://bit.ly/abc',
      'https://malicious.ru/login',
      'https://phishingsite.com/verify',
    ];
    for (const pattern of maliciousUrlPatterns) {
      expect(samples.some(s => pattern.test(s))).toBe(true);
    }
  });

  it('detects IP leakage', () => {
    const samples = [
      '192.168.1.1',
      '10.0.0.5',
      '172.16.0.1',
      '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
    ];
    for (const pattern of ipLeakagePatterns) {
      expect(samples.some(s => pattern.test(s))).toBe(true);
    }
  });
}); 