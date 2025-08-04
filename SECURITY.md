# Security Policy

## Overview

RESK-LLM-TS is a security-focused library designed to protect LLM interactions from various threats including prompt injection, PII leakage, toxic content, and other security vulnerabilities. We take security seriously and appreciate the security community's efforts to help us maintain the highest security standards.

## Supported Versions

We provide security updates for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 0.3.x   | :white_check_mark: |
| 0.2.x   | :white_check_mark: |
| < 0.2   | :x:                |

## Reporting a Vulnerability

### Security Contact

If you discover a security vulnerability, please report it responsibly:

- **Email**: contact@resk.fr
- **Subject**: [SECURITY] RESK-LLM-TS Vulnerability Report
- **Response Time**: We aim to respond within 24 hours

### What to Include

Please include the following information in your security report:

1. **Description** of the vulnerability
2. **Steps to reproduce** the issue
3. **Potential impact** assessment
4. **Suggested fix** (if available)
5. **Your contact information** for follow-up

### What NOT to Include

- Do not include actual API keys or sensitive credentials
- Do not publish the vulnerability publicly before we've had a chance to address it
- Do not test the vulnerability against production systems

## Vulnerability Handling Process

1. **Acknowledgment** (24 hours): We confirm receipt of your report
2. **Initial Assessment** (72 hours): We evaluate the severity and impact
3. **Investigation** (1-2 weeks): We investigate and develop a fix
4. **Resolution** (varies): We release a patch and security advisory
5. **Disclosure** (coordinated): Public disclosure after fix is released

## Security Features

RESK-LLM-TS includes multiple security layers:

### Frontend Security
- **Input Validation**: Comprehensive input sanitization
- **PII Detection**: Automatic detection and protection of sensitive data
- **Prompt Injection Protection**: Advanced prompt injection detection
- **Content Moderation**: Toxic content filtering
- **API Key Protection**: Prevention of accidental API key exposure

### Backend Security
- **Sanitization**: Input/output sanitization
- **Rate Limiting**: Protection against abuse
- **Logging & Monitoring**: Security event logging
- **Vector Database Security**: Secure vector storage and retrieval

### SIEM Integration
- **Real-time Monitoring**: Security event streaming
- **Multiple Platforms**: Support for Splunk, Elastic, Azure Sentinel, Datadog
- **Custom Webhooks**: Flexible integration options

## Security Best Practices

### For Developers

1. **API Key Management**
   - Never hardcode API keys in source code
   - Use environment variables or secure vaults
   - Rotate keys regularly
   - Monitor key usage

2. **Input Validation**
   - Always validate user inputs
   - Use the library's built-in sanitization
   - Implement additional validation as needed
   - Log suspicious activities

3. **Error Handling**
   - Don't expose sensitive information in error messages
   - Log errors securely
   - Implement proper error recovery

4. **Dependencies**
   - Keep dependencies updated
   - Regularly audit for vulnerabilities
   - Use only trusted packages

### For Users

1. **Configuration**
   - Use strict security settings
   - Enable all relevant security features
   - Configure appropriate thresholds
   - Monitor security logs

2. **Deployment**
   - Use HTTPS in production
   - Implement proper access controls
   - Monitor resource usage
   - Regular security assessments

## Known Security Considerations

### Frontend Usage
- The frontend security filter is **not** a replacement for backend security
- Always implement server-side validation
- Use the frontend filter as an additional layer of protection
- Backend proxy is recommended for LLM API calls

### Data Handling
- PII detection is pattern-based and may have false positives/negatives
- Always implement additional data protection measures
- Consider data residency requirements
- Implement proper data retention policies

### Performance vs Security
- Some security features may impact performance
- Configure thresholds based on your use case
- Monitor performance metrics
- Balance security and usability

## Security Configuration

### Recommended Settings

```typescript
const securityConfig = {
  piiProtection: {
    enabled: true,
    strictMode: true,
    customPatterns: []
  },
  promptInjection: {
    enabled: true,
    sensitivity: 'high',
    blockOnDetection: true
  },
  contentModeration: {
    enabled: true,
    categories: ['toxic', 'hate', 'violence'],
    threshold: 0.7
  },
  logging: {
    enabled: true,
    level: 'warn',
    securityEvents: true
  }
};
```

### SIEM Configuration

```typescript
const siemConfig = {
  type: 'webhook',
  endpoint: 'https://your-siem.com/webhook',
  batchSize: 100,
  flushInterval: 30000,
  retryPolicy: {
    maxRetries: 3,
    backoffMs: 1000
  }
};
```

## Compliance and Standards

We follow industry best practices and standards:

- **OWASP** - Application Security Guidelines
- **ISO 27001** - Information Security Management
- **GDPR** - Data Protection Regulation
- **SOC 2** - Security and Availability

## Security Audits

- Regular internal security assessments
- Third-party security audits (annually)
- Automated vulnerability scanning
- Dependency vulnerability monitoring

## Responsible Disclosure

We believe in responsible disclosure and will:

1. **Acknowledge** security researchers who report vulnerabilities
2. **Provide updates** on our progress addressing the issue
3. **Credit researchers** in our security advisories (if desired)
4. **Maintain confidentiality** until patches are released

## Security Resources

- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)
- [Security Documentation](docs/SIEM_MONITORING_GUIDE.md)

## Contact

For security-related questions or concerns:

- **Security Team**: contact@resk.fr
- **General Support**: https://github.com/Resk-Security/resk-llm-js/issues
- **Website**: https://resk.fr

---

*Last updated: 2024*
*Version: 1.0*