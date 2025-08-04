# SIEM Integration & Security Monitoring Guide

## 🔍 SIEM Monitoring Overview

The Resk-LLM-TS library provides enterprise-grade SIEM (Security Information and Event Management) integration for comprehensive security monitoring. This system automatically captures, processes, and forwards security events to your existing SIEM infrastructure.

## 📊 How SIEM Monitoring Works

### 1. Event Collection
The security filter automatically generates events for:
- **Injection Attempts**: Prompt injection detection with confidence scores
- **Content Violations**: Blocked content by moderation policies  
- **PII Detection**: Personally Identifiable Information found in requests
- **Performance Issues**: Slow validations, timeouts, errors
- **Security Violations**: API key exposure, bypass attempts

### 2. Event Processing
Events are:
- **Enriched** with user context (IP, session, browser)
- **Filtered** by severity levels (low/medium/high/critical)
- **Batched** for efficient transmission
- **Retried** with exponential backoff on failures

### 3. Event Forwarding
Events are sent to your SIEM using:
- **Real-time streaming** for critical events
- **Batch processing** for normal events
- **Multiple channels** (webhook, Splunk, Elastic, etc.)
- **Compliance formatting** (GDPR, HIPAA, PCI-DSS)

## 🚀 Quick Setup Examples

### Basic Webhook Integration
```typescript
import { ReskSecurityFilter, SIEMIntegration } from 'resk-llm-ts';

// Simple webhook endpoint
const securityFilter = new ReskSecurityFilter({
    siem: {
        enabled: true,
        provider: 'webhook',
        endpoint: 'https://your-security-api.com/events',
        apiKey: 'your-webhook-token',
        batchSize: 50,
        flushInterval: 30000, // 30 seconds
        filters: {
            minSeverity: 'medium',
            includeSuccess: false,
            includeMetrics: true
        }
    }
});
```

### Splunk Enterprise Integration
```typescript
const splunkSiem = new SIEMIntegration({
    enabled: true,
    provider: 'splunk',
    endpoint: 'https://splunk-hec.yourcompany.com:8088/services/collector',
    apiKey: process.env.SPLUNK_HEC_TOKEN,
    indexName: 'security_events',
    batchSize: 100,
    retryPolicy: {
        maxRetries: 3,
        retryDelay: 2000,
        exponentialBackoff: true
    }
});

// Use in security filter
const filter = new ReskSecurityFilter({
    siem: splunkSiem.config
});
```

### Elasticsearch/ELK Stack Integration
```typescript
const elasticSiem = new SIEMIntegration({
    enabled: true,
    provider: 'elastic',
    endpoint: 'https://elasticsearch.yourcompany.com:9200',
    apiKey: process.env.ELASTIC_API_KEY,
    indexName: 'resk-security-logs',
    batchSize: 200,
    filters: {
        minSeverity: 'low',
        includeSuccess: true,
        includeMetrics: true
    }
});
```

### Azure Sentinel Integration
```typescript
const azureSiem = new SIEMIntegration({
    enabled: true,
    provider: 'azure-sentinel',
    endpoint: 'your-workspace-id', // Log Analytics Workspace ID
    apiKey: process.env.AZURE_LOG_ANALYTICS_KEY,
    batchSize: 100
});
```

### Datadog Integration
```typescript
const datadogSiem = new SIEMIntegration({
    enabled: true,
    provider: 'datadog',
    apiKey: process.env.DATADOG_API_KEY,
    batchSize: 150,
    filters: {
        minSeverity: 'medium',
        includeMetrics: true
    }
});
```

## 🛠️ Adding Custom SIEM Endpoints

### 1. Custom Webhook Endpoint

Create your own security event receiver:

```typescript
// Backend endpoint (Express.js example)
import express from 'express';
import { SecurityEvent } from 'resk-llm-ts';

const app = express();

app.post('/api/security/events', express.json(), (req, res) => {
    const { source, events, metadata } = req.body;
    
    // Validate the request
    if (source !== 'resk-llm-ts' || !Array.isArray(events)) {
        return res.status(400).json({ error: 'Invalid event format' });
    }

    // Process each security event
    events.forEach((event: SecurityEvent) => {
        console.log(`[SECURITY] ${event.eventType}: ${event.severity}`);
        
        // Route to appropriate handler
        switch (event.eventType) {
            case 'injection_detected':
                handleInjectionEvent(event);
                break;
            case 'content_blocked':
                handleContentViolation(event);
                break;
            case 'pii_detected':
                handlePIIEvent(event);
                break;
            default:
                handleGenericEvent(event);
        }
    });

    res.json({ 
        success: true, 
        processed: events.length,
        timestamp: new Date().toISOString()
    });
});

function handleInjectionEvent(event: SecurityEvent) {
    // Send alert to security team
    if (event.severity === 'critical') {
        sendUrgentAlert('Potential prompt injection detected', event);
    }
    
    // Log to security database
    securityDb.insertEvent(event);
    
    // Update threat intelligence
    updateThreatPatterns(event.details);
}

function handleContentViolation(event: SecurityEvent) {
    // Log policy violation
    complianceDb.recordViolation(event);
    
    // Check for patterns
    if (isRepeatedViolation(event.source)) {
        flagUserAccount(event.userId);
    }
}

function handlePIIEvent(event: SecurityEvent) {
    // GDPR compliance logging
    if (event.compliance?.gdprRelevant) {
        gdprDb.recordPIIEvent(event);
    }
    
    // Send notification to data protection officer
    if (event.severity === 'high') {
        notifyDPO(event);
    }
}
```

### 2. Custom SIEM Provider

Extend the SIEM system for proprietary solutions:

```typescript
import { SIEMIntegration, SecurityEvent, SIEMConfig } from 'resk-llm-ts';

class CustomSIEMProvider extends SIEMIntegration {
    constructor(config: SIEMConfig) {
        super({
            ...config,
            provider: 'custom'
        });
    }

    protected async sendToCustom(events: SecurityEvent[]): Promise<void> {
        // Your custom SIEM implementation
        const transformedEvents = events.map(event => ({
            timestamp: event.timestamp,
            event_type: event.eventType,
            severity_level: this.mapSeverity(event.severity),
            user_id: event.userId,
            session_id: event.sessionId,
            event_details: JSON.stringify(event.details),
            compliance_flags: event.compliance
        }));

        // Send to your SIEM system
        await yourSiemApi.sendEvents(transformedEvents);
    }

    private mapSeverity(severity: string): number {
        const mapping = { low: 1, medium: 2, high: 3, critical: 4 };
        return mapping[severity] || 1;
    }
}

// Usage
const customSiem = new CustomSIEMProvider({
    enabled: true,
    endpoint: 'https://your-siem.company.com/api/events',
    apiKey: process.env.CUSTOM_SIEM_TOKEN
});
```

## 📈 Event Types and Structure

### Security Event Schema
```typescript
interface SecurityEvent {
    // Basic event information
    timestamp: string;           // ISO 8601 timestamp
    eventId: string;            // Unique event identifier
    eventType: 'request_validation' | 'response_validation' | 
               'injection_detected' | 'content_blocked' | 
               'pii_detected' | 'performance_metric';
    severity: 'low' | 'medium' | 'high' | 'critical';
    source: 'frontend' | 'security_filter';
    
    // User context
    userId?: string;            // User identifier
    sessionId?: string;         // Session identifier
    userAgent?: string;         // Browser user agent
    ipAddress?: string;         // Client IP address
    
    // Event details
    details: Record<string, unknown>;
    
    // Compliance information
    compliance?: {
        gdprRelevant?: boolean;
        pciScope?: boolean;
        hipaaProtected?: boolean;
        retentionDays?: number;
    };
}
```

### Injection Detection Event
```typescript
{
    "timestamp": "2024-01-15T10:30:00.000Z",
    "eventId": "resk_1705312200000_abc123def",
    "eventType": "injection_detected",
    "severity": "high",
    "source": "frontend",
    "userId": "user_12345",
    "sessionId": "session_67890",
    "userAgent": "Mozilla/5.0...",
    "ipAddress": "192.168.1.100",
    "details": {
        "confidence": 0.85,
        "techniques": ["direct_override", "role_switch"],
        "blocked": true,
        "contentLength": 156,
        "contentSample": "Ignore all previous instructions and..."
    },
    "compliance": {
        "gdprRelevant": false,
        "retentionDays": 90
    }
}
```

### Content Moderation Event
```typescript
{
    "timestamp": "2024-01-15T10:35:00.000Z",
    "eventId": "resk_1705312500000_def456ghi",
    "eventType": "content_blocked",
    "severity": "medium",
    "source": "frontend",
    "details": {
        "categories": ["toxic", "harassment"],
        "actions": ["block", "log"],
        "confidence": 0.92,
        "contentLength": 87
    }
}
```

### PII Detection Event
```typescript
{
    "timestamp": "2024-01-15T10:40:00.000Z",
    "eventId": "resk_1705312800000_ghi789jkl",
    "eventType": "pii_detected",
    "severity": "medium",
    "source": "frontend",
    "details": {
        "types": ["email", "phone"],
        "count": 2,
        "redacted": false,
        "context": "user_input"
    },
    "compliance": {
        "gdprRelevant": true,
        "retentionDays": 365
    }
}
```

## 🔧 Configuration Management

### Environment-Based Configuration
```typescript
// config/siem.config.ts
export const getSiemConfig = () => {
    const environment = process.env.NODE_ENV || 'development';
    
    const baseConfig = {
        enabled: true,
        batchSize: 50,
        flushInterval: 30000,
        filters: {
            minSeverity: 'medium' as const,
            includeSuccess: false,
            includeMetrics: true
        }
    };

    switch (environment) {
        case 'production':
            return {
                ...baseConfig,
                provider: 'splunk' as const,
                endpoint: process.env.SPLUNK_HEC_ENDPOINT!,
                apiKey: process.env.SPLUNK_HEC_TOKEN!,
                indexName: 'prod_security_events',
                batchSize: 200,
                filters: {
                    minSeverity: 'low' as const,
                    includeSuccess: true,
                    includeMetrics: true
                }
            };
            
        case 'staging':
            return {
                ...baseConfig,
                provider: 'webhook' as const,
                endpoint: process.env.STAGING_WEBHOOK_URL!,
                apiKey: process.env.STAGING_WEBHOOK_TOKEN!,
                filters: {
                    minSeverity: 'medium' as const,
                    includeSuccess: false,
                    includeMetrics: true
                }
            };
            
        case 'development':
        default:
            return {
                ...baseConfig,
                provider: 'webhook' as const,
                endpoint: 'http://localhost:3001/api/security/events',
                apiKey: 'dev-token-123',
                filters: {
                    minSeverity: 'low' as const,
                    includeSuccess: true,
                    includeMetrics: true
                }
            };
    }
};
```

### Dynamic SIEM Configuration
```typescript
import { ReskSecurityFilter } from 'resk-llm-ts';

class AdaptiveSIEMManager {
    private securityFilter: ReskSecurityFilter;
    private currentConfig: any;

    constructor() {
        this.currentConfig = getSiemConfig();
        this.securityFilter = new ReskSecurityFilter({
            siem: this.currentConfig
        });
        
        // Monitor and adapt SIEM configuration
        this.startConfigMonitoring();
    }

    private startConfigMonitoring() {
        setInterval(() => {
            this.adaptConfiguration();
        }, 60000); // Check every minute
    }

    private adaptConfiguration() {
        const metrics = this.securityFilter.getPerformanceStats();
        
        // Adapt batch size based on throughput
        if (metrics.totalValidations > 1000) {
            this.updateBatchSize(Math.min(500, this.currentConfig.batchSize * 1.2));
        }
        
        // Adjust severity threshold based on event volume
        const eventVolume = this.getEventVolume();
        if (eventVolume > 10000) {
            this.updateSeverityFilter('high');
        } else if (eventVolume < 100) {
            this.updateSeverityFilter('low');
        }
    }

    private updateBatchSize(newSize: number) {
        this.currentConfig.batchSize = newSize;
        console.log(`[SIEM] Adapted batch size to ${newSize}`);
    }

    private updateSeverityFilter(severity: string) {
        this.currentConfig.filters.minSeverity = severity;
        console.log(`[SIEM] Adapted severity filter to ${severity}`);
    }

    private getEventVolume(): number {
        // Get event volume from SIEM metrics
        return 0; // Implement based on your metrics
    }
}
```

## 📊 Monitoring Dashboard Integration

### Grafana Dashboard Configuration
```json
{
    "dashboard": {
        "title": "Resk LLM Security Monitoring",
        "panels": [
            {
                "title": "Security Events by Type",
                "type": "piechart",
                "targets": [
                    {
                        "expr": "sum by (eventType) (resk_security_events_total)",
                        "legendFormat": "{{eventType}}"
                    }
                ]
            },
            {
                "title": "Injection Detection Rate",
                "type": "stat",
                "targets": [
                    {
                        "expr": "rate(resk_injection_detected_total[5m])",
                        "legendFormat": "Injections/min"
                    }
                ]
            },
            {
                "title": "Content Moderation Actions",
                "type": "timeseries",
                "targets": [
                    {
                        "expr": "rate(resk_content_blocked_total[1m])",
                        "legendFormat": "Blocked Content/min"
                    }
                ]
            }
        ]
    }
}
```

### Splunk Search Queries
```sql
-- Top injection techniques
index=security_events eventType=injection_detected 
| stats count by details.techniques 
| sort -count

-- PII detection trends
index=security_events eventType=pii_detected 
| timechart span=1h count by details.types

-- Security events by user
index=security_events 
| stats count by userId, eventType 
| sort -count

-- High-confidence security violations
index=security_events severity=critical OR severity=high 
| table timestamp, eventType, userId, details.confidence, details.blocked
| sort -timestamp
```

## 🚨 Alerting and Response

### Real-time Alert Configuration
```typescript
import { SIEMIntegration } from 'resk-llm-ts';

class SecurityAlertManager {
    private siem: SIEMIntegration;
    private alertChannels: Map<string, Function> = new Map();

    constructor(siemConfig: any) {
        this.siem = new SIEMIntegration(siemConfig);
        this.setupAlertChannels();
        this.startEventMonitoring();
    }

    private setupAlertChannels() {
        // Email alerts
        this.alertChannels.set('email', async (event) => {
            await this.sendEmailAlert(event);
        });

        // Slack alerts  
        this.alertChannels.set('slack', async (event) => {
            await this.sendSlackAlert(event);
        });

        // PagerDuty for critical events
        this.alertChannels.set('pagerduty', async (event) => {
            await this.triggerPagerDuty(event);
        });
    }

    private startEventMonitoring() {
        // Override SIEM event logging to add alerting
        const originalLogEvent = this.siem.logSecurityEvent.bind(this.siem);
        
        this.siem.logSecurityEvent = async (eventType, details, severity) => {
            // Log to SIEM as normal
            await originalLogEvent(eventType, details, severity);
            
            // Check if alert is needed
            if (this.shouldAlert(eventType, severity, details)) {
                await this.triggerAlert(eventType, details, severity);
            }
        };
    }

    private shouldAlert(eventType: string, severity: string, details: any): boolean {
        // Critical events always alert
        if (severity === 'critical') return true;
        
        // High-confidence injection attempts
        if (eventType === 'injection_detected' && details.confidence > 0.8) return true;
        
        // Repeated violations from same user
        if (this.isRepeatedViolation(details.userId)) return true;
        
        return false;
    }

    private async triggerAlert(eventType: string, details: any, severity: string) {
        const alertData = {
            timestamp: new Date().toISOString(),
            eventType,
            severity,
            details,
            alertId: `alert_${Date.now()}_${Math.random().toString(36)}`
        };

        // Send to appropriate channels based on severity
        if (severity === 'critical') {
            await this.alertChannels.get('pagerduty')?.(alertData);
            await this.alertChannels.get('slack')?.(alertData);
        } else if (severity === 'high') {
            await this.alertChannels.get('slack')?.(alertData);
            await this.alertChannels.get('email')?.(alertData);
        } else {
            await this.alertChannels.get('email')?.(alertData);
        }
    }

    private async sendSlackAlert(alertData: any) {
        const webhook = process.env.SLACK_SECURITY_WEBHOOK;
        if (!webhook) return;

        const message = {
            text: `🚨 Security Alert: ${alertData.eventType}`,
            attachments: [{
                color: this.getSeverityColor(alertData.severity),
                fields: [
                    { title: 'Severity', value: alertData.severity, short: true },
                    { title: 'Event Type', value: alertData.eventType, short: true },
                    { title: 'Time', value: alertData.timestamp, short: true },
                    { title: 'Details', value: JSON.stringify(alertData.details, null, 2), short: false }
                ]
            }]
        };

        await fetch(webhook, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(message)
        });
    }

    private getSeverityColor(severity: string): string {
        const colors = {
            low: 'good',
            medium: 'warning', 
            high: 'danger',
            critical: '#ff0000'
        };
        return colors[severity] || 'good';
    }

    private isRepeatedViolation(userId: string): boolean {
        // Implement repeated violation detection
        return false;
    }
}
```

## 🔍 Compliance and Audit

### GDPR Compliance Logging
```typescript
class GDPRComplianceLogger {
    private siem: SIEMIntegration;

    constructor(siem: SIEMIntegration) {
        this.siem = siem;
    }

    async logDataProcessing(userId: string, dataType: string, purpose: string) {
        await this.siem.logSecurityEvent('pii_detected', {
            userId,
            dataType,
            purpose,
            legalBasis: 'consent',
            retentionPeriod: '2 years',
            gdprArticle: 'Article 6.1.a'
        }, 'low');
    }

    async logDataSubjectRequest(userId: string, requestType: 'access' | 'deletion' | 'portability') {
        await this.siem.logSecurityEvent('pii_detected', {
            userId,
            requestType,
            timestamp: new Date().toISOString(),
            status: 'received'
        }, 'medium');
    }
}
```

### HIPAA Audit Trail
```typescript
class HIPAAAuditLogger {
    private siem: SIEMIntegration;

    constructor(siem: SIEMIntegration) {
        this.siem = siem;
    }

    async logPHIAccess(userId: string, patientId: string, accessType: string) {
        await this.siem.logSecurityEvent('pii_detected', {
            userId,
            patientId: this.hashPatientId(patientId),
            accessType,
            phi: true,
            auditTrail: true,
            minimumNecessary: true
        }, 'medium');
    }

    private hashPatientId(patientId: string): string {
        // Hash patient ID for audit while maintaining privacy
        return Buffer.from(patientId).toString('base64');
    }
}
```

This comprehensive guide shows exactly how SIEM monitoring works, how to add custom endpoints, and ensures your security events are properly captured and forwarded to your existing security infrastructure.