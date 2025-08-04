/**
 * Intégration SIEM pour la surveillance de sécurité frontend
 * Support pour Splunk, Elastic Stack, Azure Sentinel, et autres SIEM
 */

export interface SIEMConfig {
    enabled: boolean;
    provider: 'splunk' | 'elastic' | 'azure-sentinel' | 'datadog' | 'custom' | 'webhook';
    endpoint?: string;
    apiKey?: string;
    indexName?: string;
    batchSize?: number;
    flushInterval?: number;
    retryPolicy?: {
        maxRetries: number;
        retryDelay: number;
        exponentialBackoff: boolean;
    };
    filters?: {
        minSeverity: 'low' | 'medium' | 'high' | 'critical';
        includeSuccess: boolean;
        includeMetrics: boolean;
    };
    compliance?: {
        gdpr: boolean;
        pciDss: boolean;
        hipaa: boolean;
        sox: boolean;
    };
}

export interface SecurityEvent {
    timestamp: string;
    eventId: string;
    eventType: 'request_validation' | 'response_validation' | 'injection_detected' | 'content_blocked' | 'pii_detected' | 'performance_metric';
    severity: 'low' | 'medium' | 'high' | 'critical';
    source: 'frontend' | 'security_filter';
    userId?: string;
    sessionId?: string;
    userAgent?: string;
    ipAddress?: string;
    details: Record<string, unknown>;
    compliance?: {
        gdprRelevant?: boolean;
        pciScope?: boolean;
        hipaaProtected?: boolean;
        retentionDays?: number;
    };
}

export interface SIEMMetrics {
    eventsSent: number;
    eventsQueued: number;
    eventsFailed: number;
    lastSyncTime: number;
    averageLatency: number;
    errors: Array<{ timestamp: number; error: string }>;
}

/**
 * Intégration SIEM pour surveillance de sécurité
 */
export class SIEMIntegration {
    private config: Required<SIEMConfig>;
    private eventQueue: SecurityEvent[] = [];
    private metrics: SIEMMetrics;
    private flushInterval: NodeJS.Timeout | null = null;
    private isDestroyed = false;

    constructor(config: SIEMConfig) {
        this.config = this.mergeDefaultConfig(config);
        this.metrics = {
            eventsSent: 0,
            eventsQueued: 0,
            eventsFailed: 0,
            lastSyncTime: 0,
            averageLatency: 0,
            errors: []
        };

        this.startFlushInterval();
        console.info(`[SIEMIntegration] Initialized for ${this.config.provider}`);
    }

    /**
     * Fusion avec la configuration par défaut
     */
    private mergeDefaultConfig(userConfig: SIEMConfig): Required<SIEMConfig> {
        return {
            endpoint: '',
            apiKey: '',
            indexName: 'resk-security-events',
            batchSize: 100,
            flushInterval: 30000, // 30 seconds
            retryPolicy: {
                maxRetries: 3,
                retryDelay: 1000,
                exponentialBackoff: true
            },
            filters: {
                minSeverity: 'low',
                includeSuccess: true,
                includeMetrics: false
            },
            compliance: {
                gdpr: false,
                pciDss: false,
                hipaa: false,
                sox: false
            },
            ...userConfig,
            enabled: userConfig.enabled !== undefined ? userConfig.enabled : true,
            provider: userConfig.provider || 'webhook'
        };
    }

    /**
     * Enregistrement d'un événement de sécurité
     */
    async logSecurityEvent(
        eventType: SecurityEvent['eventType'],
        details: Record<string, unknown>,
        severity: SecurityEvent['severity'] = 'medium'
    ): Promise<void> {
        if (!this.config.enabled || this.isDestroyed) return;

        // Filtrage selon la configuration
        if (!this.shouldLogEvent(severity)) return;

        const event: SecurityEvent = {
            timestamp: new Date().toISOString(),
            eventId: this.generateEventId(),
            eventType,
            severity,
            source: 'frontend',
            userId: await this.extractUserId(),
            sessionId: this.extractSessionId(),
            userAgent: this.extractUserAgent(),
            ipAddress: await this.extractClientIP(),
            details: this.sanitizeDetails(details),
            compliance: this.getComplianceInfo(details)
        };

        this.eventQueue.push(event);
        this.metrics.eventsQueued++;

        // Flush immédiat pour les événements critiques
        if (severity === 'critical') {
            await this.flush();
        }
    }

    /**
     * Enregistrement d'une métrique de performance
     */
    async logPerformanceMetric(metrics: Record<string, number>): Promise<void> {
        if (!this.config.filters.includeMetrics) return;

        await this.logSecurityEvent('performance_metric', {
            metrics,
            component: 'security_filter',
            performance: true
        }, 'low');
    }

    /**
     * Enregistrement d'une détection d'injection
     */
    async logInjectionDetection(details: {
        confidence: number;
        techniques: string[];
        severity: string;
        blocked: boolean;
        content?: string; // Optionnel et sanitisé
    }): Promise<void> {
        // Déterminer la sévérité selon la confiance
        const severity: SecurityEvent['severity'] = 
            details.confidence > 0.8 ? 'critical' :
            details.confidence > 0.6 ? 'high' :
            details.confidence > 0.4 ? 'medium' : 'low';

        await this.logSecurityEvent('injection_detected', {
            confidence: details.confidence,
            techniques: details.techniques,
            severity: details.severity,
            blocked: details.blocked,
            contentLength: details.content?.length || 0,
            // Ne pas logger le contenu complet pour la sécurité
            contentSample: details.content?.substring(0, 100) || ''
        }, severity);
    }

    /**
     * Enregistrement d'un blocage de contenu
     */
    async logContentBlocked(details: {
        categories: string[];
        actions: string[];
        severity: string;
        confidence: number;
    }): Promise<void> {
        await this.logSecurityEvent('content_blocked', details, 
            details.severity as SecurityEvent['severity']);
    }

    /**
     * Enregistrement d'une détection PII
     */
    async logPIIDetected(details: {
        types: string[];
        count: number;
        redacted: boolean;
        context: string;
    }): Promise<void> {
        await this.logSecurityEvent('pii_detected', {
            ...details,
            gdprRelevant: true, // PII est toujours relevant pour GDPR
            severity: details.count > 3 ? 'high' : 'medium'
        }, details.count > 3 ? 'high' : 'medium');
    }

    /**
     * Flush manuel des événements
     */
    async flush(): Promise<void> {
        if (this.eventQueue.length === 0) return;

        const events = this.eventQueue.splice(0, this.config.batchSize);
        const startTime = performance.now();

        try {
            await this.sendEvents(events);
            
            const latency = performance.now() - startTime;
            this.updateMetrics(events.length, latency, false);
            
            console.debug(`[SIEMIntegration] Sent ${events.length} events to ${this.config.provider}`);
        } catch (error) {
            this.handleSendError(error, events);
        }
    }

    /**
     * Envoi des événements selon le provider
     */
    private async sendEvents(events: SecurityEvent[]): Promise<void> {
        switch (this.config.provider) {
            case 'splunk':
                await this.sendToSplunk(events);
                break;
            case 'elastic':
                await this.sendToElastic(events);
                break;
            case 'azure-sentinel':
                await this.sendToAzureSentinel(events);
                break;
            case 'datadog':
                await this.sendToDatadog(events);
                break;
            case 'webhook':
                await this.sendToWebhook(events);
                break;
            case 'custom':
                await this.sendToCustom(events);
                break;
            default:
                throw new Error(`Unsupported SIEM provider: ${this.config.provider}`);
        }
    }

    /**
     * Envoi vers Splunk HEC
     */
    private async sendToSplunk(events: SecurityEvent[]): Promise<void> {
        if (!this.config.endpoint || !this.config.apiKey) {
            throw new Error('Splunk endpoint and API key required');
        }

        const splunkEvents = events.map(event => ({
            time: new Date(event.timestamp).getTime() / 1000,
            source: 'resk-llm-ts',
            sourcetype: 'resk:security',
            index: this.config.indexName,
            event: event
        }));

        const response = await fetch(`${this.config.endpoint}/services/collector`, {
            method: 'POST',
            headers: {
                'Authorization': `Splunk ${this.config.apiKey}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(splunkEvents)
        });

        if (!response.ok) {
            throw new Error(`Splunk HTTP ${response.status}: ${response.statusText}`);
        }
    }

    /**
     * Envoi vers Elasticsearch
     */
    private async sendToElastic(events: SecurityEvent[]): Promise<void> {
        if (!this.config.endpoint) {
            throw new Error('Elasticsearch endpoint required');
        }

        const bulkBody = events.flatMap(event => [
            { index: { _index: this.config.indexName, _type: '_doc' } },
            event
        ]);

        const response = await fetch(`${this.config.endpoint}/_bulk`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-ndjson',
                ...(this.config.apiKey && { 'Authorization': `ApiKey ${this.config.apiKey}` })
            },
            body: bulkBody.map(item => JSON.stringify(item)).join('\n') + '\n'
        });

        if (!response.ok) {
            throw new Error(`Elasticsearch HTTP ${response.status}: ${response.statusText}`);
        }
    }

    /**
     * Envoi vers Azure Sentinel
     */
    private async sendToAzureSentinel(events: SecurityEvent[]): Promise<void> {
        if (!this.config.endpoint || !this.config.apiKey) {
            throw new Error('Azure Sentinel workspace ID and shared key required');
        }

        // Azure Sentinel utilise l'API Log Analytics
        const body = JSON.stringify(events);
        const dateString = new Date().toUTCString();
        const signature = await this.generateAzureSignature(body, dateString);

        const response = await fetch(
            `https://${this.config.endpoint}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01`,
            {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Log-Type': 'ReskSecurityEvents',
                    'x-ms-date': dateString,
                    'Authorization': signature
                },
                body: body
            }
        );

        if (!response.ok) {
            throw new Error(`Azure Sentinel HTTP ${response.status}: ${response.statusText}`);
        }
    }

    /**
     * Envoi vers Datadog
     */
    private async sendToDatadog(events: SecurityEvent[]): Promise<void> {
        if (!this.config.apiKey) {
            throw new Error('Datadog API key required');
        }

        const datadogLogs = events.map(event => ({
            ddsource: 'resk-llm-ts',
            ddtags: `severity:${event.severity},type:${event.eventType}`,
            timestamp: new Date(event.timestamp).getTime(),
            message: JSON.stringify(event),
            level: event.severity,
            service: 'resk-security-filter'
        }));

        const response = await fetch('https://http-intake.logs.datadoghq.com/v1/input/' + this.config.apiKey, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(datadogLogs)
        });

        if (!response.ok) {
            throw new Error(`Datadog HTTP ${response.status}: ${response.statusText}`);
        }
    }

    /**
     * Envoi vers webhook générique
     */
    private async sendToWebhook(events: SecurityEvent[]): Promise<void> {
        if (!this.config.endpoint) {
            throw new Error('Webhook endpoint required');
        }

        const response = await fetch(this.config.endpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'User-Agent': 'Resk-LLM-TS/1.0',
                ...(this.config.apiKey && { 'Authorization': `Bearer ${this.config.apiKey}` })
            },
            body: JSON.stringify({
                source: 'resk-llm-ts',
                events: events,
                metadata: {
                    batchSize: events.length,
                    timestamp: new Date().toISOString()
                }
            })
        });

        if (!response.ok) {
            throw new Error(`Webhook HTTP ${response.status}: ${response.statusText}`);
        }
    }

    /**
     * Envoi personnalisé (à implémenter selon besoins)
     */
    private async sendToCustom(events: SecurityEvent[]): Promise<void> {
        console.warn('[SIEMIntegration] Custom provider not implemented');
        // Implémentation personnalisée selon les besoins
    }

    /**
     * Génération de signature Azure
     */
    private async generateAzureSignature(body: string, dateString: string): Promise<string> {
        // Implémentation simplifiée - en production, utiliser crypto-js ou équivalent
        const stringToSign = `POST\n${body.length}\napplication/json\nx-ms-date:${dateString}\n/api/logs`;
        
        // Note: Implémentation complète nécessite crypto.subtle pour HMAC-SHA256
        // Pour la démo, retourner une signature factice
        return `SharedKey workspace:${btoa(stringToSign)}`;
    }

    /**
     * Démarrage du flush automatique
     */
    private startFlushInterval(): void {
        this.flushInterval = setInterval(async () => {
            await this.flush();
        }, this.config.flushInterval);
    }

    /**
     * Filtrage des événements
     */
    private shouldLogEvent(severity: SecurityEvent['severity']): boolean {
        const severityLevels = { low: 0, medium: 1, high: 2, critical: 3 };
        return severityLevels[severity] >= severityLevels[this.config.filters.minSeverity];
    }

    /**
     * Génération d'ID d'événement
     */
    private generateEventId(): string {
        return `resk_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    }

    /**
     * Extraction de l'ID utilisateur (si disponible)
     */
    private async extractUserId(): Promise<string | undefined> {
        // Logique d'extraction de l'ID utilisateur depuis le contexte
        if (typeof window !== 'undefined') {
            // Chercher dans le localStorage, sessionStorage, ou contexte global
            return localStorage.getItem('userId') || sessionStorage.getItem('userId') || undefined;
        }
        return undefined;
    }

    /**
     * Extraction de l'ID de session
     */
    private extractSessionId(): string | undefined {
        if (typeof window !== 'undefined') {
            return sessionStorage.getItem('sessionId') || document.cookie
                .split('; ')
                .find(row => row.startsWith('sessionId='))
                ?.split('=')[1];
        }
        return undefined;
    }

    /**
     * Extraction du User-Agent
     */
    private extractUserAgent(): string | undefined {
        return typeof navigator !== 'undefined' ? navigator.userAgent : undefined;
    }

    /**
     * Extraction de l'IP client (approximation)
     */
    private async extractClientIP(): Promise<string | undefined> {
        // Note: L'IP réelle ne peut pas être obtenue côté client
        // Ceci est une approximation via des services tiers
        try {
            const response = await fetch('https://api.ipify.org?format=json');
            const data = await response.json();
            return data.ip;
        } catch {
            return 'unknown';
        }
    }

    /**
     * Sanitisation des détails sensibles
     */
    private sanitizeDetails(details: Record<string, unknown>): Record<string, unknown> {
        const sanitized = { ...details };
        
        // Supprimer les champs sensibles
        delete sanitized.password;
        delete sanitized.apiKey;
        delete sanitized.token;
        delete sanitized.secret;
        
        // Tronquer les contenus longs
        Object.keys(sanitized).forEach(key => {
            if (typeof sanitized[key] === 'string' && (sanitized[key] as string).length > 1000) {
                sanitized[key] = (sanitized[key] as string).substring(0, 1000) + '...[truncated]';
            }
        });

        return sanitized;
    }

    /**
     * Obtention des informations de compliance
     */
    private getComplianceInfo(details: Record<string, unknown>): SecurityEvent['compliance'] {
        const compliance: SecurityEvent['compliance'] = {};

        if (this.config.compliance.gdpr) {
            compliance.gdprRelevant = this.isGDPRRelevant(details);
            compliance.retentionDays = 365; // Défaut GDPR
        }

        if (this.config.compliance.pciDss) {
            compliance.pciScope = this.isPCIScope(details);
        }

        if (this.config.compliance.hipaa) {
            compliance.hipaaProtected = this.isHIPAAProtected(details);
        }

        return compliance;
    }

    /**
     * Vérification de relevance GDPR
     */
    private isGDPRRelevant(details: Record<string, unknown>): boolean {
        // Logique pour déterminer si l'événement concerne des données GDPR
        return !!(details.piiDetected || details.personalData || details.userId);
    }

    /**
     * Vérification du scope PCI DSS
     */
    private isPCIScope(details: Record<string, unknown>): boolean {
        // Logique pour déterminer si l'événement concerne des données de carte
        return !!(details.paymentData || details.cardNumber || details.financialData);
    }

    /**
     * Vérification de protection HIPAA
     */
    private isHIPAAProtected(details: Record<string, unknown>): boolean {
        // Logique pour déterminer si l'événement concerne des données de santé
        return !!(details.healthData || details.medicalRecord || details.phi);
    }

    /**
     * Gestion des erreurs d'envoi
     */
    private handleSendError(error: any, events: SecurityEvent[]): void {
        this.metrics.eventsFailed += events.length;
        this.metrics.errors.push({
            timestamp: Date.now(),
            error: error.message || String(error)
        });

        // Garder seulement les 100 dernières erreurs
        if (this.metrics.errors.length > 100) {
            this.metrics.errors.shift();
        }

        console.error('[SIEMIntegration] Failed to send events:', error);

        // Retry logic avec exponential backoff
        if (this.config.retryPolicy.maxRetries > 0) {
            setTimeout(() => {
                this.retryEvents(events, 1);
            }, this.config.retryPolicy.retryDelay);
        }
    }

    /**
     * Retry des événements
     */
    private async retryEvents(events: SecurityEvent[], attempt: number): Promise<void> {
        if (attempt > this.config.retryPolicy.maxRetries) {
            console.error('[SIEMIntegration] Max retries exceeded, dropping events');
            return;
        }

        try {
            await this.sendEvents(events);
            console.info(`[SIEMIntegration] Retry ${attempt} successful`);
        } catch (error) {
            const delay = this.config.retryPolicy.exponentialBackoff 
                ? this.config.retryPolicy.retryDelay * Math.pow(2, attempt)
                : this.config.retryPolicy.retryDelay;

            setTimeout(() => {
                this.retryEvents(events, attempt + 1);
            }, delay);
        }
    }

    /**
     * Mise à jour des métriques
     */
    private updateMetrics(eventCount: number, latency: number, failed: boolean): void {
        if (!failed) {
            this.metrics.eventsSent += eventCount;
            this.metrics.lastSyncTime = Date.now();
            
            // Moyenne mobile de la latence
            this.metrics.averageLatency = this.metrics.averageLatency === 0 
                ? latency 
                : (this.metrics.averageLatency * 0.9) + (latency * 0.1);
        }
    }

    /**
     * Obtention des métriques
     */
    getMetrics(): SIEMMetrics {
        this.metrics.eventsQueued = this.eventQueue.length;
        return { ...this.metrics };
    }

    /**
     * Nettoyage des ressources
     */
    dispose(): void {
        this.isDestroyed = true;
        
        if (this.flushInterval) {
            clearInterval(this.flushInterval);
            this.flushInterval = null;
        }

        // Flush final des événements en attente
        if (this.eventQueue.length > 0) {
            this.flush().catch(error => {
                console.error('[SIEMIntegration] Failed final flush:', error);
            });
        }

        console.info('[SIEMIntegration] Disposed');
    }
}