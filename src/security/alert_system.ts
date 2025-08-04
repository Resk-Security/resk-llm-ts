import { randomUUID } from 'crypto';

export interface AlertConfig {
    enabled: boolean;
    channels?: {
        webhook?: {
            enabled: boolean;
            url: string;
            headers?: Record<string, string>;
            timeout?: number;
        };
        email?: {
            enabled: boolean;
            smtp?: {
                host: string;
                port: number;
                secure?: boolean;
                auth: {
                    user: string;
                    pass: string;
                };
            };
            from: string;
            to: string[];
            subject?: string;
        };
        slack?: {
            enabled: boolean;
            webhookUrl: string;
            channel?: string;
            username?: string;
            iconEmoji?: string;
        };
        console?: {
            enabled: boolean;
            logLevel?: 'info' | 'warn' | 'error';
        };
    };
    retryPolicy?: {
        maxRetries: number;
        retryDelay: number; // milliseconds
        backoffMultiplier?: number;
    };
    rateLimiting?: {
        maxAlertsPerMinute: number;
        maxAlertsPerHour: number;
    };
}

export interface AlertPayload {
    id: string;
    timestamp: string;
    type: 'canary_token_leak' | 'security_violation' | 'injection_detected' | 'content_moderation';
    severity: 'low' | 'medium' | 'high' | 'critical';
    title: string;
    description: string;
    details: Record<string, unknown>;
    context?: {
        userId?: string;
        sessionId?: string;
        ipAddress?: string;
        userAgent?: string;
        endpoint?: string;
        tokenAge?: number;
        [key: string]: any;
    };
    metadata?: Record<string, unknown>;
}

export interface AlertResult {
    success: boolean;
    channel: string;
    error?: string;
    duration?: number;
}

/**
 * Système d'alertes multi-canal pour les événements de sécurité
 * Support pour webhook, email, Slack, et console
 */
export class AlertSystem {
    private config: AlertConfig;
    private alertCounts: Map<string, { minute: number; hour: number; lastReset: number }> = new Map();
    
    constructor(config: AlertConfig) {
        this.config = {
            retryPolicy: {
                maxRetries: 3,
                retryDelay: 1000,
                backoffMultiplier: 2
            },
            rateLimiting: {
                maxAlertsPerMinute: 10,
                maxAlertsPerHour: 100
            },
            ...config,
            enabled: config.enabled !== undefined ? config.enabled : true
        };

        // Validation de la configuration
        this.validateConfig();
    }

    /**
     * Envoie une alerte via tous les canaux configurés
     */
    async sendAlert(payload: AlertPayload): Promise<AlertResult[]> {
        if (!this.config.enabled) {
            return [{ success: false, channel: 'system', error: 'Alert system disabled' }];
        }

        // Vérification du rate limiting
        if (!this.checkRateLimit(payload.type)) {
            return [{ success: false, channel: 'system', error: 'Rate limit exceeded' }];
        }

        // Ajout d'un ID unique si pas présent
        if (!payload.id) {
            payload.id = randomUUID();
        }

        // Ajout du timestamp si pas présent
        if (!payload.timestamp) {
            payload.timestamp = new Date().toISOString();
        }

        const results: AlertResult[] = [];
        const channels = this.config.channels || {};

        // Envoi via tous les canaux activés en parallèle
        const promises: Promise<AlertResult>[] = [];

        if (channels.console?.enabled) {
            promises.push(this.sendConsoleAlert(payload));
        }

        if (channels.webhook?.enabled && channels.webhook.url) {
            promises.push(this.sendWebhookAlert(payload, channels.webhook));
        }

        if (channels.slack?.enabled && channels.slack.webhookUrl) {
            promises.push(this.sendSlackAlert(payload, channels.slack));
        }

        if (channels.email?.enabled && channels.email.smtp && channels.email.to.length > 0) {
            promises.push(this.sendEmailAlert(payload, channels.email));
        }

        // Attendre tous les envois
        const allResults = await Promise.allSettled(promises);
        
        for (const result of allResults) {
            if (result.status === 'fulfilled') {
                results.push(result.value);
            } else {
                results.push({
                    success: false,
                    channel: 'unknown',
                    error: result.reason?.message || 'Unknown error'
                });
            }
        }

        // Mise à jour des compteurs de rate limiting
        this.updateRateLimit(payload.type);

        return results;
    }

    /**
     * Alerte console (toujours disponible)
     */
    private async sendConsoleAlert(payload: AlertPayload): Promise<AlertResult> {
        const start = Date.now();
        try {
            const logLevel = this.config.channels?.console?.logLevel || 'warn';
            const message = `[SECURITY ALERT] ${payload.title}: ${payload.description}`;
            const details = {
                id: payload.id,
                type: payload.type,
                severity: payload.severity,
                timestamp: payload.timestamp,
                details: payload.details,
                context: payload.context
            };

            switch (logLevel) {
                case 'error':
                    console.error(message, details);
                    break;
                case 'warn':
                    console.warn(message, details);
                    break;
                case 'info':
                default:
                    console.info(message, details);
                    break;
            }

            return {
                success: true,
                channel: 'console',
                duration: Date.now() - start
            };
        } catch (error) {
            return {
                success: false,
                channel: 'console',
                error: error instanceof Error ? error.message : 'Unknown console error',
                duration: Date.now() - start
            };
        }
    }

    /**
     * Alerte via webhook HTTP
     */
    private async sendWebhookAlert(payload: AlertPayload, config: NonNullable<AlertConfig['channels']>['webhook']): Promise<AlertResult> {
        if (!config?.url) {
            return { success: false, channel: 'webhook', error: 'No webhook URL configured' };
        }

        return this.retryOperation(async () => {
            const start = Date.now();
            try {
                const response = await fetch(config.url, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'User-Agent': 'Resk-LLM-TS AlertSystem/1.0',
                        ...config.headers
                    },
                    body: JSON.stringify({
                        alert: payload,
                        source: 'resk-llm-ts'
                    }),
                    signal: AbortSignal.timeout(config.timeout || 5000)
                });

                if (!response.ok) {
                    throw new Error(`Webhook failed: ${response.status} ${response.statusText}`);
                }

                return {
                    success: true,
                    channel: 'webhook',
                    duration: Date.now() - start
                };
            } catch (error) {
                throw new Error(`Webhook error: ${error instanceof Error ? error.message : 'Unknown error'}`);
            }
        }, 'webhook');
    }

    /**
     * Alerte via Slack
     */
    private async sendSlackAlert(payload: AlertPayload, config: NonNullable<AlertConfig['channels']>['slack']): Promise<AlertResult> {
        if (!config?.webhookUrl) {
            return { success: false, channel: 'slack', error: 'No Slack webhook URL configured' };
        }

        return this.retryOperation(async () => {
            const start = Date.now();
            try {
                const color = this.getSeverityColor(payload.severity);
                const slackPayload = {
                    channel: config.channel,
                    username: config.username || 'Resk Security',
                    icon_emoji: config.iconEmoji || ':warning:',
                    attachments: [{
                        color: color,
                        title: `🚨 ${payload.title}`,
                        text: payload.description,
                        fields: [
                            {
                                title: 'Type',
                                value: payload.type.replace(/_/g, ' ').toUpperCase(),
                                short: true
                            },
                            {
                                title: 'Severity',
                                value: payload.severity.toUpperCase(),
                                short: true
                            },
                            {
                                title: 'Timestamp',
                                value: payload.timestamp,
                                short: true
                            },
                            {
                                title: 'Alert ID',
                                value: payload.id,
                                short: true
                            }
                        ],
                        footer: 'Resk-LLM-TS Security System',
                        ts: Math.floor(new Date(payload.timestamp).getTime() / 1000)
                    }]
                };

                const response = await fetch(config.webhookUrl, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(slackPayload),
                    signal: AbortSignal.timeout(5000)
                });

                if (!response.ok) {
                    throw new Error(`Slack webhook failed: ${response.status} ${response.statusText}`);
                }

                return {
                    success: true,
                    channel: 'slack',
                    duration: Date.now() - start
                };
            } catch (error) {
                throw new Error(`Slack error: ${error instanceof Error ? error.message : 'Unknown error'}`);
            }
        }, 'slack');
    }

    /**
     * Alerte via email (implémentation basique - nécessite une vraie lib SMTP en production)
     */
    private async sendEmailAlert(payload: AlertPayload, config: NonNullable<AlertConfig['channels']>['email']): Promise<AlertResult> {
        const start = Date.now();
        try {
            // NOTE: Implémentation simplifiée - en production, utiliser nodemailer ou équivalent
            console.warn('[EMAIL ALERT] Email sending not implemented in this demo version');
            console.info('[EMAIL ALERT] Would send to:', config?.to || 'no recipients');
            console.info('[EMAIL ALERT] Subject:', config?.subject || `Security Alert: ${payload.title}`);
            console.info('[EMAIL ALERT] Content:', {
                title: payload.title,
                description: payload.description,
                severity: payload.severity,
                details: payload.details
            });

            // Simulation d'envoi
            await new Promise(resolve => setTimeout(resolve, 100));

            return {
                success: true,
                channel: 'email',
                duration: Date.now() - start
            };
        } catch (error) {
            return {
                success: false,
                channel: 'email',
                error: error instanceof Error ? error.message : 'Unknown email error',
                duration: Date.now() - start
            };
        }
    }

    /**
     * Système de retry avec backoff exponentiel
     */
    private async retryOperation<T>(
        operation: () => Promise<T>,
        channel: string
    ): Promise<T> {
        const retryConfig = this.config.retryPolicy!;
        let lastError: Error | null = null;

        for (let attempt = 0; attempt <= retryConfig.maxRetries; attempt++) {
            try {
                return await operation();
            } catch (error) {
                lastError = error instanceof Error ? error : new Error(String(error));
                
                if (attempt < retryConfig.maxRetries) {
                    const delay = retryConfig.retryDelay * Math.pow(retryConfig.backoffMultiplier || 2, attempt);
                    console.warn(`[AlertSystem] ${channel} failed (attempt ${attempt + 1}), retrying in ${delay}ms:`, lastError.message);
                    await new Promise(resolve => setTimeout(resolve, delay));
                }
            }
        }

        throw lastError || new Error('Unknown retry error');
    }

    /**
     * Vérification du rate limiting
     */
    private checkRateLimit(alertType: string): boolean {
        if (!this.config.rateLimiting) return true;

        const now = Date.now();
        const key = alertType;
        const limits = this.alertCounts.get(key) || { minute: 0, hour: 0, lastReset: now };

        // Reset des compteurs si nécessaire
        const minutesSinceReset = (now - limits.lastReset) / (1000 * 60);
        const hoursSinceReset = (now - limits.lastReset) / (1000 * 60 * 60);

        if (minutesSinceReset >= 1) {
            limits.minute = 0;
        }
        if (hoursSinceReset >= 1) {
            limits.hour = 0;
            limits.lastReset = now;
        }

        // Vérification des limites
        if (limits.minute >= this.config.rateLimiting.maxAlertsPerMinute) {
            return false;
        }
        if (limits.hour >= this.config.rateLimiting.maxAlertsPerHour) {
            return false;
        }

        return true;
    }

    /**
     * Mise à jour des compteurs de rate limiting
     */
    private updateRateLimit(alertType: string): void {
        if (!this.config.rateLimiting) return;

        const key = alertType;
        const limits = this.alertCounts.get(key) || { minute: 0, hour: 0, lastReset: Date.now() };
        
        limits.minute++;
        limits.hour++;
        
        this.alertCounts.set(key, limits);
    }

    /**
     * Obtient la couleur Slack basée sur la sévérité
     */
    private getSeverityColor(severity: string): string {
        switch (severity) {
            case 'critical': return 'danger';
            case 'high': return '#ff6b6b';
            case 'medium': return 'warning';
            case 'low': return 'good';
            default: return '#ffd93d';
        }
    }

    /**
     * Validation de la configuration
     */
    private validateConfig(): void {
        const channels = this.config.channels;
        if (!channels) return;

        // Validation webhook
        if (channels.webhook?.enabled && !channels.webhook.url) {
            console.warn('[AlertSystem] Webhook enabled but no URL provided');
        }

        // Validation Slack
        if (channels.slack?.enabled && !channels.slack.webhookUrl) {
            console.warn('[AlertSystem] Slack enabled but no webhook URL provided');
        }

        // Validation email
        if (channels.email?.enabled) {
            if (!channels.email.smtp) {
                console.warn('[AlertSystem] Email enabled but no SMTP config provided');
            }
            if (!channels.email.to || channels.email.to.length === 0) {
                console.warn('[AlertSystem] Email enabled but no recipients provided');
            }
        }
    }

    /**
     * Met à jour la configuration
     */
    updateConfig(newConfig: Partial<AlertConfig>): void {
        this.config = { ...this.config, ...newConfig };
        this.validateConfig();
    }

    /**
     * Teste la connectivité des canaux configurés
     */
    async testChannels(): Promise<Record<string, AlertResult>> {
        const testPayload: AlertPayload = {
            id: `test-${randomUUID()}`,
            timestamp: new Date().toISOString(),
            type: 'security_violation',
            severity: 'low',
            title: 'Test Alert',
            description: 'This is a test alert to verify channel connectivity',
            details: { test: true }
        };

        const results = await this.sendAlert(testPayload);
        const channelResults: Record<string, AlertResult> = {};

        for (const result of results) {
            channelResults[result.channel] = result;
        }

        return channelResults;
    }
}