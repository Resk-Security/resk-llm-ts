/**
 * Optimiseur de performance pour les validations de sécurité frontend
 * Parallélisation, throttling, et optimisations intelligentes
 */

export interface PerformanceConfig {
    enableParallel: boolean;
    timeout: number;
    maxConcurrent: number;
    throttleMs: number;
    adaptiveThrottling: boolean;
    batchSize: number;
    priorityQueue: boolean;
}

export interface PerformanceMetrics {
    totalValidations: number;
    averageProcessingTime: number;
    parallelExecutions: number;
    throttledRequests: number;
    timeouts: number;
    queueLength: number;
    throughput: number; // validations/second
}

export interface ValidationTask {
    id: string;
    priority: number;
    timeout: number;
    task: () => Promise<any>;
    resolve: (value: any) => void;
    reject: (error: any) => void;
    createdAt: number;
}

/**
 * Optimiseur de performance pour validations de sécurité
 */
export class PerformanceOptimizer {
    private config: Required<PerformanceConfig>;
    private metrics: PerformanceMetrics;
    private executionTimes: number[] = [];
    private queue: ValidationTask[] = [];
    private running = new Set<string>();
    private lastExecution = 0;
    private throttleQueue: Array<{ fn: () => void; timestamp: number }> = [];
    private queueProcessorInterval: NodeJS.Timeout | null = null;
    private adaptiveThrottlingInterval: NodeJS.Timeout | null = null;

    constructor(config: Partial<PerformanceConfig> = {}) {
        this.config = {
            enableParallel: true,
            timeout: 5000,
            maxConcurrent: 4,
            throttleMs: 100,
            adaptiveThrottling: true,
            batchSize: 10,
            priorityQueue: true,
            ...config
        };

        this.metrics = {
            totalValidations: 0,
            averageProcessingTime: 0,
            parallelExecutions: 0,
            throttledRequests: 0,
            timeouts: 0,
            queueLength: 0,
            throughput: 0
        };

        // Démarrer le traitement de la queue
        this.startQueueProcessor();
        
        // Traitement du throttling adaptatif
        if (this.config.adaptiveThrottling) {
            this.startAdaptiveThrottling();
        }

        console.debug('[PerformanceOptimizer] Initialized with config:', this.config);
    }

    /**
     * Exécution d'une tâche de validation avec optimisations
     */
    async executeValidation<T>(
        id: string,
        task: () => Promise<T>,
        priority: number = 5,
        timeout?: number
    ): Promise<T> {
        const startTime = performance.now();
        
        return new Promise<T>((resolve, reject) => {
            const validationTask: ValidationTask = {
                id,
                priority,
                timeout: timeout || this.config.timeout,
                task,
                resolve: (value: T) => {
                    this.recordExecution(performance.now() - startTime);
                    resolve(value);
                },
                reject: (error: any) => {
                    this.recordExecution(performance.now() - startTime);
                    reject(error);
                },
                createdAt: Date.now()
            };

            if (this.config.priorityQueue) {
                this.addToQueue(validationTask);
            } else {
                this.executeImmediately(validationTask);
            }
        });
    }

    /**
     * Exécution parallèle de plusieurs validations
     */
    async executeParallel<T>(tasks: Array<{ id: string; task: () => Promise<T>; priority?: number }>): Promise<T[]> {
        if (!this.config.enableParallel || tasks.length <= 1) {
            // Exécution séquentielle
            const results: T[] = [];
            for (const taskInfo of tasks) {
                const result = await this.executeValidation(taskInfo.id, taskInfo.task, taskInfo.priority);
                results.push(result);
            }
            return results;
        }

        this.metrics.parallelExecutions++;
        
        // Batching intelligent
        const batches: Array<typeof tasks> = [];
        for (let i = 0; i < tasks.length; i += this.config.batchSize) {
            batches.push(tasks.slice(i, i + this.config.batchSize));
        }

        const allResults: T[] = [];
        
        for (const batch of batches) {
            const batchPromises = batch.map(taskInfo =>
                this.executeValidation(taskInfo.id, taskInfo.task, taskInfo.priority)
            );
            
            const batchResults = await Promise.all(batchPromises);
            allResults.push(...batchResults);
        }

        return allResults;
    }

    /**
     * Throttling intelligent des requêtes
     */
    async throttle<T>(fn: () => Promise<T>): Promise<T> {
        const now = Date.now();
        const timeSinceLastExecution = now - this.lastExecution;

        if (timeSinceLastExecution < this.config.throttleMs) {
            this.metrics.throttledRequests++;
            
            const delay = this.config.throttleMs - timeSinceLastExecution;
            await this.wait(delay);
        }

        this.lastExecution = Date.now();
        return fn();
    }

    /**
     * Debouncing pour éviter les validations redondantes
     */
    debounce<T extends (...args: any[]) => any>(
        fn: T,
        delay: number,
        key?: string
    ): (...args: Parameters<T>) => Promise<ReturnType<T>> {
        const debounceKey = key || fn.name || 'default';
        let timeoutId: NodeJS.Timeout;

        return (...args: Parameters<T>): Promise<ReturnType<T>> => {
            return new Promise((resolve, reject) => {
                clearTimeout(timeoutId);
                timeoutId = setTimeout(async () => {
                    try {
                        const result = await fn(...args);
                        resolve(result);
                    } catch (error) {
                        reject(error);
                    }
                }, delay);
            });
        };
    }

    /**
     * Memoization avec TTL pour éviter les re-calculs
     */
    memoize<T extends (...args: any[]) => Promise<any>>(
        fn: T,
        ttl: number = 300000, // 5 minutes
        keyFn?: (...args: Parameters<T>) => string
    ): T {
        const cache = new Map<string, { value: any; expiry: number }>();

        return ((...args: Parameters<T>): Promise<ReturnType<T>> => {
            const key = keyFn ? keyFn(...args) : JSON.stringify(args);
            const cached = cache.get(key);
            
            if (cached && Date.now() < cached.expiry) {
                return Promise.resolve(cached.value);
            }

            const result = fn(...args);
            
            if (result instanceof Promise) {
                return result.then(value => {
                    cache.set(key, {
                        value,
                        expiry: Date.now() + ttl
                    });
                    return value;
                });
            }

            cache.set(key, {
                value: result,
                expiry: Date.now() + ttl
            });
            
            return Promise.resolve(result);
        }) as T;
    }

    /**
     * Circuit breaker pour éviter les surcharges
     */
    createCircuitBreaker<T>(
        fn: () => Promise<T>,
        failureThreshold: number = 5,
        resetTimeout: number = 60000
    ): () => Promise<T> {
        let failures = 0;
        let isOpen = false;
        let lastFailureTime = 0;

        return async (): Promise<T> => {
            // Vérifier si le circuit peut être réinitialisé
            if (isOpen && Date.now() - lastFailureTime > resetTimeout) {
                isOpen = false;
                failures = 0;
                console.debug('[PerformanceOptimizer] Circuit breaker reset');
            }

            if (isOpen) {
                throw new Error('Circuit breaker is open - too many failures');
            }

            try {
                const result = await fn();
                failures = 0; // Reset sur succès
                return result;
            } catch (error) {
                failures++;
                lastFailureTime = Date.now();
                
                if (failures >= failureThreshold) {
                    isOpen = true;
                    console.warn('[PerformanceOptimizer] Circuit breaker opened due to failures');
                }
                
                throw error;
            }
        };
    }

    /**
     * Ajout à la queue avec priorité
     */
    private addToQueue(task: ValidationTask): void {
        // Insertion avec priorité (higher priority = lower number)
        let insertIndex = this.queue.length;
        for (let i = 0; i < this.queue.length; i++) {
            if (task.priority < this.queue[i].priority) {
                insertIndex = i;
                break;
            }
        }
        
        this.queue.splice(insertIndex, 0, task);
        this.metrics.queueLength = this.queue.length;
    }

    /**
     * Exécution immédiate (sans queue)
     */
    private async executeImmediately(task: ValidationTask): Promise<void> {
        if (this.running.size >= this.config.maxConcurrent) {
            // Attendre qu'une place se libère
            await this.waitForSlot();
        }

        this.running.add(task.id);
        
        try {
            const result = await this.executeWithTimeout(task);
            task.resolve(result);
        } catch (error) {
            task.reject(error);
        } finally {
            this.running.delete(task.id);
        }
    }

    /**
     * Exécution avec timeout
     */
    private async executeWithTimeout(task: ValidationTask): Promise<any> {
        return new Promise(async (resolve, reject) => {
            const timeoutId = setTimeout(() => {
                this.metrics.timeouts++;
                reject(new Error(`Validation timeout after ${task.timeout}ms`));
            }, task.timeout);

            try {
                const result = await task.task();
                clearTimeout(timeoutId);
                resolve(result);
            } catch (error) {
                clearTimeout(timeoutId);
                reject(error);
            }
        });
    }

    /**
     * Démarrage du processeur de queue
     */
    private startQueueProcessor(): void {
        this.queueProcessorInterval = setInterval(() => {
            this.processQueue();
        }, 10); // Vérifier toutes les 10ms
    }

    /**
     * Traitement de la queue
     */
    private async processQueue(): Promise<void> {
        while (this.queue.length > 0 && this.running.size < this.config.maxConcurrent) {
            const task = this.queue.shift();
            if (!task) continue;

            this.metrics.queueLength = this.queue.length;

            // Vérifier si la tâche n'est pas expirée
            if (Date.now() - task.createdAt > task.timeout) {
                task.reject(new Error('Task expired in queue'));
                continue;
            }

            this.executeImmediately(task);
        }
    }

    /**
     * Attente d'un slot libre
     */
    private async waitForSlot(): Promise<void> {
        return new Promise(resolve => {
            const checkSlot = () => {
                if (this.running.size < this.config.maxConcurrent) {
                    resolve();
                } else {
                    setTimeout(checkSlot, 10);
                }
            };
            checkSlot();
        });
    }

    /**
     * Throttling adaptatif basé sur les performances
     */
    private startAdaptiveThrottling(): void {
        this.adaptiveThrottlingInterval = setInterval(() => {
            this.adjustThrottling();
        }, 5000); // Ajuster toutes les 5 secondes
    }

    /**
     * Ajustement automatique du throttling
     */
    private adjustThrottling(): void {
        const currentThroughput = this.calculateThroughput();
        
        if (currentThroughput < 1) { // Moins d'1 validation/seconde
            // Réduire le throttling pour améliorer la performance
            this.config.throttleMs = Math.max(50, this.config.throttleMs - 10);
        } else if (currentThroughput > 10) { // Plus de 10 validations/seconde
            // Augmenter le throttling pour éviter la surcharge
            this.config.throttleMs = Math.min(500, this.config.throttleMs + 10);
        }
    }

    /**
     * Calcul du throughput
     */
    private calculateThroughput(): number {
        const now = Date.now();
        const oneSecondAgo = now - 1000;
        
        // Compter les exécutions de la dernière seconde
        const recentExecutions = this.executionTimes.filter(time => time > oneSecondAgo);
        return recentExecutions.length;
    }

    /**
     * Enregistrement d'une exécution
     */
    private recordExecution(duration: number): void {
        this.metrics.totalValidations++;
        this.executionTimes.push(Date.now());
        
        // Garder seulement les 1000 dernières exécutions
        if (this.executionTimes.length > 1000) {
            this.executionTimes.shift();
        }

        // Calculer la moyenne mobile
        const recentTimes = this.executionTimes.slice(-100); // 100 dernières
        if (recentTimes.length > 0) {
            this.metrics.averageProcessingTime = recentTimes.reduce((a, b) => a + b, 0) / recentTimes.length;
        }

        this.metrics.throughput = this.calculateThroughput();
    }

    /**
     * Utilitaire d'attente
     */
    private wait(ms: number): Promise<void> {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    /**
     * Obtention des métriques de performance
     */
    getMetrics(): PerformanceMetrics {
        return { ...this.metrics };
    }

    /**
     * Obtention du temps de traitement moyen
     */
    getAverageProcessingTime(): number {
        return this.metrics.averageProcessingTime;
    }

    /**
     * Obtention du nombre total de validations
     */
    getTotalValidations(): number {
        return this.metrics.totalValidations;
    }

    /**
     * Reset des métriques
     */
    resetMetrics(): void {
        this.metrics = {
            totalValidations: 0,
            averageProcessingTime: 0,
            parallelExecutions: 0,
            throttledRequests: 0,
            timeouts: 0,
            queueLength: this.queue.length,
            throughput: 0
        };
        this.executionTimes = [];
    }

    /**
     * Optimisation automatique des paramètres
     */
    autoOptimize(): void {
        const metrics = this.getMetrics();
        
        // Ajuster la concurrence selon la performance
        if (metrics.averageProcessingTime > 1000 && this.config.maxConcurrent > 2) {
            this.config.maxConcurrent--;
            console.debug('[PerformanceOptimizer] Reduced concurrency due to slow processing');
        } else if (metrics.averageProcessingTime < 100 && this.config.maxConcurrent < 8) {
            this.config.maxConcurrent++;
            console.debug('[PerformanceOptimizer] Increased concurrency due to fast processing');
        }

        // Ajuster la taille des batches
        if (metrics.throughput > 5 && this.config.batchSize < 20) {
            this.config.batchSize += 2;
        } else if (metrics.throughput < 1 && this.config.batchSize > 5) {
            this.config.batchSize -= 2;
        }
    }

    /**
     * Nettoyage des ressources
     */
    dispose(): void {
        // Nettoyer les timers
        if (this.queueProcessorInterval) {
            clearInterval(this.queueProcessorInterval);
            this.queueProcessorInterval = null;
        }
        if (this.adaptiveThrottlingInterval) {
            clearInterval(this.adaptiveThrottlingInterval);
            this.adaptiveThrottlingInterval = null;
        }
        
        this.queue.length = 0;
        this.running.clear();
        this.executionTimes.length = 0;
        console.debug('[PerformanceOptimizer] Disposed');
    }
}