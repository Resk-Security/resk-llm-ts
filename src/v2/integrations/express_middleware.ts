import type { Request, Response, NextFunction } from 'express';
import type { PipelineResult, SecurityPipeline } from '../core/pipeline.js';
import { createDefaultPipeline } from '../defaults.js';

export interface ExpressMiddlewareOptions {
    pipeline?: SecurityPipeline;
    excludedPaths?: string[];
    onBlock?: (req: Request, res: Response, r: PipelineResult) => void;
}

/** Collect every string value nested in a request body, so detection sees text
 * regardless of how deep it is nested (and never the JSON punctuation). */
function collectStrings(value: unknown, out: string[] = []): string[] {
    if (typeof value === 'string') {
        out.push(value);
    } else if (Array.isArray(value)) {
        for (const item of value) collectStrings(item, out);
    } else if (value && typeof value === 'object') {
        for (const item of Object.values(value)) collectStrings(item, out);
    }
    return out;
}

export function ExpressMiddleware(opts: ExpressMiddlewareOptions = {}) {
    const pipeline = opts.pipeline ?? createDefaultPipeline();
    const excl = opts.excludedPaths ?? ['/health', '/docs'];
    const onBlock = opts.onBlock ?? ((_, res, r) => res.status(400).json({ error: 'blocked', reason: r.blockReason }));
    return async (req: Request, res: Response, next: NextFunction) => {
        if (excl.some(p => req.path.startsWith(p)) || !['POST', 'PUT', 'PATCH'].includes(req.method)) return next();
        const text = collectStrings(req.body).join('\n');
        if (!text.trim()) return next();
        const r = pipeline.run(text);
        if (r.blocked) return onBlock(req, res, r);
        next();
    };
}
