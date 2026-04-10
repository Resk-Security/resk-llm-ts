import type { Context, MiddlewareHandler } from 'hono';
import { SecurityPipeline } from '../core/pipeline';
import { DEFAULT_CONFIG } from '../core/config';
export interface HonoOptions { pipeline?: SecurityPipeline; excludedPaths?: string[]; }
export function HonoMiddleware(opts: HonoOptions = {}): MiddlewareHandler {
    const pipeline = opts.pipeline ?? new SecurityPipeline(DEFAULT_CONFIG);
    const excl = opts.excludedPaths ?? ['/health','/docs'];
    return async (c: Context, next: () => Promise<void>) => {
        const path = c.req.path;
        if (excl.some(p => path.startsWith(p)) || !['POST','PUT','PATCH'].includes(c.req.method)) return next();
        const cloned = c.req.raw.clone();
        const raw = await cloned.text();
        if (!raw) return next();
        const r = pipeline.run(raw);
        if (r.blocked) return c.json({error:'blocked',reason:r.blockReason}, 400);
        await next();
    };
}
