import type { Request, Response, NextFunction } from 'express';
import { SecurityPipeline, type PipelineResult } from '../core/pipeline';
import { DEFAULT_CONFIG } from '../core/config';
export interface ExpressMiddlewareOptions { pipeline?: SecurityPipeline; excludedPaths?: string[]; onBlock?: (req: Request, res: Response, r: PipelineResult) => void; }
export function ExpressMiddleware(opts: ExpressMiddlewareOptions = {}) {
    const pipeline = opts.pipeline ?? new SecurityPipeline(DEFAULT_CONFIG);
    const excl = opts.excludedPaths ?? ['/health','/docs'];
    const onBlock = opts.onBlock ?? ((_,res,r) => res.status(400).json({error:'blocked',reason:r.blockReason}));
    return async (req: Request, res: Response, next: NextFunction) => {
        if (excl.includes(req.path) || !['POST','PUT','PATCH'].includes(req.method)) return next();
        const body = JSON.stringify(req.body ?? '');
        if (body === '{}') return next();
        const r = pipeline.run(body);
        if (r.blocked) return onBlock(req, res, r);
        next();
    };
}
