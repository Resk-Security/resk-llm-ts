import { DetectionResult, ThreatCategory, Severity, type BaseDetector, type DetectorMatch } from '../core/detector';
import { getPatternValue } from '../core/pattern_loader';

interface AclNode {
    action?: 'allow' | 'deny' | 'warn' | 'block';
    reason?: string;
    condition?: string;
    branches?: Record<string, AclNode>;
}

interface AclDecision {
    action: 'allow' | 'deny' | 'warn' | 'block';
    reason: string;
    path: string[];
}

export class AclDecisionTreeDetector implements BaseDetector {
    readonly name = 'acl_decision_tree';
    readonly category = ThreatCategory.DIRECT_INJECTION;
    enabled: boolean;

    private root: AclNode | null;

    constructor() {
        const root = getPatternValue('acl_decision_tree', 'root') as AclNode | undefined;
        this.root = root ?? null;
        this.enabled = root !== undefined;
    }

    private evaluate(node: AclNode, context: Record<string, unknown>, path: string[]): AclDecision {
        // Terminal node
        if (node.action) {
            return { action: node.action, reason: node.reason ?? 'Decision reached', path: [...path] };
        }

        // Decision node
        if (node.condition && node.branches) {
            const value = context[node.condition];
            const strValue = value !== undefined ? String(value) : '__undefined__';
            const updatedPath = [...path, `${node.condition}=${strValue}`];

            if (node.branches[strValue]) {
                return this.evaluate(node.branches[strValue]!, context, updatedPath);
            }

            // Try default branch
            if (node.branches['default']) {
                return this.evaluate(node.branches['default'], context, updatedPath);
            }

            // No match -> deny
            return { action: 'deny', reason: `No matching branch for ${node.condition}=${strValue}`, path: updatedPath };
        }

        // Fallback
        return { action: 'deny', reason: 'Incomplete node (no action or condition)', path: [...path] };
    }

    private decisionToMatch(action: AclDecision, name: string): Array<{ name: string; match: string; category: ThreatCategory }> {
        return [{
            name,
            match: `path: ${action.path.join(' -> ')}`,
            category: ThreatCategory.DIRECT_INJECTION,
        }];
    }

    private actionToDetection(action: AclDecision): DetectionResult {
        switch (action.action) {
            case 'allow':
                return DetectionResult.safe('acl_decision_tree', `ACL decision: ${action.reason}`);

            case 'warn':
                return DetectionResult.threat('acl_decision_tree', ThreatCategory.DIRECT_INJECTION, {
                    severity: Severity.LOW,
                    confidence: 0.3,
                    reason: `ACL warning: ${action.reason}`,
                    matches: this.decisionToMatch(action, 'acl_warn'),
                });

            case 'deny':
                return DetectionResult.threat('acl_decision_tree', ThreatCategory.DIRECT_INJECTION, {
                    severity: Severity.HIGH,
                    confidence: 0.85,
                    reason: `ACL denied: ${action.reason}`,
                    matches: this.decisionToMatch(action, 'acl_deny'),
                });

            case 'block':
                return DetectionResult.threat('acl_decision_tree', ThreatCategory.DIRECT_INJECTION, {
                    severity: Severity.CRITICAL,
                    confidence: 0.95,
                    reason: `ACL blocked: ${action.reason}`,
                    matches: this.decisionToMatch(action, 'acl_block'),
                });

            default:
                return DetectionResult.safe('acl_decision_tree', 'Unknown action');
        }
    }

    detect(text: string, context?: Record<string, unknown>): DetectionResult {
        if (!text || !text.trim()) return DetectionResult.safe('acl_decision_tree', 'Empty input');
        if (!this.enabled || !this.root) {
            return DetectionResult.safe('acl_decision_tree', 'No decision tree configured');
        }

        const ctx = context ?? {};
        const decision = this.evaluate(this.root, ctx, []);
        return this.actionToDetection(decision);
    }
}

export const aclDecisionTreeDetector = new AclDecisionTreeDetector();
