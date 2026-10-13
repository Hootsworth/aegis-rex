/**
 * aegis-rex/index.js
 * AEGIS-REX: The Amber Protocol 🛡️🦖
 * High-Assurance Autonomous Security & Safety Operating System for RexAI.
 *
 * Provides a unified 6-layer defense-in-depth shield:
 *   Layer 1: Privilege Ring Gate
 *   Layer 2: Taint-Tracking Shield
 *   Layer 3: Dual-Key Inquisitor
 *   Layer 4: Amber Sandbox & Paleo-Reversion
 *   Layer 5: Metabolic Brake
 *   Layer 6: Honey-Token Egress Mask
 */

import { RingGate, RINGS } from './layers/ringGate.js';
import { TaintShield } from './layers/taintShield.js';
import { DualKeyInquisitor } from './layers/dualKeyInquisitor.js';
import { AmberSandbox } from './layers/amberSandbox.js';
import { MetabolicBrake } from './layers/metabolicBrake.js';
import { EgressMask } from './layers/egressMask.js';
import { AEGIS_DEFAULT_CONFIG } from './config.js';

export { RINGS };

export class AegisSecuritySystem {
    constructor(customConfig = {}) {
        this.config = { ...AEGIS_DEFAULT_CONFIG, ...customConfig };

        // Initialize all 6 defense layers
        this.ringGate = new RingGate(this.config.rings);
        this.taintShield = new TaintShield(this.config.taintShield);
        this.inquisitor = new DualKeyInquisitor(this.config.inquisitor);
        this.amberSandbox = new AmberSandbox(this.config.amberSandbox);
        this.metabolicBrake = new MetabolicBrake(this.config.metabolicBrake);
        this.egressMask = new EgressMask(this.config.egressMask);

        this.telemetry = {
            totalEvaluations: 0,
            blockedAttempts: 0,
            taintsNeutralized: 0,
            paleoReversions: 0,
            redactionsApplied: 0
        };
    }

    /**
     * Intercept incoming input from user, external web, or remote platform
     * @param {string} input - Text input
     * @param {object} context - { userId, username, modality, isWhitelisted, source }
     * @returns {{ sanitizedInput: string, ring: number, warnings: string[] }}
     */
    interceptIncoming(input, context = {}) {
        this.telemetry.totalEvaluations++;
        const warnings = [];

        // 1. Resolve Privilege Ring
        const ring = this.ringGate.resolveRing(context);

        // 2. Apply Taint Boundary if external/untrusted
        let sanitizedInput = String(input || '');
        if (ring === RINGS.RING_3_UNTRUSTED || context.modality === 'untrusted_payload') {
            const initialLen = this.taintShield.intrusionLog.length;
            sanitizedInput = this.taintShield.enforceTaintBoundary(sanitizedInput, context.source || 'untrusted');
            if (this.taintShield.intrusionLog.length > initialLen) {
                this.telemetry.taintsNeutralized++;
                warnings.push('Hostile prompt injection signatures were neutralized in incoming payload.');
            }
        }

        // 3. Reset per-turn Metabolic Brake
        this.metabolicBrake.resetTurn();

        return {
            sanitizedInput,
            ring,
            warnings
        };
    }

    /**
     * Gatekeeper for all proposed tool executions before they run
     * @param {string} toolName
     * @param {object} toolArgs
     * @param {object} context - { ring, userIntent }
     * @returns {{ authorized: boolean, reason?: string, riskScore: string, snapshotId?: string }}
     */
    authorizeToolExecution(toolName, toolArgs = {}, context = {}) {
        const ring = context.ring ?? RINGS.RING_0_SOVEREIGN;

        // Step 1: Privilege Ring Authorization
        const ringAuth = this.ringGate.authorizeTool(toolName, ring);
        if (!ringAuth.authorized) {
            this.telemetry.blockedAttempts++;
            return {
                authorized: false,
                riskScore: 'CRITICAL',
                reason: ringAuth.reason
            };
        }

        // Step 2: Metabolic Loop & Resource Check
        const brakeCheck = this.metabolicBrake.recordStepAndCheck(toolName, toolArgs);
        if (brakeCheck.tripped) {
            this.telemetry.blockedAttempts++;
            return {
                authorized: false,
                riskScore: 'HIGH',
                reason: brakeCheck.reason
            };
        }

        // Step 3: Dual-Key Inquisitor Blast Radius Check
        const inquisition = this.inquisitor.evaluateAction(toolName, toolArgs, context);
        if (!inquisition.allowed) {
            this.telemetry.blockedAttempts++;
            return {
                authorized: false,
                riskScore: inquisition.riskScore,
                reason: inquisition.reason
            };
        }

        // Step 4: Capture Amber Sandbox Snapshot for file mutations
        let snapshotId = null;
        if (toolName === 'write_file' || toolName === 'patch_file') {
            const targetPath = toolArgs.filePath || toolArgs.file;
            if (targetPath) {
                snapshotId = this.amberSandbox.capturePreflight(targetPath);
            }
        }

        return {
            authorized: true,
            riskScore: inquisition.riskScore,
            snapshotId
        };
    }

    /**
     * Post-execution integrity verification (enforces Paleo-Reversion if corrupted)
     * @param {string|null} snapshotId - Snapshot ID from authorizeToolExecution
     * @returns {{ healthy: boolean, reverted: boolean, reason?: string }}
     */
    verifyToolResult(snapshotId) {
        if (!snapshotId) return { healthy: true, reverted: false };
        const result = this.amberSandbox.verifyAndEnforce(snapshotId);
        if (result.reverted) {
            this.telemetry.paleoReversions++;
        }
        return result;
    }

    /**
     * Sanitize outgoing response before transmitting to chat, Discord, or Voice TTS
     * @param {string} text
     * @returns {{ sanitizedText: string, honeyTokenTripped: boolean, redactedCount: number }}
     */
    interceptOutgoing(text) {
        const result = this.egressMask.sanitizeOutput(text);
        if (result.redactedCount > 0) {
            this.telemetry.redactionsApplied += result.redactedCount;
        }
        return result;
    }

    /**
     * Get real-time security dashboard telemetry
     */
    getTelemetry() {
        return {
            ...this.telemetry,
            activeSnapshots: this.amberSandbox.snapshots.size,
            intrusionsNeutralized: this.taintShield.intrusionLog.length,
            sessionEstimatedCost: `$${this.metabolicBrake.estimatedSessionCostUsd.toFixed(4)}`
        };
    }
}

// Export singleton instance for quick usage
export const aegis = new AegisSecuritySystem();
