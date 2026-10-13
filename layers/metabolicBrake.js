/**
 * aegis-rex/layers/metabolicBrake.js
 * Layer 5: The Metabolic Brake (Loop & Resource Guard).
 * Prevents hallucinatory tool loops, token runaways, and runaway compute spikes.
 */

import crypto from 'crypto';

export class MetabolicBrake {
    constructor(config = {}) {
        this.maxIterationsPerTurn = config.maxIterationsPerTurn || config.maxTurnsPerInstruction || 8;
        this.maxIdenticalToolCalls = config.maxIdenticalToolCalls || config.loopThreshold || 3;
        this.budgetUsdLimit = config.budgetUsdLimit || 1.0;
        this.maxExecutionTimeoutMs = config.maxExecutionTimeoutMs || 60000;

        this.recentActionHashes = [];
        this.turnIterationCount = 0;
        this.estimatedSessionCostUsd = 0.0;
    }

    /**
     * Reset per-turn iteration count at the start of a user prompt
     */
    resetTurn() {
        this.turnIterationCount = 0;
        this.recentActionHashes = [];
    }

    /**
     * Evaluate whether the next execution step is safe to proceed
     * @param {string} toolName
     * @param {object} toolArgs
     * @returns {{ tripped: boolean, reason?: string }}
     */
    recordStepAndCheck(toolName, toolArgs = {}) {
        this.turnIterationCount++;

        // 1. Max iteration ceiling
        if (this.turnIterationCount > this.maxIterationsPerTurn) {
            return {
                tripped: true,
                reason: `Turn budget exceeded: turn reached maximum iteration budget of ${this.maxIterationsPerTurn} steps.`
            };
        }

        // 2. Entropy / Repetitive Tool Loop Detection
        const argsStr = JSON.stringify(toolArgs || {});
        const actionHash = crypto.createHash('sha256').update(`${toolName}:${argsStr}`).digest('hex');
        this.recentActionHashes.push(actionHash);

        // Check if last N actions are identical
        if (this.recentActionHashes.length >= this.maxIdenticalToolCalls) {
            const tail = this.recentActionHashes.slice(-this.maxIdenticalToolCalls);
            const allMatch = tail.every(h => h === actionHash);
            if (allMatch) {
                return {
                    tripped: true,
                    reason: `Infinite repetition loop detected: entropy guard tripped (${toolName} called ${this.maxIdenticalToolCalls} times with identical arguments).`
                };
            }
        }

        // 3. Cost limit check
        if (this.estimatedSessionCostUsd >= this.budgetUsdLimit) {
            return {
                tripped: true,
                reason: `Financial brake tripped: session cost ($${this.estimatedSessionCostUsd.toFixed(2)}) reached budget limit ($${this.budgetUsdLimit.toFixed(2)}).`
            };
        }

        return { tripped: false };
    }

    /**
     * Record estimated cost of a completed LLM step
     */
    addCost(amountUsd) {
        if (typeof amountUsd === 'number' && !isNaN(amountUsd)) {
            this.estimatedSessionCostUsd += amountUsd;
        }
    }
}
