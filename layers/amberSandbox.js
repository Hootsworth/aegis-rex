/**
 * aegis-rex/layers/amberSandbox.js
 * Layer 4: The Amber Sandbox (Temporal Micro-Rollback & Paleo-Reversion).
 * Automatically captures pre-flight state and reverts corrupted or truncated file edits.
 */

import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { execSync } from 'child_process';

export class AmberSandbox {
    constructor(config = {}) {
        this.enabled = config.enabled !== false;
        this.maxSnapshots = config.maxSnapshots || 50;
        this.syntaxValidationEnabled = config.syntaxValidationEnabled !== false;
        this.lineCountDropTolerance = config.lineCountDropTolerance ?? 0.5;
        this.snapshots = new Map();
    }

    /**
     * Take a pre-flight shadow snapshot before a file mutation
     * @param {string} filePath - Absolute or relative file path
     * @returns {string} Snapshot ID
     */
    capturePreflight(filePath) {
        if (!this.enabled || !filePath) return null;

        const resolved = path.resolve(process.cwd(), filePath);
        let exists = false;
        let content = null;
        let lineCount = 0;
        let hash = '';

        if (fs.existsSync(resolved)) {
            exists = true;
            try {
                content = fs.readFileSync(resolved, 'utf-8');
                lineCount = content.split('\n').length;
                hash = crypto.createHash('sha256').update(content).digest('hex');
            } catch {
                content = null;
            }
        }

        const snapshotId = `amber_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
        const snapshot = {
            id: snapshotId,
            filePath: resolved,
            existed: exists,
            content,
            lineCount,
            hash,
            timestamp: Date.now()
        };

        this.snapshots.set(snapshotId, snapshot);

        // Prune older snapshots if cache exceeds limit
        if (this.snapshots.size > this.maxSnapshots) {
            const oldestKey = this.snapshots.keys().next().value;
            this.snapshots.delete(oldestKey);
        }

        return snapshotId;
    }

    /**
     * Verify post-mutation integrity of a file. If corrupted, automatically execute Paleo-Reversion.
     * @param {string} snapshotId - Pre-flight snapshot ID
     * @returns {{ healthy: boolean, reverted: boolean, reason?: string }}
     */
    verifyAndEnforce(snapshotId) {
        if (!this.enabled || !snapshotId || !this.snapshots.has(snapshotId)) {
            return { healthy: true, reverted: false };
        }

        const snapshot = this.snapshots.get(snapshotId);
        const resolved = snapshot.filePath;

        if (!fs.existsSync(resolved)) {
            if (snapshot.existed) {
                this.paleoRevert(snapshotId);
                return {
                    healthy: false,
                    reverted: true,
                    reason: 'Target file was deleted unexpectedly; Paleo-Reversion restored original.'
                };
            }
            return { healthy: true, reverted: false };
        }

        let newContent = '';
        try {
            newContent = fs.readFileSync(resolved, 'utf-8');
        } catch (e) {
            this.paleoRevert(snapshotId);
            return { healthy: false, reverted: true, reason: `Unreadable file: ${e.message}` };
        }

        const newLineCount = newContent.split('\n').length;

        // 1. Catastrophic truncation check (e.g. AI truncated 1000-line file down to 10 lines)
        if (snapshot.existed && snapshot.lineCount > 20 && newLineCount < (snapshot.lineCount * this.lineCountDropTolerance)) {
            this.paleoRevert(snapshotId);
            return {
                healthy: false,
                reverted: true,
                reason: `Catastrophic truncation detected (lines dropped from ${snapshot.lineCount} to ${newLineCount}). Restored original.`
            };
        }

        // 2. Syntax validation for JavaScript / JSON files
        if (this.syntaxValidationEnabled) {
            const ext = path.extname(resolved).toLowerCase();
            if (ext === '.js' || ext === '.mjs') {
                try {
                    execSync(`node -c "${resolved}"`, { stdio: 'pipe' });
                } catch (syntaxErr) {
                    this.paleoRevert(snapshotId);
                    return {
                        healthy: false,
                        reverted: true,
                        reason: `Syntax error introduced in ${path.basename(resolved)}; Paleo-Reversion restored clean code.`
                    };
                }
            } else if (ext === '.json') {
                try {
                    JSON.parse(newContent);
                } catch (jsonErr) {
                    this.paleoRevert(snapshotId);
                    return {
                        healthy: false,
                        reverted: true,
                        reason: `Malformed JSON written to ${path.basename(resolved)}; restored valid original.`
                    };
                }
            }
        }

        return { healthy: true, reverted: false };
    }

    /**
     * Revert a file back to its pre-flight snapshot (Paleo-Reversion)
     */
    paleoRevert(snapshotId) {
        if (!this.snapshots.has(snapshotId)) return false;
        const snapshot = this.snapshots.get(snapshotId);

        try {
            if (!snapshot.existed) {
                if (fs.existsSync(snapshot.filePath)) fs.unlinkSync(snapshot.filePath);
            } else {
                fs.writeFileSync(snapshot.filePath, snapshot.content, 'utf-8');
            }
            return true;
        } catch {
            return false;
        }
    }
}
