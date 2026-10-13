/**
 * aegis-rex/layers/dualKeyInquisitor.js
 * Layer 3: Dual-Key Inquisitor (Split-Brain Preflight Verification).
 * Acts as an independent constitutional gatekeeper for all high blast-radius actions.
 */

export class DualKeyInquisitor {
    constructor(config = {}) {
        this.enabled = config.enabled !== false;
        this.highBlastRadiusTools = new Set(config.highBlastRadiusTools || [
            'run_shell',
            'run_command',
            'execute_applescript',
            'write_file',
            'patch_file',
            'send_email',
            'gmail_send',
            'github_create_pr'
        ]);

        this.forbiddenShellPatterns = config.forbiddenShellPatterns || [
            /\brm\s+-(?:r|f|rf|fr)\s+(?:\/|~|\$HOME|\.\.)/i,
            /\bmkfs\b/i,
            /\bdd\s+if=/i,
            /\bdiskutil\s+(?:erase|partition)/i,
            /\bchmod\s+-(?:R)?\s+777\s+\//i,
            />\s*\/dev\/sda/i,
            /:[(][)]\s*[{]\s*:[|]:&\s*[}]\s*[;]\s*:/,
            />\s*\/etc\/(?:shadow|passwd|sudoers)/i,
            /\b(?:nc|ncat|netcat)\s+.*-e\s+\/bin/i,
            /\bcurl\b.*(?:\.env|config\.json|knowledge_graph\.json).*-d\b/i
        ];
    }

    /**
     * Inspect a proposed action before execution
     * @param {string} toolName - Name of the tool to execute
     * @param {object} toolArgs - Arguments passed to the tool
     * @param {object} sessionContext - { ring, userIntent, topLevelGoal }
     * @returns {{ allowed: boolean, requiresMasterApproval: boolean, riskScore: 'LOW'|'MEDIUM'|'HIGH'|'CRITICAL', reason?: string }}
     */
    evaluateAction(toolName, toolArgs = {}, sessionContext = {}) {
        if (!this.enabled) {
            return { allowed: true, requiresMasterApproval: false, riskScore: 'LOW' };
        }

        // Safe/Readonly tools pass automatically
        if (!this.highBlastRadiusTools.has(toolName)) {
            return { allowed: true, requiresMasterApproval: false, riskScore: 'LOW' };
        }

        // 1. Evaluate Shell Commands
        if (toolName === 'run_shell' || toolName === 'run_command') {
            const cmd = String(toolArgs.command || toolArgs.cmd || '').trim();
            for (const pattern of this.forbiddenShellPatterns) {
                if (pattern.test(cmd)) {
                    return {
                        allowed: false,
                        requiresMasterApproval: true,
                        riskScore: 'CRITICAL',
                        reason: `Command matches critical security blocklist pattern: "${cmd}"`
                    };
                }
            }

            // High risk operations that require human Sovereign approval
            if (/\b(?:sudo|passwd|killall|shutdown|reboot)\b/i.test(cmd)) {
                return {
                    allowed: false,
                    requiresMasterApproval: true,
                    riskScore: 'HIGH',
                    reason: `Privileged command execution requires explicit Sovereign confirmation: "${cmd}"`
                };
            }
        }

        // 2. Evaluate AppleScript Execution
        if (toolName === 'execute_applescript') {
            const script = String(toolArgs.script || '').trim();
            if (/system\s+events.*keystroke.*password/i.test(script) || /do\s+shell\s+script.*administrator\s+privileges/i.test(script)) {
                return {
                    allowed: false,
                    requiresMasterApproval: true,
                    riskScore: 'CRITICAL',
                    reason: `AppleScript attempts elevated privilege escalation: "${script.slice(0, 80)}..."`
                };
            }
        }

        // 3. Evaluate File System Writes
        if (toolName === 'write_file' || toolName === 'patch_file') {
            const filePath = String(toolArgs.filePath || toolArgs.file || '');
            const normalized = filePath.replace(/\\/g, '/');

            // Protect critical OS, home directories, and shell profiles
            if (/^\/(?:etc|bin|sbin|usr\/bin|System|Library)\b/.test(normalized) ||
                normalized.includes('.ssh') ||
                normalized.includes('.gnupg') ||
                /\.(?:zshrc|bashrc|bash_profile|profile|zprofile)$/i.test(normalized) ||
                normalized.includes('/.zshrc') ||
                normalized.includes('/.bashrc')) {
                return {
                    allowed: false,
                    requiresMasterApproval: true,
                    riskScore: 'CRITICAL',
                    reason: `Target file is located in a protected system directory or shell profile: "${filePath}"`
                };
            }
        }

        // 4. Outbound communications
        if (toolName === 'send_email' || toolName === 'gmail_send') {
            const to = String(toolArgs.to || '');
            if (!to || to.includes('@')) {
                return {
                    allowed: true,
                    requiresMasterApproval: sessionContext.ring !== 0,
                    riskScore: 'MEDIUM',
                    reason: 'Outbound communications require Ring 0 Sovereign privilege.'
                };
            }
        }

        return {
            allowed: true,
            requiresMasterApproval: false,
            riskScore: 'LOW'
        };
    }
}
