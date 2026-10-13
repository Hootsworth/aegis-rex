/**
 * aegis-rex/layers/ringGate.js
 * Layer 1: The Multi-Tier Privilege Ring Gate.
 * Enforces strict role-based capability boundaries based on caller identity & modality.
 */

export const RINGS = {
    RING_0_SOVEREIGN: 0, // Master / Local CLI / Authenticated Owner
    RING_1_STEWARD: 1,   // Ambient Voice / In-Call Voice Assistant
    RING_2_ENVOY: 2,     // Non-whitelisted Discord / Telegram Guests
    RING_3_UNTRUSTED: 3  // External Web Payloads / Cloned Content
};

export class RingGate {
    constructor(config = {}) {
        const rawUsers = config.ring0Users || config.sovereignUserIds || ['aditya', 'owner', 'master'];
        this.ring0Users = new Set(rawUsers.map(u => String(u).toLowerCase()));
        this.strictVoiceDemotion = config.strictVoiceDemotion !== false;
        this.guestDefaultRing = config.guestDefaultRing ?? RINGS.RING_2_ENVOY;

        // Tool permissions mapping by Ring
        this.disallowedByRing = {
            [RINGS.RING_0_SOVEREIGN]: new Set(), // Nothing disallowed by default for Sovereign
            [RINGS.RING_1_STEWARD]: new Set([
                'run_shell',
                'run_command',
                'execute_applescript',
                'manage_power',
                'send_email',
                'gmail_send',
                'github_create_pr'
            ]),
            [RINGS.RING_2_ENVOY]: new Set([
                'run_shell',
                'run_command',
                'execute_applescript',
                'mac_control',
                'write_file',
                'patch_file',
                'manage_personal_memory',
                'analyze_screen',
                'capture_screen',
                'set_volume',
                'set_brightness',
                'get_clipboard',
                'set_clipboard',
                'send_email',
                'gmail_send',
                'gmail_draft',
                'calendar_add',
                'github_create_pr',
                'linear_comment_issue',
                'notion_add_page'
            ]),
            [RINGS.RING_3_UNTRUSTED]: new Set([
                '*' // Completely inert: no tools allowed
            ])
        };
    }

    /**
     * Resolve the privilege ring for a given request
     * @param {object} context - { userId, username, modality: 'cli'|'voice'|'discord'|'telegram'|'web', isWhitelisted, source }
     * @returns {number} Ring level (0, 1, 2, or 3)
     */
    resolveRing(context = {}) {
        const { userId = '', username = '', modality = 'cli', isWhitelisted = false, source = '' } = context;
        const normalizedUser = String(username || userId).toLowerCase();

        // 1. External unvetted payloads are always Ring 3
        if (modality === 'untrusted_payload' || modality === 'web_context' || source.includes('untrusted')) {
            return RINGS.RING_3_UNTRUSTED;
        }

        // 2. Whitelisted Sovereign users
        const isSovereign = isWhitelisted || 
            (normalizedUser !== '' && (this.ring0Users.has(normalizedUser) || this.ring0Users.has(String(userId))));

        // 3. Voice modality demotion (prevent ambient room attacks from triggering raw shell)
        if (modality === 'voice') {
            return this.strictVoiceDemotion ? RINGS.RING_1_STEWARD : (isSovereign ? RINGS.RING_0_SOVEREIGN : RINGS.RING_1_STEWARD);
        }

        // 4. CLI with explicit unverified user
        if (modality === 'cli') {
            if (isSovereign || (!userId && !username)) {
                return RINGS.RING_0_SOVEREIGN;
            }
            return this.guestDefaultRing;
        }

        if (isSovereign) {
            return RINGS.RING_0_SOVEREIGN;
        }

        return this.guestDefaultRing;
    }

    /**
     * Verify whether a tool execution is authorized under the active Ring
     * @param {string} toolName
     * @param {number} ring
     * @returns {{ authorized: boolean, reason?: string }}
     */
    authorizeTool(toolName, ring) {
        if (ring === RINGS.RING_0_SOVEREIGN) {
            return { authorized: true };
        }

        const disallowed = this.disallowedByRing[ring] || new Set(['*']);
        if (disallowed.has('*') || disallowed.has(toolName)) {
            const ringLabels = {
                [RINGS.RING_1_STEWARD]: 'Ring 1 (Steward/Voice)',
                [RINGS.RING_2_ENVOY]: 'Ring 2 (Envoy/Remote Guest)',
                [RINGS.RING_3_UNTRUSTED]: 'Ring 3 (Untrusted/Inert)'
            };
            const label = ringLabels[ring] || `Ring ${ring}`;
            return {
                authorized: false,
                reason: `Tool '${toolName}' is forbidden under ${label}. Elevate to Ring 0 Sovereign to execute.`
            };
        }

        return { authorized: true };
    }
}
