/**
 * aegis-rex/config.js
 * Default configuration and threat thresholds for the AEGIS-REX Security System.
 */

export const AEGIS_DEFAULT_CONFIG = {
    // Layer 1: Privilege Rings
    rings: {
        ring0Users: ['aditya', 'owner', 'master'], // Whitelisted sovereign IDs/usernames
        strictVoiceDemotion: true, // Voice interactions automatically demoted to Ring 1
        guestDefaultRing: 2, // Non-whitelisted interactions clamped to Ring 2
    },

    // Layer 2: Taint Shield (Indirect Prompt Injection)
    taintShield: {
        enabled: true,
        stripControlCharacters: true,
        disarmDangerousDirectives: true,
        suspiciousPatterns: [
            /ignore\s+(all\s+)?(previous\s+)?instructions/i,
            /system\s+(prompt\s+)?override/i,
            /\[\s*(?:system|sys)(?:\s+override)?\s*\]/i,
            /<<\s*sys\s*>>/i,
            /you\s+are\s+now\s+(in\s+)?developer\s+mode/i,
            /act\s+as\s+(dan|unrestricted|jailbroken)/i,
            /send\s+(the\s+)?(api\s+key|\.env|token|password|dossier)/i,
            /exfiltrate|leak|dump\s+(all\s+)?memory/i,
            /delete\s+(all\s+)?files|rm\s+-rf/i,
            /curl\s+-X\s+POST.*attacker/i
        ]
    },

    // Layer 3: Dual-Key Inquisitor (Blast Radius Limits)
    inquisitor: {
        enabled: true,
        highBlastRadiusTools: [
            'run_shell',
            'run_command',
            'execute_applescript',
            'write_file',
            'patch_file',
            'send_email',
            'gmail_send',
            'github_create_pr'
        ],
        forbiddenShellPatterns: [
            /\brm\s+-(?:r|f|rf|fr)\s+(?:\/|~|\$HOME|\.\.)/i,
            /\bmkfs\b/i,
            /\bdd\s+if=/i,
            /\bdiskutil\s+(?:erase|partition)/i,
            /\bchmod\s+-(?:R)?\s+777\s+\//i,
            />\s*\/dev\/sda/i,
            /:[(][)]\s*[{]\s*:[|]:&\s*[}]\s*[;]\s*:/, // Fork bomb
            />\s*\/etc\/(?:shadow|passwd|sudoers)/i,
            /\b(?:nc|ncat|netcat)\s+.*-e\s+\/bin/i,
            /\bcurl\b.*(?:\.env|config\.json|knowledge_graph\.json).*-d\b/i
        ]
    },

    // Layer 4: Amber Sandbox (Micro-Rollback)
    amberSandbox: {
        enabled: true,
        maxSnapshots: 50,
        syntaxValidationEnabled: true,
        lineCountDropTolerance: 0.5 // Flag if file drops by > 50% lines unexpectedly
    },

    // Layer 5: Metabolic Brake (Loop & Resource Guard)
    metabolicBrake: {
        maxIterationsPerTurn: 8,
        maxIdenticalToolCalls: 3, // Entropy detector trips if same tool & args called 3x
        budgetUsdLimit: 1.0,
        maxExecutionTimeoutMs: 60000 // 60s hard timeout per tool step
    },

    // Layer 6: Egress Mask & Honey-Tokens
    egressMask: {
        enabled: true,
        maskSecretKeys: true,
        redactLocalHomePaths: true,
        honeyToken: 'AEGIS_HONEY_TOKEN_77A_DO_NOT_EXFILTRATE',
        keyPatterns: [
            /sk-[A-Za-z0-9_-]{20,}/g, // OpenAI
            /sk_car_[A-Za-z0-9_-]{20,}/g, // Cartesia
            /AIzaSy[A-Za-z0-9_-]{33}/g, // Google AI / Gemini
            /ghp_[A-Za-z0-9]{36}/g, // GitHub Personal Access Token
            /gho_[A-Za-z0-9]{36}/g, // GitHub OAuth Token
            /[A-Za-z0-9+/]{40,}=*/g // Generic high-entropy base64 secret tokens
        ]
    }
};
