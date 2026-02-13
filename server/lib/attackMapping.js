// MITRE ATT&CK Mapping Service (lightweight, keyword-based)
// Maps CVE descriptions to ATT&CK techniques based on common vulnerability patterns
// Based on MITRE's Center for Threat-Informed Defense attack_to_cve dataset patterns

const ATTACK_TECHNIQUE_PATTERNS = [
    // Initial Access
    { id: 'T1190', name: 'Exploit Public-Facing Application', patterns: ['remote code execution', 'rce', 'web application', 'public-facing', 'internet-facing'] },
    { id: 'T1133', name: 'External Remote Services', patterns: ['vpn', 'rdp', 'remote desktop', 'remote access', 'citrix', 'pulse secure'] },
    { id: 'T1566', name: 'Phishing', patterns: ['phishing', 'malicious attachment', 'spear-phishing'] },
    { id: 'T1078', name: 'Valid Accounts', patterns: ['default credentials', 'hardcoded credentials', 'credential', 'authentication bypass'] },

    // Execution
    { id: 'T1059', name: 'Command and Scripting Interpreter', patterns: ['command injection', 'os command', 'shell injection', 'code injection'] },
    { id: 'T1203', name: 'Exploitation for Client Execution', patterns: ['client-side', 'browser', 'office', 'pdf', 'use-after-free', 'type confusion'] },

    // Persistence
    { id: 'T1505', name: 'Server Software Component', patterns: ['webshell', 'web shell', 'backdoor', 'server component'] },

    // Privilege Escalation
    { id: 'T1068', name: 'Exploitation for Privilege Escalation', patterns: ['privilege escalation', 'local privilege', 'elevation of privilege', 'eop'] },

    // Defense Evasion
    { id: 'T1211', name: 'Exploitation for Defense Evasion', patterns: ['security bypass', 'bypass security', 'defense evasion', 'antivirus bypass'] },

    // Credential Access
    { id: 'T1212', name: 'Exploitation for Credential Access', patterns: ['credential theft', 'password disclosure', 'information disclosure', 'sensitive data'] },

    // Lateral Movement
    { id: 'T1210', name: 'Exploitation of Remote Services', patterns: ['smb', 'lateral movement', 'remote service', 'network service'] },

    // Impact
    { id: 'T1499', name: 'Endpoint Denial of Service', patterns: ['denial of service', 'dos', 'crash', 'resource exhaustion'] },
    { id: 'T1486', name: 'Data Encrypted for Impact', patterns: ['ransomware', 'encryption', 'ransom'] },
    { id: 'T1565', name: 'Data Manipulation', patterns: ['data manipulation', 'data corruption', 'integrity'] },

    // Collection
    { id: 'T1005', name: 'Data from Local System', patterns: ['data exfiltration', 'file read', 'arbitrary file', 'path traversal', 'directory traversal', 'local file inclusion'] },

    // Exfiltration
    { id: 'T1567', name: 'Exfiltration Over Web Service', patterns: ['exfiltration', 'data leak', 'information leak'] },

    // Cross-site attacks
    { id: 'T1189', name: 'Drive-by Compromise', patterns: ['cross-site scripting', 'xss', 'cross-site request forgery', 'csrf'] },

    // SQL
    { id: 'T1190', name: 'Exploit Public-Facing Application', patterns: ['sql injection', 'sqli'] },

    // Deserialization
    { id: 'T1059', name: 'Command and Scripting Interpreter', patterns: ['deserialization', 'unsafe deserialization', 'insecure deserialization'] },

    // Buffer overflows
    { id: 'T1203', name: 'Exploitation for Client Execution', patterns: ['buffer overflow', 'heap overflow', 'stack overflow', 'memory corruption', 'out-of-bounds'] },

    // SSRF
    { id: 'T1190', name: 'Exploit Public-Facing Application', patterns: ['server-side request forgery', 'ssrf'] }
];

/**
 * Map a vulnerability to relevant ATT&CK techniques based on its description
 * @param {Object} vuln - Vulnerability object with description
 * @returns {Array<{id: string, name: string}>} Matched ATT&CK techniques (deduplicated)
 */
export function mapToAttackTechniques(vuln) {
    if (!vuln?.description) return [];

    const desc = vuln.description.toLowerCase();
    const matched = new Map(); // Use map to deduplicate by technique ID

    for (const technique of ATTACK_TECHNIQUE_PATTERNS) {
        if (matched.has(technique.id)) continue; // Already matched this technique

        const isMatch = technique.patterns.some(pattern => desc.includes(pattern));
        if (isMatch) {
            matched.set(technique.id, { id: technique.id, name: technique.name });
        }
    }

    // Return at most 3 techniques per CVE to keep it manageable
    return Array.from(matched.values()).slice(0, 3);
}

/**
 * Enrich vulnerability objects with ATT&CK technique mappings
 * @param {Array} vulns - Array of vulnerability objects
 * @returns {Array} Enriched vulnerability objects
 */
export function enrichWithAttackTechniques(vulns) {
    if (!vulns || vulns.length === 0) return vulns;

    return vulns.map(vuln => {
        const techniques = mapToAttackTechniques(vuln);
        if (techniques.length > 0) {
            return { ...vuln, attackTechniques: techniques };
        }
        return vuln;
    });
}
