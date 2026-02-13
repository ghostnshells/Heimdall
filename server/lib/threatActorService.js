// Threat actor association enrichment.
// Uses CISA KEV ransomware signals and lightweight Mandiant-reference pattern matching.

const MANDIANT_ACTOR_PATTERNS = [
    { aliases: ['apt29', 'cozy bear', 'nobelium', 'midnight blizzard'], name: 'APT29 / NOBELIUM' },
    { aliases: ['apt28', 'fancy bear', 'sofacy', 'forest blizzard'], name: 'APT28 / Fancy Bear' },
    { aliases: ['sandworm', 'apt44', 'seashell blizzard'], name: 'Sandworm / APT44' },
    { aliases: ['lazarus', 'apt38', 'hidden cobra'], name: 'Lazarus Group' },
    { aliases: ['apt41', 'double dragon', 'barium'], name: 'APT41' },
    { aliases: ['unc2452', 'unc3004', 'unc3944', 'unc5221'], name: 'Mandiant UNC Cluster' },
    { aliases: ['cl0p', 'clop'], name: 'Cl0p Ransomware' },
    { aliases: ['lockbit'], name: 'LockBit Ransomware' },
    { aliases: ['blackcat', 'alphv'], name: 'ALPHV / BlackCat' }
];

function findMandiantActors(vuln) {
    const text = [
        vuln?.description || '',
        ...(vuln?.references || []).map((r) => r.url || '')
    ].join(' ').toLowerCase();

    // Require at least one Mandiant signal before applying alias matching.
    const hasMandiantSignal =
        text.includes('mandiant') ||
        (vuln?.references || []).some((r) => (r.url || '').toLowerCase().includes('mandiant.com'));

    if (!hasMandiantSignal) return [];

    const actors = [];
    for (const actor of MANDIANT_ACTOR_PATTERNS) {
        const matched = actor.aliases.some((alias) => text.includes(alias));
        if (matched) {
            actors.push({
                name: actor.name,
                source: 'Mandiant'
            });
        }
    }

    // If Mandiant is referenced but no alias is parsed, keep a generic attribution.
    if (!actors.length) {
        actors.push({
            name: 'Mandiant-linked activity',
            source: 'Mandiant'
        });
    }

    return actors;
}

function findCISAActors(vuln) {
    if (vuln?.cisaData?.knownRansomwareCampaignUse !== 'Known') return [];

    return [{
        name: 'Known ransomware campaign',
        source: 'CISA KEV'
    }];
}

export function enrichWithThreatActors(vulns) {
    if (!Array.isArray(vulns) || vulns.length === 0) return vulns;

    return vulns.map((vuln) => {
        const cisaActors = findCISAActors(vuln);
        const mandiantActors = findMandiantActors(vuln);
        const combined = [...cisaActors, ...mandiantActors];

        if (!combined.length) return vuln;

        // Dedupe by actor name + source.
        const unique = Array.from(
            new Map(combined.map((a) => [`${a.name}|${a.source}`, a])).values()
        );

        return {
            ...vuln,
            threatActors: unique
        };
    });
}

