// Asset definitions for Heimdall Vulnerability Monitor
// Each asset represents a vendor or product to monitor for vulnerabilities
// Consolidated structure: One card per major vendor (Cisco, Microsoft, HPE) with sub-products

// Vendor Groups for hierarchical navigation
export const VENDOR_GROUPS = {
    WATCHGUARD: 'WatchGuard',
    HPE: 'HPE',
    CISCO: 'Cisco',
    MICROSOFT: 'Microsoft',
    TRIPP_LITE: 'Tripp Lite',
    SOLARWINDS: 'SolarWinds',
    CONNECTWISE: 'ConnectWise',
    ORACLE: 'Oracle',
    VEEAM: 'Veeam',
    ZERTO: 'Zerto',
    BITDEFENDER: 'BitDefender',
    ZOOM: 'Zoom',
    GOOGLE: 'Google',
    MOZILLA: 'Mozilla',
    CRESTRON: 'Crestron'
};

// Asset categories for filtering
export const ASSET_CATEGORIES = {
    FIREWALL_VPN: 'Firewall & VPN',
    STORAGE: 'Storage',
    SERVERS: 'Servers',
    POWER: 'Power & UPS',
    NETWORK: 'Network Infrastructure',
    IT_MANAGEMENT: 'IT Management',
    DATABASE: 'Database',
    BACKUP_DR: 'Backup & DR',
    SECURITY: 'Security',
    COLLABORATION: 'Collaboration',
    BROWSERS: 'Browsers',
    AV_CONTROL: 'AV & Control',
    OPERATING_SYSTEMS: 'Operating Systems',
    ENTERPRISE_SOFTWARE: 'Enterprise Software'
};

export const ASSETS = [
    // ==========================================
    // CISCO - Consolidated vendor card
    // Monitors: IOS, IOS XE, ISE, Catalyst switches, Nexus, Wireless LAN Controllers
    // ==========================================
    {
        id: 'cisco',
        name: 'Cisco',
        vendor: 'Cisco',
        category: ASSET_CATEGORIES.NETWORK,
        vendorGroup: VENDOR_GROUPS.CISCO,
        description: 'Cisco networking infrastructure including IOS, switches, and wireless controllers',
        // Primary CPE vendor for searching
        cpeVendor: 'cisco',
        // Multiple CPE products to search for
        cpeProducts: [
            'ios',
            'ios_xe',
            'ios_xr',
            'identity_services_engine',
            'catalyst',
            'nexus',
            'wireless_lan_controller',
            'aironet',
            'meraki'
        ],
        // Keywords for keyword-based searching
        keywords: [
            'cisco ios',
            'cisco ios xe',
            'cisco ios xr',
            'cisco ise',
            'cisco identity services engine',
            'cisco catalyst',
            'cisco nexus',
            'cisco wireless lan controller',
            'cisco wlc',
            'cisco aironet',
            'cisco meraki'
        ],
        // Sub-products for display and filtering within the vendor card
        subProducts: [
            { id: 'ios', name: 'Cisco IOS', type: 'Software' },
            { id: 'ios-xe', name: 'Cisco IOS XE', type: 'Software' },
            { id: 'ios-xr', name: 'Cisco IOS XR', type: 'Software' },
            { id: 'ise', name: 'Cisco ISE', type: 'Software' },
            { id: 'catalyst-9500', name: 'Catalyst 9500', type: 'Switch' },
            { id: 'catalyst-9300', name: 'Catalyst 9300', type: 'Switch' },
            { id: 'catalyst-3750', name: 'Catalyst 3750', type: 'Switch' },
            { id: 'catalyst-3650', name: 'Catalyst 3650', type: 'Switch' },
            { id: 'nexus-9000', name: 'Nexus 9000 Series', type: 'Switch' },
            { id: 'wlc', name: 'Wireless LAN Controller', type: 'Controller' },
            { id: 'aironet', name: 'Aironet Access Points', type: 'Wireless' },
            { id: 'meraki', name: 'Meraki', type: 'Cloud Managed' }
        ]
    },

    // ==========================================
    // MICROSOFT - Consolidated vendor card
    // Monitors: Windows OS, Server, Office 365, Exchange, SharePoint, SQL Server, etc.
    // ==========================================
    {
        id: 'microsoft',
        name: 'Microsoft',
        vendor: 'Microsoft',
        category: ASSET_CATEGORIES.ENTERPRISE_SOFTWARE,
        vendorGroup: VENDOR_GROUPS.MICROSOFT,
        description: 'Microsoft products including Windows, Office 365, Exchange, and development tools',
        // Primary CPE vendor for searching
        cpeVendor: 'microsoft',
        // Multiple CPE products to search for
        cpeProducts: [
            'windows_10',
            'windows_11',
            'windows_server_2012',
            'windows_server_2016',
            'windows_server_2019',
            'windows_server_2022',
            'exchange_server',
            'sharepoint_server',
            'sql_server',
            '365_apps',
            'office',
            'visual_studio',
            'teams',
            'edge_chromium',
            'azure'
        ],
        // Keywords for keyword-based searching
        keywords: [
            'microsoft windows',
            'windows server',
            'microsoft exchange',
            'microsoft sharepoint',
            'microsoft sql server',
            'microsoft 365',
            'office 365',
            'microsoft teams',
            'microsoft edge',
            'visual studio',
            'microsoft azure'
        ],
        // Sub-products grouped by category for display
        subProducts: [
            // Desktop OS
            { id: 'windows-10', name: 'Windows 10', type: 'Desktop OS', group: 'Operating Systems' },
            { id: 'windows-11', name: 'Windows 11', type: 'Desktop OS', group: 'Operating Systems' },
            // Server OS
            { id: 'server-2012', name: 'Windows Server 2012', type: 'Server OS', group: 'Operating Systems' },
            { id: 'server-2016', name: 'Windows Server 2016', type: 'Server OS', group: 'Operating Systems' },
            { id: 'server-2019', name: 'Windows Server 2019', type: 'Server OS', group: 'Operating Systems' },
            { id: 'server-2022', name: 'Windows Server 2022', type: 'Server OS', group: 'Operating Systems' },
            // Microsoft 365 / Productivity
            { id: 'office-365', name: 'Microsoft 365 / Office', type: 'Productivity', group: 'Microsoft 365' },
            { id: 'exchange', name: 'Exchange Server', type: 'Email', group: 'Microsoft 365' },
            { id: 'sharepoint', name: 'SharePoint', type: 'Collaboration', group: 'Microsoft 365' },
            { id: 'teams', name: 'Microsoft Teams', type: 'Communication', group: 'Microsoft 365' },
            // Database
            { id: 'sql-server', name: 'SQL Server', type: 'Database', group: 'Data Platform' },
            // Development Tools
            { id: 'visual-studio', name: 'Visual Studio', type: 'IDE', group: 'Development' },
            // Browsers
            { id: 'edge', name: 'Microsoft Edge', type: 'Browser', group: 'Applications' },
            // Cloud
            { id: 'azure', name: 'Azure', type: 'Cloud', group: 'Cloud Services' }
        ]
    },

    // ==========================================
    // HPE - Consolidated vendor card
    // Monitors: ProLiant servers, Alletra/Nimble Storage, iLO
    // ==========================================
    {
        id: 'hpe',
        name: 'HPE',
        vendor: 'Hewlett Packard Enterprise',
        category: ASSET_CATEGORIES.SERVERS,
        vendorGroup: VENDOR_GROUPS.HPE,
        description: 'HPE infrastructure including ProLiant servers and Nimble/Alletra storage',
        // Primary CPE vendor for searching
        cpeVendor: 'hpe',
        // Additional CPE vendors (HPE uses multiple vendor strings in NVD)
        additionalCpeVendors: ['hp', 'hewlett_packard_enterprise'],
        // Multiple CPE products to search for
        cpeProducts: [
            'proliant',
            'proliant_dl380',
            'proliant_dl360',
            'proliant_ml350',
            'nimble_storage',
            'alletra',
            'integrated_lights-out',
            'ilo',
            'oneview',
            'storeonce'
        ],
        // Keywords for keyword-based searching
        keywords: [
            'hpe proliant',
            'hpe nimble',
            'hpe alletra',
            'hewlett packard enterprise',
            'hpe ilo',
            'integrated lights-out',
            'hpe oneview',
            'hpe storeonce'
        ],
        // Sub-products for display
        subProducts: [
            // Servers
            { id: 'proliant-dl380', name: 'ProLiant DL380', type: 'Rack Server', group: 'Servers' },
            { id: 'proliant-dl360', name: 'ProLiant DL360', type: 'Rack Server', group: 'Servers' },
            { id: 'proliant-ml350', name: 'ProLiant ML350', type: 'Tower Server', group: 'Servers' },
            { id: 'ilo', name: 'iLO (Integrated Lights-Out)', type: 'Management', group: 'Management' },
            // Storage
            { id: 'nimble', name: 'Nimble Storage', type: 'Storage', group: 'Storage' },
            { id: 'alletra', name: 'Alletra', type: 'Storage', group: 'Storage' },
            { id: 'storeonce', name: 'StoreOnce', type: 'Backup', group: 'Storage' },
            // Management
            { id: 'oneview', name: 'OneView', type: 'Management', group: 'Management' }
        ]
    },

    // ==========================================
    // WatchGuard - Firewall & VPN
    // ==========================================
    {
        id: 'watchguard',
        name: 'WatchGuard',
        vendor: 'WatchGuard',
        category: ASSET_CATEGORIES.FIREWALL_VPN,
        vendorGroup: VENDOR_GROUPS.WATCHGUARD,
        description: 'WatchGuard Firebox firewalls and VPN solutions',
        cpeVendor: 'watchguard',
        cpeProducts: ['firebox', 'fireware', 'mobile_vpn', 'authpoint'],
        keywords: ['watchguard', 'firebox', 'fireware', 'watchguard vpn'],
        subProducts: [
            { id: 'firebox', name: 'Firebox', type: 'Firewall' },
            { id: 'fireware', name: 'Fireware OS', type: 'Software' },
            { id: 'mobile-vpn', name: 'Mobile VPN', type: 'VPN' },
            { id: 'authpoint', name: 'AuthPoint', type: 'MFA' }
        ]
    },

    // ==========================================
    // Tripp Lite - Power & UPS
    // ==========================================
    {
        id: 'tripplite-ups',
        name: 'Tripp Lite UPS',
        vendor: 'Tripp Lite',
        category: ASSET_CATEGORIES.POWER,
        vendorGroup: VENDOR_GROUPS.TRIPP_LITE,
        description: 'Tripp Lite UPS and power management products',
        cpeVendor: 'tripp_lite',
        cpeProducts: ['smartpro', 'smart_online', 'smartonline', 'poweralert'],
        keywords: ['tripp lite'],
        preferKeywordSearch: true
    },

    // ==========================================
    // SolarWinds - IT Management
    // ==========================================
    {
        id: 'solarwinds',
        name: 'SolarWinds',
        vendor: 'SolarWinds',
        category: ASSET_CATEGORIES.IT_MANAGEMENT,
        vendorGroup: VENDOR_GROUPS.SOLARWINDS,
        description: 'SolarWinds IT management and monitoring platform',
        cpeVendor: 'solarwinds',
        cpeProducts: ['orion', 'orion_platform', 'network_performance_monitor', 'server_and_application_monitor'],
        keywords: ['solarwinds', 'orion platform', 'solarwinds npm', 'solarwinds sam']
    },

    // ==========================================
    // ConnectWise - IT Management
    // ==========================================
    {
        id: 'connectwise',
        name: 'ConnectWise',
        vendor: 'ConnectWise',
        category: ASSET_CATEGORIES.IT_MANAGEMENT,
        vendorGroup: VENDOR_GROUPS.CONNECTWISE,
        description: 'ConnectWise RMM and remote access tools',
        cpeVendor: 'connectwise',
        cpeProducts: ['screenconnect', 'automate', 'control', 'manage'],
        keywords: ['connectwise', 'screenconnect', 'connectwise automate', 'connectwise manage']
    },

    // ==========================================
    // Oracle - Database
    // ==========================================
    {
        id: 'oracle-database',
        name: 'Oracle Database',
        vendor: 'Oracle',
        category: ASSET_CATEGORIES.DATABASE,
        vendorGroup: VENDOR_GROUPS.ORACLE,
        description: 'Oracle Database and related products',
        cpeVendor: 'oracle',
        cpeProducts: ['database', 'database_server', 'enterprise_manager'],
        keywords: ['oracle database', 'oracle db', 'oracle enterprise manager']
    },

    // ==========================================
    // Veeam - Backup & DR
    // ==========================================
    {
        id: 'veeam',
        name: 'Veeam',
        vendor: 'Veeam',
        category: ASSET_CATEGORIES.BACKUP_DR,
        vendorGroup: VENDOR_GROUPS.VEEAM,
        description: 'Veeam backup and replication solutions',
        cpeVendor: 'veeam',
        cpeProducts: ['backup_and_replication', 'veeam_backup_\\&_replication', 'one', 'agent'],
        keywords: ['veeam'],
        preferKeywordSearch: true
    },

    // ==========================================
    // Zerto - Backup & DR
    // ==========================================
    {
        id: 'zerto',
        name: 'Zerto',
        vendor: 'Zerto',
        category: ASSET_CATEGORIES.BACKUP_DR,
        vendorGroup: VENDOR_GROUPS.ZERTO,
        description: 'Zerto disaster recovery and replication',
        cpeVendor: 'zerto',
        cpeProducts: ['virtual_replication', 'zerto'],
        keywords: ['zerto', 'zerto virtual replication']
    },

    // ==========================================
    // BitDefender - Security
    // ==========================================
    {
        id: 'bitdefender',
        name: 'BitDefender',
        vendor: 'BitDefender',
        category: ASSET_CATEGORIES.SECURITY,
        vendorGroup: VENDOR_GROUPS.BITDEFENDER,
        description: 'BitDefender endpoint security and GravityZone',
        cpeVendor: 'bitdefender',
        cpeProducts: ['gravityzone', 'endpoint_security', 'total_security'],
        keywords: ['bitdefender', 'gravityzone']
    },

    // ==========================================
    // Zoom - Collaboration
    // ==========================================
    {
        id: 'zoom',
        name: 'Zoom',
        vendor: 'Zoom Video Communications',
        category: ASSET_CATEGORIES.COLLABORATION,
        vendorGroup: VENDOR_GROUPS.ZOOM,
        description: 'Zoom video conferencing and collaboration',
        cpeVendor: 'zoom',
        cpeProducts: ['meetings', 'zoom', 'zoom_client', 'workplace', 'rooms'],
        keywords: ['zoom video communications', 'zoom meetings', 'zoom client']
    },

    // ==========================================
    // Google Chrome - Browsers
    // ==========================================
    {
        id: 'google-chrome',
        name: 'Google Chrome',
        vendor: 'Google',
        category: ASSET_CATEGORIES.BROWSERS,
        vendorGroup: VENDOR_GROUPS.GOOGLE,
        description: 'Google Chrome web browser',
        cpeVendor: 'google',
        cpeProducts: ['chrome'],
        keywords: ['google chrome', 'chrome browser']
    },

    // ==========================================
    // Firefox - Browsers
    // ==========================================
    {
        id: 'firefox',
        name: 'Firefox',
        vendor: 'Mozilla',
        category: ASSET_CATEGORIES.BROWSERS,
        vendorGroup: VENDOR_GROUPS.MOZILLA,
        description: 'Mozilla Firefox web browser',
        cpeVendor: 'mozilla',
        cpeProducts: ['firefox'],
        keywords: ['mozilla firefox', 'firefox browser']
    },

    // ==========================================
    // Crestron - AV & Control
    // ==========================================
    {
        id: 'crestron',
        name: 'Crestron',
        vendor: 'Crestron',
        category: ASSET_CATEGORIES.AV_CONTROL,
        vendorGroup: VENDOR_GROUPS.CRESTRON,
        description: 'Crestron AV and control systems',
        cpeVendor: 'crestron',
        cpeProducts: ['crestron', 'dm', 'nvx', 'flex'],
        keywords: ['crestron', 'crestron av', 'crestron control']
    }
];

// Get unique categories
export const getCategories = () => {
    return [...new Set(ASSETS.map(asset => asset.category))];
};

// Get assets by category
export const getAssetsByCategory = (category) => {
    if (!category || category === 'All') {
        return ASSETS;
    }
    return ASSETS.filter(asset => asset.category === category);
};

// Get asset by ID
export const getAssetById = (id) => {
    return ASSETS.find(asset => asset.id === id);
};

// Get all keywords for an asset (for API searching)
export const getAssetKeywords = (assetId) => {
    const asset = getAssetById(assetId);
    return asset ? asset.keywords : [];
};

// ============================================
// Vendor Grouping Helper Functions
// ============================================

// Get list of unique vendor groups that have assets
export const getVendorGroups = () => {
    const vendorGroups = [...new Set(ASSETS.map(asset => asset.vendorGroup))];
    return vendorGroups.filter(Boolean).sort();
};

// Get assets by vendor group
export const getAssetsByVendorGroup = (vendorGroup) => {
    if (!vendorGroup || vendorGroup === 'All') {
        return ASSETS;
    }
    return ASSETS.filter(asset => asset.vendorGroup === vendorGroup);
};

// Get subcategories for a vendor (based on asset categories within that vendor group)
export const getSubcategoriesForVendor = (vendorGroup) => {
    const vendorAssets = getAssetsByVendorGroup(vendorGroup);
    const subcategories = [...new Set(vendorAssets.map(asset => asset.category))];
    return subcategories.filter(Boolean).sort();
};

// Get assets by vendor and subcategory (category within a vendor group)
export const getAssetsByVendorAndSubcategory = (vendorGroup, subcategory) => {
    return ASSETS.filter(asset =>
        asset.vendorGroup === vendorGroup && asset.category === subcategory
    );
};

// Get vulnerability counts for a vendor group
export const getVendorVulnCounts = (vendorGroup, vulnCounts) => {
    const vendorAssets = getAssetsByVendorGroup(vendorGroup);
    let total = 0;
    let critical = 0;
    let high = 0;
    let medium = 0;
    let low = 0;

    vendorAssets.forEach(asset => {
        const counts = vulnCounts[asset.id];
        if (counts) {
            total += counts.total || 0;
            critical += counts.critical || 0;
            high += counts.high || 0;
            medium += counts.medium || 0;
            low += counts.low || 0;
        }
    });

    return { total, critical, high, medium, low };
};

// Get vulnerability counts for a subcategory within a vendor
export const getSubcategoryVulnCounts = (vendorGroup, subcategory, vulnCounts) => {
    const assets = getAssetsByVendorAndSubcategory(vendorGroup, subcategory);
    let total = 0;
    let critical = 0;
    let high = 0;
    let medium = 0;
    let low = 0;

    assets.forEach(asset => {
        const counts = vulnCounts[asset.id];
        if (counts) {
            total += counts.total || 0;
            critical += counts.critical || 0;
            high += counts.high || 0;
            medium += counts.medium || 0;
            low += counts.low || 0;
        }
    });

    return { total, critical, high, medium, low };
};

// Get sub-products for an asset (for drill-down view)
export const getSubProductsForAsset = (assetId) => {
    const asset = getAssetById(assetId);
    return asset?.subProducts || [];
};

// Get sub-products grouped by their group property
export const getGroupedSubProducts = (assetId) => {
    const subProducts = getSubProductsForAsset(assetId);
    const groups = {};

    subProducts.forEach(subProduct => {
        const groupName = subProduct.group || 'Other';
        if (!groups[groupName]) {
            groups[groupName] = [];
        }
        groups[groupName].push(subProduct);
    });

    return groups;
};

// Helper to match a vulnerability to specific sub-products within a vendor
export const matchVulnToSubProducts = (vuln, asset) => {
    if (!asset?.subProducts) return [];

    const desc = vuln.description?.toLowerCase() || '';
    const cpes = vuln.affectedProducts?.map(p => p.cpe?.toLowerCase() || '') || [];

    const matchedSubProducts = [];

    asset.subProducts.forEach(subProduct => {
        // Check if the vulnerability description or CPEs mention this sub-product
        const subProductTerms = subProduct.name.toLowerCase().split(' ');
        const matchesDesc = subProductTerms.some(term => term.length > 3 && desc.includes(term));
        const matchesCPE = cpes.some(cpe =>
            subProductTerms.some(term => term.length > 3 && cpe.includes(term))
        );

        if (matchesDesc || matchesCPE) {
            matchedSubProducts.push(subProduct);
        }
    });

    return matchedSubProducts;
};

export default ASSETS;
