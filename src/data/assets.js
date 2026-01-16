// Asset definitions from Plan.txt
// Each asset has metadata for display and vulnerability tracking

export const ASSET_CATEGORIES = {
    FIREWALL_VPN: 'Firewall & VPN',
    STORAGE: 'Storage',
    SERVERS: 'Servers',
    POWER: 'Power & UPS',
    NETWORK: 'Network Switches',
    NETWORK_OS: 'Network OS',
    IT_MANAGEMENT: 'IT Management',
    DATABASE: 'Database',
    BACKUP_DR: 'Backup & DR',
    SECURITY: 'Security',
    COLLABORATION: 'Collaboration',
    BROWSERS: 'Browsers',
    AV_CONTROL: 'AV & Control',
    // New Microsoft categories
    MICROSOFT_OS: 'Microsoft OS',
    MICROSOFT_SERVER: 'Microsoft Server',
    MICROSOFT_APPS: 'Microsoft Apps',
    MICROSOFT_DEV: 'Microsoft Dev Tools'
};

export const ASSETS = [
    // Firewall & VPN
    {
        id: 'watchguard-firebox',
        name: 'WatchGuard Firebox',
        vendor: 'WatchGuard',
        category: ASSET_CATEGORIES.FIREWALL_VPN,
        keywords: ['watchguard', 'firebox', 'firewall'],
        cpeVendor: 'watchguard',
        cpeProduct: 'firebox'
    },
    {
        id: 'watchguard-vpn',
        name: 'WatchGuard VPN',
        vendor: 'WatchGuard',
        category: ASSET_CATEGORIES.FIREWALL_VPN,
        keywords: ['watchguard', 'vpn', 'mobile vpn', 'ipsec'],
        cpeVendor: 'watchguard',
        cpeProduct: 'mobile_vpn'
    },

    // Storage
    {
        id: 'hpe-alletra-nimble',
        name: 'HPE Alletra Nimble Storage',
        vendor: 'HPE',
        category: ASSET_CATEGORIES.STORAGE,
        keywords: ['hpe', 'nimble', 'alletra', 'storage'],
        cpeVendor: 'hpe',
        cpeProduct: 'nimble_storage'
    },

    // Servers
    {
        id: 'hpe-proliant-dl380',
        name: 'HPE ProLiant DL380',
        vendor: 'HPE',
        category: ASSET_CATEGORIES.SERVERS,
        keywords: ['hpe', 'proliant', 'dl380', 'server', 'ilo'],
        cpeVendor: 'hpe',
        cpeProduct: 'proliant_dl380'
    },

    // Power
    {
        id: 'tripplite-ups',
        name: 'Tripplite UPS',
        vendor: 'Tripplite',
        category: ASSET_CATEGORIES.POWER,
        keywords: ['tripplite', 'tripp-lite', 'ups', 'power'],
        cpeVendor: 'tripplite',
        cpeProduct: 'ups'
    },

    // Network OS
    {
        id: 'cisco-ios',
        name: 'Cisco IOS',
        vendor: 'Cisco',
        category: ASSET_CATEGORIES.NETWORK_OS,
        keywords: ['cisco', 'ios', 'ios-xe', 'ios-xr'],
        cpeVendor: 'cisco',
        cpeProduct: 'ios'
    },

    // Network Switches
    {
        id: 'cisco-catalyst-9500',
        name: 'Cisco Catalyst 9500',
        vendor: 'Cisco',
        category: ASSET_CATEGORIES.NETWORK,
        keywords: ['cisco', 'catalyst', '9500', 'switch'],
        cpeVendor: 'cisco',
        cpeProduct: 'catalyst_9500'
    },
    {
        id: 'cisco-catalyst-9300',
        name: 'Cisco Catalyst 9300',
        vendor: 'Cisco',
        category: ASSET_CATEGORIES.NETWORK,
        keywords: ['cisco', 'catalyst', '9300', 'switch'],
        cpeVendor: 'cisco',
        cpeProduct: 'catalyst_9300'
    },
    {
        id: 'cisco-sg500',
        name: 'Cisco SG500',
        vendor: 'Cisco',
        category: ASSET_CATEGORIES.NETWORK,
        keywords: ['cisco', 'sg500', 'small business', 'switch'],
        cpeVendor: 'cisco',
        cpeProduct: 'sg500'
    },
    {
        id: 'cisco-catalyst-3750',
        name: 'Cisco Catalyst 3750',
        vendor: 'Cisco',
        category: ASSET_CATEGORIES.NETWORK,
        keywords: ['cisco', 'catalyst', '3750', 'switch'],
        cpeVendor: 'cisco',
        cpeProduct: 'catalyst_3750'
    },
    {
        id: 'cisco-catalyst-3650',
        name: 'Cisco Catalyst 3650',
        vendor: 'Cisco',
        category: ASSET_CATEGORIES.NETWORK,
        keywords: ['cisco', 'catalyst', '3650', 'switch'],
        cpeVendor: 'cisco',
        cpeProduct: 'catalyst_3650'
    },
    {
        id: 'cisco-nexus-93180',
        name: 'Cisco Nexus 93180',
        vendor: 'Cisco',
        category: ASSET_CATEGORIES.NETWORK,
        keywords: ['cisco nexus 93180', 'nexus 9000'],
        cpeVendor: 'cisco',
        cpeProduct: 'nexus_93180yc-ex',
        additionalCpeProducts: ['nexus_93180yc-fx', 'nexus_9000', 'nx-os']
    },

    // IT Management
    {
        id: 'solarwinds',
        name: 'SolarWinds',
        vendor: 'SolarWinds',
        category: ASSET_CATEGORIES.IT_MANAGEMENT,
        keywords: ['solarwinds', 'orion', 'npm', 'sam', 'network monitoring'],
        cpeVendor: 'solarwinds',
        cpeProduct: 'orion'
    },
    {
        id: 'connectwise',
        name: 'ConnectWise',
        vendor: 'ConnectWise',
        category: ASSET_CATEGORIES.IT_MANAGEMENT,
        keywords: ['connectwise', 'screenconnect', 'automate', 'manage'],
        cpeVendor: 'connectwise',
        cpeProduct: 'screenconnect'
    },

    // Database
    {
        id: 'oracle-database-appliance',
        name: 'Oracle Database Appliances',
        vendor: 'Oracle',
        category: ASSET_CATEGORIES.DATABASE,
        keywords: ['oracle', 'database', 'oda', 'appliance', 'db'],
        cpeVendor: 'oracle',
        cpeProduct: 'database'
    },

    // Backup & DR
    {
        id: 'veeam',
        name: 'Veeam',
        vendor: 'Veeam',
        category: ASSET_CATEGORIES.BACKUP_DR,
        keywords: ['veeam'],
        cpeVendor: 'veeam',
        cpeProduct: 'veeam_backup_\\&_replication',
        // Additional CPE products (NVD uses different formats for Veeam)
        additionalCpeProducts: ['backup_and_replication', 'veeam_agent_for_windows', 'one'],
        // Use keyword search as primary for this asset (CPE matching is unreliable)
        preferKeywordSearch: true
    },
    {
        id: 'zerto',
        name: 'Zerto',
        vendor: 'Zerto',
        category: ASSET_CATEGORIES.BACKUP_DR,
        keywords: ['zerto', 'disaster recovery', 'replication', 'dr'],
        cpeVendor: 'zerto',
        cpeProduct: 'virtual_replication'
    },

    // Security
    {
        id: 'bitdefender',
        name: 'BitDefender',
        vendor: 'BitDefender',
        category: ASSET_CATEGORIES.SECURITY,
        keywords: ['bitdefender', 'antivirus', 'endpoint', 'gravityzone'],
        cpeVendor: 'bitdefender',
        cpeProduct: 'gravityzone'
    },

    // Collaboration
    {
        id: 'microsoft-teams',
        name: 'Microsoft Teams',
        vendor: 'Microsoft',
        category: ASSET_CATEGORIES.COLLABORATION,
        keywords: ['microsoft', 'teams', 'office 365', 'm365'],
        cpeVendor: 'microsoft',
        cpeProduct: 'teams'
    },
    {
        id: 'zoom',
        name: 'Zoom Video Conferencing',
        vendor: 'Zoom Video Communications',
        category: ASSET_CATEGORIES.COLLABORATION,
        keywords: ['zoom video communications', 'zoom meetings', 'zoom client'],
        cpeVendor: 'zoom',
        cpeProduct: 'meetings'
    },

    // Browsers
    {
        id: 'google-chrome',
        name: 'Google Chrome',
        vendor: 'Google',
        category: ASSET_CATEGORIES.BROWSERS,
        keywords: ['google', 'chrome', 'chromium', 'browser'],
        cpeVendor: 'google',
        cpeProduct: 'chrome'
    },
    {
        id: 'microsoft-edge',
        name: 'Microsoft Edge',
        vendor: 'Microsoft',
        category: ASSET_CATEGORIES.BROWSERS,
        keywords: ['microsoft edge browser', 'edge chromium'],
        cpeVendor: 'microsoft',
        cpeProduct: 'edge_chromium'
    },
    {
        id: 'firefox',
        name: 'Firefox',
        vendor: 'Mozilla',
        category: ASSET_CATEGORIES.BROWSERS,
        keywords: ['mozilla', 'firefox', 'browser'],
        cpeVendor: 'mozilla',
        cpeProduct: 'firefox'
    },

    // AV & Control
    {
        id: 'crestron',
        name: 'Crestron Electronics',
        vendor: 'Crestron',
        category: ASSET_CATEGORIES.AV_CONTROL,
        keywords: ['crestron', 'av', 'control', 'automation', 'touch panel'],
        cpeVendor: 'crestron',
        cpeProduct: 'crestron'
    },

    // Microsoft Operating Systems
    {
        id: 'windows-10',
        name: 'Windows 10',
        vendor: 'Microsoft',
        category: ASSET_CATEGORIES.MICROSOFT_OS,
        keywords: ['windows 10', 'win10'],
        cpeVendor: 'microsoft',
        cpeProduct: 'windows_10'
    },
    {
        id: 'windows-11',
        name: 'Windows 11',
        vendor: 'Microsoft',
        category: ASSET_CATEGORIES.MICROSOFT_OS,
        keywords: ['windows 11', 'win11'],
        cpeVendor: 'microsoft',
        cpeProduct: 'windows_11'
    },

    // Microsoft Server Products
    {
        id: 'windows-server-2012',
        name: 'Windows Server 2012',
        vendor: 'Microsoft',
        category: ASSET_CATEGORIES.MICROSOFT_SERVER,
        keywords: ['windows server 2012'],
        cpeVendor: 'microsoft',
        cpeProduct: 'windows_server_2012'
    },
    {
        id: 'windows-server-2016',
        name: 'Windows Server 2016',
        vendor: 'Microsoft',
        category: ASSET_CATEGORIES.MICROSOFT_SERVER,
        keywords: ['windows server 2016'],
        cpeVendor: 'microsoft',
        cpeProduct: 'windows_server_2016'
    },
    {
        id: 'windows-server-2019',
        name: 'Windows Server 2019',
        vendor: 'Microsoft',
        category: ASSET_CATEGORIES.MICROSOFT_SERVER,
        keywords: ['windows server 2019'],
        cpeVendor: 'microsoft',
        cpeProduct: 'windows_server_2019'
    },
    {
        id: 'windows-server-2022',
        name: 'Windows Server 2022',
        vendor: 'Microsoft',
        category: ASSET_CATEGORIES.MICROSOFT_SERVER,
        keywords: ['windows server 2022'],
        cpeVendor: 'microsoft',
        cpeProduct: 'windows_server_2022'
    },
    {
        id: 'microsoft-exchange',
        name: 'Microsoft Exchange Server',
        vendor: 'Microsoft',
        category: ASSET_CATEGORIES.MICROSOFT_SERVER,
        keywords: ['microsoft exchange', 'exchange server'],
        cpeVendor: 'microsoft',
        cpeProduct: 'exchange_server'
    },
    {
        id: 'microsoft-sharepoint',
        name: 'Microsoft SharePoint',
        vendor: 'Microsoft',
        category: ASSET_CATEGORIES.MICROSOFT_SERVER,
        keywords: ['microsoft sharepoint', 'sharepoint server'],
        cpeVendor: 'microsoft',
        cpeProduct: 'sharepoint_server'
    },
    {
        id: 'microsoft-sql-server',
        name: 'Microsoft SQL Server',
        vendor: 'Microsoft',
        category: ASSET_CATEGORIES.DATABASE,
        keywords: ['microsoft sql server', 'mssql'],
        cpeVendor: 'microsoft',
        cpeProduct: 'sql_server'
    },

    // Microsoft Applications
    {
        id: 'microsoft-office-365',
        name: 'Microsoft Office 365',
        vendor: 'Microsoft',
        category: ASSET_CATEGORIES.MICROSOFT_APPS,
        keywords: ['office 365', 'microsoft 365', 'm365'],
        cpeVendor: 'microsoft',
        cpeProduct: '365_apps'
    },

    // Microsoft Development Tools
    {
        id: 'microsoft-visual-studio',
        name: 'Microsoft Visual Studio',
        vendor: 'Microsoft',
        category: ASSET_CATEGORIES.MICROSOFT_DEV,
        keywords: ['visual studio', 'vs2019', 'vs2022'],
        cpeVendor: 'microsoft',
        cpeProduct: 'visual_studio'
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

export default ASSETS;
