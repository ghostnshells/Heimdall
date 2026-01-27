// Asset definitions for server-side vulnerability fetching
// Mirrors the frontend assets.js for consistency
// Consolidated structure: One card per major vendor (Cisco, Microsoft, HPE) with sub-products

export const ASSETS = [
    // ==========================================
    // CISCO - Consolidated vendor card
    // Monitors: IOS, IOS XE, IOS XR, ISE, Unified CM (software only - hardware rarely has CVEs)
    // ==========================================
    {
        id: 'cisco',
        name: 'Cisco',
        vendor: 'Cisco',
        cpeVendor: 'cisco',
        cpeProducts: [
            'ios',
            'ios_xe',
            'ios_xr',
            'identity_services_engine',
            'unified_communications_manager'
        ],
        // First keyword is used for primary search - 'cisco' catches all Cisco vulns
        // including those without CPE data yet; validators filter out false positives
        keywords: [
            'cisco',
            'cisco ios',
            'cisco ios xe',
            'cisco ios xr',
            'cisco ise',
            'cisco identity services engine',
            'cisco unified communications manager',
            'cisco unified cm',
            'cisco cucm'
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
        cpeVendor: 'microsoft',
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
        cpeVendor: 'hpe',
        additionalCpeVendors: ['hp', 'hewlett_packard_enterprise'],
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
        keywords: [
            'hpe proliant',
            'hpe nimble',
            'hpe alletra',
            'hewlett packard enterprise',
            'hpe ilo',
            'integrated lights-out',
            'hpe oneview',
            'hpe storeonce'
        ]
    },

    // ==========================================
    // WatchGuard - Firewall & VPN
    // ==========================================
    {
        id: 'watchguard',
        name: 'WatchGuard',
        vendor: 'WatchGuard',
        cpeVendor: 'watchguard',
        cpeProducts: ['firebox', 'fireware', 'mobile_vpn', 'authpoint'],
        keywords: ['watchguard', 'firebox', 'fireware', 'watchguard vpn']
    },

    // ==========================================
    // Tripp Lite - Power & UPS
    // ==========================================
    {
        id: 'tripplite-ups',
        name: 'Tripp Lite UPS',
        vendor: 'Tripp Lite',
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
        cpeVendor: 'crestron',
        cpeProducts: ['crestron', 'dm', 'nvx', 'flex'],
        keywords: ['crestron', 'crestron av', 'crestron control']
    }
];

export default ASSETS;
