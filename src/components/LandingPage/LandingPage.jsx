import React, { useEffect, useRef } from 'react';
import {
    Shield,
    Activity,
    Link2,
    Cloud,
    ArrowRight,
    Terminal,
    Eye,
    Zap,
    Lock,
    Globe,
    ChevronDown,
    MonitorCheck,
    Server,
    AlertTriangle
} from 'lucide-react';
import './LandingPage.css';

const LandingPage = ({ onEnterApp, onSignIn }) => {
    const canvasRef = useRef(null);

    // Animated matrix/grid background
    useEffect(() => {
        const canvas = canvasRef.current;
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        let animationId;
        let particles = [];

        const resize = () => {
            canvas.width = window.innerWidth;
            canvas.height = window.innerHeight;
        };
        resize();
        window.addEventListener('resize', resize);

        // Create grid nodes
        const initParticles = () => {
            particles = [];
            const spacing = 60;
            for (let x = 0; x < canvas.width + spacing; x += spacing) {
                for (let y = 0; y < canvas.height + spacing; y += spacing) {
                    particles.push({
                        x: x + (Math.random() - 0.5) * 20,
                        y: y + (Math.random() - 0.5) * 20,
                        baseX: x,
                        baseY: y,
                        vx: (Math.random() - 0.5) * 0.3,
                        vy: (Math.random() - 0.5) * 0.3,
                        size: Math.random() * 1.5 + 0.5,
                        pulse: Math.random() * Math.PI * 2,
                    });
                }
            }
        };
        initParticles();

        const draw = () => {
            ctx.clearRect(0, 0, canvas.width, canvas.height);

            // Draw connections
            for (let i = 0; i < particles.length; i++) {
                for (let j = i + 1; j < particles.length; j++) {
                    const dx = particles[i].x - particles[j].x;
                    const dy = particles[i].y - particles[j].y;
                    const dist = Math.sqrt(dx * dx + dy * dy);
                    if (dist < 80) {
                        const alpha = (1 - dist / 80) * 0.08;
                        ctx.beginPath();
                        ctx.strokeStyle = `rgba(99, 102, 241, ${alpha})`;
                        ctx.lineWidth = 0.5;
                        ctx.moveTo(particles[i].x, particles[i].y);
                        ctx.lineTo(particles[j].x, particles[j].y);
                        ctx.stroke();
                    }
                }
            }

            // Draw and update particles
            particles.forEach(p => {
                p.pulse += 0.02;
                p.x += p.vx;
                p.y += p.vy;

                // Gentle drift back to base position
                p.x += (p.baseX - p.x) * 0.005;
                p.y += (p.baseY - p.y) * 0.005;

                const alpha = 0.2 + Math.sin(p.pulse) * 0.15;
                ctx.beginPath();
                ctx.fillStyle = `rgba(99, 102, 241, ${alpha})`;
                ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
                ctx.fill();
            });

            animationId = requestAnimationFrame(draw);
        };
        draw();

        return () => {
            cancelAnimationFrame(animationId);
            window.removeEventListener('resize', resize);
        };
    }, []);

    return (
        <div className="landing">
            <canvas ref={canvasRef} className="landing-bg-canvas" />

            {/* Gradient overlays */}
            <div className="landing-bg-gradient" />
            <div className="landing-bg-glow" />

            {/* Navigation */}
            <nav className="landing-nav">
                <div className="landing-nav-inner">
                    <div className="landing-nav-brand">
                        <img
                            src={`${import.meta.env.BASE_URL}panoptes-logo.png`}
                            alt="Panoptes"
                            className="landing-nav-logo"
                        />
                        <span className="landing-nav-name">PANOPTES</span>
                    </div>
                    <div className="landing-nav-links">
                        <a href="#features" className="landing-nav-link">Features</a>
                        <a href="#killchain" className="landing-nav-link">Kill Chain</a>
                        <a href="#monitoring" className="landing-nav-link">Monitoring</a>
                        <button className="landing-nav-signin" onClick={onSignIn}>
                            Sign In
                        </button>
                        <button className="landing-nav-cta" onClick={onEnterApp}>
                            Launch App
                            <ArrowRight size={16} />
                        </button>
                    </div>
                </div>
            </nav>

            {/* Hero Section */}
            <section className="landing-hero">
                <div className="landing-hero-content">
                    <div className="landing-hero-badge">
                        <Terminal size={14} />
                        <span>Real-time threat intelligence from the NVD</span>
                    </div>
                    <h1 className="landing-hero-title">
                        See Every Threat.<br />
                        <span className="landing-hero-accent">Before It Sees You.</span>
                    </h1>
                    <p className="landing-hero-sub">
                        Panoptes aggregates vulnerabilities across your entire infrastructure, 
	                from firewalls to cloud platforms, and maps them to real-world
                        attack chains so you know exactly what to patch first.
                    </p>
                    <div className="landing-hero-actions">
                        <button className="landing-btn-primary" onClick={onEnterApp}>
                            <Eye size={18} />
                            Enter Dashboard
                        </button>
                        <button className="landing-btn-ghost" onClick={onSignIn}>
                            Create Account
                            <ArrowRight size={16} />
                        </button>
                    </div>
                    <div className="landing-hero-stats">
                        <div className="landing-hero-stat">
                            <span className="landing-hero-stat-value">24+</span>
                            <span className="landing-hero-stat-label">Monitored Assets</span>
                        </div>
                        <div className="landing-hero-stat-divider" />
                        <div className="landing-hero-stat">
                            <span className="landing-hero-stat-value">Live</span>
                            <span className="landing-hero-stat-label">NVD API Feed</span>
                        </div>
                        <div className="landing-hero-stat-divider" />
                        <div className="landing-hero-stat">
                            <span className="landing-hero-stat-value">ATT&CK</span>
                            <span className="landing-hero-stat-label">Kill Chain Mapping</span>
                        </div>
                    </div>
                </div>

                {/* Animated terminal preview */}
                <div className="landing-hero-visual">
                    <div className="landing-terminal">
                        <div className="landing-terminal-bar">
                            <div className="landing-terminal-dots">
                                <span className="dot red" />
                                <span className="dot yellow" />
                                <span className="dot green" />
                            </div>
                            <span className="landing-terminal-title">panoptes@threat-intel ~</span>
                        </div>
                        <div className="landing-terminal-body">
                            <TerminalLine delay={0} prompt="$" text="panoptes scan --assets all --time 30d" />
                            <TerminalLine delay={1} prompt="" text="" />
                            <TerminalLine delay={1.2} prompt="[SCAN]" text="Querying NVD for 24 assets..." color="var(--accent-primary)" />
                            <TerminalLine delay={2} prompt="[CVE]" text="CVE-2025-21590 Juniper Junos OS — CRITICAL 9.8" color="var(--severity-critical)" />
                            <TerminalLine delay={2.5} prompt="[CVE]" text="CVE-2025-0283 Ivanti Connect — HIGH 7.0" color="var(--severity-high)" />
                            <TerminalLine delay={3} prompt="[CVE]" text="CVE-2025-24472 Fortinet FortiOS — CRITICAL 9.8" color="var(--severity-critical)" />
                            <TerminalLine delay={3.5} prompt="[CHAIN]" text="Kill chain detected: 3 stages, score 78/100" color="var(--status-warning)" />
                            <TerminalLine delay={4} prompt="[PATCH]" text="Priority: CVE-2025-24472 — blocks 6 attack chains" color="var(--status-success)" />
                            <TerminalLine delay={4.5} prompt="" text="" />
                            <TerminalLine delay={5} prompt="$" text="█" blink />
                        </div>
                    </div>
                </div>

                <a href="#features" className="landing-scroll-hint">
                    <ChevronDown size={20} />
                </a>
            </section>

            {/* Features Section */}
            <section id="features" className="landing-section">
                <div className="landing-section-inner">
                    <div className="landing-section-header">
                        <span className="landing-section-tag">
                            <Zap size={14} />
                            Core Capabilities
                        </span>
                        <h2 className="landing-section-title">
                            Everything You Need to<br />
                            <span className="landing-hero-accent">Stay Ahead of Threats</span>
                        </h2>
                        <p className="landing-section-sub">
                            Three integrated modules that transform raw CVE data into actionable security intelligence.
                        </p>
                    </div>

                    <div className="landing-features-grid">
                        <div className="landing-feature-card feature-highlight">
                            <div className="landing-feature-icon">
                                <Shield size={24} />
                            </div>
                            <h3>Asset Vulnerability Monitoring</h3>
                            <p>
                                Track CVEs across 24+ enterprise assets from Cisco, Microsoft,
                                Fortinet, Palo Alto, and more. Every vulnerability is sourced
                                directly from the National Vulnerability Database with CVSS scoring
                                and EPSS exploit probability.
                            </p>
                            <div className="landing-feature-tags">
                                <span className="landing-tag">Real-time NVD</span>
                                <span className="landing-tag">CVSS Scoring</span>
                                <span className="landing-tag">EPSS Data</span>
                                <span className="landing-tag">CISA KEV</span>
                            </div>
                        </div>

                        <div className="landing-feature-card">
                            <div className="landing-feature-icon icon-cloud">
                                <Cloud size={24} />
                            </div>
                            <h3>Cloud Infrastructure Monitoring</h3>
                            <p>
                                Monitor AWS, Azure, and Google Cloud for vulnerabilities.
                                Filter by your deployed regions and services. Understand
                                your cloud attack surface alongside on-prem infrastructure.
                            </p>
                            <div className="landing-feature-tags">
                                <span className="landing-tag">AWS</span>
                                <span className="landing-tag">Azure</span>
                                <span className="landing-tag">GCP</span>
                                <span className="landing-tag">Region Filtering</span>
                            </div>
                        </div>

                        <div className="landing-feature-card">
                            <div className="landing-feature-icon icon-chain">
                                <Link2 size={24} />
                            </div>
                            <h3>Kill Chain Analysis</h3>
                            <p>
                                Automatically maps vulnerabilities to MITRE ATT&CK stages
                                and synthesizes multi-step attack chains. Identifies which
                                single patch would disrupt the most attack paths.
                            </p>
                            <div className="landing-feature-tags">
                                <span className="landing-tag">MITRE ATT&CK</span>
                                <span className="landing-tag">Attack Chains</span>
                                <span className="landing-tag">Patch Priority</span>
                            </div>
                        </div>
                    </div>
                </div>
            </section>

            {/* Kill Chain Deep Dive */}
            <section id="killchain" className="landing-section landing-section-dark">
                <div className="landing-section-inner">
                    <div className="landing-section-header">
                        <span className="landing-section-tag tag-red">
                            <AlertTriangle size={14} />
                            Attack Path Intelligence
                        </span>
                        <h2 className="landing-section-title">
                            Map the Kill Chain.<br />
                            <span className="landing-hero-accent">Break It.</span>
                        </h2>
                        <p className="landing-section-sub">
                            Panoptes doesn't just list CVEs. It shows how vulnerabilities
                            chain together into real attack paths and tells you exactly
                            where to cut.
                        </p>
                    </div>

                    <div className="landing-killchain-visual">
                        <div className="landing-chain-stages">
                            {[
                                { name: 'Initial Access', icon: Globe, color: '#ef4444', example: 'FortiOS RCE' },
                                { name: 'Execution', icon: Terminal, color: '#f97316', example: 'SolarWinds Cmd Injection' },
                                { name: 'Privilege Escalation', icon: Zap, color: '#eab308', example: 'Windows Kernel' },
                                { name: 'Lateral Movement', icon: ArrowRight, color: '#22c55e', example: 'Cisco IOS XE' },
                                { name: 'Impact', icon: AlertTriangle, color: '#ef4444', example: 'Exchange Data Exfil' },
                            ].map((stage, i) => (
                                <div key={stage.name} className="landing-chain-stage" style={{ animationDelay: `${i * 0.15}s` }}>
                                    <div className="landing-chain-stage-icon" style={{ borderColor: stage.color, color: stage.color }}>
                                        <stage.icon size={18} />
                                    </div>
                                    <div className="landing-chain-stage-info">
                                        <span className="landing-chain-stage-name">{stage.name}</span>
                                        <span className="landing-chain-stage-example">{stage.example}</span>
                                    </div>
                                    {i < 4 && <div className="landing-chain-connector" />}
                                </div>
                            ))}
                        </div>
                        <div className="landing-chain-insight">
                            <div className="landing-chain-insight-card">
                                <Lock size={20} />
                                <div>
                                    <strong>Break the Chain</strong>
                                    <p>Patch CVE-2025-24472 to disrupt 6 attack paths at once. One fix, maximum impact.</p>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </section>

            {/* Monitoring Dashboard Preview */}
            <section id="monitoring" className="landing-section">
                <div className="landing-section-inner">
                    <div className="landing-section-header">
                        <span className="landing-section-tag">
                            <MonitorCheck size={14} />
                            Unified Visibility
                        </span>
                        <h2 className="landing-section-title">
                            Your Entire Attack Surface.<br />
                            <span className="landing-hero-accent">One Dashboard.</span>
                        </h2>
                        <p className="landing-section-sub">
                            From Cisco routers to Azure cloud services, every vulnerability
                            is aggregated, scored, and prioritized in a single view.
                        </p>
                    </div>

                    <div className="landing-vendors-grid">
                        {[
                            { name: 'Cisco', cat: 'Network' },
                            { name: 'Microsoft', cat: 'Enterprise' },
                            { name: 'Fortinet', cat: 'Security' },
                            { name: 'Palo Alto', cat: 'Firewall' },
                            { name: 'AWS', cat: 'Cloud' },
                            { name: 'Azure', cat: 'Cloud' },
                            { name: 'Juniper', cat: 'Network' },
                            { name: 'SolarWinds', cat: 'IT Mgmt' },
                            { name: 'VMware', cat: 'Compute' },
                            { name: 'Docker', cat: 'Containers' },
                            { name: 'Ubuntu', cat: 'Linux' },
                            { name: 'RHEL', cat: 'Linux' },
                        ].map(v => (
                            <div key={v.name} className="landing-vendor-pill">
                                <Server size={14} />
                                <span className="landing-vendor-name">{v.name}</span>
                                <span className="landing-vendor-cat">{v.cat}</span>
                            </div>
                        ))}
                    </div>

                    <div className="landing-dashboard-mock">
                        <div className="landing-mock-header">
                            <div className="landing-mock-stat">
                                <span className="mock-value critical">12</span>
                                <span className="mock-label">Critical</span>
                            </div>
                            <div className="landing-mock-stat">
                                <span className="mock-value high">28</span>
                                <span className="mock-label">High</span>
                            </div>
                            <div className="landing-mock-stat">
                                <span className="mock-value medium">45</span>
                                <span className="mock-label">Medium</span>
                            </div>
                            <div className="landing-mock-stat">
                                <span className="mock-value low">67</span>
                                <span className="mock-label">Low</span>
                            </div>
                        </div>
                        <div className="landing-mock-bars">
                            {[85, 62, 45, 78, 30, 55].map((w, i) => (
                                <div key={i} className="landing-mock-bar-row">
                                    <div className="landing-mock-bar" style={{ width: `${w}%`, animationDelay: `${i * 0.1}s` }} />
                                </div>
                            ))}
                        </div>
                    </div>
                </div>
            </section>

            {/* CTA Section */}
            <section className="landing-section landing-cta-section">
                <div className="landing-section-inner">
                    <div className="landing-cta-glow" />
                    <div className="landing-cta-content">
                        <h2 className="landing-cta-title">
                            Ready to See What's Lurking<br />in Your Infrastructure?
                        </h2>
                        <p className="landing-cta-sub">
                            Free to use. No credit card required. Powered by live NVD data.
                        </p>
                        <div className="landing-hero-actions" style={{ justifyContent: 'center' }}>
                            <button className="landing-btn-primary large" onClick={onEnterApp}>
                                <Eye size={20} />
                                Launch Panoptes
                            </button>
                            <button className="landing-btn-ghost" onClick={onSignIn}>
                                Sign Up Free
                                <ArrowRight size={16} />
                            </button>
                        </div>
                    </div>
                </div>
            </section>

            {/* Footer */}
            <footer className="landing-footer">
                <div className="landing-footer-inner">
                    <div className="landing-footer-brand">
                        <img
                            src={`${import.meta.env.BASE_URL}panoptes-logo.png`}
                            alt="Panoptes"
                            className="landing-footer-logo"
                        />
                        <span>PANOPTES</span>
                    </div>
                    <p className="landing-footer-text">
                        Vulnerability intelligence powered by the National Vulnerability Database.
                    </p>
                    <p className="landing-footer-copy">
                        &copy; {new Date().getFullYear()} Panoptes. All rights reserved.
                    </p>
                </div>
            </footer>
        </div>
    );
};

// Animated terminal line component
const TerminalLine = ({ delay, prompt, text, color, blink }) => (
    <div
        className={`landing-terminal-line ${blink ? 'blink' : ''}`}
        style={{ animationDelay: `${delay}s`, color: color || 'var(--text-secondary)' }}
    >
        {prompt && <span className="landing-terminal-prompt" style={{ color: color || 'var(--accent-primary)' }}>{prompt}</span>}
        <span className="landing-terminal-text">{text}</span>
    </div>
);

export default LandingPage;
