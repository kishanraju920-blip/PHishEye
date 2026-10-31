Core Features & Architecture
1.
 Multi-Layer Detection Pipeline

Layer1: Tranco Whitelist & Threat Feeds: Instant checks against verified legitimate domains (Tranco top sites) and live blacklists (PhishTank, URLhaus).  

Layer 2: 3-Factor Correlation Matrix (Zero-Day Invariant Engine): Correlates lexical features, domain age (WHOIS/RDAP lookup), TLS certificate validity, and behavioral heuristics to flag zero-day phishing pages before they appear on public blacklists.

2.
 Advanced Computer Vision & Brand Impersonation DetectorpHash Visual Matching: Computes 64-bit Perceptual Hashes (pHash) using 2D Discrete Cosine Transform (DCT) on favicons and page logos to detect visual spoofing of major brands (e.g., Microsoft, Google, PayPal, Apple, banking portals).
Hotlink Detection: Flags unauthorized domains hotlinking official assets or CDNs belonging to protected brands.   3.
 Live NLP & Intent ForensicsScans page text samples and titles for social engineering triggers (e.g., fake account suspension coercion, crypto wallet drainer seed-phrase prompts, unauthorized Mod APK distribution lures). 
4.
 Sandbox & DOM Signal AnalysisSafely crawls target URLs with strict SSRF guards and Content Security Policies, extracting forms, credential input fields, and exfiltration webhooks.  
5.
 Download Safety InspectorPerforms secure payload inspection (size and time-limited downloads), validates magic byte signatures, checks archive contents for hidden executables, and cross-references file hashes against VirusTotal.  

Tech Stack & DependenciesFramework: FastAPI (Python) with CORS middleware enabled.   
Machine Learning: xgboost (XGBClassifier) for multi-feature lexical and structural classification.   
Data Processing & Numerical Computing: numpy, scipy (DCT transform for perceptual hashing), scikit-learn.   Database: Lightweight embedded sqlite3 for local caching of WHOIS data, TLS records, feedback reporting, and threat intelligence entries.   
Networking & Security: requests, python-whois, Pillow (PIL), and nh3 (HTML sanitization).   Environment VariablesThe application behavior can be tuned using the following environment variables:REPORT_THRESHOLD: Minimum feedback report threshold (default: 3).   

USE_URLHAUS_LIVE: Enable or disable live URLhaus API lookups (1 or 0, default: 1).   
VT_API_KEY: VirusTotal API Key for enhanced file hash reputation checking.  
API Endpoints OverviewPOST /analyze / POST /scan: Main URL analysis endpoint returning threat scores, confidence levels, verdict badges, lexical features, and detection layers.   
POST /report: Community feedback submission endpoint for reporting safe or phishing URLs to improve model training.   
POST /sandbox: Secure preview crawler that isolates payloads and inspects brand impersonation markers.   
POST /scan-download: Deep file inspection endpoint analyzing file extensions, magic signatures, archive contents, and antivirus reputation.   
GET /health: Health check endpoint returning model feature dimensions and configuration status.   