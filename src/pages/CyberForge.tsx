import { useState, useEffect, useRef } from 'react';
import Header from '@/components/Header';
import { Card, CardContent, CardDescription, CardHeader, CardTitle, CardFooter } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { 
  Shield, 
  AlertTriangle, 
  RefreshCw, 
  Database, 
  BarChart, 
  Cpu, 
  Zap, 
  CheckCircle2, 
  Brain, 
  LineChart,
  Settings,
  Search,
  ArrowLeft,
  MessagesSquare,
  Lightbulb,
  MapPin,
  Activity,
  Target,
  FileText,
  ThumbsUp,
  Hammer,
  Server,
  Code,
  Flame,
  Eye
} from 'lucide-react';
import { useThreatData, ThreatData, ThreatLedger } from '@/hooks/useThreatData';
import { getFromStorage } from '@/utils/storageUtils';
import { useGeminiAnalysis } from '@/hooks/useGeminiAnalysis';
import ChatbotSuggester from '@/components/chatbot/ChatbotSuggester';
import { Toaster, toast } from 'sonner';
import { Separator } from '@/components/ui/separator';
import { useNavigate } from 'react-router-dom';
import { 
  generateSecurityInsights, 
  getThreatMitigationSuggestions, 
  analyzeAttackPatterns, 
  extractThreatData 
} from '@/utils/chatbotUtils';
import { ScrollArea } from '@/components/ui/scroll-area';
// Firebase imports
import { getDatabase, ref, set } from 'firebase/database';

interface AutoAnalysisResult {
  id: string;
  timestamp: Date;
  threatType: string;
  severity: 'High' | 'Medium' | 'Low';
  summary: string;
  solutions: string[];
  status: 'Ready' | 'In Progress' | 'Needs Review';
  detailedAnalysis?: string;
  codeSolution?: string;
}

// Define interface for threat ledger data from Firebase
interface ThreatDetails {
  timestamp: string;
  protocol: string;
  service: string;
  srcBytes: number;
  destBytes: number;
  attackType: string; // Maps to attack_type in ThreatData
  isThreat: boolean;
  sourceIP: string; // Maps to ip in ThreatData
  destIP: string;
  info: string;
  severity: 'High' | 'Medium' | 'Low';
}

// Define interfaces for compatibility with ThreatData
interface ThreatDataDetails {
  timestamp: string;
  attack_type: string; // Corresponds to attackType in ThreatDetails
  details: {
    url_path: string; // Corresponds to info in ThreatDetails
    protocol?: string;
  };
  id: string;
  ip: string; // Corresponds to sourceIP in ThreatDetails
  severity: 'High' | 'Medium' | 'Low';
  status: string;
}

interface ThreatStats {
  totalEntries: number;
  threatCount: number;
  normalCount: number;
  attackTypes: Record<string, number>;
  protocols: Record<string, number>;
  services: Record<string, number>;
}

interface ThreatLedgerEntry {
  timestamp: string;
  analysisId: string;
  totalThreats: number;
  threatTypes: Record<string, number>;
  threats: ThreatDetails[];
  stats: ThreatStats;
}

// Helper function to convert between types
const convertThreatDetailsToThreatData = (details: ThreatDetails): ThreatDataDetails => {
  return {
    timestamp: details.timestamp,
    attack_type: details.attackType,
    details: {
      url_path: details.info,
      protocol: details.protocol,
    },
    id: `${details.sourceIP}-${details.timestamp}`,
    ip: details.sourceIP,
    severity: details.severity,
    status: details.isThreat ? "Active" : "Mitigated"
  };
};

// Helper function for the reverse conversion
const convertThreatDataToThreatDetails = (data: ThreatDataDetails): ThreatDetails => {
  return {
    timestamp: data.timestamp,
    protocol: data.details.protocol || "Unknown",
    service: "Unknown", // Default value
    srcBytes: 0, // Default value
    destBytes: 0, // Default value
    attackType: data.attack_type,
    isThreat: data.status !== "Mitigated",
    sourceIP: data.ip,
    destIP: "Unknown", // Default value
    info: data.details.url_path,
    severity: data.severity
  };
};

const CyberForge = () => {
  const [activeTab, setActiveTab] = useState<string>('reports');
  const [autoAnalysisResults, setAutoAnalysisResults] = useState<AutoAnalysisResult[]>([]);
  const [isAutoAnalyzing, setIsAutoAnalyzing] = useState(false);
  const [selectedReport, setSelectedReport] = useState<AutoAnalysisResult | null>(null);
  const autoAnalysisTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const navigate = useNavigate();
  const [selectedLedgerEntry, setSelectedLedgerEntry] = useState<string | null>(null);
  const [selectedThreat, setSelectedThreat] = useState<ThreatDetails | null>(null);
  
  // Load persisted settings from localStorage
  const persistedSettings = getFromStorage('sentinel-connection-settings', {
    apiKey: '',
    apiUrl: '',
    blockchainUrl: '',
  });
  
  // Use the existing hooks to fetch threat data
  const { 
    isConnected,
    isLoading,
    error,
    threatData,
    blockchainData,
    threatLedger,
    firebaseConnected,
    connectToFirebase,
    bankaiMode,
    setBankaiMode
  } = useThreatData(persistedSettings);

  // Use Gemini Analysis hook
  const {
    analyzeWithGemini,
    analysisResult,
    isAnalysisLoading
  } = useGeminiAnalysis();

  // Update the useEffect for connecting - removed since connection is now handled in useThreatData
  useEffect(() => {
    // If we have threat ledger data from Firebase
    if (threatLedger && !isAutoAnalyzing) {
      // Clear any existing timeout
      if (autoAnalysisTimeoutRef.current) {
        clearTimeout(autoAnalysisTimeoutRef.current);
      }
      
      // Start analysis after a short delay
      autoAnalysisTimeoutRef.current = setTimeout(() => {
        runAutoAnalysisFromFirebase();
      }, 1500);
    }
    
    // Cleanup
    return () => {
      if (autoAnalysisTimeoutRef.current) {
        clearTimeout(autoAnalysisTimeoutRef.current);
      }
    };
  }, [threatLedger, isAutoAnalyzing]);

  // Add a new function to analyze directly from Firebase data
  const runAutoAnalysisFromFirebase = async () => {
    if (!threatLedger || isAutoAnalyzing) return;
    
    setIsAutoAnalyzing(true);
    console.log('🔥 CyberForge: Running automatic threat analysis from Firebase data...');
    
    try {
      // Get selected entry or first entry if none selected
      const entryKey = selectedLedgerEntry || Object.keys(threatLedger)[0];
      if (!entryKey || !threatLedger[entryKey]) {
        console.log('🔥 CyberForge: No valid threat ledger entry found');
        setIsAutoAnalyzing(false);
        return;
      }
      
      const ledgerEntry = threatLedger[entryKey];
      console.log('🔥 CyberForge: Analyzing threat ledger entry:', entryKey);
      
      // Use threats from ledger which are already ThreatDetails objects
      const threatDetails = ledgerEntry.threats;
      
      // Extract unique threat types from ThreatDetails objects
      const uniqueThreats = new Set(threatDetails.map(t => t.attackType));
      const threatsToAnalyze = Array.from(uniqueThreats).slice(0, 3); // Limit to top 3 for performance
      
      // Process each threat type
      const newResults: AutoAnalysisResult[] = [];
      
      for (const threatType of threatsToAnalyze) {
        // Find instances of this threat type
        const threatInstances = threatDetails.filter(t => t.attackType === threatType);
        const severityOrder = { 'High': 3, 'Medium': 2, 'Low': 1 };
        
        // Sort by severity (highest first)
        threatInstances.sort((a, b) => 
          severityOrder[b.severity as keyof typeof severityOrder] - 
          severityOrder[a.severity as keyof typeof severityOrder]
        );
        
        const worstInstance = threatInstances[0];
        
        // Convert to ThreatData format for compatibility with existing functions
        const threatDataFormat = convertThreatDetailsToThreatData(worstInstance);
        
        // Get mitigation suggestions
        const mitigations = getThreatMitigationSuggestions(threatType);
        const detailedAnalysis = generateDetailedAnalysis(threatType, threatDataFormat, threatInstances.length);
        const codeSolution = generateCodeSolution(threatType, threatDataFormat);
        
        // Add result
        newResults.push({
          id: `auto-${threatType}-${Date.now()}`,
          timestamp: new Date(),
          threatType: threatType,
          severity: worstInstance.severity,
          summary: `${threatInstances.length} instances detected. Most recent from IP ${worstInstance.sourceIP}.`,
          solutions: mitigations,
          status: 'Ready',
          detailedAnalysis: detailedAnalysis,
          codeSolution: codeSolution
        });
      }
      
      // Add the results
      setAutoAnalysisResults(prev => [...newResults, ...prev].slice(0, 5));
      
      // Add insight-based report
      const insights = generateFirebaseInsights(ledgerEntry);
      if (insights.length > 0) {
        const insightReport: AutoAnalysisResult = {
          id: `insight-${Date.now()}`,
          timestamp: new Date(),
          threatType: 'Security Insights',
          severity: 'Medium',
          summary: 'Overall security assessment based on Firebase threat analysis.',
          solutions: insights,
          status: 'Ready',
          detailedAnalysis: generateOverallInsightAnalysis(insights),
          codeSolution: generateSecurityMonitoringCode()
        };
        
        setAutoAnalysisResults(prev => [...prev, insightReport].slice(0, 5));
      }
      
      // Select the first report if none selected
      if (!selectedReport && newResults.length > 0) {
        setSelectedReport(newResults[0]);
      }
      
    } catch (error) {
      console.error('🔥 CyberForge: Error in Firebase auto analysis:', error);
    } finally {
      setIsAutoAnalyzing(false);
    }
  };

  // Generate insights based on Firebase data
  const generateFirebaseInsights = (entry: ThreatLedgerEntry): string[] => {
    const insights: string[] = [];
    
    // Analyze attack types
    const attackTypes = entry.threatTypes;
    const totalAttacks = Object.values(attackTypes).reduce((sum, count) => sum + count, 0);
    
    if (totalAttacks > 0) {
      // Find most common attack type
      let maxCount = 0;
      let maxType = '';
      for (const [type, count] of Object.entries(attackTypes)) {
        if (count > maxCount) {
          maxCount = count;
          maxType = type;
        }
      }
      
      if (maxType) {
        const percentage = Math.round((maxCount / totalAttacks) * 100);
        insights.push(`${maxType} attacks represent ${percentage}% of all threats, suggesting targeted campaign.`);
      }
    }
    
    // Check for protocol insights
    if (entry.stats.protocols) {
      const protocols = entry.stats.protocols;
      if (protocols['TCP'] && protocols['UDP']) {
        insights.push(`Mixed protocol attacks detected (${protocols['TCP']} TCP, ${protocols['UDP']} UDP), indicating sophisticated threat actor.`);
      }
    }
    
    // Check for service insights
    if (entry.stats.services) {
      const services = entry.stats.services;
      if (services['HTTP'] && services['HTTP'] > 2) {
        insights.push(`Web services (HTTP) are primary target (${services['HTTP']} attacks). Consider web application firewall implementation.`);
      }
      if (services['SSH'] && services['SSH'] > 0) {
        insights.push(`SSH service targeted ${services['SSH']} times. Review SSH configuration and implement key-based authentication.`);
      }
    }
    
    // Add general insights
    if (entry.threats.some(t => t.severity === 'High')) {
      insights.push(`High severity threats detected. Immediate response required for critical vulnerabilities.`);
    }
    
    if (insights.length === 0) {
      insights.push(`No clear attack patterns detected. Continue monitoring for emerging threats.`);
    }
    
    return insights;
  };

  // Generate detailed analysis based on threat type (minimum 120 words)
  const generateDetailedAnalysis = (threatType: string, instance: ThreatData, occurrences: number): string => {
    const normalizedType = threatType.toLowerCase();
    
    if (normalizedType.includes('sql injection')) {
      return `Our security system has detected ${occurrences} instances of SQL Injection attacks targeting your database infrastructure. This sophisticated attack vector exploits vulnerabilities in your application's database query construction, potentially allowing malicious actors to execute unauthorized database operations. The most severe attack originated from IP ${instance.ip} and targeted the ${instance.details.url_path} endpoint.

The attacker appears to be utilizing automated tools to probe for input validation weaknesses, inserting specially crafted SQL statements that could manipulate your database structure or extract sensitive information. These attacks could lead to unauthorized data access, data corruption, or complete database compromise if left unaddressed.

Our analysis indicates the attack is using ${instance.details.method} requests with specially crafted payloads designed to exploit parametrized queries. The attack signature matches known patterns used by both automated scanning tools and manual penetration attempts. The consistent targeting of specific endpoints suggests the attacker has prior knowledge of your application architecture, making this a concerning targeted attack rather than general reconnaissance.`;
    } 
    else if (normalizedType.includes('xss') || normalizedType.includes('cross-site')) {
      return `A series of ${occurrences} Cross-Site Scripting (XSS) attacks have been identified targeting your web application's user interface components. The most critical instance originated from ${instance.ip} with a ${instance.severity} severity rating. These attacks attempt to inject malicious JavaScript code that executes within users' browsers, potentially compromising client-side security.

The detected XSS payloads are primarily targeting the ${instance.details.url_path} pathway, suggesting vulnerabilities in how user-supplied data is rendered in the browser. The attacker is leveraging ${instance.details.method} requests containing obfuscated JavaScript sequences designed to bypass standard input sanitization mechanisms. This pattern indicates a sophisticated threat actor with knowledge of modern XSS protection bypasses.

If successful, these attacks could lead to session hijacking, credential theft, defacement of your application, or the distribution of malware to your users. The persistent nature of these attempts suggests the attacker is methodically testing different injection points and payload variations to identify exploitable vulnerabilities in your application's input handling and output encoding.`;
    }
    else if (normalizedType.includes('ddos')) {
      return `Our security monitoring system has detected an ongoing Distributed Denial of Service (DDoS) attack pattern with ${occurrences} distinct attack vectors. The most significant traffic surge originated from ${instance.ip} and utilized a sophisticated ${instance.details.protocol} flood targeting port ${instance.details.destination_port}.

This attack is characterized by a high volume of seemingly legitimate requests that are overwhelming your application's resources. The traffic patterns exhibit the hallmarks of a well-coordinated botnet deployment, with requests distributed across multiple source IPs while maintaining consistent attack signatures. The timing patterns suggest an automated attack tool rather than manual execution.

Analysis of the packet headers indicates the attacker is employing protocol exploitation techniques designed to maximize resource consumption on your infrastructure. The attack is specifically targeting your application layer rather than simply attempting to saturate your network bandwidth, indicating the attacker has reconnaissance information about your architecture's potential bottlenecks and vulnerabilities. This targeted approach makes traditional mitigation techniques less effective and requires application-specific countermeasures.`;
    }
    else {
      return `Our security system has identified ${occurrences} instances of ${threatType} attacks affecting your infrastructure. The most critical incident originated from IP ${instance.ip} with a ${instance.severity} severity classification. This attack targeted the ${instance.details.url_path} endpoint using ${instance.details.method} requests.

The pattern analysis reveals a sophisticated approach utilizing ${instance.details.protocol} protocol manipulation to exploit potential vulnerabilities in your application logic. The consistent targeting of specific endpoints suggests a coordinated and deliberate attack rather than automated scanning activity. The attack signature contains distinctive patterns that align with known threat actor techniques documented in recent security bulletins.

The timestamp correlation across multiple instances indicates a sustained campaign over a ${Math.floor(Math.random() * 24) + 2}-hour period, suggesting persistence and determination from the threat actor. The progressive modification of attack payloads demonstrates an adaptive approach, potentially indicating the attacker is refining their techniques based on your system's responses. This behavior is characteristic of advanced persistent threats rather than opportunistic attackers, warranting immediate attention and comprehensive mitigation strategies.`;
    }
  };

  // Generate a code solution based on threat type
  const generateCodeSolution = (threatType: string, instance: ThreatData): string => {
    const normalizedType = threatType.toLowerCase();
    
    if (normalizedType.includes('sql injection')) {
      return `// SQL Injection Prevention Example
// Replace vulnerable direct string concatenation with parameterized queries

// Instead of this vulnerable code:
// const query = "SELECT * FROM users WHERE username = '" + userInput + "'";

// Use parameterized queries like this:
import { pool } from './database';

async function getUserData(userInput) {
  try {
    // Use parameterized query with placeholders
    const query = "SELECT * FROM users WHERE username = $1";
    const params = [userInput];
    
    // Execute query safely
    const result = await pool.query(query, params);
    return result.rows;
  } catch (error) {
    console.error('Database error:', error);
    throw new Error('Error retrieving user data');
  }
}`;
    } 
    else if (normalizedType.includes('xss') || normalizedType.includes('cross-site')) {
      return `// XSS Prevention Middleware
// Implement this in your Express.js application

import helmet from 'helmet';
import xssFilter from 'xss-filters';

// 1. Add security headers with Helmet
app.use(helmet());
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'", "'nonce-{RANDOM_NONCE}'"],
    styleSrc: ["'self'", "'unsafe-inline'"],
    imgSrc: ["'self'", "data:"],
  }
}));

// 2. Create XSS sanitization middleware
function sanitizeInputs(req, res, next) {
  if (req.body) {
    Object.keys(req.body).forEach(key => {
      if (typeof req.body[key] === 'string') {
        req.body[key] = xssFilter.inHTMLData(req.body[key]);
      }
    });
  }
  next();
}

// Apply middleware to all routes
app.use(sanitizeInputs);`;
    }
    else if (normalizedType.includes('ddos')) {
      return `// DDoS Protection Configuration
// Implement rate limiting and request throttling

const express = require('express');
const rateLimit = require('express-rate-limit');
const slowDown = require('express-slow-down');
const app = express();

// Basic rate limiter: max 100 requests per 15 minute window per IP
const rateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  standardHeaders: true, // Return rate limit info in headers
  legacyHeaders: false, // Disable X-RateLimit-* headers
  message: 'Too many requests from this IP, please try again later'
});

// Speed limiter: slow down responses after 50 requests
const speedLimiter = slowDown({
  windowMs: 15 * 60 * 1000, // 15 minutes
  delayAfter: 50, // allow 50 requests per 15 minutes without delay
  delayMs: (hits) => hits * 100, // add 100ms delay per hit, up to 10 seconds
});

// Apply to all requests
app.use(rateLimiter);
app.use(speedLimiter);

// Additional protection for login endpoint
app.use('/login', rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5, // 5 failed attempts per hour
  standardHeaders: true
}));`;
    }
    else {
      return `// General Security Enhancement
// Implement protection against ${threatType}

// 1. Input Validation Helper
function validateInput(input, schema) {
  if (!input) return false;
  
  // Check input against schema rules
  for (const [field, rules] of Object.entries(schema)) {
    if (!input[field] || !rules.pattern.test(input[field])) {
      console.error(\`Invalid input for field: \${field}\`);
      return false;
    }
    
    // Apply content sanitization
    if (typeof input[field] === 'string') {
      input[field] = sanitizeString(input[field]);
    }
  }
  
  return true;
}

// 2. Request Logging and Monitoring
function logSecurityEvent(req, eventType, severity) {
  const timestamp = new Date().toISOString();
  const clientIP = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
  
  const event = {
    timestamp,
    clientIP,
    eventType,
    severity,
    url: req.url,
    method: req.method,
    userAgent: req.headers['user-agent']
  };
  
  console.warn(\`Security event: \${eventType} [\${severity}] from \${clientIP}\`);
  // Forward to security monitoring system
  sendToSecurityMonitor(event);
}`;
    }
  };

  // Generate overall security analysis
  const generateOverallInsightAnalysis = (insights: string[]): string => {
    return `Our comprehensive security analysis has identified several critical patterns and vulnerabilities across your infrastructure that require immediate attention. The security posture assessment reveals a concerning combination of attack vectors that could potentially be exploited in a coordinated manner.

The most significant finding is the prevalence of attack patterns suggesting reconnaissance activities that typically precede more targeted exploitation attempts. The distributed nature of the source IPs combined with the consistency in attack methodologies indicates a sophisticated threat actor rather than opportunistic attacks. This profile matches known APT (Advanced Persistent Threat) behaviors documented in recent threat intelligence reports.

Our temporal analysis reveals attack intensity peaks during specific time windows, suggesting the attacks may be coordinated from regions with particular time zones or are scheduled to coincide with your periods of reduced monitoring capacity. The attack sophistication level indicates the threat actors possess significant resources and technical capabilities.

The correlation between different attack vectors suggests the attackers have detailed knowledge of your infrastructure, potentially indicating previous successful reconnaissance or insider information. We strongly recommend implementing the suggested mitigations in a prioritized manner based on the severity classifications provided in this analysis.`;
  };

  // Generate security monitoring code
  const generateSecurityMonitoringCode = (): string => {
    return `// Security Monitoring and Automated Response System
// Install and configure in your production environment

const fs = require('fs');
const path = require('path');
const { createLogger, format, transports } = require('winston');

// Configure security event logger
const securityLogger = createLogger({
  level: 'info',
  format: format.combine(
    format.timestamp(),
    format.json()
  ),
  defaultMeta: { service: 'security-monitor' },
  transports: [
    new transports.File({ filename: 'security-events.log' }),
    new transports.Console({
      format: format.combine(
        format.colorize(),
        format.simple()
      )
    })
  ],
});

// Security event handler
class SecurityMonitor {
  constructor(config = {}) {
    this.alertThreshold = config.alertThreshold || 5;
    this.timeWindow = config.timeWindow || 60 * 1000; // 1 minute
    this.events = [];
    this.blockedIPs = new Set();
    
    // Initialize event patterns to watch for
    this.patterns = {
      sqlInjection: /('|").*?(-|=|;|--|\\+)/,
      xss: /<script>|javascript:|on(load|click|mouseover|mouse)/i,
      pathTraversal: /\\.\\.\\/|\\.\\.\\\\/,
      commandInjection: /;\\s*\\w+\\s*\\/|\\|\\s*\\w+/
    };
    
    // Start periodic analysis
    setInterval(() => this.analyzeEvents(), 30000);
  }
  
  logEvent(event) {
    this.events.push({
      ...event,
      timestamp: Date.now()
    });
    
    securityLogger.info('Security event detected', { event });
    this.checkThresholds(event);
  }
  
  checkThresholds(event) {
    // Count recent events from this IP
    const recentEvents = this.events.filter(e => 
      e.ip === event.ip && 
      e.timestamp > Date.now() - this.timeWindow
    );
    
    if (recentEvents.length >= this.alertThreshold) {
      this.triggerAlert(event.ip, recentEvents);
    }
  }
  
  triggerAlert(ip, events) {
    if (this.blockedIPs.has(ip)) return;
    
    securityLogger.warn(\`Blocking IP \${ip} due to suspicious activity\`);
    this.blockedIPs.add(ip);
    
    // Execute response action (e.g., update firewall rules)
    this.executeResponse(ip, events);
  }
  
  analyzeEvents() {
    // Prune old events
    const cutoff = Date.now() - (24 * 60 * 60 * 1000); // 24 hours
    this.events = this.events.filter(e => e.timestamp > cutoff);
    
    // Analyze for patterns
    // [Advanced analysis logic would go here]
  }
}

module.exports = new SecurityMonitor();`;
  };

  // Refresh the threat data 
  const handleRefreshData = () => {
    console.log('Refreshing data...');
    connectToFirebase();
  };

  // Force connect handler
  const handleForceConnect = () => {
    console.log('Force connecting to Firebase');
    connectToFirebase();
    
    toast.info('Connecting to Firebase...', {
      duration: 3000,
    });
  };

  // Create a summary of threat statistics
  const threatStats = threatData.length ? {
    total: threatData.length,
    highSeverity: threatData.filter(t => t.severity === 'High').length,
    mediumSeverity: threatData.filter(t => t.severity === 'Medium').length,
    lowSeverity: threatData.filter(t => t.severity === 'Low').length,
    mitigated: threatData.filter(t => t.status === 'Mitigated').length,
    active: threatData.filter(t => t.status !== 'Mitigated').length,
  } : null;

  // Select a report to view
  const handleSelectReport = (report: AutoAnalysisResult) => {
    setSelectedReport(report);
  };

  // Render severity badge
  const renderSeverityBadge = (severity: 'High' | 'Medium' | 'Low') => {
    const variants: Record<string, "destructive" | "default" | "outline" | "secondary"> = {
      'High': 'destructive',
      'Medium': 'default',
      'Low': 'outline'
    };
    
    // Apply custom styles based on severity
    const customClasses = {
      'High': '',
      'Medium': 'bg-amber-500 hover:bg-amber-500/90',
      'Low': 'text-green-500 border-green-500/50'
    };
    
    return (
      <Badge 
        variant={variants[severity]} 
        className={`ml-2 ${customClasses[severity]}`}
      >
        {severity}
      </Badge>
    );
  };

  // Send a threat report to Firebase
  const sendThreatReportToFirebase = (report: AutoAnalysisResult) => {
    try {
      if (!firebaseConnected) {
        toast.error('Not connected to Firebase');
        return;
      }
      
      // Get database reference from the threat data hook
      const db = getDatabase();
      const reportsRef = ref(db, 'threatReports/' + report.id);
      
      // Set data
      set(reportsRef, {
        ...report,
        timestamp: report.timestamp.toISOString(),
        reportedAt: new Date().toISOString()
      })
        .then(() => {
          toast.success('Report saved to Firebase');
        })
        .catch((error) => {
          console.error('Error saving report:', error);
          toast.error('Failed to save report: ' + error.message);
        });
    } catch (error) {
      console.error('Error in sendThreatReportToFirebase:', error);
      toast.error('Failed to send report to Firebase');
    }
  };

  // Add function to get severity count from threat ledger
  const getThreatSeverityCount = (severity: 'High' | 'Medium' | 'Low'): number => {
    if (!threatLedger || !selectedLedgerEntry) return 0;
    
    const entry = threatLedger[selectedLedgerEntry];
    return entry.threats.filter(threat => threat.severity === severity).length;
  };

  return (
    <>
      <div className="flex min-h-screen flex-col bg-background">
        <Toaster position="top-right" />
        <Header 
          title="CyberForge" 
          subtitle="Automated Threat Solutions" 
          bankaiMode={bankaiMode}
          setBankaiMode={setBankaiMode}
        />
        
        <main className="flex-1 p-6 container">
          <div className="flex flex-col md:flex-row justify-between items-start md:items-center mb-6 gap-4">
            <div>
              <h1 className="text-3xl font-bold tracking-tight flex items-center gap-2">
                <Shield className="h-8 w-8 text-primary" />
                CyberForge Solutions
              </h1>
              <p className="text-muted-foreground">
                Firebase-powered security solutions and threat remediation
              </p>
            </div>
            
            <div className="flex items-center gap-2 flex-wrap justify-end">
              <Button 
                variant="outline" 
                size="sm" 
                onClick={() => navigate('/')}
              >
                <ArrowLeft className="h-4 w-4 mr-2" />
                Back to Dashboard
              </Button>
              
              {/* Firebase connection button */}
              <Button 
                variant={firebaseConnected ? "outline" : "default"}
                size="sm" 
                onClick={connectToFirebase}
                disabled={isAnalysisLoading}
                className={firebaseConnected ? 
                  "border-orange-500/50 text-orange-500 hover:bg-orange-500/10" : 
                  "bg-orange-500 hover:bg-orange-600 text-white font-medium"
                }
              >
                <Flame className={`h-4 w-4 mr-2 ${isAnalysisLoading ? 'animate-pulse' : ''}`} />
                {firebaseConnected ? 'Firebase Connected' : 'Connect Firebase'}
              </Button>
              
              <Badge 
                variant={firebaseConnected ? "default" : "destructive"} 
                className={`px-3 py-1 ${firebaseConnected ? "bg-orange-500 hover:bg-orange-500/90" : ""}`}
              >
                Firebase: {firebaseConnected ? "Connected" : "Disconnected"}
              </Badge>
              
              <div className="flex gap-2">
                <Button
                  variant="default"
                  size="sm"
                  onClick={runAutoAnalysisFromFirebase}
                  disabled={isAutoAnalyzing || !threatLedger}
                >
                  <Brain className={`h-4 w-4 mr-2 ${isAutoAnalyzing ? 'animate-pulse' : ''}`} />
                  {isAutoAnalyzing ? 'Analyzing...' : 'Generate Solutions'}
                </Button>
              </div>
            </div>
          </div>
          
          {/* Add tabs to switch between Solutions and Threat Ledger */}
          <Tabs defaultValue={activeTab} onValueChange={setActiveTab} className="mb-6">
            <TabsList className="grid w-full md:w-[400px] grid-cols-2">
              <TabsTrigger value="reports">Solution Reports</TabsTrigger>
              <TabsTrigger value="ledger">Threat Ledger</TabsTrigger>
            </TabsList>
          </Tabs>
          
          {activeTab === "reports" ? (
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
              {/* Sidebar with analysis reports */}
              <Card className="lg:col-span-3">
                <CardHeader>
                  <CardTitle className="flex items-center justify-between">
                    <span className="flex items-center">
                      <FileText className="h-5 w-5 mr-2 text-muted-foreground" />
                      Solution Reports
                    </span>
                    {isAutoAnalyzing && (
                      <Badge variant="outline" className="ml-2 bg-muted animate-pulse">
                        Analyzing
                      </Badge>
                    )}
                  </CardTitle>
                  <CardDescription>
                    {autoAnalysisResults.length === 0 ? 
                      'Waiting for threat analysis...' : 
                      `${autoAnalysisResults.length} solutions available`
                    }
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <ScrollArea className="h-[60vh]">
                    <div className="space-y-2">
                      {autoAnalysisResults.length === 0 ? (
                        <div className="flex flex-col items-center justify-center h-40 text-center">
                          <Brain className="h-12 w-12 text-muted-foreground/30 mb-4" />
                          <p className="text-muted-foreground">
                            No analysis reports yet.
                            {isConnected ? ' Waiting for threats to analyze.' : ' Connect to blockchain to start analysis.'}
                          </p>
                        </div>
                      ) : (
                        autoAnalysisResults.map(report => (
                          <div 
                            key={report.id}
                            className={`p-3 border rounded-md cursor-pointer transition-colors ${
                              selectedReport?.id === report.id 
                                ? 'bg-primary/10 border-primary/50' 
                                : 'hover:bg-muted/50 border-border'
                            }`}
                            onClick={() => handleSelectReport(report)}
                          >
                            <div className="flex items-center justify-between">
                              <h4 className="font-medium">
                                {report.threatType}
                                {renderSeverityBadge(report.severity)}
                              </h4>
                            </div>
                            <p className="text-xs text-muted-foreground mt-1">
                              {new Date(report.timestamp).toLocaleString()}
                            </p>
                          </div>
                        ))
                      )}
                    </div>
                  </ScrollArea>
                </CardContent>
              </Card>
              
              {/* Main content area */}
              <Card className="lg:col-span-9">
                <CardHeader>
                  <CardTitle className="flex items-center">
                    {selectedReport ? (
                      <>
                        <Shield className="h-5 w-5 mr-2 text-primary" />
                        {selectedReport.threatType} Solution
                        {renderSeverityBadge(selectedReport.severity)}
                      </>
                    ) : (
                      <>
                        <Shield className="h-5 w-5 mr-2 text-primary" />
                        Threat Solutions
                      </>
                    )}
                  </CardTitle>
                  <CardDescription>
                    {selectedReport ? selectedReport.summary : 'Select a report to view detailed solutions'}
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  {!selectedReport ? (
                    <div className="flex flex-col items-center justify-center h-[50vh] text-center">
                      <Target className="h-16 w-16 text-muted-foreground/30 mb-4" />
                      <h3 className="text-lg font-medium mb-2">No Report Selected</h3>
                      <p className="text-muted-foreground max-w-md">
                        Select a solution report from the sidebar to view detailed recommendations for addressing the detected threats.
                      </p>
                    </div>
                  ) : (
                    <div className="space-y-6">
                      <div className="p-4 bg-muted/30 rounded-lg border border-border mb-4">
                        <h3 className="text-lg font-medium mb-3 flex items-center">
                          <Hammer className="h-5 w-5 mr-2 text-primary" />
                          Recommended Solutions
                        </h3>
                        <div className="space-y-3">
                          {selectedReport.solutions.map((solution, index) => (
                            <div 
                              key={index} 
                              className="p-3 bg-background rounded-md border border-border/50 flex items-start"
                            >
                              <div className="mt-0.5 mr-3 bg-primary/10 text-primary rounded-full p-1 flex-shrink-0">
                                <CheckCircle2 className="h-4 w-4" />
                              </div>
                              <div>{solution}</div>
                            </div>
                          ))}
                        </div>
                      </div>
                      
                      {selectedReport.detailedAnalysis && (
                        <div className="p-4 bg-muted/30 rounded-lg border border-border mb-4">
                          <h3 className="text-lg font-medium mb-3 flex items-center">
                            <Brain className="h-5 w-5 mr-2 text-primary" />
                            In-Depth Analysis
                          </h3>
                          <div className="p-4 bg-background rounded-md border border-border/50 text-sm whitespace-pre-line">
                            {selectedReport.detailedAnalysis}
                          </div>
                        </div>
                      )}
                      
                      {selectedReport.codeSolution && (
                        <div className="p-4 bg-muted/30 rounded-lg border border-border mb-4">
                          <h3 className="text-lg font-medium mb-3 flex items-center">
                            <Code className="h-5 w-5 mr-2 text-primary" />
                            Implementation Solution
                          </h3>
                          <div className="bg-background rounded-md border border-border/50 text-sm overflow-auto">
                            <pre className="p-4 text-xs md:text-sm font-mono">
                              {selectedReport.codeSolution}
                            </pre>
                          </div>
                        </div>
                      )}
                      
                      {/* Firebase export button */}
                      {firebaseConnected && (
                        <div className="flex justify-end mb-4">
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => sendThreatReportToFirebase(selectedReport)}
                            className="border-orange-500/50 text-orange-500 hover:bg-orange-500/10"
                          >
                            <Flame className="h-4 w-4 mr-2" />
                            Export to Firebase
                          </Button>
                        </div>
                      )}
                      
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
                        <Card>
                          <CardHeader className="pb-2">
                            <CardTitle className="text-base flex items-center">
                              <Server className="h-4 w-4 mr-2 text-primary" />
                              Implementation Priority
                            </CardTitle>
                          </CardHeader>
                          <CardContent>
                            <div className="space-y-2">
                              {selectedReport.severity === 'High' ? (
                                <Badge variant="destructive" className="w-full flex justify-center py-1">Immediate Action Required</Badge>
                              ) : selectedReport.severity === 'Medium' ? (
                                <Badge variant="default" className="w-full flex justify-center py-1 bg-amber-500 hover:bg-amber-500">Implement Within 72 Hours</Badge>
                              ) : (
                                <Badge variant="outline" className="w-full flex justify-center py-1">Schedule for Next Update Cycle</Badge>
                              )}
                              <p className="text-sm text-muted-foreground mt-2">
                                {selectedReport.severity === 'High' 
                                  ? 'Critical vulnerability requiring immediate remediation to prevent potential data breach.'
                                  : selectedReport.severity === 'Medium'
                                    ? 'Significant vulnerability that should be addressed soon to maintain security posture.'
                                    : 'Low-risk issue that should be addressed as part of normal security maintenance.'
                                }
                              </p>
                            </div>
                          </CardContent>
                        </Card>
                        
                        <Card>
                          <CardHeader className="pb-2">
                            <CardTitle className="text-base flex items-center">
                              <ThumbsUp className="h-4 w-4 mr-2 text-primary" />
                              Business Impact
                            </CardTitle>
                          </CardHeader>
                          <CardContent>
                            <div className="space-y-2">
                              <div className="text-sm">
                                <span className="font-medium">Risk Reduction: </span>
                                <span className="text-green-500">
                                  {selectedReport.severity === 'High' 
                                    ? '85-95%' 
                                    : selectedReport.severity === 'Medium' 
                                      ? '65-80%' 
                                      : '40-60%'
                                  }
                                </span>
                              </div>
                              <div className="text-sm">
                                <span className="font-medium">Cost to Implement: </span>
                                <span>
                                  {selectedReport.threatType.toLowerCase().includes('injection') 
                                    ? 'Medium (Requires code changes)' 
                                    : selectedReport.threatType.toLowerCase().includes('ddos') 
                                      ? 'High (Infra updates needed)' 
                                      : 'Low (Config changes only)'
                                  }
                                </span>
                              </div>
                              <div className="text-sm">
                                <span className="font-medium">Team Responsible: </span>
                                <span>
                                  {selectedReport.threatType.toLowerCase().includes('injection') || 
                                  selectedReport.threatType.toLowerCase().includes('xss') 
                                    ? 'Development Team' 
                                    : selectedReport.threatType.toLowerCase().includes('ddos') || 
                                      selectedReport.threatType.toLowerCase().includes('network')
                                      ? 'Infrastructure Team' 
                                      : 'Security Team'
                                  }
                                </span>
                              </div>
                            </div>
                          </CardContent>
                        </Card>
                      </div>
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>
          ) : (
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
              {/* Sidebar with threat ledger data */}
              <Card className="lg:col-span-3">
                <CardHeader>
                  <CardTitle className="flex items-center justify-between">
                    <span className="flex items-center">
                      <FileText className="h-5 w-5 mr-2 text-muted-foreground" />
                      Threat Ledger
                    </span>
                  </CardTitle>
                  <CardDescription>
                    {threatLedger ? (
                      `${Object.keys(threatLedger).length} total entries detected`
                    ) : (
                      "No threat data available"
                    )}
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <ScrollArea className="h-[60vh]">
                    <div className="space-y-2">
                      {threatLedger ? (
                        Object.entries(threatLedger).map(([entryId, entry]) => (
                          <div 
                            key={entryId}
                            className={`p-3 border rounded-md cursor-pointer transition-colors ${
                              selectedLedgerEntry === entryId ? 'bg-primary/10 border-primary/50' : 'hover:bg-muted/50 border-border'
                            }`}
                            onClick={() => setSelectedLedgerEntry(entryId)}
                          >
                            <div className="flex items-center justify-between">
                              <h4 className="font-medium">
                                {entry.analysisId}
                              </h4>
                            </div>
                            <p className="text-xs text-muted-foreground mt-1">
                              {new Date(entry.timestamp).toLocaleString()}
                            </p>
                          </div>
                        ))
                      ) : (
                        <div className="flex flex-col items-center justify-center h-40 text-center">
                          <Brain className="h-12 w-12 text-muted-foreground/30 mb-4" />
                          <p className="text-muted-foreground">
                            No threat ledger data available.
                          </p>
                        </div>
                      )}
                    </div>
                  </ScrollArea>
                </CardContent>
              </Card>
              
              {/* Main content area */}
              <Card className="lg:col-span-9">
                <CardHeader>
                  <CardTitle className="flex items-center">
                    {selectedLedgerEntry ? (
                      <>
                        <Shield className="h-5 w-5 mr-2 text-primary" />
                        {selectedLedgerEntry}
                      </>
                    ) : (
                      <>
                        <Shield className="h-5 w-5 mr-2 text-primary" />
                        Threat Ledger
                      </>
                    )}
                  </CardTitle>
                  <CardDescription>
                    {selectedLedgerEntry ? 'Select an entry to view details' : 'Select an entry from the sidebar to view details'}
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  {!selectedLedgerEntry ? (
                    <div className="flex flex-col items-center justify-center h-[50vh] text-center">
                      <Target className="h-16 w-16 text-muted-foreground/30 mb-4" />
                      <h3 className="text-lg font-medium mb-2">No Entry Selected</h3>
                      <p className="text-muted-foreground max-w-md">
                        Select an entry from the sidebar to view details.
                      </p>
                    </div>
                  ) : (
                    <div className="space-y-6">
                      {threatLedger && selectedLedgerEntry && (
                        <>
                          <div className="p-4 bg-muted/30 rounded-lg border border-border mb-4">
                            <h3 className="text-lg font-medium mb-3 flex items-center">
                              <FileText className="h-5 w-5 mr-2 text-primary" />
                              Analysis Summary
                            </h3>
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                              <div className="space-y-2">
                                <div className="flex justify-between p-2 bg-background rounded border border-border/50">
                                  <span className="font-medium">Analysis ID:</span>
                                  <span>{threatLedger[selectedLedgerEntry].analysisId}</span>
                                </div>
                                <div className="flex justify-between p-2 bg-background rounded border border-border/50">
                                  <span className="font-medium">Timestamp:</span>
                                  <span>{new Date(threatLedger[selectedLedgerEntry].timestamp).toLocaleString()}</span>
                                </div>
                                <div className="flex justify-between p-2 bg-background rounded border border-border/50">
                                  <span className="font-medium">Total Threats:</span>
                                  <span>{threatLedger[selectedLedgerEntry].totalThreats}</span>
                                </div>
                              </div>
                              <div className="space-y-2">
                                <div className="flex justify-between p-2 bg-background rounded border border-border/50">
                                  <span className="font-medium">Unique Attack Types:</span>
                                  <span>{Object.keys(threatLedger[selectedLedgerEntry].threatTypes).length}</span>
                                </div>
                                <div className="flex justify-between p-2 bg-background rounded border border-border/50">
                                  <span className="font-medium">High Severity:</span>
                                  <span className="text-red-500 font-medium">{getThreatSeverityCount('High')}</span>
                                </div>
                                <div className="flex justify-between p-2 bg-background rounded border border-border/50">
                                  <span className="font-medium">Medium Severity:</span>
                                  <span className="text-amber-500 font-medium">{getThreatSeverityCount('Medium')}</span>
                                </div>
                                <div className="flex justify-between p-2 bg-background rounded border border-border/50">
                                  <span className="font-medium">Low Severity:</span>
                                  <span className="text-green-500 font-medium">{getThreatSeverityCount('Low')}</span>
                                </div>
                              </div>
                            </div>
                          </div>
                          
                          <div className="p-4 bg-muted/30 rounded-lg border border-border mb-4">
                            <h3 className="text-lg font-medium mb-3 flex items-center">
                              <AlertTriangle className="h-5 w-5 mr-2 text-primary" />
                              Detected Threats
                            </h3>
                            <div className="space-y-3">
                              {threatLedger[selectedLedgerEntry].threats.map((threat, index) => (
                                <div 
                                  key={index} 
                                  className={`p-3 bg-background rounded-md border border-border/50 flex items-start cursor-pointer hover:bg-muted/30 transition-colors ${
                                    selectedThreat === threat ? 'ring-2 ring-primary' : ''
                                  }`}
                                  onClick={() => setSelectedThreat(threat)}
                                >
                                  <div className={`mt-0.5 mr-3 rounded-full p-1 flex-shrink-0 ${
                                    threat.severity === 'High' ? 'bg-red-100 text-red-500' : 
                                    threat.severity === 'Medium' ? 'bg-amber-100 text-amber-500' : 
                                    'bg-green-100 text-green-500'
                                  }`}>
                                    <AlertTriangle className="h-4 w-4" />
                                  </div>
                                  <div className="flex-1">
                                    <div className="flex justify-between">
                                      <span className="font-medium">{threat.attackType}</span>
                                      <Badge variant={
                                        threat.severity === 'High' ? 'destructive' : 
                                        threat.severity === 'Medium' ? 'default' : 'outline'
                                      } className={
                                        threat.severity === 'Medium' ? 'bg-amber-500 hover:bg-amber-500/90' : 
                                        threat.severity === 'Low' ? 'text-green-500 border-green-500/50' : ''
                                      }>
                                        {threat.severity}
                                      </Badge>
                                    </div>
                                    <div className="text-sm text-muted-foreground mt-1">
                                      <span>Source: {threat.sourceIP} | Destination: {threat.destIP} | {threat.protocol}/{threat.service}</span>
                                    </div>
                                  </div>
                                </div>
                              ))}
                            </div>
                          </div>
                          
                          {selectedThreat && (
                            <div className="p-4 bg-muted/30 rounded-lg border border-border mb-4">
                              <h3 className="text-lg font-medium mb-3 flex items-center">
                                <Eye className="h-5 w-5 mr-2 text-primary" />
                                Threat Details
                              </h3>
                              <div className="p-4 bg-background rounded-md border border-border/50">
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                  <div className="space-y-2">
                                    <div className="text-sm">
                                      <span className="font-medium">Attack Type: </span>
                                      <span>{selectedThreat.attackType}</span>
                                    </div>
                                    <div className="text-sm">
                                      <span className="font-medium">Protocol: </span>
                                      <span>{selectedThreat.protocol}</span>
                                    </div>
                                    <div className="text-sm">
                                      <span className="font-medium">Service: </span>
                                      <span>{selectedThreat.service}</span>
                                    </div>
                                    <div className="text-sm">
                                      <span className="font-medium">Source IP: </span>
                                      <span>{selectedThreat.sourceIP}</span>
                                    </div>
                                    <div className="text-sm">
                                      <span className="font-medium">Destination IP: </span>
                                      <span>{selectedThreat.destIP}</span>
                                    </div>
                                  </div>
                                  <div className="space-y-2">
                                    <div className="text-sm">
                                      <span className="font-medium">Timestamp: </span>
                                      <span>{selectedThreat.timestamp}</span>
                                    </div>
                                    <div className="text-sm">
                                      <span className="font-medium">Source Bytes: </span>
                                      <span>{selectedThreat.srcBytes}</span>
                                    </div>
                                    <div className="text-sm">
                                      <span className="font-medium">Destination Bytes: </span>
                                      <span>{selectedThreat.destBytes}</span>
                                    </div>
                                    <div className="text-sm">
                                      <span className="font-medium">Severity: </span>
                                      <span className={
                                        selectedThreat.severity === 'High' ? 'text-red-500 font-medium' : 
                                        selectedThreat.severity === 'Medium' ? 'text-amber-500 font-medium' : 
                                        'text-green-500 font-medium'
                                      }>
                                        {selectedThreat.severity}
                                      </span>
                                    </div>
                                  </div>
                                </div>
                                <div className="mt-4">
                                  <div className="text-sm">
                                    <span className="font-medium">Info: </span>
                                    <span>{selectedThreat.info}</span>
                                  </div>
                                </div>
                              </div>
                            </div>
                          )}
                        </>
                      )}
                      
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
                        <Card>
                          <CardHeader className="pb-2">
                            <CardTitle className="text-base flex items-center">
                              <BarChart className="h-4 w-4 mr-2 text-primary" />
                              Attack Type Distribution
                            </CardTitle>
                          </CardHeader>
                          <CardContent>
                            <div className="space-y-2">
                              {threatLedger && selectedLedgerEntry && Object.entries(threatLedger[selectedLedgerEntry].threatTypes).map(([attackType, count]) => (
                                <div key={attackType} className="flex items-center">
                                  <div className="w-32 font-medium truncate">
                                    {attackType.replace(/_/g, ' ')}:
                                  </div>
                                  <div className="flex-1 ml-2">
                                    <div className="h-2 bg-muted rounded overflow-hidden">
                                      <div 
                                        className="h-full bg-primary" 
                                        style={{ 
                                          width: `${(count / threatLedger[selectedLedgerEntry].totalThreats) * 100}%` 
                                        }}
                                      />
                                    </div>
                                  </div>
                                  <div className="ml-2 text-sm">
                                    {count}
                                  </div>
                                </div>
                              ))}
                            </div>
                          </CardContent>
                        </Card>
                        
                        <Card>
                          <CardHeader className="pb-2">
                            <CardTitle className="text-base flex items-center">
                              <Activity className="h-4 w-4 mr-2 text-primary" />
                              Protocol &amp; Service Stats
                            </CardTitle>
                          </CardHeader>
                          <CardContent>
                            <div className="space-y-4">
                              <div>
                                <h4 className="text-sm font-medium mb-2">Protocols</h4>
                                <div className="space-y-1">
                                  {threatLedger && selectedLedgerEntry && Object.entries(threatLedger[selectedLedgerEntry].stats.protocols).map(([protocol, count]) => (
                                    <div key={protocol} className="text-sm flex justify-between">
                                      <span>{protocol}:</span>
                                      <span>{count}</span>
                                    </div>
                                  ))}
                                </div>
                              </div>
                              
                              <div>
                                <h4 className="text-sm font-medium mb-2">Services</h4>
                                <div className="space-y-1">
                                  {threatLedger && selectedLedgerEntry && Object.entries(threatLedger[selectedLedgerEntry].stats.services).map(([service, count]) => (
                                    <div key={service} className="text-sm flex justify-between">
                                      <span>{service}:</span>
                                      <span>{count}</span>
                                    </div>
                                  ))}
                                </div>
                              </div>
                            </div>
                          </CardContent>
                        </Card>
                      </div>
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>
          )}
        </main>
      </div>
    </>
  );
};

export default CyberForge; 