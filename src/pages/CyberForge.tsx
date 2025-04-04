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
  Server
} from 'lucide-react';
import { useThreatData, ThreatData } from '@/hooks/useThreatData';
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

interface AutoAnalysisResult {
  id: string;
  timestamp: Date;
  threatType: string;
  severity: 'High' | 'Medium' | 'Low';
  summary: string;
  solutions: string[];
  status: 'Ready' | 'In Progress' | 'Needs Review';
}

const CyberForge = () => {
  const [activeTab, setActiveTab] = useState<string>('reports');
  const [autoAnalysisResults, setAutoAnalysisResults] = useState<AutoAnalysisResult[]>([]);
  const [isAutoAnalyzing, setIsAutoAnalyzing] = useState(false);
  const [selectedReport, setSelectedReport] = useState<AutoAnalysisResult | null>(null);
  const autoAnalysisTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const navigate = useNavigate();
  
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
    fetchBlockchainData,
    apiConnected,
    blockchainConnected,
    isReconnecting,
    blockchainData,
    connectToSources,
    bankaiMode,
    setBankaiMode
  } = useThreatData(persistedSettings);

  // Use Gemini Analysis hook
  const {
    analyzeWithGemini,
    analysisResult,
    isAnalysisLoading
  } = useGeminiAnalysis();

  // Connect to blockchain on component mount if we have settings
  useEffect(() => {
    // Check if we need to connect
    if (persistedSettings.blockchainUrl && !isConnected && !isLoading && !isReconnecting) {
      console.log('Attempting to connect with stored settings in CyberForge');
      connectToSources();
    }
  }, [persistedSettings, isConnected, isLoading, isReconnecting, connectToSources]);

  // Automatically run analysis when blockchain data is available
  useEffect(() => {
    // If we have blockchain data and we're not already analyzing
    if (blockchainData && !isAutoAnalyzing && threatData.length > 0) {
      // Clear any existing timeout
      if (autoAnalysisTimeoutRef.current) {
        clearTimeout(autoAnalysisTimeoutRef.current);
      }
      
      // Start analysis after a short delay to avoid repeated calls
      autoAnalysisTimeoutRef.current = setTimeout(() => {
        runAutoAnalysis();
      }, 1500);
    }
    
    // Cleanup
    return () => {
      if (autoAnalysisTimeoutRef.current) {
        clearTimeout(autoAnalysisTimeoutRef.current);
      }
    };
  }, [blockchainData, threatData, isAutoAnalyzing]);

  // Automatic analysis function
  const runAutoAnalysis = async () => {
    if (!threatData.length || isAutoAnalyzing) return;
    
    setIsAutoAnalyzing(true);
    console.log('Running automatic threat analysis...');
    
    try {
      const extractedThreats = extractThreatData(blockchainData, bankaiMode);
      const attackPatterns = analyzeAttackPatterns(extractedThreats);
      const insights = generateSecurityInsights(extractedThreats);
      
      // Get unique threat types that need analysis
      const uniqueThreats = new Set(extractedThreats.map(t => t.attack_type));
      const threatsToAnalyze = Array.from(uniqueThreats).slice(0, 3); // Limit to top 3 for performance
      
      // Process each threat type
      const newResults: AutoAnalysisResult[] = [];
      
      for (const threatType of threatsToAnalyze) {
        // Find most severe instance of this threat type
        const threatInstances = extractedThreats.filter(t => t.attack_type === threatType);
        const severityOrder = { 'High': 3, 'Medium': 2, 'Low': 1 };
        
        // Sort by severity (highest first)
        threatInstances.sort((a, b) => 
          severityOrder[b.severity] - severityOrder[a.severity]
        );
        
        const worstInstance = threatInstances[0];
        
        // Get mitigation suggestions
        const mitigations = getThreatMitigationSuggestions(threatType);
        
        // Create analysis result
        const result: AutoAnalysisResult = {
          id: `analysis-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
          timestamp: new Date(),
          threatType: threatType,
          severity: worstInstance.severity,
          summary: `${threatInstances.length} instances detected. Most recent from IP ${worstInstance.ip}.`,
          solutions: mitigations,
          status: 'Ready'
        };
        
        newResults.push(result);
      }
      
      // Add insight-based report if we have insights
      if (insights.length > 0) {
        const insightReport: AutoAnalysisResult = {
          id: `insight-${Date.now()}`,
          timestamp: new Date(),
          threatType: 'Security Insights',
          severity: 'Medium',
          summary: 'Overall security assessment based on threat analysis.',
          solutions: insights,
          status: 'Ready'
        };
        
        newResults.push(insightReport);
      }
      
      // Combine with existing results, avoiding duplicates
      const existingIds = new Set(autoAnalysisResults.map(r => r.id));
      const uniqueNewResults = newResults.filter(r => !existingIds.has(r.id));
      
      setAutoAnalysisResults(prev => [...uniqueNewResults, ...prev]);
      
      // Select the first report if none selected
      if (!selectedReport && uniqueNewResults.length > 0) {
        setSelectedReport(uniqueNewResults[0]);
      }
      
    } catch (error) {
      console.error('Error in auto analysis:', error);
    } finally {
      setIsAutoAnalyzing(false);
    }
  };

  // Refresh the threat data 
  const handleRefreshData = () => {
    console.log('Refreshing blockchain data');
    fetchBlockchainData();
    
    toast.info('Refreshing blockchain data...', {
      duration: 2000
    });
  };

  // Force connect handler
  const handleForceConnect = () => {
    console.log('Force connecting to blockchain');
    connectToSources();
    
    toast.info('Connecting to blockchain...', {
      duration: 2000
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
    const variants = {
      'High': 'destructive',
      'Medium': 'warning',
      'Low': 'success'
    };
    
    return (
      <Badge 
        variant={variants[severity] as any} 
        className="ml-2"
      >
        {severity}
      </Badge>
    );
  };

  return (
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
              Automated security solutions and threat remediation
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
            <Badge 
              variant={blockchainConnected ? "default" : "destructive"} 
              className="px-3 py-1"
            >
              {blockchainConnected ? "Connected" : "Disconnected"}
            </Badge>
            <Button 
              variant="outline" 
              size="sm" 
              onClick={handleRefreshData}
              disabled={isLoading || isReconnecting}
            >
              <RefreshCw className={`h-4 w-4 mr-2 ${isLoading || isReconnecting ? 'animate-spin' : ''}`} />
              Refresh Data
            </Button>
            {!blockchainConnected && (
              <Button 
                variant="outline" 
                size="sm" 
                onClick={handleForceConnect}
                disabled={isLoading || isReconnecting}
              >
                <Database className="h-4 w-4 mr-2" />
                Connect
              </Button>
            )}
            <Button
              variant="default"
              size="sm"
              onClick={runAutoAnalysis}
              disabled={isAutoAnalyzing || !threatData.length}
            >
              <Brain className={`h-4 w-4 mr-2 ${isAutoAnalyzing ? 'animate-pulse' : ''}`} />
              {isAutoAnalyzing ? 'Analyzing...' : 'Regenerate Solutions'}
            </Button>
          </div>
        </div>
        
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
                            <Badge variant="warning" className="w-full flex justify-center py-1">Implement Within 72 Hours</Badge>
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
      </main>
    </div>
  );
};

export default CyberForge; 