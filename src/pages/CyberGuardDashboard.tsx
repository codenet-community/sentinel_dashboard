import { useState, useEffect } from 'react';
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
  Target
} from 'lucide-react';
import { useThreatData } from '@/hooks/useThreatData';
import { getFromStorage } from '@/utils/storageUtils';
import { useGeminiAnalysis } from '@/hooks/useGeminiAnalysis';
import ChatbotSuggester from '@/components/chatbot/ChatbotSuggester';
import { Toaster, toast } from 'sonner';
import { Separator } from '@/components/ui/separator';
import { useNavigate } from 'react-router-dom';

export interface PredictionDetails {
  is_anomaly: boolean;
  is_zero_day: boolean;
  top_features: string[];
}

export interface EnhancedThreatDetail extends ThreatDetail {
  confidence_score?: number;
  anomaly_score?: number;
  zero_day_score?: number;
  prediction_details?: PredictionDetails;
}

export interface EnhancedThreatData extends ThreatData {
  details: EnhancedThreatDetail;
}

const CyberGuardDashboard = () => {
  const [activeTab, setActiveTab] = useState<string>('assistant');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
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
    isAnalysisLoading,
    analysisError,
    geminiResults
  } = useGeminiAnalysis();

  // Connect to blockchain on component mount if we have settings
  useEffect(() => {
    // Check if we need to connect
    if (persistedSettings.blockchainUrl && !isConnected && !isLoading && !isReconnecting) {
      console.log('Attempting to connect with stored settings in CyberGuard');
      connectToSources();
    }
  }, [persistedSettings, isConnected, isLoading, isReconnecting, connectToSources]);

  // Log connection status for debugging
  useEffect(() => {
    console.log('CyberGuard connection status:', { 
      isConnected, 
      blockchainConnected, 
      hasBlockchainData: !!blockchainData,
      chainLength: blockchainData?.chain?.length || 0
    });
  }, [isConnected, blockchainConnected, blockchainData]);

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

  // Analyze threat data with AI
  const analyzeThreats = async () => {
    if (!threatData.length) {
      toast.error('No threat data available to analyze');
      return;
    }

    setIsAnalyzing(true);
    try {
      // Get the most recent high severity threats
      const highSeverityThreats = threatData
        .filter(t => t.severity === 'High')
        .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
        .slice(0, 3);
      
      if (highSeverityThreats.length === 0) {
        toast.error('No high severity threats found to analyze');
        setIsAnalyzing(false);
        return;
      }
      
      // Add AI-specific fields
      const enhancedThreat = {
        ...highSeverityThreats[0],
        details: {
          ...highSeverityThreats[0].details,
          confidence_score: 0.89,
          anomaly_score: 0.92,
          zero_day_score: 0.65,
          prediction_details: {
            is_anomaly: true,
            is_zero_day: false,
            top_features: ['unusual_port', 'path_traversal', 'high_frequency']
          }
        }
      };
      
      await analyzeWithGemini(JSON.stringify(enhancedThreat, null, 2));
      toast.success('Threat analysis complete');
      setActiveTab('analysis');
    } catch (err) {
      console.error('Error analyzing threats:', err);
      toast.error('Failed to analyze threats');
    } finally {
      setIsAnalyzing(false);
    }
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

  return (
    <div className="flex min-h-screen flex-col bg-background">
      <Toaster position="top-right" />
      <Header 
        title="CyberGuard" 
        subtitle="Advanced Threat Analysis" 
        bankaiMode={bankaiMode}
        setBankaiMode={setBankaiMode}
      />
      
      <main className="flex-1 p-6 container">
        <div className="flex flex-col md:flex-row justify-between items-start md:items-center mb-6 gap-4">
          <div>
            <h1 className="text-3xl font-bold tracking-tight flex items-center gap-2">
              <Shield className="h-8 w-8 text-primary" />
              CyberGuard AI Assistant
            </h1>
            <p className="text-muted-foreground">
              Advanced cybersecurity analysis powered by AI
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
            <Button 
              variant="outline" 
              size="sm" 
              onClick={handleForceConnect}
              disabled={isLoading || isReconnecting}
            >
              <Database className="h-4 w-4 mr-2" />
              Connect
            </Button>
            <Button
              variant="default"
              size="sm"
              onClick={analyzeThreats}
              disabled={isAnalyzing || !threatData.length}
            >
              <Brain className={`h-4 w-4 mr-2 ${isAnalyzing ? 'animate-pulse' : ''}`} />
              {isAnalyzing ? 'Analyzing...' : 'AI Analysis'}
            </Button>
          </div>
        </div>
        
        {error && (
          <Card className="mb-6 border-destructive">
            <CardContent className="p-4">
              <div className="flex items-center gap-2 text-destructive">
                <AlertTriangle className="h-5 w-5" />
                <p>Error: {error}</p>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Threat Statistics Cards */}
        {threatStats && (
          <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-6 gap-4 mb-6">
            <Card className="bg-gradient-to-br from-blue-500/10 to-indigo-500/10">
              <CardContent className="p-4 flex flex-col justify-center h-full">
                <p className="text-sm text-muted-foreground">Total Threats</p>
                <div className="flex items-center mt-1">
                  <Shield className="h-5 w-5 text-primary mr-2" />
                  <span className="text-2xl font-bold">{threatStats.total}</span>
                </div>
              </CardContent>
            </Card>
            <Card className="bg-gradient-to-br from-red-500/10 to-red-600/10">
              <CardContent className="p-4 flex flex-col justify-center h-full">
                <p className="text-sm text-muted-foreground">High Severity</p>
                <div className="flex items-center mt-1">
                  <AlertTriangle className="h-5 w-5 text-red-500 mr-2" />
                  <span className="text-2xl font-bold">{threatStats.highSeverity}</span>
                </div>
              </CardContent>
            </Card>
            <Card className="bg-gradient-to-br from-orange-500/10 to-orange-600/10">
              <CardContent className="p-4 flex flex-col justify-center h-full">
                <p className="text-sm text-muted-foreground">Medium Severity</p>
                <div className="flex items-center mt-1">
                  <AlertTriangle className="h-5 w-5 text-orange-500 mr-2" />
                  <span className="text-2xl font-bold">{threatStats.mediumSeverity}</span>
                </div>
              </CardContent>
            </Card>
            <Card className="bg-gradient-to-br from-green-500/10 to-green-600/10">
              <CardContent className="p-4 flex flex-col justify-center h-full">
                <p className="text-sm text-muted-foreground">Low Severity</p>
                <div className="flex items-center mt-1">
                  <CheckCircle2 className="h-5 w-5 text-green-500 mr-2" />
                  <span className="text-2xl font-bold">{threatStats.lowSeverity}</span>
                </div>
              </CardContent>
            </Card>
            <Card className="bg-gradient-to-br from-purple-500/10 to-purple-600/10">
              <CardContent className="p-4 flex flex-col justify-center h-full">
                <p className="text-sm text-muted-foreground">Active Threats</p>
                <div className="flex items-center mt-1">
                  <Zap className="h-5 w-5 text-purple-500 mr-2" />
                  <span className="text-2xl font-bold">{threatStats.active}</span>
                </div>
              </CardContent>
            </Card>
            <Card className="bg-gradient-to-br from-teal-500/10 to-teal-600/10">
              <CardContent className="p-4 flex flex-col justify-center h-full">
                <p className="text-sm text-muted-foreground">Mitigated</p>
                <div className="flex items-center mt-1">
                  <CheckCircle2 className="h-5 w-5 text-teal-500 mr-2" />
                  <span className="text-2xl font-bold">{threatStats.mitigated}</span>
                </div>
              </CardContent>
            </Card>
          </div>
        )}
        
        {/* Main Content Tabs */}
        <div className="mt-8">
          <Tabs defaultValue="assistant" onValueChange={setActiveTab} className="w-full">
            <TabsList className="mb-4 bg-background/60 backdrop-blur-sm border border-border/50 p-1">
              <TabsTrigger value="assistant" className="data-[state=active]:bg-primary data-[state=active]:text-primary-foreground">
                <MessagesSquare className="h-4 w-4 mr-2" />
                AI Assistant
              </TabsTrigger>
              <TabsTrigger value="analysis" className="data-[state=active]:bg-primary data-[state=active]:text-primary-foreground">
                <LineChart className="h-4 w-4 mr-2" />
                Analysis
              </TabsTrigger>
              <TabsTrigger value="insights" className="data-[state=active]:bg-primary data-[state=active]:text-primary-foreground">
                <Lightbulb className="h-4 w-4 mr-2" />
                Insights
              </TabsTrigger>
            </TabsList>
            
            {/* AI Assistant Tab */}
            <TabsContent value="assistant" className="space-y-4">
              <ChatbotSuggester 
                blockchainData={blockchainData}
                isConnected={blockchainConnected}
                bankaiMode={bankaiMode}
              />
            </TabsContent>
            
            {/* Analysis Tab */}
            <TabsContent value="analysis" className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <LineChart className="h-5 w-5 text-primary" />
                      Threat Distribution
                    </CardTitle>
                    <CardDescription>Analysis of threats by severity and type</CardDescription>
                  </CardHeader>
                  <CardContent>
                    {threatData.length > 0 ? (
                      <div className="h-[300px] flex items-center justify-center">
                        {/* In a real implementation, you would use a chart component here */}
                        <div className="space-y-4 w-full">
                          <div className="space-y-2">
                            <div className="flex justify-between items-center">
                              <span className="text-sm font-medium">High Severity</span>
                              <span className="text-sm font-medium">{threatStats.highSeverity}</span>
                            </div>
                            <div className="w-full bg-secondary h-2 rounded-full overflow-hidden">
                              <div 
                                className="bg-red-500 h-full rounded-full" 
                                style={{ width: `${(threatStats.highSeverity / threatStats.total) * 100}%` }}
                              ></div>
                            </div>
                          </div>
                          
                          <div className="space-y-2">
                            <div className="flex justify-between items-center">
                              <span className="text-sm font-medium">Medium Severity</span>
                              <span className="text-sm font-medium">{threatStats.mediumSeverity}</span>
                            </div>
                            <div className="w-full bg-secondary h-2 rounded-full overflow-hidden">
                              <div 
                                className="bg-yellow-500 h-full rounded-full" 
                                style={{ width: `${(threatStats.mediumSeverity / threatStats.total) * 100}%` }}
                              ></div>
                            </div>
                          </div>
                          
                          <div className="space-y-2">
                            <div className="flex justify-between items-center">
                              <span className="text-sm font-medium">Low Severity</span>
                              <span className="text-sm font-medium">{threatStats.lowSeverity}</span>
                            </div>
                            <div className="w-full bg-secondary h-2 rounded-full overflow-hidden">
                              <div 
                                className="bg-green-500 h-full rounded-full" 
                                style={{ width: `${(threatStats.lowSeverity / threatStats.total) * 100}%` }}
                              ></div>
                            </div>
                          </div>
                        </div>
                      </div>
                    ) : (
                      <div className="flex items-center justify-center h-[300px] text-muted-foreground">
                        No threat data available
                      </div>
                    )}
                  </CardContent>
                </Card>
                
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <Database className="h-5 w-5 text-primary" />
                      Attack Vectors
                    </CardTitle>
                    <CardDescription>Most common attack types</CardDescription>
                  </CardHeader>
                  <CardContent>
                    {threatData.length > 0 ? (
                      <div className="h-[300px] overflow-auto">
                        <table className="w-full">
                          <thead>
                            <tr className="border-b border-border">
                              <th className="text-left py-2 text-sm font-medium">Attack Type</th>
                              <th className="text-right py-2 text-sm font-medium">Count</th>
                              <th className="text-right py-2 text-sm font-medium">Percentage</th>
                            </tr>
                          </thead>
                          <tbody>
                            {Object.entries(
                              threatData.reduce((acc: Record<string, number>, threat) => {
                                const attackType = threat.attack_type || 'Unknown';
                                acc[attackType] = (acc[attackType] || 0) + 1;
                                return acc;
                              }, {})
                            )
                              .sort((a, b) => b[1] - a[1])
                              .slice(0, 10)
                              .map(([attackType, count], index) => (
                                <tr key={index} className="border-b border-border/50">
                                  <td className="py-2 text-sm">{attackType}</td>
                                  <td className="py-2 text-sm text-right">{count}</td>
                                  <td className="py-2 text-sm text-right">
                                    {((count / threatData.length) * 100).toFixed(1)}%
                                  </td>
                                </tr>
                              ))}
                          </tbody>
                        </table>
                      </div>
                    ) : (
                      <div className="flex items-center justify-center h-[300px] text-muted-foreground">
                        No threat data available
                      </div>
                    )}
                  </CardContent>
                </Card>
              </div>
              
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <MapPin className="h-5 w-5 text-primary" />
                    Origin Analysis
                  </CardTitle>
                  <CardDescription>Geographic distribution of threats</CardDescription>
                </CardHeader>
                <CardContent>
                  {threatData.length > 0 ? (
                    <div className="h-[400px] flex items-center justify-center">
                      {/* In a real implementation, you would use a map component here */}
                      <div className="space-y-4 w-full">
                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                          {Object.entries(
                            threatData.reduce((acc: Record<string, number>, threat) => {
                              const country = threat.country || 'Unknown';
                              acc[country] = (acc[country] || 0) + 1;
                              return acc;
                            }, {})
                          )
                            .sort((a, b) => b[1] - a[1])
                            .slice(0, 6)
                            .map(([country, count], index) => (
                              <div key={index} className="bg-secondary/30 p-4 rounded-lg">
                                <div className="flex justify-between items-center mb-2">
                                  <span className="font-medium">{country}</span>
                                  <Badge variant="outline">{count}</Badge>
                                </div>
                                <div className="w-full bg-secondary h-2 rounded-full overflow-hidden">
                                  <div 
                                    className="bg-primary h-full rounded-full" 
                                    style={{ width: `${(count / threatData.length) * 100}%` }}
                                  ></div>
                                </div>
                              </div>
                            ))}
                        </div>
                      </div>
                    </div>
                  ) : (
                    <div className="flex items-center justify-center h-[400px] text-muted-foreground">
                      No threat data available
                    </div>
                  )}
                </CardContent>
              </Card>
            </TabsContent>
            
            {/* Insights Tab */}
            <TabsContent value="insights" className="space-y-4">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Brain className="h-5 w-5 text-primary" />
                    AI Insights
                  </CardTitle>
                  <CardDescription>AI-generated security recommendations</CardDescription>
                </CardHeader>
                <CardContent>
                  {geminiResults ? (
                    <div className="prose prose-slate dark:prose-invert max-w-none">
                      {geminiResults.predictions.map((prediction, index) => (
                        <div key={index} className="mb-6 p-4 bg-primary/5 rounded-lg">
                          <h3 className="text-lg font-medium mb-2 flex items-center gap-2">
                            <AlertTriangle className="h-5 w-5 text-primary" />
                            {prediction.title}
                          </h3>
                          <p className="text-sm mb-3">{prediction.description}</p>
                          <div className="space-y-2">
                            <h4 className="text-sm font-medium">Recommended Actions:</h4>
                            <ul className="list-disc list-inside text-sm space-y-1">
                              {prediction.actions.map((action, actionIndex) => (
                                <li key={actionIndex}>{action}</li>
                              ))}
                            </ul>
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="space-y-4">
                      <div className="bg-secondary/30 p-4 rounded-lg">
                        <p className="mb-3 text-muted-foreground">
                          No AI analysis performed yet. Click the "AI Analysis" button to generate security insights.
                        </p>
                        <Button
                          variant="default"
                          size="sm"
                          onClick={analyzeThreats}
                          disabled={isAnalyzing || !threatData.length}
                        >
                          <Brain className={`h-4 w-4 mr-2 ${isAnalyzing ? 'animate-pulse' : ''}`} />
                          {isAnalyzing ? 'Analyzing...' : 'Generate Security Insights'}
                        </Button>
                      </div>
                      
                      {threatData.length > 0 && (
                        <div>
                          <h3 className="text-lg font-medium mb-3">General Security Recommendations</h3>
                          <div className="space-y-3">
                            <div className="p-3 bg-primary/5 rounded-lg">
                              <h4 className="font-medium mb-1 flex items-center gap-2">
                                <Shield className="h-4 w-4 text-primary" />
                                Implement Robust Authentication
                              </h4>
                              <p className="text-sm text-muted-foreground">
                                Use multi-factor authentication across all systems and regularly rotate credentials.
                              </p>
                            </div>
                            <div className="p-3 bg-primary/5 rounded-lg">
                              <h4 className="font-medium mb-1 flex items-center gap-2">
                                <RefreshCw className="h-4 w-4 text-primary" />
                                Keep Systems Updated
                              </h4>
                              <p className="text-sm text-muted-foreground">
                                Apply security patches promptly and maintain an inventory of all software.
                              </p>
                            </div>
                            <div className="p-3 bg-primary/5 rounded-lg">
                              <h4 className="font-medium mb-1 flex items-center gap-2">
                                <Database className="h-4 w-4 text-primary" />
                                Secure Your Infrastructure
                              </h4>
                              <p className="text-sm text-muted-foreground">
                                Implement network segmentation and use firewalls to restrict unnecessary access.
                              </p>
                            </div>
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </CardContent>
              </Card>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <Activity className="h-5 w-5 text-primary" />
                      Threat Trends
                    </CardTitle>
                    <CardDescription>Changes in threat patterns over time</CardDescription>
                  </CardHeader>
                  <CardContent>
                    {threatData.length > 0 ? (
                      <div className="h-[300px] flex items-center justify-center">
                        {/* In a real implementation, you would use a trend chart component here */}
                        <div className="text-center text-muted-foreground">
                          <p>Trend visualization would appear here</p>
                          <p className="text-sm mt-2">Based on {threatData.length} threat records</p>
                        </div>
                      </div>
                    ) : (
                      <div className="flex items-center justify-center h-[300px] text-muted-foreground">
                        No threat data available
                      </div>
                    )}
                  </CardContent>
                </Card>
                
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <Target className="h-5 w-5 text-primary" />
                      Vulnerability Analysis
                    </CardTitle>
                    <CardDescription>Most targeted systems and services</CardDescription>
                  </CardHeader>
                  <CardContent>
                    {threatData.length > 0 ? (
                      <div className="h-[300px] overflow-auto">
                        <table className="w-full">
                          <thead>
                            <tr className="border-b border-border">
                              <th className="text-left py-2 text-sm font-medium">Target</th>
                              <th className="text-left py-2 text-sm font-medium">Service</th>
                              <th className="text-right py-2 text-sm font-medium">Attacks</th>
                            </tr>
                          </thead>
                          <tbody>
                            {Object.entries(
                              threatData.reduce((acc: Record<string, {service: string, count: number}[]>, threat) => {
                                const target = threat.target_ip || 'Unknown';
                                const service = threat.service || 'Unknown';
                                
                                if (!acc[target]) {
                                  acc[target] = [];
                                }
                                
                                const existingService = acc[target].find(s => s.service === service);
                                if (existingService) {
                                  existingService.count += 1;
                                } else {
                                  acc[target].push({ service, count: 1 });
                                }
                                
                                return acc;
                              }, {})
                            )
                              .sort((a, b) => {
                                const totalA = a[1].reduce((sum, item) => sum + item.count, 0);
                                const totalB = b[1].reduce((sum, item) => sum + item.count, 0);
                                return totalB - totalA;
                              })
                              .slice(0, 5)
                              .flatMap(([target, services]) => 
                                services.map((service, serviceIndex) => (
                                  <tr key={`${target}-${serviceIndex}`} className="border-b border-border/50">
                                    <td className="py-2 text-sm">{serviceIndex === 0 ? target : ''}</td>
                                    <td className="py-2 text-sm">{service.service}</td>
                                    <td className="py-2 text-sm text-right">{service.count}</td>
                                  </tr>
                                ))
                              )}
                          </tbody>
                        </table>
                      </div>
                    ) : (
                      <div className="flex items-center justify-center h-[300px] text-muted-foreground">
                        No threat data available
                      </div>
                    )}
                  </CardContent>
                </Card>
              </div>
            </TabsContent>
          </Tabs>
        </div>
      </main>
    </div>
  );
};

export default CyberGuardDashboard; 