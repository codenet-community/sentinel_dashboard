import { useState, useEffect, useRef } from 'react';
import { BlockchainData, BlockchainBlock, ThreatData } from '@/hooks/useThreatData';
import { Button } from '@/components/ui/button';
import { Textarea } from '@/components/ui/textarea';
import { Input } from '@/components/ui/input';
import { 
  BotIcon, 
  SendIcon, 
  MessagesSquare, 
  XIcon, 
  AlertCircle, 
  Shield, 
  Database,
  Clock,
  Repeat,
  ListChecks,
  Lightbulb,
  Menu,
  ChevronLeft,
  LayoutDashboard,
  LineChart,
  Settings,
  AlertOctagon,
  Network
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Avatar } from '@/components/ui/avatar';
import { Badge } from '@/components/ui/badge';
import { 
  extractThreatData, 
  analyzeAttackPatterns, 
  analyzeProtocolUsage,
  analyzePortTargets,
  generateThreatSummary,
  getThreatDetailsByAttackType,
  analyzeSeverityTrends,
  getThreatMitigationSuggestions,
  generateSecurityInsights,
  enrichThreatData
} from '@/utils/chatbotUtils';

interface Message {
  id: string;
  role: 'user' | 'bot';
  content: string;
  timestamp: Date;
}

interface ChatbotSuggesterProps {
  blockchainData: BlockchainData | null;
  isConnected: boolean;
  className?: string;
  onBack?: () => void;
}

const ChatbotSuggester = ({ blockchainData, isConnected, className, onBack }: ChatbotSuggesterProps) => {
  console.log('ChatbotSuggester rendering, isConnected:', isConnected);
  console.log('blockchainData available:', !!blockchainData);
  
  // Add a local state to track connection status to be more resilient
  const [localConnectionStatus, setLocalConnectionStatus] = useState<boolean>(isConnected);
  
  // Enhanced state to store processed threat data
  const [enrichedData, setEnrichedData] = useState<any>(null);
  const [messages, setMessages] = useState<Message[]>([
    {
      id: '1',
      role: 'bot',
      content: 'Welcome to CyberGuard AI Assistant! I can analyze your blockchain security data and provide advanced threat intelligence. How can I assist you today?',
      timestamp: new Date()
    }
  ]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  
  // Update local connection status based on props and blockchain data
  useEffect(() => {
    console.log('Connection props update:', { isConnected, hasBlockchainData: !!blockchainData });
    
    // If we have blockchain data, consider ourselves connected regardless of the isConnected flag
    const hasValidBlockchainData = blockchainData && 
      blockchainData.chain && 
      Array.isArray(blockchainData.chain) && 
      blockchainData.chain.length > 0;
    
    const effectiveConnectionStatus = isConnected || hasValidBlockchainData;
    console.log('Effective connection status:', effectiveConnectionStatus, 'hasValidBlockchainData:', hasValidBlockchainData);
    
    setLocalConnectionStatus(effectiveConnectionStatus);
  }, [isConnected, blockchainData]);
  
  // Process blockchain data whenever it changes
  useEffect(() => {
    console.log('Processing blockchain data in ChatbotSuggester', blockchainData);
    
    // Create default enriched data if none exists yet, so suggestions work
    if (!enrichedData) {
      setEnrichedData({
        insights: [
          "Your security assistant is ready to analyze threats and vulnerabilities",
          "Ask me about attack patterns, security vulnerabilities, or threat mitigation"
        ]
      });
    }
    
    // Check if we have valid blockchain data
    if (blockchainData && blockchainData.chain && Array.isArray(blockchainData.chain) && blockchainData.chain.length > 0) {
      try {
        console.log('Chain length:', blockchainData.chain.length);
        const processedData = enrichThreatData(blockchainData);
        setEnrichedData(processedData);
        console.log('Enriched blockchain data:', processedData);
        
        // Automatically provide insights when data is first loaded
        if (processedData && processedData.insights && processedData.insights.length > 0 && messages.length <= 1) {
          const insightsMessage: Message = {
            id: Date.now().toString(),
            content: `I've analyzed your blockchain data and found some important security insights:\n\n${processedData.insights.join('\n\n')}`,
            role: 'bot',
            timestamp: new Date()
          };
          setMessages(prev => [...prev, insightsMessage]);
        }
        
        // Force local connection status to true if we have valid blockchain data
        setLocalConnectionStatus(true);
      } catch (error) {
        console.error('Error processing blockchain data:', error);
      }
    } else {
      console.log('No blockchain data available or chain is empty');
    }
  }, [blockchainData]);
  
  // Auto-scroll to bottom of messages
  useEffect(() => {
    if (messagesEndRef.current) {
      messagesEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [messages]);

  // Focus input on load
  useEffect(() => {
    if (inputRef.current) {
      inputRef.current.focus();
    }
  }, []);
  
  // Function to analyze blockchain data and generate responses
  const analyzeBlockchainData = (userQuery: string) => {
    console.log('Analyzing query:', userQuery);
    
    if (!blockchainData || blockchainData.chain.length === 0) {
      return "I don't have any blockchain data to analyze. Please ensure you're connected to a blockchain source.";
    }
    
    // Normalize the query to lowercase for easier pattern matching
    const normalizedQuery = userQuery.toLowerCase();
    
    // Extract threat data using utility function
    const threatData = extractThreatData(blockchainData);
    console.log('Analyzed threat blocks:', threatData.length);
    
    // Check if query is asking for specific attack type details
    const attackTypeMatch = normalizedQuery.match(/(?:about|details on|info on|explain|what is|analyze)\s+([a-z\s-]+(?:attack|injection|exploit|vulnerability|overflow|xss|csrf|ddos))/i);
    if (attackTypeMatch) {
      const attackType = attackTypeMatch[1].trim();
      const matchingThreats = getThreatDetailsByAttackType(threatData, attackType);
      
      if (matchingThreats.length > 0) {
        const mitigations = getThreatMitigationSuggestions(attackType);
        
        return `I found ${matchingThreats.length} instances of ${attackType} in your blockchain data.\n\n` +
          `Most recent example:\n` +
          `- IP: ${matchingThreats[0].ip}\n` +
          `- Severity: ${matchingThreats[0].severity}\n` +
          `- Timestamp: ${new Date(matchingThreats[0].timestamp).toLocaleString()}\n\n` +
          `Recommended mitigations:\n${mitigations.map(m => `- ${m}`).join('\n')}`;
      }
    }
    
    // Handle different user query intents
    if (normalizedQuery.includes('latest') || normalizedQuery.includes('recent') || normalizedQuery.includes('last')) {
      const latestThreats = threatData.slice(-3).reverse();
      if (latestThreats.length === 0) return "I haven't detected any recent threats in the blockchain data.";
      
      return `Here are the latest threats I've detected:\n\n${latestThreats.map((threat, i) => 
        `${i+1}. ${threat.attack_type} (${threat.severity} severity) from IP ${threat.ip}`
      ).join('\n')}`;
    }
    
    if (normalizedQuery.includes('common') || normalizedQuery.includes('frequent') || normalizedQuery.includes('pattern')) {
      // Use utility function to analyze attack patterns
      const sortedAttacks = analyzeAttackPatterns(threatData).slice(0, 3);
      
      if (sortedAttacks.length === 0) return "I haven't detected any attack patterns in the blockchain data.";
      
      // Add mitigation suggestions for the most common attack
      const mostCommonAttack = sortedAttacks[0][0] as string;
      const mitigations = getThreatMitigationSuggestions(mostCommonAttack);
      
      return `I've analyzed the blockchain data and found these common attack patterns:\n\n${
        sortedAttacks.map(([attackType, count], i) => 
          `${i+1}. ${attackType}: ${count} occurrences`
        ).join('\n')
      }\n\nFor the most common attack (${mostCommonAttack}), I recommend:\n${
        mitigations.map(m => `- ${m}`).slice(0, 2).join('\n')
      }`;
    }
    
    if (normalizedQuery.includes('high') || normalizedQuery.includes('severe') || normalizedQuery.includes('critical')) {
      const highSeverityThreats = threatData.filter(threat => 
        threat.severity === 'High'
      );
      
      if (highSeverityThreats.length === 0) return "Good news! I haven't detected any high severity threats.";
      
      // Add mitigation suggestions for the most recent high severity attack
      const latestHighSeverity = highSeverityThreats[highSeverityThreats.length - 1];
      const mitigations = getThreatMitigationSuggestions(latestHighSeverity.attack_type);
      
      return `I've detected ${highSeverityThreats.length} high severity threats in the blockchain data. Here are the most recent ones:\n\n${
        highSeverityThreats.slice(-3).reverse().map((threat, i) => 
          `${i+1}. ${threat.attack_type} from IP ${threat.ip} (${new Date(threat.timestamp).toLocaleString()})`
        ).join('\n')
      }\n\nTo mitigate the latest high severity threat (${latestHighSeverity.attack_type}):\n${
        mitigations.map(m => `- ${m}`).slice(0, 2).join('\n')
      }`;
    }
    
    if (normalizedQuery.includes('port') || normalizedQuery.includes('protocol')) {
      // Use utility functions to analyze protocols and ports
      const topPorts = analyzePortTargets(threatData).slice(0, 3);
      const topProtocols = analyzeProtocolUsage(threatData).slice(0, 3);
      
      return `Based on my analysis of the blockchain data:\n\nMost targeted ports:
${topPorts.map(([port, count], i) => `${i+1}. Port ${port}: ${count} attacks`).join('\n')}
\nMost used protocols:
${topProtocols.map(([protocol, count], i) => `${i+1}. ${protocol}: ${count} attacks`).join('\n')}
\nI recommend reviewing your firewall rules for these ports and protocols.`;
    }
    
    if (normalizedQuery.includes('insight') || normalizedQuery.includes('analyze') || normalizedQuery.includes('assessment')) {
      const insights = generateSecurityInsights(threatData);
      
      if (insights.length === 0) return "I couldn't generate any significant insights from the available data.";
      
      return `Based on my analysis of your blockchain threat data, here are key insights:\n\n${
        insights.map((insight, i) => `${i+1}. ${insight}`).join('\n\n')
      }`;
    }
    
    if (normalizedQuery.includes('mitigate') || normalizedQuery.includes('prevent') || normalizedQuery.includes('protect') || normalizedQuery.includes('defend')) {
      // Find the most common attack type and provide mitigation
      const attackPatterns = analyzeAttackPatterns(threatData);
      
      if (attackPatterns.length === 0) return "I don't have enough data to suggest specific mitigations.";
      
      const commonAttacks = attackPatterns.slice(0, 2);
      let response = "Based on your blockchain threat data, here are mitigation strategies for your most common attack types:\n\n";
      
      commonAttacks.forEach(([attackType, count], i) => {
        const mitigations = getThreatMitigationSuggestions(attackType as string);
        response += `For ${attackType} (${count} occurrences):\n${
          mitigations.map(m => `- ${m}`).join('\n')
        }\n\n`;
      });
      
      return response;
    }
    
    if (normalizedQuery.includes('summary') || normalizedQuery.includes('overview')) {
      // Use utility function to generate summary
      const summary = generateThreatSummary(threatData);
      
      if (!summary) return "I don't have any threat data to summarize.";
      
      // Format latest attack information
      let latestAttackStr = "No attacks recorded";
      if (summary.latestThreat) {
        latestAttackStr = `${summary.latestThreat.attack_type} (${summary.latestThreat.severity}) at ${new Date(summary.latestThreat.timestamp).toLocaleString()}`;
      }
      
      // Get attack patterns
      const attackPatterns = analyzeAttackPatterns(threatData).slice(0, 3);
      const attackPatternsStr = attackPatterns.map(([type, count]) => 
        `${type}: ${count} (${Math.round((count as number / summary.total) * 100)}%)`
      ).join('\n• ');
      
      return `Here's a comprehensive summary of the blockchain threat data:\n\n• Total attacks: ${summary.total}
• High severity: ${summary.highSeverity} (${Math.round((summary.highSeverity / summary.total) * 100)}%)
• Medium severity: ${summary.mediumSeverity} (${Math.round((summary.mediumSeverity / summary.total) * 100)}%)
• Low severity: ${summary.lowSeverity} (${Math.round((summary.lowSeverity / summary.total) * 100)}%)
• Unique attacker IPs: ${summary.uniqueIPs}
• Latest attack: ${latestAttackStr}

Most common attack types:
• ${attackPatternsStr}

What specific aspect would you like me to analyze further?`;
    }
    
    // Default response if we can't match a specific intent
    return "I can analyze your blockchain threat data. Try asking about:\n\n• Recent threats\n• Common attack patterns\n• High severity threats\n• Port/protocol analysis\n• Security insights\n• Mitigation strategies\n• Overall summary";
  };
  
  // Handle user sending a message
  const handleSendMessage = () => {
    if (!input.trim()) return;
    
    console.log('Sending message:', input);
    
    // Add user message
    const userMessage: Message = {
      id: Date.now().toString(),
      role: 'user',
      content: input,
      timestamp: new Date()
    };
    
    setMessages(prev => [...prev, userMessage]);
    setInput('');
    setIsLoading(true);
    
    // Generate response with a slight delay to simulate processing
    setTimeout(() => {
      // Generate response based on blockchain data
      let botResponse = '';
      
      if (!localConnectionStatus && (!blockchainData || !blockchainData.chain || blockchainData.chain.length === 0)) {
        botResponse = "I'm unable to analyze blockchain data because there's no active connection. Please connect to a blockchain data source first.";
      } else {
        botResponse = analyzeBlockchainData(userMessage.content);
      }
      
      const botMessage: Message = {
        id: (Date.now() + 1).toString(),
        role: 'bot',
        content: botResponse,
        timestamp: new Date()
      };
      
      setMessages(prev => [...prev, botMessage]);
      setIsLoading(false);
    }, 1000);
  };
  
  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  };
  
  // Handle disconnect message
  const renderDisconnectedWarning = () => {
    // Only show disconnected warning if both checks fail
    if (!localConnectionStatus && (!blockchainData || !blockchainData.chain || blockchainData.chain.length === 0)) {
      return (
        <div className="rounded-lg px-4 py-4 bg-amber-500/10 text-amber-600 dark:text-amber-400 mb-4 flex items-start gap-3 text-sm border border-amber-200 dark:border-amber-800/30">
          <AlertCircle className="h-6 w-6 flex-shrink-0 mt-0.5" />
          <div className="flex-1">
            <p className="font-medium mb-2 text-base">Blockchain connection required</p>
            <p className="mb-2">To use the CyberGuard AI Assistant, you need to connect to a blockchain data source. This will allow me to analyze threat data and provide security insights.</p>
            <div className="flex flex-col sm:flex-row gap-2">
              <Button 
                variant="outline" 
                size="sm" 
                className="h-9 border-amber-200 dark:border-amber-800/50 bg-amber-500/5 hover:bg-amber-500/10"
                onClick={() => document.getElementById('settings-trigger')?.click()}
              >
                <Database className="h-4 w-4 mr-2" />
                Configure Connection
              </Button>
              <Button
                variant="outline"
                size="sm"
                className="h-9 border-amber-200 dark:border-amber-800/50 bg-amber-500/5 hover:bg-amber-500/10"
                onClick={() => window.location.href = '/'}
              >
                <Shield className="h-4 w-4 mr-2" />
                Return to Dashboard
              </Button>
            </div>
          </div>
        </div>
      );
    }
    return null;
  };
  
  // Generate suggested queries based on available data
  const renderSuggestedQueries = () => {
    const defaultSuggestions = [
      { text: "Analyze recent security threats", icon: <Clock className="h-3.5 w-3.5" /> },
      { text: "What are the common attack patterns?", icon: <Repeat className="h-3.5 w-3.5" /> },
      { text: "Generate threat intelligence summary", icon: <ListChecks className="h-3.5 w-3.5" /> },
      { text: "How to mitigate these vulnerabilities?", icon: <Shield className="h-3.5 w-3.5" /> },
      { text: "Show high severity threats", icon: <AlertCircle className="h-3.5 w-3.5" /> },
      { text: "What ports are being targeted?", icon: <Database className="h-3.5 w-3.5" /> },
      { text: "Give me a security assessment", icon: <ListChecks className="h-3.5 w-3.5" /> },
      { text: "Show attack trends over time", icon: <LineChart className="h-3.5 w-3.5" /> },
      { text: "What are the latest critical alerts?", icon: <AlertOctagon className="h-3.5 w-3.5" /> },
      { text: "Analyze protocol usage patterns", icon: <Network className="h-3.5 w-3.5" /> }
    ];
    
    // Always show suggestions
    const suggestions = [...defaultSuggestions];
    
    // Add personalized suggestion based on data if available
    if (enrichedData && enrichedData.insights && enrichedData.insights.length > 0) {
      suggestions.push({ 
        text: "Provide security insights", 
        icon: <Lightbulb className="h-3.5 w-3.5" /> 
      });
    }
    
    return (
      <div className="flex flex-wrap gap-1.5">
        {suggestions.map((suggestion, i) => (
          <Button
            key={i}
            variant="outline"
            size="sm"
            className="text-xs h-8 flex items-center gap-1.5 px-3 py-1 border-slate-200 dark:border-slate-700 bg-white/80 dark:bg-slate-800/80 hover:bg-gradient-to-r hover:from-blue-50 hover:to-indigo-50 dark:hover:from-blue-900/20 dark:hover:to-indigo-900/20 transition-all"
            onClick={() => {
              setInput(suggestion.text);
              // Trigger send message after a short delay to let state update
              setTimeout(() => handleSendMessage(), 100);
            }}
            disabled={!localConnectionStatus && (!blockchainData || !blockchainData.chain || blockchainData.chain.length === 0)}
          >
            <span className="text-blue-600 dark:text-blue-400 flex-shrink-0">{suggestion.icon}</span>
            <span className="truncate">{suggestion.text}</span>
          </Button>
        ))}
      </div>
    );
  };
  
  // Add navigation handler
  const handleNavigation = (path: string) => {
    window.location.href = path;
  };

  return (
    <div className="fixed inset-0 flex flex-col bg-white dark:bg-slate-950 z-50">
      {/* Header */}
      <div className="flex flex-col border-b border-slate-200 dark:border-slate-800">
        <div className="flex items-center justify-between px-4 py-3 bg-gradient-to-r from-blue-50 to-indigo-50 dark:from-blue-950/40 dark:to-indigo-950/40">
          <div className="flex items-center gap-4">
            {onBack && (
              <Button 
                variant="ghost" 
                size="icon" 
                className="h-9 w-9" 
                onClick={onBack}
              >
                <ChevronLeft className="h-5 w-5" />
              </Button>
            )}
            <div className="flex items-center gap-3">
              <div className="h-10 w-10 rounded-full bg-blue-600/10 dark:bg-blue-500/20 flex items-center justify-center">
                <Shield className="h-5 w-5 text-blue-600 dark:text-blue-400" />
              </div>
              <div>
                <h1 className="text-xl font-semibold flex items-center gap-2">
                  CyberGuard Assistant 
                  <Badge variant="outline" className="h-5 font-normal text-[10px] bg-blue-50 dark:bg-blue-900/30 border-blue-200 dark:border-blue-800 text-blue-700 dark:text-blue-400">AI</Badge>
                </h1>
                <p className="text-sm text-slate-500 dark:text-slate-400">Advanced security analysis and threat intelligence</p>
              </div>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2">
              <Button
                variant="ghost"
                size="sm"
                className="flex items-center gap-2 text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100"
                onClick={() => handleNavigation('/')}
              >
                <LayoutDashboard className="h-4 w-4" />
                <span>Dashboard</span>
              </Button>
              <Button
                variant="ghost"
                size="sm"
                className="flex items-center gap-2 text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100"
                onClick={() => handleNavigation('/blockchain-analytics')}
              >
                <LineChart className="h-4 w-4" />
                <span>Analytics</span>
              </Button>
              <Button
                variant="ghost"
                size="sm"
                className="flex items-center gap-2 text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100"
                onClick={() => handleNavigation('/cyberguard-dashboard')}
              >
                <Shield className="h-4 w-4" />
                <span>CyberGuard</span>
              </Button>
              <Button
                variant="ghost"
                size="sm"
                className="flex items-center gap-2 text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100"
                onClick={() => document.getElementById('settings-trigger')?.click()}
              >
                <Settings className="h-4 w-4" />
                <span>Settings</span>
              </Button>
            </div>
            <Badge variant="outline" className={cn("px-3 py-1", {
              "bg-green-50 dark:bg-green-900/30 border-green-200 dark:border-green-800 text-green-700 dark:text-green-400": localConnectionStatus,
              "bg-red-50 dark:bg-red-900/30 border-red-200 dark:border-red-800 text-red-700 dark:text-red-400": !localConnectionStatus
            })}>
              {localConnectionStatus ? "Connected" : "Disconnected"}
            </Badge>
          </div>
        </div>
      </div>
      
      {/* Main content */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Messages container */}
        <ScrollArea className="flex-1 px-4 py-6 overflow-y-auto">
          {renderDisconnectedWarning()}
          
          {messages.length === 0 ? (
            <div className="flex flex-col gap-6 items-center justify-center h-full text-center p-6">
              <div className="w-24 h-24 rounded-full bg-gradient-to-br from-blue-100 to-indigo-100 dark:from-blue-900/30 dark:to-indigo-900/30 flex items-center justify-center shadow-sm">
                <Shield className="h-12 w-12 text-blue-600 dark:text-blue-400" />
              </div>
              <div className="space-y-3 max-w-lg">
                <h3 className="text-2xl font-semibold text-slate-900 dark:text-slate-100">CyberGuard Assistant</h3>
                <p className="text-slate-500 dark:text-slate-400">
                  Your AI-powered security analyst. Ask about threats, analyze vulnerabilities, or get advanced security insights from your blockchain data.
                </p>
              </div>
              <div className="mt-6 bg-gradient-to-r from-blue-50/50 to-indigo-50/50 dark:from-blue-900/10 dark:to-indigo-900/10 rounded-lg p-6 w-full max-w-2xl">
                <p className="text-sm font-medium text-slate-600 dark:text-slate-300 mb-4">Try asking about:</p>
                {renderSuggestedQueries()}
              </div>
            </div>
          ) : (
            <div className="space-y-6 max-w-3xl mx-auto">
              {messages.map((message) => (
                <div
                  key={message.id}
                  className={cn("flex", {
                    "justify-end": message.role === 'user',
                    "justify-start": message.role === 'bot',
                  })}
                >
                  <div
                    className={cn("max-w-[85%] px-5 py-4 rounded-2xl", {
                      "bg-gradient-to-r from-blue-600 to-indigo-600 text-white rounded-br-none shadow-md": message.role === 'user',
                      "bg-gradient-to-r from-slate-100 to-slate-50 dark:from-slate-800 dark:to-slate-800/80 text-slate-900 dark:text-slate-100 rounded-bl-none shadow-md": message.role === 'bot',
                    })}
                  >
                    <div className="whitespace-pre-line text-base">{message.content}</div>
                    <div className={cn("text-xs mt-2", {
                      "text-blue-100/70": message.role === 'user',
                      "text-slate-400 dark:text-slate-500": message.role === 'bot'
                    })}>
                      {message.timestamp.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}
                    </div>
                  </div>
                </div>
              ))}
              {isLoading && (
                <div className="flex justify-start">
                  <div className="max-w-[85%] px-5 py-4 rounded-2xl bg-gradient-to-r from-slate-100 to-slate-50 dark:from-slate-800 dark:to-slate-800/80 text-slate-900 dark:text-slate-100 rounded-bl-none shadow-md">
                    <div className="flex gap-2 items-center">
                      <span className="w-2.5 h-2.5 rounded-full bg-blue-400 dark:bg-blue-500 animate-pulse" style={{ animationDelay: '0ms' }}></span>
                      <span className="w-2.5 h-2.5 rounded-full bg-blue-400 dark:bg-blue-500 animate-pulse" style={{ animationDelay: '300ms' }}></span>
                      <span className="w-2.5 h-2.5 rounded-full bg-blue-400 dark:bg-blue-500 animate-pulse" style={{ animationDelay: '600ms' }}></span>
                    </div>
                  </div>
                </div>
              )}
              <div ref={messagesEndRef} />
            </div>
          )}
        </ScrollArea>
        
        {/* Suggestions */}
        {messages.length > 0 && (
          <div className="px-4 py-3 bg-gradient-to-r from-slate-50/80 to-slate-50/80 dark:from-slate-900/60 dark:to-slate-900/60 backdrop-blur-sm border-t border-slate-200 dark:border-slate-800">
            <div className="flex items-center mb-2 max-w-3xl mx-auto">
              <Lightbulb className="h-3.5 w-3.5 text-blue-500 mr-1.5" />
              <span className="text-xs font-medium text-slate-600 dark:text-slate-300">Security intelligence</span>
            </div>
            <div className="max-w-3xl mx-auto">
              {renderSuggestedQueries()}
            </div>
          </div>
        )}
        
        {/* Input area */}
        <form 
          onSubmit={(e) => {
            e.preventDefault();
            handleSendMessage();
          }}
          className="px-4 py-4 border-t border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-950"
        >
          <div className="max-w-3xl mx-auto flex gap-3">
            <Input
              ref={inputRef}
              placeholder="Ask about security threats or vulnerabilities..."
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              disabled={!localConnectionStatus && (!blockchainData || !blockchainData.chain || blockchainData.chain.length === 0)}
              className="flex-1 h-14 text-base border-slate-300 dark:border-slate-700 focus-visible:ring-blue-500 rounded-full px-6"
              aria-label="Chat message input"
            />
            <Button 
              type="submit" 
              size="icon"
              className="h-14 w-14 rounded-full bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700 text-white shadow-md"
              disabled={!localConnectionStatus && (!blockchainData || !blockchainData.chain || blockchainData.chain.length === 0)}
              aria-label="Send message"
            >
              <SendIcon className="h-6 w-6" />
              <span className="sr-only">Send</span>
            </Button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default ChatbotSuggester;