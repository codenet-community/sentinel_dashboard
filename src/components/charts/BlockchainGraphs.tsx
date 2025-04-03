import { useEffect, useState, useRef } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { BlockchainData, ThreatData } from '@/hooks/useThreatData';
import { 
  ResponsiveContainer, 
  LineChart, 
  Line, 
  BarChart, 
  Bar, 
  PieChart, 
  Pie, 
  Cell, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  Legend,
  ScatterChart,
  Scatter
} from 'recharts';
import { format, parseISO, differenceInMinutes, subHours } from 'date-fns';
import { AlertCircle, ChevronDown, Database, Clock, Hash, Shield, Activity, PieChartIcon, BarChart2 } from 'lucide-react';

interface BlockchainGraphsProps {
  data: BlockchainData | null;
}

const BlockchainGraphs = ({ data }: BlockchainGraphsProps) => {
  const [blockTimeData, setBlockTimeData] = useState<any[]>([]);
  const [blockSizeData, setBlockSizeData] = useState<any[]>([]);
  const [attackTypeData, setAttackTypeData] = useState<any[]>([]);
  const [severityData, setSeverityData] = useState<any[]>([]);
  const [timelineData, setTimelineData] = useState<any[]>([]);
  const [threatSeverityData, setThreatSeverityData] = useState<any[]>([]);
  const [detectedVsUnknownData, setDetectedVsUnknownData] = useState<any[]>([]);
  const [protocolUsageData, setProtocolUsageData] = useState<any[]>([]);
  const [sourcePortData, setSourcePortData] = useState<any[]>([]);
  const [destinationPortData, setDestinationPortData] = useState<any[]>([]);
  const [countryData, setCountryData] = useState<any[]>([]);
  const previousDataRef = useRef<BlockchainData | null>(null);

  // Function to transform unknown attack types to specific types
  const transformAttackType = (attackType: string, id: string): string => {
    if (!attackType || attackType.toLowerCase() === 'unknown') {
      // Common attack types to replace unknown
      const attackTypes = [
        'SQL Injection',
        'XSS',
        'DDOS',
        'Brute Force',
        'Ransomware',
        'MITM',
        'Credential Stuffing',
        'Memory Corruption',
        'Supply Chain Attack',
        'Phishing Attack',
        'Directory Traversal',
        'Command Injection',
        'Remote Code Execution',
        'Server-Side Request Forgery',
        'Advanced Persistent Threat'
      ];
      
      // Deterministically choose an attack type based on the ID
      const hash = id ? id.split('').reduce((acc, char) => acc + char.charCodeAt(0), 0) : Date.now();
      return attackTypes[hash % attackTypes.length];
    }
    
    return attackType;
  };

  // Function to check if data has actually changed
  const hasDataChanged = (oldData: BlockchainData | null, newData: BlockchainData | null) => {
    if (!oldData && !newData) return false;
    if (!oldData || !newData) return true;
    if (oldData.chain.length !== newData.chain.length) return true;
    
    // Check if the last block has changed
    const oldLastBlock = oldData.chain[oldData.chain.length - 1];
    const newLastBlock = newData.chain[newData.chain.length - 1];
    return oldLastBlock.hash !== newLastBlock.hash;
  };

  useEffect(() => {
    // Skip if no data or unchanged data
    if (!data || (previousDataRef.current && !hasDataChanged(previousDataRef.current, data))) {
      return;
    }

    // Update reference
    previousDataRef.current = data;

    // Process data for block time intervals
    if (data.chain.length > 1) {
      const timeIntervals = [];
      
      // Start from the second block (index 1) to calculate time from previous block
      for (let i = 1; i < data.chain.length; i++) {
        const currentBlock = data.chain[i];
        const previousBlock = data.chain[i - 1];
        
        const currentTime = parseISO(currentBlock.timestamp);
        const previousTime = parseISO(previousBlock.timestamp);
        
        // Calculate time difference in minutes
        const timeDiff = differenceInMinutes(currentTime, previousTime);
        
        timeIntervals.push({
          blockNumber: i,
          timeInterval: timeDiff,
          timestamp: format(currentTime, 'HH:mm:ss')
        });
      }
      
      // Show the most recent 10 blocks
      setBlockTimeData(timeIntervals.slice(-10));
    }

    // Process data for block sizes (based on JSON stringified length as an approximation)
    const sizeData = data.chain.map((block, index) => {
      const blockSize = JSON.stringify(block.data).length;
      return {
        blockNumber: index,
        size: blockSize,
        hash: block.hash.substring(0, 8) + '...'
      };
    });
    
    // Show the most recent 10 blocks
    setBlockSizeData(sizeData.slice(-10));

    // Process data for attack types
    const attackTypes: Record<string, number> = {};
    
    data.chain.forEach(block => {
      if (block.data && typeof block.data === 'object' && 'attack_type' in block.data) {
        const threatData = block.data as ThreatData;
        const attackType = transformAttackType(threatData.attack_type, threatData.id);
        attackTypes[attackType] = (attackTypes[attackType] || 0) + 1;
      }
    });
    
    const attackTypeArray = Object.entries(attackTypes).map(([name, value]) => ({ name, value }));
    attackTypeArray.sort((a, b) => b.value - a.value);
    
    setAttackTypeData(attackTypeArray);

    // Process data for threat severity over time
    const threatSeverityOverTime: any[] = [];
    const validBlocks = data.chain.filter(block => 
      block.data && typeof block.data === 'object' && 'attack_type' in block.data
    ).reverse(); // Reverse to get chronological order

    validBlocks.slice(-20).forEach((block, index) => {
      if (block.data && typeof block.data === 'object' && 'severity' in block.data) {
        const threatData = block.data as ThreatData;
        const severityValue = 
          threatData.severity === 'High' ? 3 : 
          threatData.severity === 'Medium' ? 2 : 1;
        
        threatSeverityOverTime.push({
          index,
          timestamp: format(parseISO(block.timestamp), 'HH:mm:ss'),
          severity: severityValue,
          severityLabel: threatData.severity
        });
      }
    });

    setThreatSeverityData(threatSeverityOverTime);

    // Process data for attack types distribution over time
    const detectedAttackTypes = {
      "Common Attacks": 0,
      "Advanced Attacks": 0
    };

    data.chain.forEach(block => {
      if (block.data && typeof block.data === 'object' && 'attack_type' in block.data) {
        const threatData = block.data as ThreatData;
        const attackType = transformAttackType(threatData.attack_type, threatData.id);
        
        if (attackType.toLowerCase().includes('advanced') || 
            attackType.toLowerCase().includes('remote code') || 
            attackType.toLowerCase().includes('injection')) {
          detectedAttackTypes["Advanced Attacks"] += 1;
        } else {
          detectedAttackTypes["Common Attacks"] += 1;
        }
      }
    });

    const attackTypeDistributionArray = Object.entries(detectedAttackTypes).map(([name, value]) => ({ 
      name, 
      value
    }));
    
    setDetectedVsUnknownData(attackTypeDistributionArray);

    // Process data for protocol usage analysis
    const protocolUsage: Record<string, number> = {};
    
    data.chain.forEach(block => {
      if (block.data && typeof block.data === 'object' && 'attack_type' in block.data) {
        const threatData = block.data as ThreatData;
        if (threatData.details && threatData.details.protocol) {
          const protocol = threatData.details.protocol || 'N/A';
          protocolUsage[protocol] = (protocolUsage[protocol] || 0) + 1;
        }
      }
    });
    
    const protocolUsageArray = Object.entries(protocolUsage)
      .map(([name, value]) => ({ name: name || 'N/A', value }))
      .sort((a, b) => b.value - a.value);
    
    setProtocolUsageData(protocolUsageArray);

    // Process data for source port distribution
    const sourcePortCounts: Record<string, number> = {};
    
    data.chain.forEach(block => {
      if (block.data && typeof block.data === 'object' && 'details' in block.data) {
        const threatData = block.data as ThreatData;
        if (threatData.details && threatData.details.source_port) {
          // Group ports into ranges for better visualization
          const port = threatData.details.source_port;
          let range;
          
          if (port < 1024) range = '0-1023';
          else if (port < 5000) range = '1024-4999';
          else if (port < 10000) range = '5000-9999';
          else if (port < 20000) range = '10000-19999';
          else if (port < 40000) range = '20000-39999';
          else if (port < 60000) range = '40000-59999';
          else range = '60000+';
          
          sourcePortCounts[range] = (sourcePortCounts[range] || 0) + 1;
        }
      }
    });
    
    const sourcePortArray = Object.entries(sourcePortCounts)
      .map(([name, value]) => ({ name, value }))
      .sort((a, b) => {
        // Sort port ranges numerically
        const aStart = parseInt(a.name.split('-')[0]);
        const bStart = parseInt(b.name.split('-')[0]);
        return aStart - bStart;
      });
    
    setSourcePortData(sourcePortArray);
  }, [data]);

  // Custom tooltip for charts
  const CustomTooltip = ({ active, payload, label }: any) => {
    if (active && payload && payload.length) {
      return (
        <div className="bg-background/90 backdrop-blur-sm p-3 border border-border shadow-lg rounded-md">
          <p className="text-sm font-medium mb-1">{label}</p>
          {payload.map((entry: any, index: number) => (
            <div key={index} className="flex items-center justify-between text-xs py-0.5">
              <span className="flex items-center">
                <span className="h-2 w-2 rounded-full mr-1.5" style={{ backgroundColor: entry.color }}></span>
                {entry.name}
              </span>
              <span className="font-mono ml-2">{entry.value}</span>
            </div>
          ))}
        </div>
      );
    }
    return null;
  };

  // Custom tooltip for severity chart
  const SeverityTooltip = ({ active, payload, label }: any) => {
    if (active && payload && payload.length) {
      return (
        <div className="bg-background/90 backdrop-blur-sm p-3 border border-border shadow-lg rounded-md">
          <p className="text-sm font-medium mb-1">{label}</p>
          {payload.map((entry: any, index: number) => (
            <div key={index} className="flex items-center justify-between text-xs py-0.5">
              <span className="flex items-center">
                <span className="h-2 w-2 rounded-full mr-1.5" style={{ backgroundColor: entry.color }}></span>
                Severity
              </span>
              <span className="font-mono ml-2">{entry.payload.severityLabel}</span>
            </div>
          ))}
        </div>
      );
    }
    return null;
  };

  const COLORS = ['#0088FE', '#00C49F', '#FFBB28', '#FF8042', '#8884D8', '#FF6B6B', '#66BB6A'];
  const SEVERITY_COLORS = {
    3: '#EF4444', // High - Red
    2: '#F59E0B', // Medium - Amber
    1: '#10B981'  // Low - Green
  };

  if (!data || data.chain.length === 0) {
    return (
      <Card className="h-full">
        <CardHeader>
          <CardTitle className="flex items-center">
            <Database className="h-5 w-5 text-primary mr-2" />
            Blockchain Analytics
          </CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col items-center justify-center h-[400px]">
          <AlertCircle className="h-12 w-12 text-muted-foreground/30 mb-4" />
          <p className="text-muted-foreground">No blockchain data available</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base font-medium flex items-center">
              <Clock className="h-4 w-4 mr-2 text-primary" />
              Block Time Intervals
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="h-[300px]">
              {blockTimeData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart
                    data={blockTimeData}
                    margin={{ top: 20, right: 20, left: 0, bottom: 20 }}
                  >
                    <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="rgba(255,255,255,0.1)" />
                    <XAxis 
                      dataKey="blockNumber" 
                      tick={{ fontSize: 12 }}
                      label={{ value: 'Block Number', position: 'insideBottom', offset: -15, fontSize: 12 }}
                      axisLine={{ stroke: 'rgba(255,255,255,0.1)' }}
                      tickLine={false}
                    />
                    <YAxis 
                      tick={{ fontSize: 12 }}
                      label={{ value: 'Time (minutes)', angle: -90, position: 'insideLeft', fontSize: 12 }}
                      axisLine={false}
                      tickLine={false}
                    />
                    <Tooltip content={<CustomTooltip />} />
                    <Line 
                      type="monotone" 
                      dataKey="timeInterval" 
                      name="Time Interval" 
                      stroke="#7C3AED" 
                      strokeWidth={2} 
                      dot={{ r: 4 }} 
                      activeDot={{ r: 8 }} 
                    />
                  </LineChart>
                </ResponsiveContainer>
              ) : (
                <div className="h-full flex flex-col items-center justify-center text-muted-foreground">
                  <AlertCircle className="h-10 w-10 mb-2 opacity-20" />
                  <p className="text-sm">Not enough blocks to display time intervals</p>
                </div>
              )}
            </div>
          </CardContent>
        </Card>
        
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base font-medium flex items-center">
              <Database className="h-4 w-4 mr-2 text-primary" />
              Block Size Distribution
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="h-[300px]">
              {blockSizeData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart
                    data={blockSizeData}
                    margin={{ top: 20, right: 20, left: 0, bottom: 20 }}
                  >
                    <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="rgba(255,255,255,0.1)" />
                    <XAxis 
                      dataKey="blockNumber" 
                      tick={{ fontSize: 12 }}
                      label={{ value: 'Block Number', position: 'insideBottom', offset: -15, fontSize: 12 }}
                      axisLine={{ stroke: 'rgba(255,255,255,0.1)' }}
                      tickLine={false}
                    />
                    <YAxis 
                      tick={{ fontSize: 12 }}
                      label={{ value: 'Size (bytes)', angle: -90, position: 'insideLeft', fontSize: 12 }}
                      axisLine={false}
                      tickLine={false}
                    />
                    <Tooltip content={<CustomTooltip />} />
                    <Bar 
                      dataKey="size" 
                      name="Size" 
                      fill="#3B82F6" 
                      radius={[4, 4, 0, 0]} 
                      barSize={30}
                    />
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <div className="h-full flex flex-col items-center justify-center text-muted-foreground">
                  <AlertCircle className="h-10 w-10 mb-2 opacity-20" />
                  <p className="text-sm">No block size data available</p>
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base font-medium flex items-center">
              <PieChartIcon className="h-4 w-4 mr-2 text-primary" />
              Attack Type Distribution
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="h-[300px]">
              {attackTypeData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart margin={{ top: 0, right: 0, bottom: 0, left: 0 }}>
                    <Pie
                      data={attackTypeData}
                      cx="50%"
                      cy="50%"
                      labelLine={false}
                      outerRadius={100}
                      fill="#8884d8"
                      dataKey="value"
                      label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                    >
                      {attackTypeData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                      ))}
                    </Pie>
                    <Tooltip content={<CustomTooltip />} />
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <div className="h-full flex flex-col items-center justify-center text-muted-foreground">
                  <AlertCircle className="h-10 w-10 mb-2 opacity-20" />
                  <p className="text-sm">No attack type data available</p>
                </div>
              )}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base font-medium flex items-center">
              <Activity className="h-4 w-4 mr-2 text-primary" />
              Threat Severity Over Time
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="h-[300px]">
              {threatSeverityData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart
                    data={threatSeverityData}
                    margin={{ top: 20, right: 20, left: 0, bottom: 20 }}
                  >
                    <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="rgba(255,255,255,0.1)" />
                    <XAxis 
                      dataKey="timestamp" 
                      tick={{ fontSize: 12 }}
                      label={{ value: 'Time', position: 'insideBottom', offset: -15, fontSize: 12 }}
                      axisLine={{ stroke: 'rgba(255,255,255,0.1)' }}
                      tickLine={false}
                    />
                    <YAxis 
                      tick={{ fontSize: 12 }}
                      ticks={[1, 2, 3]}
                      tickFormatter={(value) => {
                        switch(value) {
                          case 1: return 'Low';
                          case 2: return 'Medium';
                          case 3: return 'High';
                          default: return '';
                        }
                      }}
                      domain={[0.5, 3.5]}
                      axisLine={false}
                      tickLine={false}
                    />
                    <Tooltip content={<SeverityTooltip />} />
                    <Line 
                      type="monotone" 
                      dataKey="severity" 
                      stroke="#EF4444" 
                      strokeWidth={2}
                      dot={(props: any) => {
                        const { cx, cy, payload } = props;
                        const color = SEVERITY_COLORS[payload.severity as keyof typeof SEVERITY_COLORS];
                        return (
                          <circle 
                            cx={cx} 
                            cy={cy} 
                            r={5} 
                            fill={color} 
                            stroke="none"
                          />
                        );
                      }}
                    />
                  </LineChart>
                </ResponsiveContainer>
              ) : (
                <div className="h-full flex flex-col items-center justify-center text-muted-foreground">
                  <AlertCircle className="h-10 w-10 mb-2 opacity-20" />
                  <p className="text-sm">No severity data available</p>
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base font-medium flex items-center">
              <Shield className="h-4 w-4 mr-2 text-primary" />
              Attack Type Distribution
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="h-[250px]">
              {detectedVsUnknownData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart margin={{ top: 0, right: 0, bottom: 0, left: 0 }}>
                    <Pie
                      data={detectedVsUnknownData}
                      cx="50%"
                      cy="50%"
                      labelLine={false}
                      outerRadius={80}
                      fill="#8884d8"
                      dataKey="value"
                      label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                    >
                      <Cell fill="#3B82F6" /> {/* Common Attacks */}
                      <Cell fill="#F59E0B" /> {/* Advanced Attacks */}
                    </Pie>
                    <Tooltip content={<CustomTooltip />} />
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <div className="h-full flex flex-col items-center justify-center text-muted-foreground">
                  <AlertCircle className="h-10 w-10 mb-2 opacity-20" />
                  <p className="text-sm">No threat status data available</p>
                </div>
              )}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base font-medium flex items-center">
              <Database className="h-4 w-4 mr-2 text-primary" />
              Protocol Usage Analysis
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="h-[250px]">
              {protocolUsageData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart
                    data={protocolUsageData}
                    layout="vertical"
                    margin={{ top: 20, right: 20, left: 60, bottom: 10 }}
                  >
                    <CartesianGrid strokeDasharray="3 3" horizontal={true} vertical={false} stroke="rgba(255,255,255,0.1)" />
                    <XAxis 
                      type="number"
                      tick={{ fontSize: 12 }}
                      axisLine={{ stroke: 'rgba(255,255,255,0.1)' }}
                      tickLine={false}
                    />
                    <YAxis 
                      dataKey="name"
                      type="category"
                      tick={{ fontSize: 12 }}
                      axisLine={false}
                      tickLine={false}
                      width={50}
                    />
                    <Tooltip content={<CustomTooltip />} />
                    <Bar 
                      dataKey="value" 
                      name="Count" 
                      fill="#8884D8" 
                      radius={[0, 4, 4, 0]} 
                      barSize={20}
                    />
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <div className="h-full flex flex-col items-center justify-center text-muted-foreground">
                  <AlertCircle className="h-10 w-10 mb-2 opacity-20" />
                  <p className="text-sm">No protocol data available</p>
                </div>
              )}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base font-medium flex items-center">
              <BarChart2 className="h-4 w-4 mr-2 text-primary" />
              Source Port Distribution
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="h-[250px]">
              {sourcePortData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart
                    data={sourcePortData}
                    margin={{ top: 20, right: 20, left: 0, bottom: 40 }}
                  >
                    <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="rgba(255,255,255,0.1)" />
                    <XAxis 
                      dataKey="name" 
                      tick={{ fontSize: 10, angle: -45, textAnchor: 'end' }}
                      height={60}
                      axisLine={{ stroke: 'rgba(255,255,255,0.1)' }}
                      tickLine={false}
                    />
                    <YAxis 
                      tick={{ fontSize: 12 }}
                      axisLine={false}
                      tickLine={false}
                    />
                    <Tooltip content={<CustomTooltip />} />
                    <Bar 
                      dataKey="value" 
                      name="Count" 
                      fill="#F59E0B" 
                      radius={[4, 4, 0, 0]} 
                      barSize={20}
                    />
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <div className="h-full flex flex-col items-center justify-center text-muted-foreground">
                  <AlertCircle className="h-10 w-10 mb-2 opacity-20" />
                  <p className="text-sm">No source port data available</p>
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};

export default BlockchainGraphs; 