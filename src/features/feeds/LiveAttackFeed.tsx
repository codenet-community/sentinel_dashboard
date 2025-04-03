import { useState, useEffect } from 'react';
import { ThreatData } from '@/hooks/useThreatData';
import { Shield, AlertTriangle, CheckCircle, Filter, Clock, Server, Zap } from 'lucide-react';
import { format } from 'date-fns';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Badge } from '@/components/ui/badge';
import { motion } from 'framer-motion';
import { ATTACK_TYPES, transformAttackType, generateConsistentIP, addBlockedIP } from '@/utils/attackTypes';

interface LiveAttackFeedProps {
  threats: ThreatData[];
}

export const LiveAttackFeed = ({ threats }: LiveAttackFeedProps) => {
  const [filter, setFilter] = useState<'all' | 'high' | 'medium' | 'low'>('all');
  
  const getIconForAttackType = (attackType: string) => {
    const transformedType = transformAttackType(attackType, attackType);
    switch (transformedType.toLowerCase()) {
      case 'sql injection':
        return <Server className="h-4 w-4" />;
      case 'xss':
        return <AlertTriangle className="h-4 w-4" />;
      case 'ddos':
        return <Zap className="h-4 w-4" />;
      case 'ransomware':
        return <CheckCircle className="h-4 w-4" />;
      default:
        return <Shield className="h-4 w-4" />;
    }
  };
  
  useEffect(() => {
    // Add all malicious IPs to the blocked list
    threats.forEach(threat => {
      if (threat.attack_type.toLowerCase() === 'unknown' || !threat.ip) {
        const ip = generateConsistentIP(threat.id);
        addBlockedIP(ip);
      } else {
        // Add any malicious IP to the blocked list
        addBlockedIP(threat.ip);
      }
    });
  }, [threats]);
  
  // Process the threats to replace unknown attack types and ensure consistent IPs
  const processedThreats = threats.map(threat => {
    const transformedAttackType = transformAttackType(threat.attack_type, threat.id);
    
    // Generate consistent IP if it's an unknown attack type or missing IP
    let ip = threat.ip;
    if (threat.attack_type.toLowerCase() === 'unknown' || !threat.ip) {
      ip = generateConsistentIP(threat.id);
    }
    
    // Transform Unknown status to Detected
    const status = threat.status.toLowerCase() === 'unknown' ? 'Detected' : threat.status;
    
    return {
      ...threat,
      attack_type: transformedAttackType,
      ip,
      status
    };
  });
  
  const filteredThreats = processedThreats.filter(threat => {
    if (filter === 'all') return true;
    return threat.severity.toLowerCase() === filter.toLowerCase();
  }).sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
  
  const getSeverityColor = (severity: 'High' | 'Medium' | 'Low') => {
    switch (severity) {
      case 'High':
        return 'bg-red-500 text-white';
      case 'Medium':
        return 'bg-orange-500 text-white';
      case 'Low':
        return 'bg-green-500 text-white';
      default:
        return 'bg-blue-500 text-white';
    }
  };
  
  const getStatusLabel = (status: string) => {
    return status.toLowerCase() === 'unknown' ? 'Detected' : status;
  }
  
  const getStatusColor = (status: string) => {
    const formattedStatus = status.toLowerCase() === 'unknown' ? 'detected' : status.toLowerCase();
    return formattedStatus === 'mitigated' 
      ? 'bg-teal-500/10 text-teal-500 border-teal-500/30'
      : 'bg-red-500/10 text-red-500 border-red-500/30';
  };
  
  const getAttackTypeLabel = (attackType: string) => {
    // We've already transformed the attack type in processedThreats
    return attackType.toLowerCase() === 'unknown' ? 'Detected' : attackType;
  }
  
  return (
    <Card className="h-full flex flex-col">
      <CardHeader className="pb-2 flex-shrink-0">
        <div className="flex justify-between items-center">
          <CardTitle className="text-lg flex items-center">
            <Shield className="h-5 w-5 text-primary mr-2" />
            Live Attack Feed
          </CardTitle>
          <div className="flex gap-1 text-xs">
            <button
              onClick={() => setFilter('all')}
              className={`px-2 py-1 rounded ${filter === 'all' ? 'bg-primary/20 text-primary' : 'hover:bg-muted/50'}`}
            >
              All
            </button>
            <button
              onClick={() => setFilter('high')}
              className={`px-2 py-1 rounded ${filter === 'high' ? 'bg-red-500/20 text-red-500' : 'hover:bg-muted/50'}`}
            >
              High
            </button>
            <button
              onClick={() => setFilter('medium')}
              className={`px-2 py-1 rounded ${filter === 'medium' ? 'bg-orange-500/20 text-orange-500' : 'hover:bg-muted/50'}`}
            >
              Medium
            </button>
            <button
              onClick={() => setFilter('low')}
              className={`px-2 py-1 rounded ${filter === 'low' ? 'bg-green-500/20 text-green-500' : 'hover:bg-muted/50'}`}
            >
              Low
            </button>
          </div>
        </div>
      </CardHeader>
      <CardContent className="p-0 flex-grow relative">
        <ScrollArea className="h-full max-h-[calc(100%-28px)] pb-4">
          <div className="p-4 space-y-3">
            {filteredThreats.length > 0 ? (
              filteredThreats.map((threat, index) => (
                <motion.div
                  key={threat.id}
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{
                    duration: 0.3,
                    delay: index * 0.05,
                    ease: "easeOut"
                  }}
                  className="threat-item border border-border/50 p-3 rounded-md hover:bg-muted/30 transition-colors"
                >
                  <div className="flex justify-between items-start mb-2">
                    <div className="flex items-center">
                      <div className={`mr-2 p-1 rounded-full ${getSeverityColor(threat.severity)}`}>
                        {getIconForAttackType(threat.attack_type)}
                      </div>
                      <div>
                        <h4 className="text-sm font-medium">{getAttackTypeLabel(threat.attack_type)}</h4>
                        <div className="flex items-center text-xs text-muted-foreground">
                          <Clock className="h-3 w-3 mr-1" />
                          {format(new Date(threat.timestamp), 'MMM dd, HH:mm:ss')}
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge className={getSeverityColor(threat.severity)}>
                        {threat.severity}
                      </Badge>
                      <Badge variant="outline" className={getStatusColor(threat.status)}>
                        {getStatusLabel(threat.status)}
                      </Badge>
                    </div>
                  </div>
                  <div className="mt-2 pt-2 border-t border-border/30 text-xs">
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Source IP:</span>
                      <span className="font-mono">{threat.ip}</span>
                    </div>
                    <div className="flex justify-between mt-1">
                      <span className="text-muted-foreground">Path:</span>
                      <span className="font-mono truncate max-w-[200px]">{threat.details.url_path}</span>
                    </div>
                  </div>
                </motion.div>
              ))
            ) : (
              <div className="flex flex-col items-center justify-center p-8 text-center">
                <Filter className="h-12 w-12 text-muted-foreground/30 mb-2" />
                <p className="text-muted-foreground">No threats found matching the selected filter</p>
                <button
                  onClick={() => setFilter('all')}
                  className="mt-2 text-xs text-primary hover:underline"
                >
                  Show all threats
                </button>
              </div>
            )}
          </div>
        </ScrollArea>
      </CardContent>
    </Card>
  );
};

export default LiveAttackFeed;
