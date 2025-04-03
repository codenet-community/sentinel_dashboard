
import { useEffect, useRef, useState } from 'react';
import { format } from 'date-fns';
import { Activity, ArrowUpRight, ExternalLink } from 'lucide-react';
import { ThreatData } from '@/hooks/useThreatData';

interface LiveAttackFeedProps {
  threats: ThreatData[];
}

const SeverityBadge = ({ severity }: { severity: 'High' | 'Medium' | 'Low' }) => {
  const baseClasses = "inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium";
  
  switch (severity) {
    case 'High':
      return <span className={`${baseClasses} bg-severity-high/10 text-severity-high`}>High</span>;
    case 'Medium':
      return <span className={`${baseClasses} bg-severity-medium/10 text-severity-medium`}>Medium</span>;
    case 'Low':
      return <span className={`${baseClasses} bg-severity-low/10 text-severity-low`}>Low</span>;
    default:
      return null;
  }
};

const StatusBadge = ({ status }: { status: string }) => {
  const isMitigated = status === 'Mitigated';
  const baseClasses = "inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium";
  
  return (
    <span className={`${baseClasses} ${isMitigated ? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400' : 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400'}`}>
      {status}
    </span>
  );
};

const AttackItem = ({ threat, isNew = false }: { threat: ThreatData; isNew?: boolean }) => {
  const [highlight, setHighlight] = useState(isNew);
  
  useEffect(() => {
    if (isNew) {
      const timer = setTimeout(() => {
        setHighlight(false);
      }, 3000);
      
      return () => clearTimeout(timer);
    }
  }, [isNew]);
  
  const formattedDate = format(new Date(threat.timestamp), 'MMM dd, HH:mm:ss');
  
  return (
    <div className={`p-4 border-b border-border transition-colors duration-1000 ${highlight ? 'bg-primary/5' : ''}`}>
      <div className="flex justify-between items-start mb-2">
        <div>
          <div className="flex items-center">
            <span className="font-medium">{threat.attack_type}</span>
            {isNew && (
              <span className="ml-2 inline-flex items-center px-1.5 py-0.5 rounded text-xs font-medium bg-primary/10 text-primary animate-pulse-subtle">
                New
              </span>
            )}
          </div>
          <div className="text-sm text-muted-foreground mt-0.5">
            {formattedDate}
          </div>
        </div>
        <div className="flex space-x-2">
          <SeverityBadge severity={threat.severity} />
          <StatusBadge status={threat.status} />
        </div>
      </div>
      
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-3">
        <div className="text-sm">
          <div className="flex items-center text-muted-foreground">
            <span className="w-24">IP Address</span>
            <span className="font-mono">{threat.ip}</span>
          </div>
          <div className="flex items-center text-muted-foreground mt-1">
            <span className="w-24">Method</span>
            <span className="font-mono">{threat.details.method}</span>
          </div>
        </div>
        
        <div className="text-sm">
          <div className="flex items-center text-muted-foreground">
            <span className="w-24">Path</span>
            <span className="font-mono truncate">{threat.details.url_path}</span>
          </div>
          <div className="flex items-center text-muted-foreground mt-1">
            <span className="w-24">Port</span>
            <span className="font-mono">{threat.details.source_port} → {threat.details.destination_port}</span>
          </div>
        </div>
      </div>
      
      <div className="mt-2 text-sm text-muted-foreground truncate">
        <span className="w-24 inline-block">User Agent</span>
        <span className="font-mono text-xs">{threat.details.user_agent}</span>
      </div>
      
      <div className="mt-3 flex justify-end">
        <button className="inline-flex items-center text-xs text-primary hover:text-primary/80 transition-colors">
          View details
          <ArrowUpRight className="ml-1 h-3 w-3" />
        </button>
      </div>
    </div>
  );
};

const LiveAttackFeed = ({ threats }: LiveAttackFeedProps) => {
  const [newThreats, setNewThreats] = useState<string[]>([]);
  const prevThreatsRef = useRef<ThreatData[]>([]);
  const containerRef = useRef<HTMLDivElement>(null);
  
  useEffect(() => {
    // Check for new threats by comparing with previous threats
    if (prevThreatsRef.current.length > 0) {
      const prevIds = new Set(prevThreatsRef.current.map(t => t.id));
      const newIds = threats
        .filter(t => !prevIds.has(t.id))
        .map(t => t.id);
      
      if (newIds.length > 0) {
        setNewThreats(prev => [...newIds, ...prev]);
        
        // Clear "new" status after 10 seconds
        setTimeout(() => {
          setNewThreats(prev => prev.filter(id => !newIds.includes(id)));
        }, 10000);
      }
    }
    
    prevThreatsRef.current = threats;
  }, [threats]);
  
  return (
    <div className="h-full flex flex-col">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-lg font-medium">Live Attack Feed</h2>
        <div className="flex items-center text-sm text-muted-foreground">
          <Activity className="h-4 w-4 mr-1 text-primary animate-pulse" />
          <span>Live</span>
        </div>
      </div>
      
      <div className="glass-card rounded-lg overflow-hidden flex-1">
        <div className="p-3 bg-muted/50 border-b border-border flex justify-between items-center">
          <div className="text-sm font-medium">Recent Attacks</div>
          <button className="inline-flex items-center text-xs text-muted-foreground hover:text-foreground transition-colors">
            <ExternalLink className="h-3 w-3 mr-1" />
            Expand
          </button>
        </div>
        
        <div 
          ref={containerRef}
          className="overflow-y-auto max-h-[calc(100%-40px)] overscroll-contain"
          style={{ scrollbarWidth: 'thin' }}
        >
          {threats.length > 0 ? (
            threats.map(threat => (
              <AttackItem 
                key={threat.id} 
                threat={threat} 
                isNew={newThreats.includes(threat.id)}
              />
            ))
          ) : (
            <div className="p-8 text-center text-muted-foreground">
              <p>No attack data available</p>
              <p className="text-sm mt-1">Connect to data source to view attacks</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default LiveAttackFeed;
