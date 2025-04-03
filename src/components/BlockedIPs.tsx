import { useEffect, useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Shield, X, Copy } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { blockedIPs } from '@/utils/attackTypes';
import { motion } from 'framer-motion';

export const BlockedIPs = () => {
  const [localBlockedIPs, setLocalBlockedIPs] = useState<string[]>([]);
  const [copiedIP, setCopiedIP] = useState<string | null>(null);

  useEffect(() => {
    // Update the local state when blockedIPs changes
    setLocalBlockedIPs([...blockedIPs]);
    
    // Set up interval to check for new blocked IPs
    const interval = setInterval(() => {
      if (JSON.stringify(localBlockedIPs) !== JSON.stringify(blockedIPs)) {
        setLocalBlockedIPs([...blockedIPs]);
      }
    }, 5000);
    
    return () => clearInterval(interval);
  }, [localBlockedIPs]);
  
  const handleCopyIP = (ip: string) => {
    navigator.clipboard.writeText(ip);
    setCopiedIP(ip);
    setTimeout(() => setCopiedIP(null), 2000);
  };
  
  const handleRemoveIP = (ip: string) => {
    const index = blockedIPs.indexOf(ip);
    if (index > -1) {
      blockedIPs.splice(index, 1);
      setLocalBlockedIPs([...blockedIPs]);
    }
  };
  
  return (
    <Card className="h-full flex flex-col">
      <CardHeader className="pb-2 flex-shrink-0">
        <div className="flex justify-between items-center">
          <CardTitle className="text-lg flex items-center">
            <Shield className="h-5 w-5 text-primary mr-2" />
            Blocked IPs
          </CardTitle>
          <Badge variant="outline">
            {localBlockedIPs.length} IPs Blocked
          </Badge>
        </div>
      </CardHeader>
      <CardContent className="p-0 flex-grow relative overflow-hidden">
        <ScrollArea className="h-full max-h-[270px]">
          <div className="p-4 space-y-2">
            {localBlockedIPs.length > 0 ? (
              localBlockedIPs.map((ip, index) => (
                <motion.div
                  key={ip}
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.2, delay: index * 0.05 }}
                  className="flex items-center justify-between p-2 border border-border/50 rounded bg-background hover:bg-muted/30 transition-colors"
                >
                  <div className="font-mono text-sm">{ip}</div>
                  <div className="flex gap-1">
                    <button
                      onClick={() => handleCopyIP(ip)}
                      className="text-muted-foreground hover:text-foreground p-1 rounded-sm"
                      title="Copy IP"
                    >
                      {copiedIP === ip ? (
                        <Badge variant="outline" className="text-xs bg-green-500/10 text-green-500">Copied</Badge>
                      ) : (
                        <Copy className="h-4 w-4" />
                      )}
                    </button>
                    <button
                      onClick={() => handleRemoveIP(ip)}
                      className="text-muted-foreground hover:text-red-500 p-1 rounded-sm"
                      title="Remove from block list"
                    >
                      <X className="h-4 w-4" />
                    </button>
                  </div>
                </motion.div>
              ))
            ) : (
              <div className="flex flex-col items-center justify-center py-8 text-center">
                <Shield className="h-10 w-10 text-muted-foreground/30 mb-2" />
                <p className="text-muted-foreground">No IPs currently blocked</p>
              </div>
            )}
          </div>
        </ScrollArea>
      </CardContent>
    </Card>
  );
};

export default BlockedIPs; 