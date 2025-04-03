import { Badge } from '@/components/ui/badge';
import { Card, CardContent } from '@/components/ui/card';
import { Separator } from '@/components/ui/separator';
import { Progress } from '@/components/ui/progress';
import { EnhancedThreatData } from '@/pages/CyberGuardDashboard';
import { AlertCircle, Clock, Globe, Lock, Server, Database, Link2 } from 'lucide-react';

interface ThreatDetailViewProps {
  threat: EnhancedThreatData;
}

const ThreatDetailView = ({ threat }: ThreatDetailViewProps) => {
  // Format timestamp
  const formattedTimestamp = new Date(threat.timestamp).toLocaleString();
  
  // Get threat severity color
  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'Critical':
      case 'High':
        return 'text-destructive';
      case 'Medium':
        return 'text-orange-500';
      case 'Low':
        return 'text-yellow-500';
      default:
        return 'text-muted-foreground';
    }
  };
  
  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <h3 className="text-xl font-semibold flex items-center gap-2">
            <AlertCircle className={`h-5 w-5 ${getSeverityColor(threat.severity)}`} />
            {threat.attack_type}
          </h3>
          <div className="flex items-center gap-2 text-sm text-muted-foreground mt-1">
            <Clock className="h-4 w-4" />
            <span>{formattedTimestamp}</span>
          </div>
        </div>
        
        <Badge variant={
          threat.severity === 'Critical' || threat.severity === 'High' ? 'destructive' :
          threat.severity === 'Medium' ? 'warning' : 'default'
        } className="px-3 py-1">
          {threat.severity}
        </Badge>
      </div>
      
      <Separator />
      
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Source Information */}
        <Card>
          <CardContent className="p-4 space-y-4">
            <h4 className="font-medium">Source Information</h4>
            
            <div className="space-y-2">
              <div className="flex justify-between items-center">
                <div className="flex items-center gap-2">
                  <Globe className="h-4 w-4 text-primary" />
                  <span className="text-sm">Source IP</span>
                </div>
                <span className="font-mono">{threat.ip}</span>
              </div>
              
              <div className="flex justify-between items-center">
                <div className="flex items-center gap-2">
                  <Database className="h-4 w-4 text-primary" />
                  <span className="text-sm">Source Port</span>
                </div>
                <span className="font-mono">{threat.details.source_port}</span>
              </div>
              
              <div className="flex justify-between items-center">
                <div className="flex items-center gap-2">
                  <Server className="h-4 w-4 text-primary" />
                  <span className="text-sm">Destination Port</span>
                </div>
                <span className="font-mono">{threat.details.destination_port}</span>
              </div>
              
              <div className="flex justify-between items-center">
                <div className="flex items-center gap-2">
                  <Lock className="h-4 w-4 text-primary" />
                  <span className="text-sm">Protocol</span>
                </div>
                <span className="font-mono">{threat.details.protocol.toUpperCase()}</span>
              </div>
            </div>
          </CardContent>
        </Card>
        
        {/* Request Details */}
        <Card>
          <CardContent className="p-4 space-y-4">
            <h4 className="font-medium">Request Details</h4>
            
            <div className="space-y-2">
              <div className="flex justify-between items-center">
                <div className="flex items-center gap-2">
                  <Link2 className="h-4 w-4 text-primary" />
                  <span className="text-sm">Method</span>
                </div>
                <Badge variant="outline" className="font-mono">
                  {threat.details.method}
                </Badge>
              </div>
              
              <div className="flex flex-col gap-1">
                <div className="flex items-center gap-2">
                  <Link2 className="h-4 w-4 text-primary" />
                  <span className="text-sm">URL Path</span>
                </div>
                <code className="text-xs bg-muted p-2 rounded-md w-full overflow-auto">
                  {threat.details.url_path}
                </code>
              </div>
              
              <div className="flex flex-col gap-1">
                <div className="flex items-center gap-2">
                  <Globe className="h-4 w-4 text-primary" />
                  <span className="text-sm">User Agent</span>
                </div>
                <code className="text-xs bg-muted p-2 rounded-md w-full overflow-auto">
                  {threat.details.user_agent}
                </code>
              </div>
              
              <div className="flex justify-between items-center">
                <div className="flex items-center gap-2">
                  <Lock className="h-4 w-4 text-primary" />
                  <span className="text-sm">Flag</span>
                </div>
                <Badge variant="outline" className="font-mono">
                  {threat.details.flag}
                </Badge>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
      
      {/* Prediction Metrics */}
      {(threat.details.confidence_score !== undefined || 
        threat.details.anomaly_score !== undefined || 
        threat.details.zero_day_score !== undefined) && (
        <>
          <Separator />
          
          <div>
            <h4 className="font-medium mb-4">Prediction Metrics</h4>
            
            <div className="space-y-6">
              {threat.details.confidence_score !== undefined && (
                <div className="space-y-2">
                  <div className="flex justify-between text-sm">
                    <span>Confidence Score</span>
                    <span className="font-medium">{(threat.details.confidence_score * 100).toFixed(1)}%</span>
                  </div>
                  <Progress value={threat.details.confidence_score * 100} className="h-2" />
                </div>
              )}
              
              {threat.details.anomaly_score !== undefined && (
                <div className="space-y-2">
                  <div className="flex justify-between text-sm">
                    <span>Anomaly Score</span>
                    <span className="font-medium">{(threat.details.anomaly_score * 100).toFixed(1)}%</span>
                  </div>
                  <Progress value={threat.details.anomaly_score * 100} className="h-2" />
                </div>
              )}
              
              {threat.details.zero_day_score !== undefined && (
                <div className="space-y-2">
                  <div className="flex justify-between text-sm">
                    <span>Zero-Day Score</span>
                    <span className="font-medium">{(threat.details.zero_day_score * 100).toFixed(1)}%</span>
                  </div>
                  <Progress value={threat.details.zero_day_score * 100} className="h-2" />
                </div>
              )}
            </div>
          </div>
        </>
      )}
      
      {/* Prediction Details */}
      {threat.details.prediction_details && (
        <>
          <Separator />
          
          <div>
            <h4 className="font-medium mb-4">Prediction Details</h4>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <Card>
                <CardContent className="p-4">
                  <div className="flex justify-between items-center">
                    <span className="text-sm">Is Anomaly</span>
                    <Badge variant={threat.details.prediction_details.is_anomaly ? "destructive" : "outline"}>
                      {threat.details.prediction_details.is_anomaly ? "Yes" : "No"}
                    </Badge>
                  </div>
                </CardContent>
              </Card>
              
              <Card>
                <CardContent className="p-4">
                  <div className="flex justify-between items-center">
                    <span className="text-sm">Is Zero-Day</span>
                    <Badge variant={threat.details.prediction_details.is_zero_day ? "destructive" : "outline"}>
                      {threat.details.prediction_details.is_zero_day ? "Yes" : "No"}
                    </Badge>
                  </div>
                </CardContent>
              </Card>
            </div>
            
            {threat.details.prediction_details.top_features && (
              <div className="mt-4">
                <h5 className="text-sm font-medium mb-2">Top Features</h5>
                <div className="flex flex-wrap gap-2">
                  {threat.details.prediction_details.top_features.map((feature, index) => (
                    <Badge key={index} variant="secondary">
                      {feature}
                    </Badge>
                  ))}
                </div>
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
};

export default ThreatDetailView; 