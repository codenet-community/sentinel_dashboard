
import { useState, useEffect } from 'react';
import { Shield, AlertTriangle, CheckCircle, Activity, Zap, TrendingUp, Clock, ShieldAlert, Eye } from 'lucide-react';
import { Card, CardContent } from "@/components/ui/card";
import { cn } from '@/lib/utils';
import { motion } from 'framer-motion';
import { format } from 'date-fns';

interface ThreatStatsProps {
  total: number;
  high: number;
  medium: number;
  low: number;
  mitigated: number;
  active: number;
}

const StatCard = ({ 
  title, 
  value, 
  icon: Icon, 
  iconColor, 
  delay,
  animate = true,
  badgeText = '',
  badgeColor = '',
  description = ''
}: { 
  title: string; 
  value: number; 
  icon: any; 
  iconColor: string; 
  delay: number;
  animate?: boolean;
  badgeText?: string;
  badgeColor?: string;
  description?: string;
}) => {
  const [isVisible, setIsVisible] = useState(false);
  const [previousValue, setPreviousValue] = useState(value);
  const [isIncreasing, setIsIncreasing] = useState(false);
  
  useEffect(() => {
    const timer = setTimeout(() => {
      setIsVisible(true);
    }, delay);
    
    return () => clearTimeout(timer);
  }, [delay]);
  
  useEffect(() => {
    if (value !== previousValue) {
      setIsIncreasing(value > previousValue);
      setPreviousValue(value);
    }
  }, [value, previousValue]);
  
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: isVisible ? 1 : 0, y: isVisible ? 0 : 20 }}
      transition={{ duration: 0.5, delay: delay / 1000 }}
      className="w-full"
    >
      <Card className="stat-card overflow-hidden h-full">
        <CardContent className="p-4 md:p-6">
          <div className="flex items-center justify-between">
            <div className="flex-1">
              <p className="text-sm font-medium text-muted-foreground mb-1">{title}</p>
              <div className="flex items-center gap-2">
                <p className="text-2xl md:text-3xl font-semibold tracking-tight">{value}</p>
                {isIncreasing && animate && (
                  <span className="text-green-500 text-sm animate-pulse">
                    <Zap size={14} />
                  </span>
                )}
                {badgeText && (
                  <span className={`text-xs px-1.5 py-0.5 rounded ${badgeColor}`}>
                    {badgeText}
                  </span>
                )}
              </div>
              {description && (
                <p className="text-xs text-muted-foreground mt-1">{description}</p>
              )}
            </div>
            <div className={`p-3 rounded-full bg-${iconColor}/10`}>
              <Icon className={`h-5 w-5 text-${iconColor}`} />
            </div>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
};

const BarIndicator = ({ 
  percentage, 
  color, 
  animated = true 
}: { 
  percentage: number; 
  color: string;
  animated?: boolean;
}) => (
  <div className="relative h-2 w-full bg-gray-100 dark:bg-gray-800 rounded-full overflow-hidden">
    <motion.div
      className={`absolute left-0 top-0 h-full bg-${color}`}
      initial={{ width: animated ? 0 : `${percentage}%` }}
      animate={{ width: `${percentage}%` }}
      transition={{ duration: 1, ease: "easeOut" }}
    />
  </div>
);

const ThreatStats = ({ total, high, medium, low, mitigated, active }: ThreatStatsProps) => {
  const [showPercentage, setShowPercentage] = useState(false);
  const [currentTime, setCurrentTime] = useState(new Date());
  
  useEffect(() => {
    const timer = setTimeout(() => {
      setShowPercentage(true);
    }, 500);
    
    return () => clearTimeout(timer);
  }, []);
  
  useEffect(() => {
    const interval = setInterval(() => {
      setCurrentTime(new Date());
    }, 1000);
    
    return () => clearInterval(interval);
  }, []);
  
  const calculatePercentage = (value: number) => (total > 0 ? (value / total) * 100 : 0);
  
  const highPercentage = calculatePercentage(high);
  const mediumPercentage = calculatePercentage(medium);
  const lowPercentage = calculatePercentage(low);
  
  return (
    <div className="space-y-6">
      <div>
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-medium flex items-center">
            <Activity className="h-4 w-4 mr-2 text-primary" />
            Threat Overview
          </h2>
          <div className="text-xs text-muted-foreground flex items-center">
            <Clock className="h-3 w-3 mr-1" />
            {format(currentTime, 'MMM dd, HH:mm:ss')}
          </div>
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <StatCard 
            title="Total Threats" 
            value={total} 
            icon={Shield} 
            iconColor="primary" 
            delay={100} 
            description="All detected threats across all severity levels"
          />
          <StatCard 
            title="Active Threats" 
            value={active} 
            icon={AlertTriangle} 
            iconColor="severity-high" 
            delay={200} 
            badgeText={active > 0 ? "LIVE" : ""}
            badgeColor={active > 0 ? "bg-red-500/10 text-red-500" : ""}
            description="Threats requiring immediate attention"
          />
          <StatCard 
            title="Mitigated" 
            value={mitigated} 
            icon={CheckCircle} 
            iconColor="severity-low" 
            delay={300} 
            description="Successfully blocked or resolved threats"
          />
        </div>
      </div>
      
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.4 }}
          className="glass-card p-5 rounded-lg"
        >
          <h3 className="text-sm font-medium mb-4 flex items-center">
            <Zap className="h-4 w-4 mr-2 text-primary" />
            Severity Distribution
          </h3>
          <div className="space-y-4">
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <div className="flex items-center">
                  <span className="w-2 h-2 rounded-full bg-severity-high mr-2" />
                  <span className="text-sm">High Severity</span>
                </div>
                <div className="flex items-center">
                  <span className="text-sm font-medium">{high}</span>
                  <span className="text-xs text-muted-foreground ml-1">
                    ({highPercentage.toFixed(1)}%)
                  </span>
                </div>
              </div>
              <BarIndicator 
                percentage={showPercentage ? highPercentage : 0} 
                color="severity-high" 
                animated={showPercentage} 
              />
            </div>
            
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <div className="flex items-center">
                  <span className="w-2 h-2 rounded-full bg-severity-medium mr-2" />
                  <span className="text-sm">Medium Severity</span>
                </div>
                <div className="flex items-center">
                  <span className="text-sm font-medium">{medium}</span>
                  <span className="text-xs text-muted-foreground ml-1">
                    ({mediumPercentage.toFixed(1)}%)
                  </span>
                </div>
              </div>
              <BarIndicator 
                percentage={showPercentage ? mediumPercentage : 0} 
                color="severity-medium" 
                animated={showPercentage} 
              />
            </div>
            
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <div className="flex items-center">
                  <span className="w-2 h-2 rounded-full bg-severity-low mr-2" />
                  <span className="text-sm">Low Severity</span>
                </div>
                <div className="flex items-center">
                  <span className="text-sm font-medium">{low}</span>
                  <span className="text-xs text-muted-foreground ml-1">
                    ({lowPercentage.toFixed(1)}%)
                  </span>
                </div>
              </div>
              <BarIndicator 
                percentage={showPercentage ? lowPercentage : 0} 
                color="severity-low" 
                animated={showPercentage} 
              />
            </div>
          </div>
          
          {total > 0 && (
            <div className="mt-4 pt-3 border-t border-border">
              <div className="flex justify-between text-sm">
                <span className="text-muted-foreground">Mitigation Rate:</span>
                <span className="font-medium">
                  {total > 0 ? ((mitigated / total) * 100).toFixed(1) : 0}%
                </span>
              </div>
            </div>
          )}
        </motion.div>
        
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.5 }}
          className="glass-card p-5 rounded-lg"
        >
          <h3 className="text-sm font-medium mb-4 flex items-center">
            <ShieldAlert className="h-4 w-4 mr-2 text-primary" />
            Threat Intelligence
          </h3>
          
          <div className="space-y-3">
            <div className="flex justify-between items-center">
              <div className="flex items-center space-x-2">
                <Eye className="h-3.5 w-3.5 text-muted-foreground" />
                <span className="text-sm">Detection Rate</span>
              </div>
              <div className="text-sm font-medium">
                {active > 0 ? (active / (active + mitigated) * 100).toFixed(1) : 0}%
              </div>
            </div>
            
            <div className="flex justify-between items-center">
              <div className="flex items-center space-x-2">
                <TrendingUp className="h-3.5 w-3.5 text-muted-foreground" />
                <span className="text-sm">Threat Trend</span>
              </div>
              <div className="text-sm font-medium">
                {active > mitigated ? "Increasing" : "Decreasing"}
              </div>
            </div>
            
            <div className="flex justify-between items-center">
              <div className="flex items-center space-x-2">
                <AlertTriangle className="h-3.5 w-3.5 text-muted-foreground" />
                <span className="text-sm">Critical Status</span>
              </div>
              <div className="text-sm font-medium">
                {high > 0 ? 
                  <span className="text-severity-high">Warning</span> : 
                  <span className="text-severity-low">Normal</span>
                }
              </div>
            </div>
            
            <div className="flex justify-between items-center">
              <div className="flex items-center space-x-2">
                <Shield className="h-3.5 w-3.5 text-muted-foreground" />
                <span className="text-sm">Security Posture</span>
              </div>
              <div className="text-sm font-medium">
                {high === 0 && medium <= 1 ? 
                  <span className="text-severity-low">Strong</span> : 
                  high > 2 ? 
                    <span className="text-severity-high">Vulnerable</span> : 
                    <span className="text-severity-medium">Moderate</span>
                }
              </div>
            </div>
          </div>
          
          <div className="mt-4 pt-3 border-t border-border">
            <div className="text-xs text-muted-foreground">
              Security recommendation: {high > 0 ? "Address high severity threats immediately" : "Continue monitoring for new threats"}
            </div>
          </div>
        </motion.div>
      </div>
    </div>
  );
};

export default ThreatStats;
