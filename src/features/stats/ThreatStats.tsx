
import { Card, CardContent } from '@/components/ui/card';
import { Shield, AlertTriangle, CheckCircle } from 'lucide-react';

interface ThreatStatsProps {
  total: number;
  high: number;
  medium: number;
  low: number;
  mitigated: number;
  active: number;
}

export const ThreatStats = ({ total, high, medium, low, mitigated, active }: ThreatStatsProps) => {
  return (
    <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-6 gap-4">
      <StatCard 
        title="Total Threats"
        value={total}
        icon={<Shield className="h-5 w-5 text-primary/80" />}
        description="All detected threats"
        color="bg-primary/10 text-primary"
      />
      
      <StatCard 
        title="High Severity"
        value={high}
        icon={<AlertTriangle className="h-5 w-5 text-red-500/80" />}
        description="Critical threats"
        color="bg-red-500/10 text-red-500"
      />
      
      <StatCard 
        title="Medium Severity"
        value={medium}
        icon={<AlertTriangle className="h-5 w-5 text-orange-500/80" />}
        description="Moderate threats"
        color="bg-orange-500/10 text-orange-500"
      />
      
      <StatCard 
        title="Low Severity"
        value={low}
        icon={<AlertTriangle className="h-5 w-5 text-green-500/80" />}
        description="Minor threats"
        color="bg-green-500/10 text-green-500"
      />
      
      <StatCard 
        title="Active"
        value={active}
        icon={<Shield className="h-5 w-5 text-blue-500/80" />}
        description="Ongoing threats"
        color="bg-blue-500/10 text-blue-500"
      />
      
      <StatCard 
        title="Mitigated"
        value={mitigated}
        icon={<CheckCircle className="h-5 w-5 text-teal-500/80" />}
        description="Resolved threats"
        color="bg-teal-500/10 text-teal-500"
      />
    </div>
  );
};

interface StatCardProps {
  title: string;
  value: number;
  icon: React.ReactNode;
  description: string;
  color: string;
}

const StatCard = ({ title, value, icon, description, color }: StatCardProps) => {
  return (
    <Card className="stat-card overflow-hidden relative">
      <CardContent className="p-6">
        <div className="flex justify-between items-start">
          <div>
            <p className="text-sm font-medium text-muted-foreground mb-1">{title}</p>
            <div className="text-3xl font-bold">{value}</div>
            <p className="text-xs text-muted-foreground mt-1">{description}</p>
          </div>
          <div className={`p-2 rounded-full ${color}`}>
            {icon}
          </div>
        </div>
      </CardContent>
    </Card>
  );
};

export default ThreatStats;
