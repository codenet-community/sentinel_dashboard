import { cn } from "@/lib/utils";
import { Loader2 } from "lucide-react";

interface LoadingSpinnerProps {
  size?: "sm" | "default" | "lg";
  className?: string;
}

const LoadingSpinner = ({ 
  size = "default",
  className 
}: LoadingSpinnerProps) => {
  const sizeClasses = {
    sm: "h-4 w-4",
    default: "h-8 w-8",
    lg: "h-12 w-12"
  };
  
  return (
    <Loader2 
      className={cn(
        "animate-spin text-muted-foreground", 
        sizeClasses[size],
        className
      )} 
    />
  );
};

export default LoadingSpinner; 