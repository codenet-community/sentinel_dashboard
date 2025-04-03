
# Sentinel Security Dashboard

This web application provides a comprehensive cybersecurity monitoring dashboard that displays real-time threat intelligence data and blockchain security ledger information. The dashboard is designed to help security professionals monitor and respond to cyber threats efficiently.

## Features

- **Real-time Threat Monitoring**: View active threats as they occur
- **Blockchain Security Ledger**: Monitor blockchain-based security records
- **Threat Statistics**: View aggregated threat statistics by severity
- **Interactive Threat Map**: Visualize threat origins geographically
- **Attack Timeline**: Track threat patterns over time
- **High-severity Alerts**: Get immediate notifications for critical threats
- **Sound Alerts**: Optional audio notifications for critical events
- **Dark/Light Mode**: UI theme options for different environments

## Dashboard Components

1. **Connection Status Panel**: Shows connection status to both the Threat API and Blockchain API
2. **Threat Statistics**: Summary of total threats categorized by severity level
3. **Live Attack Feed**: Real-time feed of incoming threats
4. **Threat Chart**: Visualization of threat patterns over time
5. **Threat Map**: Geographic visualization of attack origins
6. **Blockchain Viewer**: View of the blockchain security ledger
7. **Threat Trends**: Analysis of threat patterns and trends

## Setup and Configuration

The dashboard connects to two main data sources:
- **Threat Intelligence API**: Provides real-time threat data
- **Blockchain Ledger API**: Provides blockchain-based security records

To configure the dashboard:
1. Click the Settings icon in the top left
2. Enter your API endpoints in the Connection Settings tab
3. Optionally configure notification settings in the General tab
4. Click Connect to establish connections to the data sources

## Error Handling

The dashboard implements robust error handling to ensure usability even when connections fail:
- Connection Status indicators show which API (Threat or Blockchain) is disconnected
- Detailed error messages are displayed when connection attempts fail
- The application continues to function with partial data if only one API is available
- Reconnection attempts are automatically made when connections are lost

## Project Structure

The project is organized into feature-based folders for better maintainability:

- **/features**: Core functionality organized by feature
  - **/blockchain**: Blockchain ledger components
  - **/feeds**: Real-time data feed components
  - **/settings**: Configuration and settings components
  - **/stats**: Statistical visualization components
- **/components**: Reusable UI components
  - **/ui**: Shadcn UI component library
  - **/charts**: Data visualization components
  - **/maps**: Geographic visualization components
  - **/alerts**: Notification components
- **/hooks**: React hooks for data fetching and state management
- **/utils**: Utility functions for data processing and other operations
- **/pages**: Application pages and routes

## Technologies Used

- React for the user interface
- Tailwind CSS for styling
- Shadcn UI for component library
- Recharts for data visualization
- Lucide React for icons
- Tanstack Query for data fetching
- date-fns for date formatting

## Best Practices

This project follows modern React best practices:
- Component-based architecture
- Custom hooks for logic separation
- Responsive design for all screen sizes
- Graceful error handling
- Persistent user settings
- Accessibility considerations
