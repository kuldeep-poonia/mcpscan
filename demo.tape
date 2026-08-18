# VHS Tape Configuration for MCPScan Demo Recording
# Output settings
Output mcpscan_demo.gif
Output mcpscan_demo.mp4

# Terminal window styling
Set Shell "powershell"
Set FontSize 15
Set Width 1280
Set Height 680
Set Padding 20
Set Theme "Catppuccin Mocha"
Set WindowBar Colorful
Set TypingSpeed 35ms

# Step 1: Initial Intro
Sleep 1s
Type "# Discovering shadow & unauthenticated MCP servers across local cluster"
Sleep 600ms
Enter
Sleep 1s

# Step 2: Run MCPScan against the 3 microservices
Type "mcpscan scan --local --ports 8000,8001,8002 --include-stdio"
Sleep 1s
Enter

# Step 3: Let scan execute and table render
Sleep 6s

# Step 4: Show detailed JSON inspection for CI/DevSecOps
Type "mcpscan report --format json | jq '.discovered_http_servers[] | {endpoint: .ip_port, auth: .auth_status, risk: .risk_level, flagged_params: .dangerous_parameters}'"
Sleep 1s
Enter

Sleep 8s
