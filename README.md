# TCP Statistics Tool for Windows

A command-line tool that displays detailed TCP connection statistics for **all connections** on a Windows system. Similar to Linux's `ss -i`, but using Windows' native APIs.

## What It Does

Shows comprehensive TCP metrics for every connection on your system:
- Round-trip time (RTT) and variance
- Congestion window size and thresholds  
- Retransmission counts and fast retransmits
- Bytes/segments transferred
- Bandwidth estimates
- Path MTU and timeout statistics

Perfect for network troubleshooting, performance analysis, and understanding TCP behavior.

## Example Output

```
╔═══════════════════════════════════════════════════════════════════
║ 192.168.1.100:54321 → 93.184.216.34:443
║ State: ESTABLISHED   PID: 4567
╠═══════════════════════════════════════════════════════════════════
║ Data Transfer:
║   Bytes Out:          45,678    Bytes In:         123,456
║   Segs Out:              123    Segs In:              234
║   Segs Retrans:            2    Bytes Retrans:        876
║ Path Metrics:
║   RTT:         12 ms    RTT Var:        3 ms
║   Max RTT:     45 ms    Min RTT:        8 ms
║   Path MTU:  1500 bytes  Timeouts: 0
║ Congestion Control:
║   Cwnd:     65535 bytes   Slow Start Threshold: 32768
║   Fast Retrans: 2    DupAcks: 5
║ Bandwidth Estimate:
║   Outbound:       1,234,567 bps
║   Inbound:        9,876,543 bps
╚═══════════════════════════════════════════════════════════════════
```

## Quick Start

### Option 1: Download and Run

1. Download `TcpStats.exe` from [Releases](../../releases)
2. Open Command Prompt or PowerShell **as Administrator**
3. Run: `TcpStats.exe`

**Note:** Windows may show a SmartScreen warning (unsigned executable). Click "More info" → "Run anyway".

### Option 2: Build from Source

```cmd
# Using csc.exe (comes with .NET Framework)
csc.exe /out:TcpStats.exe /optimize+ TcpStats.cs

# Or use the build script
build_tcpstats.bat
```

Then run as Administrator: `TcpStats.exe`

## Usage

```cmd
# Show all ESTABLISHED connections with statistics
TcpStats.exe

# Show all connection states (LISTEN, TIME_WAIT, etc.)
TcpStats.exe --all

# Filter by process ID
TcpStats.exe -p 1234

# Filter by port number
TcpStats.exe --port 443

# Verbose output (shows debug info)
TcpStats.exe -v

# Combined options
TcpStats.exe --all --port 80 --no-pause
```

## Why This Tool?

Windows doesn't have a built-in equivalent to Linux's `ss -i` command. This tool fills that gap by using the `GetPerTcpConnectionEStats` API to provide:

- **System-wide visibility** - See statistics for ALL TCP connections, not just your own
- **Detailed metrics** - Far more data than `netstat` provides
- **Real-time data** - Query current connection state on demand
- **No dependencies** - Single executable, pure Windows API calls

Useful for:
- Network performance troubleshooting
- Detecting packet loss and retransmissions
- Analyzing latency issues
- Monitoring congestion control behavior
- Validating network configurations

## Requirements

- Windows Vista or later (tested on Windows 10, 11, Server 2016+)
- Administrator privileges (required to enable statistics collection)
- .NET Framework 4.0+ (already installed on modern Windows)

## Technical Details

The tool uses Windows IP Helper APIs:
- `GetExtendedTcpTable` - Enumerates all TCP connections
- `SetPerTcpConnectionEStats` - Enables statistics collection (requires admin)
- `GetPerTcpConnectionEStats` - Retrieves detailed statistics

Statistics categories retrieved:
- Data transfer (bytes, segments, retransmissions)
- Path metrics (RTT, MTU, timeouts)
- Congestion control (cwnd, ssthresh, fast retransmits)
- Send/receive buffers and windows
- Bandwidth estimates
- Fine-grained RTT measurements

## Building from Source

Requires only the C# compiler (included with .NET Framework):

```cmd
# Find csc.exe
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe

# Build
csc.exe /out:TcpStats.exe /optimize+ /platform:anycpu TcpStats.cs
```

No external dependencies or NuGet packages required.

## Limitations

- IPv4 only (IPv6 support could be added)
- Statistics are only available after enabling with admin rights
- Some metrics may show zero on newly established connections
- Performance impact is minimal but not zero (reads kernel TCP state)

## Contributing

Issues and pull requests welcome. This is a single-file tool kept intentionally simple.

## Author

Created for network engineers who need detailed TCP visibility on Windows systems.

---

**Tip:** For continuous monitoring, wrap this in a PowerShell loop:
```powershell
while ($true) { 
    Clear-Host
    .\TcpStats.exe --no-pause
    Start-Sleep -Seconds 5 
}
```
