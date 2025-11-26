# TCP Statistics Tool for Windows

A command-line tool that displays detailed TCP connection statistics for **all connections** on a Windows system, supporting both **IPv4 and IPv6**. Similar to Linux's `ss -i`, but using Windows' native APIs.

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
║ 172.17.1.188:51517 → 96.104.60.117:443 [IPv4]
║ State: ESTABLISHED     PID: 12712
╠═══════════════════════════════════════════════════════════════════
║
║ PATH METRICS:
║   Sample RTT:                 N/A ms      Smoothed RTT:                50 ms
║   RTT Variance:                17 ms      Min RTT:                     33 ms
║   Max RTT:                     82 ms      Sum RTT:                      0 ms
║   RTT Count:                    0 samples
║
║ RETRANSMISSION TIMEOUTS (RTO):
║   Current RTO:                300 ms      Min RTO:                    300 ms
║   Max RTO:                    300 ms
║   Timeouts:                     0 count    Subsequent:                   0 count
║   Cur Timeout Count:            0 count    Abrupt Timeouts:              0 count
║   Spurious RTO Detect:          0 count
║
║ RETRANSMISSIONS (PATH):
║   Packets Retrans:                   0 pkts
║   Bytes Retrans:                     0 bytes
║   Fast Retrans:                      0 count
║   Retrans Threshold:            3 pkts
║
║ DUPLICATE ACKS & SACKS:
║   Dup ACKs In:                       0 pkts
║   Dup ACK Episodes:                  0 count
║   SACKs Received:                    0 pkts
║   SACK Blocks Rcvd:                  0 blocks
║   DSACK Duplicates:                  3 count
║
║ REORDERING:
║   Bytes Reordered:                   0 bytes
║   Non-Recov DA:                 0 count    Episodes:                     0 count
║   ACK After FR:                      0 pkts
║
║ CONGESTION SIGNALS:
║   Congestion Signals:                0 count
║   ECN Signals:                  0 count    ECE Received:                 0 pkts
║   Pre-Cong Sum Cwnd:            0 bytes    Pre-Cong Sum RTT:             0 ms
║   Post-Cong Sum RTT:            0 ms       Post-Cong Count:              0 count
║
║ MAXIMUM SEGMENT SIZE:
║   Current MSS:              1,460 bytes
║   Max MSS:                  1,460 bytes    Min MSS:                  1,460 bytes
║
║ OTHER:
║   Send Stall:                   0 count    Quench Received:              0 count
║
║ BANDWIDTH ESTIMATES:
║   Outbound:                    272,440 bps
║   Inbound:                   2,482,376 bps
║   Outbound Instability:        181,696 count
║   Inbound Instability:       2,971,088 count
║   Outbound Peaked:              0 flag     Inbound Peaked:               0 flag
║
║ FINE-GRAINED RTT (High Resolution):
║   RTT Variance:         17.035 ms
║   Max RTT:              82.187 ms
║   Min RTT:              33.288 ms
║   Sum RTT:              50.764 ms
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
# Show all ESTABLISHED connections with statistics (IPv4 + IPv6)
TcpStats.exe

# Show all connection states (LISTEN, TIME_WAIT, etc.)
TcpStats.exe --all

# Show only IPv4 connections
TcpStats.exe -4

# Show only IPv6 connections
TcpStats.exe -6

# Filter by process ID
TcpStats.exe -p 1234

# Filter by port number
TcpStats.exe --port 443

# Verbose output (shows debug info)
TcpStats.exe -v

# CSV output (machine-readable format)
TcpStats.exe --csv

# Combined options
TcpStats.exe --all --port 80

# CSV with filtering
TcpStats.exe --csv -p 1234

# IPv6 only, CSV format
TcpStats.exe -6 --csv
```

**Note:** The tool outputs to the terminal and exits immediately. Perfect for scripting and automation.

## IPv4 and IPv6 Support

The tool supports **dual-stack** operation by default:
- Enumerates both IPv4 and IPv6 TCP connections
- All TCP statistics available for both protocol versions
- Use `-4` flag to show only IPv4 connections
- Use `-6` flag to show only IPv6 connections
- Connection display includes protocol version indicator `[IPv4]` or `[IPv6]`

**Note:** IPv6 connections are displayed using standard notation (e.g., `2001:db8::1` or `fe80::1%12` with zone ID).

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

- Windows Vista or later
- Administrator privileges (required to enable statistics collection)
- .NET Framework 4.0+ 

## Technical Details

### CSV Output

The `--csv` flag outputs data in comma-separated format for easy parsing and analysis:

```cmd
# Export to file
TcpStats.exe --csv > tcp_stats.csv

# Filter and export
TcpStats.exe --csv -p 1234 > process_tcp.csv

# Pipe to analysis tools
TcpStats.exe --csv | grep "443"
```

**CSV Format:**
- First row: Column headers
- Subsequent rows: One row per TCP connection
- First 4 columns: LocalIP, LocalPort, RemoteIP, RemotePort
- Followed by 100+ TCP statistics columns
- Empty fields indicate N/A or unavailable data
- All numeric values, no formatting

Useful for:
- Log analysis and monitoring
- Data visualization (Excel, Python, R)
- Automated network auditing
- Time-series analysis

### API Details

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
    .\TcpStats.exe
    Start-Sleep -Seconds 5 
}
```