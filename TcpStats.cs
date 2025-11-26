using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;

namespace TcpStatsTool
{
    class Program
    {
        static void Main(string[] args)
        {
            bool csvOutput = args.Contains("--csv") || args.Contains("-csv");
            
            if (!csvOutput)
            {
                Console.WriteLine("Windows TCP Statistics Tool - System-Wide View");
                Console.WriteLine("===============================================");
                Console.WriteLine("Note: Run as Administrator for full statistics\n");
            }

            bool verbose = args.Contains("-v") || args.Contains("--verbose");
            bool showAll = args.Contains("-a") || args.Contains("--all");
            bool ipv4Only = args.Contains("-4");
            bool ipv6Only = args.Contains("-6");
            string filterPid = null;
            string filterPort = null;

            for (int i = 0; i < args.Length; i++)
            {
                if ((args[i] == "-p" || args[i] == "--pid") && i + 1 < args.Length)
                    filterPid = args[i + 1];
                if ((args[i] == "--port") && i + 1 < args.Length)
                    filterPort = args[i + 1];
            }

            try
            {
                var connections = new List<TcpConnectionInfo>();
                
                // Get IPv4 connections
                if (!ipv6Only)
                {
                    connections.AddRange(GetTcpConnections());
                }
                
                // Get IPv6 connections
                if (!ipv4Only)
                {
                    connections.AddRange(GetTcp6Connections());
                }
                
                if (!showAll)
                    connections = connections.Where(c => c.State == MIB_TCP_STATE.ESTABLISHED).ToList();

                if (!string.IsNullOrEmpty(filterPid))
                {
                    uint pid = uint.Parse(filterPid);
                    connections = connections.Where(c => c.Pid == pid).ToList();
                }

                if (!string.IsNullOrEmpty(filterPort))
                {
                    ushort port = ushort.Parse(filterPort);
                    connections = connections.Where(c => c.LocalPort == port || c.RemotePort == port).ToList();
                }

                if (!csvOutput)
                {
                    Console.WriteLine(string.Format("Found {0} TCP connections\n", connections.Count));
                }

                if (csvOutput)
                {
                    // CSV mode - output header then rows
                    OutputCsvHeader();
                    foreach (var conn in connections)
                    {
                        OutputCsvRow(conn);
                    }
                }
                else
                {
                    // Normal formatted output
                    foreach (var conn in connections)
                    {
                        DisplayConnectionStats(conn, verbose);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(string.Format("Error: {0}", ex.Message));
                if (verbose)
                    Console.WriteLine(string.Format("Stack: {0}", ex.StackTrace));
            }
        }

        static string CsvValue(uint value)
        {
            if (value == uint.MaxValue || value == 0xFFFFFFFF)
                return "";
            return value.ToString();
        }

        static string CsvValue(ulong value)
        {
            if (value == ulong.MaxValue || value == 0xFFFFFFFFFFFFFFFF)
                return "";
            return value.ToString();
        }

        static void OutputCsvHeader()
        {
            Console.WriteLine("LocalIP,LocalPort,RemoteIP,RemotePort,State,PID," +
                "DataBytesOut,DataBytesIn,DataSegsOut,DataSegsIn,TotalSegsOut,TotalSegsIn,ThruBytesAcked,ThruBytesReceived," +
                "SegsRetrans,BytesRetrans,FastRetrans,TimeoutEpisodes,SynRetrans," +
                "DupAcksIn,SoftErrors,SoftErrorReason," +
                "SndUna,SndNxt,SndMax,RcvNxt," +
                "SampleRtt,SmoothedRtt,RttVar,MinRtt,MaxRtt,SumRtt,RttCount," +
                "CurRto,MinRto,MaxRto,Timeouts,SubsequentTimeouts,CurTimeoutCount,AbruptTimeouts,SpuriousRtoDetections," +
                "PathPktsRetrans,PathBytesRetrans,PathFastRetrans,RetranThresh," +
                "PathDupAcksIn,DupAckEpisodes,SacksRcvd,SackBlocksRcvd,DsackDups," +
                "BytesReordered,NonRecovDa,NonRecovDaEpisodes,AckAfterFr," +
                "CongSignals,EcnSignals,EceRcvd,PreCongSumCwnd,PreCongSumRtt,PostCongSumRtt,PostCongCountRtt," +
                "CurMss,MaxMss,MinMss," +
                "SendStall,QuenchRcvd," +
                "CurCwnd,CurSsthresh,MaxSsCwnd,MaxCaCwnd,MaxSsthresh,MinSsthresh,SlowStart,CongAvoid,OtherReductions," +
                "SndLimTransRwin,SndLimTimeRwin,SndLimBytesRwin," +
                "SndLimTransCwnd,SndLimTimeCwnd,SndLimBytesCwnd," +
                "SndLimTransSnd,SndLimTimeSnd,SndLimBytesSnd," +
                "CurRetxQueue,MaxRetxQueue,CurAppWQueue,MaxAppWQueue," +
                "CurRwinSent,MaxRwinSent,MinRwinSent,CurRwinRcvd,MaxRwinRcvd,MinRwinRcvd,LimRwin," +
                "WinScaleSent,WinScaleRcvd," +
                "RecDupAckEpisodes,RecDupAcksOut,CeRcvd,EcnSent,EcnNoncesRcvd," +
                "CurReasmQueue,MaxReasmQueue,CurAppRQueue,MaxAppRQueue," +
                "ObsMinRtt,ObsBaseRtt,ObsCurRwinRcvd,ObsMaxRwinRcvd,ObsMinRwinRcvd,ObsWinScaleRcvd," +
                "OutboundBandwidth,InboundBandwidth,OutboundInstability,InboundInstability,OutboundBandwidthPeaked,InboundBandwidthPeaked," +
                "FineRttVar,FineMaxRtt,FineMinRtt,FineSumRtt");
        }

        static void OutputCsvRow(TcpConnectionInfo conn)
        {
            // Try to enable and retrieve statistics
            bool statsEnabled;
            TCP_ESTATS_DATA_ROD_v0? data;
            TCP_ESTATS_PATH_ROD_v0? path;
            TCP_ESTATS_SND_CONG_ROD_v0? sndCong;
            TCP_ESTATS_SEND_BUFF_ROD_v0? sendBuff;
            TCP_ESTATS_REC_ROD_v0? rec;
            TCP_ESTATS_OBS_REC_ROD_v0? obsRec;
            TCP_ESTATS_BANDWIDTH_ROD_v0? bandwidth;
            TCP_ESTATS_FINE_RTT_ROD_v0? fineRtt;

            if (conn.IsIPv6)
            {
                var row = conn.RowV6;
                statsEnabled = EnableConnection6Stats(ref row);
                data = statsEnabled ? GetConnection6Stats<TCP_ESTATS_DATA_ROD_v0>(ref row, TCP_ESTATS_TYPE.TcpConnectionEstatsData) : null;
                path = statsEnabled ? GetConnection6Stats<TCP_ESTATS_PATH_ROD_v0>(ref row, TCP_ESTATS_TYPE.TcpConnectionEstatsPath) : null;
                sndCong = statsEnabled ? GetConnection6Stats<TCP_ESTATS_SND_CONG_ROD_v0>(ref row, TCP_ESTATS_TYPE.TcpConnectionEstatsSndCong) : null;
                sendBuff = statsEnabled ? GetConnection6Stats<TCP_ESTATS_SEND_BUFF_ROD_v0>(ref row, TCP_ESTATS_TYPE.TcpConnectionEstatsSendBuff) : null;
                rec = statsEnabled ? GetConnection6Stats<TCP_ESTATS_REC_ROD_v0>(ref row, TCP_ESTATS_TYPE.TcpConnectionEstatsRec) : null;
                obsRec = statsEnabled ? GetConnection6Stats<TCP_ESTATS_OBS_REC_ROD_v0>(ref row, TCP_ESTATS_TYPE.TcpConnectionEstatsObsRec) : null;
                bandwidth = statsEnabled ? GetConnection6Stats<TCP_ESTATS_BANDWIDTH_ROD_v0>(ref row, TCP_ESTATS_TYPE.TcpConnectionEstatsBandwidth) : null;
                fineRtt = statsEnabled ? GetConnection6Stats<TCP_ESTATS_FINE_RTT_ROD_v0>(ref row, TCP_ESTATS_TYPE.TcpConnectionEstatsFineRtt) : null;
            }
            else
            {
                var row = conn.RowV4;
                statsEnabled = EnableConnectionStats(ref row);
                data = statsEnabled ? GetConnectionStats<TCP_ESTATS_DATA_ROD_v0>(ref row, TCP_ESTATS_TYPE.TcpConnectionEstatsData) : null;
                path = statsEnabled ? GetConnectionStats<TCP_ESTATS_PATH_ROD_v0>(ref row, TCP_ESTATS_TYPE.TcpConnectionEstatsPath) : null;
                sndCong = statsEnabled ? GetConnectionStats<TCP_ESTATS_SND_CONG_ROD_v0>(ref row, TCP_ESTATS_TYPE.TcpConnectionEstatsSndCong) : null;
                sendBuff = statsEnabled ? GetConnectionStats<TCP_ESTATS_SEND_BUFF_ROD_v0>(ref row, TCP_ESTATS_TYPE.TcpConnectionEstatsSendBuff) : null;
                rec = statsEnabled ? GetConnectionStats<TCP_ESTATS_REC_ROD_v0>(ref row, TCP_ESTATS_TYPE.TcpConnectionEstatsRec) : null;
                obsRec = statsEnabled ? GetConnectionStats<TCP_ESTATS_OBS_REC_ROD_v0>(ref row, TCP_ESTATS_TYPE.TcpConnectionEstatsObsRec) : null;
                bandwidth = statsEnabled ? GetConnectionStats<TCP_ESTATS_BANDWIDTH_ROD_v0>(ref row, TCP_ESTATS_TYPE.TcpConnectionEstatsBandwidth) : null;
                fineRtt = statsEnabled ? GetConnectionStats<TCP_ESTATS_FINE_RTT_ROD_v0>(ref row, TCP_ESTATS_TYPE.TcpConnectionEstatsFineRtt) : null;
            }

            // Build CSV row
            var csvRow = string.Format("{0},{1},{2},{3},{4},{5}",
                conn.LocalAddress, conn.LocalPort, conn.RemoteAddress, conn.RemotePort, conn.State, conn.Pid);

            // Data transfer
            if (data.HasValue)
            {
                var d = data.Value;
                csvRow += string.Format(",{0},{1},{2},{3},{4},{5},{6},{7}",
                    CsvValue(d.DataBytesOut), CsvValue(d.DataBytesIn), CsvValue(d.DataSegsOut), CsvValue(d.DataSegsIn),
                    CsvValue(d.SegsOut), CsvValue(d.SegsIn), CsvValue(d.ThruBytesAcked), CsvValue(d.ThruBytesReceived));
                csvRow += string.Format(",{0},{1},{2},{3},{4}",
                    CsvValue(d.SegsRetrans), CsvValue(d.BytesRetrans), CsvValue(d.FastRetran), CsvValue(d.TimeoutEpisodes), d.SynRetrans);
                csvRow += string.Format(",{0},{1},{2}",
                    CsvValue(d.DupAcksIn), CsvValue(d.SoftErrors), CsvValue(d.SoftErrorReason));
                csvRow += string.Format(",{0},{1},{2},{3}",
                    CsvValue(d.SndUna), CsvValue(d.SndNxt), CsvValue(d.SndMax), CsvValue(d.RcvNxt));
            }
            else
            {
                csvRow += new string(',', 22); // 23 fields
            }

            // Path metrics
            if (path.HasValue)
            {
                var p = path.Value;
                csvRow += string.Format(",{0},{1},{2},{3},{4},{5},{6}",
                    CsvValue(p.SampleRtt), CsvValue(p.SmoothedRtt), CsvValue(p.RttVar), CsvValue(p.MinRtt), 
                    CsvValue(p.MaxRtt), CsvValue(p.SumRtt), CsvValue(p.CountRtt));
                csvRow += string.Format(",{0},{1},{2},{3},{4},{5},{6},{7}",
                    CsvValue(p.CurRto), CsvValue(p.MinRto), CsvValue(p.MaxRto), CsvValue(p.Timeouts),
                    CsvValue(p.SubsequentTimeouts), CsvValue(p.CurTimeoutCount), CsvValue(p.AbruptTimeouts), CsvValue(p.SpuriousRtoDetections));
                csvRow += string.Format(",{0},{1},{2},{3}",
                    CsvValue(p.PktsRetrans), CsvValue(p.BytesRetrans), CsvValue(p.FastRetran), CsvValue(p.RetranThresh));
                csvRow += string.Format(",{0},{1},{2},{3},{4}",
                    CsvValue(p.DupAcksIn), CsvValue(p.SndDupAckEpisodes), CsvValue(p.SacksRcvd), CsvValue(p.SackBlocksRcvd), CsvValue(p.DsackDups));
                csvRow += string.Format(",{0},{1},{2},{3}",
                    CsvValue(p.SumBytesReordered), CsvValue(p.NonRecovDa), CsvValue(p.NonRecovDaEpisodes), CsvValue(p.AckAfterFr));
                csvRow += string.Format(",{0},{1},{2},{3},{4},{5},{6}",
                    CsvValue(p.CongSignals), CsvValue(p.EcnSignals), CsvValue(p.EceRcvd), CsvValue(p.PreCongSumCwnd),
                    CsvValue(p.PreCongSumRtt), CsvValue(p.PostCongSumRtt), CsvValue(p.PostCongCountRtt));
                csvRow += string.Format(",{0},{1},{2}",
                    CsvValue(p.CurMss), CsvValue(p.MaxMss), CsvValue(p.MinMss));
                csvRow += string.Format(",{0},{1}",
                    CsvValue(p.SendStall), CsvValue(p.QuenchRcvd));
            }
            else
            {
                csvRow += new string(',', 41); // 42 fields
            }

            // Congestion control
            if (sndCong.HasValue)
            {
                var s = sndCong.Value;
                csvRow += string.Format(",{0},{1},{2},{3},{4},{5},{6},{7},{8}",
                    CsvValue(s.CurCwnd), CsvValue(s.CurSsthresh), CsvValue(s.MaxSsCwnd), CsvValue(s.MaxCaCwnd),
                    CsvValue(s.MaxSsthresh), CsvValue(s.MinSsthresh), CsvValue(s.SlowStart), CsvValue(s.CongAvoid), CsvValue(s.OtherReductions));
                csvRow += string.Format(",{0},{1},{2}",
                    CsvValue(s.SndLimTransRwin), CsvValue(s.SndLimTimeRwin), CsvValue(s.SndLimBytesRwin));
                csvRow += string.Format(",{0},{1},{2}",
                    CsvValue(s.SndLimTransCwnd), CsvValue(s.SndLimTimeCwnd), CsvValue(s.SndLimBytesCwnd));
                csvRow += string.Format(",{0},{1},{2}",
                    CsvValue(s.SndLimTransSnd), CsvValue(s.SndLimTimeSnd), CsvValue(s.SndLimBytesSnd));
            }
            else
            {
                csvRow += new string(',', 17); // 18 fields
            }

            // Send buffers
            if (sendBuff.HasValue)
            {
                var sb = sendBuff.Value;
                csvRow += string.Format(",{0},{1},{2},{3}",
                    CsvValue(sb.CurRetxQueue), CsvValue(sb.MaxRetxQueue), CsvValue(sb.CurAppWQueue), CsvValue(sb.MaxAppWQueue));
            }
            else
            {
                csvRow += new string(',', 3); // 4 fields
            }

            // Receive
            if (rec.HasValue)
            {
                var r = rec.Value;
                csvRow += string.Format(",{0},{1},{2},{3},{4},{5},{6}",
                    CsvValue(r.CurRwinSent), CsvValue(r.MaxRwinSent), CsvValue(r.MinRwinSent),
                    CsvValue(r.CurRwinRcvd), CsvValue(r.MaxRwinRcvd), CsvValue(r.MinRwinRcvd), CsvValue(r.LimRwin));
                csvRow += string.Format(",{0},{1}",
                    r.WinScaleSent, r.WinScaleRcvd);
                csvRow += string.Format(",{0},{1},{2},{3},{4}",
                    CsvValue(r.DupAckEpisodes), CsvValue(r.DupAcksOut), CsvValue(r.CeRcvd), CsvValue(r.EcnSent), CsvValue(r.EcnNoncesRcvd));
                csvRow += string.Format(",{0},{1},{2},{3}",
                    CsvValue(r.CurReasmQueue), CsvValue(r.MaxReasmQueue), CsvValue(r.CurAppRQueue), CsvValue(r.MaxAppRQueue));
            }
            else
            {
                csvRow += new string(',', 17); // 18 fields
            }

            // Observed receive
            if (obsRec.HasValue)
            {
                var or = obsRec.Value;
                csvRow += string.Format(",{0},{1},{2},{3},{4},{5}",
                    CsvValue(or.MinRtt), CsvValue(or.BaseRtt), CsvValue(or.CurRwinRcvd),
                    CsvValue(or.MaxRwinRcvd), CsvValue(or.MinRwinRcvd), or.WinScaleRcvd);
            }
            else
            {
                csvRow += new string(',', 5); // 6 fields
            }

            // Bandwidth
            if (bandwidth.HasValue)
            {
                var bw = bandwidth.Value;
                csvRow += string.Format(",{0},{1},{2},{3},{4},{5}",
                    CsvValue(bw.OutboundBandwidth), CsvValue(bw.InboundBandwidth), CsvValue(bw.OutboundInstability),
                    CsvValue(bw.InboundInstability), bw.OutboundBandwidthPeaked, bw.InboundBandwidthPeaked);
            }
            else
            {
                csvRow += new string(',', 5); // 6 fields
            }

            // Fine RTT (convert from microseconds to milliseconds)
            if (fineRtt.HasValue)
            {
                var fr = fineRtt.Value;
                csvRow += string.Format(",{0},{1},{2},{3}",
                    (fr.RttVar == uint.MaxValue) ? "" : (fr.RttVar / 1000.0).ToString("F3"),
                    (fr.MaxRtt == uint.MaxValue) ? "" : (fr.MaxRtt / 1000.0).ToString("F3"),
                    (fr.MinRtt == uint.MaxValue) ? "" : (fr.MinRtt / 1000.0).ToString("F3"),
                    (fr.SumRtt == uint.MaxValue) ? "" : (fr.SumRtt / 1000.0).ToString("F3"));
            }
            else
            {
                csvRow += new string(',', 3); // 4 fields
            }

            Console.WriteLine(csvRow);
        }

        static string FormatValue(uint value, string format = "N0")
        {
            if (value == uint.MaxValue || value == 0xFFFFFFFF)
                return "N/A";
            if (format == "N0")
                return value.ToString("N0");
            return value.ToString(format);
        }

        static string FormatValue(ulong value, string format = "N0")
        {
            if (value == ulong.MaxValue || value == 0xFFFFFFFFFFFFFFFF)
                return "N/A";
            if (format == "N0")
                return value.ToString("N0");
            return value.ToString(format);
        }

        static void DisplayConnectionStats(TcpConnectionInfo conn, bool verbose)
        {
            Console.WriteLine("╔═══════════════════════════════════════════════════════════════════");
            Console.WriteLine(string.Format("║ {0}:{1} → {2}:{3} [{4}]", 
                conn.LocalAddress, conn.LocalPort, conn.RemoteAddress, conn.RemotePort, 
                conn.IsIPv6 ? "IPv6" : "IPv4"));
            Console.WriteLine(string.Format("║ State: {0,-15} PID: {1}", conn.State, conn.Pid));
            Console.WriteLine("╠═══════════════════════════════════════════════════════════════════");

            // Try to enable and retrieve statistics
            bool statsEnabled;
            if (conn.IsIPv6)
            {
                statsEnabled = EnableConnection6Stats(ref conn.RowV6);
            }
            else
            {
                statsEnabled = EnableConnectionStats(ref conn.RowV4);
            }
            
            if (!statsEnabled)
            {
                Console.WriteLine("║");
                Console.WriteLine("║ [TCP Statistics NOT Available]");
                Console.WriteLine("║ Run as Administrator to enable statistics collection.");
                Console.WriteLine("║ Use: Right-click Command Prompt → 'Run as administrator'");
                Console.WriteLine("╚═══════════════════════════════════════════════════════════════════\n");
                return;
            }

            // Get all available statistics
            TCP_ESTATS_DATA_ROD_v0? data;
            TCP_ESTATS_PATH_ROD_v0? path;
            TCP_ESTATS_SND_CONG_ROD_v0? sndCong;
            TCP_ESTATS_SEND_BUFF_ROD_v0? sendBuff;
            TCP_ESTATS_REC_ROD_v0? rec;
            TCP_ESTATS_OBS_REC_ROD_v0? obsRec;
            TCP_ESTATS_BANDWIDTH_ROD_v0? bandwidth;
            TCP_ESTATS_FINE_RTT_ROD_v0? fineRtt;

            if (conn.IsIPv6)
            {
                var row = conn.RowV6;
                data = GetConnection6Stats<TCP_ESTATS_DATA_ROD_v0>(ref row, TCP_ESTATS_TYPE.TcpConnectionEstatsData);
                path = GetConnection6Stats<TCP_ESTATS_PATH_ROD_v0>(ref row, TCP_ESTATS_TYPE.TcpConnectionEstatsPath);
                sndCong = GetConnection6Stats<TCP_ESTATS_SND_CONG_ROD_v0>(ref row, TCP_ESTATS_TYPE.TcpConnectionEstatsSndCong);
                sendBuff = GetConnection6Stats<TCP_ESTATS_SEND_BUFF_ROD_v0>(ref row, TCP_ESTATS_TYPE.TcpConnectionEstatsSendBuff);
                rec = GetConnection6Stats<TCP_ESTATS_REC_ROD_v0>(ref row, TCP_ESTATS_TYPE.TcpConnectionEstatsRec);
                obsRec = GetConnection6Stats<TCP_ESTATS_OBS_REC_ROD_v0>(ref row, TCP_ESTATS_TYPE.TcpConnectionEstatsObsRec);
                bandwidth = GetConnection6Stats<TCP_ESTATS_BANDWIDTH_ROD_v0>(ref row, TCP_ESTATS_TYPE.TcpConnectionEstatsBandwidth);
                fineRtt = GetConnection6Stats<TCP_ESTATS_FINE_RTT_ROD_v0>(ref row, TCP_ESTATS_TYPE.TcpConnectionEstatsFineRtt);
            }
            else
            {
                var row = conn.RowV4;
                data = GetConnectionStats<TCP_ESTATS_DATA_ROD_v0>(ref row, TCP_ESTATS_TYPE.TcpConnectionEstatsData);
                path = GetConnectionStats<TCP_ESTATS_PATH_ROD_v0>(ref row, TCP_ESTATS_TYPE.TcpConnectionEstatsPath);
                sndCong = GetConnectionStats<TCP_ESTATS_SND_CONG_ROD_v0>(ref row, TCP_ESTATS_TYPE.TcpConnectionEstatsSndCong);
                sendBuff = GetConnectionStats<TCP_ESTATS_SEND_BUFF_ROD_v0>(ref row, TCP_ESTATS_TYPE.TcpConnectionEstatsSendBuff);
                rec = GetConnectionStats<TCP_ESTATS_REC_ROD_v0>(ref row, TCP_ESTATS_TYPE.TcpConnectionEstatsRec);
                obsRec = GetConnectionStats<TCP_ESTATS_OBS_REC_ROD_v0>(ref row, TCP_ESTATS_TYPE.TcpConnectionEstatsObsRec);
                bandwidth = GetConnectionStats<TCP_ESTATS_BANDWIDTH_ROD_v0>(ref row, TCP_ESTATS_TYPE.TcpConnectionEstatsBandwidth);
                fineRtt = GetConnectionStats<TCP_ESTATS_FINE_RTT_ROD_v0>(ref row, TCP_ESTATS_TYPE.TcpConnectionEstatsFineRtt);
            }

            // Display data statistics - comprehensive view
            if (data.HasValue)
            {
                var d = data.Value;
                Console.WriteLine("║ DATA TRANSFER:");
                Console.WriteLine(string.Format("║   Data Bytes Out:      {0,15} bytes    Data Bytes In:       {1,15} bytes", 
                    FormatValue(d.DataBytesOut), FormatValue(d.DataBytesIn)));
                Console.WriteLine(string.Format("║   Data Segs Out:       {0,15} pkts     Data Segs In:        {1,15} pkts", 
                    FormatValue(d.DataSegsOut), FormatValue(d.DataSegsIn)));
                Console.WriteLine(string.Format("║   Total Segs Out:      {0,15} pkts     Total Segs In:       {1,15} pkts", 
                    FormatValue(d.SegsOut), FormatValue(d.SegsIn)));
                Console.WriteLine(string.Format("║   Thru Bytes Acked:    {0,15} bytes    Thru Bytes Received: {1,15} bytes", 
                    FormatValue(d.ThruBytesAcked), FormatValue(d.ThruBytesReceived)));
                Console.WriteLine("║");
                Console.WriteLine("║ RETRANSMISSIONS:");
                Console.WriteLine(string.Format("║   Segments Retrans:    {0,15} pkts", FormatValue(d.SegsRetrans)));
                Console.WriteLine(string.Format("║   Bytes Retrans:       {0,15} bytes", FormatValue(d.BytesRetrans)));
                Console.WriteLine(string.Format("║   Fast Retransmits:    {0,15} count", FormatValue(d.FastRetran)));
                Console.WriteLine(string.Format("║   Timeout Episodes:    {0,15} count", FormatValue(d.TimeoutEpisodes)));
                Console.WriteLine(string.Format("║   SYN Retransmits:     {0,15} count", d.SynRetrans));
                Console.WriteLine("║");
                Console.WriteLine("║ DUPLICATE ACKS & ERRORS:");
                Console.WriteLine(string.Format("║   Dup ACKs In:         {0,15} pkts", FormatValue(d.DupAcksIn)));
                Console.WriteLine(string.Format("║   Soft Errors:         {0,15} count    Reason: {1}", 
                    FormatValue(d.SoftErrors), FormatValue(d.SoftErrorReason)));
                Console.WriteLine("║");
                Console.WriteLine("║ SEQUENCE NUMBERS:");
                Console.WriteLine(string.Format("║   SndUna: {0,12}  SndNxt: {1,12}  SndMax: {2,12}  RcvNxt: {3,12}", 
                    FormatValue(d.SndUna), FormatValue(d.SndNxt), FormatValue(d.SndMax), FormatValue(d.RcvNxt)));
            }

            // Display path statistics - comprehensive view
            if (path.HasValue)
            {
                var p = path.Value;
                Console.WriteLine("║");
                Console.WriteLine("║ PATH METRICS:");
                Console.WriteLine(string.Format("║   Sample RTT:          {0,10} ms      Smoothed RTT:        {1,10} ms", 
                    FormatValue(p.SampleRtt), FormatValue(p.SmoothedRtt)));
                Console.WriteLine(string.Format("║   RTT Variance:        {0,10} ms      Min RTT:             {1,10} ms", 
                    FormatValue(p.RttVar), FormatValue(p.MinRtt)));
                Console.WriteLine(string.Format("║   Max RTT:             {0,10} ms      Sum RTT:             {1,10} ms", 
                    FormatValue(p.MaxRtt), FormatValue(p.SumRtt)));
                Console.WriteLine(string.Format("║   RTT Count:           {0,10} samples", FormatValue(p.CountRtt)));
                Console.WriteLine("║");
                Console.WriteLine("║ RETRANSMISSION TIMEOUTS (RTO):");
                Console.WriteLine(string.Format("║   Current RTO:         {0,10} ms      Min RTO:             {1,10} ms", 
                    FormatValue(p.CurRto), FormatValue(p.MinRto)));
                Console.WriteLine(string.Format("║   Max RTO:             {0,10} ms", FormatValue(p.MaxRto)));
                Console.WriteLine(string.Format("║   Timeouts:            {0,10} count    Subsequent:          {1,10} count", 
                    FormatValue(p.Timeouts), FormatValue(p.SubsequentTimeouts)));
                Console.WriteLine(string.Format("║   Cur Timeout Count:   {0,10} count    Abrupt Timeouts:     {1,10} count", 
                    FormatValue(p.CurTimeoutCount), FormatValue(p.AbruptTimeouts)));
                Console.WriteLine(string.Format("║   Spurious RTO Detect: {0,10} count", FormatValue(p.SpuriousRtoDetections)));
                Console.WriteLine("║");
                Console.WriteLine("║ RETRANSMISSIONS (PATH):");
                Console.WriteLine(string.Format("║   Packets Retrans:     {0,15} pkts", FormatValue(p.PktsRetrans)));
                Console.WriteLine(string.Format("║   Bytes Retrans:       {0,15} bytes", FormatValue(p.BytesRetrans)));
                Console.WriteLine(string.Format("║   Fast Retrans:        {0,15} count", FormatValue(p.FastRetran)));
                Console.WriteLine(string.Format("║   Retrans Threshold:   {0,10} pkts", FormatValue(p.RetranThresh)));
                Console.WriteLine("║");
                Console.WriteLine("║ DUPLICATE ACKS & SACKS:");
                Console.WriteLine(string.Format("║   Dup ACKs In:         {0,15} pkts", FormatValue(p.DupAcksIn)));
                Console.WriteLine(string.Format("║   Dup ACK Episodes:    {0,15} count", FormatValue(p.SndDupAckEpisodes)));
                Console.WriteLine(string.Format("║   SACKs Received:      {0,15} pkts", FormatValue(p.SacksRcvd)));
                Console.WriteLine(string.Format("║   SACK Blocks Rcvd:    {0,15} blocks", FormatValue(p.SackBlocksRcvd)));
                Console.WriteLine(string.Format("║   DSACK Duplicates:    {0,15} count", FormatValue(p.DsackDups)));
                Console.WriteLine("║");
                Console.WriteLine("║ REORDERING:");
                Console.WriteLine(string.Format("║   Bytes Reordered:     {0,15} bytes", FormatValue(p.SumBytesReordered)));
                Console.WriteLine(string.Format("║   Non-Recov DA:        {0,10} count    Episodes:            {1,10} count", 
                    FormatValue(p.NonRecovDa), FormatValue(p.NonRecovDaEpisodes)));
                Console.WriteLine(string.Format("║   ACK After FR:        {0,15} pkts", FormatValue(p.AckAfterFr)));
                Console.WriteLine("║");
                Console.WriteLine("║ CONGESTION SIGNALS:");
                Console.WriteLine(string.Format("║   Congestion Signals:  {0,15} count", FormatValue(p.CongSignals)));
                Console.WriteLine(string.Format("║   ECN Signals:         {0,10} count    ECE Received:        {1,10} pkts", 
                    FormatValue(p.EcnSignals), FormatValue(p.EceRcvd)));
                Console.WriteLine(string.Format("║   Pre-Cong Sum Cwnd:   {0,10} bytes    Pre-Cong Sum RTT:    {1,10} ms", 
                    FormatValue(p.PreCongSumCwnd), FormatValue(p.PreCongSumRtt)));
                Console.WriteLine(string.Format("║   Post-Cong Sum RTT:   {0,10} ms       Post-Cong Count:     {1,10} count", 
                    FormatValue(p.PostCongSumRtt), FormatValue(p.PostCongCountRtt)));
                Console.WriteLine("║");
                Console.WriteLine("║ MAXIMUM SEGMENT SIZE:");
                Console.WriteLine(string.Format("║   Current MSS:         {0,10} bytes", FormatValue(p.CurMss)));
                Console.WriteLine(string.Format("║   Max MSS:             {0,10} bytes    Min MSS:             {1,10} bytes", 
                    FormatValue(p.MaxMss), FormatValue(p.MinMss)));
                Console.WriteLine("║");
                Console.WriteLine("║ OTHER:");
                Console.WriteLine(string.Format("║   Send Stall:          {0,10} count    Quench Received:     {1,10} count", 
                    FormatValue(p.SendStall), FormatValue(p.QuenchRcvd)));
            }

            // Display congestion control - comprehensive
            if (sndCong.HasValue)
            {
                var s = sndCong.Value;
                Console.WriteLine("║");
                Console.WriteLine("║ CONGESTION CONTROL:");
                Console.WriteLine(string.Format("║   Current Cwnd:        {0,15} bytes", FormatValue(s.CurCwnd)));
                Console.WriteLine(string.Format("║   Current Ssthresh:    {0,15} bytes", FormatValue(s.CurSsthresh)));
                Console.WriteLine(string.Format("║   Max Slow Start Cwnd: {0,15} bytes", FormatValue(s.MaxSsCwnd)));
                Console.WriteLine(string.Format("║   Max Cong Avoid Cwnd: {0,15} bytes", FormatValue(s.MaxCaCwnd)));
                Console.WriteLine(string.Format("║   Max Ssthresh:        {0,15} bytes", FormatValue(s.MaxSsthresh)));
                Console.WriteLine(string.Format("║   Min Ssthresh:        {0,15} bytes", FormatValue(s.MinSsthresh)));
                Console.WriteLine("║");
                Console.WriteLine("║ CONGESTION PHASES:");
                Console.WriteLine(string.Format("║   Slow Start Count:    {0,10} count", FormatValue(s.SlowStart)));
                Console.WriteLine(string.Format("║   Cong Avoidance Cnt:  {0,10} count", FormatValue(s.CongAvoid)));
                Console.WriteLine(string.Format("║   Other Reductions:    {0,10} count", FormatValue(s.OtherReductions)));
                Console.WriteLine("║");
                Console.WriteLine("║ SEND LIMITING (Receiver Window):");
                Console.WriteLine(string.Format("║   Trans Limited:       {0,10} count    Time Limited:        {1,10} ms", 
                    FormatValue(s.SndLimTransRwin), FormatValue(s.SndLimTimeRwin)));
                Console.WriteLine(string.Format("║   Bytes Limited:       {0,15} bytes", FormatValue(s.SndLimBytesRwin)));
                Console.WriteLine("║ SEND LIMITING (Congestion Window):");
                Console.WriteLine(string.Format("║   Trans Limited:       {0,10} count    Time Limited:        {1,10} ms", 
                    FormatValue(s.SndLimTransCwnd), FormatValue(s.SndLimTimeCwnd)));
                Console.WriteLine(string.Format("║   Bytes Limited:       {0,15} bytes", FormatValue(s.SndLimBytesCwnd)));
                Console.WriteLine("║ SEND LIMITING (Sender):");
                Console.WriteLine(string.Format("║   Trans Limited:       {0,10} count    Time Limited:        {1,10} ms", 
                    FormatValue(s.SndLimTransSnd), FormatValue(s.SndLimTimeSnd)));
                Console.WriteLine(string.Format("║   Bytes Limited:       {0,15} bytes", FormatValue(s.SndLimBytesSnd)));
            }

            // Display send buffer - comprehensive
            if (sendBuff.HasValue)
            {
                var sb = sendBuff.Value;
                Console.WriteLine("║");
                Console.WriteLine("║ SEND BUFFERS:");
                Console.WriteLine(string.Format("║   Cur Retrans Queue:   {0,15} bytes", FormatValue(sb.CurRetxQueue)));
                Console.WriteLine(string.Format("║   Max Retrans Queue:   {0,15} bytes", FormatValue(sb.MaxRetxQueue)));
                Console.WriteLine(string.Format("║   Cur App Write Queue: {0,15} bytes", FormatValue(sb.CurAppWQueue)));
                Console.WriteLine(string.Format("║   Max App Write Queue: {0,15} bytes", FormatValue(sb.MaxAppWQueue)));
            }

            // Display receive statistics - comprehensive
            if (rec.HasValue)
            {
                var r = rec.Value;
                Console.WriteLine("║");
                Console.WriteLine("║ RECEIVE WINDOWS:");
                Console.WriteLine(string.Format("║   Cur Rwin Sent:       {0,15} bytes", FormatValue(r.CurRwinSent)));
                Console.WriteLine(string.Format("║   Max Rwin Sent:       {0,15} bytes", FormatValue(r.MaxRwinSent)));
                Console.WriteLine(string.Format("║   Min Rwin Sent:       {0,15} bytes", FormatValue(r.MinRwinSent)));
                Console.WriteLine(string.Format("║   Cur Rwin Received:   {0,15} bytes", FormatValue(r.CurRwinRcvd)));
                Console.WriteLine(string.Format("║   Max Rwin Received:   {0,15} bytes", FormatValue(r.MaxRwinRcvd)));
                Console.WriteLine(string.Format("║   Min Rwin Received:   {0,15} bytes", FormatValue(r.MinRwinRcvd)));
                Console.WriteLine(string.Format("║   Limited Rwin:        {0,15} bytes", FormatValue(r.LimRwin)));
                Console.WriteLine("║");
                Console.WriteLine("║ WINDOW SCALING:");
                Console.WriteLine(string.Format("║   Win Scale Sent:      {0,10} shift    Win Scale Received:  {1,10} shift", 
                    r.WinScaleSent, r.WinScaleRcvd));
                Console.WriteLine("║");
                Console.WriteLine("║ DUPLICATE ACKS & ECN:");
                Console.WriteLine(string.Format("║   Dup ACK Episodes:    {0,10} count    Dup ACKs Out:        {1,10} pkts", 
                    FormatValue(r.DupAckEpisodes), FormatValue(r.DupAcksOut)));
                Console.WriteLine(string.Format("║   CE Received:         {0,10} pkts     ECN Sent:            {1,10} pkts", 
                    FormatValue(r.CeRcvd), FormatValue(r.EcnSent)));
                Console.WriteLine(string.Format("║   ECN Nonces Received: {0,10} count", FormatValue(r.EcnNoncesRcvd)));
                Console.WriteLine("║");
                Console.WriteLine("║ RECEIVE QUEUES:");
                Console.WriteLine(string.Format("║   Cur Reassembly Q:    {0,15} bytes", FormatValue(r.CurReasmQueue)));
                Console.WriteLine(string.Format("║   Max Reassembly Q:    {0,15} bytes", FormatValue(r.MaxReasmQueue)));
                Console.WriteLine(string.Format("║   Cur App Read Queue:  {0,15} bytes", FormatValue(r.CurAppRQueue)));
                Console.WriteLine(string.Format("║   Max App Read Queue:  {0,15} bytes", FormatValue(r.MaxAppRQueue)));
            }

            // Display observed receive statistics
            if (obsRec.HasValue)
            {
                var or = obsRec.Value;
                Console.WriteLine("║");
                Console.WriteLine("║ OBSERVED RECEIVE:");
                Console.WriteLine(string.Format("║   Min RTT:             {0,10} ms      Base RTT:            {1,10} ms", 
                    FormatValue(or.MinRtt), FormatValue(or.BaseRtt)));
                Console.WriteLine(string.Format("║   Cur Rwin Received:   {0,15} bytes", FormatValue(or.CurRwinRcvd)));
                Console.WriteLine(string.Format("║   Max Rwin Received:   {0,15} bytes", FormatValue(or.MaxRwinRcvd)));
                Console.WriteLine(string.Format("║   Min Rwin Received:   {0,15} bytes", FormatValue(or.MinRwinRcvd)));
                Console.WriteLine(string.Format("║   Win Scale Received:  {0,10} shift", or.WinScaleRcvd));
            }

            // Display bandwidth estimate
            if (bandwidth.HasValue)
            {
                var bw = bandwidth.Value;
                Console.WriteLine("║");
                Console.WriteLine("║ BANDWIDTH ESTIMATES:");
                Console.WriteLine(string.Format("║   Outbound:            {0,15} bps", FormatValue(bw.OutboundBandwidth)));
                Console.WriteLine(string.Format("║   Inbound:             {0,15} bps", FormatValue(bw.InboundBandwidth)));
                Console.WriteLine(string.Format("║   Outbound Instability:{0,15} count", FormatValue(bw.OutboundInstability)));
                Console.WriteLine(string.Format("║   Inbound Instability: {0,15} count", FormatValue(bw.InboundInstability)));
                Console.WriteLine(string.Format("║   Outbound Peaked:     {0,10} flag     Inbound Peaked:      {1,10} flag", 
                    bw.OutboundBandwidthPeaked, bw.InboundBandwidthPeaked));
            }

            // Display fine-grained RTT (convert microseconds to milliseconds)
            if (fineRtt.HasValue)
            {
                var fr = fineRtt.Value;
                Console.WriteLine("║");
                Console.WriteLine("║ FINE-GRAINED RTT (High Resolution):");
                
                string rttVar = (fr.RttVar == uint.MaxValue) ? "N/A" : string.Format("{0:F3} ms", fr.RttVar / 1000.0);
                string maxRtt = (fr.MaxRtt == uint.MaxValue) ? "N/A" : string.Format("{0:F3} ms", fr.MaxRtt / 1000.0);
                string minRtt = (fr.MinRtt == uint.MaxValue) ? "N/A" : string.Format("{0:F3} ms", fr.MinRtt / 1000.0);
                string sumRtt = (fr.SumRtt == uint.MaxValue) ? "N/A" : string.Format("{0:F3} ms", fr.SumRtt / 1000.0);
                
                Console.WriteLine(string.Format("║   RTT Variance:        {0,10}", rttVar));
                Console.WriteLine(string.Format("║   Max RTT:             {0,10}", maxRtt));
                Console.WriteLine(string.Format("║   Min RTT:             {0,10}", minRtt));
                Console.WriteLine(string.Format("║   Sum RTT:             {0,10}", sumRtt));
            }

            Console.WriteLine("╚═══════════════════════════════════════════════════════════════════\n");
        }

        static bool EnableConnectionStats(ref MIB_TCPROW row)
        {
            // Enable all available statistics types
            var statsTypes = new[]
            {
                TCP_ESTATS_TYPE.TcpConnectionEstatsData,
                TCP_ESTATS_TYPE.TcpConnectionEstatsPath,
                TCP_ESTATS_TYPE.TcpConnectionEstatsSndCong,
                TCP_ESTATS_TYPE.TcpConnectionEstatsSendBuff,
                TCP_ESTATS_TYPE.TcpConnectionEstatsRec,
                TCP_ESTATS_TYPE.TcpConnectionEstatsObsRec,
                TCP_ESTATS_TYPE.TcpConnectionEstatsBandwidth,
                TCP_ESTATS_TYPE.TcpConnectionEstatsFineRtt
            };

            bool anyEnabled = false;

            foreach (var type in statsTypes)
            {
                var rw = new TCP_ESTATS_DATA_RW_v0 { EnableCollection = 1 };
                int rwSize = Marshal.SizeOf(typeof(TCP_ESTATS_DATA_RW_v0));
                
                IntPtr rwPtr = Marshal.AllocHGlobal(rwSize);
                try
                {
                    Marshal.StructureToPtr(rw, rwPtr, false);
                    
                    uint result = SetPerTcpConnectionEStats(
                        ref row,
                        type,
                        rwPtr,
                        0,
                        rwSize,
                        0
                    );

                    if (result == 0)
                        anyEnabled = true;
                }
                finally
                {
                    Marshal.FreeHGlobal(rwPtr);
                }
            }

            return anyEnabled;
        }

        static bool EnableConnection6Stats(ref MIB_TCP6ROW row)
        {
            // Enable all available statistics types for IPv6
            var statsTypes = new[]
            {
                TCP_ESTATS_TYPE.TcpConnectionEstatsData,
                TCP_ESTATS_TYPE.TcpConnectionEstatsPath,
                TCP_ESTATS_TYPE.TcpConnectionEstatsSndCong,
                TCP_ESTATS_TYPE.TcpConnectionEstatsSendBuff,
                TCP_ESTATS_TYPE.TcpConnectionEstatsRec,
                TCP_ESTATS_TYPE.TcpConnectionEstatsObsRec,
                TCP_ESTATS_TYPE.TcpConnectionEstatsBandwidth,
                TCP_ESTATS_TYPE.TcpConnectionEstatsFineRtt
            };

            bool anyEnabled = false;

            foreach (var type in statsTypes)
            {
                var rw = new TCP_ESTATS_DATA_RW_v0 { EnableCollection = 1 };
                int rwSize = Marshal.SizeOf(typeof(TCP_ESTATS_DATA_RW_v0));
                
                IntPtr rwPtr = Marshal.AllocHGlobal(rwSize);
                try
                {
                    Marshal.StructureToPtr(rw, rwPtr, false);
                    
                    uint result = SetPerTcp6ConnectionEStats(
                        ref row,
                        type,
                        rwPtr,
                        0,
                        rwSize,
                        0
                    );

                    if (result == 0)
                        anyEnabled = true;
                }
                finally
                {
                    Marshal.FreeHGlobal(rwPtr);
                }
            }

            return anyEnabled;
        }

        static T? GetConnection6Stats<T>(ref MIB_TCP6ROW row, TCP_ESTATS_TYPE type) where T : struct
        {
            int rodSize = Marshal.SizeOf(typeof(T));
            IntPtr rodPtr = Marshal.AllocHGlobal(rodSize);

            try
            {
                // Zero the memory buffer before calling API
                byte[] zeros = new byte[rodSize];
                Marshal.Copy(zeros, 0, rodPtr, rodSize);
                
                uint result = GetPerTcp6ConnectionEStats(
                    ref row,
                    type,
                    IntPtr.Zero, 0, 0,
                    IntPtr.Zero, 0, 0,
                    rodPtr, 0, rodSize
                );

                if (result == 0)
                {
                    return (T)Marshal.PtrToStructure(rodPtr, typeof(T));
                }
            }
            catch { }
            finally
            {
                Marshal.FreeHGlobal(rodPtr);
            }

            return null;
        }

        static TCP_ESTATS_DATA_ROD_v0? GetConnectionData(ref MIB_TCPROW row)
        {
            return GetConnectionStats<TCP_ESTATS_DATA_ROD_v0>(
                ref row, 
                TCP_ESTATS_TYPE.TcpConnectionEstatsData
            );
        }

        static TCP_ESTATS_PATH_ROD_v0? GetPathStats(ref MIB_TCPROW row)
        {
            return GetConnectionStats<TCP_ESTATS_PATH_ROD_v0>(
                ref row,
                TCP_ESTATS_TYPE.TcpConnectionEstatsPath
            );
        }

        static TCP_ESTATS_SND_CONG_ROD_v0? GetSndCongestionStats(ref MIB_TCPROW row)
        {
            return GetConnectionStats<TCP_ESTATS_SND_CONG_ROD_v0>(
                ref row,
                TCP_ESTATS_TYPE.TcpConnectionEstatsSndCong
            );
        }

        static TCP_ESTATS_SEND_BUFF_ROD_v0? GetSendBuffStats(ref MIB_TCPROW row)
        {
            return GetConnectionStats<TCP_ESTATS_SEND_BUFF_ROD_v0>(
                ref row,
                TCP_ESTATS_TYPE.TcpConnectionEstatsSendBuff
            );
        }

        static TCP_ESTATS_REC_ROD_v0? GetRecStats(ref MIB_TCPROW row)
        {
            return GetConnectionStats<TCP_ESTATS_REC_ROD_v0>(
                ref row,
                TCP_ESTATS_TYPE.TcpConnectionEstatsRec
            );
        }

        static TCP_ESTATS_OBS_REC_ROD_v0? GetObsRecStats(ref MIB_TCPROW row)
        {
            return GetConnectionStats<TCP_ESTATS_OBS_REC_ROD_v0>(
                ref row,
                TCP_ESTATS_TYPE.TcpConnectionEstatsObsRec
            );
        }

        static TCP_ESTATS_BANDWIDTH_ROD_v0? GetBandwidthStats(ref MIB_TCPROW row)
        {
            return GetConnectionStats<TCP_ESTATS_BANDWIDTH_ROD_v0>(
                ref row,
                TCP_ESTATS_TYPE.TcpConnectionEstatsBandwidth
            );
        }

        static TCP_ESTATS_FINE_RTT_ROD_v0? GetFineRttStats(ref MIB_TCPROW row)
        {
            return GetConnectionStats<TCP_ESTATS_FINE_RTT_ROD_v0>(
                ref row,
                TCP_ESTATS_TYPE.TcpConnectionEstatsFineRtt
            );
        }

        static T? GetConnectionStats<T>(ref MIB_TCPROW row, TCP_ESTATS_TYPE type) where T : struct
        {
            int rodSize = Marshal.SizeOf(typeof(T));
            IntPtr rodPtr = Marshal.AllocHGlobal(rodSize);

            try
            {
                // Zero the memory buffer before calling API
                byte[] zeros = new byte[rodSize];
                Marshal.Copy(zeros, 0, rodPtr, rodSize);
                
                uint result = GetPerTcpConnectionEStats(
                    ref row,
                    type,
                    IntPtr.Zero, 0, 0,
                    IntPtr.Zero, 0, 0,
                    rodPtr, 0, rodSize
                );

                if (result == 0)
                {
                    return (T)Marshal.PtrToStructure(rodPtr, typeof(T));
                }
            }
            catch { }
            finally
            {
                Marshal.FreeHGlobal(rodPtr);
            }

            return null;
        }

        // Unified connection info for both IPv4 and IPv6
        class TcpConnectionInfo
        {
            public IPAddress LocalAddress;
            public ushort LocalPort;
            public IPAddress RemoteAddress;
            public ushort RemotePort;
            public MIB_TCP_STATE State;
            public uint Pid;
            public bool IsIPv6;
            
            // For statistics queries
            public MIB_TCPROW RowV4;
            public MIB_TCP6ROW RowV6;
        }

        static IPAddress BytesToIPAddress(byte[] bytes)
        {
            return new IPAddress(bytes);
        }

        static List<TcpConnectionInfo> GetTcpConnections()
        {
            var connections = new List<TcpConnectionInfo>();
            int bufferSize = 0;

            uint result = GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true,
                AF_INET, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);

            IntPtr tcpTablePtr = Marshal.AllocHGlobal(bufferSize);

            try
            {
                result = GetExtendedTcpTable(tcpTablePtr, ref bufferSize, true,
                    AF_INET, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);

                if (result != 0)
                    throw new Exception(string.Format("GetExtendedTcpTable failed: {0}", result));

                var table = (MIB_TCPTABLE_OWNER_PID)Marshal.PtrToStructure(
                    tcpTablePtr, typeof(MIB_TCPTABLE_OWNER_PID));
                
                IntPtr rowPtr = (IntPtr)((long)tcpTablePtr + Marshal.SizeOf(table.dwNumEntries));

                for (int i = 0; i < table.dwNumEntries; i++)
                {
                    var row = (MIB_TCPROW_OWNER_PID)Marshal.PtrToStructure(
                        rowPtr, typeof(MIB_TCPROW_OWNER_PID));
                    
                    var connInfo = new TcpConnectionInfo
                    {
                        LocalAddress = new IPAddress(row.dwLocalAddr),
                        LocalPort = (ushort)IPAddress.NetworkToHostOrder((short)row.dwLocalPort),
                        RemoteAddress = new IPAddress(row.dwRemoteAddr),
                        RemotePort = (ushort)IPAddress.NetworkToHostOrder((short)row.dwRemotePort),
                        State = row.dwState,
                        Pid = row.dwOwningPid,
                        IsIPv6 = false,
                        RowV4 = new MIB_TCPROW
                        {
                            dwState = row.dwState,
                            dwLocalAddr = row.dwLocalAddr,
                            dwLocalPort = row.dwLocalPort,
                            dwRemoteAddr = row.dwRemoteAddr,
                            dwRemotePort = row.dwRemotePort
                        }
                    };
                    
                    connections.Add(connInfo);
                    rowPtr = (IntPtr)((long)rowPtr + Marshal.SizeOf(typeof(MIB_TCPROW_OWNER_PID)));
                }
            }
            finally
            {
                Marshal.FreeHGlobal(tcpTablePtr);
            }

            return connections;
        }

        static List<TcpConnectionInfo> GetTcp6Connections()
        {
            var connections = new List<TcpConnectionInfo>();
            int bufferSize = 0;

            uint result = GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true,
                AF_INET6, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);

            IntPtr tcpTablePtr = Marshal.AllocHGlobal(bufferSize);

            try
            {
                result = GetExtendedTcpTable(tcpTablePtr, ref bufferSize, true,
                    AF_INET6, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);

                if (result != 0)
                {
                    // IPv6 may not be available on all systems
                    Marshal.FreeHGlobal(tcpTablePtr);
                    return connections;
                }

                var table = (MIB_TCP6TABLE_OWNER_PID)Marshal.PtrToStructure(
                    tcpTablePtr, typeof(MIB_TCP6TABLE_OWNER_PID));
                
                IntPtr rowPtr = (IntPtr)((long)tcpTablePtr + Marshal.SizeOf(table.dwNumEntries));

                for (int i = 0; i < table.dwNumEntries; i++)
                {
                    var row = (MIB_TCP6ROW_OWNER_PID)Marshal.PtrToStructure(
                        rowPtr, typeof(MIB_TCP6ROW_OWNER_PID));
                    
                    var connInfo = new TcpConnectionInfo
                    {
                        LocalAddress = BytesToIPAddress(row.ucLocalAddr),
                        LocalPort = (ushort)IPAddress.NetworkToHostOrder((short)row.dwLocalPort),
                        RemoteAddress = BytesToIPAddress(row.ucRemoteAddr),
                        RemotePort = (ushort)IPAddress.NetworkToHostOrder((short)row.dwRemotePort),
                        State = row.dwState,
                        Pid = row.dwOwningPid,
                        IsIPv6 = true,
                        RowV6 = new MIB_TCP6ROW
                        {
                            LocalAddr = row.ucLocalAddr,
                            LocalScopeId = row.dwLocalScopeId,
                            LocalPort = row.dwLocalPort,
                            RemoteAddr = row.ucRemoteAddr,
                            RemoteScopeId = row.dwRemoteScopeId,
                            RemotePort = row.dwRemotePort,
                            State = row.dwState
                        }
                    };
                    
                    connections.Add(connInfo);
                    rowPtr = (IntPtr)((long)rowPtr + Marshal.SizeOf(typeof(MIB_TCP6ROW_OWNER_PID)));
                }
            }
            finally
            {
                Marshal.FreeHGlobal(tcpTablePtr);
            }

            return connections;
        }

        #region Windows API

        const int AF_INET = 2;
        const int AF_INET6 = 23;

        [DllImport("iphlpapi.dll", SetLastError = true)]
        static extern uint GetExtendedTcpTable(
            IntPtr pTcpTable,
            ref int pdwSize,
            bool bOrder,
            int ulAf,
            TCP_TABLE_CLASS TableClass,
            uint Reserved = 0
        );

        [DllImport("iphlpapi.dll", SetLastError = true)]
        static extern uint SetPerTcpConnectionEStats(
            ref MIB_TCPROW Row,
            TCP_ESTATS_TYPE EstatsType,
            IntPtr Rw,
            uint RwVersion,
            int RwSize,
            uint Offset
        );

        [DllImport("iphlpapi.dll", SetLastError = true)]
        static extern uint GetPerTcpConnectionEStats(
            ref MIB_TCPROW Row,
            TCP_ESTATS_TYPE EstatsType,
            IntPtr Rw, uint RwVersion, int RwSize,
            IntPtr Ros, uint RosVersion, int RosSize,
            IntPtr Rod, uint RodVersion, int RodSize
        );

        [DllImport("iphlpapi.dll", SetLastError = true)]
        static extern uint SetPerTcp6ConnectionEStats(
            ref MIB_TCP6ROW Row,
            TCP_ESTATS_TYPE EstatsType,
            IntPtr Rw,
            uint RwVersion,
            int RwSize,
            uint Offset
        );

        [DllImport("iphlpapi.dll", SetLastError = true)]
        static extern uint GetPerTcp6ConnectionEStats(
            ref MIB_TCP6ROW Row,
            TCP_ESTATS_TYPE EstatsType,
            IntPtr Rw, uint RwVersion, int RwSize,
            IntPtr Ros, uint RosVersion, int RosSize,
            IntPtr Rod, uint RodVersion, int RodSize
        );

        enum TCP_TABLE_CLASS
        {
            TCP_TABLE_BASIC_LISTENER,
            TCP_TABLE_BASIC_CONNECTIONS,
            TCP_TABLE_BASIC_ALL,
            TCP_TABLE_OWNER_PID_LISTENER,
            TCP_TABLE_OWNER_PID_CONNECTIONS,
            TCP_TABLE_OWNER_PID_ALL,
            TCP_TABLE_OWNER_MODULE_LISTENER,
            TCP_TABLE_OWNER_MODULE_CONNECTIONS,
            TCP_TABLE_OWNER_MODULE_ALL
        }

        enum MIB_TCP_STATE
        {
            CLOSED = 1,
            LISTEN = 2,
            SYN_SENT = 3,
            SYN_RCVD = 4,
            ESTABLISHED = 5,
            FIN_WAIT1 = 6,
            FIN_WAIT2 = 7,
            CLOSE_WAIT = 8,
            CLOSING = 9,
            LAST_ACK = 10,
            TIME_WAIT = 11,
            DELETE_TCB = 12
        }

        enum TCP_ESTATS_TYPE
        {
            TcpConnectionEstatsSynOpts,
            TcpConnectionEstatsData,
            TcpConnectionEstatsSndCong,
            TcpConnectionEstatsPath,
            TcpConnectionEstatsSendBuff,
            TcpConnectionEstatsRec,
            TcpConnectionEstatsObsRec,
            TcpConnectionEstatsBandwidth,
            TcpConnectionEstatsFineRtt,
            TcpConnectionEstatsMaximum
        }

        [StructLayout(LayoutKind.Sequential)]
        struct MIB_TCPTABLE_OWNER_PID
        {
            public uint dwNumEntries;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct MIB_TCPROW_OWNER_PID
        {
            public MIB_TCP_STATE dwState;
            public uint dwLocalAddr;
            public uint dwLocalPort;
            public uint dwRemoteAddr;
            public uint dwRemotePort;
            public uint dwOwningPid;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct MIB_TCPROW
        {
            public MIB_TCP_STATE dwState;
            public uint dwLocalAddr;
            public uint dwLocalPort;
            public uint dwRemoteAddr;
            public uint dwRemotePort;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct MIB_TCP6TABLE_OWNER_PID
        {
            public uint dwNumEntries;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct MIB_TCP6ROW_OWNER_PID
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] ucLocalAddr;
            public uint dwLocalScopeId;
            public uint dwLocalPort;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] ucRemoteAddr;
            public uint dwRemoteScopeId;
            public uint dwRemotePort;
            public MIB_TCP_STATE dwState;
            public uint dwOwningPid;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct MIB_TCP6ROW
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] LocalAddr;
            public uint LocalScopeId;
            public uint LocalPort;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] RemoteAddr;
            public uint RemoteScopeId;
            public uint RemotePort;
            public MIB_TCP_STATE State;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct TCP_ESTATS_DATA_RW_v0
        {
            public byte EnableCollection;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct TCP_ESTATS_DATA_ROD_v0
        {
            public ulong DataBytesOut;
            public ulong DataSegsOut;
            public ulong DataBytesIn;
            public ulong DataSegsIn;
            public ulong SegsOut;
            public ulong SegsIn;
            public uint SoftErrors;
            public uint SoftErrorReason;
            public uint SndUna;
            public uint SndNxt;
            public uint SndMax;
            public ulong ThruBytesAcked;
            public uint RcvNxt;
            public ulong ThruBytesReceived;
            public uint SegsRetrans;
            public uint BytesRetrans;
            public uint FastRetran;
            public uint DupAcksIn;
            public uint TimeoutEpisodes;
            public byte SynRetrans;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct TCP_ESTATS_PATH_ROD_v0
        {
            public uint FastRetran;
            public uint Timeouts;
            public uint SubsequentTimeouts;
            public uint CurTimeoutCount;
            public uint AbruptTimeouts;
            public uint PktsRetrans;
            public uint BytesRetrans;
            public uint DupAcksIn;
            public uint SacksRcvd;
            public uint SackBlocksRcvd;
            public uint CongSignals;
            public uint PreCongSumCwnd;
            public uint PreCongSumRtt;
            public uint PostCongSumRtt;
            public uint PostCongCountRtt;
            public uint EcnSignals;
            public uint EceRcvd;
            public uint SendStall;
            public uint QuenchRcvd;
            public uint RetranThresh;
            public uint SndDupAckEpisodes;
            public uint SumBytesReordered;
            public uint NonRecovDa;
            public uint NonRecovDaEpisodes;
            public uint AckAfterFr;
            public uint DsackDups;
            public uint SampleRtt;
            public uint SmoothedRtt;
            public uint RttVar;
            public uint MaxRtt;
            public uint MinRtt;
            public uint SumRtt;
            public uint CountRtt;
            public uint CurRto;
            public uint MaxRto;
            public uint MinRto;
            public uint CurMss;
            public uint MaxMss;
            public uint MinMss;
            public uint SpuriousRtoDetections;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct TCP_ESTATS_SND_CONG_ROD_v0
        {
            public uint SndLimTransRwin;
            public uint SndLimTimeRwin;
            public uint SndLimBytesRwin;
            public uint SndLimTransCwnd;
            public uint SndLimTimeCwnd;
            public uint SndLimBytesCwnd;
            public uint SndLimTransSnd;
            public uint SndLimTimeSnd;
            public uint SndLimBytesSnd;
            public uint SlowStart;
            public uint CongAvoid;
            public uint OtherReductions;
            public uint CurCwnd;
            public uint MaxSsCwnd;
            public uint MaxCaCwnd;
            public uint CurSsthresh;
            public uint MaxSsthresh;
            public uint MinSsthresh;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct TCP_ESTATS_SEND_BUFF_ROD_v0
        {
            public uint CurRetxQueue;
            public uint MaxRetxQueue;
            public uint CurAppWQueue;
            public uint MaxAppWQueue;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct TCP_ESTATS_REC_ROD_v0
        {
            public uint CurRwinSent;
            public uint MaxRwinSent;
            public uint MinRwinSent;
            public uint LimRwin;
            public uint DupAckEpisodes;
            public uint DupAcksOut;
            public uint CeRcvd;
            public uint EcnSent;
            public uint EcnNoncesRcvd;
            public uint CurReasmQueue;
            public uint MaxReasmQueue;
            public uint CurAppRQueue;
            public uint MaxAppRQueue;
            public byte WinScaleRcvd;
            public byte WinScaleSent;
            public uint CurRwinRcvd;
            public uint MaxRwinRcvd;
            public uint MinRwinRcvd;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct TCP_ESTATS_OBS_REC_ROD_v0
        {
            public uint CurRwinRcvd;
            public uint MaxRwinRcvd;
            public uint MinRwinRcvd;
            public byte WinScaleRcvd;
            public uint MinRtt;
            public uint BaseRtt;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct TCP_ESTATS_BANDWIDTH_ROD_v0
        {
            public ulong OutboundBandwidth;
            public ulong InboundBandwidth;
            public ulong OutboundInstability;
            public ulong InboundInstability;
            public byte OutboundBandwidthPeaked;
            public byte InboundBandwidthPeaked;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct TCP_ESTATS_FINE_RTT_ROD_v0
        {
            public uint RttVar;
            public uint MaxRtt;
            public uint MinRtt;
            public uint SumRtt;
        }

        #endregion
    }
}