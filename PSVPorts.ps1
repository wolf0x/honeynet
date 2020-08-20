<#

.DESCRIPTION
    Sentinel Guard:
    Creates jobs that listens on TCP Ports specified and when
    a connection is established, it can send msg to syslog server.
    SYN Scan will not be alerted until service fingerprint detection.
    It will auto omit the opened Ports and jobs closed when PS exits.

.PARAMETER  Ports
    List of Ports to listen in for connections.

.PARAMETER  WhiteList
    List of host that will not trigger alert.
    use -WhiteList for avoid the internal scanners.

.PARAMETER  SysLogSrv
    SysLogSrv Receiver IP Address, assigned at Line #52
    Finally did not parameter the variable

.PARAMETER  SysLogSrvPort
    SysLogSrv Receiver Port Number, default is 514

.EXAMPLE
    Example monitoring on different ports
        PS C:\> .\PSVPorts.ps1 -Ports 21,23,7001
        PS C:\> .\PSVPorts.ps1 -Ports 21,23,7001 -WhiteList 192.168.1.200,192.168.2.100

.NOTES
    Authors: wolf0x
    Stopping PSVPorts: (Or close the powershell console directly)
        PS C:\> stop-job -name VPort*
        PS C:\> remove-job -name VPort*
#>

[CmdletBinding()]
Param(
    [Parameter(
        Position = 0, 
        Mandatory = $False)]
    [int32[]]$Ports = (21,23,80,1433,3306,6379,7001),
    [string[]]$WhiteList = (127.0.0.1)
)

foreach($port in $Ports){
    Start-Job -ScriptBlock {
        param($port, $WhiteList)

        Function SendTo-SysLog{
            Param ($Content = "Your payload...")
            # Change it to your SIEM/SysLog server
            $SysLogSrv = "192.168.0.100" 
            $SysLogSrvPort = 514 
            $Facility = 5 * 8
            $Severity = 1
            $SourceHostname = $env:computername
            $Tag = "SentinelGuard"

            $pri = "<" + ($Facility + $Severity) + ">"

            # Note that the timestamp is local time on the originating computer, not UTC.
            if ($(get-date).day -lt 10) { $timestamp = $(get-date).tostring("MMM d HH:mm:ss") } else { $timestamp = $(get-date).tostring("MMM dd HH:mm:ss") }

            # Hostname does not have to be in lowercase, and it shouldn't have spaces anyway, but lowercase is more traditional.
             # The name should be the simple hostname, not a fully-qualified domain name, but the script doesn't enforce this.
            $header = $timestamp + " " + $sourcehostname.tolower().replace(" ","").trim() + " "

            #Cannot have non-alphanumerics in the TAG field or have it be longer than 32 characters. 
            if ($tag -match '[^a-z0-9]') { $tag = $tag -replace '[^a-z0-9]','' } #Simply delete the non-alphanumerics
            if ($tag.length -gt 32) { $tag = $tag.substring(0,31) } #and truncate at 32 characters.

            $msg = $pri + $header + $tag + ": " + $content

            # Convert message to array of ASCII bytes.
            $bytearray = $([System.Text.Encoding]::ASCII).getbytes($msg)

            # RFC3164 Section 4.1: "The total length of the packet MUST be 1024 bytes or less."
             # "Packet" is not "PRI + HEADER + MSG", and IP header = 20, UDP header = 8, hence:
            if ($bytearray.count -gt 996) { $bytearray = $bytearray[0..995] }

            # Send the message... 
            $UdpClient = New-Object System.Net.Sockets.UdpClient 
            $UdpClient.Connect($SysLogSrv,$SysLogSrvPort) 
            $UdpClient.Send($ByteArray, $ByteArray.length) | out-null
        }

        # Create Objects needed.
        $endpoint = new-object System.Net.IPEndPoint([system.net.ipaddress]::any, $port)
        $listener = new-object System.Net.Sockets.TcpListener $endpoint
        $listener.server.ReceiveTimeout = 3000
        $listener.start()
        try {
            Write-Host "Listening on port: $port, Stop-Job to cancel"
            While ($true){
                if (!$listener.Pending())
                {
                    Start-Sleep -Seconds 1; 
                    continue; 
                }
                $client = $listener.AcceptTcpClient()
                $client.client.RemoteEndPoint
                $IP = $client.Client.RemoteEndPoint
                $IP = $IP.tostring()
                $IP = $IP.split(':')
                $IP = $IP[0]
                $client.close()
                $SrcHost = [System.Net.Dns]::GetHostName()
                if (![string]::IsNullOrEmpty($IP)){
                    if ($WhiteList -notcontains $IP){
                        $logIP = "$IP has probed the Sentinel $SrcHost on port $port"
                        #Send email alert can be configured easily, but is hard to re-dup alerts
                        #Send-MailMessage -From 'sender@xxx.com' -To 'alert@xxx.com' -Subject $logIP -SmtpServer mailserver 
                        SendTo-SysLog -Content $logIP
                    }
                }
            }
        }
        catch {
            Write-Error $_          
        }
        finally{
                $listener.stop()
                Write-host "Listener Closed Safely"
        }       
    } -ArgumentList $port, $WhiteList -Name "VPort-$port" -ErrorAction Stop  
}

