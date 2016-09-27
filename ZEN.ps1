# "Zero Effort Networking" © Brad Lape, February, 2015
# Intruducing: ZEN two point oh!
  
# Prequesites

    # change host window buffer size
    $pshost = get-host
    $pswindow = $pshost.ui.rawui
    $pswindow.windowtitle = "ZEN"
    $pswindow.foregroundcolor = "DarkYellow"
    $pswindow.backgroundcolor = "Black"
    $newsize = $pswindow.buffersize
    $newsize.height = 3000
    $newsize.width = 100
    Try {
         $pswindow.buffersize = $newsize
         $newsize = $pswindow.windowsize
         $newsize.height = 65
         $newsize.width = 100
         $pswindow.windowsize = $newsize
         }
         Catch {
                # There is no catch!
                }

    # enable QuickEdit
    Set-ItemProperty –path “HKCU:\Console” –name QuickEdit –value 1

    $path2script = split-path $SCRIPT:MyInvocation.MyCommand.Path -parent

    If (Test-Path "$path2script") { } 
                                    Else {
                                          New-Item -Path "$path2script" -ItemType Directory
                                          }

    If (Test-Path "$path2script\unicode.tmp") {
                                               Remove-Item -Path "$path2script\unicode.tmp" -Force
                                               }

    $date = (Get-Date -Format s).ToString() | % {$_ -Replace ':',"-"}
    $username = [Environment]::UserName
    $menuitems = 'Search offline config files','Download router configs locally'
    Import-Module -Name "$path2script\Posh-SSH\Posh-SSH.psd1"
    $description = 'ZEN'
    $applnkname = 'ZEN.lnk'
    $app = '%SystemRoot%\system32\WindowsPowerShell\v1.0\powershell.exe'
    $arguments = "-File ""$path2script\ZEN.ps1"" -ExecutionPolicy Bypass"  
    $icon = $app
    $lnklocation = "c:\Users\$username\Desktop"
    Remove-Variable week -Force -ErrorAction SilentlyContinue
    $clearables = 'model','log','flap','adminlink','search','results','okx','date','logpath','fqdn','description','interface','circuittype','business','street','CID','routinginstance','bandwidth','ether','ethernet','portmode','meInternet','speed','duplex','mtu','type','DPC','PIC','ports','port','subport','uplink','ipv4address','routedips','alotofips','uptime','light','lightlevels','drops','framing','runts','policed','l3incompletes','l2channel','l2mismatch','fifo','resource','carrier','collisions','agedpackets','hslinkcrc','mtuerrors','CE','MGMTints','CPE','cetype','cpehost','vendor','device','outfile','items','vplsloop','vplsid','vrf','macmove','BGPneighbor','BGPas','BGProutes','policeri','policero'
    $rempathscp = '/YOUR/RANCID/configs/PATH'
    $routersls = 'ls -l --full-time ' + $rempathscp + ' ' + '|' + ' ' + 'awk' + ' ' + "'" + '{print $9}' + "'"
    $regdom = '.yourdomain.com'
    $rancidhost = 'RANCIDhost' + "$regdom"

    # if shortcut does not exist creates new shortcut
    If (Test-Path "$lnklocation\$applnkname") { } 
                                                Else {
                                                      $appfolder = Split-Path $app -Parent
                                                      $AppLocation = "$app"
                                                      $WshShell = New-Object -ComObject WScript.Shell
                                                      $Shortcut = $WshShell.CreateShortcut("$lnklocation\$applnkname")
                                                      $Shortcut.TargetPath = "$app"
                                                      $Shortcut.IconLocation = "$icon"
                                                      $shortcut.Arguments = "$arguments"
                                                      $Shortcut.Description ="$description"
                                                      $Shortcut.WorkingDirectory ="$path2script"
                                                      $Shortcut.Save()
                                                      Remove-Variable appfolder -Force -ErrorAction SilentlyContinue
                                                      Remove-Variable AppLocation -Force -ErrorAction SilentlyContinue
                                                      Remove-Variable Shortcut -Force -ErrorAction SilentlyContinue
                                                      Remove-Variable app -Force -ErrorAction SilentlyContinue
                                                      Remove-Variable icon -Force -ErrorAction SilentlyContinue
                                                      Remove-Variable arguments -Force -ErrorAction SilentlyContinue
                                                      Remove-Variable description -Force -ErrorAction SilentlyContinue
                                                      }


# Functions

    # center text, credit for this is here: http://project500.squarespace.com/journal/2014/1/5/powershell-centering-console-text
    Function Write-Centered {
                             Param(
                                   [string] $message,
                                   [string] $color = "black"
                                   )

                             $offsetvalue = [Math]::Round(([Console]::WindowWidth / 2) + ($message.Length / 2))
                             Write-Host ("{0,$offsetvalue}" -f $message) -ForegroundColor $color
                             }

    # Get the week of the year
    Function Week-of-Year {
                           Param(
                                 [string] $weekcheck
                                 )
                           
                           If ($week) {
                                       [int]$week = get-date -UFormat %V
                                       $week -= "{0:D2}" -f 1
                                       $week = $week.ToString().PadLeft(2, '0')
                                       If ($weekcheck -lt $week) {
                                                                  Write-Centered "You are in week number $week of 52!" -Color DarkCyan
                                                                  $script:week = $week
                                                                  Write-Host "`n" -ForegroundColor Black
                                                                  }
                                        }
                                        Else {
                                              [int]$week = get-date -UFormat %V
                                              $week -= "{0:D2}" -f 1
                                              $week = $week.ToString().PadLeft(2, '0')
                                              Write-Centered "You are in week number $week of 52!" -Color DarkCyan
                                              $script:week = $week
                                              Write-Host "`n" -ForegroundColor Black
                                              }
                           
                           }

    # ToArray
    function ToArray {
                      begin
                           {
                            $output = @(); 
                            }
                            process
                                  {
                                   $output += $_; 
                                   }
                                   end
                                     {
                                      return ,$output; 
                                      }
                       }

    # to Unicode
    Function ToUnicode {
                        process {
                                 $_ | Out-File -FilePath "$path2script\unicode.tmp" -Encoding unicode; 
                                 }
                                 end
                                   {
                                    return ,$_ = Get-Content -Path "$path2script\unicode.tmp"-Encoding unicode; 
                                    Remove-Item -Path "$path2script\unicode.tmp" -Force
                                    }
                        }

    # Test port, not my work, credit goes to here: http://www.travisgan.com/2014/03/use-powershell-to-test-port.html
    function TestPort
                    {
                        Param(
                            [parameter(ParameterSetName='ComputerName', Position=0)]
                            [string]
                            $ComputerName,

                            [parameter(ParameterSetName='IP', Position=0)]
                            [System.Net.IPAddress]
                            $IPAddress,

                            [parameter(Mandatory=$true , Position=1)]
                            [int]
                            $Port,

                            [parameter(Mandatory=$true, Position=2)]
                            [ValidateSet("TCP", "UDP")]
                            [string]
                            $Protocol
                            )

                        $RemoteServer = If ([string]::IsNullOrEmpty($ComputerName)) {$IPAddress} Else {$ComputerName};

                        If ($Protocol -eq 'TCP')
                        {
                            $test = New-Object System.Net.Sockets.TcpClient;
                            Try
                            {
                                $test.Connect($RemoteServer, $Port);
                                $true;
                            }
                            Catch
                            {
                                $false;
                            }
                            Finally
                            {
                                $test.Dispose();
                            }
                        }

                        If ($Protocol -eq 'UDP')
                        {
                            Write-Host "UDP port test functionality currently not available."
                            <#
                            $test = New-Object System.Net.Sockets.UdpClient;
                            Try
                            {
                                Write-Host "Connecting to "$RemoteServer":"$Port" (UDP)..";
                                $test.Connect($RemoteServer, $Port);
                                Write-Host "Connection successful";
                            }
                            Catch
                            {
                                Write-Host "Connection failed";
                            }
                            Finally
                            {
                                $test.Dispose();
                            }
                            #>
                        }
                    }

                        # IP Subnetting adress conversion, Googled and credit belongs to someone else..
                        function ConvertTo-Mask {
                      <#
                        .Synopsis
                          Returns a dotted decimal subnet mask from a mask length.
                        .Description
                          ConvertTo-Mask returns a subnet mask in dotted decimal format from an integer value ranging 
                          between 0 and 32. ConvertTo-Mask first creates a binary string from the length, converts 
                          that to an unsigned 32-bit integer then calls ConvertTo-DottedDecimalIP to complete the operation.
                        .Parameter MaskLength
                          The number of bits which must be masked.
                      #>
  
                      [CmdLetBinding()]
                      param(
                        [Parameter(Mandatory = $true, Position = 0, ValueFromPipCCC = $true)]
                        [Alias("Length")]
                        [ValidateRange(0, 32)]
                        $MaskLength
                      )
  
                      Process {
                        return ConvertTo-DottedDecimalIP ([Convert]::ToUInt32($(("1" * $MaskLength).PadRight(32, "0")), 2))
                      }
                    }

    function ConvertTo-DecimalIP {
  <#
    .Synopsis
      Converts a Decimal IP address into a 32-bit unsigned integer.
    .Description
      ConvertTo-DecimalIP takes a decimal IP, uses a shift-like operation on each octet and returns a single UInt32 value.
    .Parameter IPAddress
      An IP Address to convert.
  #>
  
  [CmdLetBinding()]
  param(
    [Parameter(Mandatory = $true, Position = 0, ValueFromPipCCC = $true)]
    [Net.IPAddress]$IPAddress
  )
 
  process {
    $i = 3; $DecimalIP = 0;
    $IPAddress.GetAddressBytes() | ForEach-Object { $DecimalIP += $_ * [Math]::Pow(256, $i); $i-- }
 
    return [UInt32]$DecimalIP
  }
}

    function ConvertTo-DottedDecimalIP {
  <#
    .Synopsis
      Returns a dotted decimal IP address from either an unsigned 32-bit integer or a dotted binary string.
    .Description
      ConvertTo-DottedDecimalIP uses a regular expression match on the input string to convert to an IP address.
    .Parameter IPAddress
      A string representation of an IP address from either UInt32 or dotted binary.
  #>
 
  [CmdLetBinding()]
  param(
    [Parameter(Mandatory = $true, Position = 0, ValueFromPipCCC = $true)]
    [String]$IPAddress
  )
  
  process {
    Switch -RegEx ($IPAddress) {
      "([01]{8}.){3}[01]{8}" {
        return [String]::Join('.', $( $IPAddress.Split('.') | ForEach-Object { [Convert]::ToUInt32($_, 2) } ))
      }
      "\d" {
        $IPAddress = [UInt32]$IPAddress
        $DottedIP = $( For ($i = 3; $i -gt -1; $i--) {
          $Remainder = $IPAddress % [Math]::Pow(256, $i)
          ($IPAddress - $Remainder) / [Math]::Pow(256, $i)
          $IPAddress = $Remainder
         } )
       
        return [String]::Join('.', $DottedIP)
      }
      default {
        Write-Error "Cannot convert this format"
      }
    }
  }
}

    function Get-NetworkRange( [String]$IP, [String]$Mask ) {
  if ($IP.Contains("/")) {
    $Temp = $IP.Split("/")
    $IP = $Temp[0]
    $Mask = $Temp[1]
  }
 
  if (!$Mask.Contains(".")) {
    $Mask = ConvertTo-Mask $Mask
  }
 
  $DecimalIP = ConvertTo-DecimalIP $IP
  $DecimalMask = ConvertTo-DecimalIP $Mask
  
  $Network = $DecimalIP -band $DecimalMask
  $Broadcast = $DecimalIP -bor ((-bnot $DecimalMask) -band [UInt32]::MaxValue)
 
  for ($i = $($Network + 1); $i -lt $Broadcast; $i++) {
    ConvertTo-DottedDecimalIP $i
  }
}

    # Get POSH SSH Function
    Function Get-POSH {
                       $webclient = New-Object System.Net.WebClient
                       $url = "https://github.com/darkoperator/Posh-SSH/archive/master.zip"
                       $file = "$path2script\Posh-SSH.zip"
                       $webclient.DownloadFile($url,$file)
                       $shell_app=new-object -com shell.application
                       $zip_file = $shell_app.namespace($file)
                       $destination = $shell_app.namespace($path2script)
                       $destination.Copyhere($zip_file.items(), 0x10)
                       Rename-Item -Path ($path2script+"\Posh-SSH-master") -NewName "Posh-SSH" -Force
                       Get-Command -Module Posh-SSH
                       Remove-Item -Path $file
                       Remove-Variable webclient -Force -ErrorAction SilentlyContinue
                       Remove-Variable url -Force -ErrorAction SilentlyContinue
                       Remove-Variable file -Force -ErrorAction SilentlyContinue
                       Remove-Variable shell_app -Force -ErrorAction SilentlyContinue
                       Remove-Variable zip_file -Force -ErrorAction SilentlyContinue
                       Remove-Variable destination -Force -ErrorAction SilentlyContinue
                       }

    If (Test-Path "$path2script\Posh-SSH") { } 
                                             Else {
                                                   Get-POSH
                                                   }

    # port forwarding (not my work, credit belongs elsewhere https://github.com/darkoperator/Posh-SSH)
    function New-SSHLocalPortForward
{
    [CmdletBinding(DefaultParameterSetName="Index")]
    param(
        [Parameter(Mandatory=$true,
            Position=1)]
        [String]
        $BoundHost,

        [Parameter(Mandatory=$true,
            Position=2)]
        [Int32]
        $BoundPort,

        [Parameter(Mandatory=$true,
            Position=3)]
        [String]
        $RemoteAddress,

        [Parameter(Mandatory=$true,
            Position=4)]
        [Int32]
        $RemotePort,

        [Parameter(Mandatory=$true,
            ParameterSetName = "Session",
            ValueFromPipCCC=$true,
            Position=0)]
        [Alias("Session")]
        [SSH.SSHSession]
        $SSHSession,

        [Parameter(Mandatory=$true,
            ParameterSetName = "Index",
            ValueFromPipCCC=$true,
            Position=0)]
        [Alias('Index')]
        [Int32]
        $SessionId 
    )

    Begin
    {
        $ToProcess = $null
        switch($PSCmdlet.ParameterSetName)
        {
            'Session'
            {
                $ToProcess = $SSHSession
            }

            'Index'
            {
                $sess = Get-SSHSession -Index $SessionId
                if ($sess)
                {
                    $ToProcess = $sess
                }
                else
                {
                    Write-Error -Message "Session specified with Index $($SessionId) was not found"
                    return
                }
            }
        }
        
    }
    Process
    {
        $ports = $ToProcess.Session.ForwardedPorts
        foreach($p in $ports)
        {
            if (($p.BoundPort -eq $BoundPort) -and ($p.BoundHost -eq $BoundHost))
            {
                Write-Error -Message "A forward port already exists for port $($BoundPort) with address $($LocalAdress)"
                return
            }
        }
        # Initialize the ForwardPort Object
        $SSHFWP = New-Object Renci.SshNet.ForwardedPortLocal($BoundHost, $BoundPort, $RemoteAddress, $RemotePort)
        
        # Add the forward port object to the session
        Write-Verbose -message "Adding Forward Port Configuration to session $($ToProcess.Index)"
        $ToProcess.session.AddForwardedPort($SSHFWP)
        Write-Verbose -message "Starting the Port Forward."
        $SSHFWP.start()
        Write-Verbose -message "Forwarding has been started."
    
    }
    End{}


}

function New-SSHDynamicPortForward
{
    [CmdletBinding(DefaultParameterSetName="Index")]
    param(
        [Parameter(Mandatory=$true,
            Position=1)]
        [String]
        $BoundHost = 'localhost',

        [Parameter(Mandatory=$true,
            Position=2)]
        [Int32]
        $BoundPort,

        [Parameter(Mandatory=$true,
            ParameterSetName = "Session",
            ValueFromPipCCC=$true,
            Position=0)]
        [Alias("Session")]
        [SSH.SSHSession]
        $SSHSession,

        [Parameter(Mandatory=$true,
            ParameterSetName = "Index",
            ValueFromPipCCC=$true,
            Position=0)]
        [Alias('Index')]
        [Int32]
        $SessionId
    )

     Begin
    {
        $ToProcess = $null
        switch($PSCmdlet.ParameterSetName)
        {
            'Session'
            {
                $ToProcess = $SSHSession
            }

            'Index'
            {
                $sess = Get-SSHSession -Index $SessionId
                if ($sess)
                {
                    $ToProcess = $sess
                }
                else
                {
                    Write-Error -Message "Session specified with Index $($SessionId) was not found"
                    return
                }
            }
        }  
    }
    Process
    {
        $ports = $ToProcess.Session.ForwardedPorts
        foreach($p in $ports)
        {
            if ($p.BoundHost -eq $BoundHost -and $p.BoundPort -eq $BoundPort)
            {
                throw "A forward port already exists for port $($BoundPort) with address $($BoundHost)"
            }
        }

         # Initialize the ForwardPort Object
        $SSHFWP = New-Object Renci.SshNet.ForwardedPortDynamic($BoundHost, $BoundPort)

        # Add the forward port object to the session
        Write-Verbose -message "Adding Forward Port Configuration to session $($ToProcess.Index)"
        $ToProcess.session.AddForwardedPort($SSHFWP)
        $ToProcess.session.KeepAliveInterval = New-TimeSpan -Seconds 30
        $ToProcess.session.ConnectionInfo.Timeout = New-TimeSpan -Seconds 20
        $ToProcess.session.SendKeepAlive()
        
        [System.Threading.Thread]::Sleep(500)
        Write-Verbose -message "Starting the Port Forward."
        $SSHFWP.start()
        Write-Verbose -message "Forwarding has been started."
               
    }
    End{}
}

function Get-SSHPortForward
{
    [CmdletBinding(DefaultParameterSetName="Index")]
    param(
        [Parameter(Mandatory=$true,
            ParameterSetName = "Session",
            ValueFromPipCCC=$true,
            Position=0)]
        [Alias("Session")]
        [SSH.SSHSession]
        $SSHSession,

        [Parameter(Mandatory=$true,
            ParameterSetName = "Index",
            ValueFromPipCCC=$true,
            Position=0)]
        [Alias('Index')]
        [Int32]
        $SessionId
    )

     Begin
    {
        $ToProcess = $null
        switch($PSCmdlet.ParameterSetName)
        {
            'Session'
            {
                $ToProcess = $SSHSession
            }

            'Index'
            {
                $sess = Get-SSHSession -Index $SessionId
                if ($sess)
                {
                    $ToProcess = $sess
                }
                else
                {
                    Write-Error -Message "Session specified with Index $($SessionId) was not found"
                    return
                }
            }
        }  
    }
    Process
    {
        
        $ToProcess.Session.ForwardedPorts
              
    }
    End{}
}

function Stop-SSHPortForward
{
    [CmdletBinding(DefaultParameterSetName="Index")]
    param(

        [Parameter(Mandatory=$true,
            ParameterSetName = "Session",
            ValueFromPipCCC=$true,
            Position=0)]
        [Alias("Session")]
        [SSH.SSHSession]
        $SSHSession,

        [Parameter(Mandatory=$true,
            ParameterSetName = "Index",
            ValueFromPipCCC=$true,
            Position=0)]
        [Alias('Index')]
        [Int32]
        $SessionId,

        [Parameter(Mandatory=$true,
            Position=2)]
        [Int32]
        $BoundPort,

        [Parameter(Mandatory=$true,
            Position=1)]
        [string]
        $BoundHost
    )

     Begin
    {
         $ToProcess = $null
        switch($PSCmdlet.ParameterSetName)
        {
            'Session'
            {
                $ToProcess = $SSHSession
            }

            'Index'
            {
                $sess = Get-SSHSession -Index $SessionId
                if ($sess)
                {
                    $ToProcess = $sess
                }
                else
                {
                    Write-Error -Message "Session specified with Index $($SessionId) was not found"
                    return
                }
            }
        } 
    }
    Process
    {
        $ports = $ToProcess.Session.ForwardedPorts
        foreach($p in $ports)
        {
            if ($p.BoundPort -eq $BoundPort -and $p.BoundHost -eq $BoundHost)
            {
                $p.Stop()
                $p
            }
        }
    }
    End{}
}#>

function Start-SSHPortForward
{
    [CmdletBinding(DefaultParameterSetName="Index")]
    param(

        [Parameter(Mandatory=$true,
            ParameterSetName = "Session",
            ValueFromPipCCC=$true,
            Position=0)]
        [Alias("Session")]
        [SSH.SSHSession]
        $SSHSession,

        [Parameter(Mandatory=$true,
            ParameterSetName = "Index",
            ValueFromPipCCC=$true,
            Position=0)]
        [Alias('Index')]
        [Int32]
        $SessionId,

        [Parameter(Mandatory=$true,
            Position=2)]
        [Int32]
        $BoundPort,

        [Parameter(Mandatory=$true,
            Position=1)]
        [string]
        $BoundHost
    )

     Begin
    {
         $ToProcess = $null
        switch($PSCmdlet.ParameterSetName)
        {
            'Session'
            {
                $ToProcess = $SSHSession
            }

            'Index'
            {
                $sess = Get-SSHSession -Index $SessionId
                if ($sess)
                {
                    $ToProcess = $sess
                }
                else
                {
                    Write-Error -Message "Session specified with Index $($SessionId) was not found"
                    return
                }
            }
        } 
    }
    Process
    {

        $ports = $ToProcess.Session.ForwardedPorts
        foreach($p in $ports)
        {
            if ($p.BoundPort -eq $BoundPort -and $p.BoundHost -eq $BoundHost)
            {
                $p.Start()
                $p
            }
        }
               
    }
    End{}
}

    # MAC vendor lookup
    Function Get-MacAddressVendor {
                                   Param (
                                     [Parameter(Position=0,
                                                Mandatory=$true,
                                                ValueFromPipCCCByPropertyName = $true,
                                                ValueFromPipCCC = $true,
                                                HelpMessage='Enter the Mac address with "-" or ":" separator')]
                                     [ValidateNotNullOrEmpty()] 
                                     [Alias("MACAddress","AdresseMac","PhysicalAddress")]                
                                    [string]$Mac)

                                 Begin { 
                                   $WebSite="www.coffer.com"
                                   $WebClient=New-Object Net.WebClient 
                                 }   
                                 Process {
                                   if (!($Mac -match '^([0-9a-f]{2}:){5}([0-9a-f]{2})$|^([0-9a-f]{2}-){5}([0-9a-f]{2})$'))
                                   { 
                                     ;return
                                   }
                                   Try {
                                     $DownloadedString= $WebClient.DownloadString("http://www.coffer.com/mac_find/?string=$Mac")
                                   }Catch {
                                     ;return  
                                   }
                                   $RegEx=[Regex]::Matches($DownloadedString, 'google\.com/search.*">(.*)</a.*', [Text.RegularExpressions.RegexOptions]::MultiLine)
                                   if ($RegEx.Count -ne 0) 
                                    {New-Object PSCustomObject -property @{Name=$RegEx[0].Groups[1].value;Mac=$Mac}
                                    }
                                   elseif ($RegEx.Count -gt 1) 
                                   {
                                    }
                                   else
                                    {;return}
                                 }
                                 End {
                                   if ($WebClient) 
                                    {$WebClient.Dispose() }  
                                 }
    } 

    Function Get-MacAddressVendor2 {
                                    Param (
                                         [Parameter(Position=0,
                                                    Mandatory=$true,
                                                    ValueFromPipCCCByPropertyName = $true,
                                                    ValueFromPipCCC = $true,
                                                    HelpMessage='Enter the Mac address with ":" separator')]
                                         [ValidateNotNullOrEmpty()] 
                                         [Alias("MACAddress","AdresseMac","PhysicalAddress")]                
                                        [string]$Mac)

                                        $newmac = $Mac | %{$_.Replace(’:’,'-')}
                                        $webrequest = Invoke-WebRequest -Uri “http://www.macvendorlookup.com/api/v2/$newmac/csv”
                                        $splitmac = (($webrequest.Content -split ’\,’)[4] -split ’"’)[1]
                                        New-Object PSCustomObject -property @{Name=$splitmac;Mac=$Mac}
                                    }

    # ZEN proxy
    Function rancidhost-Tunnel {
                               Param(  
                                     [string] $suppress
                                     )

                               If ((Get-SSHSession | Where-Object -Property Host -EQ "$rancidhost").Connected) {$script:smrthstses = (Get-SSHSession | Where-Object -Property Host -EQ "$rancidhost").SessionID}
                                                                                                                Else {
                                                                                                                      If ($corporate) { } Else {
                                                                                                                                                $script:corporate = Get-Credential -Message "Please provide your rancidhost login"
                                                                                                                                                }
                                                                                                                      New-SSHSession -ComputerName $rancidhost -Credential $corporate -AcceptKey | Out-Null
                                                                                                                      $script:smrthstses = (Get-SSHSession | Where-Object -Property Host -EQ "$rancidhost").SessionID
                                                                                                                      If ((Get-SSHPortForward -SessionID $smrthstses -ErrorAction SilentlyContinue).BoundHost -notmatch "localhost") {
                                                                                                                                                                                                                                      New-SSHDynamicPortForward -SessionId $smrthstses -BoundHost localhost -BoundPort 554 -ErrorAction SilentlyContinue | Out-Null
                                                                                                                                                                                                                                      }
                                                                                                                    }
                               
                               If (($suppress -notmatch "yes") -or ((Get-SSHSession | Where-Object -Property Host -EQ "$rancidhost").Connected)) {
                                                                                                                                                 Write-Centered "ZEN proxy enabled to $rancidhost port 22 via local dynamic port 554" -Color Green
                                                                                                                                                 Write-Host "`n" -ForegroundColor Black
                                                                                                                                                 }
                               }

    # ZEN local proxy
    Function ZEN-local {

                        Param(  
                             [string] $device
                             )

                        Remove-Sessions
                        write-host "Had to tear down rancidhost tunnel to create a new local port forward" -ForegroundColor Yellow
                        write-host "`n" -ForegroundColor Black
                        New-SSHSession -ComputerName $rancidhost -Credential $corporate -AcceptKey | Out-Null
                        $script:smrthstses = (Get-SSHSession | Where-Object -Property Host -EQ "$rancidhost").SessionID

                        Try {    
                            If ([ipaddress]"$device") {$ipv4addy = $device
                                                      }# end of if device
                             } Catch {
                                      $nslookup = 'nslookup' + ' ' + "$device" + ' ' + '|' + ' ' + 'awk' + ' ' + "'" + '{print $2}' + "'" + ' ' + '|' + ' ' + 'head -6' + ' ' + '|' + ' ' + 'tail -1'
                                      $ipv4addy = (Invoke-SSHCommand -Index $smrthstses -Command "$nslookup").Output.Trim()
                                      }
                                          
                                If ([ipaddress]"$ipv4addy") {                                                                                                   
                                                           New-SSHLocalPortForward -SessionId $smrthstses -BoundHost localhost -BoundPort 554 -RemoteAddress $ipv4addy -RemotePort 22
                                                           New-SSHSession -ComputerName localhost -Port 554 -Credential $corporate -ConnectionTimeout 99999 -AcceptKey | Out-Null
                                                           $script:session = (Get-SSHSession | Where-Object -Property Host -EQ localhost).SessionID
                                                           If ((Get-SSHSession | Where-Object -Property Host -EQ "localhost").Connected) {
                                                                                                                                          Write-Centered "ZEN proxy now established to $device port 22 via localhost:554" -Color Green
                                                                                                                                          write-host "`n" -ForegroundColor Black
                                                                                                                                          If ($device -match "$regdom") {
                                                                                                                                                                                $script:fqdn = "$device"
                                                                                                                                                                                } # end of if device match .twcbiz.com
                                                                                                                                                                                Else {
                                                                                                                                                                                      Try {If ([ipaddress]"$device") {
                                                                                                                                                                                                                      $script:fqdn = (Invoke-SSHCommand -index $smrthstses -Command "dig +short -x $device" -ErrorAction SilentlyContinue).Output.Trim().TrimEnd('.') | Sort-Object -Unique
                                                                                                                                                                                                                      } # end of if ipaddress
                                                                           
                                                                                                                                                                                           } # end of try, if ip address
                                                                                                                                                                                           Catch {
                                                                                                                                                                                                 $script:fqdn = "$device" + "$regdom" | Get-Unique
                                                                                                                                                                                                  } # end of catch, if ip adrress

                                                                                                                                                                                        } # end of else if device match .twcbiz.com
                                                                                                                                          }
                                                           Remove-Variable ipv4addy -Force -ErrorAction SilentlyContinue
                                                           } # end of if ipv4addy 
                                                           Else {
                                                                 write-host "Unable to connect to $device via ZEN proxy" -ForegroundColor Yellow
                                                                 write-host "`n" -ForegroundColor Black
                                                                 Remove-Sessions
                                                                 rancidhost-Tunnel
                                                                 }
                        Remove-Variable nslookup -Force -ErrorAction SilentlyContinue
                        Remove-Variable ipv4addy -Force -ErrorAction SilentlyContinue
                        Remove-Variable device -Force -ErrorAction SilentlyContinue
                        } # end of ZEN-local proxy function  

    # Add Session
    Function Add-Session {

                          Param(
                                [Parameter(Mandatory = $true)]
                                [string] $device
                                )

                          If ($corporate) { } Else {$script:corporate = Get-Credential -Message "Please provide your rancidhost login"}

                          If ($smrthstses) { } Else {
                                                     New-SSHSession -ComputerName $rancidhost -Credential $corporate -AcceptKey | Out-Null
                                                     $script:smrthstses = (Get-SSHSession | Where-Object -Property Host -EQ "$rancidhost").SessionID
                                                     } 

                          If ($device -match "$regdom") {
                                                             $script:fqdn = "$device"
                                                             } # end of if device match .twcbiz.com
                                                             Else {
                                                                   Try {
                                                                        If ([ipaddress]"$device") {
                                                                                                      $script:fqdn = (Invoke-SSHCommand -index $smrthstses -Command "dig +short -x $device" -ErrorAction SilentlyContinue).Output.Trim().TrimEnd('.') | Sort-Object -Unique
                                                                                                      If ($fqdn) { }
                                                                                                                   Else {
                                                                                                                         $script:fqdn = $device
                                                                                                                         Write-Host "`n" -ForegroundColor Black
                                                                                                                         write-host "Using IP address $device because the FQDN could not be resolved" -ForegroundColor Yello
                                                                                                                         Write-Host "`n" -ForegroundColor Black
                                                                                                                         }
                                                                                                      } # end of if ipaddress
                                                                           
                                                                           } # end of try, if ip address
                                                                           Catch {
                                                                                  $script:fqdn = "$device" + "$regdom" | Get-Unique
                                                                                  } # end of catch, if ip adrress

                                                                         } # end of else if device match .twcbiz.com

                         If (Test-Connection -ComputerName "$fqdn" -ErrorAction SilentlyContinue) {
                                                                                                   Try {
                                                                                                        New-SSHSession -ComputerName "$fqdn" -Credential $corporate -ConnectionTimeout 99999 -AcceptKey | Out-Null
                                                                                                        $script:session = (Get-SSHSession | Where-Object -Property Host -EQ "$fqdn").SessionID
                                                                                                        } 
                                                                                                        Catch {
                                                                                                               Try { 
                                                                                                                    clv fqdn -Force -ErrorAction SilentlyContinue
                                                                                                                    $script:fqdn = (Invoke-SSHCommand -index $smrthstses -Command "dig +short -x $device" -ErrorAction SilentlyContinue).Output.Trim().TrimEnd('.') | Sort-Object -Unique  
                                                                                                                    New-SSHSession -ComputerName "$fqdn" -Credential $corporate -ConnectionTimeout 99999 -AcceptKey | Out-Null
                                                                                                                    $script:session = (Get-SSHSession | Where-Object -Property Host -EQ "$fqdn").SessionID
                                                                                                                    }
                                                                                                                    Catch {
                                                                                                                           Try {
                                                                                                                                ZEN-local -device $device
                                                                                                                                }
                                                                                                                                Catch {
                                                                                                                                       Write-Host "`n" -ForegroundColor Black
                                                                                                                                       If ($fqdn) {
                                                                                                                                                   Write-host "Unable to connect to: $fqdn" -ForegroundColor Red
                                                                                                                                                   }
                                                                                                                                                   Else {
                                                                                                                                                         Write-host "Unable to connect to: $device" -ForegroundColor Red
                                                                                                                                                         }


                                                                                                                                       Write-Host "`n" -ForegroundColor Black
                                                                                                                                       Remove-Sessions
                                                                                                                                       rancidhost-Tunnel
                                                                                                                                       Remove-Variable fqdn -Force -ErrorAction SilentlyContinue                       
                                                                                                                                       Remove-Variable device -Force -ErrorAction SilentlyContinue
                                                                                                                                       Remove-Variable interface -Force -ErrorAction SilentlyContinue
                                                                                                                                       Remove-Variable nslookup -Force -ErrorAction SilentlyContinue
                                                                                                                                       continue 
                                                                                                                                       }
                                                                                                                           }
                                                                                                                 }
                                                
                                                                    } 
                                                                    Else {
                                                                          Try {
                                                                               ZEN-local -device $device
                                                                               }
                                                                               Catch {
                                                                                      Write-Host "`n" -ForegroundColor Black
                                                                                      write-host "Unable to connect to: $fqdn" -ForegroundColor Red
                                                                                      Write-Host "`n" -ForegroundColor Black
                                                                                      Remove-Sessions
                                                                                      rancidhost-Tunnel                       
                                                                                      Remove-Variable device -Force -ErrorAction SilentlyContinue
                                                                                      Remove-Variable interface -Force -ErrorAction SilentlyContinue
                                                                                      Remove-Variable fqdn -Force -ErrorAction SilentlyContinue
                                                                                      Remove-Variable nslookup -Force -ErrorAction SilentlyContinue
                                                                                      continue 
                                                                                      } 
                                                                          }

                    } # end of Add Session function

    # cleanup sessions
    Function Remove-Sessions {
                              Param(  [string] $exclude)

                              $sessions = (Get-SSHSession).SessionId
                            
                              Foreach ($session in $sessions) {
                                                               If ($exclude -match "$null") {
                                                                                             Try {
                                                                                                  Stop-SSHPortForward -SessionId $session -BoundHost localhost -BoundPort 554 -ErrorAction SilentlyContinue | Out-Null
                                                                                                  Stop-SSHPortForward -SessionId $smrthstses -BoundHost localhost -BoundPort 554 -ErrorAction SilentlyContinue | Out-Null
                                                                                                  }
                                                                                                  Catch {
                                                                                                         # Catch? There is no catch!
                                                                                                         }
                                                                                             Remove-SSHSession -SessionId $session -ErrorAction SilentlyContinue | Out-Null
                                                                                             }
                                                                                             Else {
                                                                                                   If ($exclude -notmatch "$exclude") {
                                                                                                                                       Try {
                                                                                                                                            Stop-SSHPortForward -SessionId $session -BoundHost localhost -BoundPort 554 -ErrorAction SilentlyContinue | Out-Null
                                                                                                                                            Stop-SSHPortForward -SessionId $smrthstses -BoundHost localhost -BoundPort 554 -ErrorAction SilentlyContinue | Out-Null
                                                                                                                                            }
                                                                                                                                            Catch {
                                                                                                                                                   # Catch? There is no catch!
                                                                                                                                                   }
                                                                                                                                       Remove-SSHSession -SessionId $session -ErrorAction SilentlyContinue | Out-Null
                                                                                                                                       }
                                                                                                   Remove-Variable sessions -Force -ErrorAction SilentlyContinue
                                                                                                   Get-Item -path HKCU:\Software\PoshSSH | Remove-ItemProperty -name localhost -Force -ErrorAction SilentlyContinue
                                                                                                   }
                                                               }

                                Remove-Variable sessions -Force -ErrorAction SilentlyContinue
                                Get-Item -path HKCU:\Software\PoshSSH | Remove-ItemProperty -name localhost -Force -ErrorAction SilentlyContinue

    Write-Host "Tore down port forwarding and all sessions" -ForegroundColor Yellow
    Write-Host "`n" -ForegroundColor Black
    }

    # download Rancid nightlies (Juniper config backups)
    Function Rancid-Nightlies {
                               If ($corporate) { } Else {
                                                         $script:corporate = Get-Credential -Message "Please provide your rancidhost login"
                                                         }

                               If ($smrthstses) { } Else {
                                                          rancidhost-Tunnel -suppress yes
                                                          }
                               
                               If (Test-Path -Path "$path2script\configs") { }
                                                                                   Else {
                                                                                         New-Item -Path "$path2script\configs" -ItemType Directory | Out-Null
                                                                                         }

                               (Invoke-SSHCommand -Index $smrthstses -Command "$routersls").Output | Out-File "$path2script\configs\routers.txt" -Encoding unicode
                               $routers = (Get-Content -Path "$path2script\configs\routers.txt" | % {$_ -replace ':', ""} | % {$_ -Replace "Host",""} | % {$_ -Replace "Output",""} | % {$_ -Replace "$rancidhost",""} | % {$_ -Replace "ExitStatus  0",""} | ToArray ).Trim()
                               Remove-Item -Path "$path2script\configs\routers.txt" -Force
                               
                               Foreach ($router in $routers) {
                                                              Try {
                                                                   If (($router -match ".new") -or ($router -match ".raw")) { }
                                                                                                                              Else {
                                                                                                                                    Get-SCPFile -LocalFile "$path2script\configs\$router" -RemoteFile "$rempathscp/$router" -ComputerName $rancidhost -Credential $corporate -ErrorAction SilentlyContinue
                                                                                                                                    }
                                                                   }
                                                                   Catch {
                                                                          # catch? there is no catch!
                                                                          }
                                                               }
Write-Host "Your Rancid Juniper config file nightlies have been downloaded" -ForegroundColor Green
Write-Host "`n" -ForegroundColor Black
                          }

    # Get CPE info
    Function Get-CPE {
                      $mgmtbridges = (((Invoke-SSHCommand -index $session -Command "show configuration | display set | match ""domain-type bridge"" | trim 19").Output | % {$_ -replace 'domain-type bridge', ""}).Trim() -Split " ").Split("",[System.StringSplitOptions]::RemoveEmptyEntries)
                      Foreach ($mgmtbridge in $mgmtbridges) {
                                                             $script:MGMTints += (((Invoke-SSHCommand -index $session -Command "show configuration | match ""$parent"" | display set | match $mgmtbridge | trim 19").Output | % {$_ -replace "$mgmtbridge.* interface", ""}).Trim() -Split " ").Split("",[System.StringSplitOptions]::RemoveEmptyEntries)
                                                             }
                      clv mgmtbridges -Force -ErrorAction SilentlyContinue
                        
                      Foreach ($mgm in $MGMTints) {
                                                   $arp = 'show arp no-resolve | match ' + "$mgm"
                                                   [System.Collections.Generic.List[System.Object]] $noresolve += (((Invoke-SSHCommand -index $session -Command "$arp" -ErrorAction SilentlyContinue).Output | % {$_ -replace 'none', ""} | % {$_ -replace "$mgm", ""}).Trim() -Split " ").Split("",[System.StringSplitOptions]::RemoveEmptyEntries) 
                                                   clv arp -Force -ErrorAction SilentlyContinue
                                                   }

                      Foreach ($entry in $noresolve) {
                                                      If ($entry -match '\.') {
                                                                               $address = $entry
                                                                               $hostname = ((Invoke-SSHCommand -index $smrthstses -Command "dig +short -x $address" -ErrorAction SilentlyContinue).Output | % {$_ -replace "$regdom.", ""}).Trim() | Select -Unique
                                                                               }  

                                                      If ($entry -match ':') {
                                                      $mac = $entry
                                                      Try {
                                                           $vendor = (Get-MacAddressVendor "$mac").Name.Trim()
                                                           }
                                                           Catch {
                                                                  Try {
                                                                       $vendor = (Get-MacAddressVendor2 "$mac").Name.Trim()
                                                                       }
                                                                       Catch {
                                                                              # Catch? There is no catch!
                                                                              }
                                                                        }
                        
                                                                              }
        
                       If (($address) -and ($mac)) {
                                                    $CPE = New-Object System.Object
                                                    $prop = @{'CPE_IP'= $address}
                                                    $CPE = New-Object -TypeName PSObject -Property $prop
                                                    $CPE | add-member –membertype NoteProperty –name MAC –value $mac
                                                    If ($hostname) {
                                                                    $CPE | add-member –membertype NoteProperty –name host –value $hostname
                                                                    }
                                                    If ($vendor) {
                                                                  $CPE | add-member –membertype NoteProperty –name vendor –value $vendor
                                                                  }
                                                    }

                                                        $CPE

                                                        $address = $address -ne $address  
                                                        clv entry -Force -ErrorAction SilentlyContinue
                                                        }
                       clv prop -Force -ErrorAction SilentlyContinue
                       clv address -Force -ErrorAction SilentlyContinue
                       clv mac -Force -ErrorAction SilentlyContinue
                       clv vendor -Force -ErrorAction SilentlyContinue
                       clv noresolve -Force -ErrorAction SilentlyContinue
                       clv mgmt -Force -ErrorAction SilentlyContinue
                      }

    # Function to get CE info
    Function Get-CE {
                     If ($model -match "ex") {
                                              $showswitchingtable = 'show ethernet-switching table vlan ' + $vlan + ' brief | match ' + $interface + ' | find learn | trim 20' 
                                              [System.Collections.Generic.List[System.Object]] $cenoresolve = (((Invoke-SSHCommand -index $session -Command "$showswitchingtable").Output | % {$_ -replace ' Learn', ""} | % {$_ -replace '          0', ""} | % {$_ -replace "$interface", ""}).Trim() -Split " ").Split("",[System.StringSplitOptions]::RemoveEmptyEntries)
                                              $script:cetype = "CE" + '_MAC'
                                              clv showswitchingtable -Force -ErrorAction SilentlyContinue
                                              }

                     If ($circuittype -match "VPLS") {
                                                      $showvplsmac = 'show vpls mac-table interface ' + $interface + ' brief | find address | trim 3' 
                                                      [System.Collections.Generic.List[System.Object]] $cenoresolve = (((Invoke-SSHCommand -index $session -Command "$showvplsmac").Output | % {$_ -replace 'address             flags    interface', ""} | % {$_ -replace '   D       ', ""} | % {$_ -replace "$interface", ""}).Trim() -Split " ").Split("",[System.StringSplitOptions]::RemoveEmptyEntries)
                                                      $script:cetype = "$circuittype" + '_MAC'
                                                      clv showvplsmac -Force -ErrorAction SilentlyContinue
                                                      }

                     If (($circuittype -match "Internet") -or ($circuittype -match "PRI") -or ($circuittype -match "SIP")){
                                                                                                                      $cearp = 'show arp no-resolve | match ' + "$interface"
                                                                                                                      [System.Collections.Generic.List[System.Object]] $cenoresolve = (((Invoke-SSHCommand -index $session -Command "$cearp" -ErrorAction SilentlyContinue).Output | % {$_ -replace 'none', ""} | % {$_ -replace "$interface", ""}).Trim() -Split " ").Split("",[System.StringSplitOptions]::RemoveEmptyEntries) 
                                                                                                                      $script:cetype = "$circuittype" + '_IP'
                                                                                                                      clv cearp -Force -ErrorAction SilentlyContinue
                                                                                                                      }


                    Foreach ($entry in $cenoresolve) {
                                                      If ($cetype -match '_IP') {
                                                                                 If ($entry -match '\.') {
                                                                                 $ceaddress = $entry
                                                                                 If (($cetype -match "PRI") -or ($cetype -match "SIP")) { 
                                                                                                                                         $hostname = ((Invoke-SSHCommand -index $smrthstses -Command "dig +short -x $ceaddress" -ErrorAction SilentlyContinue).Output | % {$_ -replace "$regdom.", ""}).Trim() | Select -Unique
                                                                                                                                         }
                                                                                 }  

                                                                                 If ($entry -match ':') {
                                                                                                         $cemac = $entry
                                                                                                         Try {
                                                                                                              $cevendor = (Get-MacAddressVendor "$cemac").Name.Trim()
                                                                                                              }
                                                                                                              Catch {
                                                                                                                     Try {
                                                                                                                          $cevendor = (Get-MacAddressVendor2 "$cemac").Name.Trim()
                                                                                                                          }
                                                                                                                          Catch {
                                                                                                                                 # Catch? There is no catch!
                                                                                                                                 }
                                                                                                              }
                                                                                                              If (($cetype -match "PRI") -or ($cetype -match "SIP") -and ($hostname)) {
                                                                                                                                                                                       $CE | add-member –membertype NoteProperty –name host –value $hostname
                                                                                                                                                                                       }                        
                                                                                                         }
        
                                                                                If (($ceaddress) -and ($cemac)) {
                                                                                $CE = New-Object System.Object
                                                                                $prop = @{"$cetype"= $ceaddress}
                                                                                $CE = New-Object -TypeName PSObject -Property $prop
                                                                                $CE | add-member –membertype NoteProperty –name MAC –value $cemac
                                                                                If ($cevendor) {
                                                                                                $CE | add-member –membertype NoteProperty –name vendor –value $cevendor
                                                                                                }
        
                                                                                $CE
        
                                                                                $ceaddress = $ceaddress -ne $ceaddress  
        
                                                                                clv entry -Force -ErrorAction SilentlyContinue
            }
                                } # end if cetype _IP

    If ($cetype -match '_MAC') {
        
            If ($entry -match ':') {
            $cemac = $entry
            Try {
                 $cevendor = (Get-MacAddressVendor "$cemac").Name.Trim()
                 }
                 Catch {
                        Try {
                             $cevendor = (Get-MacAddressVendor2 "$cemac").Name.Trim()
                             }
                             Catch {
                                    # Catch? There is no catch!
                                    }
                        }
                        
                  }
        
            If ($cemac) {
                         $CE = New-Object System.Object
                         $prop = @{"$cetype"= "$cemac"}
                         $CE = New-Object -TypeName PSObject -Property $prop
                         If ($cevendor) {
                                         $CE | add-member –membertype NoteProperty –name vendor –value $cevendor
                                         }

            $CE
            $cemac = $cemac -ne $cemac  
            clv entry -Force -ErrorAction SilentlyContinue
                                } # end if cetype _MAC

                                }
    clv entry -Force -ErrorAction SilentlyContinue
    }
    clv prop -Force -ErrorAction SilentlyContinue
    clv ceaddress -Force -ErrorAction SilentlyContinue
    clv cemac -Force -ErrorAction SilentlyContinue
    clv cevendor -Force -ErrorAction SilentlyContinue
    clv cearp -Force -ErrorAction SilentlyContinue
    clv cenoresolve -Force -ErrorAction SilentlyContinue
                      }

    # Function Get-Juniper-CPE-INT
Function Get-Juniper-CPE-INT {
                            If ($vlan) {
                                        Foreach ($mgmt in $MGMTints) {
                                                                      $mgmtsubint = ($mgmt -replace "$parent.", "").Trim().Split("",[System.StringSplitOptions]::RemoveEmptyEntries)
                                          
                                                                      If (($uplink -match "ge-") -or ($uplink -match "xe-") -or ($uplink -match "gi0") -or ($uplink -match "fa0") -or ($uplink -match "ae")) {clv parent -Force -ErrorAction SilentlyContinue}
                                                                                      Else {
                                                                                            $script:uplink = (((Invoke-SSHCommand -index $session -Command "show configuration | display set | match ""set interfaces"" | match ""native-vlan-id $mgmtsubint"" | trim 15" -ErrorAction SilentlyContinue).Output | % {$_ -replace " unit 0 family ethernet-switching native-vlan-id $mgmtsubint", ""}).Trim() -Split " ").Split("",[System.StringSplitOptions]::RemoveEmptyEntries) 
                                                                                            Remove-Variable mgmtsubint -Force -ErrorAction SilentlyContinue
                                                                                            If (($uplink -match "ge-") -or ($uplink -match "xe-") -or ($uplink -match "gi0") -or ($uplink -match "fa0") -or ($uplink -match "ae")) {  } 
                                                                                                            Else {
                                                                                                                  $showuplink = ((Invoke-SSHCommand -index $session -Command "show configuration | display set | match description | match uplink | trim 15" -ErrorAction SilentlyContinue).Output.Trim() -Split " ").Split("",[System.StringSplitOptions]::RemoveEmptyEntries) 
                                                                                                                  $script:uplink = $showuplink.Get(0)
                                                                                                                  Remove-Variable showuplink -Force -ErrorAction SilentlyContinue
                                                                                                                  }
                                                                                            }
                                                                      } # end of for each mgmt in MGMTints
                                                                      Remove-Variable parent -Force -ErrorAction SilentlyContinue 
                                                                     Remove-Variable MGMTints -Force -ErrorAction SilentlyContinue

                            $script:interfaces = ((Invoke-SSHCommand -index $session -Command "show vlans $vlan | match ""ge|xe|ae"" | trim 23" -ErrorAction SilentlyContinue).Output.Trim().Replace('.0*', "") -split ',').Split("",[System.StringSplitOptions]::RemoveEmptyEntries) 
                                                                                                  
                                        Remove-Variable vlanname -Force -ErrorAction SilentlyContinue
                                        }


                              } # end of Function Get-Juniper-CPE-INT

    # Juniper get Interface function
Function Juniper-Get-INT {

    # prerequisites
    Param(
          [string] $interface
          )

If ($session) {
$script:model = (Invoke-SSHCommand -index $session -Command 'show version | match model | trim 7').Output.Trim().Split("",[System.StringSplitOptions]::RemoveEmptyEntries)      
$script:uptime = (Invoke-SSHCommand -index $session -Command 'show system uptime | match booted | trim 15').Output.Trim()
If ($model -match "ex") {$script:lastCPE = $result.router}

If ($interface) {

$script:interface = $interface

    If ($interface -match "-") {
    $intsplit = $interface -split "/"
    $type_DPC = $intsplit.Get(0) -split "-"
    If ($type_DPC.Get(0) -match "fe") {$script:ethernet = 'Fast Ethernet'}
    If ($type_DPC.Get(0) -match "ge") {$script:ethernet = 'Gigabit Ethernet'}
    If ($type_DPC.Get(0) -match "xe") {$script:ethernet = 'Ten Gigabit Ethernet'}
    $script:type = $type_DPC.Get(0)
    $script:DPC = $type_DPC.Get(1)
    $script:PIC = $intsplit.Get(1)
    $script:ports = $intsplit.Get(2)
        If ($ports -match '\.') {
    $port = [Math]::Truncate($ports)
    $script:port = $port
    $portsubport = $ports -split '\.'
    $script:subport = $portsubport.Get(1)
    $script:parent = "$type-$DPC/$PIC/$port"
    Remove-Variable portsubport -Force -ErrorAction SilentlyContinue
    } 
    Else {
    $script:parent = "$interface"
    }
    
    }
    

    If ($interface -match "ae") {
    If ($interface -match '\.') {
    $intsplit = $interface -split '\.'
    $script:type = 'ae'
    $script:ethernet = 'Aggregated Ethernet'
    $script:DPC = $intsplit.Get(0)| % {$_ -Replace "ae",""} 
    $script:subport = $intsplit.Get(1)
    $script:parent = "$type" + "$DPC"
    }
    Else {
    $script:parent = "$interface"
    }
                                } # end of if interface match ae
 
    $link = 'show interfaces ' + "$interface" + ' terse | match "up|down" | trim 24'
    $VPLSinstance = 'show configuration | match routing-instances | match ' + "$interface" + ' | display set | trim 22'
    $loopscript = 'show configuration interfaces ' + "$interface" + ' | match vpls-loop-protect'
    
    If (($model -notmatch "mx") -and ($vlan)) {
    
                                               }
                                               Else { 
                                                     $script:vlan = ((Invoke-SSHCommand -index $session -Command "show configuration interfaces $interface | match vlan-id").Output | % {$_ -replace 'vlan-id', ""} | % {$_ -replace ';', ""} | % {$_ -replace 'native-', ""}).Trim()
                                                     }
 
    $family = (((Invoke-SSHCommand -index $session -Command "show configuration interfaces $interface | match family").Output | % {$_ -replace 'family ', ""} | % {$_ -replace ' {', ""} | % {$_ -replace ';', ""} | % {$_ -replace 'inet6', ""}).Trim() -Split " ").Split("",[System.StringSplitOptions]::RemoveEmptyEntries)
    
    If ($family) { }
                        Else {
                             $encapsulation = (((Invoke-SSHCommand -index $session -Command "show configuration interfaces $interface | match encapsulation").Output | % {$_ -replace 'encapsulation ', ""} | % {$_ -replace ' {', ""} | % {$_ -replace ';', ""} | % {$_ -replace 'vlan-', ""}).Trim() -Split " ").Split("",[System.StringSplitOptions]::RemoveEmptyEntries)
                             }

    $script:bandwidth = ((Invoke-SSHCommand -index $session -Command "show configuration interfaces $interface | match bandwidth").Output | % {$_ -replace 'bandwidth', ""} | % {$_ -replace ';', ""}).Trim()
     
    $policerinput = 'show configuration | match ' + "$parent" + ' | match "unit ' + $subport + '"' +' | match "policer input" | display set'
    $policeroutput = 'show configuration | match ' + "$parent" + ' | match "unit ' + $subport + '"' +' | match "policer output" | display set'

    $input = ((Invoke-SSHCommand -index $session -Command "$policerinput").Output | % {$_ -replace "set interfaces $parent unit $subport family $family policer input ", ""}).Trim()
    $output = ((Invoke-SSHCommand -index $session -Command "$policeroutput").Output | % {$_ -replace "set interfaces $parent unit $subport family $family policer output ", ""}).Trim()
    
    Remove-Variable policerinput -Force -ErrorAction SilentlyContinue
    Remove-Variable policeroutput -Force -ErrorAction SilentlyContinue
         
       If (($input -match "m") -or ($input -match "g")) {
    $script:policeri = "$input"
        }
        
        If (($output -match "m") -or ($output -match "g")) {
    $script:policero = "$output"      
        }


If ($interface -match '\.') {   
    If ($family -match "inet") {
                                $script:ipv4address = (((Invoke-SSHCommand -index $session -Command "show configuration | match $parent | display set | match ""unit $subport family inet address"" | trim 15").Output | % {$_ -replace "$parent unit $subport family inet address ", ""}).Trim() -Split " ").Split("",[System.StringSplitOptions]::RemoveEmptyEntries)
                                
                                    
        If ($search -match "pri") {
                                    $script:circuittype = 'PRI'
                                    $script:CE = Get-CE
                                   } # search ipxn

                                   Else {
            If ($search -match "sip") {
                                        $script:circuittype = 'SIP'
                                        $script:CE = Get-CE
                                        } # search tgxx

                                   Else {
                If ($vlan -match "1300") {
                                          $script:circuittype = 'Internet'
                                          $script:CE = Get-CE
                                                  } # if vlan 1300
                                    Else {
                    If ($vlan -match "2400") {
                                              $script:circuittype = 'Internet'
                                              $script:CE = Get-CE
                                             } # if vlan 2400
                                    
                                        Else {
                         $script:circuittype = 'Internet'
                         $script:CE = Get-CE

                         Foreach ($ipv4 in $ipv4address) {
                         $allips += Get-NetworkRange -IP "$ipv4" 
                         } # end of for each ipv4address

                         $alotofips = $allips.Count

                         If ($alotofips -ge "30") {
                         OKX -question "Found $alotofips IP addresses to search for Routed Blocks?" -title "Search for Routed Blocks?"
                         } 
                         Else {
                         $okx = 'OK'
                         }

                         Remove-Variable alotofips -Force -ErrorAction SilentlyContinue

                         If ($okx -match "OK") {

                        Foreach ($singleip in $allips) {
                         $showrouted = 'show configuration | display set | match "static route" | match ' + "$singleip" + ' | trim 33'
                         $routed = (((Invoke-SSHCommand -index $session -Command "$showrouted").Output | % {$_ -replace "$singleip", ""} | % {$_ -replace ' next-hop ', ""}).Trim() -Split " ").Split("",[System.StringSplitOptions]::RemoveEmptyEntries)
                            If ($routed) {  
                                          $script:routedips += "$routed"
                                          Foreach ($routedblock in $routed) {
                                          $allips += Get-NetworkRange -IP "$routedblock"
                                                                                } # end of for each routedips
                                          Remove-Variable showrouted -Force -ErrorAction SilentlyContinue
                                          Remove-Variable routed -Force -ErrorAction SilentlyContinue
                                          } # end of if routed

                                                
                                                        } # end of 1st for each allips
                                               
                                               } # end of 1st if okx match OK

                         clv okx -Force -ErrorAction SilentlyContinue
                         
                         $alotofips = $allips.Count

                         If ($alotofips -ge "30") {
                         OKX -question "Found $alotofips IP addresses to search for BGP Neighbors?" -title "Search for BGP Neighbors?"
                         } 
                         Else {
                         $okx = 'OK'
                         }

                         Remove-Variable alotofips -Force -ErrorAction SilentlyContinue

                         If ($okx -match "OK") { 
                         Foreach ($singleip in $allips) {
                         $showBGPas = 'show bgp neighbor ' + "$singleip" + ' | match "Local:" | trim 6'
                         $getBGPas = (((Invoke-SSHCommand -index $session -Command "$showBGPas").Output | % {$_ -replace "$singleip", ""} | % {$_ -replace 'Local: ', ""}  | % {$_ -replace 'AS 10796', ""} | % {$_ -replace 'AS 20231', ""}).Trim() -Split " ").Split("",[System.StringSplitOptions]::RemoveEmptyEntries)

                            If ($getBGPas) {
                                            If ($getBGPas -match '\+') {
                                                                       $script:BGPas += ($getBGPas.Get(2)).Trim() | ToArray
                                                                       }
                                                                       Else {
                                                                             $script:BGPas += ($getBGPas.Get(1)).Trim() | ToArray
                                                                             }
                                           $script:BGPneighbor += $singleip | ToArray
                                           } # end of if getBGPas
                                           
                                           Remove-Variable showBGPas -Force -ErrorAction SilentlyContinue
                                           Remove-Variable getBGPas -Force -ErrorAction SilentlyContinue
                                                        
                                                        } # end of 2nd for each allips
                         
                                               } # end of 2nd if okx match OK
                         
                         clv okx -Force -ErrorAction SilentlyContinue  

                         $script:alotofips = $allips.Count
                         Remove-Variable allips -Force -ErrorAction SilentlyContinue   
                                                  
                                If ($BGPas) {
                                    Foreach ($as in $BGPas) {
                         $showBGProute = 'show configuration | display set | match ' + "$as" + ' | match "term EXPORT from route-filter" | trim 36'
                         $script:BGProutes += ((Invoke-SSHCommand -index $session -Command "$showBGProute").Output | % {$_ -replace "$BGPasformat", ""} | % {$_ -replace ' term EXPORT from route-filter', ""}).Trim() 
                         Remove-Variable BGPasformat -Force -ErrorAction SilentlyContinue
                         Remove-Variable showBGProute -Force -ErrorAction SilentlyContinue
                                                            } # end for each of BGPas
                                            } # end of if BGPas
                         
                                 
                                 } # else if not vlan 2400
                                } # else if not vlan 1300
                                                 } # else if not tgxx
                } # else if not ipxn                                                                 
                                } # end if inet            
} # end if \. 

                } # end of if interface


# Parent interface details 

    $lastflap = 'show interfaces ' + "$parent" + ' extensive | match "Last flapped" | trim 19'
    $optics = 'show interfaces Internetgnostics optics ' + "$parent" + ' | match "Laser rx power                            :|Receiver signal average optical power" | trim 4'
    $powerlevels = 'show interfaces Internetgnostics optics ' + "$parent" + ' | match "Laser rx power" | match threshold | trim 49'
    $logs = 'show log messages | match ' + "$parent" + ' | last 2 | no-more | except UI_CMDLINE_READ_LINE'

    $script:speed = ((Invoke-SSHCommand -index $session -Command "show configuration interfaces $parent | match speed | trim 15").Output | % {$_ -replace ';', ""}).Trim()
    
    $desc = 'show configuration | match ' + "$parent" + ' | display set | match "unit ' + "$subport" +  ' description"'
    $script:description = ((Invoke-SSHCommand -index $session -Command "$desc").Output | % {$_ -replace "set interfaces $parent unit $subport description ", ""}).Trim()
 

    Try {
    $breakout = ($description | % {$_ -replace '"', ""}).Trim().Split('@') -Split ':'
       
       If ($breakout.Get(0) -match "CUST") {
                                           If (($breakout.Get(1) -match "VOICE") -or ($breakout.Get(1) -match "CCC") -or ($breakout.Get(1) -match "VPLS") -or ($breakout.Get(1) -match "Internet")) {
                                           $script:business = $breakout.Get(2)                                                                                                                      
                                                If ($breakout.Get(3) -match '.TWCC') {
                                                                                     $script:CID = $breakout.Get(3).Trim()
                                                                                     } # end of 1st circuit if 
                                                                                     Else {
                                                                                          $script:street = $breakout.Get(3)
                                                                                          If (($breakout.Get(4) -match "XX") -or ($entry -match "IPXN")) {
                                                                                                                                                         $script:CID = $breakout.Get(4).Trim() 
                                                                                                                                                         } # end of 2nd circuit if
                                                                                                                } # end of else of 1st circuit if
                                           } # end of type if
                                           } # end of CUST if  
         
       
    Remove-Variable breakout -Force -ErrorAction SilentlyContinue
        
        }
        Catch {
        # Catch? There is no catch!
        }
         
    $parentdesc = 'show configuration | match ' + "$parent" + ' | display set | match "' + "$parent" +  ' description"'
    $script:parentdescription = ((Invoke-SSHCommand -index $session -Command "$parentdesc").Output | % {$_ -replace "set interfaces $parent description ", ""}).Trim()
    
    Try {
    $breakout = ($parentdescription | % {$_ -replace '"', ""}).Trim().Split('@') -Split ':'
       
       If ($breakout.Get(0) -match "CPE") {
                                           If ($breakout.Get(1) -match "$business") {
                                                                                     If ($street) { } Else {                                                                                                          
                                                                                     $script:street = $breakout.Get(2)
                                                                                                            } # end of street else
                                                                                     # $script:CPEhost = $breakout.Get(3)     
                                                                                                            
                                                                                     } # end of type if business
                                                                                     Else {
                                                                                           $script:business = $breakout.Get(1)
                                                                                           $script:street = $breakout.Get(2)
                                                                                           $script:CPEhost = $breakout.Get(3)
                                                                                           }
                                           } # end of CPE if  
         
       
    Remove-Variable breakout -Force -ErrorAction SilentlyContinue
        
        }
        Catch {
        # Catch? There is no catch!
        }
     
    
    If ($ipv4address) {
                       $ipaddy = [String]$ipv4address
                       $script:adminlink = ((Invoke-SSHCommand -index $session -Command "$link").Output.TrimEnd() | % {$_ -replace 'inet', ""}).TrimEnd("$ipaddy")                                        
                       clv ipaddy -Force -ErrorAction SilentlyContinue
                       }
                       Else {
                             $script:adminlink = ((Invoke-SSHCommand -index $session -Command "$link").Output.TrimEnd() | % {$_ -replace 'inet', ""} | % {$_ -replace 'bridge', ""} | % {$_ -replace 'ccc', ""} | % {$_ -replace 'multiservice', ""} | % {$_ -replace 'vpls', ""})    
                             }
 
    $script:flap = (Invoke-SSHCommand -index $session -Command "$lastflap").Output.TrimEnd()
    $i_probs = ((Invoke-SSHCommand -index $session -Command "show interfaces $parent extensive | match ""Framing"" | trim 4").Output.Trim() -Split ',').Trim()
    $o_probs = ((Invoke-SSHCommand -index $session -Command "show interfaces $parent extensive | match ""Carrier"" | trim 4").Output.Trim() -Split ',').Trim()
    $lightmwdb = (((Invoke-SSHCommand -index $session -Command "$optics").Output | % {$_ -replace 'Receiver signal average optical power     :', ""} | % {$_ -replace 'Laser rx power                            :', ""} | % {$_ -replace '/', ""}).Trim() -Split " ").Split("",[System.StringSplitOptions]::RemoveEmptyEntries)
    $script:lightlevels = (((Invoke-SSHCommand -index $session -Command "$powerlevels").Output | % {$_ -replace 'Receiver signal average optical power     :', ""} | % {$_ -replace 'Laser rx power                            :', ""} | % {$_ -replace '/', ""}).Trim() -Split " ").Split("",[System.StringSplitOptions]::RemoveEmptyEntries)
    $linklevel = ((Invoke-SSHCommand -index $session -Command "show interfaces $parent meInternet brief | match Link-Level | trim 13").Output.Trim() -Split ',').Trim()

    If ($model -notmatch "mx") {
                                $script:portmode = ((Invoke-SSHCommand -index $session -Command "show configuration | match $parent | display set | match port-mode | trim 15").Output | % {$_ -replace "$parent", ""} | % {$_ -replace 'unit 0 family ethernet-switching port-mode', ""}).Trim()
                                }


    If ($linklevel) {
    $script:meInternet = ($linklevel.Get(0) -replace "type: ")
    $script:mtu = ($linklevel.Get(1) -replace "MTU: ")
    $script:speed = ($linklevel.Get(2) -replace "Speed: ")
    $script:duplex = ($linklevel.Get(3) -replace "Duplex: ")
    }

    If ($lightmwdb) {
    $script:light = $lightmwdb.Get(0) 
    }
    Else {
          $script:light = $null
          }

    Try {
    # input errors
    [int]$script:drops = ($i_probs.Get(1) -replace "Drops: ")
    [int]$script:framing = ($i_probs.Get(2) -replace "Framing errors: ")
    [int]$script:runts = ($i_probs.Get(3) -replace "Runts: ")
    [int]$script:policed = ($i_probs.Get(4) -replace "Policed discards: ")
    [int]$script:l3incompletes = ($i_probs.Get(5) -replace "L3 incompletes: ")
    [int]$script:l2channel = ($i_probs.Get(6) -replace "L2 channel errors: ")
    [int]$script:l2mismatch = ($i_probs.Get(7) -replace "L2 mismatch timeouts: ")
    [int]$script:fifo = ($i_probs.Get(8) -replace "FIFO errors: ")
    [int]$script:resource = ($i_probs.Get(9) -replace "Resource errors: ")
    # output errors
    [int]$script:carrier = ($o_probs.Get(0) -replace "Carrier transitions: ")
    # [int]$script:errors = ($o_probs.Get(1) -replace "Errors: ")
    [int]$script:drops += ($o_probs.Get(2) -replace "Drops: ")
    [int]$script:collisions = ($o_probs.Get(3) -replace "Collisions: ")
    [int]$script:agedpackets = ($o_probs.Get(4) -replace "Aged packets: ")
    [int]$script:fifo += ($o_probs.Get(5) -replace "FIFO errors: ")
    [int]$script:hslinkcrc = ($o_probs.Get(6) -replace "HS link CRC errors: ")
    [int]$script:mtuerrors = ($o_probs.Get(7) -replace "MTU errors: ")
    [int]$script:resource += ($o_probs.Get(8) -replace "Resource errors: ") 
        }
        Catch {
               # Catch? There is no catch! 
               }


# CCCs and VPLSs

 If (($family -match "ccc") -or ($encapsulation -match "ccc")){
    $script:circuittype = 'CCC'
    }

 If (($family -match "vpls") -or ($encapsulation -match "vpls")){
                                                                 $script:circuittype = 'VPLS'
                                                                 $script:routinginstance = ((Invoke-SSHCommand -index $session -Command "$VPLSinstance").Output | % {$_ -replace "interface $interface", ""}).Trim() 
                                                                 $script:vplsid = ((Invoke-SSHCommand -index $session -Command "show configuration | display set | match $routinginstance | match vpls-id | trim 22").Output.Trim() | % {$_ -replace "$routinginstance", ""} | % {$_ -replace 'protocols vpls vpls-id', ""}).Trim().Split("",[System.StringSplitOptions]::RemoveEmptyEntries)
                                                                 If ($vplsid) { }
                                                                                Else {
                                                                                      $getvrftarget = 'show configuration | display set | match ' + "$routinginstance" + ' | match vrf-target | trim 22'
                                                                                      $vrftarget = ((Invoke-SSHCommand -index $session -Command "$getvrftarget").Output.Trim() | % {$_ -replace "$routinginstance", ""} | % {$_ -replace ' vrf-target', ""} | % {$_ -replace ' target:', ""}).Trim()   
                                                                                      
                                                                                      If (($vrftarget -match "import") -or ($vrftarget -match "export")) {
                                                                                                                                                          $vrftarget = ($vrftarget -replace 'import', "" -replace 'export', "" -split ':').Trim().Split("",[System.StringSplitOptions]::RemoveEmptyEntries)
                                                                                                                                                          $script:vplsid = $vrftarget.Get(0)
                                                                                                                                                          $script:vrf = $vrftarget.Get(1)
                                                                                                                                                          }
                                                                                                                                                          Else {
                                                                                                                                                                $vrftarget = ($vrftarget -split ':').Trim().Split("",[System.StringSplitOptions]::RemoveEmptyEntries)
                                                                                                                                                                $script:vrf = $vrftarget.Get(0)
                                                                                                                                                                $script:vplsid = $vrftarget.Get(1)
                                                                                                                                                                }
                                                                                      }
                                                                               
                                                                 }

    

    If ($adminlink -match 'down  up') {
    $script:vplsloop = (Invoke-SSHCommand -index $session -Command "$loopscript").Output.TrimEnd()    
    $bridging = 'show vpls mac-table interface ' + "$interface" + ' | match bridging | trim 19'
    $bridgedomain = ((Invoke-SSHCommand -index $session -Command "$bridging").Output | % {$_ -replace ', VLAN : none', ""}).Trim()
    $macmovebuffer = 'show l2-learning mac-move-buffer | match '+ $bridgedomain +' | last 1 | no-more'
    $script:macmove = ((Invoke-SSHCommand -index $session -Command "$macmovebuffer").Output | % {$_ -replace "$bridgedomain", ""} | % {$_ -replace '[()]', ""} | % {$_ -replace 'more 100%', ""}).Trim()
    }



# Get customer premise equipment

$script:CPE = Get-CPE


# Get customer equipment

$script:CE = Get-CE


# Out to log    

    $script:log = ((Invoke-SSHCommand -index $session -Command "$logs" -ErrorAction SilentlyContinue).Output | % {$_ -replace '{master}', ""}).Trim()


# clearables

    Remove-Variable intsplit -Force -ErrorAction SilentlyContinue
    Remove-Variable type_DPC -Force -ErrorAction SilentlyContinue
    Remove-Variable nslookup -Force -ErrorAction SilentlyContinue
    Remove-Variable result -Force -ErrorAction SilentlyContinue
    Remove-Variable getvlan -Force -ErrorAction SilentlyContinue
    Remove-Variable desc -Force -ErrorAction SilentlyContinue
    Remove-Variable parentdesc -Force -ErrorAction SilentlyContinue
    Remove-Variable policerinput -Force -ErrorAction SilentlyContinue
    Remove-Variable policeroutput -Force -ErrorAction SilentlyContinue
    Remove-Variable input -Force -ErrorAction SilentlyContinue
    Remove-Variable output -Force -ErrorAction SilentlyContinue
    Remove-Variable family -Force -ErrorAction SilentlyContinue
    Remove-Variable encapsulation -Force -ErrorAction SilentlyContinue
    Remove-Variable link -Force -ErrorAction SilentlyContinue
    Remove-Variable i_probs -Force -ErrorAction SilentlyContinue
    Remove-Variable o_probs -Force -ErrorAction SilentlyContinue
    Remove-Variable errors -Force -ErrorAction SilentlyContinue
    Remove-Variable exterrors -Force -ErrorAction SilentlyContinue
    Remove-Variable lastflap -Force -ErrorAction SilentlyContinue
    Remove-Variable optics -Force -ErrorAction SilentlyContinue
    Remove-Variable lightmwdb -Force -ErrorAction SilentlyContinue
    Remove-Variable lightlevels -Force -ErrorAction SilentlyContinue
    Remove-Variable arp -Force -ErrorAction SilentlyContinue
    Remove-Variable arpVGW -Force -ErrorAction SilentlyContinue
    Remove-Variable VPLSinstance -Force -ErrorAction SilentlyContinue
    Remove-Variable bridging -Force -ErrorAction SilentlyContinue
    Remove-Variable bridgedomain -Force -ErrorAction SilentlyContinue
    Remove-Variable macmovebuffer -Force -ErrorAction SilentlyContinue
    Remove-Variable getvrftarget -Force -ErrorAction SilentlyContinue
    Remove-Variable vrftarget -Force -ErrorAction SilentlyContinue
    Remove-Variable logs -Force -ErrorAction SilentlyContinue
    Remove-Variable loopscript -Force -ErrorAction SilentlyContinue

If ($date) { } 
             Else {
                   $script:date = (Get-Date -Format s).ToString() | % {$_ -Replace ':',"-"}
                   }

Out-Console_Log

        } # end if session

} # end of Juniper-Get-INT     

    # Juniper find SPLUNK
    Function Juniper-Find-SPLUNK {
                                  Add-Session -device $result.router
                                  $macmovebuffer = 'show l2-learning mac-move-buffer | match ' + "$mac" + ' | last 1 | no-more | trim 39'
                                  $routinginstance = ((Invoke-SSHCommand -index $session -Command "$macmovebuffer").Output | % {$_ -replace '_', ""} | % {$_ -replace '-', ""} | % {$_ -replace '[()]', ""} | % {$_ -replace 'more 100%', ""}).Trim().Split("",[System.StringSplitOptions]::RemoveEmptyEntries)
                                  $findint = 'show configuration | match ' + "$routinginstance" + ' | display set | match interface | trim 22 | no-more'
                                  $interfaces = (((Invoke-SSHCommand -index $session -Command "$findint").Output | % {$_ -replace "$routinginstance", ""} | % {$_ -replace 'interface', ""} | % {$_ -replace 'protocols vpls -mac-limit', ""}).Trim()  -Split " ").Split("",[System.StringSplitOptions]::RemoveEmptyEntries)

                                  If (($interfaces -match "ge-") -or ($interfaces -match "xe-") -or ($interfaces -match "ae")) {
                                                                                                                                Foreach ($int in $interfaces) {
                                                                                                                                                               $prop = @{
                                                                                                                                                                         'router'=$router
                                                                                                                                                                         }
                                                                                                                                                               $obj = New-Object -TypeName PSObject -Property $prop
                                                                                                                                                               $obj | Add-Member -type NoteProperty -name interface -value $int -Force
                                                                                                                                                               $obj

                                                                                                                                                               clv prop -Force -ErrorAction SilentlyContinue
                                                                                                                                                               clv int -Force -ErrorAction SilentlyContinue
                                                                                                                                                               clv desc -Force -ErrorAction SilentlyContinue
                                                                                                                                                               }
                                                                                                                                 }
                                                                                                                                 Else {
                                                                                                                                       $obj = "could not find interface(s)"
                                                                                                                                       $obj
                                                                                                                                       }
                                  
                                clv router -Force -ErrorAction SilentlyContinue
                                clv interfaces -Force -ErrorAction SilentlyContinue
    }
    
    # execute Juniper commands function
    Function Juniper-Commands {
                               param (
                                      [Parameter(Position=0)]
                                      [ValidateSet('ticket paster','config','terse','extensive','light','arp','logs','all','VPLS_MAC','VPLS_status','ping')]
                                      [System.String]$Command
                                      )
                                
                                If ($Command -match "ticket paster") {return}

                                If ($session) {       
    
                                If (($model -match "mx") -or ($model -match "ex")) {
    
                                If (($Command -match "all") -or ($Command -match "config")) {
                                $exec = 'show configuration interfaces' + ' ' + "$interface"
                                $status += "$fqdn" + '>' + ' ' + "$exec"
                                $status += "`n"
                                $status += (Invoke-SSHCommand -index $session -Command "$exec" -ErrorAction SilentlyContinue).Output
                                $status += "`n"             
                                Remove-Variable exec -Force -ErrorAction SilentlyContinue
                                }

                                If (($Command -match "all") -or ($Command -match "terse")) {
                                $exec = 'show interfaces' + ' ' + "$interface" + ' ' + 'terse'
                                $status += "$fqdn" + '>' + ' ' + "$exec"
                                $status += "`n"
                                $status += (Invoke-SSHCommand -index $session -Command "$exec" -ErrorAction SilentlyContinue).Output
                                $status += "`n"             
                                Remove-Variable exec -Force -ErrorAction SilentlyContinue
                                }

                                If (($Command -match "all") -or ($Command -match "extensive")) {
                                $exec = 'show interfaces' + ' ' + "$parent" + ' ' + 'extensive' + ' ' + '|' + ' ' + 'match' + ' ' + '"' + 'physical|descr|linklevel|SNMP-Traps|flap|error' + '"'
                                $status += "$fqdn" + '>' + ' ' + "$exec"
                                $status += "`n"
                                $status += (Invoke-SSHCommand -index $session -Command "$exec" -ErrorAction SilentlyContinue).Output
                                $status += "`n"             
                                Remove-Variable exec -Force -ErrorAction SilentlyContinue
                                }

                                If (($Command -match "all") -or ($Command -match "light")) {
                                $exec = 'show interfaces Internetgnostics optics' + ' ' + "$parent" + ' ' + '|' + ' ' + 'match' + ' ' + '"receiver|rx"'

                                $status += "$fqdn" + '>' + ' ' + "$exec"
                                $status += "`n"
                                $status += (Invoke-SSHCommand -index $session -Command "$exec" -ErrorAction SilentlyContinue).Output
                                $status += "`n"             
                                Remove-Variable exec -Force -ErrorAction SilentlyContinue
                                }

                                If (($model -match "ex") -and ($Command -match "all") -or ($Command -match "Switching Table")) {
                                $exec = 'show ethernet-switching table vlan ' + $vlan + ' brief | match ' + $interface + ' | find learn | trim 20'
                                $status += "$fqdn" + '>' + ' ' + "$exec"
                                $status += "`n"
                                $status += (Invoke-SSHCommand -index $session -Command "$exec" -ErrorAction SilentlyContinue).Output
                                $status += "`n"
                                Remove-Variable exec -Force -ErrorAction SilentlyContinue
                                }
                                Else {
                                      If (($Command -match "all") -or ($Command -match "arp")) {
                                                                                                $exec = 'show arp no-resolve' + ' ' + '|' + ' ' + 'match' + ' ' + "$parent"
                                                                                                $status += "$fqdn" + '>' + ' ' + "$exec"
                                                                                                $status += "`n"
                                                                                                $status += (Invoke-SSHCommand -index $session -Command "$exec" -ErrorAction SilentlyContinue).Output
                                                                                                $status += "`n"             
                                                                                                Remove-Variable exec -Force -ErrorAction SilentlyContinue
                                                                                                }
                                      }

                                If (($Command -match "all") -or ($Command -match "logs")) {
                                $exec = 'show log messages | match ' + "$parent" + ' | last 4 | no-more | except UI_CMDLINE_READ_LINE'
                                $status += "$fqdn" + '>' + ' ' + "$exec"
                                $status += "`n"
                                $status += (Invoke-SSHCommand -index $session -Command "$exec" -ErrorAction SilentlyContinue).Output
                                $status += "`n"             
                                Remove-Variable exec -Force -ErrorAction SilentlyContinue
                                }

                                If (($circuittype -match "VPLS") -and ($Command -match "all") -or ($Command -match "VPLS_MAC")) {
                                $exec = 'show vpls mac-table interface' + ' ' + "$interface"
                                $status += "$fqdn" + '>' + ' ' + "$exec"
                                $status += "`n"
                                $status += (Invoke-SSHCommand -index $session -Command "$exec" -ErrorAction SilentlyContinue).Output
                                $status += "`n"             
                                Remove-Variable exec -Force -ErrorAction SilentlyContinue
                                }

                                If (($circuittype -match "VPLS") -and ($Command -match "all") -or ($Command -match "VPLS_status")) {
                                $exec = 'show vpls connections instance ' + "$routinginstance" + ' | find ' + "$routinginstance"
                                $status += "$fqdn" + '>' + ' ' + "$exec"
                                $status += "`n"
                                $status += (Invoke-SSHCommand -index $session -Command "$exec" -ErrorAction SilentlyContinue).Output
                                $status += "`n"
                                Remove-Variable exec -Force -ErrorAction SilentlyContinue
                                }

    

                                If (($circuittype -match "Internet") -and ($Command -match "all") -or ($Command -match "ping")) {
                                $exec = 'ping 216.58.217.142 interface ' + "$interface" + ' rapid count 10'
                                $status += "$fqdn" + '>' + ' ' + "$exec"
                                $status += "`n"
                                $status += (Invoke-SSHCommand -index $session -Command "$exec" -ErrorAction SilentlyContinue).Output
                                $status += "`n"
                                Remove-Variable exec -Force -ErrorAction SilentlyContinue
                                }    


                            Remove-Variable int -Force -ErrorAction SilentlyContinue         
                            Remove-Variable ver -Force -ErrorAction SilentlyContinue
                            Remove-Variable logs -Force -ErrorAction SilentlyContinue

                            Write-Host "`n"
                            echo " " | ToUnicode | Out-File -FilePath $logpath -Append
                            Write-Host "$status"
                            echo "$status" | ToUnicode | Out-File -FilePath $logpath -Append 
                            Write-Host "`n"
                            echo " " | ToUnicode | Out-File -FilePath $logpath -Append

                                Write-Host "end of $Command command(s) for $fqdn > $interface > $description" -ForegroundColor DarkCyan
                                Write-Host "output has been saved to $logpath" -ForegroundColor DarkCyan
                                Write-Host "`n" -ForegroundColor Black


                            Remove-Variable exec -Force -ErrorAction SilentlyContinue
                            Remove-Variable status -Force -ErrorAction SilentlyContinue

                            }

                                               } # end if session

    }
                                                                          
# select an action Internetlog function
Function Menu{

Param($addmenuitems,
      $menutitle
      )

If ($menutitle -eq $null) {
                           $menutitle = "ZEN select an action box"
                           }


[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing") 

$objForm = New-Object System.Windows.Forms.Form
$objForm.Text = $menutitle
$objForm.Size = New-Object System.Drawing.Size(300,200) 
$objForm.StartPosition = "CenterScreen"

$objForm.KeyPreview = $True
$objForm.Add_KeyDown({if ($_.KeyCode -eq "Enter") 
    {$x=$objListBox.SelectedItem;$objForm.Close()}})
$objForm.Add_KeyDown({if ($_.KeyCode -eq "Escape") 
    {$objForm.Close()}})

$OKButton = New-Object System.Windows.Forms.Button
$OKButton.Location = New-Object System.Drawing.Size(75,120)
$OKButton.Size = New-Object System.Drawing.Size(75,23)
$OKButton.Text = "OK"
$OKButton.Add_Click({$x=$objListBox.SelectedItem;$objForm.Close()})
$objForm.Controls.Add($OKButton)

$CancelButton = New-Object System.Windows.Forms.Button
$CancelButton.Location = New-Object System.Drawing.Size(150,120)
$CancelButton.Size = New-Object System.Drawing.Size(75,23)
$CancelButton.Text = "Cancel"
$CancelButton.Add_Click({$objForm.Close()})
$objForm.Controls.Add($CancelButton)

$objLabel = New-Object System.Windows.Forms.Label
$objLabel.Location = New-Object System.Drawing.Size(10,20) 
$objLabel.Size = New-Object System.Drawing.Size(280,20) 
$objLabel.Text = "Please select an action:"
$objForm.Controls.Add($objLabel) 

$objListBox = New-Object System.Windows.Forms.ListBox 
$objListBox.Location = New-Object System.Drawing.Size(10,40) 
$objListBox.Size = New-Object System.Drawing.Size(260,20) 
$objListBox.Height = 80

Foreach ($sum in $addmenuitems) {
[void] $objListBox.Items.Add("$sum")
}

$objForm.Controls.Add($objListBox) 

$objForm.Topmost = $True

$objForm.Add_Shown({$objForm.Activate()})
[void] $objForm.ShowInternetlog()

$x

$script:action = $objListBox.SelectedItem
}

    # ZEN data entry
    Function Input-Box {
                        Param($text)

                        [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing") 
                        [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") 

                        $objForm = New-Object System.Windows.Forms.Form 
                        $objForm.Text = "ZEN data entry box"
                        $objForm.Size = New-Object System.Drawing.Size(300,200) 
                        $objForm.StartPosition = "CenterScreen"

                        $objForm.KeyPreview = $True
                        $objForm.Add_KeyDown({if ($_.KeyCode -eq "Enter") 
                            {$x=$objTextBox.Text;$objForm.Close()}})
                        $objForm.Add_KeyDown({if ($_.KeyCode -eq "Escape") 
                            {$objForm.Close()}})

                        $OKButton = New-Object System.Windows.Forms.Button
                        $OKButton.Location = New-Object System.Drawing.Size(75,120)
                        $OKButton.Size = New-Object System.Drawing.Size(75,23)
                        $OKButton.Text = "OK"
                        $OKButton.Add_Click({$x=$objTextBox.Text;$objForm.Close()})
                        $objForm.Controls.Add($OKButton)

                        $CancelButton = New-Object System.Windows.Forms.Button
                        $CancelButton.Location = New-Object System.Drawing.Size(150,120)
                        $CancelButton.Size = New-Object System.Drawing.Size(75,23)
                        $CancelButton.Text = "Cancel"
                        $CancelButton.Add_Click({$objForm.Close()})
                        $objForm.Controls.Add($CancelButton)

                        $objLabel = New-Object System.Windows.Forms.Label
                        $objLabel.Location = New-Object System.Drawing.Size(10,10) 
                        $objLabel.Size = New-Object System.Drawing.Size(280,40) 
                        $objLabel.Text = "$text"
                        $objForm.Controls.Add($objLabel) 

                        $objTextBox = New-Object System.Windows.Forms.TextBox 
                        $objTextBox.Location = New-Object System.Drawing.Size(10,80) 
                        $objTextBox.Size = New-Object System.Drawing.Size(260,20) 
                        $objForm.Controls.Add($objTextBox) 

                        $objForm.Topmost = $True

                        $objForm.Add_Shown({$objForm.Activate()})
                        [void] $objForm.ShowInternetlog()

                        $x

                        $script:search = $objTextBox.Text
    }

    # okay or cancel prompt box
    Function OKX {
    Param(  
    [string] $question,
    [string] $title
    )
    $script:okx = [System.Windows.Forms.MessageBox]::Show("$question","$title",[System.Windows.Forms.MessageBoxButtons]::OKCancel)
    }

    # out to console and log file
    Function Out-Console_Log {
                              If ($logpath) { }
                                              Else {
                                                    If ($CID) {
                                                               $script:logpath = "$lnklocation" + '\' + "$CID" + '_' + "$date" + '.log'
                                                               }
                                                               Else {
                                                                     $script:logpath = "$lnklocation" + '\' + "$search" + '_' + "$date" + '.log'
                                                                     }
                      
                                                   echo "Run on: $date" | Out-File -FilePath $logpath -Append
                                                   echo "Searched for: $search" | Out-File -FilePath $logpath -Append
                                                   echo " " | Out-File -FilePath $logpath -Append
                                                   }
                        "`n"

                        If ($business) {
                        Write-Host "Business: $business" -ForegroundColor Green
                        echo "Business: $business" | Out-File -FilePath $logpath -Append
                            If ($street) {
                            Write-Host "Address: $street" -ForegroundColor Green
                            echo "Address: $street" | Out-File -FilePath $logpath -Append
                            }
                        }

                        If ($CID) {
                        Write-Host "Circuit ID: $CID" -ForegroundColor Green
                        echo "Circuit ID: $CID" | Out-File -FilePath $logpath -Append
                        }

                        If ($circuittype) {
                        Write-Host "Circuit Type: $circuittype" -ForegroundColor Green
                        echo "Circuit Type: $circuittype" | Out-File -FilePath $logpath -Append
                        }

                        If (($bandwidth -match "m") -or ($bandwidth -match "g")) {
                        Write-Host "Bandwidth: $bandwidth" -ForegroundColor Green
                        echo "Bandwidth: $bandwidth" | Out-File -FilePath $logpath -Append}

                        $model = $model+':'
                        Write-Host "$model $fqdn" -ForegroundColor Green
                        echo "$model $fqdn" | Out-File -FilePath $logpath -Append

                        $ether = "$ethernet" + ':'

                        If ($interface -match '\.') {    
                            If (($business) -and ($CID)) {
                            Write-Host "Logical Interface: $interface" -ForegroundColor Green
                            echo "Logical Interface: $interface" | Out-File -FilePath $logpath -Append
                                                          }
                            Else {
                                  Write-Host "Logical Interface: $interface > $description" -ForegroundColor Green
                                  echo "Logical Interface: $interface > $description" | Out-File -FilePath $logpath -Append
                                  }

                        }

                        If (($street)){ 
                        Write-Host "$ethernet Physical Interface: $parent" -ForegroundColor Green
                        echo "$ethernet Physical Interface: $parent" | Out-File -FilePath $logpath -Append
                        }
                        Else {
                        Write-Host "$ethernet Physical Interface: $parent > $parentdescription" -ForegroundColor Green
                        echo "$ethernet Physical Interface: $parent > $parentdescription" | Out-File -FilePath $logpath -Append
                        }

                        Remove-Variable ether -Force -ErrorAction SilentlyContinue

                        If (($model -notmatch "mx") -and ($portmode)) {
                                                                       Write-Host "Mode: $portmode" -ForegroundColor Green
                                                                       echo "Mode: $portmode" | Out-File -FilePath $logpath -Append
                                                                       }

                        If (($meInternet -match "Flexible-Ethernet") -or ($light)) {
                                                                               Write-Host "MeInternet: Fiber" -ForegroundColor Green
                                                                               echo "MeInternet: Fiber" | Out-File -FilePath $logpath -Append
                                                                               }
                                                                               Else {
                                                                                     Write-Host "MeInternet: Copper" -ForegroundColor Green
                                                                                     echo "MeInternet: Copper" | Out-File -FilePath $logpath -Append
                                                                                     }


                        If (($speed -match "m") -or($speed -match "M") -or ($speed -match "G") -or ($speed -match "g")) {
                        Write-Host "Speed: $speed" -ForegroundColor Green
                        echo "Speed: $speed" | Out-File -FilePath $logpath -Append}

                        If (($duplex -match "half") -or ($duplex -match "full")) {
                        Write-Host "Duplex: $duplex" -ForegroundColor Green
                        echo "Duplex: $duplex" | Out-File -FilePath $logpath -Append}

                        If ($mtu) {
                        Write-Host "MTU: $mtu" -ForegroundColor Green
                        echo "MTU: $mtu" | Out-File -FilePath $logpath -Append}

                        If ($vlan) {
                        Write-Host "VLAN: $vlan" -ForegroundColor Green
                        echo "VLAN: $vlan" | Out-File -FilePath $logpath -Append
                        }

                        If ($circuittype -match "VPLS") {
                        Write-Host "VPLS ID: $vplsid" -ForegroundColor Green
                        echo "VPLS ID: $vplsid" | Out-File -FilePath $logpath -Append
                        Write-Host "VPLS Instance: $routinginstance" -ForegroundColor Green
                        echo "VPLS Instance: $routinginstance" | Out-File -FilePath $logpath -Append
                        }

                        If (($circuittype -match "Internet") -or ($circuittype -match "PRI") -or ($circuittype -match "SIP")) {
                        Write-Host "IPv4 Address Block(s): $ipv4address" -ForegroundColor Green
                        echo "IPv4 Address Block(s): $ipv4address" | Out-File -FilePath $logpath -Append
                        }

                        If (($circuittype -match "Internet") -and ($routedips)){
                        Write-Host "IPv4 Routed: $routedips" -ForegroundColor Green
                        echo "IPv4 Routed: $routedips" | Out-File -FilePath $logpath -Append
                        }

                        If ($log) {
                                   If (($log -match (get-date -Format "MMM d")) -and ($log -match (get-date -Format "yyyy")) -and ($log -match "SNMP_TRAP_LINK_DOWN")) {
                                                                                                                                                                        $statuscolor = "Yellow"
                                                                                                                                                                        }
                                                                                                                                                                        Else {
                                                                                                                                                                              If (($log -match (get-date -Format "MMM d")) -and ($log -match (get-date -Format "yyyy")) -and ($log -match "SNMP_TRAP_LINK_DOWN") -or ($adminlink -match 'down  up') -or ($adminlink -match 'up    down') -or ($adminlink -match 'down  down')) {
                                                                                                                                                                                                                                                                                                                                                                                                                                $statuscolor = "Red"
                                                                                                                                                                                                                                                                                                                                                                                                                                }
                                                                                                                                                                                                                                                                                                                                                                                                                                Else {
                                                                                                                                                                                                                                                                                                                                                                                                                                      $statuscolor = "Green"
                                                                                                                                                                                                                                                                                                                                                                                                                                      }
                                                                                                                                                                              }

                                   Write-Host "Last Log: $log" -ForegroundColor $statuscolor
                                   echo "Last Log: $log" | Out-File -FilePath $logpath -Append
                                   Remove-Variable statuscolor -Force -ErrorAction SilentlyContinue
                                   }


                    If (($circuittype -match "VPLS") -and ($vplsloop)) {
                                                                        $statuscolor = "Red"
                                                                        Write-Host "VPLS Loop: $vplsloop" -ForegroundColor $statuscolor
                                                                        echo "VPLS Loop: $vplsloop" | Out-File -FilePath $logpath -Append
                                                                        Write-Host "MAC Move: $macmove" -ForegroundColor $statuscolor
                                                                        echo "MAC Move: $macmove" | Out-File -FilePath $logpath -Append
                                                                        }

                        Remove-Variable statuscolor -Force -ErrorAction SilentlyContinue
    
                    If ($uptime) {
                                  Write-Host "Uptime: $uptime" -ForegroundColor Green
                                  echo "Uptime: $uptime" | Out-File -FilePath $logpath -Append
                                  }

                    If ($flap) {
                                If (($flap -match (get-date -Format "yyyy-M-d")) -and ($log -match "SNMP_TRAP_LINK_DOWN") -or ($adminlink -match 'down  up') -or ($adminlink -match 'up    down') -or ($adminlink -match 'down  down')) {
                                                                                                                                                                                                                                         $statuscolor = "Red"
                                                                                                                                                                                                                                         }
                                                                                                                                                                                                                                         Else {
                                                                                                                                                                                                                                               If (($flap -match (get-date -Format "yyyy-M-d")) -and ($log -match "SNMP_TRAP_LINK_DOWN")) {
                                                                                                                                                                                                                                                                                                                                           $statuscolor = "Yellow"
                                                                                                                                                                                                                                                                                                                                           }
                                                                                                                                                                                                                                                                                                                                           Else {
                                                                                                                                                                                                                                                                                                                                                 $statuscolor = "Green"
                                                                                                                                                                                                                                                                                                                                                 }
                                                                                                                                                                                                                                                                                                                                                                                                                                                  
                                                                                                                                                                                                                                         }
            
                                Write-Host "Last Flap: $flap" -ForegroundColor $statuscolor
                                echo "Last Flap: $flap" | Out-File -FilePath $logpath -Append
                                Remove-Variable statuscolor -Force -ErrorAction SilentlyContinue
                                }

                    If (($adminlink -match 'down  up') -or ($adminlink -match 'up    down') -or ($adminlink -match 'down  down')){
                        $statuscolor = "Red"
                        } Else {
                        $statuscolor = "Green"
                        }

                        Write-Host "Admin/Link: $adminlink" -ForegroundColor $statuscolor
                        echo "Admin/Link: $adminlink" | Out-File -FilePath $logpath -Append

                        Remove-Variable statuscolor -Force -ErrorAction SilentlyContinue

                        If ($light -match '\.') {
        
                            If ($lightlevels -match '\.') {
                            Try {
                            $highalarm = $lightlevels.Get(0)
                            $lowalarm = $lightlevels.Get(4)
                            $highwarning = $lightlevels.Get(8)
                            $lowwarning = $lightlevels.Get(12)
                            } 
                            Catch {
                            # Catch? There is no catch!
                            }

                            If (($light -ge "$highalarm") -or ($light -le "$lowalarm")){
                            $statuscolor = "Red"
                                } Else {
                                If (($light -ge "$highwarning") -or ($light -le "$lowwarning")) {
                            $statuscolor = "Yellow"
                                        } Else {
                                        If ($light -le "0.0019") {
                                        $statuscolor = "Red"
                                        } Else {
                                                $statuscolor = "Green"
                                                }
                                        }
                                        }
                                                            } Else {
                                                                    $statuscolor = "Green"
                                                                    }

                        Write-Host "Optics: $light mW" -ForegroundColor $statuscolor
                        echo "Optics: $light mW" | Out-File -FilePath $logpath -Append
    
                        Remove-Variable statuscolor -Force -ErrorAction SilentlyContinue
                        Remove-Variable highalarm -Force -ErrorAction SilentlyContinue
                        Remove-Variable lowalarm -Force -ErrorAction SilentlyContinue
                        Remove-Variable highwarning -Force -ErrorAction SilentlyContinue
                        Remove-Variable lowwarning -Force -ErrorAction SilentlyContinue
                        }

                        If ($agedpackets -ge "1") {
                                                   write-host Aged packets: $agedpackets -ForegroundColor Red
                                                   echo "Aged packets: $agedpackets" | Out-File -FilePath $logpath -Append
                                                   }
                        If ($carrier -ge "1") {
                                               write-host Carrier transistions: $carrier -ForegroundColor Red
                                               echo "Carrier transistions: $carrier" | Out-File -FilePath $logpath -Append
                                               }
                        If ($collisions -ge "1") {
                                                  write-host Collisions: $collisions -ForegroundColor Red
                                                  echo "Collisions: $collisions" | Out-File -FilePath $logpath -Append
                                                  }
                        If ($drops -ge "1") {
                                             write-host Drops: $drops -ForegroundColor Red
                                             echo "Drops: $drops" | Out-File -FilePath $logpath -Append
                                             }
                        If ($hslinkcrc -ge "1") {
                                                 write-host HS link CRC errors: $hslinkcrc -ForegroundColor Red
                                                 echo "HS link CRC errors: $hslinkcrc" | Out-File -FilePath $logpath -Append
                                                 }
                        If ($framing -ge "1") {
                                               write-host Framing errors: $framing -ForegroundColor Red
                                               echo "Framing errors: $framing" | Out-File -FilePath $logpath -Append
                                               }
                        If ($runts -ge "1") {
                                             write-host Runts: $runts -ForegroundColor Red
                                             echo "Runts: $runts" | Out-File -FilePath $logpath -Append
                                             }
                        If ($policed -ge "1") {
                                               write-host Policed discards: $policed -ForegroundColor Red
                                               echo "Policed discards: $policed" | Out-File -FilePath $logpath -Append
                                               }
                        If ($l3incompletes -ge "1") {
                                                     write-host L3 incompletes: $l3incompletes -ForegroundColor Red
                                                     echo "L3 incompletes: $l3incompletes" | Out-File -FilePath $logpath -Append
                                                     }
                        If ($l2channel -ge "1") {
                                                 write-host L2 channel errors: $l2channel -ForegroundColor Red
                                                 echo "L2 channel errors: $l2channel" | Out-File -FilePath $logpath -Append
                                                 }
                        If ($l2mismatch -ge "1") {
                                                  write-host L2 mismatch timeouts: $l2mismatch -ForegroundColor Red
                                                  echo "L2 channel errors: $l2channel" | Out-File -FilePath $logpath -Append
                                                  }
                        If ($mtuerrors -ge "1") {
                                                 write-host MTU errors: $mtuerrors -ForegroundColor Red
                                                 echo "MTU errors: $mtuerrors" | Out-File -FilePath $logpath -Append
                                                 }
                        If ($fifo -ge "1") {
                                            write-host FIFO errors: $fifo -ForegroundColor Red
                                            echo "FIFO errors: $fifo" | Out-File -FilePath $logpath -Append
                                            }
                        If ($resource -ge "1") {
                                                write-host Resource errors: $resource -ForegroundColor Red
                                                echo "Resource errors: $resource" | Out-File -FilePath $logpath -Append
                                                }

                        If (($policeri -match "m") -or ($policeri -match "g") -and ($policero -match "m") -or ($policero -match "g")) {
                        Write-Host "Policer Rx/Tx: $policeri/$policero" -ForegroundColor Green
                        echo "Policer Rx/Tx: $policeri/$policero" | Out-File -FilePath $logpath -Append
                                                                                                                                       } # end of if policeri match m or g and policero match m or g
                                                                                                                                       Else { 
                                                                                                                                               If (($policeri -match "m") -or ($policeri -match "g")) {
                                                                                                                                               Write-Host "Policer Rx: $policeri" -ForegroundColor Green
                                                                                                                                               echo "Policer Rx: $policeri" | Out-File -FilePath $logpath -Append
                                                                                                                                                    } # end of if policeri match m or g
                                                                                                                                                    Else {
                                                                                                                                                          If (($policero -match "m") -or ($policero -match "g")) {
                                                                                                                                                          Write-Host "Policer Tx: $policero" -ForegroundColor Green
                                                                                                                                                          echo "Policer Tx: $policero" | Out-File -FilePath $logpath -Append
                                                                                                                                                          } # end of if policero match m or g
                                                                                                                                        } # end of else if policeri match m or g
                                                                                                                                        } # end of else if policeri match m or g and policero match m or g


                        "`n"
                        echo " " | Out-File -FilePath $logpath -Append

                        If ($circuittype -match "Internet") {
                            If ($BGPas) {
                            Write-Host "BGP Neighbor: $BGPneighbor" -ForegroundColor Green
                            echo "BGP Neighbor: $BGPneighbor" | Out-File -FilePath $logpath -Append
                            Write-Host "BGP AS: $BGPas" -ForegroundColor Green
                            echo "BGP AS: $BGPas" | Out-File -FilePath $logpath -Append
                            }
                            If ($BGProutes) {
                            Write-Host "BGP Routes: $BGProutes" -ForegroundColor Green
                            echo "BGP Routes: $BGProutes" | Out-File -FilePath $logpath -Append 
                            "`n"
                            echo " " | Out-File -FilePath $logpath -Append
                            } Else {
                            "`n"
                            echo " " | Out-File -FilePath $logpath -Append
                            } 
                        }

                        If ($CPE) {
                        $CPE | select "CPE_IP","host","vendor" -Unique | Out-Host
                        $CPE | select "CPE_IP","host","vendor" -Unique | Out-File -FilePath $logpath -Append
                        }

                        If (($circuittype -match "Internet") -or ($circuittype -match "PRI") -or ($circuittype -match "SIP") -or ($circuittype -match "VPLS") -or ($model -match "ex")){
                                                                                                                                                                                   If (($cetype -match "PRI") -or ($cetype -match "SIP")) {
                                                                                                                                                                                                                                           $CE | select "$cetype","host","vendor" -Unique | Out-Host
                                                                                                                                                                                                                                           $CE | select "$cetype","host","vendor" -Unique | Out-File -FilePath $logpath -Append
                                                                                                                                                                                                                                           }
                                                                                                                                                                                                                                           Else {
                                                                                                                                                                                                                                                 $CE | select "$cetype","vendor" -Unique | Out-Host
                                                                                                                                                                                                                                                 $CE | select "$cetype","vendor" -Unique | Out-File -FilePath $logpath -Append
                                                                                                                                                                                                                                                 }
                                                                                                                                                                                                                                               
                                                                                                                                                                                   Remove-Variable cetype -Force -ErrorAction SilentlyContinue
                                                                                                                                                                                   }

                        Write-Host "`n" -ForegroundColor Black
                        echo " " | Out-File -FilePath $logpath -Append

                        If (($description) -and ($interface)) {
                                           Write-Host "end of Ticket Paster for $fqdn > $interface > $description" -ForegroundColor DarkCyan
                                           }
                                           Else {
                                           Write-Host "end of Ticket Paster for $fqdn > $parent > $parentdescription" -ForegroundColor DarkCyan
                                           }
                    Write-Host "`n" -ForegroundColor Black
                    Write-Host "ouput has been saved to $logpath" -ForegroundColor DarkCyan
                    Write-Host "`n" -ForegroundColor Black
                    Remove-Variable logpath -Force -ErrorAction SilentlyContinue

    } # end of Out-Console_Log

    # to search Rancid archived configration files for Juniper host names and interfaces
    Function Search {
                     Input-Box -text "Enter: search locally stored RANCID backups for interface descriptions"
                     clv text -Force -ErrorAction SilentlyContinue
                     If ($search) {
                                   Write-Host "Searching for: $search" -ForegroundColor DarkCyan
                                   Write-Host "`n" -ForegroundColor Black
                                   If (($search -notmatch ".twcc") -and ("$search" -As [IPAddress] -As [Bool])) {
                                                                                If (Test-Connection $search -ErrorAction SilentlyContinue) {
                                                                                                                                            Write-Host "Host IP address $search responds to ping" -ForegroundColor Green
                                                                                                                                            If (TestPort -IPAddress $search -Protocol TCP -Port 22 -ErrorAction SilentlyContinue) {
                                                                                                                                                                                                                                   Write-Host "Host IP address $search has port 22 open (SSH)" -ForegroundColor Green
                                                                                                                                                                                                                                   }
                                                                                                                                            If (TestPort -IPAddress $search -Protocol TCP -Port 23 -ErrorAction SilentlyContinue) {
                                                                                                                                                                                                                                   Write-Host "Host IP address $search has port 23 open (Telnet)" -ForegroundColor Green
                                                                                                                                            If (TestPort -IPAddress $search -Protocol TCP -Port 443 -ErrorAction SilentlyContinue) {
                                                                                                                                                                                                                                    Write-Host "Host IP address $search has port 443 open (HTTPS)" -ForegroundColor Green
                                                                                                                                                                                                                                    }
                                                                                                                                            Write-Host "`n" -ForegroundColor Black
                                                                                                                                            }
                                                                                                                                            
                                                                                 $octets = $search -split '\.'
                                                                                 [ipaddress]$device = $octets.Get(0) + '.' + $octets.Get(1) + '.' + $octets.Get(2) + '.' +  ($octets.Get(3)- 1)
                                                                                 Remove-Variable $octets -Force -ErrorAction SilentlyContinue
                                                                                 Add-Session -device $device
                                                                                 If ((Get-SSHSession | Where-Object -Property Host -EQ "$device").Connected) {
                                                                                                                                                             $int = (Invoke-SSHCommand -index $session -Command "show route $device | match ""Local via"" | trim 32").Output.Trim()
                                                                                                                                                             $desc = ((Invoke-SSHCommand -index $session -Command "show configuration interfaces $int | match description | trim 12").Output | % {$_ -replace ';', ""}).Trim()
                                                                                                                                                             $prop = @{}
                                                                                                                                                             $prop.router = $device
                                                                                                                                                             $prop.interface = $int
                                                                                                                                                             $prop.description = $desc
                                                                                                                                                             New-Object PSObject -property $prop | Sort-Object -Unique
                                                                                                                                                             }
                                                                                                                                                             Else {
                                                                                                                                                                   Write-Host "Unable to find Edge router by IP $device" -ForegroundColor Red
                                                                                                                                                                   Write-Host "`n" -ForegroundColor Black
                                                                                                                                                                   clv device -Force -ErrorAction SilentlyContinue
                                                                                                                                                                   clv octets -Force -ErrorAction SilentlyContinue
                                                                                                                                                                   clv search -Force -ErrorAction SilentlyContinue
                                                                                                                                                                   Pause
                                                                                                                                                                   continue
                                                                                                                                                                   }        
                                                                                                                                                                                                                                                                                                                                                                                                                                                      
                                                                                                                                           
                                                                                      
                                                                                      } # end if search is an IP address
                                                                                      }
                                                                                      Else {
                                                                                            Try {
                                                                                                 $routers = (Get-Item "$path2script\configs\*" -ErrorAction SilentlyContinue | where {(select-string -path $_.FullName -pattern "$search")}).Name.Trim().Split("",[System.StringSplitOptions]::RemoveEmptyEntries)
                                                                                                 }
                                                                                                 Catch {
                                                                                                        # Catch? There is no catch!
                                                                                                        }
                                                                                            Foreach ($router in $routers) {
                                                                                                                           Try {
                                                                                                                                $descriptions = (Select-String -Path "$path2script\configs\$router" -Pattern "$search" | Select-String -pattern "#" | Select-String -pattern "Description" -NotMatch).Line.TrimStart() | Out-String | % {$_ -replace '#', ""} | % {$_ -replace '  up    up  ', ""} | % {$_ -replace '  up    down', ""} | % {$_ -replace 'down    up  ', "" | % {$_ -replace 'down  down',""}} | ToArray 
                                                                                                                                Foreach ($desc in $descriptions) {
                                                                                                                                                                  $ints = $desc.Split() | where {(($_ -match "ge-") -or ($_ -match "xe-") -or ($_ -match "gi0") -or ($_ -match "fa0") -or ($_ -match "ae"))}
    
                                                                                                                                Foreach ($int in $ints) {
                                                                                                                                                         If ($desc) {
                                                                                                                                                                     $desc = $desc.TrimStart() | % {$_ -replace "$int", ""}  
                                                                                                                                                                     }

                                                                                                                                If (($int -match "ge-") -or ($int -match "xe-") -or ($int -match "gi0") -or ($int -match "fa0") -or ($int -match "ae")) { 
                                                                                                                                                                                                                                                         $prop = @{
                                                                                                                                                                                                                                                         'router'=$router
                                                                                                                                                                                                                                                         }
                                                                                                                                                                                                                                                         $obj = New-Object -TypeName PSObject -Property $prop
                                                                                                                                                                                                                                                         $obj | Add-Member -type NoteProperty -name interface -value $int -Force
                                                                                                                                                                                                                                                         If ($desc) {
                                                                                                                                                                                                                                                                     $obj | Add-Member -type NoteProperty -name description -value $desc.TrimStart() -Force
                                                                                                                                                                                                                                                                     }
                                                                                                                                                                                                                                                         $obj | Sort-Object -Unique
                                                                                                                                                                                                                                                         clv prop -Force -ErrorAction SilentlyContinue
                                                                                                                                                                                                                                                         clv int -Force -ErrorAction SilentlyContinue
                                                                                                                                                                                                                                                         clv desc -Force -ErrorAction SilentlyContinue
                                                                                                                                                                                                                                                         }
                                                                                                                                                                                         }
        
                                                                                                                                                                   }
                                                                                                             }
                                                                                                             Catch {
                                                                                                                    # catch? there is no catch!
                                                                                                                    }     
                                  
                                                    

                                                                                                                       clv router -Force -ErrorAction SilentlyContinue
                                                                                                                       clv descriptions -Force -ErrorAction SilentlyContinue
                                                                                                                       }
    
                                                                                         clv routers -Force -ErrorAction SilentlyContinue
                                                }
                                              
                         } # end of if search
                         } # end of search function

# Scriptblocks

    # Juniper CPE interface find and command execution
    $Juniper_CPE_SB = {
             If ($CPE) {
                        $customerpremiseequipment = $CPE | select "CPE_IP","host","vendor" -Unique
                        Remove-Variable CPE -Force -ErrorAction SilentlyContinue
                        Foreach ($eachCPE in $customerpremiseequipment) {
                                                    If ($eachCPE.vendor -match "juniper") {
                                                                                           If ($lastCPE -notmatch $eachCPE.host) {
                                                                                                                                  If ($vlan) {
                                                                                                                                              Add-Session -device $eachCPE.CPE_IP
                                                                                                                                              Get-Juniper-CPE-INT
                                                                                                                                              If (($results | Where-Object -Property router -EQ $eachCPE.host).router) {
                                                                                                                                                                                                                        $cpehost += $eachCPE.host
                                                                                                                                                                                                                        }
                                                                                                                                              }
                                                                                                                                              Else {
                                                                                                                                                    break
                                                                                                                                                    }
                                                                                                                                  If ($interfaces.Count -ge "2") {
                                                                                                                                                                  Foreach ($interface in $interfaces | where {(($_ -match "ge-") -or ($_ -match "xe-") -or ($_ -match "gi0") -or ($_ -match "fa0") -or ($_ -match "ae"))}) {
                                                                                                                                                                                                                                                                                                                            If ($interface -match $uplink) { 
                                                                                                                                                                                                                                                                                                                                                            Write-Host "Found management on interface $interface on CPE"$eachCPE.CPE_IP""
                                                                                                                                                                                                                                                                                                                                                            }
                                                                                                                                                                                                                                                                                                                                                            Else {
                                                                                                                                                                                                                                                                                                                                                                  Write-Host "Found hand-off interface $interface on CPE"$eachCPE.CPE_IP""
                                                                                                                                                                                                                                                                                                                                                                  }
                                                                                                                                                                                                                                                                                                                            Juniper-Get-INT -interface $interface
                                                                                                                                                                                                                                                                                                                            Foreach ($item in $items) {
                                                                                                                                                                                                                                                                                                                                                       If ($action -match "$item") {          
                                                                                                                                                                                                                                                                                                                                                                                    Juniper-Commands -Command $action
                                                                                                                                                                                                                                                                                                                                                                                    }
                                                                                                                                                                                                                                                                                                                                                       }
                                                                                                                                                                                                                                                                                                                            clv interface -Force -ErrorAction SilentlyContinue
                                                                                                                                                                                                                                                                                                                            # clearing lots of variables
                                                                                                                                                                                                                                                                                                                            Foreach ($clearable in $clearables) {
                                                                                                                                                                                                                                                                                                                                                                 If (($clearable -match "area") -or ($clearable -match "rancidhost") -or ($clearable -match "items") -or ($clearable -match "results") -or ($clearable -match "action") -or ($clearable -match "fqdn") -or ($clearable -match "date") -or ($clearable -match "logpath") -or ($clearable -match "business") -or ($clearable -match "CID") -or ($clearable -match "MGMTints") -or ($clearable -match "vlan") -or ($clearable -match "parent")) { }
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           Else {
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 Remove-Variable $clearable -Force -ErrorAction SilentlyContinue
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 }
                                                                                                                                                                                                                                                                                                                                                                 } # end of clearing lots of variables


                                                                                                                                                                                                                                                                                                                            } # end of for each interface in interfaces
                                                                                                                                                                  Remove-Variable vlan -Force -ErrorAction SilentlyContinue
                                                                                                                                                                  Remove-Variable interfaces -Force -ErrorAction SilentlyContinue
                                                                                                                                                                  } # end of if interfaces count equal to or greater than 2
                                                                                                                                                                  Else {
                                                                                                                                                                        If (($interfaces -match $Null) -or ($interfaces.Count -eq "0")) {break}
                                                                                                                                                                                                                                              Else {
                                                                                                                                                                                                                                                    Write-Host "Found Interface $interfaces on CPE"$eachCPE.CPE_IP""
                                                                                                                                                                                                                                                    Juniper-Get-INT -interface $interfaces
                                                                                                                                                                                                                                                    Foreach ($item in $items) {
                                                                                                                                                                                                                                                                               If ($action -match "$item") {          
                                                                                                                                                                                                                                                                                                            Juniper-Commands -Command $action
                                                                                                                                                                                                                                                                                                            }
                                                                                                                                                                                                                                                                               }
                                                                                                                                                                                                                                                    Remove-Variable vlan -Force -ErrorAction SilentlyContinue
                                                                                                                                                                                                                                                    Remove-Variable interfaces -Force -ErrorAction SilentlyContinue
                                                                                                                                                                                                                                                    }
                                                                                                                                                                        } # end of else if interfaces count greater than or equal to 2

                                                                                           } # end of if lastsession not match eachCPE host
                                                                                           Remove-Variable lastCPE -Force -ErrorAction SilentlyContinue
                                                                                           Remove-Variable customerpremiseequipment -Force -ErrorAction SilentlyContinue
                        # clearing lots of variables
                        Foreach ($clearable in $clearables) {
                                                             If (($clearable -match "area") -or ($clearable -match "rancidhost") -or ("search" -match $clearable) -or ("results" -match $clearable) -or ("action" -match $clearable) -or ("MGMTints" -match $clearable) -or ("vlan" -match $clearable) -or ("parent" -match $clearable)) { }
                                                                                                                                                                                                                                                                       Else {
                                                                                                                                                                                                                                                                             Remove-Variable $clearable -Force -ErrorAction SilentlyContinue
                                                                                                                                                                                                                                                                             }
                                                              } # end of clearing lots of variables

                                                             Try {
                                                                  If ((Get-SSHSession | Where-Object -Property Host -EQ "localhost").Connected) {
                                                                                                                                                 Remove-Sessions
                                                                                                                                                 rancidhost-Tunnel
                                                                                                                                                 }
                                                                                                                                                  Else {
                                                                                                                                                        Remove-SSHSession -SessionId $session -ErrorAction SilentlyContinue | Out-Null 
                                                                                                                                                        }
                                                                                                                                                  }
                                                                                                                                                  Catch {
                                                                                                                                                         # catch? there is no catch!
                                                                                                                                                         }
                                                                                                                     Try {
                                                                                                                          If ((Get-SSHSession | Where-Object -Property Host -EQ "localhost").Connected) {
                                                                                                                                                                                                         Remove-Sessions
                                                                                                                                                                                                         rancidhost-Tunnel
                                                                                                                                                                                                         }
                                                                                                                                                                                                         Else {
                                                                                                                                                                                                               Remove-SSHSession -SessionId $session -ErrorAction SilentlyContinue | Out-Null 
                                                                                                                                                                                                               }
                                                                                                                          }
                                                                                                                          Catch {
                                                                                                                                 # catch? there is no catch!
                                                                                                                                 }
                                                                                                                     } # end of if eachCPE match Juniper
                                                              
                                              
                     
                                                     clv eachCPE -Force -ErrorAction SilentlyContinue
                                                     } # end for eachCPE in CPE
                                                     Remove-Variable lastCPE -Force -ErrorAction SilentlyContinue
                                                     Remove-Variable customerpremiseequipment -Force -ErrorAction SilentlyContinue
            
                                    }
               }

# greetings ladies and gentlemen (AYBABTU!)
                          $greetz = {
                                    cls
                                    Write-Host "Brad Lape presents to you..... drum roll please:" -ForegroundColor DarkCyan
                                    Write-Host "`n" -ForegroundColor Black
                                    Write-Centered "A RANCID inspired creation for use with a Juniper based network!" -Color DarkCyan
                                    Write-Host "`n" -ForegroundColor Black
                                    Write-Centered "################################################" -Color Green
                                    Write-Centered "################################################" -Color Green
                                    Write-Centered "############## __ ## __ ## .  . ################" -Color Green
                                    Write-Centered "##############  / ## |_ ## |\ | ################" -Color Green
                                    Write-Centered "############## /_ ## |_ ## | \| ################" -Color Green
                                    Write-Centered "##############    ##    ##      ################" -Color Green
                                    Write-Centered "################################################" -Color Green
                                    Write-Centered "##################################¡TWO POINT OH!" -Color Green
                                    Write-Host "`n" -ForegroundColor Black
                                    Write-Centered '"Zero Effort Networking"' -Color DarkCyan 
                                    Write-Host "`n" -ForegroundColor Black
                                        
                                        # Getting week of the year
                                        Week-of-Year

                                    Write-Host "`n" -ForegroundColor Black
                                        
                                        rancidhost-Tunnel
                                    
                                    Write-Host "`n" -ForegroundColor Black
                                    }
    # end of scriptblocks

    # Starting the ZEN application!
Do {
    # Greetings
    Invoke-Command -ScriptBlock $greetz
       
    If (Test-Path "$path2script\configs") { 
                                                 $mwconfigs = ((gci -Path "$path2script\configs\." *.*) | where { ! $_.PSIsContainer }).Name
                                                 If ($mwconfigs.Count -gt 0) {Foreach ($mwconfig in $mwconfigs) {Move-Item -Path "$path2script\configs\$mwconfig" -Destination "$path2script\configs\MW" -Force -ErrorAction SilentlyContinue}}    
                                                 clv mwconfigs -Force -ErrorAction SilentlyContinue
                                                 } 
                                                 Else {
                                                       New-Item -Path "$path2script\configs" -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
                                                       $mwconfigs = ((gci -Path "$path2script\configs\." *.*) | where { ! $_.PSIsContainer }).Name
                                                       If ($mwconfigs.Count -gt 0) {Foreach ($mwconfig in $mwconfigs) {Move-Item -Path "$path2script\configs\$mwconfig" -Destination "$path2script\configs\MW" -Force -ErrorAction SilentlyContinue}}    
                                                       clv mwconfigs -Force -ErrorAction SilentlyContinue
                                                       ZEN-Update
                                                       Rancid-Nightlies
                                                       Start-Sleep -Seconds 5
                                                       cls
                                                       Invoke-Command -ScriptBlock $greetz
                                                       continue
                                                       } 
    Menu -addmenuitems $menuitems
    $topmenu = $action
    Remove-Variable action -Force -ErrorAction SilentlyContinue

    Switch ($topmenu) {
                       "Download router configs locally" {
                                                         Rancid-Nightlies
                                                         Start-Sleep -Seconds 5
                                                         cls
                                                         Invoke-Command -ScriptBlock $greetz
                                                         continue
                                                         }

                      "Search offline config files" {
                                                     $results = Search 
                                                     # | ? {$_}  
                                                     If ($results -ne $Null) {
                                                                              $results | select "router", "interface", "description" | Out-Host
                                                                              Do {
                                                                                  $items='all','terse','config','extensive','arp','light','logs'
                                                                                  Foreach ($item in $items) {
                                                                                                             If (($action -match $item) -or ($action -match "ticket")) {
                                                                                                                                                                        clv action -Force -ErrorAction SilentlyContinue
                                                                                                                                                                        }
                                                                                                                                                            
                                                                                                             }
                                                                                    
                                                                                  Menu -addmenuitems 'ticket paster','all','terse','config','extensive','arp','light','logs' -menutitle 'ZEN interface commands'
                                                                                  
                                                                                  If ($action) {                                                                                
                                                                                  Foreach ($result in $results) {
                                                                                                                 If (($result.router -ne $Null) -or ($result.interface -ne $Null) -or ($result.interface -match ':')) {

                                                                                  # clearing lots of variables
                                                                                  Foreach ($clearable in $clearables) {
                                                                                                                       If (($clearable -match "search") -or ($clearable -match "results") -or ($clearable -match "date") -or ($clearable -match "logpath") -or ($clearable -match "cpehost")) { }
                                                                                                                                                                                                                                                                                                Else {
                                                                                                                                                                                                                                                                                                      clv $clearable -Force -ErrorAction SilentlyContinue
                                                                                                                                                                                                                                                                                                      }
                                                                                                                       } # end of clearing lots of variables

                                                                                  If (($result | Where-Object -Property router -EQ $cpehost).router) {
                                                                                                                                                      write-host "`n" -ForegroundColor Black
                                                                                                                                                      write-host "$cpehost has already returned Ticket Paster results"
                                                                                                                                                      write-host "`n" -ForegroundColor Black
                                                                                                                                                      continue
                                                                                                                                                      }
                                                                                  
                                                                                  # remove local proxied connection or current session if new result does not match past result
                                                                                  Try {
                                                                                       If ($smrthstses) {
                                                                                                         If ($lastsession -notmatch $result.router) {
                                                                                                                                                     Remove-SSHSession -SessionId $session -ErrorAction SilentlyContinue | Out-Null
                                                                                                                                                     rancidhost-Tunnel -suppress
                                                                                                                                                     }
                                                                                                         }
                                                                                                         Else {
                                                                                                               If (($lastsession -notmatch $result.router) -and ((Get-SSHSession | Where-Object -Property Host -EQ "localhost").Connected)){
                                                                                                                                                                                                                                            Remove-Sessions
                                                                                                                                                                                                                                            rancidhost-Tunnel -suppress
                                                                                                                                                                                                                                            }
                                                                                                               }
                                                                                        }
                                                                                        Catch {
                                                                                               # Catch? There is no catch!
                                                                                               }                                                      
                                                                                  
                                                                                  # add new session if not already connected  
                                                                                  Try { 
                                                                                       If (((Get-SSHSession | Where-Object -Property Host -match $result.router).Connected) -or (Get-SSHSession | Where-Object -Property Host -EQ "localhost").Connected -and ($lastsession -match $result.router))  {$fqdn = $result.router}
                                                                                                                                                                                                                                                                                                                            Else {
                                                                                                                                                                                                                                                                                                                                  Add-Session -device $result.router
                                                                                                                                                                                                                                                                                                                                  }
                                                                                      }
                                                                                      Catch {
                                                                                             Add-Session -device $result.router
                                                                                             }

                                                                                  If (((Get-SSHSession | Where-Object -Property Host -match $result.router).Connected) -or (Get-SSHSession | Where-Object -Property Host -EQ "localhost").Connected) {
                                                                                                                                                                                                                                                      $lastsession = $result.router
                                                                                                                                                                                                                                                      }

                                                                                  Juniper-Get-INT -interface $result.interface
                                                                                  Juniper-Commands -Command $action                                                            
                                                                                                      
                                                                                  # clearing lots of variables
                                                                                  Foreach ($clearable in $clearables) {
                                                                                                                       If (($clearable -match "results") -or ($clearable -match "date") -or ($clearable -match "logpath") -or ($clearable -match "business") -or ($clearable -match "CID") -or ($clearable -match "MGMTints") -or ($clearable -match "CPE") -or ($clearable -match "vlan") -or ($clearable -match "parent")) { }
                                                                                                                                                                                                                                                                                                                                                                                                                               Else {
                                                                                                                                                                                                                                                                                                                                                                                                                                     clv $clearable -Force -ErrorAction SilentlyContinue
                                                                                                                                                                                                                                                                                                                                                                                                                                     }
                                                                                                                       } # end of clearing lots of variables

                                                                                  Invoke-Command -ScriptBlock $Juniper_CPE_SB
                                                                                  Remove-Variable CPE -Force -ErrorAction SilentlyContinue
                                                                                                                                                            } # end of if result is not null
                                                                                                                   } # end of for each result in results

                                                                                  # Removing lots of variables
                                                                                  Foreach ($clearable in $clearables) {
                                                                                                                       If (($clearable -match "results") -or ($clearable -match "date") -or ($clearable -match "logpath")) { }
                                                                                                                                                                                                                             Else {
                                                                                                                                                                                                                                   Remove-Variable $clearable -Force -ErrorAction SilentlyContinue
                                                                                                                                                                                                                                   }
                                                                                                                       } # end of clearing lots of variables
                                                                                  }                                                   
                                                                                  } # end of do while action
                                                                                  While ($action -match '.+')

                                                                                  # remove local proxied connection or current session if new result does not match past result
                                                                                  If ((Get-SSHSession -SessionId $session | Where-Object -Property Host -EQ "localhost").Connected) {
                                                                                                                                                                                     Remove-Sessions
                                                                                                                                                                                     }
                                                                                                                                                                                     Else {
                                                                                                                                                                                           If ($session) {
                                                                                                                                                                                                          Remove-SSHSession -SessionId $session -ErrorAction SilentlyContinue | Out-Null
                                                                                                                                                                                                          }
                                                                                                                                                                                           }
                                                                                                                                                                    
                                                                                  # Removing lots of variables
                                                                                  Foreach ($clearable in $clearables) {
                                                                                                                       Remove-Variable $clearable -Force -ErrorAction SilentlyContinue
                                                                                                                       } # end of clearing lots of variables
                                                                                  
                                                                                  continue
                                                                 
                                                                 
                                                   }
                                                   Else {
                                                         write-host "No results found" -ForegroundColor Red
                                                         write-host "Please download newer router configs for better results" -ForegroundColor Green
                                                         Write-Host "`n" -ForegroundColor Black
                                                         Remove-Variable results -Force -ErrorAction SilentlyContinue
                                                         Start-Sleep 5
                                                         continue
                                                         }
                                                     }

                      default {
                               continue
                               }
                                
    

   
   
   }
   
   }
   # restart loop
   While ($topmenu -match '.+')

# terminate all sessions
Remove-Sessions

# Removing lots of variables
Foreach ($clearable in $clearables) {
                                     Remove-Variable $clearable -Force -ErrorAction SilentlyContinue
                                     } # end of clearing lots of variables

# clear remaining variables
Remove-Variable regdom -Force -ErrorAction SilentlyContinue
Remove-Variable area -Force -ErrorAction SilentlyContinue
Remove-Variable currentone -Force -ErrorAction SilentlyContinue
Remove-Variable rancidhost -Force -ErrorAction SilentlyContinue
Remove-Variable routersls -Force -ErrorAction SilentlyContinue
Remove-Variable rempathscp -Force -ErrorAction SilentlyContinue
Remove-Variable message -Force -ErrorAction SilentlyContinue
Remove-Variable color -Force -ErrorAction SilentlyContinue
Remove-Variable offsetvalue -Force -ErrorAction SilentlyContinue
Remove-Variable output -Force -ErrorAction SilentlyContinue
Remove-Variable area -Force -ErrorAction SilentlyContinue
Remove-Variable currentone -Force -ErrorAction SilentlyContinue
Remove-Variable rancidhost -Force -ErrorAction SilentlyContinue
Remove-Variable smrthstses -Force -ErrorAction SilentlyContinue
Remove-Variable routersls -Force -ErrorAction SilentlyContinue
Remove-Variable routers -Force -ErrorAction SilentlyContinue
Remove-Variable tech -Force -ErrorAction SilentlyContinue
Remove-Variable EID -Force -ErrorAction SilentlyContinue
Remove-Variable corporate -Force -ErrorAction SilentlyContinue
Remove-Variable topmenu -Force -ErrorAction SilentlyContinue
Remove-Variable action -Force -ErrorAction SilentlyContinue
Remove-Variable clearables -Force -ErrorAction SilentlyContinue