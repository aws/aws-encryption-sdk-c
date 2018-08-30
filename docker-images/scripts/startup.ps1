Set-MpPreference -DisableRealtimeMonitoring $true
diskpart /s c:\scripts\diskpart.txt
mkdir d:\docker
restart-service *docker*f