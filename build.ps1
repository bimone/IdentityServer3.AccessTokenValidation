Param(
    [string]$buildNumber = "0",
    [string]$preRelease = $null
)

gci .\source -Recurse "packages.config" |% {
    "Restoring " + $_.FullName
    nuget.exe install $_.FullName -o .\source\packages
}

Import-Module .\source\packages\psake.4.9.0\tools\psake

if(Test-Path Env:\APPVEYOR_BUILD_NUMBER){
    $buildNumber = [int]$Env:APPVEYOR_BUILD_NUMBER
    Write-Host "Using APPVEYOR_BUILD_NUMBER"

    $task = "appVeyor"
}

"Build number $buildNumber"

Invoke-Psake .\default.ps1 "default" -framework "4.8x64" -properties @{ buildNumber=$buildNumber; preRelease=$preRelease }

Remove-Module psake