#requires -Version 7.4
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$compiled = Join-Path ([System.IO.Path]::GetTempPath()) "apim-lab-$([guid]::NewGuid().ToString('N')).json"
$oldCompiled = $env:APIM_LAB_COMPILED_FILE
Push-Location $root
try {
    & az bicep build --file main.bicep --outfile $compiled
    if ($LASTEXITCODE -ne 0) { throw 'Bicep build/lint failed.' }
    $env:APIM_LAB_COMPILED_FILE = $compiled
    & node --test (Join-Path 'tests' 'template.test.mjs') (Join-Path 'tests' 'validator.test.mjs')
    if ($LASTEXITCODE -ne 0) { throw 'Local lab contracts failed.' }
} finally {
    $env:APIM_LAB_COMPILED_FILE = $oldCompiled
    if (Test-Path -LiteralPath $compiled) { Remove-Item -LiteralPath $compiled }
    Pop-Location
}
