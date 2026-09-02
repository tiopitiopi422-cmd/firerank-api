param(
    [string]$ProjectPath = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
)

$ErrorActionPreference = "Stop"

Write-Host "Validando FireRank backend em: $ProjectPath" -ForegroundColor Cyan

$node = Get-Command node -ErrorAction Stop
$npm = Get-Command npm -ErrorAction Stop

$versionRaw = (& node -p "process.versions.node").Trim()
$major = [int]($versionRaw.Split('.')[0])

Write-Host "Node: $versionRaw"

if ($major -lt 22) {
    throw "Node 22+ necessario para firebase-admin atual."
}

Push-Location $ProjectPath
try {
    if (-not (Test-Path ".\server.js")) { throw "server.js ausente" }
    if (-not (Test-Path ".\package.json")) { throw "package.json ausente" }

    Write-Host "1/4 node --check" -ForegroundColor Cyan
    & node --check .\server.js
    if ($LASTEXITCODE -ne 0) { throw "node --check falhou" }

    Write-Host "2/4 package.json" -ForegroundColor Cyan
    & node -e "JSON.parse(require('fs').readFileSync('package.json','utf8')); console.log('package.json OK')"
    if ($LASTEXITCODE -ne 0) { throw "package.json invalido" }

    Write-Host "3/4 railway.json" -ForegroundColor Cyan
    & node -e "JSON.parse(require('fs').readFileSync('railway.json','utf8')); console.log('railway.json OK')"
    if ($LASTEXITCODE -ne 0) { throw "railway.json invalido" }

    Write-Host "4/4 segredos versionaveis" -ForegroundColor Cyan
    $forbidden = @(
        ".env",
        "service-account.json",
        "firebase-adminsdk.json"
    )
    foreach ($name in $forbidden) {
        if (Test-Path ".\$name") {
            throw "Arquivo sensivel encontrado na raiz: $name"
        }
    }

    Write-Host ""
    Write-Host "VALIDACAO ESTATICA OK." -ForegroundColor Green
    Write-Host "Se dependencias ainda nao foram instaladas, rode: npm install"
}
finally {
    Pop-Location
}
