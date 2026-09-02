$ErrorActionPreference = "Stop"

function New-SecureSecret([int]$Bytes = 48) {
    $buffer = New-Object byte[] $Bytes
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($buffer)
    }
    finally {
        $rng.Dispose()
    }
    return [Convert]::ToBase64String($buffer)
}

Write-Host ""
Write-Host "FireRank - secrets locais para configurar NO RAILWAY" -ForegroundColor Cyan
Write-Host "NAO salve estes valores no Git." -ForegroundColor Yellow
Write-Host ""
Write-Host "MEDIA_TOKEN_SECRET=" -NoNewline
Write-Host (New-SecureSecret 48) -ForegroundColor Green
Write-Host ""
Write-Host "INTERNAL_MAINTENANCE_SECRET=" -NoNewline
Write-Host (New-SecureSecret 48) -ForegroundColor Green
Write-Host ""
Write-Host "Copie cada valor diretamente para Railway > Variables." -ForegroundColor Cyan
