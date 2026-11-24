# Сборка VPN Check: Windows 11 x64 (exe и zip) и Linux amd64/arm64 (tar.gz).
# Требуется Go 1.27+ (https://go.dev/dl/). Запуск: .\build.ps1 [-Version 1.0.0] [-SkipTests]
[CmdletBinding()]
param(
    [string]$Version = "",
    [switch]$SkipTests,
    [switch]$Console   # собрать с консольным окном (для отладки), по умолчанию -H windowsgui
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    throw "Go не найден в PATH. Установите Go 1.27+ (winget install GoLang.Go) и откройте новый терминал."
}
$goVersion = (go version)
Write-Host "Go: $goVersion"

if ($Version -eq "") {
    # Версия по умолчанию берётся из internal/app/app.go (правило: большое изменение +1.0, остальные +0.1).
    $m = Select-String -Path (Join-Path $PSScriptRoot "internal\app\app.go") -Pattern 'var Version = "([^"]+)"'
    $Version = if ($m) { $m.Matches[0].Groups[1].Value } else { "1.0" }
}

# Ресурсы Windows (значок, сведения о версии) лежат в cmd\vpncheck\rsrc_windows_amd64.syso и
# подхватываются go build автоматически. Пересоздать после смены значка или версии:
#   go run tools/mkicon/main.go winres/icon.png
#   go run github.com/tc-hib/go-winres@v0.3.3 make --in winres/winres.json --out cmd/vpncheck/rsrc --arch amd64

$dist = Join-Path $PSScriptRoot "dist"
New-Item -ItemType Directory -Force $dist | Out-Null
$exe = Join-Path $dist "VPNCheck.exe"

if (-not $SkipTests) {
    Write-Host "== go vet ./..."
    go vet ./...
    if ($LASTEXITCODE -ne 0) { throw "go vet завершился с ошибкой" }
    Write-Host "== go test ./..."
    go test ./...
    if ($LASTEXITCODE -ne 0) { throw "тесты не прошли" }
}

$ldflags = "-s -w -X vpncheck/internal/app.Version=$Version"
if (-not $Console) { $ldflags += " -H windowsgui" }

Write-Host "== go build ($Version)"
$env:GOOS = "windows"; $env:GOARCH = "amd64"; $env:CGO_ENABLED = "0"
go build -trimpath -ldflags $ldflags -o $exe ./cmd/vpncheck
if ($LASTEXITCODE -ne 0) { throw "сборка не удалась" }

$size = (Get-Item $exe).Length
$hash = (Get-FileHash -Algorithm SHA256 $exe).Hash
Write-Host ("VPNCheck.exe: {0:N2} МБ, SHA-256 {1}" -f ($size / 1MB), $hash)

# Релизный ZIP: exe, README, документация по реестру, контрольная сумма.
$zip = Join-Path $dist "VPNCheck-$Version-windows-amd64.zip"
Remove-Item $zip -ErrorAction SilentlyContinue
$stage = Join-Path $dist "stage"
Remove-Item -Recurse -Force $stage -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $stage | Out-Null
Copy-Item $exe $stage
Copy-Item (Join-Path $PSScriptRoot "README.md") $stage
Copy-Item (Join-Path $PSScriptRoot "README.ru.md") $stage
Copy-Item (Join-Path $PSScriptRoot "LICENSE") $stage
Copy-Item (Join-Path $PSScriptRoot "docs\REGISTRY.md") $stage
"$hash *VPNCheck.exe" | Set-Content -Encoding ascii (Join-Path $stage "VPNCheck.exe.sha256")
Compress-Archive -Path (Join-Path $stage "*") -DestinationPath $zip
Remove-Item -Recurse -Force $stage
Write-Host "ZIP: $zip"

# Linux: amd64 и arm64, статический бинарник без CGO, архив tar.gz с правами 0755 на программу.
foreach ($arch in @("amd64", "arm64")) {
    $linStage = Join-Path $dist "stage-linux-$arch"
    Remove-Item -Recurse -Force $linStage -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force $linStage | Out-Null
    $bin = Join-Path $linStage "vpncheck"
    $env:GOOS = "linux"; $env:GOARCH = $arch; $env:CGO_ENABLED = "0"
    go build -trimpath -ldflags "-s -w -X vpncheck/internal/app.Version=$Version" -o $bin ./cmd/vpncheck
    if ($LASTEXITCODE -ne 0) { throw "сборка для Linux $arch не удалась" }
    $binHash = (Get-FileHash -Algorithm SHA256 $bin).Hash.ToLower()
    "$binHash  vpncheck" | Set-Content -Encoding ascii -NoNewline (Join-Path $linStage "vpncheck.sha256")
    Copy-Item (Join-Path $PSScriptRoot "README.md"), (Join-Path $PSScriptRoot "README.ru.md"), (Join-Path $PSScriptRoot "LICENSE"), (Join-Path $PSScriptRoot "docs\REGISTRY.md") $linStage
    $tgz = Join-Path $dist "VPNCheck-$Version-linux-$arch.tar.gz"
    $env:GOOS = ""; $env:GOARCH = ""
    go run ./tools/tarball -out $tgz -dir "VPNCheck-$Version" -exec vpncheck (Get-ChildItem $linStage | ForEach-Object FullName)
    if ($LASTEXITCODE -ne 0) { throw "архив для Linux $arch не собран" }
    Remove-Item -Recurse -Force $linStage
    Write-Host ("Linux {0}: {1}, SHA-256 программы {2}" -f $arch, $tgz, $binHash)
}
$env:GOOS = ""; $env:GOARCH = ""; $env:CGO_ENABLED = ""
Write-Host "Бинарник не подписан кодовой подписью: SmartScreen может показать предупреждение. Не отключайте защиту Windows; проверьте SHA-256 и нажмите «Подробнее → Выполнить в любом случае» только если сумма совпадает."
