# Build script for zkp_c_coloring
# This script sets up MinGW and builds the project

$mingwBin = "C:\Users\cenar\AppData\Local\Temp\mingw\mingw64\bin"
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
$env:Path = "$mingwBin;$env:Path"

Write-Host "Building zkp_c_coloring project..." -ForegroundColor Cyan
Write-Host "MinGW path: $mingwBin" -ForegroundColor Gray

cargo build

if ($LASTEXITCODE -eq 0) {
    Write-Host "`n=== BUILD SUCCESSFUL! ===" -ForegroundColor Green
    Write-Host "You can now run the project with:" -ForegroundColor Yellow
    Write-Host "  cargo run -- --help" -ForegroundColor White
} else {
    Write-Host "`n=== BUILD FAILED ===" -ForegroundColor Red
    exit 1
}

