# Run comprehensive benchmarks
$mingwBin = "C:\Users\cenar\AppData\Local\Temp\mingw\mingw64\bin"
$env:Path = "$mingwBin;" + [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")

Write-Host "Starting ZKP C-Coloring Benchmark Suite..." -ForegroundColor Cyan
Write-Host "This will test multiple graph sizes, round counts, and blank strategies." -ForegroundColor Yellow
Write-Host "Note: Running in release mode for accurate timing.`n" -ForegroundColor Gray

cargo run --release --bin benchmark

Write-Host "`n✓ Benchmark complete!" -ForegroundColor Green
Write-Host "Review the output above for detailed performance metrics." -ForegroundColor Gray
