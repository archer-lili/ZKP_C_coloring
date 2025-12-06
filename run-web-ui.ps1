# Run the Web UI for development
$mingwBin = "C:\Users\cenar\AppData\Local\Temp\mingw\mingw64\bin"
$env:Path = "$mingwBin;" + [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")

Write-Host "Starting Web UI..." -ForegroundColor Cyan
Write-Host "The UI will be available at: http://127.0.0.1:8787" -ForegroundColor Yellow
Write-Host "Press Ctrl+C to stop the server`n" -ForegroundColor Gray

cargo run --bin zkp_c_coloring -- visualize-web --instance instances/graph10.bin --rounds 10 --port 8787

