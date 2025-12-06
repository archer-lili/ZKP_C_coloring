# Run the Terminal UI
$mingwBin = "C:\Users\cenar\AppData\Local\Temp\mingw\mingw64\bin"
$env:Path = "$mingwBin;" + [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")

Write-Host "Starting Terminal UI..." -ForegroundColor Cyan
Write-Host "Press 'q' or 'Esc' to exit`n" -ForegroundColor Gray

cargo run --bin zkp_c_coloring -- visualize --instance instances/graph10.bin --rounds 10

