# 修复后的 一键全平台编译脚本
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o Releases/zakj_nginx_rift_scanner-windows.exe zakj_nginx_rift_scanner.go
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o Releases/zakj_nginx_rift_scanner-linux zakj_nginx_rift_scanner.go
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -o Releases/zakj_nginx_rift_scanner-mac zakj_nginx_rift_scanner.go
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -o Releases/zakj_nginx_rift_scanner-mac-arm zakj_nginx_rift_scanner.go
