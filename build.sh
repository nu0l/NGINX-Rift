# 一键全平台编译脚本
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o Releases/nginx_rift_scanner-windows.exe nginx_rift_scanner.go
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o Releases/nginx_rift_scanner-linux nginx_rift_scanner.go
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -o Releases/nginx_rift_scanner-mac nginx_rift_scanner.go
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -o Releases/nginx_rift_scanner-mac-arm nginx_rift_scanner.go
