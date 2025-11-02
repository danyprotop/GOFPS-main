OPEN PORT SCANNER on Golang

Instruction how to install on linux:

pkg install golang

git clone https://github.com/danyprotop/GOFPS-main/

cd GOFPS-main

go mod init gofps

go get github.com/fatih/color

touch ranges.txt

touch found_ips.txt

put the ip ranges in ranges.txt

go run app.go
