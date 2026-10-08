# nsnali — nslookup + nali

## 构建
    go mod download
    go build -o nsnali .

## IP 库（放在可执行文件同目录或当前目录）
    curl -LO https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data/ip2region_v4.xdb
    curl -LO https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data/ip2region_v6.xdb

## 用法
    ./nsnali www.baidu.com                 # A + AAAA，带归属地
    ./nsnali -s 8.8.8.8 -t A,MX,TXT qq.com # 指定服务器和记录类型
    ./nsnali 8.8.8.8                       # 直接查 IP
    dig qq.com | ./nsnali                  # nali 模式
