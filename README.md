# nsnali — nslookup + nali

> 🚀 **v1.1.0 更新：IP 库首次运行自动下载，jsDelivr CDN 加速，支持自建镜像，无需手动准备 xdb。**

## 构建
    go mod download
    go build -o nsnali .

## IP 库（自动下载）
首次运行自动下载到缓存目录：`~/.cache/nsnali`（macOS: `~/Library/Caches/nsnali`，Windows: `%LocalAppData%\nsnali`）。

下载顺序：自建镜像 → jsDelivr（cdn / fastly / gcore / testingcf）→ GitHub raw。
jsDelivr 单文件限 20MB，v6 库约 37MB 会被拒，自动回退 GitHub。

自建镜像（如 Caddy 文件服务器）优先级：`-mirror` 参数 > `NSNALI_MIRROR` 环境变量 > 编译时注入：

    go build -ldflags "-s -w -X main.selfMirror=https://files.example.com/nsnali/" -o nsnali .

也可把 xdb 放在可执行文件同目录或当前目录，优先使用。

## 用法
    ./nsnali www.baidu.com                  # A + AAAA，带归属地
    ./nsnali -s 8.8.8.8 -t A,MX,TXT qq.com  # 指定服务器和记录类型
    ./nsnali 8.8.8.8                        # 直接查 IP
    dig qq.com | ./nsnali                   # nali 模式
    ./nsnali -update                        # 重新下载 IP 库
    ./nsnali -no-v6 qq.com                  # 只用 IPv4 库，免下 37MB

## 更新日志
- v1.1.0：IP 库自动下载（jsDelivr CDN 加速 + GitHub 回退）、自建镜像（-mirror / NSNALI_MIRROR / ldflags）、-update、-no-v6
- v1.0.0：nslookup + nali，支持 A/AAAA/CNAME/MX/NS/TXT、截断转 TCP、nali 管道模式
