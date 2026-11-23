# go-tls-proxy

按 IP 申请 Let's Encrypt 短期证书，并把 HTTPS / TLS 连接反向代理到本机或 Docker 容器。

模块路径：`github.com/billcoding/go-tls-proxy`

## 构建

```bash
go build -o go-tls-proxy ./cmd/go-tls-proxy
```

## 配置

示例在 `config/config.example.yml`。复制后填写本机后端：

```bash
cp config/config.example.yml config/go-tls-proxy.yml
```

`config/go-tls-proxy.yml` 是本机配置，已在 `.gitignore` 里，不要上传。

未指定 `-config` 时，按下面顺序使用第一个存在的文件：

1. `config/go-tls-proxy.yml`
2. `go-tls-proxy.yml`

都没有时，仍尝试打开 `config/go-tls-proxy.yml` 并报错。

环境变量：

| 作用 | 名字 |
| --- | --- |
| 指定证书 IP | `GO_TLS_PROXY_PUBLIC_IP` |
| 指定 ACME 目录 | `GO_TLS_PROXY_ACME_DIRECTORY` |

## 部署

```bash
./deploy.sh --arch amd64 user@host
```

不带 `--update-config` 时不覆盖远端已有配置。

- 安装目录是 `/data/opt/go-tls-proxy`，配置文件是 `go-tls-proxy.yml`，systemd 单元是 `go-tls-proxy`，运行用户是 `go-tls-proxy`。
- 证书目录由配置里的 `storage_dir` 决定。本机示例是 `/data/go-tls-proxy`。
- 防火墙规则注释是 `go-tls-proxy`。程序只删除带这个注释的临时放行。iptables 和 nft 由进程直接修改。firewalld 和 ufw 需要 root 时，通过 sudo 执行本程序的 `fw80 open` / `fw80 close`，不再安装单独的脚本。

## 目录

- `cmd/go-tls-proxy`：程序入口
- `config/config.example.yml`：配置示例
- `deploy/`：systemd 单元、环境变量示例
- `internal/cert`、`internal/config`、`internal/proxy`、`internal/docker`：包名与目录一致

仓库里没有需要单独收集的静态资源、模板或示例证书。证书和账户密钥在运行时写到配置里的 `storage_dir`，不要放进仓库。
