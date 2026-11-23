#!/usr/bin/env bash
# 在本机编译 Linux 二进制，SSH 上传后用 systemd 启动。
# 证书由服务在启动后申请：Let's Encrypt shortlived IP 证书，http-01 只在
# 申请和续期时短暂监听 80。更新会先备份二进制和配置，证书目录不会删除。
#
# 用法:
#   ./deploy.sh root@203.0.113.10
#   ./deploy.sh -p 22 -i ~/.ssh/id_ed25519 root@203.0.113.10
#   ./deploy.sh --update-config root@203.0.113.10
#   ./deploy.sh --dry-run root@203.0.113.10
#   ./deploy.sh issue --dry-run
#   ./deploy.sh issue -c config/go-tls-proxy.yml

set -euo pipefail

root=$(cd "$(dirname "$0")" && pwd)
cd "$root"

pick_default_config() {
	local f
	for f in \
		"$root/config/go-tls-proxy.yml" \
		"$root/go-tls-proxy.yml"
	do
		if [[ -f "$f" ]]; then
			printf '%s\n' "$f"
			return 0
		fi
	done
	printf '%s\n' "$root/config/go-tls-proxy.yml"
}

port=22
identity=""
config_file=$(pick_default_config)
arch=""
update_config=0
no_start=0
dry_run=0
backup_keep=10
target=""

log() { printf '[%s] %s\n' "$(date '+%H:%M:%S')" "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

usage() {
	cat <<'EOF'
用法:
  ./deploy.sh [选项] user@host
  ./deploy.sh issue [选项]

从本机交叉编译，通过 SSH 安装，并用 systemctl 启动 go-tls-proxy。
安装目录是 /data/opt/go-tls-proxy，配置文件是 go-tls-proxy.yml，运行用户是 go-tls-proxy。
证书目录由配置里的 storage_dir 决定，示例是 /data/go-tls-proxy。
服务启动后自动申请或续期 IP 证书。

选项:
  -i FILE          SSH 私钥
  -p PORT          SSH 端口，默认 22
  -c FILE          本地配置，默认 config/go-tls-proxy.yml
  --arch ARCH      远端架构，amd64 或 arm64；默认用 uname -m 判断
  --update-config  覆盖远端已有配置。不带此选项时保留远端配置和证书
  --no-start       安装 unit，但不启动或重启服务
  --backup-keep N  更新前快照保留份数，默认 10
  -n, --dry-run    只打印将要执行的操作，不编译、不连接、不写入
  issue            在本机按配置申请或续期证书，不部署
  -h               显示帮助

证书:
  certificate.email 可留空。空着或仍是 you@example.com 时，会在证书目录生成随机邮箱。
  申请使用 http-01，公网要能访问 80 端口。
  演习不连接证书机构:
    ./deploy.sh issue --dry-run
    /data/opt/go-tls-proxy/go-tls-proxy -config /data/opt/go-tls-proxy/go-tls-proxy.yml -issue -dry-run
  不带 --update-config 时保留远端已有的 go-tls-proxy.yml。
EOF
}

yaml_val() {
	local key=$1 file=$2
	awk -v key="$key" '
		/^[[:space:]]*#/ { next }
		{
			line=$0
			sub(/^[[:space:]]+/, "", line)
			split(line, a, ":")
			k=a[1]
			gsub(/[[:space:]]/, "", k)
			if (k==key) {
				val=line
				sub(/^[^:]+:[[:space:]]*/, "", val)
				gsub(/["'\'']/, "", val)
				sub(/[[:space:]]+#.*$/, "", val)
				gsub(/[[:space:]]+$/, "", val)
				print val
				exit
			}
		}
	' "$file"
}

note_email() {
	local email
	email=$(yaml_val email "$config_file")
	if [[ -n "$email" && "$email" == *@* && "$email" != *@example.com ]]; then
		log "使用配置里的邮箱 $email"
		return 0
	fi
	log "certificate.email 为空或是占位符，申请时会生成随机邮箱并写入证书目录的 account.email"
}

run_issue() {
	if ! command -v go >/dev/null 2>&1; then
		die "本机没有 go，无法申请证书。"
	fi
	local -a args=(-config "$config_file" -issue)
	if [[ "$dry_run" -eq 1 ]]; then
		args+=(-dry-run)
		log "演习申请，不连接证书机构"
	else
		log "按 $config_file 申请或续期 IP 证书"
	fi
	go run ./cmd/go-tls-proxy "${args[@]}"
}

print_plan() {
	log "模式: dry-run（不编译、不连接、不写入）"
	log "配置: $config_file"
	if [[ -n "$arch" ]]; then
		log "将编译 linux/$arch -> $root/dist/go-tls-proxy"
	else
		log "将在连接 $target 后用 uname -m 判断架构，编译到 $root/dist/go-tls-proxy"
	fi
	log "将上传二进制、systemd unit、$config_file 和 go-tls-proxy.env 到 $target:/tmp/go-tls-proxy.upload/"
	log "安装目录: /data/opt/go-tls-proxy，配置 go-tls-proxy.yml，单元名 go-tls-proxy，用户 go-tls-proxy"
	log "证书目录由远端配置的 storage_dir 决定；示例里的相对路径 data 在配置文件所在目录下"
	log "更新前备份到安装目录的 backup/<时间>-<pid>，保留 $backup_keep 份"
	log "已有远端配置默认保留；覆盖配置需要 --update-config"
	if [[ "$no_start" -eq 1 ]]; then
		log "不启动 systemd。之后可在服务器执行安装目录下的 go-tls-proxy -config <远端配置> -issue"
	else
		log "systemctl enable 并重启 go-tls-proxy"
		log "进程内申请 Let's Encrypt IP 证书，限流时会等到 Retry-After"
	fi
	log "将写入 /etc/sudoers.d/go-tls-proxy，只允许服务用户 sudo 执行安装目录里的 go-tls-proxy fw80 open / fw80 close"
	log "http-01 只在申请和续期时监听 80，并临时放行本机防火墙，校验结束（含失败）后删除本次规则"
	log "防火墙规则注释是 go-tls-proxy"
	log "云厂商安全组需要在控制台放行 80，部署脚本不能修改安全组"
}

while [[ $# -gt 0 ]]; do
	case "$1" in
	-i|--identity)
		identity=${2:?缺少私钥路径}
		shift 2
		;;
	-p|--port)
		port=${2:?缺少端口}
		shift 2
		;;
	-c|--config)
		config_file=${2:?缺少配置路径}
		shift 2
		;;
	--arch)
		arch=${2:?缺少架构}
		shift 2
		;;
	--update-config)
		update_config=1
		shift
		;;
	--no-start)
		no_start=1
		shift
		;;
	--backup-keep)
		backup_keep=${2:?缺少保留份数}
		shift 2
		;;
	-n|--dry-run)
		dry_run=1
		shift
		;;
	-h|--help)
		usage
		exit 0
		;;
	--)
		shift
		break
		;;
	-*)
		die "未知选项: $1"
		;;
	*)
		if [[ -n "$target" ]]; then
			die "只能指定一个主机: $1"
		fi
		target=$1
		shift
		;;
	esac
done

if [[ -z "$target" ]]; then
	usage >&2
	exit 1
fi

if [[ ! "$backup_keep" =~ ^[0-9]+$ || "$backup_keep" -lt 1 ]]; then
	die "--backup-keep 必须是正整数"
fi

if [[ -n "$arch" ]]; then
	case "$arch" in
	amd64|arm64) ;;
	*) die "--arch 只能是 amd64 或 arm64，当前是 $arch" ;;
	esac
fi

if [[ ! -f "$config_file" ]]; then
	die "找不到配置文件: $config_file。请先复制 config/config.example.yml 为 config/go-tls-proxy.yml，填好邮箱、IP 和后端。"
fi

note_email

if [[ "$target" == "issue" ]]; then
	run_issue
	exit 0
fi

if [[ "$dry_run" -eq 1 ]]; then
	print_plan
	exit 0
fi

if ! command -v go >/dev/null 2>&1; then
	die "本机没有 go，无法编译。"
fi

ssh_opts=(-p "$port" -o ServerAliveInterval=30 -o ConnectTimeout=15)
scp_opts=(-P "$port" -o ServerAliveInterval=30 -o ConnectTimeout=15)
if [[ -n "$identity" ]]; then
	ssh_opts+=(-i "$identity")
	scp_opts+=(-i "$identity")
fi

try_cmd() {
	local attempt=1
	local max=3
	while true; do
		if "$@"; then
			return 0
		fi
		if [[ "$attempt" -ge "$max" ]]; then
			return 1
		fi
		log "命令失败，2 秒后重试 ($attempt/$max)"
		attempt=$((attempt + 1))
		sleep 2
	done
}

if [[ -z "$arch" ]]; then
	log "检查远端架构"
	machine=""
	if ! machine=$(try_cmd ssh "${ssh_opts[@]}" "$target" 'uname -m'); then
		die "无法连接 $target"
	fi
	case "$machine" in
	x86_64|amd64) arch=amd64 ;;
	aarch64|arm64) arch=arm64 ;;
	*)
		die "无法识别远端架构: $machine。请用 --arch amd64 或 --arch arm64。"
		;;
	esac
fi

mkdir -p "$root/dist"
log "编译 linux/$arch"
CGO_ENABLED=0 GOOS=linux GOARCH="$arch" \
	go build -trimpath -ldflags '-s -w' -o "$root/dist/go-tls-proxy" ./cmd/go-tls-proxy

log "上传到 $target"
try_cmd ssh "${ssh_opts[@]}" "$target" 'rm -rf /tmp/go-tls-proxy.upload && mkdir -p /tmp/go-tls-proxy.upload'
try_cmd scp "${scp_opts[@]}" \
	"$root/dist/go-tls-proxy" \
	"$root/deploy/go-tls-proxy.service" \
	"$root/deploy/go-tls-proxy.env" \
	"$config_file" \
	"$target:/tmp/go-tls-proxy.upload/"

remote_config_name=$(basename "$config_file")

log "安装并用 systemctl 处理服务"
ssh "${ssh_opts[@]}" "$target" "bash -s -- $(printf '%q' "$update_config") $(printf '%q' "$remote_config_name") $(printf '%q' "$no_start") $(printf '%q' "$backup_keep")" <<'EOF'
set -euo pipefail
export PATH="/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"
update_config=$1
uploaded_name=$2
no_start=$3
backup_keep=$4
src=/tmp/go-tls-proxy.upload
prefix=/data/opt/go-tls-proxy

if [[ "$(id -u)" -eq 0 ]]; then
	sudo() { command "$@"; }
elif ! command -v sudo >/dev/null 2>&1 || ! sudo -n true; then
	echo "请使用 root 连接，或给当前用户配置免密 sudo。" >&2
	exit 1
fi

yaml_val() {
	local key=$1 file=$2
	awk -v key="$key" '
		/^[[:space:]]*#/ { next }
		{
			line=$0
			sub(/^[[:space:]]+/, "", line)
			split(line, a, ":")
			k=a[1]
			gsub(/[[:space:]]/, "", k)
			if (k==key) {
				val=line
				sub(/^[^:]+:[[:space:]]*/, "", val)
				gsub(/["'\'']/, "", val)
				sub(/[[:space:]]+#.*$/, "", val)
				gsub(/[[:space:]]+$/, "", val)
				print val
				exit
			}
		}
	' "$file"
}

cfg=$prefix/go-tls-proxy.yml
envfile=$prefix/go-tls-proxy.env
svc_user=go-tls-proxy

if [[ -f /etc/systemd/system/go-tls-proxy.service ]]; then
	sudo systemctl stop go-tls-proxy
fi

sudo mkdir -p /data/opt
if ! id "$svc_user" >/dev/null 2>&1; then
	nologin=$(command -v nologin || true)
	sudo useradd --system --home-dir "$prefix" --no-create-home --shell "${nologin:-/usr/sbin/nologin}" "$svc_user"
	echo "已创建系统用户 $svc_user"
fi

backup_dir() {
	local dir=$1 stamp dest copied f unit path base sorted extra i count
	local -a names=()
	[[ -d "$dir" ]] || return 0
	copied=0
	stamp=$(date '+%Y%m%d-%H%M%S')-$$-$(basename "$dir")
	dest=$dir/backup/$stamp
	sudo mkdir -p "$dest"
	for f in go-tls-proxy go-tls-proxy.yml go-tls-proxy.env; do
		if [[ -e "$dir/$f" ]]; then
			sudo cp -a "$dir/$f" "$dest/"
			copied=1
		fi
	done
	for unit in go-tls-proxy.service; do
		if [[ -f /etc/systemd/system/$unit ]]; then
			sudo cp -a "/etc/systemd/system/$unit" "$dest/"
			copied=1
		fi
	done
	if [[ -d /data/go-tls-proxy ]]; then
		sudo mkdir -p "$dest/storage-go-tls-proxy"
		sudo cp -a /data/go-tls-proxy/. "$dest/storage-go-tls-proxy/"
		copied=1
	fi
	if [[ "$copied" -eq 0 ]]; then
		sudo rm -rf "$dest"
		return 0
	fi
	echo "已备份到 $dest"
	for path in "$dir/backup"/*; do
		[[ -e "$path" ]] || continue
		names+=("$(basename "$path")")
	done
	[[ ${#names[@]} -gt 0 ]] || return 0
	sorted=$(printf '%s\n' "${names[@]}" | sort)
	names=()
	while IFS= read -r base; do
		[[ -n "$base" ]] && names+=("$base")
	done <<<"$sorted"
	count=${#names[@]}
	extra=$((count - backup_keep))
	if [[ "$extra" -le 0 ]]; then
		return 0
	fi
	for ((i=0; i<extra; i++)); do
		sudo rm -rf "$dir/backup/${names[$i]}"
		echo "删除旧备份: $dir/backup/${names[$i]}"
	done
}

backup_dir "$prefix"

if [[ "$update_config" == 1 ]]; then
	sudo install -o root -g "$svc_user" -m 0640 "$src/$uploaded_name" "$cfg"
	echo "已按 --update-config 写入 $cfg"
else
	if [[ -f "$cfg" ]]; then
		echo "保留远端已有配置 $cfg。要覆盖内容请加 --update-config"
	else
		sudo install -o root -g "$svc_user" -m 0640 "$src/$uploaded_name" "$cfg"
		echo "远端没有配置，已写入 $cfg"
	fi
fi

storage=$(yaml_val storage_dir "$cfg")
storage=${storage:-data}
if [[ "$storage" != /* ]]; then
	storage="$(dirname "$cfg")/$storage"
fi
if [[ ! -f "$envfile" ]]; then
	sudo install -o root -g "$svc_user" -m 0640 "$src/go-tls-proxy.env" "$envfile"
	echo "已写入 $envfile（默认全是注释，需要时再填写）"
else
	sudo chown root:"$svc_user" "$envfile"
	sudo chmod 0640 "$envfile"
	echo "保留已有 $envfile"
fi

sudo install -d -o root -g "$svc_user" -m 0750 "$prefix"
sudo install -d -o "$svc_user" -g "$svc_user" -m 0750 "$prefix/data"
sudo install -d -o "$svc_user" -g "$svc_user" -m 0750 "$storage"
sudo chown -R "$svc_user:$svc_user" "$storage"
sudo chown root:"$svc_user" "$cfg"
sudo chmod 0640 "$cfg"
sudo install -m 0755 "$src/go-tls-proxy" "$prefix/go-tls-proxy"
if [[ -e "$prefix/fw80" || -L "$prefix/fw80" ]]; then
	sudo rm -f "$prefix/fw80"
	echo "已删除不再使用的 $prefix/fw80"
fi

echo "证书目录已准备: $storage"

sudo install -m 0644 "$src/go-tls-proxy.service" /etc/systemd/system/go-tls-proxy.service

sudoers_tmp=$(mktemp)
cat > "$sudoers_tmp" <<SUDOERS
# go-tls-proxy 只允许通过 $prefix/go-tls-proxy fw80 临时放行或删除带 go-tls-proxy 注释的 HTTP-01 规则。
# 不能改安全组，也不能执行其他 root 命令。
$svc_user ALL=(root) NOPASSWD: $prefix/go-tls-proxy fw80 open *, $prefix/go-tls-proxy fw80 close *
SUDOERS
if command -v visudo >/dev/null 2>&1; then
	sudo visudo -cf "$sudoers_tmp"
fi
sudo install -m 0440 -o root -g root "$sudoers_tmp" /etc/sudoers.d/go-tls-proxy
rm -f "$sudoers_tmp"
echo "已写入 /etc/sudoers.d/go-tls-proxy，只允许 $prefix/go-tls-proxy fw80 open 和 fw80 close"

if sudo awk '!/^[[:space:]]*#/ && index($0, "docker://") { found=1 } END { exit !found }' "$cfg"; then
	if getent group docker >/dev/null 2>&1; then
		sudo usermod -aG docker "$svc_user"
		echo "配置使用容器名，已将用户 $svc_user 加入 docker 组"
	else
		echo "配置包含 docker://，但系统没有 docker 组。服务仍会启动；安装 Docker 后执行: usermod -aG docker $svc_user" >&2
	fi
fi

for d in /var/www/go-tls-proxy/.well-known/acme-challenge; do
	if [[ -d "$d" ]]; then
		sudo chmod 1777 "$d" || echo "无法放开 $d 的写权限" >&2
		echo "http-01 可写入已有目录 $d"
	fi
done

challenge=$(yaml_val challenge "$cfg")
http_port=$(yaml_val http_port "$cfg")
http_port=${http_port:-80}
if [[ -z "$challenge" || "$challenge" == "http-01" ]]; then
	echo "部署不长期放行 ${http_port}/tcp。申请和续期时进程临时放行，校验结束（成功、失败或中断后的下次启动）会删除本次规则。"
	echo "iptables/nft 使用 CAP_NET_ADMIN。firewalld/ufw 经 sudo 执行 $prefix/go-tls-proxy fw80，sudoers 没有其他权限。"
	echo "云厂商安全组仍要在控制台放行 ${http_port}/tcp。程序和部署脚本都不能修改安全组。"
else
	echo "当前校验方式是 $challenge。Let's Encrypt 需要从公网访问证书里每个 IP 的 443"
fi

sudo rm -rf "$src"
sudo systemctl daemon-reload
sudo systemctl enable go-tls-proxy
if [[ "$no_start" == 1 ]]; then
	echo "未启动服务。手动申请: $prefix/go-tls-proxy -config $cfg -issue"
	echo "演习: $prefix/go-tls-proxy -config $cfg -issue -dry-run"
else
	sudo systemctl restart go-tls-proxy
	sleep 1
	if ! sudo systemctl is-active --quiet go-tls-proxy; then
		sudo systemctl --no-pager --full status go-tls-proxy || true
		sudo journalctl -u go-tls-proxy -n 80 --no-pager || true
		exit 1
	fi
	sudo systemctl --no-pager --full status go-tls-proxy
fi

echo "证书目录: $storage"
echo "  cert.pem  证书（含证书链）"
echo "  key.pem   私钥"
echo "  account.key    Let's Encrypt 账户密钥，由程序自己生成"
echo "  account.email  账户邮箱。配置为空或是占位符时随机生成，之后续期继续用"
echo "限流时间若存在，记在 $storage/acme-retry-after，到点之前不会重复申请"
echo "当前配置: $cfg"
EOF

if [[ "$no_start" -eq 1 ]]; then
	log "文件已安装，服务未启动"
else
	log "已启动。查看日志: ssh -p $port $target journalctl -u go-tls-proxy -f"
fi
log "证书写在远端配置的 storage_dir。本机演习: ./deploy.sh issue --dry-run -c $config_file"
