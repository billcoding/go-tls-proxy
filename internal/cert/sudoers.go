package cert

import (
	"fmt"
	"strings"
)

// SudoersFragment 是部署时写入 /etc/sudoers.d/go-tls-proxy 的全文。
// binary 是安装后的 go-tls-proxy 路径，由部署脚本按安装前缀传入。
// 只允许这个二进制的 fw80 open / fw80 close，没有通配成其他 root 命令。
func SudoersFragment(user, binary string) string {
	user = strings.TrimSpace(user)
	binary = strings.TrimSpace(binary)
	return fmt.Sprintf(`# go-tls-proxy 只允许通过 %s fw80 临时放行或删除带 %s 注释的 HTTP-01 规则。
# 不能改安全组，也不能执行其他 root 命令。
%s ALL=(root) NOPASSWD: %s fw80 open *, %s fw80 close *
`, binary, ruleComment, user, binary, binary)
}
