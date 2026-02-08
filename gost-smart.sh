#!/usr/bin/env bash

WORKDIR=/etc/mihomo-smart
mkdir -p $WORKDIR
SUB_FILE=$WORKDIR/sub.yaml
PROXY_FILE=$WORKDIR/proxies.txt
PROXY_YAML=$WORKDIR/proxies.yaml
ACTIVE=$WORKDIR/active.txt
CONFIG=$WORKDIR/config.yaml
AUTH_FILE=$WORKDIR/auth.txt
SECRET_FILE=$WORKDIR/secret.txt
MODE_FILE=$WORKDIR/mode.txt

SUBCONVERTER_DIR=$WORKDIR/subconverter
SUBCONVERTER_BIN=$SUBCONVERTER_DIR/subconverter
SUBCONVERTER_PORT=25500
SUBCONVERTER_PID=$WORKDIR/subconverter.pid
SUBCONVERTER_LOG=$WORKDIR/subconverter.log

SUB_UA=${SUB_UA:-clash}

HTTP_PORT=18080
SOCKS_PORT=18081

rand_str() { tr -dc a-z0-9 </dev/urandom | head -c 12; }

if [[ -f $AUTH_FILE ]]; then
  USER=${USER:-$(cut -d: -f1 $AUTH_FILE)}
  PASS=${PASS:-$(cut -d: -f2- $AUTH_FILE)}
else
  USER=$(rand_str)
  PASS=$(rand_str)
  echo "${USER}:${PASS}" > $AUTH_FILE
fi

if [[ -f $SECRET_FILE ]]; then
  SECRET=$(cat $SECRET_FILE)
else
  SECRET=$(rand_str)
  echo "$SECRET" > $SECRET_FILE
fi

line() { echo "-------------------------------------------------------"; }

logo() {
clear
echo
echo "   ██████╗  ██████╗ ███████╗████████╗"
echo "  ██╔════╝ ██╔═══██╗██╔════╝╚══██╔══╝"
echo "  ██║  ███╗██║   ██║███████╗   ██║   "
echo "  ██║   ██║██║   ██║╚════██║   ██║   "
echo "  ╚██████╔╝╚██████╔╝███████║   ██║   "
echo "   ╚═════╝  ╚═════╝ ╚══════╝   ╚═╝   "
echo
echo "        MIHOMO 智能订阅代理管理面板"
line
echo
}

install_mihomo() {
if command -v mihomo >/dev/null; then
  return
fi

if ! command -v python3 >/dev/null; then
  echo "  安装失败：需要 python3 用于解析 GitHub 发布信息"
  exit 1
fi

echo "  未检测到 mihomo，正在安装..."
ARCH=$(uname -m)
case "$ARCH" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  armv7l|armv7) ARCH=armv7 ;;
  armv6l|armv6) ARCH=armv6 ;;
  *)
    echo "  不支持的架构: $ARCH"
    exit 1
    ;;
esac

if [[ -n "${MIHOMO_URL:-}" ]]; then
  URL="$MIHOMO_URL"
else
  TMP_JSON=$(mktemp)
  if ! curl -fsSL -H "Accept: application/vnd.github+json" -H "User-Agent: mihomo-smart" \
    https://api.github.com/repos/MetaCubeX/mihomo/releases/latest -o "$TMP_JSON"; then
    echo "  获取发布信息失败：可能网络受限或 GitHub API 限流"
    rm -f "$TMP_JSON"
    exit 1
  fi

  URL=$(ARCH="$ARCH" python3 - "$TMP_JSON" <<'PY'
import json, os, sys
arch = os.environ.get("ARCH")
path = sys.argv[1]
try:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
except Exception:
    sys.exit(0)
assets = data.get("assets", [])
choices = []
for a in assets:
    name = a.get("name", "")
    url = a.get("browser_download_url", "")
    if not name or not url:
        continue
    n = name.lower()
    if "linux" in n and arch in n and "sha256" not in n:
        choices.append((name, url))
if not choices:
    sys.exit(0)
choices.sort(key=lambda x: (0 if x[0].endswith(".gz") else 1, len(x[0])))
print(choices[0][1])
PY
  )
  rm -f "$TMP_JSON"
fi

if [[ -z "$URL" ]]; then
  echo "  安装失败：未找到对应的 Linux 发行包"
  echo "  可手动指定下载地址：MIHOMO_URL=... 重新运行脚本"
  exit 1
fi

TMP=$(mktemp)
if ! curl -fsSL "$URL" -o "$TMP"; then
  echo "  下载失败：$URL"
  rm -f "$TMP"
  exit 1
fi

if [[ "$URL" == *.gz ]]; then
  gunzip -c "$TMP" > /usr/local/bin/mihomo
else
  cat "$TMP" > /usr/local/bin/mihomo
fi

chmod +x /usr/local/bin/mihomo
rm -f "$TMP"

if ! command -v mihomo >/dev/null; then
  echo "  安装失败：mihomo 不可执行"
  exit 1
fi
}

set_ini_kv() {
  local key="$1"
  local value="$2"
  local file="$3"
  if grep -qE "^[[:space:]]*${key}=" "$file"; then
    sed -i "s|^[[:space:]]*${key}=.*|${key}=${value}|" "$file"
    return
  fi
  if grep -q '^\[common\]' "$file"; then
    awk -v k="$key" -v v="$value" '
      BEGIN{done=0}
      /^\[common\]/{print; if(!done){print k"="v; done=1; next}}
      {print}
      END{if(!done){print k"="v}}
    ' "$file" > "${file}.tmp" && mv "${file}.tmp" "$file"
  else
    echo "${key}=${value}" >> "$file"
  fi
}

urlencode() {
  local s="$1"
  local i c
  for ((i=0; i<${#s}; i++)); do
    c="${s:i:1}"
    case "$c" in
      [a-zA-Z0-9.~_-]) printf '%s' "$c" ;;
      *) printf '%%%02X' "'$c" ;;
    esac
  done
}

install_subconverter() {
  if [[ -x "$SUBCONVERTER_BIN" && -d "$SUBCONVERTER_DIR/base" ]]; then
    return 0
  fi

  if ! command -v curl >/dev/null || ! command -v tar >/dev/null; then
    echo "  安装失败：需要 curl 与 tar"
    return 1
  fi

  echo "  未检测到 subconverter，正在安装..."
  local arch
  arch=$(uname -m)
  local candidates=()
  case "$arch" in
    x86_64|amd64)
      candidates=(subconverter_linux64.tar.gz subconverter_linux_amd64.tar.gz subconverter_linux_x86_64.tar.gz)
      ;;
    aarch64|arm64)
      candidates=(subconverter_linux_arm64.tar.gz subconverter_linux_aarch64.tar.gz subconverter_linux_armv8.tar.gz)
      ;;
    armv7l|armv7)
      candidates=(subconverter_linux_armv7.tar.gz subconverter_linux_armv7l.tar.gz)
      ;;
    armv6l|armv6)
      candidates=(subconverter_linux_armv6.tar.gz subconverter_linux_armv6l.tar.gz)
      ;;
    *)
      echo "  不支持的架构: $arch"
      return 1
      ;;
  esac

  local tmp url ok
  tmp=$(mktemp)
  ok=0
  for name in "${candidates[@]}"; do
    url="https://github.com/tindy2013/subconverter/releases/latest/download/${name}"
    if curl -fsSL "$url" -o "$tmp"; then
      ok=1
      break
    fi
  done

  if [[ $ok -ne 1 ]]; then
    echo "  安装失败：未找到对应的 subconverter 发行包"
    rm -f "$tmp"
    return 1
  fi

  rm -rf "$SUBCONVERTER_DIR"
  mkdir -p "$SUBCONVERTER_DIR"
  if ! tar -xzf "$tmp" -C "$SUBCONVERTER_DIR"; then
    echo "  安装失败：解压 subconverter 失败"
    rm -f "$tmp"
    return 1
  fi
  rm -f "$tmp"

  if [[ -f "$SUBCONVERTER_BIN" && ! -x "$SUBCONVERTER_BIN" ]]; then
    chmod +x "$SUBCONVERTER_BIN" 2>/dev/null || true
  fi
  if [[ ! -x "$SUBCONVERTER_BIN" ]]; then
    echo "  安装失败：subconverter 不可执行"
    return 1
  fi

  local conf=""
  if [[ -f "$SUBCONVERTER_DIR/pref.ini" ]]; then
    conf="$SUBCONVERTER_DIR/pref.ini"
  elif [[ -f "$SUBCONVERTER_DIR/subconverter.ini" ]]; then
    conf="$SUBCONVERTER_DIR/subconverter.ini"
  fi
  if [[ -n "$conf" ]]; then
    set_ini_kv "listen" "127.0.0.1" "$conf"
    set_ini_kv "port" "$SUBCONVERTER_PORT" "$conf"
    set_ini_kv "api_mode" "true" "$conf"
  fi
}

start_subconverter() {
  rm -f "$SUBCONVERTER_PID"
  : > "$SUBCONVERTER_LOG"
  (cd "$SUBCONVERTER_DIR" && nohup "$SUBCONVERTER_BIN" >"$SUBCONVERTER_LOG" 2>&1 & echo $! > "$SUBCONVERTER_PID")
  sleep 2
  local pid
  pid=$(cat "$SUBCONVERTER_PID" 2>/dev/null || true)
  if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
    echo 1
  else
    echo "  subconverter 启动失败，日志如下："
    tail -n 20 "$SUBCONVERTER_LOG" 2>/dev/null || true
    echo 0
  fi
}

stop_subconverter() {
  local pid
  pid=$(cat "$SUBCONVERTER_PID" 2>/dev/null || true)
  if [[ -n "$pid" ]]; then
    kill "$pid" 2>/dev/null || true
  fi
  rm -f "$SUBCONVERTER_PID"
}

convert_sub_to_clash() {
  local sub_url="$1"
  echo "  订阅不是 Clash/Mihomo 格式，尝试本地转换..."

  if ! install_subconverter; then
    return 1
  fi

  local started
  started=$(start_subconverter)
  if [[ "$started" != "1" ]]; then
    return 1
  fi

  local enc url ok
  enc=$(urlencode "$sub_url")
  url="http://127.0.0.1:${SUBCONVERTER_PORT}/sub?target=clash&url=${enc}"

  ok=0
  for i in 1 2 3 4 5; do
    if curl -fsSL "$url" -o "$SUB_FILE"; then
      ok=1
      break
    fi
    sleep 1
  done

  if [[ "$started" == "1" ]]; then
    stop_subconverter
  fi

  if [[ $ok -ne 1 ]]; then
    echo "  本地转换失败：subconverter 无法获取订阅"
    return 1
  fi

  if ! grep -q '^proxies:' "$SUB_FILE"; then
    echo "  本地转换失败：输出不是 Clash/Mihomo 格式"
    return 1
  fi
}

yaml_quote() {
  local s="$1"
  s=${s//\\/\\\\}
  s=${s//\"/\\\"}
  printf '"%s"' "$s"
}

normalize_yaml() {
  local f="$1"
  # 去除 UTF-8 BOM 与 Windows 换行
  sed -i '1s/^\xEF\xBB\xBF//' "$f" 2>/dev/null || true
  sed -i 's/\r$//' "$f" 2>/dev/null || true
}

is_clash_yaml() {
  local f="$1"
  grep -qE '^[[:space:]]*proxies:' "$f"
}

extract_proxies_block() {
  awk '
  /^[[:space:]]*proxies:/ {flag=1; print; next}
  flag {
    if ($0 ~ /^[^[:space:]#]/) {exit}
    print
  }' "$SUB_FILE" > "$PROXY_YAML"

  if ! is_clash_yaml "$PROXY_YAML"; then
    echo "  订阅内容缺少 proxies 字段，无法解析"
    return 1
  fi
}

extract_proxy_names() {
  awk -F'name:' '/- *name:/{sub(/^[[:space:]]*- *name:[[:space:]]*/, ""); gsub(/^"+|"+$/, ""); gsub(/^'\''+|'\''+$/, ""); print}' "$PROXY_YAML" | \
  awk 'NF' > "$PROXY_FILE"

  if [[ ! -s "$PROXY_FILE" ]]; then
    echo "  未解析到任何节点名称"
    return 1
  fi
}

update_sub() {
  read -p "  输入订阅链接(支持 Clash/Mihomo 或 v2rayN): " SUB
  echo
  echo "  正在下载订阅并解析节点..."

  TMP=$(mktemp)
  TMP_DEC=$(mktemp)
  if ! curl -fsSL --compressed -A "$SUB_UA" "$SUB" -o "$TMP"; then
    echo "  下载失败，请检查链接"
    rm -f "$TMP" "$TMP_DEC"
    return
  fi

  normalize_yaml "$TMP"
  if is_clash_yaml "$TMP"; then
    mv "$TMP" "$SUB_FILE"
  elif base64 -d "$TMP" > "$TMP_DEC" 2>/dev/null; then
    normalize_yaml "$TMP_DEC"
    if is_clash_yaml "$TMP_DEC"; then
    mv "$TMP_DEC" "$SUB_FILE"
    rm -f "$TMP"
    else
      rm -f "$TMP" "$TMP_DEC"
      if ! convert_sub_to_clash "$SUB"; then
        return
      fi
    fi
  else
    rm -f "$TMP" "$TMP_DEC"
    if ! convert_sub_to_clash "$SUB"; then
      return
    fi
  fi

  rm -f "$TMP" "$TMP_DEC"

  if ! extract_proxies_block; then
    return
  fi

  if ! extract_proxy_names; then
    return
  fi

  if [[ -s $ACTIVE ]] && ! grep -Fxq "$(cat $ACTIVE)" "$PROXY_FILE"; then
    rm -f "$ACTIVE"
  fi

  echo
  echo "  解析完成，节点数量：$(wc -l < $PROXY_FILE)"
  echo "  说明：mihomo 将在运行时自动健康检查（AUTO 组）"
}

build_proxy_list() {
  local active="$1"
  if [[ -n "$active" ]]; then
    echo "      - $(yaml_quote "$active")"
  fi
  while IFS= read -r name; do
    [[ -z "$name" ]] && continue
    [[ "$name" == "$active" ]] && continue
    echo "      - $(yaml_quote "$name")"
  done < "$PROXY_FILE"
}

gen_config() {
  if [[ ! -s $PROXY_FILE ]]; then
    echo "  未找到节点，请先更新订阅"
    return 1
  fi

  echo "proxy" > "$MODE_FILE"
  ACTIVE_NODE=$(cat $ACTIVE 2>/dev/null || true)

  cat > "$CONFIG" <<EOL
port: ${HTTP_PORT}
socks-port: ${SOCKS_PORT}
allow-lan: true
bind-address: 0.0.0.0
mode: global
log-level: info
ipv6: false
external-controller: 127.0.0.1:9090
secret: "${SECRET}"
authentication:
  - "${USER}:${PASS}"

EOL

  cat "$PROXY_YAML" >> "$CONFIG"

  cat >> "$CONFIG" <<EOL
proxy-groups:
  - name: PROXY
    type: select
    proxies:
$(build_proxy_list "$ACTIVE_NODE")
  - name: AUTO
    type: url-test
    url: http://www.gstatic.com/generate_204
    interval: 300
    proxies:
$(build_proxy_list "$ACTIVE_NODE")

rules:
  - MATCH,PROXY
EOL
}

gen_direct_config() {
  echo "direct" > "$MODE_FILE"
  cat > "$CONFIG" <<EOL
port: ${HTTP_PORT}
socks-port: ${SOCKS_PORT}
allow-lan: true
bind-address: 0.0.0.0
mode: direct
log-level: info
ipv6: false
external-controller: 127.0.0.1:9090
secret: "${SECRET}"
authentication:
  - "${USER}:${PASS}"

rules:
  - MATCH,DIRECT
EOL
}

gen_service() {
  if ! gen_config; then
    return
  fi

  cat > /etc/systemd/system/mihomo-proxy.service <<EOL
[Unit]
Description=Mihomo Smart Proxy
After=network.target

[Service]
ExecStart=/usr/local/bin/mihomo -d ${WORKDIR} -f ${CONFIG}
Restart=always

[Install]
WantedBy=multi-user.target
EOL

  systemctl daemon-reload
  systemctl enable mihomo-proxy
  systemctl restart mihomo-proxy

  IP=$(curl -s ip.sb)
  echo
  line
  echo "  代理已启用"
  line
  echo "  HTTP  : http://${USER}:${PASS}@${IP}:${HTTP_PORT}"
  echo "  SOCKS : socks5://${USER}:${PASS}@${IP}:${SOCKS_PORT}"
  echo "  控制面板: 127.0.0.1:9090 (secret: ${SECRET})"
  line
}

direct_mode() {
  gen_direct_config

  cat > /etc/systemd/system/mihomo-proxy.service <<EOL
[Unit]
Description=Mihomo Smart Proxy
After=network.target

[Service]
ExecStart=/usr/local/bin/mihomo -d ${WORKDIR} -f ${CONFIG}
Restart=always

[Install]
WantedBy=multi-user.target
EOL

  systemctl daemon-reload
  systemctl enable mihomo-proxy
  systemctl restart mihomo-proxy

  IP=$(curl -s ip.sb)
  echo
  line
  echo "  直连代理已启用（无需订阅）"
  line
  echo "  HTTP  : http://${USER}:${PASS}@${IP}:${HTTP_PORT}"
  echo "  SOCKS : socks5://${USER}:${PASS}@${IP}:${SOCKS_PORT}"
  echo "  控制面板: 127.0.0.1:9090 (secret: ${SECRET})"
  line
}

select_node() {
  if [[ ! -s $PROXY_FILE ]]; then
    echo "  未找到节点，请先更新订阅"
    return
  fi
  echo
  nl -w2 -s'. ' "$PROXY_FILE"
  echo
  read -p "  选择节点编号: " NUM
  sed -n "${NUM}p" "$PROXY_FILE" > "$ACTIVE"
  gen_service
}

current_node() {
  echo
  echo "  当前使用节点："
  line
  if [[ -f "$MODE_FILE" ]] && [[ "$(cat "$MODE_FILE")" == "direct" ]]; then
    echo "  直连模式（无需订阅）"
    line
    return
  fi
  if [[ -s $ACTIVE ]]; then
    cat "$ACTIVE"
  else
    echo "  未选择（默认使用列表第一个节点）"
  fi
  line
}

uninstall_all() {
  echo
  read -p "  确认卸载？(y/n): " c
  [[ $c != "y" ]] && return

  systemctl stop mihomo-proxy 2>/dev/null
  systemctl disable mihomo-proxy 2>/dev/null
  rm -f /etc/systemd/system/mihomo-proxy.service
  rm -rf $WORKDIR

  echo
  echo "  已卸载 Mihomo 代理管理环境"
  echo
}

menu() {
  logo
  echo "  1) 更新订阅并解析节点"
  echo "  2) 选择节点并启用代理"
  echo "  3) 查看当前使用节点"
  echo "  4) 重启代理服务"
  echo "  5) 卸载所有组件"
  echo "  6) 启用直连 HTTP/SOCKS 代理（无需订阅）"
  echo "  0) 退出"
  echo
  read -p "  请输入选项: " n

  case $n in
  1) update_sub ;;
  2) select_node ;;
  3) current_node ;;
  4) systemctl restart mihomo-proxy ;;
  5) uninstall_all ;;
  6) direct_mode ;;
  0) exit ;;
  esac
}

install_mihomo
while true; do menu; read -p "  回车返回菜单"; done
