#!/usr/bin/env bash

WORKDIR=/etc/mihomo-smart
mkdir -p $WORKDIR
SUB_FILE=$WORKDIR/sub.yaml
PROXY_FILE=$WORKDIR/proxies.txt
PROXY_YAML=$WORKDIR/proxies.yaml
ACTIVE=$WORKDIR/active.txt
CONFIG=$WORKDIR/config.yaml
AUTH_FILE=$WORKDIR/auth.txt
MODE_FILE=$WORKDIR/mode.txt
SUB_URLS_FILE=$WORKDIR/sub_urls.txt
SUB_DEFAULT_FILE=$WORKDIR/sub_default.txt

SUBCONVERTER_DIR=$WORKDIR/subconverter
SUBCONVERTER_BIN=$SUBCONVERTER_DIR/subconverter
SUBCONVERTER_PORT=25500
SUBCONVERTER_PID=$WORKDIR/subconverter.pid
SUBCONVERTER_LOG=$WORKDIR/subconverter.log

SUB_UA=${SUB_UA:-Mihomo}

HTTP_PORT=18080
SOCKS_PORT=18081
MENU_WIDTH=16
SUB_NAME_WIDTH=12

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  C_RESET=$'\033[0m'
  C_BOLD=$'\033[1m'
  C_BLUE=$'\033[34m'
  C_GREEN=$'\033[32m'
  C_YELLOW=$'\033[33m'
  C_RED=$'\033[31m'
  C_CYAN=$'\033[36m'
else
  C_RESET=""
  C_BOLD=""
  C_BLUE=""
  C_GREEN=""
  C_YELLOW=""
  C_RED=""
  C_CYAN=""
fi

rand_str() { tr -dc a-z0-9 </dev/urandom | head -c 12; }

if [[ -f $AUTH_FILE ]]; then
  USER=$(cut -d: -f1 "$AUTH_FILE")
  PASS=$(cut -d: -f2- "$AUTH_FILE")
else
  USER=$(rand_str)
  PASS=$(rand_str)
  echo "${USER}:${PASS}" > "$AUTH_FILE"
fi


line() { printf "%b\n" "${C_GREEN}-------------------------------------------------------${C_RESET}"; }

msg_info() { printf "%b\n" "  ${C_GREEN}$*${C_RESET}"; }
msg_warn() { printf "%b\n" "  ${C_YELLOW}$*${C_RESET}"; }
msg_err() { printf "%b\n" "  ${C_RED}$*${C_RESET}"; }
msg_title() { printf "%b\n" "  ${C_BOLD}$*${C_RESET}"; }

menu_item() {
  local num="$1"
  local label="$2"
  printf "  %b%s%b. %b%-*s%b\n" "${C_YELLOW}" "$num" "${C_RESET}" "${C_CYAN}" "$MENU_WIDTH" "$label" "${C_RESET}"
}

wait_back() {
  local msg="${1:-0. 返回上一级}"
  local v
  while true; do
    read -p "  ${msg} " v
    [[ "$v" == "0" ]] && break
  done
}

wait_main() { wait_back "0. 返回上一级"; }

logo() {
clear
echo
printf "%b\n" "${C_CYAN}███╗   ███╗██╗██╗  ██╗ ██████╗ ███╗   ███╗ ██████╗${C_RESET}"
printf "%b\n" "${C_CYAN}████╗ ████║██║██║  ██║██╔═══██╗████╗ ████║██╔═══██╗${C_RESET}"
printf "%b\n" "${C_CYAN}██╔████╔██║██║███████║██║   ██║██╔████╔██║██║   ██║${C_RESET}"
printf "%b\n" "${C_CYAN}██║╚██╔╝██║██║██╔══██║██║   ██║██║╚██╔╝██║██║   ██║${C_RESET}"
printf "%b\n" "${C_CYAN}██║ ╚═╝ ██║██║██║  ██║╚██████╔╝██║ ╚═╝ ██║╚██████╔╝${C_RESET}"
printf "%b\n" "${C_CYAN}╚═╝     ╚═╝╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝ ╚═════╝${C_RESET}"
echo
printf "%b\n" "${C_BOLD}        MIHOMO 智能订阅代理管理面板${C_RESET}"
line
echo
}

install_mihomo() {
if command -v mihomo >/dev/null; then
  return
fi

if ! command -v python3 >/dev/null; then
  msg_err "安装失败：需要 python3 用于解析 GitHub 发布信息"
  exit 1
fi

msg_info "未检测到 mihomo，正在安装..."
ARCH=$(uname -m)
case "$ARCH" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  armv7l|armv7) ARCH=armv7 ;;
  armv6l|armv6) ARCH=armv6 ;;
  *)
    msg_err "不支持的架构: $ARCH"
    exit 1
    ;;
esac

if [[ -n "${MIHOMO_URL:-}" ]]; then
  URL="$MIHOMO_URL"
else
  TMP_JSON=$(mktemp)
  if ! curl -fsSL -H "Accept: application/vnd.github+json" -H "User-Agent: mihomo-smart" \
    https://api.github.com/repos/MetaCubeX/mihomo/releases/latest -o "$TMP_JSON"; then
    msg_err "获取发布信息失败：可能网络受限或 GitHub API 限流"
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
  msg_err "安装失败：未找到对应的 Linux 发行包"
  msg_warn "可手动指定下载地址：MIHOMO_URL=... 重新运行脚本"
  exit 1
fi

TMP=$(mktemp)
if ! curl -fsSL "$URL" -o "$TMP"; then
  msg_err "下载失败：$URL"
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
  msg_err "安装失败：mihomo 不可执行"
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
    msg_err "安装失败：需要 curl 与 tar"
    return 1
  fi

  msg_info "未检测到 subconverter，正在安装..."
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
      msg_err "不支持的架构: $arch"
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
    msg_err "安装失败：未找到对应的 subconverter 发行包"
    rm -f "$tmp"
    return 1
  fi

  rm -rf "$SUBCONVERTER_DIR"
  mkdir -p "$SUBCONVERTER_DIR"
  if ! tar -xzf "$tmp" -C "$SUBCONVERTER_DIR"; then
    msg_err "安装失败：解压 subconverter 失败"
    rm -f "$tmp"
    return 1
  fi
  rm -f "$tmp"

  if [[ -f "$SUBCONVERTER_BIN" && ! -x "$SUBCONVERTER_BIN" ]]; then
    chmod +x "$SUBCONVERTER_BIN" 2>/dev/null || true
  fi
  if [[ ! -x "$SUBCONVERTER_BIN" ]]; then
    msg_err "安装失败：subconverter 不可执行"
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
    msg_err "subconverter 启动失败，日志如下："
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
  msg_warn "订阅不是 Clash/Mihomo 格式，尝试本地转换..."

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
    msg_err "本地转换失败：subconverter 无法获取订阅"
    return 1
  fi

  if ! grep -q '^proxies:' "$SUB_FILE"; then
    msg_err "本地转换失败：输出不是 Clash/Mihomo 格式"
    return 1
  fi
}

yaml_quote() {
  local s="$1"
  s=${s//\\/\\\\}
  s=${s//\"/\\\"}
  printf '"%s"' "$s"
}

get_public_ip() {
  # 强制 IPv4 获取公网地址，避免输出 IPv6
  local ip
  ip=$(curl -4 -s --max-time 6 ip.sb 2>/dev/null || true)
  if [[ -z "$ip" ]]; then
    ip="未获取到 IPv4"
  fi
  echo "$ip"
}

service_active() {
  systemctl is-active --quiet mihomo-proxy
}

show_links() {
  local ip status
  ip=$(get_public_ip)
  if service_active; then
    status="${C_GREEN}运行中${C_RESET}"
  else
    status="${C_RED}已停止${C_RESET}"
  fi
  echo
  line
  printf "%b\n" "  服务状态：${status}"
  line
  printf "%b\n" "  ${C_CYAN}HTTP  ${C_RESET}: ${C_YELLOW}http://${USER}:${PASS}@${ip}:${HTTP_PORT}${C_RESET}"
  printf "%b\n" "  ${C_CYAN}SOCKS ${C_RESET}: ${C_YELLOW}socks5://${USER}:${PASS}@${ip}:${SOCKS_PORT}${C_RESET}"
  line
}

show_status() {
  echo
  msg_title "当前状态："
  line
  if [[ -f "$MODE_FILE" ]] && [[ "$(cat "$MODE_FILE")" == "direct" ]]; then
    msg_info "直连模式（无需订阅）"
  elif [[ -s $ACTIVE ]]; then
    printf "%b\n" "  ${C_YELLOW}当前节点${C_RESET}: $(cat "$ACTIVE")"
  else
    msg_warn "未选择节点"
  fi
  line
  show_links
}

show_logs() {
  echo
  line
  printf "%b\n" "  ${C_BOLD}mihomo 运行日志（最近 200 行）${C_RESET}"
  line
  journalctl -u mihomo-proxy -n 200 --no-pager
}

normalize_yaml() {
  local f="$1"
  # 去除 UTF-8 BOM 与 Windows 换行
  sed -i '1s/^\xEF\xBB\xBF//' "$f" 2>/dev/null || true
  sed -i 's/\r$//' "$f" 2>/dev/null || true
}

b64_decode_file() {
  local src="$1"
  local dst="$2"
  python3 - "$src" "$dst" <<'PY'
import base64, sys
src, dst = sys.argv[1], sys.argv[2]
try:
    data = open(src, "rb").read()
except Exception:
    sys.exit(1)
s = b"".join(data.split())
if not s:
    sys.exit(1)
s = s.replace(b"-", b"+").replace(b"_", b"/")
s += b"=" * (-len(s) % 4)
try:
    out = base64.b64decode(s, validate=False)
except Exception:
    sys.exit(1)
if not out:
    sys.exit(1)
with open(dst, "wb") as f:
    f.write(out)
PY
}

is_clash_yaml() {
  local f="$1"
  grep -qE '^[[:space:]]*proxies:' "$f"
}

has_proxy_providers() {
  local f="$1"
  grep -qE '^[[:space:]]*proxy-providers:' "$f"
}

extract_provider_urls() {
  local f="$1"
  python3 - "$f" <<'PY'
import re, sys
path = sys.argv[1]
try:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.read().splitlines()
except Exception:
    sys.exit(1)

in_block = False
base = None
urls = []
for line in lines:
    if not in_block:
        m = re.match(r'^(\s*)proxy-providers\s*:\s*$', line)
        if m:
            in_block = True
            base = len(m.group(1))
        continue
    if line.strip() == "":
        continue
    indent = len(line) - len(line.lstrip(' '))
    if indent <= base:
        break
    m = re.match(r'^\s*url\s*:\s*(.+)\s*$', line)
    if not m:
        continue
    val = m.group(1).strip()
    if val.startswith(("'", '"')) and val.endswith(("'", '"')) and len(val) >= 2:
        val = val[1:-1]
    urls.append(val)

print("\n".join(urls))
PY
}

append_proxies_from_yaml() {
  local src="$1"
  local dst="$2"
  python3 - "$src" "$dst" <<'PY'
import re, sys
src, dst = sys.argv[1], sys.argv[2]
try:
    with open(src, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.read().splitlines()
except Exception:
    sys.exit(1)

out = []
in_proxies = False
base = None
for line in lines:
    if not in_proxies:
        m = re.match(r'^(\s*)proxies\s*:\s*$', line)
        if m:
            in_proxies = True
            base = len(m.group(1))
        continue
    if line.strip() == "":
        continue
    indent = len(line) - len(line.lstrip(' '))
    if indent <= base and not line.lstrip().startswith('-'):
        break
    # 归一化为两空格缩进
    rel = line[base + 2 :] if indent >= base + 2 else line.lstrip()
    out.append("  " + rel)

if not out:
    sys.exit(1)

with open(dst, "a", encoding="utf-8") as f:
    f.write("\n".join(out) + "\n")
PY
}

convert_providers_to_clash() {
  local src="$1"
  local ua="$2"
  local out="$3"
  local tmp_urls tmp tmp_dec tmp_node tmp_yaml
  tmp_urls=$(mktemp)
  tmp=$(mktemp)
  tmp_dec=$(mktemp)
  tmp_node=$(mktemp)
  tmp_yaml=$(mktemp)

  : > "$out"
  echo "proxies:" >> "$out"

  if ! extract_provider_urls "$src" > "$tmp_urls"; then
    rm -f "$tmp_urls" "$tmp" "$tmp_dec" "$tmp_node" "$tmp_yaml"
    return 1
  fi

  local ok=0
  while IFS= read -r url; do
    [[ -z "$url" ]] && continue
    if ! curl -fsSL --compressed -A "$ua" "$url" -o "$tmp"; then
      continue
    fi
    normalize_yaml "$tmp"
    if is_clash_yaml "$tmp"; then
      if append_proxies_from_yaml "$tmp" "$out"; then
        ok=1
      fi
      continue
    fi
    if is_node_list "$tmp"; then
      if convert_nodes_to_clash "$tmp" "$tmp_node"; then
        if append_proxies_from_yaml "$tmp_node" "$out"; then
          ok=1
        fi
      fi
      continue
    fi
    if b64_decode_file "$tmp" "$tmp_dec"; then
      normalize_yaml "$tmp_dec"
      if is_clash_yaml "$tmp_dec"; then
        if append_proxies_from_yaml "$tmp_dec" "$out"; then
          ok=1
        fi
        continue
      fi
      if is_node_list "$tmp_dec"; then
        if convert_nodes_to_clash "$tmp_dec" "$tmp_node"; then
          if append_proxies_from_yaml "$tmp_node" "$out"; then
            ok=1
          fi
        fi
        continue
      fi
    fi
  done < "$tmp_urls"

  rm -f "$tmp_urls" "$tmp" "$tmp_dec" "$tmp_node" "$tmp_yaml"
  [[ "$ok" -eq 1 ]]
}

is_node_list() {
  python3 - "$1" <<'PY'
import sys
path = sys.argv[1]
try:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.read().splitlines()
except Exception:
    sys.exit(1)
schemes = ("vless://", "vmess://", "ss://", "trojan://", "ssr://")
for line in lines:
    s = line.strip()
    if not s or s.startswith("#"):
        continue
    if s.startswith(schemes):
        sys.exit(0)
sys.exit(1)
PY
}

convert_nodes_to_clash() {
  local src="$1"
  local dst="$2"
  python3 - "$src" "$dst" <<'PY'
import sys, base64, json, urllib.parse
from collections import OrderedDict

src, dst = sys.argv[1], sys.argv[2]

def b64decode(s):
    s = s.strip()
    s = s.replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s)

def yaml_str(s):
    s = str(s)
    s = s.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{s}"'

def scalar(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    return yaml_str(v)

def dump_field(f, key, val, indent):
    sp = " " * indent
    if isinstance(val, dict):
        if not val:
            return
        f.write(f"{sp}{key}:\n")
        for k, v in val.items():
            dump_field(f, k, v, indent + 2)
        return
    if isinstance(val, list):
        if not val:
            return
        f.write(f"{sp}{key}:\n")
        for item in val:
            if isinstance(item, dict):
                f.write(f"{sp}  -\n")
                for k, v in item.items():
                    dump_field(f, k, v, indent + 4)
            else:
                f.write(f"{sp}  - {scalar(item)}\n")
        return
    if val is None or val == "":
        return
    f.write(f"{sp}{key}: {scalar(val)}\n")

def dump_proxy(f, proxy):
    f.write("  - name: " + scalar(proxy.get("name", "")) + "\n")
    for k, v in proxy.items():
        if k == "name":
            continue
        dump_field(f, k, v, 4)

def parse_hostport(hp):
    if hp.startswith("[") and "]" in hp:
        host = hp[1:hp.index("]")]
        rest = hp[hp.index("]") + 1 :]
        if rest.startswith(":"):
            rest = rest[1:]
        port = int(rest) if rest else None
        return host, port
    if hp.count(":") == 1:
        host, port = hp.split(":", 1)
        return host, int(port)
    u = urllib.parse.urlsplit("ss://" + hp)
    return u.hostname, u.port

def ensure_name(name, fallback, used):
    name = (name or "").strip() or fallback
    base = name
    idx = 2
    while name in used:
        name = f"{base}-{idx}"
        idx += 1
    used.add(name)
    return name

def parse_vmess(line):
    raw = line[8:]
    try:
        data = b64decode(raw)
        js = json.loads(data.decode("utf-8", errors="ignore"))
    except Exception:
        return None
    server = js.get("add") or ""
    port = js.get("port")
    uuid = js.get("id") or ""
    if not server or not port or not uuid:
        return None
    p = OrderedDict()
    p["name"] = js.get("ps") or ""
    p["type"] = "vmess"
    p["server"] = server
    try:
        p["port"] = int(port)
    except Exception:
        return None
    p["uuid"] = uuid
    aid = js.get("aid", 0)
    try:
        p["alterId"] = int(aid)
    except Exception:
        p["alterId"] = 0
    p["cipher"] = js.get("scy") or js.get("cipher") or "auto"
    p["udp"] = True
    net = (js.get("net") or "tcp").lower()
    if net and net != "tcp":
        p["network"] = net
    tls = (js.get("tls") or "").lower()
    if tls in ("tls", "1", "true"):
        p["tls"] = True
    sni = js.get("sni") or ""
    if sni:
        p["servername"] = sni
    alpn = js.get("alpn") or ""
    if alpn:
        p["alpn"] = [x.strip() for x in str(alpn).split(",") if x.strip()]
    fp = js.get("fp") or ""
    if fp:
        p["fingerprint"] = fp
    host = js.get("host") or ""
    path = js.get("path") or ""
    if net == "ws":
        ws_opts = OrderedDict()
        if path:
            ws_opts["path"] = path
        headers = OrderedDict()
        if host:
            headers["Host"] = host
        if headers:
            ws_opts["headers"] = headers
        if ws_opts:
            p["ws-opts"] = ws_opts
    if net == "grpc":
        grpc_opts = OrderedDict()
        svc = js.get("serviceName") or path
        if svc:
            grpc_opts["grpc-service-name"] = svc
        if grpc_opts:
            p["grpc-opts"] = grpc_opts
    return p

def parse_vless(line):
    try:
        u = urllib.parse.urlsplit(line)
    except Exception:
        return None
    if not u.hostname or not u.port or not u.username:
        return None
    params = urllib.parse.parse_qs(u.query, keep_blank_values=True)
    def q(k):
        return params.get(k, [""])[0]
    p = OrderedDict()
    p["name"] = urllib.parse.unquote(u.fragment or "")
    p["type"] = "vless"
    p["server"] = u.hostname
    p["port"] = int(u.port)
    p["uuid"] = u.username
    p["udp"] = True
    enc = q("encryption") or "none"
    p["encryption"] = enc
    flow = q("flow")
    if flow:
        p["flow"] = flow
    net = (q("type") or q("transport") or "tcp").lower()
    if net and net != "tcp":
        p["network"] = net
    if net == "ws":
        ws_opts = OrderedDict()
        path = q("path")
        if path:
            ws_opts["path"] = path
        host = q("host")
        headers = OrderedDict()
        if host:
            headers["Host"] = host
        if headers:
            ws_opts["headers"] = headers
        if ws_opts:
            p["ws-opts"] = ws_opts
    if net == "grpc":
        grpc_opts = OrderedDict()
        svc = q("serviceName") or q("service") or q("grpc-service-name")
        if svc:
            grpc_opts["grpc-service-name"] = svc
        if grpc_opts:
            p["grpc-opts"] = grpc_opts
    sec = (q("security") or "").lower()
    if sec in ("tls", "reality", "xtls"):
        p["tls"] = True
        sni = q("sni") or q("serverName") or q("servername")
        if sni:
            p["servername"] = sni
        alpn = q("alpn")
        if alpn:
            p["alpn"] = [x.strip() for x in alpn.split(",") if x.strip()]
        fp = q("fp")
        if fp:
            p["fingerprint"] = fp
        if sec == "reality":
            ropts = OrderedDict()
            pbk = q("pbk") or q("publicKey") or q("public-key")
            sid = q("sid") or q("shortId") or q("short-id")
            if pbk:
                ropts["public-key"] = pbk
            if sid:
                ropts["short-id"] = sid
            if ropts:
                p["reality-opts"] = ropts
    return p

def parse_ss(line):
    rest = line[5:]
    name = ""
    if "#" in rest:
        rest, frag = rest.split("#", 1)
        name = urllib.parse.unquote(frag)
    plugin = ""
    if "?" in rest:
        rest, query = rest.split("?", 1)
        params = urllib.parse.parse_qs(query, keep_blank_values=True)
        plugin = params.get("plugin", [""])[0]
    method = password = host = None
    port = None
    if "@" in rest:
        userinfo, hostport = rest.rsplit("@", 1)
        if ":" in userinfo:
            method, password = userinfo.split(":", 1)
        else:
            try:
                decoded = b64decode(userinfo).decode("utf-8", errors="ignore")
                if ":" in decoded:
                    method, password = decoded.split(":", 1)
                else:
                    return None
            except Exception:
                return None
    else:
        try:
            decoded = b64decode(rest).decode("utf-8", errors="ignore")
        except Exception:
            return None
        if "@" not in decoded or ":" not in decoded:
            return None
        userinfo, hostport = decoded.rsplit("@", 1)
        method, password = userinfo.split(":", 1)
    host, port = parse_hostport(hostport)
    if not host or not port or not method:
        return None
    method = urllib.parse.unquote(method)
    password = urllib.parse.unquote(password or "")
    p = OrderedDict()
    p["name"] = name
    p["type"] = "ss"
    p["server"] = host
    p["port"] = int(port)
    p["cipher"] = method
    p["password"] = password
    p["udp"] = True
    if plugin:
        plugin = urllib.parse.unquote(plugin)
        parts = plugin.split(";")
        pname = parts[0]
        opts_raw = parts[1:]
        opts = OrderedDict()
        for item in opts_raw:
            if not item:
                continue
            if "=" in item:
                k, v = item.split("=", 1)
                opts[k] = v
            else:
                opts[item] = True
        if pname in ("simple-obfs", "obfs-local"):
            pname = "obfs"
        if pname in ("v2ray", "v2ray-plugin"):
            pname = "v2ray-plugin"
        p["plugin"] = pname
        if pname == "obfs":
            opts2 = OrderedDict()
            if "obfs" in opts:
                opts2["mode"] = opts["obfs"]
            if "mode" in opts:
                opts2["mode"] = opts["mode"]
            if "obfs-host" in opts:
                opts2["host"] = opts["obfs-host"]
            if "host" in opts:
                opts2["host"] = opts["host"]
            if opts2:
                p["plugin-opts"] = opts2
        elif pname == "v2ray-plugin":
            opts2 = OrderedDict()
            if "mode" in opts:
                opts2["mode"] = opts["mode"]
            if "host" in opts:
                opts2["host"] = opts["host"]
            if "path" in opts:
                opts2["path"] = opts["path"]
            if "tls" in opts:
                opts2["tls"] = True
            if opts2:
                p["plugin-opts"] = opts2
        else:
            if opts:
                p["plugin-opts"] = opts
    return p

def parse_line(line):
    if line.startswith("vmess://"):
        return parse_vmess(line)
    if line.startswith("vless://"):
        return parse_vless(line)
    if line.startswith("ss://"):
        return parse_ss(line)
    return None

try:
    with open(src, "r", encoding="utf-8", errors="ignore") as f:
        lines = [x.strip() for x in f.read().splitlines()]
except Exception:
    sys.exit(1)

proxies = []
used_names = set()
for line in lines:
    if not line or line.startswith("#"):
        continue
    p = parse_line(line)
    if not p:
        continue
    fallback = f"{p.get('type', 'node')}-{p.get('server', '')}:{p.get('port', '')}"
    p["name"] = ensure_name(p.get("name") or "", fallback, used_names)
    proxies.append(p)

if not proxies:
    sys.exit(1)

with open(dst, "w", encoding="utf-8") as f:
    f.write("proxies:\n")
    for p in proxies:
        dump_proxy(f, p)
    f.write("\n")
PY
}

proxy_count() {
  python3 - "$1" <<'PY'
import re, sys
path = sys.argv[1]
try:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.read().splitlines()
except Exception:
    print(0)
    sys.exit(0)

in_proxies = False
base_indent = None
count = 0
for line in lines:
    if not in_proxies:
        m = re.match(r'^(\s*)proxies\s*:', line)
        if m:
            in_proxies = True
            base_indent = len(m.group(1))
        continue
    if line.strip() == "":
        continue
    indent = len(line) - len(line.lstrip(' '))
    if indent <= base_indent and not line.lstrip().startswith('-'):
        break
    if line.lstrip().startswith('-'):
        count += 1

print(count)
PY
}

extract_proxies_block() {
  python3 - "$SUB_FILE" "$PROXY_YAML" <<'PY'
import re, sys
src, dst = sys.argv[1], sys.argv[2]
try:
    with open(src, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.read().splitlines()
except Exception:
    open(dst, "w").close()
    sys.exit(0)

out = []
in_proxies = False
base_indent = None
for line in lines:
    if not in_proxies:
        m = re.match(r'^(\s*)proxies\s*:', line)
        if m:
            in_proxies = True
            base_indent = len(m.group(1))
            out.append(line.rstrip())
        continue
    if line.strip() == "":
        out.append(line)
        continue
    indent = len(line) - len(line.lstrip(' '))
    if indent <= base_indent and not line.lstrip().startswith('-'):
        break
    out.append(line)

with open(dst, "w", encoding="utf-8") as f:
    if out:
        f.write("\n".join(out) + "\n")
PY

  if ! is_clash_yaml "$PROXY_YAML"; then
    msg_err "订阅内容缺少 proxies 字段，无法解析"
    return 1
  fi
}

extract_proxy_names() {
  python3 - "$PROXY_YAML" <<'PY' > "$PROXY_FILE"
import re, sys
path = sys.argv[1]
try:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.read().splitlines()
except Exception:
    sys.exit(0)

names = []
seen = set()
for line in lines:
    if not line or line.lstrip().startswith("#"):
        continue
    m = re.search(r'\bname\s*:\s*', line)
    if not m:
        continue
    s = line[m.end():]
    s = s.strip()
    name = ""
    if s.startswith(("'", '"')):
        q = s[0]
        end = s.find(q, 1)
        if end != -1:
            name = s[1:end]
        else:
            name = s[1:].strip()
    else:
        name = re.split(r'[},#]', s, 1)[0].strip()
        if "," in name:
            name = name.split(",", 1)[0].strip()
    if name and name not in seen:
        seen.add(name)
        names.append(name)

print("\n".join(names))
PY

  if [[ ! -s "$PROXY_FILE" ]]; then
    msg_err "未解析到任何节点名称"
    return 1
  fi
}

get_default_sub() {
  if [[ -f "$SUB_DEFAULT_FILE" ]]; then
    cat "$SUB_DEFAULT_FILE"
  fi
}

set_default_sub() {
  echo "$1" > "$SUB_DEFAULT_FILE"
}

clear_default_sub() {
  rm -f "$SUB_DEFAULT_FILE"
}

auto_sub_name() {
  local url="$1"
  python3 - "$url" <<'PY'
import sys
from urllib.parse import urlsplit
u = sys.argv[1]
name = "订阅"
try:
    p = urlsplit(u)
    if p.hostname:
        name = p.hostname
except Exception:
    pass
print(name)
PY
}

normalize_sub_name() {
  local name="$1"
  name="${name//|/-}"
  name="${name//$'\t'/ }"
  name="${name//$'\r'/ }"
  name="$(echo "$name" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
  if [[ -z "$name" ]]; then
    name="订阅"
  fi
  echo "$name"
}

format_sub_line() {
  local name="$1"
  local url="$2"
  echo "${name}|${url}"
}

sub_exists_url() {
  local url="$1"
  if [[ -z "$url" || ! -f "$SUB_URLS_FILE" ]]; then
    return 1
  fi
  awk -v u="$url" 'NF && $0 !~ /^[[:space:]]*#/ {
    line=$0
    if (index(line,"|")>0) {
      split(line,a,"|")
      url=substr(line, length(a[1])+2)
    } else {
      url=line
    }
    if (url==u) {found=1; exit}
  } END{exit found?0:1}' "$SUB_URLS_FILE"
}

list_subs() {
  local def="${1:-}"
  if [[ ! -s "$SUB_URLS_FILE" ]]; then
    printf "%b\n" "  ${C_YELLOW}（暂无订阅）${C_RESET}"
    return
  fi
  awk -v def="$def" -v w="$SUB_NAME_WIDTH" -v g="$C_GREEN" -v y="$C_YELLOW" -v r="$C_RESET" 'NF && $0 !~ /^[[:space:]]*#/ {
    i++
    line=$0
    name=""
    url=""
    if (index(line,"|")>0) {
      split(line,a,"|")
      name=a[1]
      url=substr(line, length(a[1])+2)
    } else {
      url=line
      name="未命名"
    }
    if (name=="") name="未命名"
    mark=(url==def?g " [默认]" r:"")
    printf "  %2d. %s%-*s%s | %s%s\n", i, y, w, name, r, url, mark
  }' "$SUB_URLS_FILE"
}

get_sub_by_index() {
  local idx="$1"
  if [[ ! -f "$SUB_URLS_FILE" ]]; then
    return
  fi
  awk -v n="$idx" 'NF && $0 !~ /^[[:space:]]*#/ {
    i++
    if (i==n) {
      line=$0
      if (index(line,"|")>0) {
        split(line,a,"|")
        print substr(line, length(a[1])+2)
      } else {
        print line
      }
      exit
    }
  }' "$SUB_URLS_FILE"
}

get_sub_name_by_index() {
  local idx="$1"
  if [[ ! -f "$SUB_URLS_FILE" ]]; then
    return
  fi
  awk -v n="$idx" 'NF && $0 !~ /^[[:space:]]*#/ {
    i++
    if (i==n) {
      line=$0
      if (index(line,"|")>0) {
        split(line,a,"|")
        print a[1]
      } else {
        print "未命名"
      }
      exit
    }
  }' "$SUB_URLS_FILE"
}

get_sub_index_by_url() {
  local url="$1"
  if [[ -z "$url" || ! -f "$SUB_URLS_FILE" ]]; then
    return
  fi
  awk -v u="$url" 'NF && $0 !~ /^[[:space:]]*#/ {
    i++
    line=$0
    if (index(line,"|")>0) {
      split(line,a,"|")
      url=substr(line, length(a[1])+2)
    } else {
      url=line
    }
    if (url==u) {print i; exit}
  }' "$SUB_URLS_FILE"
}

count_subs() {
  if [[ ! -f "$SUB_URLS_FILE" ]]; then
    echo 0
    return
  fi
  awk 'NF && $0 !~ /^[[:space:]]*#/ {c++} END{print c+0}' "$SUB_URLS_FILE"
}

remove_sub_by_index() {
  local idx="$1"
  if [[ -z "$idx" || ! -f "$SUB_URLS_FILE" ]]; then
    return 1
  fi
  awk -v n="$idx" 'NF && $0 !~ /^[[:space:]]*#/ {i++; if(i==n){next}} {print}' "$SUB_URLS_FILE" > "${SUB_URLS_FILE}.tmp" \
    && mv "${SUB_URLS_FILE}.tmp" "$SUB_URLS_FILE"
}

replace_sub_by_index() {
  local idx="$1"
  local new_line="$2"
  if [[ -z "$idx" || -z "$new_line" || ! -f "$SUB_URLS_FILE" ]]; then
    return 1
  fi
  awk -v n="$idx" -v new="$new_line" 'NF && $0 !~ /^[[:space:]]*#/ {i++; if(i==n){print new; next}} {print}' "$SUB_URLS_FILE" > "${SUB_URLS_FILE}.tmp" \
    && mv "${SUB_URLS_FILE}.tmp" "$SUB_URLS_FILE"
}

add_sub() {
  read -p "  输入订阅链接 支持 Clash/Mihomo 或 v2rayN: " SUB
  if [[ -z "$SUB" ]]; then
    msg_warn "未输入订阅链接"
    return
  fi
  if sub_exists_url "$SUB"; then
    msg_warn "订阅已存在"
    return
  fi
  read -p "  订阅名称 可选，回车自动生成: " SUB_NAME
  if [[ -z "$SUB_NAME" ]]; then
    SUB_NAME=$(auto_sub_name "$SUB")
  fi
  SUB_NAME=$(normalize_sub_name "$SUB_NAME")
  local before
  before=$(count_subs)
  format_sub_line "$SUB_NAME" "$SUB" >> "$SUB_URLS_FILE"
  if [[ "$before" -eq 0 ]]; then
    set_default_sub "$SUB"
  fi
  msg_info "已添加订阅"
  update_sub "$SUB"
}

update_sub() {
  local sub_url="${1:-}"
  if [[ -z "$sub_url" ]]; then
    if [[ ! -s "$SUB_URLS_FILE" ]]; then
      msg_warn "未添加订阅，请先选择“添加订阅”"
      return
    fi
    local total
    total=$(count_subs)
    if [[ "$total" -le 0 ]]; then
      msg_warn "未添加订阅，请先选择“添加订阅”"
      return
    fi
    local default_url default_idx prompt idx
    default_url=$(get_default_sub)
    if [[ -n "$default_url" ]]; then
      default_idx=$(get_sub_index_by_url "$default_url")
      if [[ -z "$default_idx" ]]; then
        clear_default_sub
        default_url=""
      fi
    fi
    echo
    line
    msg_title "已保存订阅："
    list_subs "$default_url"
    line
    if [[ -n "$default_idx" ]]; then
      prompt="  选择订阅编号 回车默认 ${default_idx}: "
    elif [[ "$total" -eq 1 ]]; then
      prompt="  选择订阅编号 回车默认 1: "
    else
      prompt="  选择订阅编号: "
    fi
    read -p "$prompt" idx
    if [[ -z "$idx" ]]; then
      if [[ -n "$default_idx" ]]; then
        idx="$default_idx"
      elif [[ "$total" -eq 1 ]]; then
        idx="1"
      fi
    fi
    sub_url=$(get_sub_by_index "$idx")
    if [[ -z "$sub_url" ]]; then
      msg_err "订阅编号无效"
      return
    fi
  fi
  echo
  msg_info "正在下载订阅并解析节点..."

  TMP=$(mktemp)
  TMP_DEC=$(mktemp)
  TMP_NODE=$(mktemp)
  TMP_EMPTY=$(mktemp)
  : > "$TMP_EMPTY"

  local success=0
  local empty_ua=""
  local ua
  local count

  for ua in "$SUB_UA" "Clash" "clash" "Clash for Windows" "ClashX" "clash.meta" "Mihomo" "mihomo" "Shadowrocket" "Quantumult X" "Surge" "Mozilla/5.0"; do
    [[ -z "$ua" ]] && continue
    if ! curl -fsSL --compressed -A "$ua" "$sub_url" -o "$TMP"; then
      continue
    fi

    normalize_yaml "$TMP"
    if is_clash_yaml "$TMP"; then
      count=$(proxy_count "$TMP")
      if [[ "$count" -gt 0 ]]; then
        mv "$TMP" "$SUB_FILE"
        success=1
        break
      fi
      if has_proxy_providers "$TMP"; then
        msg_info "检测到 proxy-providers，尝试合并节点..."
        if convert_providers_to_clash "$TMP" "$ua" "$TMP_NODE"; then
          mv "$TMP_NODE" "$SUB_FILE"
          success=1
          break
        fi
      fi
      cp "$TMP" "$TMP_EMPTY"
      empty_ua="$ua"
      continue
    fi

    if is_node_list "$TMP"; then
      msg_info "识别到节点列表，尝试直接解析..."
      if convert_nodes_to_clash "$TMP" "$TMP_NODE"; then
        mv "$TMP_NODE" "$SUB_FILE"
        success=1
        break
      fi
    fi

    if b64_decode_file "$TMP" "$TMP_DEC"; then
      normalize_yaml "$TMP_DEC"
      if is_clash_yaml "$TMP_DEC"; then
        count=$(proxy_count "$TMP_DEC")
        if [[ "$count" -gt 0 ]]; then
          mv "$TMP_DEC" "$SUB_FILE"
          rm -f "$TMP"
          success=1
          break
        fi
        if has_proxy_providers "$TMP_DEC"; then
          msg_info "检测到 proxy-providers，尝试合并节点..."
          if convert_providers_to_clash "$TMP_DEC" "$ua" "$TMP_NODE"; then
            mv "$TMP_NODE" "$SUB_FILE"
            rm -f "$TMP"
            success=1
            break
          fi
        fi
        cp "$TMP_DEC" "$TMP_EMPTY"
        empty_ua="$ua"
        continue
      fi
      if is_node_list "$TMP_DEC"; then
        msg_info "识别到节点列表，尝试直接解析..."
        if convert_nodes_to_clash "$TMP_DEC" "$TMP_NODE"; then
          mv "$TMP_NODE" "$SUB_FILE"
          rm -f "$TMP"
          success=1
          break
        fi
      fi
    fi
  done

  rm -f "$TMP" "$TMP_DEC" "$TMP_NODE"

  if [[ "$success" -ne 1 ]]; then
    if [[ -n "$empty_ua" ]]; then
      mv "$TMP_EMPTY" "$SUB_FILE"
      echo
      msg_warn "订阅返回 proxies: []（空节点）"
      msg_warn "可能原因：订阅过期/绑定 IP/UA 限制/访问受限"
      msg_warn "已使用的 UA：$empty_ua"
      return
    fi
    rm -f "$TMP_EMPTY"
    if ! convert_sub_to_clash "$sub_url"; then
      return
    fi
  fi

  rm -f "$TMP_EMPTY"

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
  msg_info "解析完成，节点数量：$(wc -l < $PROXY_FILE)"
}

show_subs() {
  local def
  def=$(get_default_sub)
  echo
  line
  msg_title "已保存订阅："
  list_subs "$def"
  line
}

set_default_sub_interactive() {
  if [[ ! -s "$SUB_URLS_FILE" ]]; then
    msg_warn "暂无订阅"
    return
  fi
  local def idx url name
  def=$(get_default_sub)
  echo
  line
  msg_title "已保存订阅："
  list_subs "$def"
  line
  read -p "  选择默认订阅编号: " idx
  url=$(get_sub_by_index "$idx")
  if [[ -z "$url" ]]; then
    msg_err "订阅编号无效"
    return
  fi
  name=$(get_sub_name_by_index "$idx")
  set_default_sub "$url"
  msg_info "已设为默认：${name}"
}

delete_sub_interactive() {
  if [[ ! -s "$SUB_URLS_FILE" ]]; then
    msg_warn "暂无订阅"
    return
  fi
  local def idx url
  def=$(get_default_sub)
  echo
  line
  msg_title "已保存订阅："
  list_subs "$def"
  line
  read -p "  删除订阅编号: " idx
  url=$(get_sub_by_index "$idx")
  if [[ -z "$url" ]]; then
    msg_err "订阅编号无效"
    return
  fi
  remove_sub_by_index "$idx"
  if [[ "$url" == "$def" ]]; then
    clear_default_sub
  fi
  msg_info "已删除订阅"
}

edit_sub_interactive() {
  if [[ ! -s "$SUB_URLS_FILE" ]]; then
    msg_warn "暂无订阅"
    return
  fi
  local def idx old_url old_name new_url new_name line
  def=$(get_default_sub)
  echo
  line
  msg_title "已保存订阅："
  list_subs "$def"
  line
  read -p "  选择订阅编号: " idx
  old_url=$(get_sub_by_index "$idx")
  old_name=$(get_sub_name_by_index "$idx")
  if [[ -z "$old_url" ]]; then
    msg_err "订阅编号无效"
    return
  fi
  read -p "  订阅名称 回车保留 ${old_name}: " new_name
  if [[ -z "$new_name" ]]; then
    new_name="$old_name"
  else
    new_name=$(normalize_sub_name "$new_name")
  fi
  read -p "  订阅链接 回车保留: " new_url
  if [[ -z "$new_url" ]]; then
    new_url="$old_url"
  fi
  if [[ "$new_url" != "$old_url" ]] && sub_exists_url "$new_url"; then
    msg_warn "订阅已存在"
    return
  fi
  line=$(format_sub_line "$new_name" "$new_url")
  replace_sub_by_index "$idx" "$line"
  if [[ "$old_url" == "$def" ]]; then
    set_default_sub "$new_url"
  fi
  msg_info "已修改订阅"
}

manage_subs() {
  while true; do
    echo
    line
    msg_title "订阅管理"
    line
    menu_item "1" "查看订阅"
    menu_item "2" "设为默认"
    menu_item "3" "删除订阅"
    menu_item "4" "修改订阅"
    menu_item "0" "返回上级"
    echo
    read -p "  请输入选项: " n
    case $n in
    1) show_subs; wait_back ;;
    2) set_default_sub_interactive; wait_back ;;
    3) delete_sub_interactive; wait_back ;;
    4) edit_sub_interactive; wait_back ;;
    0) return ;;
    esac
  done
}

build_proxy_list() {
  local active="$1"
  if [[ -n "$active" ]]; then
    echo "      - $(yaml_quote "$active")"
  fi
}

gen_config() {
  if [[ ! -s $PROXY_FILE ]]; then
    msg_warn "未找到节点，请先更新订阅"
    return 1
  fi

  echo "proxy" > "$MODE_FILE"
  ACTIVE_NODE=$(cat $ACTIVE 2>/dev/null || true)
  if [[ -z "$ACTIVE_NODE" ]]; then
    msg_warn "未选择节点，未启动代理"
    return 1
  fi

  cat > "$CONFIG" <<EOL
port: ${HTTP_PORT}
socks-port: ${SOCKS_PORT}
allow-lan: true
bind-address: 0.0.0.0
mode: global
log-level: info
ipv6: false
authentication:
  - "${USER}:${PASS}"

EOL

  cat "$PROXY_YAML" >> "$CONFIG"

  cat >> "$CONFIG" <<EOL
proxy-groups:
  - name: GLOBAL
    type: select
    proxies:
$(build_proxy_list "$ACTIVE_NODE")
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

  IP=$(get_public_ip)
  echo
  line
  printf "%b\n" "  ${C_GREEN}代理已启用${C_RESET}"
  line
  printf "%b\n" "  ${C_CYAN}HTTP  ${C_RESET}: ${C_YELLOW}http://${USER}:${PASS}@${IP}:${HTTP_PORT}${C_RESET}"
  printf "%b\n" "  ${C_CYAN}SOCKS ${C_RESET}: ${C_YELLOW}socks5://${USER}:${PASS}@${IP}:${SOCKS_PORT}${C_RESET}"
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

  IP=$(get_public_ip)
  echo
  line
  printf "%b\n" "  ${C_GREEN}直连代理已启用（无需订阅）${C_RESET}"
  line
  printf "%b\n" "  ${C_CYAN}HTTP  ${C_RESET}: ${C_YELLOW}http://${USER}:${PASS}@${IP}:${HTTP_PORT}${C_RESET}"
  printf "%b\n" "  ${C_CYAN}SOCKS ${C_RESET}: ${C_YELLOW}socks5://${USER}:${PASS}@${IP}:${SOCKS_PORT}${C_RESET}"
  line
}

select_node() {
  if [[ ! -s $PROXY_FILE ]]; then
    msg_warn "未找到节点，请先更新订阅"
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
  msg_title "当前使用节点："
  line
  if [[ -f "$MODE_FILE" ]] && [[ "$(cat "$MODE_FILE")" == "direct" ]]; then
    msg_info "直连模式（无需订阅）"
    line
    return
  fi
  if [[ -s $ACTIVE ]]; then
    cat "$ACTIVE"
  else
    msg_warn "未选择（默认使用列表第一个节点）"
  fi
  line
}

uninstall_all() {
  echo
  read -p "  确认卸载？y/n: " c
  [[ $c != "y" ]] && return

  systemctl stop mihomo-proxy 2>/dev/null
  systemctl disable mihomo-proxy 2>/dev/null
  rm -f /etc/systemd/system/mihomo-proxy.service
  rm -rf $WORKDIR

  echo
  msg_info "已卸载 Mihomo 代理管理环境"
  echo
}

menu() {
  logo
  menu_item "1" "添加订阅"
  menu_item "2" "更新订阅"
  menu_item "M" "订阅管理"
  menu_item "3" "选择节点"
  menu_item "4" "当前状态"
  menu_item "5" "重启服务"
  menu_item "6" "停止服务"
  menu_item "7" "查看日志"
  menu_item "8" "直连模式"
  menu_item "U" "卸载全部"
  menu_item "0" "退出程序"
  echo
  read -p "  请输入选项: " n

  case $n in
  1) add_sub; wait_main ;;
  2) update_sub; wait_main ;;
  M|m) manage_subs ;;
  3) select_node; wait_main ;;
  4) show_status; wait_main ;;
  5)
    systemctl restart mihomo-proxy
    echo
    printf "%b\n" "  ${C_GREEN}代理服务已重启${C_RESET}"
    wait_main
    ;;
  6)
    systemctl stop mihomo-proxy
    echo
    printf "%b\n" "  ${C_GREEN}代理服务已停止${C_RESET}"
    wait_main
    ;;
  7) show_logs; wait_main ;;
  8) direct_mode; wait_main ;;
  0) exit ;;
  U|u) uninstall_all; wait_main ;;
  esac
}

install_mihomo
while true; do menu; done
