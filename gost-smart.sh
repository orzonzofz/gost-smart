#!/usr/bin/env bash

WORKDIR=/etc/gost-smart
mkdir -p $WORKDIR
SUB_FILE=$WORKDIR/sub.txt
OK_FILE=$WORKDIR/ok.txt
ACTIVE=$WORKDIR/active.txt

HTTP_PORT=18080
SOCKS_PORT=18081
TEST_PORT=19090

rand_str() { tr -dc a-z0-9 </dev/urandom | head -c 8; }
USER=$(rand_str)
PASS=$(rand_str)

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
echo "        GOST 智能订阅代理管理面板"
line
echo
}

install_gost() {
if ! command -v gost >/dev/null; then
  bash <(curl -fsSL https://raw.githubusercontent.com/ginuerzh/gost/master/examples/get.sh)
fi
}

test_node() {
NODE="$1"
gost -L "socks5://127.0.0.1:${TEST_PORT}" -F "$NODE" >/dev/null 2>&1 &
PID=$!
sleep 3
RESULT=$(curl --socks5 127.0.0.1:${TEST_PORT} -m 6 -s ip.sb || true)
kill $PID >/dev/null 2>&1

if [[ "$RESULT" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "$NODE" >> $OK_FILE
  echo "     ✔ 可用"
else
  echo "     ✘ 不通"
fi
}

update_sub() {
read -p "  输入订阅链接: " SUB
echo
echo "  正在下载订阅并检测节点可用性..."
> $OK_FILE
curl -s $SUB | base64 -d > $SUB_FILE

i=1
while read -r line; do
  [[ -z "$line" ]] && continue
  printf "  [%02d] 检测节点... " "$i"
  test_node "$line"
  ((i++))
done < $SUB_FILE

echo
echo "  检测完成，可用节点数量：$(wc -l < $OK_FILE)"
}

gen_service() {
NODE=$(cat $ACTIVE)

cat > /etc/systemd/system/gost-proxy.service <<EOL
[Unit]
Description=GOST Smart Proxy
After=network.target

[Service]
ExecStart=/usr/local/bin/gost \
  -L "http://${USER}:${PASS}@:${HTTP_PORT}" \
  -L "socks5://${USER}:${PASS}@:${SOCKS_PORT}" \
  -F "$NODE"
Restart=always

[Install]
WantedBy=multi-user.target
EOL

systemctl daemon-reload
systemctl enable gost-proxy
systemctl restart gost-proxy

IP=$(curl -s ip.sb)
echo
line
echo "  代理已启用"
line
echo "  HTTP  : http://${USER}:${PASS}@${IP}:${HTTP_PORT}"
echo "  SOCKS : socks5://${USER}:${PASS}@${IP}:${SOCKS_PORT}"
line
}

select_node() {
echo
nl -w2 -s'. ' $OK_FILE
echo
read -p "  选择节点编号: " NUM
sed -n "${NUM}p" $OK_FILE > $ACTIVE
gen_service
}

current_node() {
echo
echo "  当前使用节点："
line
cat $ACTIVE 2>/dev/null || echo "  未选择"
line
}

uninstall_all() {
echo
read -p "  确认卸载？(y/n): " c
[[ $c != "y" ]] && return

systemctl stop gost-proxy 2>/dev/null
systemctl disable gost-proxy 2>/dev/null
rm -f /etc/systemd/system/gost-proxy.service
rm -rf $WORKDIR

echo
echo "  已完全卸载 GOST 代理管理环境"
echo
}

menu() {
logo
echo "  1) 更新订阅并智能检测节点"
echo "  2) 选择可用节点作为代理"
echo "  3) 查看当前使用节点"
echo "  4) 重启代理服务"
echo "  5) 卸载所有组件"
echo "  0) 退出"
echo
read -p "  请输入选项: " n

case $n in
1) update_sub ;;
2) select_node ;;
3) current_node ;;
4) systemctl restart gost-proxy ;;
5) uninstall_all ;;
0) exit ;;
esac
}

install_gost
while true; do menu; read -p "  回车返回菜单"; done
