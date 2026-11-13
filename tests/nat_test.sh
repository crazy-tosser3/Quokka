#!/usr/bin/env bash
# Настоящий NAT в Docker: две машины с серыми адресами за разными роутерами и VPS с публичным адресом.
#
#   home (10.1.0.0/24) -- router1 --\
#                                    public (172.30.0.0/24) -- vps
#   laptop (10.2.0.0/24) -- router2 --/
#
# Между home и laptop нет маршрута, а снаружи к ним нельзя подключиться. Нужны Docker и права NET_ADMIN.
# Запуск: tests/nat_test.sh
set -u

IMAGE=quokka:nat-test
PREFIX=qknat
FAILED=0

ok() { echo "  ok    $1"; }
bad() { echo "  FAIL  $1"; [ $# -gt 1 ] && echo "$2" | tail -15; FAILED=1; }
check() { if eval "$2"; then ok "$1"; else bad "$1" "${3:-}"; fi; }

cleanup() {
  docker rm -f $PREFIX-vps $PREFIX-r1 $PREFIX-r2 $PREFIX-home $PREFIX-laptop >/dev/null 2>&1
  docker network rm $PREFIX-pub $PREFIX-l1 $PREFIX-l2 >/dev/null 2>&1
}
trap cleanup EXIT
cleanup

docker build -q --target nat-test -t $IMAGE "$(dirname "$0")/.." >/dev/null || exit 2

docker network create --subnet 172.30.0.0/24 $PREFIX-pub >/dev/null
docker network create --subnet 10.1.0.0/24 $PREFIX-l1 >/dev/null
docker network create --subnet 10.2.0.0/24 $PREFIX-l2 >/dev/null

run() {  # имя сеть ip
  docker run -d --name $PREFIX-$1 --hostname $1 --network $PREFIX-$2 --ip $3 --cap-add NET_ADMIN \
    --sysctl net.ipv4.ip_forward=1 $IMAGE sleep infinity >/dev/null
}
sh_in() { docker exec "$PREFIX-$1" sh -c "$2"; }
# Ждёт строку в логе узла, возвращает секунды ожидания
wait_log() {  # контейнер строка таймаут
  local start=$SECONDS
  while [ $((SECONDS - start)) -lt "$3" ]; do
    if sh_in "$1" "grep -q '$2' /tmp/q.log 2>/dev/null"; then return 0; fi
    sleep 0.2
  done
  return 1
}

run vps pub 172.30.0.10
run r1 pub 172.30.0.2
run r2 pub 172.30.0.3
docker network connect --ip 10.1.0.2 $PREFIX-l1 $PREFIX-r1
docker network connect --ip 10.2.0.2 $PREFIX-l2 $PREFIX-r2
run home l1 10.1.0.10
run laptop l2 10.2.0.10

# Роутеры: исходящие подменяют адрес на свой, входящие без установленного соединения отбрасываются
for r in r1 r2; do
  pub_if=$(sh_in $r "ip -o addr show | awk '/172\\.30\\./{print \$2}'")
  sh_in $r "iptables -t nat -A POSTROUTING -o $pub_if -j MASQUERADE \
    && iptables -A FORWARD -i $pub_if -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT \
    && iptables -A FORWARD -i $pub_if -j DROP" || { echo "iptables недоступен"; exit 2; }
done
sh_in home "ip route replace default via 10.1.0.2"
sh_in laptop "ip route replace default via 10.2.0.2"

echo "Сеть"
check "home выходит в публичную сеть только через NAT" \
  "sh_in home 'python3 -c \"import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.connect((\\\"172.30.0.10\\\",1));print(s.getsockname()[0])\"' | grep -q 10.1.0.10"
# Контроль: прямой путь между серыми адресами и снаружи к ним действительно закрыт
cat > /tmp/qknat_udp.py <<'PY'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(1.0)
try:
    s.sendto(b"x", (sys.argv[1], int(sys.argv[2])))
    s.recvfrom(10)
    print("reached")
except OSError:
    print("blocked")
PY
for c in vps home laptop; do docker cp /tmp/qknat_udp.py $PREFIX-$c:/tmp/udp.py >/dev/null; done
sh_in home "python3 -c \"
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('0.0.0.0',9));
while True:
    d,a=s.recvfrom(10);s.sendto(d,a)
\"" >/dev/null 2>&1 &
sleep 1
# Контроль стенда: без этого все проверки ниже бессмысленны
sh_in vps "python3 -c \"
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('0.0.0.0',9));
while True:
    d,a=s.recvfrom(10);print(a,flush=True);s.sendto(d,a)
\"" >/tmp/qknat_probe.log 2>&1 &
PROBE=$!
sleep 1
check "контроль: UDP из-за NAT на VPS проходит" "[ \"\$(sh_in home 'python3 /tmp/udp.py 172.30.0.10 9')\" = reached ]"
check "контроль: VPS видит не серый адрес, а адрес роутера" "grep -q 172.30.0.2 /tmp/qknat_probe.log" "$(cat /tmp/qknat_probe.log)"
kill $PROBE 2>/dev/null; wait $PROBE 2>/dev/null
sh_in vps "pkill -f 'bind' 2>/dev/null; true"
check "контроль: с ноутбука до домашней машины нет пути" "[ \"\$(sh_in laptop 'python3 /tmp/udp.py 10.1.0.10 9')\" = blocked ]"
check "контроль: с VPS до домашней машины нет пути" "[ \"\$(sh_in vps 'python3 /tmp/udp.py 10.1.0.10 9')\" = blocked ]"

echo "Вход через VPS"
docker exec -d $PREFIX-vps sh -c 'exec quokka server --public 172.30.0.10 --name vps >/tmp/q.log 2>&1'
wait_log vps 'Код приглашения' 10
CODE=$(sh_in vps "grep -o 'Код приглашения: [^ ]*' /tmp/q.log | cut -d' ' -f3")
check "VPS выдал короткий код" "[ -n \"$CODE\" ]" "$(sh_in vps 'cat /tmp/q.log')"

cat > /tmp/qknat_echo.py <<'PY'
import socket, threading
def udp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("127.0.0.1", 7000))
    while True:
        d, a = s.recvfrom(65535); s.sendto(d, a)
threading.Thread(target=udp, daemon=True).start()
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); srv.bind(("127.0.0.1", 8000)); srv.listen(16)
def serve(c):
    try:
        while True:
            d = c.recv(65536)
            if not d: break
            c.sendall(d)
    finally:
        c.close()
while True:
    threading.Thread(target=serve, args=(srv.accept()[0],), daemon=True).start()
PY
cat > /tmp/qknat_client.py <<'PY'
import hashlib, os, socket, sys, threading, time
kind, port = sys.argv[1], int(sys.argv[2])
if kind == "udp":
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(1)
    deadline = time.time() + float(sys.argv[3])
    while time.time() < deadline:
        try:
            s.sendto(b"ping", ("127.0.0.1", port))
            if s.recvfrom(100)[0] == b"ping":
                print("ok"); sys.exit(0)
        except OSError:
            pass
    print("fail"); sys.exit(1)
if kind == "udprate":
    # Доля пакетов, вернувшихся с заданной скоростью, и средняя задержка
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(0.5)
    got, rtt = 0, []
    for i in range(200):
        t = time.time()
        s.sendto(b"p" * 200, ("127.0.0.1", port))
        try:
            s.recvfrom(1000); got += 1; rtt.append(time.time() - t)
        except OSError:
            pass
        time.sleep(0.01)
    print("%d %.0f" % (got, 1000 * sum(rtt) / max(1, len(rtt))))
    sys.exit(0)
size = int(sys.argv[3])
body = os.urandom(size)
s = socket.create_connection(("127.0.0.1", port), timeout=20); s.settimeout(120)
t = time.time()
threading.Thread(target=s.sendall, args=(body,), daemon=True).start()
got = bytearray()
while len(got) < size:
    d = s.recv(65536)
    if not d: break
    got.extend(d)
ok = hashlib.sha256(got).digest() == hashlib.sha256(body).digest()
print("%s %.2f" % ("ok" if ok else "fail", time.time() - t))
sys.exit(0 if ok else 1)
PY
docker cp /tmp/qknat_echo.py $PREFIX-home:/tmp/echo.py >/dev/null
docker cp /tmp/qknat_client.py $PREFIX-laptop:/tmp/client.py >/dev/null
docker exec -d $PREFIX-home python3 /tmp/echo.py

docker exec -d $PREFIX-home sh -c "exec quokka join $CODE --peer 172.30.0.10 --name home --tcp 8000 --udp 7000 >/tmp/q.log 2>&1"
T0=$(python3 -c 'import time;print(time.time())')
wait_log home 'Сосед подключён' 25
echo "        вход занял $(python3 -c "import time;print(round(time.time()-$T0,1))") с"
check "домашняя машина вошла по короткому коду" "sh_in home 'grep -q \"Сосед подключён\" /tmp/q.log'" "$(sh_in home 'cat /tmp/q.log')"
wait_log home 'vps' 10; sleep 1

# Код выдаётся прямо с машины за NAT, а новое устройство входит через VPS
OUT=$(sh_in home 'quokka invite')
CODE2=$(echo "$OUT" | grep -o 'Код приглашения: [^ ]*' | cut -d' ' -f3)
check "код с машины за NAT подсказывает адрес VPS" "echo \"\$OUT\" | grep -q -- '--peer 172.30.0.10'" "$OUT"
docker exec -d $PREFIX-laptop sh -c "exec quokka join $CODE2 --peer 172.30.0.10 --name laptop --open home:8000=18000 --open home:7000=17000 >/tmp/q.log 2>&1"
wait_log laptop 'Сосед подключён' 25
wait_log laptop 'узла home' 15
check "ноутбук вошёл по этому коду" "sh_in laptop 'grep -q \"Сосед подключён\" /tmp/q.log'" "$(sh_in laptop 'cat /tmp/q.log'; sh_in vps 'cat /tmp/q.log')"

echo "Связь между машинами за NAT"
check "сервис домашней машины виден" "sh_in laptop 'grep -q \"узла home\" /tmp/q.log'" "$(sh_in laptop 'cat /tmp/q.log')"
check "путь идёт через VPS" "sh_in laptop 'grep -q \"home.*через 1 промежуточных\" /tmp/q.log'" "$(sh_in laptop 'cat /tmp/q.log')"
check "UDP" "sh_in laptop 'python3 /tmp/client.py udp 17000 10' | grep -q ok"
R=$(sh_in laptop 'python3 /tmp/client.py tcp 18000 8000000'); check "TCP 8 МБ: $R" "echo '$R' | grep -q ok"
check "VPS видит обе машины" "sh_in vps 'quokka status' | grep -q home && sh_in vps 'quokka status' | grep -q laptop"

echo "Плохая связь: 50 мс в каждую сторону на роутерах и 2% потерь"
for r in r1 r2; do
  pub_if=$(sh_in $r "ip -o addr show | awk '/172\\.30\\./{print \$2}'")
  sh_in $r "tc qdisc add dev $pub_if root netem delay 25ms 5ms loss 1%" || NO_NETEM=1
done
if [ "${NO_NETEM:-0}" = 1 ]; then
  echo "  skip  netem недоступен"
else
  sleep 1
  R=$(sh_in laptop 'python3 /tmp/client.py udprate 17000'); GOT=${R% *}; RTT=${R#* }
  check "UDP: вернулось $GOT из 200, задержка $RTT мс" "[ $GOT -ge 170 ]"
  R=$(sh_in laptop 'python3 /tmp/client.py tcp 18000 4000000'); check "TCP 4 МБ без искажений: $R" "echo '$R' | grep -q ok"
  S=$(sh_in laptop 'quokka status'); check "соединения не рвутся при потерях" "! sh_in laptop 'grep -q \"не отвечает\" /tmp/q.log'" "$S"
  for r in r1 r2; do
    pub_if=$(sh_in $r "ip -o addr show | awk '/172\\.30\\./{print \$2}'")
    sh_in $r "tc qdisc del dev $pub_if root" ;
  done
fi

echo "Сохранность связи"
echo "        простой 40 с: NAT не должен забыть соединение"
sleep 40
check "после простоя связь на месте" "sh_in laptop 'python3 /tmp/client.py udp 17000 5' | grep -q ok"
check "после простоя соединение не пересоздавалось" "[ \$(sh_in laptop 'grep -c \"Сосед подключён\" /tmp/q.log') = 1 ]" "$(sh_in laptop 'cat /tmp/q.log')"

# Роутер забывает все соединения, как при перезагрузке: внешний порт ноутбука меняется
OLD_PORT=$(sh_in r2 "conntrack -L -p udp -d 172.30.0.10 2>/dev/null" | grep -o 'dport=[0-9]*' | tail -1)
sh_in r2 "pub_if=\$(ip -o addr show | awk '/172\\.30\\./{print \$2}'); iptables -t nat -F POSTROUTING; iptables -t nat -A POSTROUTING -o \$pub_if -p udp -j MASQUERADE --to-ports 40000-40100; conntrack -F" >/dev/null 2>&1
echo "        роутер ноутбука сбросил таблицу NAT"
check "связь есть и после смены внешнего порта" "sh_in laptop 'python3 /tmp/client.py udp 17000 25' | grep -q ok" "$(sh_in laptop 'tail -5 /tmp/q.log')"
NEW_PORT=$(sh_in r2 "conntrack -L -p udp -d 172.30.0.10 2>/dev/null" | grep -o 'dport=4[0-9]*' | tail -1)
check "контроль: внешний порт действительно сменился ($NEW_PORT)" "[ -n \"$NEW_PORT\" ]" "$(sh_in r2 'conntrack -L -p udp 2>/dev/null')"
R=$(sh_in laptop 'python3 /tmp/client.py tcp 18000 1000000'); check "TCP после смены порта: $R" "echo '$R' | grep -q ok"

docker restart -t 1 $PREFIX-vps >/dev/null
docker exec -d $PREFIX-vps sh -c 'exec quokka connect default >/tmp/q.log 2>&1'
echo "        перезапуск VPS"
check "после перезапуска VPS связь вернулась" "sh_in laptop 'python3 /tmp/client.py udp 17000 40' | grep -q ok" "$(sh_in laptop 'tail -5 /tmp/q.log'; sh_in vps 'cat /tmp/q.log')"
R=$(sh_in laptop 'python3 /tmp/client.py tcp 18000 1000000'); check "TCP после перезапуска: $R" "echo '$R' | grep -q ok"

rm -f /tmp/qknat_*.py
if [ $FAILED = 0 ]; then echo; echo "NAT: все проверки пройдены"; else echo; echo "NAT: есть ошибки"; exit 1; fi
