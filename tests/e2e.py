#!/usr/bin/env python3
"""End-to-end проверка реальных бинарников: mesh из нескольких узлов на одной машине.
Топология задаётся через --no-discovery и --peer: так два узла не видят друг друга напрямую,
как если бы они были далеко. Запуск: e2e.py <quokka> <rogue_client> <quokka_evil>"""
import os
import random
import re
import resource
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

QUOKKA, ROGUE, EVIL = sys.argv[1], sys.argv[2], sys.argv[3]
ROOT = tempfile.mkdtemp(prefix="quokka-e2e-")
procs = []
failures = []
# Ниже эфемерных диапазонов macOS (49152+) и Linux (32768+): эти порты ОС раздаёт сама, в том числе MsQuic
_next_port = random.randint(20000, 30000)


def free_port():
    global _next_port
    _next_port += 1
    return _next_port


class Node:
    def __init__(self, name, args, home=None, env=None, binary=None):
        self.name = name
        self.args = args
        self.binary = binary or QUOKKA
        self.extra_env = env or {}
        self.home = home or os.path.join(ROOT, name)
        self.log_path = os.path.join(ROOT, name + ".log")
        self.start()

    def start(self):
        full_env = dict(os.environ, QUOKKA_HOME=self.home)
        full_env.update(self.extra_env)
        self.log = open(self.log_path, "ab")
        self.proc = subprocess.Popen([self.binary] + self.args, stdout=self.log, stderr=subprocess.STDOUT,
                                     stdin=subprocess.DEVNULL, env=full_env)
        if self not in procs:
            procs.append(self)

    def text(self):
        with open(self.log_path, encoding="utf-8", errors="replace") as f:
            return f.read()

    def wait_for(self, needle, timeout=15):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if needle in self.text():
                return True
            if self.proc.poll() is not None:
                return needle in self.text()
            time.sleep(0.05)
        return False

    def invite(self):
        assert self.wait_for("quokka join "), self.text()
        return self.text().split("quokka join ")[1].split()[0]

    def local_port(self, service_port, timeout=15):
        """Какой локальный порт открыт для сервиса с этим номером."""
        pattern = re.compile(r"(?:TCP|UDP) %d узла .*подключайтесь к 127\.0\.0\.1:(\d+)" % service_port)
        deadline = time.time() + timeout
        while time.time() < deadline:
            found = pattern.findall(self.text())
            if found:
                return int(found[-1])
            time.sleep(0.05)
        raise AssertionError("%s: нет порта для сервиса %d\n%s" % (self.name, service_port, self.text()))

    def stop(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                raise AssertionError("узел %s не завершился по SIGTERM за 10 с" % self.name)
        self.log.close()

    def kill(self):
        self.proc.kill()
        self.proc.wait()
        self.log.close()


def isolated(port, peers=()):
    """Узел без автопоиска с заданными соседями: топология под контролем теста."""
    args = ["--no-discovery", "--port", str(port)]
    for peer in peers:
        args += ["--peer", "127.0.0.1:%d" % peer]
    return args


def start_network(name, port, extra=(), **kw):
    node = Node(name, ["up", "--name", name] + isolated(port) + list(extra), **kw)
    return node, node.invite()


def add_node(name, code, port, peers, extra=(), **kw):
    return Node(name, ["join", code, "--name", name] + isolated(port, peers) + list(extra), **kw)


class UdpEcho:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.sources = set()
        self.received = []
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        while True:
            data, addr = self.sock.recvfrom(65535)
            self.sources.add(addr)
            self.received.append(data)
            self.sock.sendto(data, addr)


class TcpEcho:
    def __init__(self):
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(64)
        self.port = self.sock.getsockname()[1]
        self.accepted = 0
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        while True:
            conn, _ = self.sock.accept()
            self.accepted += 1
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    @staticmethod
    def _serve(conn):
        try:
            while True:
                data = conn.recv(65536)
                if not data:
                    break
                conn.sendall(data)
        except OSError:
            pass
        finally:
            conn.close()


def udp_roundtrip(port, payload=b"ping", timeout=8):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.3)
    deadline = time.time() + timeout
    try:
        while time.time() < deadline:
            sock.sendto(payload, ("127.0.0.1", port))
            try:
                data, _ = sock.recvfrom(65535)
                if data == payload:
                    return True
            except socket.timeout:
                pass
        return False
    finally:
        sock.close()


def tcp_roundtrip(port, payload, timeout=60):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=20) as sock:
            sock.settimeout(timeout)
            sender = threading.Thread(target=sock.sendall, args=(payload,), daemon=True)
            sender.start()
            got = bytearray()
            while len(got) < len(payload):
                chunk = sock.recv(65536)
                if not chunk:
                    break
                got.extend(chunk)
            sender.join(5)
        return bytes(got) == payload
    except OSError:
        return False


def tcp_retry(port, payload, timeout=25):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if tcp_roundtrip(port, payload, timeout=5):
            return True
        time.sleep(0.3)
    return False


def port_is_free(port, kind=socket.SOCK_STREAM):
    sock = socket.socket(socket.AF_INET, kind)
    try:
        sock.bind(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def check(name, ok, details=""):
    print(("  ok    " if ok else "  FAIL  ") + name + (("  -> " + str(details)[-1500:]) if details and not ok else ""), flush=True)
    if not ok:
        failures.append(name)


def cleanup():
    for node in procs:
        if node.proc.poll() is None:
            node.proc.kill()


def rss_mb(proc):
    return int(subprocess.check_output(["ps", "-o", "rss=", "-p", str(proc.pid)]).strip()) / 1024


def scenario_cli():
    print("Понятные ошибки")

    def run(*args):
        return subprocess.run([QUOKKA] + list(args), capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL,
                              env=dict(os.environ, QUOKKA_HOME=os.path.join(ROOT, "cli")))
    r = run("join", "мусор")
    check("join с плохим кодом", r.returncode == 1 and "повреждён" in r.stderr, r.stderr)
    r = run("join")
    check("join без кода и без терминала", r.returncode == 1 and "не указан" in r.stderr, r.stderr)
    r = run("up", "--listeners", "0")
    check("--listeners 0 отклонён", r.returncode == 2, r.stderr)
    r = run("up", "--open", "abc")
    check("--open с мусором отклонён", r.returncode == 2, r.stderr)
    r = run("up", "--name", "a\nb")
    check("--name с управляющим символом отклонён", r.returncode == 2, r.stderr)
    r = run("point", "--udp", "1000")
    check("старой команды point больше нет", r.returncode == 2, r.stderr)
    r = run("--help")
    check("--help", r.returncode == 0 and "--open" in r.stdout and "--peer" in r.stdout)


def scenario_discovery():
    print("Автопоиск: соседи находят друг друга сами")
    tcp, udp = TcpEcho(), UdpEcho()
    discovery = free_port()
    a = Node("disc-a", ["up", "--name", "alice", "--tcp", str(tcp.port), "--udp", str(udp.port), "--discovery-port", str(discovery)])
    code = a.invite()
    check("баннер подсказывает --open для своих сервисов", "--open %d" % tcp.port in a.text(), a.text())
    local_tcp, local_udp = free_port(), free_port()
    b = Node("disc-b", ["join", code, "--name", "bob", "--discovery-port", str(discovery),
                        "--open", "%d=%d" % (tcp.port, local_tcp), "--open", "%d=%d" % (udp.port, local_udp)])
    found = b.wait_for("узла alice", timeout=20)
    if found:
        check("сервис найден без указания адреса", tcp_retry(local_tcp, b"found"))
        check("UDP через автопоиск", udp_roundtrip(local_udp))
        check("узел сообщает, что сосед доступен напрямую", b.wait_for("alice") and "доступен напрямую" in b.text())
    else:
        print("  skip  multicast недоступен в этом окружении")
    b.stop()
    a.stop()

    # На одной машине узлы сами занимают разные QUIC-порты
    x = Node("disc-x", ["up", "--discovery-port", str(free_port()), "--no-discovery"])
    y = Node("disc-y", ["up", "--discovery-port", str(free_port()), "--no-discovery"])
    check("второй узел на машине выбрал другой порт", x.wait_for("QUIC-порт") and y.wait_for("QUIC-порт") and x.proc.poll() is None and y.proc.poll() is None)
    x.stop()
    y.stop()


def scenario_every_node_serves():
    print("Каждый клиент ещё и сервер")
    ta, tb, ub = TcpEcho(), TcpEcho(), UdpEcho()
    pa, pb, pc = free_port(), free_port(), free_port()
    a, code = start_network("srv-a", pa, ["--tcp", str(ta.port)])
    la, lb, lu = free_port(), free_port(), free_port()
    b = add_node("srv-b", code, pb, [pa], ["--tcp", str(tb.port), "--udp", str(ub.port), "--open", "%d=%d" % (ta.port, la)])
    # Открывает порт уже запущенный узел: --open у A задан заранее, а сервис появился позже
    c = add_node("srv-c", code, pc, [pa], ["--open", "%d=%d" % (tb.port, lb), "--open", "%d=%d" % (ub.port, lu)])

    check("B пользуется сервисом A", tcp_retry(la, b"b-to-a"))
    check("C пользуется сервисом B через A", tcp_retry(lb, b"c-to-b"))
    check("UDP от C к B через A", udp_roundtrip(lu))
    check("C видит B через одного промежуточного", c.wait_for("srv-b") and "через 1 промежуточных" in c.text(), c.text())

    # По умолчанию чужие порты на машине не открываются
    check("A без --open не открыл порт B", ta.port != tb.port and "В сети есть TCP %d" % tb.port in a.text() and a.wait_for("--open %d" % tb.port), a.text())
    check("у A нет подключений к порту сервиса B", "узла srv-b" not in a.text())
    for node in (c, b, a):
        node.stop()
    check("штатное завершение", all(n.proc.returncode == 0 for n in (a, b, c)))


def scenario_chain():
    print("Цепочка: A - B - C - D, A и D далеко друг от друга")
    tcp, udp = TcpEcho(), UdpEcho()
    pa, pb, pc, pd = free_port(), free_port(), free_port(), free_port()
    a, code = start_network("chain-a", pa)
    b = add_node("chain-b", code, pb, [pa])
    c = add_node("chain-c", code, pc, [pb])
    local_tcp, local_udp = free_port(), free_port()
    d = add_node("chain-d", code, pd, [pc], ["--tcp", str(tcp.port), "--udp", str(udp.port)])
    a.stop()
    a = add_node("chain-a2", code, pa, [pb], ["--open", "%d=%d" % (tcp.port, local_tcp), "--open", "%d=%d" % (udp.port, local_udp)])

    check("A видит D через двух промежуточных", a.wait_for("chain-d (") and a.wait_for("через 2 промежуточных", timeout=20), a.text())
    check("сервис D открыт на A", a.wait_for("узла chain-d", timeout=20), a.text())
    check("короткий TCP через 2 ретранслятора", tcp_retry(local_tcp, b"hello"))
    check("UDP через 2 ретранслятора", udp_roundtrip(local_udp))
    check("TCP 8 МиБ через 2 ретранслятора без потерь", tcp_roundtrip(local_tcp, os.urandom(8 * 1024 * 1024)))

    results = [None] * 4
    payload = os.urandom(1024 * 1024)

    def run(i):
        results[i] = tcp_roundtrip(local_tcp, payload)
    threads = [threading.Thread(target=run, args=(i,)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    check("4 параллельных TCP через цепочку", results == [True] * 4, results)

    # Кратковременная потеря: ретранслятор падает, маршрута нет, узел возвращается
    b.kill()
    check("A понял, что D недоступен", a.wait_for("chain-d", timeout=5) and a.wait_for("недоступен", timeout=25), a.text())
    check("локальный порт при потере маршрута остался", not port_is_free(local_udp, socket.SOCK_DGRAM))
    b.start()
    check("маршрут восстановился сам (TCP)", tcp_retry(local_tcp, b"back", timeout=40), a.text())
    check("маршрут восстановился сам (UDP)", udp_roundtrip(local_udp, timeout=20))
    for node in (a, d, c, b):
        node.stop()


def scenario_failover():
    print("Обход: ромб A - B - D и A - C - D, один путь падает")
    udp, tcp = UdpEcho(), TcpEcho()
    pa, pb, pc, pd = free_port(), free_port(), free_port(), free_port()
    d, code = start_network("ring-d", pd, ["--udp", str(udp.port), "--tcp", str(tcp.port)])
    b = add_node("ring-b", code, pb, [pd])
    c = add_node("ring-c", code, pc, [pd])
    local_udp, local_tcp = free_port(), free_port()
    a = add_node("ring-a", code, pa, [pb, pc], ["--open", "%d=%d" % (udp.port, local_udp), "--open", "%d=%d" % (tcp.port, local_tcp)])
    check("связь через ромб", udp_roundtrip(local_udp, timeout=20), a.text())

    # Какой бы путь ни был активным, один из двух отказов попадёт именно в него
    for victim, name in ((b, "B"), (c, "C")):
        victim.kill()
        started = time.time()
        check("узел %s упал: UDP пошёл в обход" % name, udp_roundtrip(local_udp, timeout=25), a.text())
        elapsed = time.time() - started
        print("        восстановление за %.1f с" % elapsed)
        check("узел %s упал: обход занял меньше 10 с" % name, elapsed < 10, elapsed)
        check("узел %s упал: TCP работает" % name, tcp_retry(local_tcp, b"around"))
        # Следующий отказ осмыслен, только когда обход снова существует
        before = a.text().count("Сосед подключён")
        victim.start()
        deadline = time.time() + 25
        while a.text().count("Сосед подключён") <= before and time.time() < deadline:
            time.sleep(0.1)
        time.sleep(1)
    for node in (a, b, c, d):
        node.stop()


def scenario_relay_cannot_read():
    print("Злой ретранслятор: читает всё, что проходит через него")
    tcp, udp = TcpEcho(), UdpEcho()
    pa, pe, pc = free_port(), free_port(), free_port()
    tap = os.path.join(ROOT, "tap.bin")
    c, code = start_network("spy-c", pc, ["--tcp", str(tcp.port), "--udp", str(udp.port)])
    e = Node("spy-evil", ["join", code, "--name", "evil"] + isolated(pe, [pc]), binary=EVIL, env={"QUOKKA_EVIL_TAP": tap})
    local_tcp, local_udp = free_port(), free_port()
    a = add_node("spy-a", code, pa, [pe], ["--open", "%d=%d" % (tcp.port, local_tcp), "--open", "%d=%d" % (udp.port, local_udp)])

    tcp_marker = b"SECRET-TCP-MARKER-" + os.urandom(8).hex().encode()
    udp_marker = b"SECRET-UDP-MARKER-" + os.urandom(8).hex().encode()
    check("трафик идёт через ретранслятор (TCP)", tcp_retry(local_tcp, tcp_marker), a.text())
    check("трафик идёт через ретранслятор (UDP)", udp_roundtrip(local_udp, udp_marker))
    check("сервис получил открытый текст (контроль маркера)", udp_marker in udp.received)

    time.sleep(0.5)
    seen = open(tap, "rb").read() if os.path.exists(tap) else b""
    check("контроль: ретранслятор реально видел трафик", len(seen) > len(tcp_marker) + len(udp_marker), len(seen))
    check("в перехваченном нет TCP-данных", tcp_marker not in seen)
    check("в перехваченном нет UDP-данных", udp_marker not in seen)
    # Какой сервис запрошен, ретранслятору тоже не видно: запрос внутри Noise
    for node in (a, e, c):
        node.stop()


def scenario_relay_mitm():
    print("Злой ретранслятор: подставляет себя вместо получателя")
    tcp, udp = TcpEcho(), UdpEcho()
    pa, pe, pc = free_port(), free_port(), free_port()
    c, code = start_network("mitm-c", pc, ["--tcp", str(tcp.port), "--udp", str(udp.port)])
    e = Node("mitm-evil", ["join", code, "--name", "evil"] + isolated(pe, [pc]), binary=EVIL, env={"QUOKKA_EVIL_TERMINATE": "1"})
    local_tcp, local_udp = free_port(), free_port()
    a = add_node("mitm-a", code, pa, [pe], ["--open", "%d=%d" % (tcp.port, local_tcp), "--open", "%d=%d" % (udp.port, local_udp)])
    check("сервис виден через ретранслятор", a.wait_for("узла mitm-c", timeout=20), a.text())

    ok = tcp_roundtrip(local_tcp, b"secret-for-c", timeout=5)
    check("MITM: TCP не прошёл", not ok)
    check("MITM: подмена обнаружена", a.wait_for("подменил ключ", timeout=10), a.text())
    check("MITM: до настоящего сервиса ничего не дошло", tcp.accepted == 0)
    check("MITM: UDP не прошёл", not udp_roundtrip(local_udp, b"secret-udp", timeout=4))
    check("MITM: UDP-данные не получены", not udp.received)
    for node in (a, e, c):
        node.stop()

    # Контроль: тот же путь с честным ретранслятором работает
    pa, pe, pc = free_port(), free_port(), free_port()
    c, code = start_network("mitm2-c", pc, ["--tcp", str(tcp.port)])
    e = Node("mitm2-relay", ["join", code] + isolated(pe, [pc]), binary=EVIL)
    local = free_port()
    a = add_node("mitm2-a", code, pa, [pe], ["--open", "%d=%d" % (tcp.port, local)])
    check("контроль: с честным ретранслятором проходит", tcp_retry(local, b"fine"), a.text())
    for node in (a, e, c):
        node.stop()


def scenario_relay_truncate():
    print("Злой ретранслятор: обрезает данные и выдаёт это за штатный конец")
    tcp = TcpEcho()
    pa, pe, pc = free_port(), free_port(), free_port()
    c, code = start_network("cut-c", pc, ["--tcp", str(tcp.port)])
    e = Node("cut-evil", ["join", code, "--name", "evil"] + isolated(pe, [pc]), binary=EVIL, env={"QUOKKA_EVIL_TRUNCATE": "65536"})
    local = free_port()
    a = add_node("cut-a", code, pa, [pe], ["--open", "%d=%d" % (tcp.port, local)])
    check("сервис виден", a.wait_for("узла cut-c", timeout=20), a.text())

    deadline = time.time() + 15
    outcome = None
    received = 0
    payload = os.urandom(1024 * 1024)
    while time.time() < deadline and outcome is None:
        try:
            sock = socket.create_connection(("127.0.0.1", local), timeout=5)
            sock.settimeout(8)

            def push():
                try:
                    sock.sendall(payload)
                except OSError:
                    pass
            threading.Thread(target=push, daemon=True).start()
            received = 0
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    outcome = "clean-eof"
                    break
                received += len(chunk)
                if received >= len(payload):
                    outcome = "complete"
                    break
        except socket.timeout:
            outcome = "hang"
        except OSError:
            if received > 0:
                outcome = "reset"
    check("обрыв виден программе как ошибка, а не как конец данных", outcome == "reset", "%s, получено %d" % (outcome, received))
    check("узел сообщил об обрыве", a.wait_for("оборван без признака конца", timeout=5), a.text())
    for node in (a, e, c):
        node.stop()

    # Контроль: штатное закрытие через ретранслятор выглядит как обычный конец данных
    pa, pb, pc = free_port(), free_port(), free_port()
    c, code = start_network("eof-c", pc, ["--tcp", str(tcp.port)])
    b = add_node("eof-b", code, pb, [pc])
    local = free_port()
    a = add_node("eof-a", code, pa, [pb], ["--open", "%d=%d" % (tcp.port, local)])
    a.wait_for("узла eof-c", timeout=20)
    time.sleep(0.5)
    sock = socket.create_connection(("127.0.0.1", local), timeout=5)
    sock.settimeout(10)
    sock.sendall(b"half-close")
    sock.shutdown(socket.SHUT_WR)
    got = b""
    while True:
        chunk = sock.recv(100)
        if not chunk:
            break
        got += chunk
    sock.close()
    check("контроль: половинное закрытие доходит через ретранслятор", got == b"half-close", got)

    # Хвост данных не должен теряться: сервис отвечает и сразу закрывает подключение
    def request_response(size):
        s2 = socket.create_connection(("127.0.0.1", local), timeout=5)
        s2.settimeout(15)
        body = os.urandom(size)
        threading.Thread(target=lambda: (s2.sendall(body), s2.shutdown(socket.SHUT_WR)), daemon=True).start()
        got2 = bytearray()
        while True:
            chunk2 = s2.recv(65536)
            if not chunk2:
                break
            got2.extend(chunk2)
        s2.close()
        return bytes(got2) == body
    results = []
    for size in [10] * 20 + [100000] * 10 + [2000000] * 3:
        try:
            results.append(request_response(size))
        except OSError as error:
            results.append(str(error))
    check("33 обмена запрос-ответ через ретранслятор без потери хвоста", all(r is True for r in results), results)
    for node in (a, b, c):
        node.stop()


def scenario_member_limits():
    print("Участник сети может обратиться только к объявленным сервисам")
    tcp, udp, hidden = TcpEcho(), UdpEcho(), TcpEcho()
    px, pe = free_port(), free_port()
    x, code = start_network("mem-x", px, ["--tcp", str(tcp.port), "--udp", str(udp.port)])

    for service, what in (("99", "несуществующий"), ("1", "UDP-сервис как TCP")):
        local = free_port()
        before = tcp.accepted
        e = Node("mem-evil-" + service, ["join", code] + isolated(pe, [px]) + ["--open", "%d=%d" % (tcp.port, local)],
                 binary=EVIL, env={"QUOKKA_EVIL_SERVICE": service})
        e.wait_for("узла mem-x", timeout=15)
        check("запрос '%s' отклонён" % what, not tcp_roundtrip(local, b"x", timeout=4))
        check("запрос '%s' записан в лог" % what, x.wait_for("несуществующий TCP-сервис", timeout=5), x.text())
        check("до сервисов не дошло", tcp.accepted == before and hidden.accepted == 0)
        e.stop()
    x.stop()


def scenario_outsiders():
    print("Посторонние")
    tcp = TcpEcho()
    px, po = free_port(), free_port()
    x, code = start_network("out-x", px, ["--tcp", str(tcp.port)])

    # Без сертификата
    r = subprocess.run([ROGUE, "127.0.0.1", str(px)], capture_output=True, text=True, timeout=30)
    check("клиент без сертификата отбит", r.returncode == 1, r.stdout)
    # С ключом сети, но без подписи узла
    r = subprocess.run([ROGUE, "127.0.0.1", str(px), code], capture_output=True, text=True, timeout=30)
    check("контроль: с ключом сети рукопожатие проходит", "handshake finished" in r.stdout, r.stdout)
    check("без подписи узла поток не принят", r.returncode == 1, r.stdout)
    check("до сервиса никто не дошёл", tcp.accepted == 0)

    # Узел из другой сети
    other, other_code = start_network("out-other", free_port())
    other.stop()
    local = free_port()
    stranger = add_node("out-stranger", other_code, po, [px], ["--open", "%d=%d" % (tcp.port, local)])
    check("узел другой сети не принят", stranger.wait_for("не из этой сети", timeout=15), stranger.text())
    check("узел другой сети не видит сервис", "узла out-x" not in stranger.text() and port_is_free(local))
    stranger.stop()

    # Контроль: с верным кодом тот же путь работает
    member = add_node("out-member", code, free_port(), [px], ["--open", "%d=%d" % (tcp.port, local)])
    check("контроль: с верным кодом подключается", tcp_retry(local, b"member"), member.text())
    member.stop()
    x.stop()


def scenario_listeners():
    print("--listeners и равные узлы")
    udp = UdpEcho()
    px = free_port()
    x, code = start_network("lim-x", px, ["--udp", str(udp.port), "--listeners", "1"])
    la, lb = free_port(), free_port()
    pa, pb = free_port(), free_port()
    a = add_node("lim-a", code, pa, [px], ["--open", "%d=%d" % (udp.port, la)])
    check("первый подключился", udp_roundtrip(la, timeout=15), a.text())

    b = add_node("lim-b", code, pb, [px], ["--open", "%d=%d" % (udp.port, lb)])
    check("второй получил отказ", b.wait_for("не принимает новые соединения", timeout=20), b.text())

    # Посторонний без ключа не занимает место
    subprocess.run([ROGUE, "127.0.0.1", str(px)], capture_output=True, timeout=30)
    subprocess.run([ROGUE, "127.0.0.1", str(px), code], capture_output=True, timeout=30)
    check("первый всё ещё работает", udp_roundtrip(la))

    a.stop()
    check("второй подключился, когда место освободилось", udp_roundtrip(lb, timeout=30), b.text())
    b.stop()
    x.stop()

    print("Без --listeners: 25 узлов, звезда с транзитом через центр")
    udp = UdpEcho()
    hub_port = free_port()
    hub, code = start_network("star-hub", hub_port)
    service_port = free_port()
    owner = add_node("star-owner", code, service_port, [hub_port], ["--udp", str(udp.port)])
    nodes = []
    ports = []
    for i in range(25):
        local = free_port()
        ports.append(local)
        nodes.append(add_node("star-%d" % i, code, free_port(), [hub_port], ["--open", "%d=%d" % (udp.port, local)]))
    check("все работают через центр", all(udp_roundtrip(p, timeout=30) for p in ports))
    check("у каждого свой поток на сервере", len(udp.sources) == 25, len(udp.sources))
    for node in nodes + [owner, hub]:
        node.stop()


def scenario_duplicate_links():
    print("Встречные --peer: между двумя узлами остаётся одно соединение")
    udp = UdpEcho()
    pa, pb = free_port(), free_port()
    a, code = start_network("dup-a", pa, ["--peer", "127.0.0.1:%d" % pb])
    local = free_port()
    b = add_node("dup-b", code, pb, [pa], ["--udp", str(udp.port)])
    a2_local = local
    a.stop()
    a = add_node("dup-a2", code, pa, [pb], ["--open", "%d=%d" % (udp.port, a2_local)])
    check("связь есть", udp_roundtrip(local, timeout=20), a.text())
    time.sleep(8)
    connected = a.text().count("Сосед подключён")
    check("соединение не пересоздаётся постоянно", connected <= 3, a.text())
    check("связь стабильна", udp_roundtrip(local, timeout=5))
    a.stop()
    b.stop()

    # Подключение к самому себе
    p = free_port()
    selfish = Node("dup-self", ["up"] + isolated(p, [p]))
    time.sleep(2)
    check("узел не считает себя соседом", "Сосед подключён" not in selfish.text() and selfish.proc.poll() is None, selfish.text())
    selfish.stop()


def scenario_lifecycle():
    print("Жизненный цикл кода и личности")
    home = os.path.join(ROOT, "life-home")
    args = ["up", "--no-discovery"]
    a = Node("life-1", args + ["--port", str(free_port())], home=home)
    first = a.invite()
    first_id = re.search(r"\((\w{8})\)", a.text()).group(1)
    a.stop()
    os.remove(a.log_path)

    a = Node("life-1", args + ["--port", str(free_port())], home=home)
    check("код не меняется после перезапуска", a.invite() == first)
    check("идентификатор не меняется", first_id in a.text())
    a.stop()
    os.remove(a.log_path)

    a = Node("life-1", args + ["--port", str(free_port()), "--new-invite"], home=home)
    second = a.invite()
    check("--new-invite создаёт другую сеть", second != first)
    a.stop()

    # Любой участник может пригласить следующего: код один на всю сеть
    px = free_port()
    x, code = start_network("life-x", px)
    b_home = os.path.join(ROOT, "life-b")
    b = Node("life-b", ["join", code] + isolated(free_port(), [px]), home=b_home)
    check("участник печатает тот же код", b.invite() == code)
    b.stop()
    again = Node("life-b2", ["join"] + isolated(free_port(), [px]), home=b_home)
    check("join без кода использует сохранённый", again.wait_for("Сосед подключён"), again.text())
    again.stop()
    x.stop()

    os.chmod(os.path.join(b_home, "node.secret"), 0o644)
    bad = Node("life-perm", ["up", "--no-discovery", "--port", str(free_port())], home=b_home)
    bad.proc.wait(10)
    check("секрет с широкими правами не читается", bad.proc.returncode == 1 and "chmod 600" in bad.text(), bad.text())


def scenario_backpressure():
    print("Обратное давление через ретранслятор: сервис перестал читать")

    class SilentTcp:
        def __init__(self):
            self.sock = socket.socket()
            self.sock.bind(("127.0.0.1", 0))
            self.sock.listen(8)
            self.port = self.sock.getsockname()[1]
            self.conns = []
            threading.Thread(target=self._run, daemon=True).start()

        def _run(self):
            while True:
                self.conns.append(self.sock.accept()[0])

    target = SilentTcp()
    pa, pb, pc = free_port(), free_port(), free_port()
    c, code = start_network("bp-c", pc, ["--tcp", str(target.port)])
    b = add_node("bp-b", code, pb, [pc])
    local = free_port()
    a = add_node("bp-a", code, pa, [pb], ["--open", "%d=%d" % (target.port, local)])
    check("подключено", a.wait_for("узла bp-c", timeout=20), a.text())

    base = rss_mb(a.proc), rss_mb(b.proc), rss_mb(c.proc)
    sock = socket.create_connection(("127.0.0.1", local), timeout=5)
    sock.settimeout(5)
    sent = 0
    chunk = b"z" * 65536
    try:
        while sent < 400 * 1024 * 1024:
            sent += sock.send(chunk)
    except socket.timeout:
        pass
    grown = [rss_mb(n.proc) - base[i] for i, n in enumerate((a, b, c))]
    print("        принято %.0f МиБ, рост памяти: A %.0f, ретранслятор %.0f, C %.0f МиБ" % (sent / 1048576, grown[0], grown[1], grown[2]))
    check("отправитель заблокирован, а не бесконечно буферизуется", sent < 100 * 1024 * 1024, sent)
    check("память ретранслятора ограничена", grown[1] < 64, grown[1])
    check("память остальных ограничена", grown[0] < 64 and grown[2] < 64, grown)
    sock.close()
    for node in (a, b, c):
        node.stop()


def scenario_flow_limit():
    print("Предел UDP-потоков на сессию")
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    wanted = 2600 if hard == resource.RLIM_INFINITY else min(hard, 2600)
    resource.setrlimit(resource.RLIMIT_NOFILE, (wanted, hard))
    udp = UdpEcho()
    pa, pc = free_port(), free_port()
    c, code = start_network("flow-c", pc, ["--udp", str(udp.port)])
    local = free_port()
    a = add_node("flow-a", code, pa, [pc], ["--open", "%d=%d" % (udp.port, local)])
    check("подключено", udp_roundtrip(local, timeout=15), a.text())
    resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))

    sockets = []
    for _ in range(1100):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(b"f", ("127.0.0.1", local))
        sockets.append(s)
        if len(sockets) % 100 == 0:
            time.sleep(0.05)
    time.sleep(1.5)
    check("потоков на сервере не больше предела", len(udp.sources) <= 1024, len(udp.sources))
    check("предел действительно достигнут", len(udp.sources) >= 1000, len(udp.sources))
    check("узлы живы", c.proc.poll() is None and a.proc.poll() is None)
    for s in sockets:
        s.close()
    a.stop()
    c.stop()


def main():
    only = set(sys.argv[4:])
    try:
        for scenario in (scenario_cli, scenario_discovery, scenario_every_node_serves, scenario_chain, scenario_failover,
                         scenario_relay_cannot_read, scenario_relay_mitm, scenario_relay_truncate, scenario_member_limits, scenario_outsiders,
                         scenario_listeners, scenario_duplicate_links, scenario_lifecycle, scenario_backpressure,
                         scenario_flow_limit):
            if not only or scenario.__name__.replace("scenario_", "") in only:
                scenario()
    finally:
        cleanup()
    if failures:
        print("\nПровалено: %d. Логи: %s" % (len(failures), ROOT))
        for name in failures:
            print("  - " + name)
        return 1
    shutil.rmtree(ROOT, ignore_errors=True)
    print("\nВсе проверки пройдены")
    return 0


if __name__ == "__main__":
    sys.exit(main())
