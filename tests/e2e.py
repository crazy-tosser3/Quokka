#!/usr/bin/env python3
"""End-to-end проверка реальных бинарников: mesh из нескольких узлов на одной машине.
Топология задаётся через --no-discovery и --peer: так два узла не видят друг друга напрямую,
как если бы они были далеко. Запуск: e2e.py <quokka> <rogue_client> <quokka_evil>"""
import hashlib
import os
import pty
import random
import re
import resource
import select
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
        """Постоянный ключ сети: сценариям важна топология, а не способ входа."""
        assert self.wait_for("QUIC-порт"), self.text()
        return self.cli("invite", "--full").stdout.strip()

    def short_code(self):
        """Короткий код из баннера нового узла."""
        assert self.wait_for("Код приглашения: "), self.text()
        return self.text().split("Код приглашения: ")[1].split()[0]

    def cli(self, *args):
        return subprocess.run([QUOKKA] + list(args), capture_output=True, text=True, timeout=20, stdin=subprocess.DEVNULL,
                              env=dict(os.environ, QUOKKA_HOME=self.home))

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
    r = run("invite")
    check("invite без запущенного узла", r.returncode == 1 and "не запущен" in r.stderr, r.stderr)
    r = run("status")
    check("status без запущенного узла", r.returncode == 1, r.stderr)
    r = run("connect", "нет")
    check("connect к неизвестной сети", r.returncode != 0 and "нет" in r.stderr, r.stderr)
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
    print("Жизненный цикл сети и личности")
    home = os.path.join(ROOT, "life-home")
    args = ["up", "--no-discovery"]
    a = Node("life-1", args + ["--port", str(free_port())], home=home)
    first = a.invite()
    first_id = re.search(r"\((\w{8})\)", a.text()).group(1)
    check("новая сеть сразу даёт короткий код", re.search(r"[0-9A-Z]{3}-[0-9A-Z]{3}-[0-9A-Z]{3}", a.short_code()) is not None)
    a.stop()
    os.remove(a.log_path)

    a = Node("life-1", args + ["--port", str(free_port())], home=home)
    check("сеть не меняется после перезапуска", a.invite() == first)
    check("идентификатор не меняется", first_id in a.text())
    check("при перезапуске новый код не выдаётся сам", "Код приглашения" not in a.text() and "quokka invite" in a.text(), a.text())
    a.stop()
    os.remove(a.log_path)

    a = Node("life-1", args + ["--port", str(free_port()), "--new-invite"], home=home)
    second = a.invite()
    check("--new-invite создаёт другую сеть", second != first)
    a.stop()

    # Постоянный ключ сети: подходит для автоматизации
    px = free_port()
    x, code = start_network("life-x", px)
    b_home = os.path.join(ROOT, "life-b")
    b = Node("life-b", ["join", code] + isolated(free_port(), [px]), home=b_home)
    check("участник знает тот же ключ", b.invite() == code)
    b.stop()
    again = Node("life-b2", ["connect", "default"], home=b_home)
    check("сеть запомнилась после join", again.wait_for("Сосед подключён"), again.text())
    again.stop()
    x.stop()

    os.chmod(os.path.join(b_home, "node.secret"), 0o644)
    bad = Node("life-perm", ["up", "--no-discovery", "--port", str(free_port())], home=b_home)
    bad.proc.wait(10)
    check("секрет с широкими правами не читается", bad.proc.returncode == 1 and "chmod 600" in bad.text(), bad.text())


def fake_code():
    """Правильно составленный, но чужой код: контрольный символ проходит, попытка тратится на узле."""
    alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
    data = "".join(random.choice(alphabet) for _ in range(8))
    digest = hashlib.sha256(b"quokka-short-code-v1" + data.encode()).digest()
    full = data + alphabet[digest[0] % 32]
    return "%s-%s-%s" % (full[:3], full[3:6], full[6:])


def join_once(name, *args):
    return subprocess.run([QUOKKA, "join"] + list(args), capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL,
                          env=dict(os.environ, QUOKKA_HOME=os.path.join(ROOT, name)))


def join_and_wait(name, code, port, extra=()):
    """Вход по короткому коду. Возвращает работающий узел или None, если код не приняли."""
    node = Node(name, ["join", code, "--no-discovery", "--peer", "127.0.0.1:%d" % port, "--name", name] + list(extra))
    deadline = time.time() + 20
    while time.time() < deadline:
        if node.proc.poll() is not None:
            return None if node.proc.returncode != 0 else node
        if "QUIC-порт" in node.text():
            return node
        time.sleep(0.05)
    raise AssertionError("вход завис: " + node.text())


def invite_cmd(node, *args):
    r = node.cli("invite", *args)
    match = re.search(r"Код приглашения: (\S+)", r.stdout)
    assert match, r.stdout + r.stderr
    return match.group(1), r.stdout


def scenario_short_codes():
    print("Короткие коды приглашения")
    tcp = TcpEcho()
    px = free_port()
    x = Node("code-x", ["up", "--name", "code-x", "--no-discovery", "--port", str(px), "--tcp", str(tcp.port)])
    first = x.short_code()
    check("код короткий и читаемый", re.fullmatch(r"[0-9A-Z]{3}-[0-9A-Z]{3}-[0-9A-Z]{3}", first) is not None, first)
    check("постоянного ключа в баннере нет", "quokka2" not in x.text(), x.text())

    local = free_port()
    a = join_and_wait("code-a", first.lower().replace("-", ""), px, ["--open", "%d=%d" % (tcp.port, local)])
    check("вход по коду в любом регистре и без дефисов", a is not None, x.text())
    check("после входа сеть работает", a is not None and tcp_retry(local, b"paired"))
    check("устройство получило настоящий ключ сети", a is not None and a.invite() == x.invite())
    check("секрет не попал в лог устройства", a is not None and x.invite() not in a.text())
    if a:
        a.stop()

    # Одноразовость
    r = join_once("code-reuse", first, "--no-discovery", "--peer", "127.0.0.1:%d" % px)
    check("код нельзя использовать второй раз", r.returncode == 1 and "код" in r.stderr.lower(), r.stdout + r.stderr)

    # Несколько устройств на один код
    code, output = invite_cmd(x, "--uses", "2")
    check("invite выводит готовую команду", "quokka join " + code in output, output)
    b = join_and_wait("code-b", code, px)
    c = join_and_wait("code-c", code, px)
    check("код на два устройства впускает двоих", b is not None and c is not None)
    r = join_once("code-d", code, "--no-discovery", "--peer", "127.0.0.1:%d" % px)
    check("третьего не впускает", r.returncode == 1, r.stdout + r.stderr)
    for node in (b, c):
        if node:
            node.stop()

    # Срок действия
    code, _ = invite_cmd(x, "--ttl", "1s")
    time.sleep(1.5)
    r = join_once("code-exp", code, "--no-discovery", "--peer", "127.0.0.1:%d" % px)
    check("истёкший код не работает", r.returncode == 1, r.stdout + r.stderr)

    # Опечатка ловится сразу, без обращения к узлу
    code, _ = invite_cmd(x)
    typo = ("B" if code[0] != "B" else "C") + code[1:]
    if typo != code:
        r = join_once("code-typo", typo, "--no-discovery", "--peer", "127.0.0.1:%d" % px)
        check("опечатка в коде опознана", r.returncode == 1, r.stdout + r.stderr)

    # Неверный код не передаёт ключ, настоящий после этого работает
    r = join_once("code-wrong", fake_code(), "--no-discovery", "--peer", "127.0.0.1:%d" % px)
    check("неверный код отклонён", r.returncode == 1 and "не подошёл" in r.stderr, r.stdout + r.stderr)
    check("при неверном коде ключ не сохранён", not os.path.exists(os.path.join(ROOT, "code-wrong", "config.toml")))
    d = join_and_wait("code-e", code, px)
    check("настоящий код после неудачной попытки работает", d is not None)
    if d:
        d.stop()

    # Перебор: после 10 попыток код сгорает, даже настоящий
    code, _ = invite_cmd(x)
    for i in range(10):
        join_once("code-brute", fake_code(), "--no-discovery", "--peer", "127.0.0.1:%d" % px)
    check("перебор замечен", x.wait_for("слишком много попыток", timeout=5), x.text())
    r = join_once("code-after", code, "--no-discovery", "--peer", "127.0.0.1:%d" % px)
    check("после перебора код сгорел", r.returncode == 1, r.stdout + r.stderr)

    # Код чужой сети: узел не подтвердит и ключа своей сети не отдаст
    other = Node("code-other", ["up", "--no-discovery", "--port", str(free_port())])
    other_code = other.short_code()
    r = join_once("code-cross", other_code, "--no-discovery", "--peer", "127.0.0.1:%d" % px)
    check("код другой сети не подходит", r.returncode == 1, r.stdout + r.stderr)
    other.stop()

    # Узел без действующих кодов вообще не отвечает на вход
    r = join_once("code-none", fake_code(), "--no-discovery", "--peer", "127.0.0.1:%d" % px)
    check("без действующих кодов входа нет", r.returncode == 1 and "недоступен" in r.stderr, r.stdout + r.stderr)

    # Переменная окружения
    code, _ = invite_cmd(x)
    node = Node("code-env", ["join", "--no-discovery", "--peer", "127.0.0.1:%d" % px], env={"QUOKKA_INVITE": code})
    check("код из QUOKKA_INVITE", node.wait_for("QUIC-порт", timeout=15), node.text())
    node.stop()

    # Управляющий сокет доступен только владельцу, статус показывает сеть
    sock_path = os.path.join(x.home, "control.sock")
    check("управляющий сокет только для владельца", os.stat(sock_path).st_mode & 0o077 == 0, oct(os.stat(sock_path).st_mode))
    status = x.cli("status")
    check("status показывает узел", status.returncode == 0 and "code-x" in status.stdout and "TCP %d" % tcp.port in status.stdout, status.stdout)
    x.stop()
    check("сокет убран при выходе", not os.path.exists(sock_path))

    # Вход в локальной сети: адрес не нужен
    discovery = free_port()
    lan = Node("code-lan", ["up", "--discovery-port", str(discovery), "--port", str(free_port())])
    lan_code = lan.short_code()
    node = Node("code-lan2", ["join", lan_code, "--discovery-port", str(discovery), "--port", str(free_port())])
    if node.wait_for("QUIC-порт", timeout=15) and node.proc.poll() is None:
        check("вход по коду находит узел в локальной сети сам", True)
        node.stop()
    else:
        print("  skip  multicast недоступен в этом окружении: " + node.text()[-200:])
    lan.stop()


def scenario_vps():
    print("VPS: машины за NAT видят друг друга через публичный узел")
    tcp = TcpEcho()
    pv = free_port()
    public = "127.0.0.1:%d" % pv
    vps = Node("vps", ["server", "--public", public, "--port", str(pv), "--name", "vps"])
    code = vps.short_code()
    check("сервер показывает, куда подключаться", "--peer " + public in vps.text(), vps.text())

    # Домашняя машина: подключается сама, входящие к ней не настроены
    home = join_and_wait("vps-home", code, pv, ["--tcp", str(tcp.port), "--no-relay"])
    check("домашняя машина вошла через VPS", home is not None, vps.text())

    # Код можно выдать прямо с домашней машины: узел передаст его на VPS
    home.wait_for("Сосед подключён", timeout=10)
    home.wait_for("vps", timeout=10)
    time.sleep(1)
    new_code, output = invite_cmd(home)
    check("код с машины за NAT подсказывает адрес VPS", "--peer " + public in output, output)

    local = free_port()
    laptop = join_and_wait("vps-laptop", new_code, pv, ["--open", "%d=%d" % (tcp.port, local), "--no-relay"])
    check("ноутбук вошёл по коду, выданному за NAT", laptop is not None, vps.text())
    check("сервис домашней машины виден", laptop.wait_for("узла vps-home", timeout=20), laptop.text())
    check("связь идёт через VPS", "через 1 промежуточных" in laptop.text(), laptop.text())
    check("TCP через VPS", tcp_retry(local, b"through-vps"))
    check("TCP 4 МиБ через VPS", tcp_roundtrip(local, os.urandom(4 * 1024 * 1024)))

    status = vps.cli("status")
    check("VPS видит обе машины", "vps-home" in status.stdout and "vps-laptop" in status.stdout, status.stdout)

    # Перезапуск VPS: всё восстанавливается само
    vps.kill()
    check("обрыв замечен", laptop.wait_for("недоступен", timeout=25), laptop.text())
    vps.start()
    check("после перезапуска VPS связь вернулась", tcp_retry(local, b"back", timeout=40), laptop.text())

    for node in (laptop, home, vps):
        node.stop()


def scenario_no_relay():
    print("--no-relay: узел не передаёт чужой трафик")
    tcp = TcpEcho()
    pa, pn, pc = free_port(), free_port(), free_port()
    c, code = start_network("nr-c", pc, ["--tcp", str(tcp.port)])
    n = add_node("nr-n", code, pn, [pc], ["--no-relay", "--tcp", str(tcp.port)])
    local = free_port()
    a = add_node("nr-a", code, pa, [pn], ["--open", "nr-n:%d=%d" % (tcp.port, local)])
    check("сам узел доступен", tcp_retry(local, b"direct"), a.text())
    time.sleep(2)
    check("узел за ним недоступен", "Узел nr-c" not in a.text(), a.text())
    for node in (a, n, c):
        node.stop()


def scenario_profiles():
    print("Файл настроек и выбор сети")
    tcp = TcpEcho()
    px = free_port()
    x, code = start_network("prof-x", px, ["--tcp", str(tcp.port)])
    home = os.path.join(ROOT, "prof-home")
    local = free_port()

    # Первый вход сохраняет всё необходимое
    first = Node("prof-1", ["join", code, "--no-discovery", "--peer", "127.0.0.1:%d" % px, "--name", "laptop",
                            "--open", "%d=%d" % (tcp.port, local), "--save", "work"], home=home)
    check("сеть подключена", tcp_retry(local, b"saved"), first.text())
    first.stop()

    listing = Node.cli(first, "list")
    check("list показывает сеть и путь к файлу", "work" in listing.stdout and "config.toml" in listing.stdout and "laptop" in listing.stdout, listing.stdout)
    check("list не выводит ключ сети", code not in listing.stdout, listing.stdout)
    config = os.path.join(home, "config.toml")
    check("файл настроек только для владельца", os.stat(config).st_mode & 0o777 == 0o600)

    # Подключение по имени без всех аргументов
    second = Node("prof-2", ["connect", "work"], home=home)
    check("connect восстанавливает настройки", tcp_retry(local, b"by-name"), second.text())
    second.stop()

    # quokka без аргументов: единственная сеть запускается сразу
    third = Node("prof-3", [], home=home)
    check("quokka без аргументов подключает сеть", tcp_retry(local, b"no-args"), third.text())
    third.stop()

    # Руками написанный файл со всеми настройками и комментариями
    with open(config, "a") as f:
        f.write("""
# запасная сеть
[network.lab]
code = "%s"
name = "лаборатория"
peers = ["127.0.0.1:%d"]
tcp = [%d]
relay = false   # не передавать чужой трафик
discovery = false
port = %d
listeners = 3
""" % (code, px, tcp.port, free_port()))
    lab = Node("prof-4", ["connect", "lab"], home=home)
    check("рукописная сеть работает", lab.wait_for("Сосед подключён"), lab.text())
    check("настройки из файла применены", "лаборатория" in lab.text() and "до 3" in lab.text() and "Транзит:      нет" in lab.text(), lab.text())
    lab.stop()

    # Несколько сетей без терминала: берётся сеть по умолчанию
    default = Node("prof-5", [], home=home)
    check("без терминала берётся сеть по умолчанию", default.wait_for("Сеть:         work"), default.text())
    default.stop()

    # Меню: выбор сети номером в терминале
    master, slave = pty.openpty()
    proc = subprocess.Popen([QUOKKA], stdin=slave, stdout=slave, stderr=slave, env=dict(os.environ, QUOKKA_HOME=home))
    os.close(slave)
    output = b""
    deadline = time.time() + 10
    answered = False
    while time.time() < deadline and b"QUIC" not in output:
        ready, _, _ = select.select([master], [], [], 0.2)
        if ready:
            try:
                output += os.read(master, 4096)
            except OSError:
                break
        if not answered and "Куда подключиться".encode() in output:
            os.write(master, b"lab\n")
            answered = True
    # Терминал нужно читать и при выходе: иначе запись в полный буфер pty заблокирует процесс
    proc.terminate()
    deadline = time.time() + 10
    while proc.poll() is None and time.time() < deadline:
        ready, _, _ = select.select([master], [], [], 0.1)
        if ready:
            try:
                output += os.read(master, 4096)
            except OSError:
                break
    check("из меню узел завершается по SIGTERM", proc.poll() is not None or proc.wait(2) is not None)
    os.close(master)
    text = output.decode("utf-8", "replace")
    check("меню показывает сети", "work" in text and "lab" in text, text)
    check("меню подключает выбранную", "Сеть:         lab" in text, text)

    # Опечатка в файле: понятная ошибка
    with open(config, "a") as f:
        f.write("\n[network.bad]\ncode = \"%s\"\ntpc = [22]\n" % code)
    r = first.cli("connect", "work")
    check("опечатка в настройке объяснена", r.returncode != 0 and "tpc" in r.stderr and "строка" in r.stderr, r.stderr)

    # Файл доступен другим: отказ
    lines = open(config).read().replace('tpc = [22]', '')
    with open(config, "w") as f:
        f.write(lines)
    os.chmod(config, 0o644)
    r = first.cli("list")
    check("файл с широкими правами не читается", r.returncode != 0 and "chmod 600" in r.stderr, r.stderr)
    x.stop()


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
                         scenario_listeners, scenario_duplicate_links, scenario_lifecycle, scenario_short_codes, scenario_vps,
                         scenario_no_relay, scenario_profiles, scenario_backpressure, scenario_flow_limit):
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
