#!/usr/bin/env python3
"""Изолированная практическая лаборатория ISC DHCP; стандартная библиотека."""
import argparse
import datetime as dt
import fcntl
import hashlib
import json
import os
import pathlib
import platform
import re
import shlex
import shutil
import signal
import stat
import tempfile
import subprocess
import sys
import time
import uuid

ROOT = pathlib.Path(__file__).resolve().parents[1]
TESTS = ROOT / "tests"
STATE = TESTS / ".lab-state.json"
RESULTS = TESTS / "results"
UTC = dt.timezone.utc
SCENARIOS = {
    "01-address": "Получение IP: DISCOVER → OFFER → REQUEST → ACK",
    "02-selection": "Активные, истёкшие и повторные аренды: фактическое правило",
    "03-subnet": "Фильтрация только целевой подсети",
    "04-safety": "Dry-run, копия и защитные проверки",
    "05-service-cycle": "Остановка, обработка, запуск и новый DHCPACK",
}


def binary_source(name):
    local = TESTS / ".tools/usr/sbin" / name
    return str(local) if local.is_file() else shutil.which(name)

class LabError(RuntimeError):
    pass


def need(condition, message):
    if not condition:
        raise LabError(message)


def utc():
    return dt.datetime.now(UTC)


def records(path):
    """Независимый разбор простых записей нашего dhcpd без импорта фильтра."""
    result = []
    for match in re.finditer(r"(?ms)^lease ([0-9.]+) \{\n.*?^\}", pathlib.Path(path).read_text()):
        block = match.group(0)
        end = re.search(r"(?m)^\s*ends\s+(?:[0-6]\s+)?([^;]+);", block)
        state = re.search(r"(?m)^\s*binding state (\w+);", block)
        result.append({"ip": match[1], "ends": end[1] if end else None,
                       "state": state[1] if state else None, "block": block})
    return result


def latest(path):
    return {entry["ip"]: entry for entry in records(path)}


def end_date(record):
    value = record["ends"]
    return None if not value or value == "never" else dt.datetime.strptime(value, "%Y/%m/%d %H:%M:%S").replace(tzinfo=UTC)


def host_network():
    addresses = json.loads(subprocess.check_output(["ip", "-j", "-4", "address"], text=True))
    routes = json.loads(subprocess.check_output(["ip", "-j", "-4", "route", "show", "table", "all"], text=True))
    return json.loads(json.dumps({
        "addresses": sorted((row["ifname"], row.get("address", ""),
                             sorted((a["local"], a["prefixlen"]) for a in row.get("addr_info", [])))
                            for row in addresses),
        "routes": sorted(json.dumps({k: row[k] for k in ("dst", "gateway", "dev", "table", "type") if k in row},
                                    sort_keys=True) for row in routes),
    }))


class Lab:
    def __init__(self, state=None):
        self.state = state
        self.client_processes = {}
        self.outcomes = []
        self.requested = []
        self.failure = None

    @property
    def directory(self):
        return pathlib.Path(self.state["directory"])

    @property
    def database(self):
        return self.directory / "dhcpd.leases"

    @property
    def server(self):
        return f"dhcp-leases-lab-{self.state['token']}.service"

    @property
    def keeper(self):
        return f"dhcp-leases-lab-{self.state['token']}-keeper.service"

    @property
    def dhcpd(self):
        return self.directory / "bin/dhcpd"

    @property
    def dhclient(self):
        return self.directory / "bin/dhclient"

    def say(self, text=""):
        print(text, flush=True)
        if self.state:
            with (self.directory / "console.log").open("a", encoding="utf-8") as stream:
                stream.write(str(text) + "\n")

    def command(self, command, *, expected=0, timeout=35, quiet=False):
        command = [str(part) for part in command]
        self.say("$ " + shlex.join(command))
        result = subprocess.run(command, text=True, capture_output=True, timeout=timeout)
        if not quiet:
            if result.stdout.strip():
                self.say(result.stdout.rstrip())
            if result.stderr.strip():
                self.say(result.stderr.rstrip())
        if expected is not None:
            need(result.returncode == expected,
                 f"Код {result.returncode}, ожидался {expected}: {shlex.join(command)}\n{result.stderr}")
        return result

    def expect(self, condition, expected, actual):
        self.say("  Ожидается: " + expected)
        self.say("  Фактически: " + str(actual))
        need(condition, expected + "; фактически: " + str(actual))

    def save(self):
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=TESTS,
                                             prefix=".lab-state-", suffix=".tmp", delete=False) as stream:
                temporary = pathlib.Path(stream.name)
                json.dump(self.state, stream, ensure_ascii=False, indent=2)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, STATE)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)

    def unit(self, name):
        result = self.command(["systemctl", "show", "--property=LoadState,ActiveState,SubState,MainPID,Description,NetworkNamespacePath,Transient",
                               "--", name], expected=None, quiet=True)
        data = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
        if data.get("LoadState") == "not-found" or not data:
            return None
        need(result.returncode == 0, "Нельзя прочитать состояние " + name)
        need(data.get("Transient") == "yes", "Отказ: unit не временный: " + name)
        need(data.get("Description") == "dhcp_leases isolated lab " + self.state["token"],
             "Отказ: unit не принадлежит лаборатории: " + name)
        if name == self.server:
            need(data.get("NetworkNamespacePath") == "/run/netns/" + self.state["namespaces"]["server"]["name"],
                 "Отказ: служба ссылается на чужой namespace")
        return data

    def stop(self):
        state = self.unit(self.server)
        if state:
            self.command(["systemctl", "stop", "--", self.server])
            state = self.unit(self.server)
            need(state is None or (state["MainPID"] == "0" and state["ActiveState"] in ("inactive", "failed")),
                 "Лабораторный dhcpd не остановлен")

    def start(self):
        need(self.unit(self.server) is not None, "Временный unit утрачен: выполните cleanup и setup")
        self.command(["systemctl", "start", "--", self.server])
        return self.wait_running()

    def wait_running(self):
        for _ in range(40):
            state = self.unit(self.server)
            if state and state["ActiveState"] == "active" and state["SubState"] == "running":
                pid = int(state["MainPID"])
                if pathlib.Path(f"/proc/{pid}/exe").exists():
                    self.check_process(pid, self.dhcpd, "server", "-lf", self.database)
                    time.sleep(0.3)
                    again = self.unit(self.server)
                    if again and again["MainPID"] == str(pid) and again["SubState"] == "running":
                        return pid
            if state and state["ActiveState"] == "failed":
                break
            time.sleep(0.1)
        log = self.directory / "server.log"
        raise LabError("dhcpd не запустился:\n" + (log.read_text(errors="replace")[-8000:] if log.exists() else ""))

    def check_process(self, pid, executable, namespace, option, value):
        process = pathlib.Path("/proc") / str(pid)
        need((process / "exe").resolve() == executable.resolve(), "Отказ: чужой бинарник PID " + str(pid))
        command = [os.fsdecode(p) for p in (process / "cmdline").read_bytes().split(b"\0") if p]
        need(option in command and command[command.index(option) + 1] == str(value), "Отказ: чужие параметры PID " + str(pid))
        need((process / "ns/net").stat().st_ino == self.state["namespaces"][namespace]["inode"],
             "Отказ: PID находится вне лабораторного namespace")

    def prepare(self):
        need(not STATE.exists() and not STATE.is_symlink(), "Лаборатория уже существует: status.sh или cleanup.sh")
        token = uuid.uuid4().hex[:10]
        RESULTS.mkdir(exist_ok=True)
        need(not RESULTS.is_symlink(), "tests/results не должен быть ссылкой")
        directory = RESULTS / (utc().strftime("%Y%m%dT%H%M%SZ") + "-" + token)
        directory.mkdir(mode=0o755)
        need(not any(c in str(directory) for c in ("\n", "\r", "%")), "Путь проекта содержит перенос строки или %")
        self.state = {"version": 1, "token": token, "directory": str(directory),
                      "namespaces": {}, "clients": [], "host_network": host_network(), "links": []}
        fd = os.open(STATE, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        self.save()
        self.say("Результаты: " + str(directory))
        (directory / "bin").mkdir(mode=0o700)
        for binary in ("dhcpd", "dhclient"):
            shutil.copyfile(binary_source(binary), directory / "bin" / binary)
            (directory / "bin" / binary).chmod(0o700)
        # ZIP/Windows-копия репозитория может потерять executable bit у hook.
        # Исполняем собственную копию с явными правами, не меняя исходники.
        hook = directory / "bin/dhclient-hook.sh"
        shutil.copyfile(TESTS / "scripts/dhclient-hook.sh", hook)
        hook.chmod(0o700)
        shutil.copyfile(TESTS / "config/dhcpd.conf", directory / "dhcpd.conf")
        with (directory / "dhcpd.conf").open("a") as stream:
            stream.write("\nlease-file-name " + json.dumps(str(self.database)) + ";\n")
            stream.write("pid-file-name " + json.dumps(str(directory / "dhcpd.pid")) + ";\n")
        self.database.touch()
        self.database.chmod(0o600)
        for role in ("server", "client-a", "client-b"):
            name = f"dhl-{token}-{role}"
            self.state["namespaces"][role] = {"name": name, "inode": None}
            self.save()
            self.command(["ip", "netns", "add", name])
            self.state["namespaces"][role]["inode"] = pathlib.Path("/run/netns", name).stat().st_ino
            self.save()
            self.command(["ip", "-n", name, "link", "set", "lo", "up"])
        server_ns = self.state["namespaces"]["server"]["name"]
        for number, role in enumerate(("client-a", "client-b")):
            a, b = f"v{token}{number}s", f"v{token}{number}c"
            for link in (a, b):
                need(self.command(["ip", "link", "show", "dev", link], expected=None, quiet=True).returncode != 0,
                     "Имя veth занято: " + link)
            self.state["links"].extend([a, b])
            self.save()
            self.command(["ip", "link", "add", a, "type", "veth", "peer", "name", b])
            self.command(["ip", "link", "set", a, "netns", server_ns])
            self.command(["ip", "-n", server_ns, "link", "set", a, "name", f"srv{number}"])
            client_ns = self.state["namespaces"][role]["name"]
            self.command(["ip", "link", "set", b, "netns", client_ns])
            self.command(["ip", "-n", client_ns, "link", "set", b, "name", "cli0"])
            self.command(["ip", "-n", server_ns, "address", "add", f"10.203.{10 + number * 10}.1/24", "dev", f"srv{number}"])
            self.command(["ip", "-n", server_ns, "link", "set", f"srv{number}", "up"])
            self.command(["ip", "-n", client_ns, "link", "set", "cli0", "up"])
        self.command([self.dhcpd, "-4", "-t", "-cf", directory / "dhcpd.conf"])
        description = "dhcp_leases isolated lab " + token
        self.command(["systemd-run", "--unit", self.server, "--description", description,
                      "--service-type=exec", "--property=Restart=no", "--property=KillMode=control-group",
                      "--property=TimeoutStopSec=10",
                      "--property=NetworkNamespacePath=/run/netns/" + server_ns,
                      "--property=StandardOutput=append:" + str(directory / "server.log"),
                      "--property=StandardError=append:" + str(directory / "server.log"),
                      self.dhcpd, "-4", "-f", "-d", "-cf", directory / "dhcpd.conf",
                      "-lf", self.database, "-pf", directory / "dhcpd.pid", "srv0", "srv1"])
        # Активная oneshot-служба удерживает ссылку: transient unit переживает stop/start.
        self.command(["systemd-run", "--unit", self.keeper, "--description", description,
                      "--service-type=oneshot", "--remain-after-exit",
                      "--property=Wants=" + self.server, "/usr/bin/true"])
        self.wait_running()
        self.say("SETUP OK: три namespace, два veth-кабеля, свой dhcpd; физических подключений нет.")

    def reset(self):
        self.stop()
        self.database.write_text("", encoding="utf-8")
        self.start()

    def stop_client(self, client):
        pid = client["pid"]
        process = pathlib.Path("/proc") / str(pid)
        if process.exists():
            fields = (process / "stat").read_text().split(") ", 1)[1].split()
            if fields[0] != "Z":
                need(fields[19] == client["start_ticks"], "Отказ: PID клиента переиспользован")
                self.check_process(pid, self.dhclient, client["role"], "-lf", pathlib.Path(client["leases"]))
                need(pathlib.Path(client["pidfile"]).read_text().strip() == str(pid), "Отказ: PID-файл клиента не соответствует процессу")
                self.command(["ip", "netns", "exec", self.state["namespaces"][client["role"]]["name"],
                              self.dhclient, "-4", "-x", "-pf", client["pidfile"],
                              "-lf", client["leases"], "-cf", client["config"],
                              "-sf", self.directory / "bin/dhclient-hook.sh",
                              "-e", "LAB_NETNS=net:[" + str(self.state["namespaces"][client["role"]]["inode"]) + "]",
                              "-e", "LAB_EVENTS=" + client["events"], "cli0"], expected=None)
        child = self.client_processes.get(pid)
        if child:
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.check_process(pid, self.dhclient, client["role"], "-lf", pathlib.Path(client["leases"]))
                child.kill()
                child.wait(timeout=5)
        else:
            deadline = time.monotonic() + 5
            while process.exists() and time.monotonic() < deadline:
                time.sleep(0.1)
            if process.exists():
                self.check_process(pid, self.dhclient, client["role"], "-lf", pathlib.Path(client["leases"]))
                os.kill(pid, signal.SIGKILL)
        self.state["clients"] = [item for item in self.state["clients"] if item["pid"] != pid]
        self.save()

    def acquire(self, role="client-a", *, short=False, identity=1):
        namespace = self.state["namespaces"][role]
        octet = 10 if role == "client-a" else 20
        mac = f"02:44:00:00:{1 if role == 'client-a' else 2:02x}:{identity:02x}"
        self.command(["ip", "-n", namespace["name"], "-4", "address", "flush", "dev", "cli0"])
        self.command(["ip", "-n", namespace["name"], "link", "set", "cli0", "address", mac])
        prefix = self.directory / ("client-" + uuid.uuid4().hex[:8])
        config = prefix.with_suffix(".conf")
        template = (TESTS / "config/dhclient.conf").read_text()
        config.write_text(template.replace("172800", "8" if short else "172800")
                          + f"\nsend dhcp-client-identifier 1:{mac};\n", encoding="utf-8")
        client = {"role": role, "leases": str(prefix.with_suffix(".leases")),
                  "pidfile": str(prefix.with_suffix(".pid")), "config": str(config),
                  "events": str(prefix.with_suffix(".events"))}
        command = ["ip", "netns", "exec", namespace["name"], str(self.dhclient),
                   "-4", "-d", "-1", "-v", "-cf", str(config), "-lf", client["leases"],
                   "-pf", client["pidfile"], "-sf", str(self.directory / "bin/dhclient-hook.sh"),
                   "-e", "LAB_NETNS=net:[" + str(namespace["inode"]) + "]",
                   "-e", "LAB_EVENTS=" + client["events"], "cli0"]
        self.say("$ " + shlex.join(command))
        logfile = prefix.with_suffix(".log")
        with logfile.open("w") as stream:
            child = subprocess.Popen(command, stdout=stream, stderr=subprocess.STDOUT)
        client["pid"] = child.pid
        self.client_processes[child.pid] = child
        client["start_ticks"] = pathlib.Path(f"/proc/{child.pid}/stat").read_text().split(") ", 1)[1].split()[19]
        self.state["clients"].append(client)
        self.save()
        try:
            deadline = time.monotonic() + 22
            address = None
            while time.monotonic() < deadline:
                if pathlib.Path(client["events"]).exists():
                    for line in pathlib.Path(client["events"]).read_text().splitlines():
                        parts = line.split()
                        if len(parts) == 2 and parts[0] in ("BOUND", "RENEW", "REBIND", "REBOOT"):
                            address = parts[1]
                if address or child.poll() is not None:
                    break
                time.sleep(0.1)
            messages = logfile.read_text(errors="replace")
            self.say(messages.rstrip())
            need(address is not None, "Клиент не получил адрес; журнал: " + str(logfile))
            need(address.startswith(f"10.203.{octet}."), "Адрес вне ожидаемой подсети")
            self.expect(all(word in messages for word in ("DHCPDISCOVER", "DHCPOFFER", "DHCPREQUEST", "DHCPACK")),
                        "Реальный обмен DISCOVER/OFFER/REQUEST/ACK", str(logfile))
            configured = self.command(["ip", "-j", "-n", namespace["name"], "-4", "address", "show", "dev", "cli0"], quiet=True)
            need(any(a["local"] == address for row in json.loads(configured.stdout) for a in row.get("addr_info", [])),
                 "ACK был, но адрес не назначен интерфейсу")
            for _ in range(30):
                entry = latest(self.database).get(address)
                if entry and entry["state"] == "active" and end_date(entry) and end_date(entry) > utc():
                    break
                time.sleep(0.1)
            else:
                raise LabError("Нет активной серверной записи после DHCPACK")
            self.say("  Адрес интерфейса и активная серверная аренда подтверждены: " + address)
            return address
        finally:
            self.stop_client(client)

    def snapshot(self, name):
        path = self.directory / (name + ".leases")
        shutil.copyfile(self.database, path)
        self.show(path)
        return path

    def show(self, path):
        self.say("Состояние: " + str(path))
        all_records = records(path)
        self.say("  IP               state       ends UTC               записей")
        for ip, entry in sorted(latest(path).items()):
            count = sum(row["ip"] == ip for row in all_records)
            self.say(f"  {ip:<16} {str(entry['state']):<11} {str(entry['ends']):<22} {count}")
        self.say(f"  Блоков: {len(all_records)}; байтов: {pathlib.Path(path).stat().st_size}")

    def filter(self, source, *arguments, expected=0):
        return self.command([sys.executable, "-B", ROOT / "filter_dhcp_leases.py",
                             "--input", source, "--subnet", "10.203.10.0/24",
                             "--hours", "24", *arguments], expected=expected)

    def separate(self, before, label):
        output = self.directory / (label + "-after.leases")
        backups = self.directory / (label + "-backups")
        self.filter(before, "--output", output, "--backup-dir", backups,
                    "--log-file", self.directory / (label + ".log"))
        self.show(output)
        self.expect(before.read_bytes() == self.database.read_bytes(),
                    "Исходник отдельной обработки не изменён", "Сравнение исходных байтов")
        copies = list(backups.glob("*.bak"))
        self.expect(len(copies) == 1 and copies[0].read_bytes() == before.read_bytes(),
                    "Одна побайтовая резервная копия исходника", [str(p) for p in copies])
        return output

    def experiment_01(self):
        self.reset()
        address = self.acquire()
        self.stop()
        before = self.snapshot("01-server")
        entry = latest(before).get(address)
        self.expect(entry is not None and entry["state"] == "active" and end_date(entry) > utc(),
                    "Выданный адрес записан сервером как active", entry)
        self.say("Полный текст созданной записи:\n" + entry["block"])

    def experiment_02(self):
        self.reset()
        active = self.acquire()
        time.sleep(1.1)
        need(active == self.acquire(), "Повторный запрос получил другой IP")
        expired = self.acquire(short=True, identity=17)
        deadline = end_date(latest(self.database)[expired])
        need(deadline is not None and 0 <= (deadline - utc()).total_seconds() <= 15,
             "Сервер не выдал короткую аренду; проверьте min-lease-time")
        self.say("Ждём реального окончания короткой аренды: " + str(deadline))
        while utc() <= deadline + dt.timedelta(seconds=1):
            time.sleep(0.25)
        self.stop()
        before = self.snapshot("02-before")
        need(expired != active, "Короткая аренда должна принадлежать отдельному IP")
        need(end_date(latest(before)[expired]) <= utc(), "Короткая аренда ещё не истекла")
        need(sum(row["ip"] == active for row in records(before)) >= 2,
             "Сервер не сохранил повторные записи; удаление истории не доказано")
        output = self.separate(before, "02")
        expected = [row["block"] for row in records(before) if row["ip"] != active]
        self.expect([row["block"] for row in records(output)] == expected,
                    "Удалена вся история только активного IP с остатком > 24 ч",
                    f"Выбран {active}; истёкший {expired} сохранён")
        need(latest(output).get(expired) == latest(before).get(expired), "Истёкшая запись изменилась")
        self.say("ОГРАНИЧЕНИЕ: текущая программа не очищает истёкшие аренды; их сохранение ожидаемо.")

    def experiment_03(self):
        self.reset()
        first = self.acquire("client-a")
        second = self.acquire("client-b")
        self.stop()
        before = self.snapshot("03-before")
        output = self.separate(before, "03")
        before_other = [row["block"] for row in records(before) if not row["ip"].startswith("10.203.10.")]
        self.expect([row["block"] for row in records(output)] == before_other,
                    "Блоки другой подсети сохранены дословно и в прежнем порядке",
                    f"{first} удалён; {second} сохранён")
        need(first not in latest(output) and second in latest(output), "Неверный состав IP")

    def experiment_04(self):
        self.reset()
        address = self.acquire()
        pid = self.wait_running()
        sandbox = self.directory / "04-dry-run"
        sandbox.mkdir()
        source = sandbox / "source.leases"
        shutil.copyfile(self.database, source)
        original = source.read_bytes()
        self.filter(source, "--apply", "--manage-service", "--service", self.server,
                    "--dhcpd", self.dhcpd, "--dhcp-config", self.directory / "dhcpd.conf",
                    "--backup-dir", sandbox / "backups", "--log-file", sandbox / "dry.log",
                    "--dry-run", "--verbose")
        self.expect(sorted(p.name for p in sandbox.iterdir()) == ["source.leases"] and source.read_bytes() == original,
                    "Dry-run не создаёт файлы и не меняет снимок", sorted(p.name for p in sandbox.iterdir()))
        self.expect(self.wait_running() == pid, "Dry-run не перезапускает dhcpd", "MainPID не изменился")
        rejected = self.filter(source, "--apply", "--manage-service", "--service", self.server,
                    "--dhcpd", self.dhcpd, "--dhcp-config", self.directory / "dhcpd.conf",
                    "--log-file", self.directory / "04-binding-error.log", expected=1)
        need("-lf работающего dhcpd не совпадает" in rejected.stderr, "Отказ получен по другой причине, привязка -lf не доказана")
        self.expect(self.wait_running() == pid and source.read_bytes() == original,
                    "Несовпадение -lf отклонено до остановки службы", "PID и байты прежние")
        self.stop()
        before = self.snapshot("04-before")
        output = self.separate(before, "04")
        need(address not in latest(output), "Выбранный IP не удалён")
        backups = self.directory / "04-backups"
        original_copies = {path: path.read_bytes() for path in backups.glob("*.bak")}
        self.filter(before, "--output", output, "--backup-dir", backups,
                    "--log-file", self.directory / "04-repeat.log")
        self.expect(len(list(backups.glob("*.bak"))) == 2
                    and all(path.read_bytes() == value for path, value in original_copies.items()),
                    "Повторная обработка создаёт новую копию и не перезаписывает старую",
                    [path.name for path in backups.glob("*.bak")])
        rejected = self.filter(before, "--output", before, "--log-file", self.directory / "04-same-path.log", expected=1)
        need("Исходный и результирующий файл должны быть разными" in rejected.stderr, "Не подтверждена причина отказа одинаковых путей")
        need(before.read_bytes() == self.database.read_bytes(), "Отказ одинаковых путей повредил исходник")
        self.say("Защита одинаковых путей подтверждена.")
        malformed = self.directory / "04-malformed.leases"
        malformed.write_text("lease 10.203.10.100 {\n", encoding="utf-8")
        original = malformed.read_bytes()
        rejected = self.filter(malformed, "--apply", "--backup-dir", self.directory / "04-invalid-backups",
                    "--log-file", self.directory / "04-invalid.log", expected=1)
        need("незавершённый блок" in rejected.stderr, "Не подтверждена причина отказа повреждённой базы")
        need(malformed.read_bytes() == original and not (self.directory / "04-invalid-backups").exists(),
             "Некорректная база изменена или дошла до копирования")

    def experiment_05(self):
        self.reset()
        address = self.acquire()
        self.snapshot("05-live-before")
        old_pid = self.wait_running()
        old_invocation = self.command(["systemctl", "show", "-p", "InvocationID", "--value", self.server], quiet=True).stdout.strip()
        backups = self.directory / "05-backups"
        journal = self.directory / "05-filter.log"
        self.filter(self.database, "--apply", "--manage-service", "--service", self.server,
                    "--dhcpd", self.dhcpd, "--dhcp-config", self.directory / "dhcpd.conf",
                    "--backup-dir", backups, "--log-file", journal, "--verbose")
        new_pid = self.wait_running()
        invocation = self.command(["systemctl", "show", "-p", "InvocationID", "--value", self.server], quiet=True).stdout.strip()
        self.expect(new_pid != old_pid and invocation != old_invocation,
                    "Программа остановила и заново запустила свой dhcpd",
                    f"MainPID {old_pid} → {new_pid}; InvocationID изменился")
        copies = list(backups.glob("*.bak"))
        need(len(copies) == 1, "Ожидалась одна резервная копия")
        backup = copies[0]
        need(address in latest(backup), "В копии нет исходной активной аренды")
        expected = [row["block"] for row in records(backup) if row["ip"] != address]
        actual = [row["block"] for row in records(self.database)]
        # dhcpd может переписать заголовок; проверяем все оставшиеся lease-блоки.
        self.expect(actual == expected and address not in latest(self.database),
                    "Выбранный IP отсутствует, остальные lease-блоки сохранены",
                    f"Копия: {backup}; блоки {len(records(backup))} → {len(actual)}")
        events = journal.read_text(encoding="utf-8")
        required = ["Служба остановлена:", "Рабочий файл заменён:", "Служба запущена и проверена:", "Результат: успешно"]
        positions = [events.find(word) for word in required]
        need(all(index >= 0 for index in positions) and positions == sorted(positions),
             "Журнал не подтверждает stop → replace → start → успех")
        self.snapshot("05-after-filter")
        next_address = self.acquire()
        self.expect(latest(self.database).get(next_address, {}).get("state") == "active",
                    "После обслуживания клиент получил новый DHCPACK и активную аренду", next_address)
        self.stop()
        self.snapshot("05-after-new-ack")

    def cleanup(self):
        self.say("\nОчистка только ресурсов лаборатории " + self.state["token"])
        errors = []
        for client in list(self.state["clients"]):
            try:
                self.stop_client(client)
            except (LabError, OSError, subprocess.SubprocessError) as error:
                errors.append(str(error))
        for name in (self.server, self.keeper):
            try:
                if self.unit(name):
                    self.command(["systemctl", "stop", "--", name])
                    stopped = self.unit(name)
                    if stopped and stopped.get("ActiveState") == "failed":
                        # failed удерживает transient unit в systemd даже без процессов.
                        # Сбрасываем отказ только у уже проверенного собственного unit.
                        self.command(["systemctl", "reset-failed", "--", name])
            except (LabError, OSError, subprocess.SubprocessError) as error:
                errors.append(str(error))
        for namespace in self.state["namespaces"].values():
            path = pathlib.Path("/run/netns") / namespace["name"]
            try:
                if not path.exists():
                    continue
                need(namespace["inode"] is not None and path.stat().st_ino == namespace["inode"],
                     "Отказ: принадлежность namespace не подтверждена: " + namespace["name"])
                pids = self.command(["ip", "netns", "pids", namespace["name"]], quiet=True).stdout.strip()
                need(not pids, "Остались процессы; автоматически чужие PID не завершаются: " + pids)
                self.command(["ip", "netns", "delete", namespace["name"]])
                need(not path.exists(), "Namespace не удалён")
            except (LabError, OSError, subprocess.SubprocessError) as error:
                errors.append(str(error))
        for link in self.state["links"]:
            if self.command(["ip", "link", "show", "dev", link], expected=None, quiet=True).returncode == 0:
                try:
                    self.command(["ip", "link", "delete", "dev", link])
                except (LabError, OSError, subprocess.SubprocessError) as error:
                    errors.append(str(error))
        if not errors:
            STATE.unlink()
            if host_network() != self.state["host_network"]:
                errors.append("Сеть хоста отличается от исходной; возможны внешние изменения.")
        if errors:
            raise LabError("Не вся очистка подтверждена:\n" + "\n".join(errors))
        self.say("CLEANUP OK: namespace и процессы удалены; сеть хоста прежняя. Результаты сохранены.")

    def report(self, cleanup_ok):
        completed = [row["scenario"] for row in self.outcomes if row["status"] == "PASS"]
        # Даже прерывание между сценариями не должно превратить неполный прогон в PASS.
        passed = (completed == self.requested and bool(self.requested)
                  and self.failure is None and cleanup_ok is not False)
        rows = list(self.outcomes)
        recorded = {row["scenario"] for row in rows}
        for name in self.requested:
            if name not in recorded:
                rows.append({"scenario": name, "status": "NOT_RUN",
                             "reason": "Сценарий не выполнен: прогон прерван раньше"})

        environment = {"os": platform.platform(), "python": sys.version.split()[0],
                       "distribution": platform.freedesktop_os_release().get("PRETTY_NAME", "не определён")}
        version = subprocess.run(["systemctl", "--version"], text=True, capture_output=True)
        environment["systemd"] = version.stdout.splitlines()[0] if version.stdout.strip() else "не определён"
        server_log = self.directory / "server.log"
        if server_log.is_file():
            match = re.search(r"(?m)^Internet Systems Consortium DHCP Server (.+)$",
                              server_log.read_text(errors="replace"))
            environment["dhcpd"] = match[1] if match else "не определён"
        programs = {}
        for name in ("filter_dhcp_leases.py", "dhcp_service_manager.py"):
            programs[name] = hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
        summary = {
            "status": "PASS" if passed else "FAIL",
            "created_at": utc().isoformat(),
            "requested_scenarios": self.requested,
            "scenarios": rows,
            "cleanup_ok": cleanup_ok,
            "error": self.failure,
            "environment": environment,
            "program_sha256": programs,
            "results": str(self.directory),
        }
        summary_path = self.directory / "summary.json"
        # Читатель results.sh видит только целый JSON, даже если открыт во время записи.
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=self.directory,
                                             prefix=".summary-", suffix=".tmp", delete=False) as stream:
                temporary = pathlib.Path(stream.name)
                json.dump(summary, stream, ensure_ascii=False, indent=2)
                stream.write("\n")
                stream.flush()
                os.fchmod(stream.fileno(), 0o644)
                os.fsync(stream.fileno())
            os.replace(temporary, summary_path)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
        self.say(f"ИТОГ: {summary['status']} | проверено сценариев: {len(completed)}/{len(self.requested)}")
        self.say("Сводка: " + str(summary_path))

    def run(self, scenario, keep):
        selected = list(SCENARIOS) if scenario == "all" else [scenario]
        self.requested = selected
        ok = False
        cleanup_ok = False
        try:
            if self.state is None:
                self.prepare()
            for name in selected:
                self.say("\n" + "=" * 76 + "\n" + name + ": " + SCENARIOS[name] + "\n" + "=" * 76)
                try:
                    getattr(self, "experiment_" + name[:2])()
                except BaseException as error:
                    self.outcomes.append({"scenario": name, "status": "FAIL", "reason": str(error)})
                    self.say("FAIL: " + name + ": " + str(error))
                    raise
                else:
                    self.outcomes.append({"scenario": name, "status": "PASS", "reason": "Проверки ожидаемых данных и действий выполнены"})
                    self.say("PASS: " + name)
            ok = True
        except BaseException as error:
            self.failure = str(error) or type(error).__name__
            raise
        finally:
            if self.state:
                if keep and ok:
                    self.say("--keep: ресурсы сохранены; для удаления sudo bash tests/cleanup.sh")
                else:
                    try:
                        self.cleanup()
                        cleanup_ok = True
                    except BaseException as error:
                        self.failure = str(error) or type(error).__name__
                        self.say("FAIL: очистка: " + str(error))
                        self.report(False)
                        raise
                self.report(None if keep and ok else cleanup_ok)
        return 0 if ok else 1


def show_results(directory=None) -> int:
    """Читает готовый отчёт без root, изменения файлов или управления службой."""
    if directory is None:
        reports = sorted(RESULTS.glob("*/summary.json"))
        need(bool(reports), "Завершённых отчётов пока нет. Запуск: sudo bash tests/run.sh all")
        report_path = reports[-1]
    else:
        directory = directory.resolve()
        need(directory.parent == RESULTS.resolve(), "Выберите каталог запуска внутри tests/results")
        report_path = directory / "summary.json"
    summary = json.loads(report_path.read_text(encoding="utf-8"))
    print("Отчёт:", report_path)
    print("Время UTC:", summary.get("created_at", "нет данных"))
    rows = {row["scenario"]: row for row in summary["scenarios"]}
    for name, description in SCENARIOS.items():
        row = rows.get(name)
        if row is None:
            print(f"  NOT_RUN   {name:<18} {description} (не входил в запуск)")
        else:
            print(f"  {row['status']:<9} {name:<18} {description}")
            if row["status"] != "PASS":
                print("            Причина:", row.get("reason", "нет данных"))
    cleanup = summary.get("cleanup_ok")
    if cleanup is True:
        print("Очистка: подтверждена")
    elif cleanup is False:
        print("Очистка: FAIL")
    else:
        print("Очистка: не выполнялась; проверьте --keep и status.sh")
    if summary.get("error"):
        print("Ошибка:", summary["error"])
    for name, value in summary.get("environment", {}).items():
        print(f"Среда {name}: {value}")
    print("Итог выбранных сценариев:", summary.get("status", "UNKNOWN"))
    print("Полный журнал:", report_path.parent / "console.log")
    return 0 if summary.get("status") == "PASS" else 1


def load_state():
    if not STATE.exists():
        need(not STATE.is_symlink(), "Отказ: state — ссылка")
        return None
    info = STATE.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and not STATE.is_symlink() and info.st_uid == 0 and info.st_mode & 0o022 == 0,
         "Небезопасный state: нужен root-owned файл без записи для остальных")
    data = json.loads(STATE.read_text())
    need(data.get("version") == 1 and re.fullmatch(r"[0-9a-f]{10}", data.get("token", "")), "Некорректное состояние")
    directory = pathlib.Path(data["directory"])
    need(directory.parent == RESULTS.resolve() and directory.resolve() == directory and directory.is_dir(),
         "Путь результатов вне tests/results")
    token = data["token"]
    need(directory.name.endswith("-" + token), "Token не соответствует каталогу")
    for role, namespace in data["namespaces"].items():
        need(role in ("server", "client-a", "client-b") and namespace["name"] == f"dhl-{token}-{role}",
             "Некорректное имя namespace")
    need(all(re.fullmatch(f"v{token}[01][sc]", link) for link in data["links"]), "Некорректное имя veth")
    return data


def preflight(require_root):
    need(sys.version_info >= (3, 10), "Требуется Python 3.10 или новее")
    need(sys.platform.startswith("linux"), "Нужен Linux с network namespaces и systemd")
    missing = [name for name in ("ip", "dhcpd", "dhclient", "systemctl", "systemd-run") if not (binary_source(name) if name in ("dhcpd", "dhclient") else shutil.which(name))]
    need(not missing, "Не найдены команды: " + ", ".join(missing))
    need(pathlib.Path("/proc/1/comm").read_text().strip() == "systemd", "PID 1 должен быть systemd")
    need((ROOT / "filter_dhcp_leases.py").is_file() and (ROOT / "dhcp_service_manager.py").is_file(), "Не найдены модули проекта")
    if require_root:
        need(os.geteuid() == 0, "Нужен sudo, CAP_NET_ADMIN, CAP_SYS_ADMIN и доступ к systemd")
    print("Зависимости найдены; PID 1 = systemd. UID =", os.geteuid(), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("check", "setup", "run", "status", "cleanup", "report"))
    parser.add_argument("scenario", nargs="?", choices=("all", *SCENARIOS), default="all")
    parser.add_argument("--keep", action="store_true", help="Сохранить ресурсы только после успешного run")
    parser.add_argument("--results", type=pathlib.Path, help="Каталог конкретного отчёта внутри tests/results")
    args = parser.parse_args()
    if args.results is not None and args.action != "report":
        parser.error("--results используется только для report/results.sh")
    os.environ["PATH"] = "/usr/sbin:/usr/bin:/sbin:/bin"
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    if args.action == "report":
        return show_results(args.results)
    if args.action == "check":
        preflight(False)
        for name, description in SCENARIOS.items():
            print(name + ": " + description)
        return 0
    need(os.geteuid() == 0, "Эта команда требует sudo")
    descriptor = os.open(TESTS / ".lab.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise LabError("Другая команда лаборатории ещё работает") from error
        state = load_state()
        lab = Lab(state)
        if args.action == "cleanup":
            if state:
                lab.cleanup()
            else:
                print("Нет зарегистрированной лаборатории; чужие ресурсы не затрагиваются.")
            return 0
        if args.action == "status":
            if state:
                lab.say(json.dumps(state, ensure_ascii=False, indent=2))
                lab.say(str(lab.unit(lab.server)))
            else:
                print("Лаборатория не создана.")
            return 0
        preflight(True)
        if args.action == "setup":
            need(state is None, "Лаборатория уже создана: status или cleanup")
            try:
                lab.prepare()
            except BaseException:
                if lab.state:
                    lab.cleanup()
                raise
            return 0
        return lab.run(args.scenario, args.keep)


if __name__ == "__main__":
    def interrupt(signum, frame):
        raise KeyboardInterrupt("Получен сигнал " + str(signum))
    signal.signal(signal.SIGTERM, interrupt)
    try:
        sys.exit(main())
    except (LabError, OSError, ValueError, subprocess.SubprocessError, KeyboardInterrupt) as error:
        print("FAIL: " + str(error), file=sys.stderr)
        sys.exit(1)
