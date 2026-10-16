"""Управление одиночным ISC DHCPv4 через systemd; вызывается только явно."""

import contextlib
from collections.abc import Iterator
import os
import pathlib
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import time


def run_command(command, logger, timeout) -> str:
    """Запускает список аргументов без shell; все команды и ответы идут в журнал."""
    command = [str(value) for value in command]
    logger.info("Команда: %s", shlex.join(command))
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, errors="replace",
            timeout=timeout, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeError(f"Не удалось выполнить {command[0]}: {error}") from error
    if result.stdout.strip():
        logger.info("stdout: %s", result.stdout.strip())
    if result.stderr.strip():
        logger.info("stderr: %s", result.stderr.strip())
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()
        raise RuntimeError(
            f"Команда завершилась с кодом {result.returncode}: "
            f"{shlex.join(command)}; {detail[-2000:]}"
        )
    return result.stdout


def service_state(args, logger) -> dict[str, str]:
    output = run_command(
        [args.systemctl, "--no-ask-password", "show",
         "--property=LoadState,ActiveState,SubState,MainPID", "--", args.service],
        logger, args.service_timeout,
    )
    state = dict(line.split("=", 1) for line in output.splitlines() if "=" in line)
    if state.get("LoadState") != "loaded":
        raise RuntimeError(f"Служба {args.service} не загружена")
    return state


def check_process_binding(args, state) -> None:
    """Не позволяет остановить чужой процесс или изменить чужую базу."""
    pid = int(state.get("MainPID", "0"))
    if pid <= 0:
        raise RuntimeError("У службы нет работающего MainPID")
    process = pathlib.Path("/proc") / str(pid)
    executable = (process / "exe").resolve(strict=True)
    if executable != args.dhcpd.resolve(strict=True):
        raise RuntimeError("MainPID службы не соответствует выбранному dhcpd")
    command = [os.fsdecode(item) for item in (process / "cmdline").read_bytes().split(b"\0") if item]
    if any(option in command for option in ("-6", "-chroot", "-play")):
        raise RuntimeError("Поддерживается только обычный DHCPv4 без chroot/playback")
    for option, expected in (("-cf", args.dhcp_config), ("-lf", args.input)):
        if command.count(option) != 1:
            raise RuntimeError(
                f"У dhcpd нужен явный {option}; проверьте ExecStart выбранной службы"
            )
        index = command.index(option)
        if index + 1 >= len(command):
            raise RuntimeError(f"Нет значения после {option}")
        actual = pathlib.Path(command[index + 1])
        if not actual.is_absolute() or actual.resolve() != expected.resolve():
            raise RuntimeError(f"{option} работающего dhcpd не совпадает с параметрами программы")


def validate_config(args, logger) -> None:
    run_command(
        [args.dhcpd, "-4", "-t", "-cf", args.dhcp_config],
        logger, args.service_timeout,
    )


def validate_lease_file(args, lease_path, logger) -> None:
    """-T не обслуживает сеть, но может создавать свои временные файлы."""
    run_command(
        [args.dhcpd, "-4", "-T", "-cf", args.dhcp_config, "-lf", lease_path],
        logger, args.service_timeout,
    )


def stop_service(args, logger) -> None:
    run_command(
        [args.systemctl, "--no-ask-password", "stop", "--", args.service],
        logger, args.service_timeout,
    )
    state = service_state(args, logger)
    if state.get("ActiveState") not in ("inactive", "failed") or state.get("MainPID") != "0":
        raise RuntimeError("Остановка службы не подтверждена; запись запрещена")
    logger.info("Служба остановлена: %s", args.service)


def start_service(args, logger) -> None:
    run_command(
        [args.systemctl, "--no-ask-password", "start", "--", args.service],
        logger, args.service_timeout,
    )
    # Type=simple может стать active раньше, чем dhcpd завершит инициализацию.
    for attempt in range(3):
        state = service_state(args, logger)
        if state.get("ActiveState") != "active" or state.get("SubState") != "running":
            raise RuntimeError(f"Служба {args.service} не перешла в active/running")
        check_process_binding(args, state)
        if attempt < 2:
            time.sleep(0.2)
    logger.info("Служба запущена и проверена: %s", args.service)


@contextlib.contextmanager
def service_lock(input_path) -> Iterator[None]:
    """Отдельный inode блокировки сохраняется при os.replace() базы."""
    import fcntl

    lock_path = input_path.parent / f".{input_path.name}.dhcp-filter.lock"
    descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise RuntimeError("Путь блокировки не является обычным файлом")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RuntimeError("Эта база уже обрабатывается другим экземпляром программы") from error
        yield
    finally:
        os.close(descriptor)
    # Файл намеренно не удаляется: удаление создало бы гонку разных inode.


def sync_directory(path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def restore_original(args, transaction, logger) -> None:
    """Атомарный откат только после подтверждённой остановки службы."""
    backup = transaction["backup"]
    original = transaction["original"]
    info = transaction["stat"]
    if backup is None or backup.read_bytes() != original:
        raise RuntimeError("Нет проверенной резервной копии для отката")
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", dir=args.input.parent, prefix=f".{args.input.name}.restore.",
            suffix=".tmp", delete=False,
        ) as temporary:
            temporary_path = pathlib.Path(temporary.name)
            temporary.write(original)
            temporary.flush()
            os.fchown(temporary.fileno(), info.st_uid, info.st_gid)
            os.fchmod(temporary.fileno(), stat.S_IMODE(info.st_mode))
            os.fsync(temporary.fileno())
        if temporary_path.read_bytes() != original:
            raise RuntimeError("Проверка файла восстановления не пройдена")
        os.replace(temporary_path, args.input)
        temporary_path = None
        sync_directory(args.input.parent)
        logger.warning("Исходная база восстановлена из %s", backup)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


@contextlib.contextmanager
def service_session(args, logger, create_backup) -> Iterator[dict | None]:
    """Остановка ДО чтения; запуск ПОСЛЕ применения; восстановление при отказах."""
    if not args.manage_service or args.dry_run:
        yield None
        return
    if not sys.platform.startswith("linux") or os.geteuid() != 0:
        raise RuntimeError("--manage-service требует Linux и root (sudo)")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.@:-]*\.service", args.service):
        raise RuntimeError("Укажите полное имя systemd-службы с окончанием .service")
    args.systemctl = shutil.which("systemctl")
    if not args.systemctl:
        raise RuntimeError("systemctl не найден; включите systemd")
    if not args.dhcpd.is_file() or not os.access(args.dhcpd, os.X_OK):
        raise RuntimeError(f"dhcpd не найден или не исполняемый: {args.dhcpd}")
    if not args.dhcp_config.is_file():
        raise RuntimeError(f"Конфигурация DHCP не найдена: {args.dhcp_config}")
    if args.input.is_symlink() or not args.input.is_file() or args.input.stat().st_nlink != 1:
        raise RuntimeError("Для службы нужен обычный исходный файл без ссылок")
    with service_lock(args.input):
        state = service_state(args, logger)
        if state.get("ActiveState") != "active" or state.get("SubState") != "running":
            raise RuntimeError("Управляемый режим требует уже запущенную службу active/running")
        check_process_binding(args, state)
        validate_config(args, logger)
        transaction = {"replaced": False, "backup": None, "original": None, "stat": None}
        try:
            # Включая неуспешную/прерванную stop: ниже будет попытка вернуть службу.
            stop_service(args, logger)
            validate_lease_file(args, args.input, logger)
            yield transaction
            start_service(args, logger)
        except BaseException as original_error:
            logger.exception("Управляемое применение прервано; восстанавливаем исходное состояние")
            try:
                if transaction["replaced"]:
                    # start мог частично запустить процесс, поэтому сначала снова stop.
                    stop_service(args, logger)
                    try:
                        failed_copy = create_backup(args.input, args.backup_dir)
                        logger.info("База перед откатом сохранена отдельно: %s", failed_copy)
                    except (OSError, ValueError):
                        logger.exception("Не удалось сохранить диагностическую копию перед откатом")
                    restore_original(args, transaction, logger)
                start_service(args, logger)
            except BaseException as recovery_error:
                raise RuntimeError(
                    f"Операция не завершена: {original_error}. "
                    f"ВОССТАНОВЛЕНИЕ НЕ УДАЛОСЬ: {recovery_error}. "
                    f"Проверьте {args.service} вручную; копия: {transaction['backup']}"
                ) from recovery_error
            raise
