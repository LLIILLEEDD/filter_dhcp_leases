"""Фильтрация DHCPv4-лиз с резервной копией и управлением службой dhcpd."""

import argparse
import datetime
import ipaddress
import logging
import os
import pathlib
import re
import shutil
import stat
import sys
import tempfile
import time
import uuid

from dhcp_service_manager import service_session, sync_directory, validate_lease_file


DEFAULT_INPUT_PATH = pathlib.Path("./dhcpd.leases")
DEFAULT_OUTPUT_PATH = pathlib.Path("./dhcpd.filtered.leases")
DATE_FORMAT = "%Y/%m/%d %H:%M:%S"
DEFAULT_LOG_PATH = pathlib.Path("./filter_dhcp_leases.log")


# 1. Параметры запуска
# ----------------------------------------------------------------------


def parse_arguments(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Выбор активных DHCPv4-лиз с остатком аренды больше заданного порога. "
            "По умолчанию результат пишется отдельно; --apply заменяет исходник."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        allow_abbrev=False,
    )
    parser.add_argument(
        "-i", "--input", type=pathlib.Path, default=DEFAULT_INPUT_PATH,
        help="Путь к исходному файлу лиз",
    )
    parser.add_argument(
        "-o", "--output", type=pathlib.Path, default=None,
        help=f"Отдельный результат (по умолчанию {DEFAULT_OUTPUT_PATH}); несовместим с --apply",
    )
    parser.add_argument(
        "-s", "--subnet", type=parse_subnet, required=True,
        help="Целевая подсеть IPv4, например 10.201.90.0/24",
    )
    parser.add_argument(
        "--check-date", type=parse_check_date, default=None, metavar="DATE",
        help='Дата проверки в UTC: "2026/08/18 10:20:00"; без параметра — текущее время',
    )
    parser.add_argument(
        "--hours", type=parse_hours, default=24,
        help="Остаток аренды должен быть строго больше этого количества часов",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Рассчитать и показать результат, не создавая и не изменяя файлы",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Дополнительно показать все последние лизы в целевой подсети",
    )
    parser.add_argument(
        "--apply", action="store_true",
        help="Заменить исходный файл после резервного копирования и проверки временного файла",
    )
    parser.add_argument(
        "--backup-dir", type=pathlib.Path, default=None,
        help="Папка резервных копий; по умолчанию рядом с исходным файлом",
    )
    parser.add_argument(
        "--log-file", type=pathlib.Path, default=DEFAULT_LOG_PATH,
        help="Журнал в UTF-8 (дополнение); в dry-run не создаётся",
    )
    parser.add_argument(
        "--manage-service", action="store_true",
        help="При --apply остановить dhcpd, проверить базу и вернуть службу; в dry-run только план",
    )
    parser.add_argument(
        "--service", default="isc-dhcp-server.service",
        help="Полное имя systemd-службы для --manage-service",
    )
    parser.add_argument(
        "--dhcpd", type=pathlib.Path, default=pathlib.Path("/usr/sbin/dhcpd"),
        help="Исполняемый ISC dhcpd для проверок -t и -T",
    )
    parser.add_argument(
        "--dhcp-config", type=pathlib.Path, default=pathlib.Path("/etc/dhcp/dhcpd.conf"),
        help="Конфигурация выбранной службы; должна совпадать с её -cf",
    )
    parser.add_argument(
        "--service-timeout", type=int, default=30,
        help="Тайм-аут каждой внешней команды в секундах (1..300)",
    )
    args = parser.parse_args(argv)
    if args.apply and args.output is not None:
        parser.error("--apply нельзя использовать вместе с --output")
    if args.manage_service and not args.apply:
        parser.error("--manage-service используется только вместе с --apply")
    if not 1 <= args.service_timeout <= 300:
        parser.error("--service-timeout должен быть от 1 до 300 секунд")
    if args.output is None:
        args.output = DEFAULT_OUTPUT_PATH
    return args


def parse_subnet(value: str) -> ipaddress.IPv4Network:
    """Проверяет параметр --subnet до начала обработки файла."""
    try:
        network = ipaddress.ip_network(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            "Укажите адрес сети с маской, например 10.201.90.0/24"
        ) from error
    if network.version != 4:
        raise argparse.ArgumentTypeError("Поддерживаются только подсети IPv4")
    return network


def parse_check_date(value: str) -> datetime.datetime:
    try:
        date = parse_end_date(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            'Дата должна иметь вид "2026/08/18 10:20:00"; время в UTC'
        ) from error
    if date is None:
        raise argparse.ArgumentTypeError("Нужна конкретная дата, а не never")
    return date


def parse_hours(value: str) -> int:
    try:
        hours = int(value)
        if hours <= 0:
            raise ValueError
        datetime.timedelta(hours=hours)
    except (ValueError, OverflowError) as error:
        raise argparse.ArgumentTypeError(
            "Количество часов должно быть положительным целым числом допустимого размера"
        ) from error
    return hours


# 2. Настройка журнала
# ----------------------------------------------------------------------


def configure_logging(args) -> logging.Logger:
    """Создаёт отдельный logger; dry-run не открывает журнал на диске."""
    logger = logging.getLogger("filter_dhcp_leases")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    close_logging_handlers(logger)
    formatter = logging.Formatter(
        "%(asctime)sZ %(levelname)s %(message)s", datefmt="%Y-%m-%dT%H:%M:%S",
    )
    formatter.converter = time.gmtime
    console = logging.StreamHandler()
    console.setLevel(logging.WARNING)
    console.setFormatter(ConsoleFormatter())
    logger.addHandler(console)
    if not args.dry_run:
        # Проверка выполняется ДО открытия FileHandler, чтобы не дописать лог в базу.
        validate_paths(args.input, args.log_file)
        if args.manage_service:
            validate_paths(args.dhcp_config, args.log_file)
        if not args.apply:
            validate_paths(args.output, args.log_file)
        handler = logging.FileHandler(args.log_file, encoding="utf-8")
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    return logger


def close_logging_handlers(logger: logging.Logger) -> None:
    """Закрывает обработчики перед перенастройкой и после завершения запуска."""
    # Список копируется: удаление из исходного списка при обходе пропускает элементы.
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
        handler.close()


class ConsoleFormatter(logging.Formatter):
    """Краткое сообщение; полный traceback форматируется файловым обработчиком."""

    def format(self, record: logging.LogRecord) -> str:
        return record.getMessage()


# 3. Проверка путей и чтение исходника
# ----------------------------------------------------------------------


def validate_paths(input_path: pathlib.Path, output_path: pathlib.Path) -> None:
    """Запрещает перезаписывать исходник, в том числе через ссылку."""
    if input_path.resolve() == output_path.resolve():
        raise ValueError("Исходный и результирующий файл должны быть разными")
    if input_path.exists() and output_path.exists():
        if input_path.samefile(output_path):
            raise ValueError("Пути указывают на один файл. Выберите другой --output")


def source_signature(path: pathlib.Path) -> tuple:
    info = path.stat()
    return (
        info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
        info.st_ctime_ns, info.st_mode, info.st_uid, info.st_gid, info.st_nlink,
    )


def read_file(file_path: pathlib.Path) -> str:
    # newline="" сохраняет исходные переводы строк, в том числе Windows CRLF.
    with open(file_path, "r", encoding="utf-8", newline="") as file:
        return file.read()


def ensure_source_unchanged(path: pathlib.Path, original: bytes, signature: tuple) -> None:
    """Отменяет применение, если исходник изменился с начала анализа."""
    if source_signature(path) != signature or path.read_bytes() != original:
        raise ValueError("Исходный файл изменился во время обработки; повторите анализ")


# 4. Разбор блоков и последние записи IP
# ----------------------------------------------------------------------


def extract_lease_blocks(content: str) -> list[str]:
    blocks = []
    depth = 0
    lease_start = None
    inside_string = False
    escaped = False
    inside_comment = False
    lease_header = re.compile(r"lease[ \t]+[\d.]+[ \t]*\{")

    for position, char in enumerate(content):
        if inside_comment:
            if char in "\r\n":
                inside_comment = False
            continue

        if inside_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                inside_string = False
            continue

        if char == "#":
            inside_comment = True
            continue
        if char == '"':
            inside_string = True
            continue

        if depth == 0 and char == "l":
            previous = content[position - 1] if position > 0 else " "
            if previous.isspace() or previous in ";}":
                if lease_header.match(content, position):
                    lease_start = position

        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth < 0:
                raise ValueError(f"Лишняя закрывающая скобка: позиция {position}")
            if depth == 0 and lease_start is not None:
                blocks.append(content[lease_start:position + 1])
                lease_start = None

    if inside_string:
        raise ValueError("В файле обнаружена незакрытая строка в кавычках")
    if depth != 0:
        raise ValueError("В файле обнаружен незавершённый блок со скобками")
    return blocks


def get_latest_leases(blocks) -> dict:
    latest = {}
    for block in blocks:
        lease_data = parse_lease(block)
        ip = lease_data["ip"]
        if ip is None:
            raise ValueError("Не удалось получить IP из блока лизы")
        # Проверяем адрес даже у старых записей, которые позже будут заменены.
        ipaddress.IPv4Address(ip)
        latest[ip] = lease_data
    return latest


def parse_lease(lease: str) -> dict:
    ip_match = re.search(
        r"^[ \t]*lease[ \t]+([\d.]+)[ \t]*\{", lease, re.MULTILINE,
    )
    ends_match = re.search(
        r"^[ \t]*ends[ \t]+(?:[0-6][ \t]+)?"
        r"(never|\d{4}/\d{2}/\d{2}[ \t]+\d{2}:\d{2}:\d{2})[ \t]*;",
        lease, re.MULTILINE,
    )
    state_match = re.search(
        r"^[ \t]*binding[ \t]+state[ \t]+(\w+)[ \t]*;", lease, re.MULTILINE,
    )
    ip = ip_match.group(1) if ip_match else None
    ends = ends_match.group(1) if ends_match else None
    state = state_match.group(1) if state_match else None
    return {"ip": ip, "ends": ends, "state": state, "active": state == "active"}


# 5. Выбор IP для удаления
# ----------------------------------------------------------------------


def find_leases_to_delete(latest_leases, subnet, check_date, hours=24) -> list:
    selected = []
    for lease_data in latest_leases.values():
        if should_delete(lease_data, subnet, check_date, hours):
            selected.append(lease_data)
    return selected


def should_delete(lease_data, subnet, check_date, hours=24) -> bool:
    if not is_in_subnet(lease_data["ip"], subnet):
        return False
    if not lease_data["active"]:
        return False
    end_date = parse_end_date(lease_data["ends"])
    remaining = get_remaining_time(end_date, check_date)
    if remaining is None:
        return False
    return remaining > datetime.timedelta(hours=hours)


def is_in_subnet(ip, subnet) -> bool:
    if ip is None:
        return False
    return ipaddress.ip_address(ip) in ipaddress.ip_network(subnet)


def parse_end_date(ends: str | None) -> datetime.datetime | None:
    if ends is None or ends == "never":
        return None
    date = datetime.datetime.strptime(ends, DATE_FORMAT)
    return date.replace(tzinfo=datetime.timezone.utc)


def get_remaining_time(end_date, check_date) -> datetime.timedelta | None:
    if end_date is None:
        return None
    return end_date - check_date


# 6. Сборка и проверка результата
# ----------------------------------------------------------------------


def build_filtered_content(content, blocks, ips_to_delete) -> str:
    """Удаляет блоки вместе с их отдельной строкой, сохраняя соседний текст."""
    parts = []
    position = 0
    for block in blocks:
        start = content.index(block, position)
        end = start + len(block)
        if parse_lease(block)["ip"] in ips_to_delete:
            # Если блок занимает отдельные строки, убираем также его отступ
            # и завершающий перевод строки. Общие пустые строки не трогаем.
            line_start = max(
                content.rfind("\n", 0, start),
                content.rfind("\r", 0, start),
            ) + 1
            trailing = re.match(r"[ \t]*(?:\r\n|\n|\r|$)", content[end:])
            if (
                line_start >= position
                and not content[line_start:start].strip(" \t")
                and trailing is not None
            ):
                start = line_start
                end += trailing.end()
            parts.append(content[position:start])
        else:
            parts.append(content[position:end])
        position = end
    parts.append(content[position:])
    return "".join(parts)


def verify_result(blocks, new_content, ips_to_delete) -> list[str]:
    """Проверяет оставшиеся блоки до любой записи на диск."""
    new_blocks = extract_lease_blocks(new_content)
    expected_blocks = []
    for block in blocks:
        if parse_lease(block)["ip"] not in ips_to_delete:
            expected_blocks.append(block)
    if new_blocks != expected_blocks:
        raise ValueError("Проверка результата не пройдена: изменились оставшиеся блоки")
    return new_blocks


# 7. Отчёт: параметры, сводка и таблица
# ----------------------------------------------------------------------


def print_report(
    args, check_date, blocks, latest_leases, selected_leases, new_blocks,
) -> None:
    in_subnet = [
        lease for lease in latest_leases.values()
        if is_in_subnet(lease["ip"], args.subnet)
    ]
    selected_ips = {lease["ip"] for lease in selected_leases}
    if args.dry_run:
        mode = "ПРЕДПРОСМОТР (DRY-RUN)"
        if args.apply:
            mode += " | ЗАМЕНА ИСХОДНИКА"
    elif args.apply:
        mode = "ПЛАН: ЗАМЕНА ИСХОДНИКА"
    else:
        mode = "ПЛАН: ОТДЕЛЬНЫЙ ФАЙЛ"
    target = args.input if args.apply else args.output
    print("\n" + "=" * 86)
    print(f" DHCP LEASES | {mode}")
    print("=" * 86)
    if args.manage_service:
        print(f"  Служба: {args.service} | остановить -> проверить -> запустить")
    print(f"  Исходник: {args.input}")
    print(f"  Результат: {target}" + (" (без записи)" if args.dry_run else ""))
    print(f"  Подсеть: {args.subnet} | Условие: active, конечный срок, остаток > {args.hours} ч")
    print(f"  Дата проверки (UTC): {check_date.isoformat(sep=' ')}")
    print("\nСВОДКА")
    print(f"  Блоки: {len(blocks)} -> {len(new_blocks)} | Удалить блоков: {len(blocks) - len(new_blocks)}")
    print(f"  IP всего: {len(latest_leases)} | В подсети: {len(in_subnet)} | Выбрано IP: {len(selected_leases)}")
    print("\n" + ("ЛИЗЫ В ПОДСЕТИ" if args.verbose else "ВЫБРАННЫЕ IP"))
    leases_to_show = in_subnet if args.verbose else selected_leases
    if leases_to_show:
        print_lease_table(leases_to_show, selected_ips, check_date)
        print("  Остаток: [дни] ЧЧ:ММ:СС; план определяется по последней записи IP.")
    else:
        print("  Нет записей в подсети." if args.verbose else "  Нет IP, подходящих под условие удаления.")
    print("\n  Проверка результата в памяти: OK")


def print_lease_table(leases, selected_ips, check_date) -> None:
    headers = ("IP", "Состояние", "Окончание UTC", "Остаток", "План")
    rows = []
    for lease in sorted(leases, key=lambda item: ipaddress.IPv4Address(item["ip"])):
        end_date = parse_end_date(lease["ends"])
        if lease["ends"] == "never":
            ends = "бессрочно"
        else:
            ends = end_date.strftime("%Y-%m-%d %H:%M:%S") if end_date else "-"
        rows.append((
            lease["ip"],
            lease["state"] or "-",
            ends,
            format_remaining(get_remaining_time(end_date, check_date)),
            "УДАЛИТЬ" if lease["ip"] in selected_ips else "оставить",
        ))
    # Начинаем с ширины заголовков, затем учитываем значения каждой строки.
    widths = [len(header) for header in headers]
    for row in rows:
        for column, value in enumerate(row):
            widths[column] = max(widths[column], len(value))

    def print_row(row) -> None:
        print("  " + " | ".join(
            value.ljust(width) for value, width in zip(row, widths)
        ).rstrip())
    print_row(headers)
    print("  " + "-+-".join("-" * width for width in widths))
    for row in rows:
        print_row(row)


def format_remaining(remaining: datetime.timedelta | None) -> str:
    """Компактный остаток аренды; секунды сохраняют видимость строгого порога."""
    if remaining is None:
        return "-"
    if remaining < datetime.timedelta(0):
        return "истёк"
    seconds = int(remaining.total_seconds())
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)
    clock = f"{hours:02}:{minutes:02}:{seconds:02}"
    return f"{days} д {clock}" if days else clock


# 8. Итог операции, включая ранний выход из dry-run
# ----------------------------------------------------------------------


def print_outcome(args, backup_path: pathlib.Path | None = None) -> None:
    """Показывает подтверждённый итог отдельно от предварительного плана."""
    print("\n" + "-" * 86)
    if args.dry_run:
        print("ИТОГ: ПРЕДПРОСМОТР ЗАВЕРШЁН")
        print("  Dry-run: файлы не создавались и не изменялись.")
        print("  Для записи повторите команду без --dry-run.")
    else:
        print("ИТОГ: ИСХОДНИК ОБНОВЛЁН" if args.apply else "ИТОГ: РЕЗУЛЬТАТ СОХРАНЁН")
        print(f"  Результат: {args.input if args.apply else args.output}")
        print(f"  Резервная копия: {backup_path}")
        print("  Проверка записи: OK")
        if not args.apply:
            print("  Исходный файл не изменён.")
        if args.manage_service:
            print(f"  Служба: {args.service} — active/running, проверена")
        print(f"  Журнал: {args.log_file}")
    print("-" * 86)


# 9. Применение: замена исходника или запись отдельного файла
# ----------------------------------------------------------------------


def apply_safely(
    input_path: pathlib.Path, new_content: str, blocks: list[str],
    ips_to_delete: set[str], original: bytes, signature: tuple,
    backup_dir: pathlib.Path | None, logger: logging.Logger,
    *, lease_validator=None, transaction=None,
) -> pathlib.Path:
    """Проверяет файл на диске, создаёт копию и атомарно заменяет исходник."""
    if input_path.is_symlink() or input_path.stat().st_nlink != 1:
        raise ValueError("--apply не поддерживает символические и жёсткие ссылки")
    ensure_source_unchanged(input_path, original, signature)
    source_stat = input_path.stat()
    temporary_path = None
    try:
        # Та же папка означает ту же файловую систему для os.replace().
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", newline="", dir=input_path.parent,
            prefix=f".{input_path.name}.", suffix=".tmp", delete=False,
        ) as temporary:
            temporary_path = pathlib.Path(temporary.name)
            temporary.write(new_content)
            temporary.flush()
            # На Linux сохраняем владельца и группу, иначе DHCP может потерять доступ.
            if hasattr(os, "fchown"):
                current = os.fstat(temporary.fileno())
                if (current.st_uid, current.st_gid) != (source_stat.st_uid, source_stat.st_gid):
                    os.fchown(temporary.fileno(), source_stat.st_uid, source_stat.st_gid)
            os.chmod(temporary_path, stat.S_IMODE(source_stat.st_mode))
            os.fsync(temporary.fileno())

        saved_content = read_file(temporary_path)
        if saved_content != new_content:
            raise ValueError("Проверка временного файла: содержимое отличается")
        verify_result(blocks, saved_content, ips_to_delete)
        if lease_validator is not None:
            lease_validator(temporary_path)
        logger.info("Временный файл проверен: %s", temporary_path)

        ensure_source_unchanged(input_path, original, signature)
        backup_path = create_backup(input_path, backup_dir)
        if transaction is not None:
            transaction["backup"] = backup_path
        logger.info("Резервная копия: %s", backup_path)
        if backup_path.read_bytes() != original:
            raise ValueError("Резервная копия отличается от проанализированного исходника")
        # Последняя проверка непосредственно перед заменой. Служба должна быть остановлена.
        ensure_source_unchanged(input_path, original, signature)
        os.replace(temporary_path, input_path)
        # Даже ошибка синхронизации каталога ниже должна привести к восстановлению.
        if transaction is not None:
            transaction["replaced"] = True
        temporary_path = None
        logger.info("Рабочий файл заменён: %s", input_path)
        if os.name == "posix":
            try:
                sync_directory(input_path.parent)
            except OSError:
                logger.exception("Файл уже заменён, но синхронизация каталога не удалась")
                raise
        return backup_path
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def save_filtered_file(
    input_path: pathlib.Path, output_path: pathlib.Path, content: str,
    original: bytes, signature: tuple, backup_dir: pathlib.Path | None,
    logger: logging.Logger,
) -> pathlib.Path:
    """Сохраняет отдельный результат и копию исходника, не заменяя исходную базу."""
    ensure_source_unchanged(input_path, original, signature)
    backup_path = create_backup(input_path, backup_dir)
    logger.info("Резервная копия: %s", backup_path)
    # Копия должна совпадать именно с проанализированной версией исходника.
    if backup_path.read_bytes() != original:
        raise ValueError("Резервная копия отличается от проанализированного исходника")
    write_file(output_path, content)
    saved_content = read_file(output_path)
    if saved_content != content:
        raise ValueError("Проверка записи не пройдена: содержимое файла отличается")
    return backup_path


def create_backup(
    input_path: pathlib.Path, backup_dir: pathlib.Path | None = None,
) -> pathlib.Path:
    """Побайтовая копия: UTC + случайный суффикс, режим xb запрещает перезапись."""
    directory = backup_dir if backup_dir is not None else input_path.parent
    directory.mkdir(parents=True, exist_ok=True)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")
    while True:
        backup_path = directory / f"{input_path.name}.{stamp}.{uuid.uuid4().hex[:8]}.bak"
        try:
            backup_file = backup_path.open("xb")
            break
        except FileExistsError:
            continue
    try:
        with backup_file:
            # На сервере резервная копия не должна стать доступнее исходника.
            os.chmod(backup_path, stat.S_IMODE(input_path.stat().st_mode))
            with input_path.open("rb") as source:
                shutil.copyfileobj(source, backup_file)
            backup_file.flush()
            os.fsync(backup_file.fileno())
        if backup_path.read_bytes() != input_path.read_bytes():
            raise ValueError("Проверка резервной копии не пройдена")
        return backup_path
    except BaseException:
        backup_path.unlink(missing_ok=True)
        raise


def write_file(file_path: pathlib.Path, content: str) -> None:
    with open(file_path, "w", encoding="utf-8", newline="") as file:
        file.write(content)


# 10. Главный сценарий выполнения
# ----------------------------------------------------------------------


def main(argv=None) -> int:
    args = parse_arguments(argv)
    check_date = args.check_date
    if check_date is None:
        check_date = datetime.datetime.now(datetime.timezone.utc)

    logger = logging.getLogger("filter_dhcp_leases")
    try:
        logger = configure_logging(args)
        logger.info(
            "Запуск: input=%s output=%s subnet=%s check_date=%s hours=%s "
            "dry_run=%s apply=%s backup_dir=%s log_file=%s verbose=%s "
            "manage_service=%s service=%s dhcpd=%s dhcp_config=%s service_timeout=%s",
            args.input, args.input if args.apply else args.output,
            args.subnet, check_date.isoformat(), args.hours, args.dry_run,
            args.apply, args.backup_dir or args.input.parent, args.log_file, args.verbose,
            args.manage_service, args.service, args.dhcpd, args.dhcp_config, args.service_timeout,
        )
        # Управляемый режим останавливает службу при входе, ещё до чтения базы.
        with service_session(args, logger, create_backup) as transaction:
            if not args.apply:
                validate_paths(args.input, args.output)
            elif args.input.is_symlink() or args.input.stat().st_nlink != 1:
                raise ValueError("--apply не поддерживает символические и жёсткие ссылки")
            signature = source_signature(args.input)
            content = read_file(args.input)
            original = content.encode("utf-8")
            ensure_source_unchanged(args.input, original, signature)
            if transaction is not None:
                # Передаём исходные байты и права для возможного восстановления.
                transaction["original"] = original
                transaction["stat"] = args.input.stat()
            blocks = extract_lease_blocks(content)
            latest_leases = get_latest_leases(blocks)
            selected_leases = find_leases_to_delete(
                latest_leases, args.subnet, check_date, args.hours,
            )
            ips_to_delete = {lease["ip"] for lease in selected_leases}
            for lease in selected_leases:
                logger.info("Выбран IP: %s ends=%s state=%s", lease["ip"], lease["ends"], lease["state"])

            new_content = build_filtered_content(content, blocks, ips_to_delete)
            new_blocks = verify_result(blocks, new_content, ips_to_delete)
            print_report(
                args, check_date, blocks, latest_leases, selected_leases, new_blocks,
            )
            logger.info(
                "Анализ: блоков=%s уникальных_IP=%s выбрано_IP=%s осталось_блоков=%s",
                len(blocks), len(latest_leases), len(selected_leases), len(new_blocks),
            )

            if args.dry_run:
                print_outcome(args)
                logger.info("Результат: dry-run успешно завершён, записи на диск не было")
                return 0

            if args.apply:
                backup_path = apply_safely(
                    input_path=args.input,
                    new_content=new_content,
                    blocks=blocks,
                    ips_to_delete=ips_to_delete,
                    original=original,
                    signature=signature,
                    backup_dir=args.backup_dir,
                    logger=logger,
                    # Внешняя проверка dhcpd подключается только в управляемом режиме.
                    lease_validator=(
                        lambda path: validate_lease_file(args, path, logger)
                    ) if transaction is not None else None,
                    transaction=transaction,
                )
            else:
                backup_path = save_filtered_file(
                    input_path=args.input,
                    output_path=args.output,
                    content=new_content,
                    original=original,
                    signature=signature,
                    backup_dir=args.backup_dir,
                    logger=logger,
                )
        # Успешный итог — только после выхода из with и проверки запуска службы.
        print_outcome(args, backup_path)
        logger.info("Результат: успешно, удалено блоков=%s", len(blocks) - len(new_blocks))
        return 0
    except (OSError, UnicodeError, ValueError, OverflowError, RuntimeError) as error:
        logger.exception("Ошибка: %s", error)
        if any(isinstance(handler, logging.FileHandler) for handler in logger.handlers):
            print(f"Подробности в журнале: {args.log_file}", file=sys.stderr)
        return 1
    finally:
        close_logging_handlers(logger)


if __name__ == "__main__":
    sys.exit(main())
