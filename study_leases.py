import re
import pathlib
import datetime
import ipaddress


LEASES_PATH = pathlib.Path("./dhcpd.leases")
OUTPUT_PATH = pathlib.Path("./dhcpd.filtered.leases")
TARGET_SUBNET = "10.201.90.0/24"
# LEASES_FILE = "/var/lib/dhcpd/dhcpd.leases"


def read_file(file_path) -> str:
    with open(file_path, "r", encoding="utf-8") as file:
        return file.read()


def parse_lease(lease: str) -> dict:
    ip_match = re.search(
        r"^[ \t]*lease[ \t]+([\d.]+)[ \t]*\{",
        lease,
        re.MULTILINE,
    )

    ends_match = re.search(
        r"^[ \t]*ends[ \t]+(?:[0-6][ \t]+)?"
        r"(never|\d{4}/\d{2}/\d{2}[ \t]+\d{2}:\d{2}:\d{2})[ \t]*;",
        lease,
        re.MULTILINE,
    )

    state_match = re.search(
        r"^[ \t]*binding[ \t]+state[ \t]+(\w+)[ \t]*;",
        lease,
        re.MULTILINE,
    )

    ip = ip_match.group(1) if ip_match else None
    ends = ends_match.group(1) if ends_match else None
    state = state_match.group(1) if state_match else None

    return {
        "ip": ip,
        "ends": ends,
        "state": state,
        "active": state == "active",
    }


def parse_end_date(ends) -> datetime.datetime | None:
    if ends is None or ends == "never":
        return None

    date = datetime.datetime.strptime(ends, "%Y/%m/%d %H:%M:%S")
    return date.replace(tzinfo=datetime.timezone.utc)


def get_remaining_time(end_date, check_date) -> datetime.timedelta | None:
    if end_date is None:
        return None
    return end_date - check_date


def is_in_subnet(ip, subnet) -> bool:
    if ip is None:
        return False
    ip = ipaddress.ip_address(ip)
    subnet = ipaddress.ip_network(subnet)
    return ip in subnet


def should_delete(lease_data, subnet, check_date) -> bool:
    # Проверка вхождения в подсеть.
    if not is_in_subnet(lease_data["ip"], subnet):
        return False

    # Проверка состояния лизы.
    if not lease_data["active"]:
        return False

    # Проверка оставшегося времени.
    end_date = parse_end_date(lease_data["ends"])
    remaining = get_remaining_time(end_date, check_date)
    if remaining is None:
        return False

    return remaining > datetime.timedelta(hours=24)


def extract_lease_blocks(content) -> list[str]:
    blocks = []
    depth = 0
    lease_start = None
    inside_string = False
    escaped = False
    inside_comment = False

    lease_header = re.compile(r"lease[ \t]+[\d.]+[ \t]*\{")

    # Идём по символам, сохраняя их позиции в исходном тексте.
    for position, char in enumerate(content):
        # Комментарий продолжается до конца строки.
        if inside_comment:
            if char in "\r\n":
                inside_comment = False
            continue

        # Внутри кавычек скобки и # являются обычными данными.
        if inside_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                inside_string = False
            continue

        # Эти символы имеют специальное значение вне кавычек.
        if char == "#":
            inside_comment = True
            continue

        if char == '"':
            inside_string = True
            continue

        # Начало лизы ищем только вне других блоков.
        if depth == 0 and char == "l":
            previous = content[position - 1] if position > 0 else " "
            if previous.isspace() or previous in ";}":
                if lease_header.match(content, position):
                    lease_start = position

        # Теперь считаем только настоящие скобки структуры.
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1

            if depth < 0:
                raise ValueError(f"Лишняя закрывающая скобка: позиция {position}")

            if depth == 0 and lease_start is not None:
                # Включаем закрывающую скобку, но не текст после неё.
                blocks.append(content[lease_start:position + 1])
                lease_start = None

    if inside_string:
        raise ValueError("В файле обнаружена незакрытая строка в кавычках")

    if depth != 0:
        raise ValueError("В файле обнаружен незавершённый блок со скобками")

    return blocks


def get_latest_leases(blocks):
    # судя по документации ISC могут быть повторные записи
    latest = {}
    for block in blocks:
        lease_data = parse_lease(block)
        ip = lease_data["ip"]
        if ip is None:
            raise ValueError("Не удалось получить IP из блока лизы")
        latest[ip] = lease_data
    return latest


def find_leases_to_delete(latest_leases, subnet, check_date):
    selected = []
    for lease_data in latest_leases.values():
        if should_delete(lease_data, subnet, check_date):
            selected.append(lease_data)
    return selected


def build_filtered_content(content, blocks, ips_to_delete):
    parts = []
    position = 0
    for block in blocks:
        start = content.index(block, position)
        end = start + len(block)

        # Сохраняем комментарии, пустые строки и другие записи между лизами.
        parts.append(content[position:start])

        lease_data = parse_lease(block)
        if lease_data["ip"] not in ips_to_delete:
            parts.append(block)

        position = end

    parts.append(content[position:])
    return "".join(parts)


def write_file(file_path, content):
    with open(file_path, "w", encoding="utf-8") as file:
        file.write(content)


def main():
    check_date = parse_end_date("2026/08/18 10:20:00")

    content = read_file(LEASES_PATH)
    blocks = extract_lease_blocks(content)
    latest_leases = get_latest_leases(blocks)
    selected_leases = find_leases_to_delete(
        latest_leases, TARGET_SUBNET, check_date,
    )

    print("Целевая сеть:", TARGET_SUBNET)
    print("Дата проверки:", check_date)
    print("Всего блоков:", len(blocks))
    print("Уникальных IP:", len(latest_leases))
    print("Выбрано для удаления:", len(selected_leases))

    in_subnet_count = 0
    for lease_data in latest_leases.values():
        if not is_in_subnet(lease_data["ip"], TARGET_SUBNET):
            continue
        in_subnet_count += 1

        end_date = parse_end_date(lease_data["ends"])
        remaining = get_remaining_time(end_date, check_date)
        print(
            f"IP: {lease_data['ip']} | "
            f"Состояние: {lease_data['state']} | "
            f"Ends: {lease_data['ends']} | "
            f"Осталось: {remaining}"
        )

    print("Всего IP в целевой сети:", in_subnet_count)
    print("\nЛизы, выбранные для удаления:")
    for lease_data in selected_leases:
        print(
            f"IP: {lease_data['ip']} | "
            f"Состояние: {lease_data['state']} | "
            f"Окончание: {lease_data['ends']}"
        )

    ips_to_delete = set()
    for lease_data in selected_leases:
        ips_to_delete.add(lease_data["ip"])

    print("IP для удаления:", sorted(ips_to_delete))
    print("Количество IP:", len(ips_to_delete))

    new_content = build_filtered_content(content, blocks, ips_to_delete)
    new_blocks = extract_lease_blocks(new_content)

    print("Блоков до:", len(blocks))
    print("Блоков после:", len(new_blocks))
    print("Убрано блоков:", len(blocks) - len(new_blocks))
    print("Исходный файл не изменён.")

    write_file(OUTPUT_PATH, new_content)
    print("Результат сохранён в:", OUTPUT_PATH)

    saved_content = read_file(OUTPUT_PATH)
    saved_blocks = extract_lease_blocks(saved_content)
    saved_leases = get_latest_leases(saved_blocks)
    saved_ips = set(saved_leases)
    expected_ips = set(latest_leases) - ips_to_delete

    print("Текст записан полностью:", saved_content == new_content)
    print("Остались нужные IP:", saved_ips == expected_ips)
    print("Блоков в сохранённом файле:", len(saved_blocks))


if __name__ == "__main__":
    main()
