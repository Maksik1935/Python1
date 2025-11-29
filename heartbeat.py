from dataclasses import dataclass

# Условный адрес уязвимого сервера
TARGET_HOST = "vulnerable.example.com"
TARGET_PORT = 443


@dataclass
class HeartbeatPacket:
    """
    Упрощённое представление heartbeat-пакета.

    В реальном протоколе тут были бы бинарные поля TLS:
    - тип записи
    - версия протокола
    - длина
    - тип heartbeat-сообщения
    - длина payload и т.д.

    Здесь только модель для демонстрации.
    """
    record_type: str
    real_payload_len: int
    claimed_payload_len: int

    def describe(self) -> str:
        return (
            f"Тип записи: {self.record_type}\n"
            f"Фактическая длина payload: {self.real_payload_len} байт\n"
            f"Заявленная длина payload (в заголовке): {self.claimed_payload_len} байт\n"
        )


def build_malicious_heartbeat(claimed_len: int = 16384) -> HeartbeatPacket:
    """
    Строим 'вредоносный' heartbeat-пакет (ЭМУЛЯЦИЯ).

    Идея Heartbleed:
    - Отправляем очень маленький payload (например, 1 байт),
    - но в заголовке говорим, что там, допустим, 16 КБ.
    - Уязвимый сервер доверяет заголовку и возвращает лишние байты памяти.
    """
    real_payload_len = 1          # фактически отправляем 1 байт
    claimed_payload_len = claimed_len  # а говорим, что отправили много

    packet = HeartbeatPacket(
        record_type="heartbeat_request",
        real_payload_len=real_payload_len,
        claimed_payload_len=claimed_payload_len,
    )

    return packet


def simulate_heartbleed_attack():
    print("[*] Эмуляция атаки CVE-2014-0160 (Heartbleed)")
    print(f"[*] Цель: {TARGET_HOST}:{TARGET_PORT}")
    print()

    # Формируем 'злой' heartbeat-пакет (только объект в памяти, без сети)
    packet = build_malicious_heartbeat()

    print("[*] Сформирован псевдо heartbeat-пакет:")
    print(packet.describe())

    # В реальном эксплойте здесь был бы сетевой код (socket/SSL) и отправка пакета.
    # Мы ничего НЕ отправляем, только показываем, что бы произошло логически.
    print("[*] Отправка пакета на сервер ОПУЩЕНА (это только эмуляция).")
    print()

    # Демонстрация того, что при реальной уязвимости сервер мог бы вернуть память.
    print("[!] При наличии уязвимости сервер мог бы вернуть до 64 КБ "
          "лишних данных из памяти процесса.")
    print("[!] Эти данные могли бы содержать пароли, cookie, приватные ключи и др.")
    print()
    print("[*] Эмуляция завершена. Реальной атаки не происходило.")


if __name__ == "__main__":
    simulate_heartbleed_attack()