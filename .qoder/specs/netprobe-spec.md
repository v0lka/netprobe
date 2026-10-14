## netprobe — спецификация проекта

Консольная утилита для глубокого мониторинга качества сетевого соединения с заданным хостом. Предоставляет TUI-дашборд в стиле btop и ведёт структурированный лог в формате JSON Lines.

Язык реализации: Rust. TUI-фреймворк: ratatui + crossterm.


### Назначение и scope

netprobe принимает домен или IP-адрес и непрерывно мониторит качество соединения на четырёх уровнях: ICMP (ping), DNS resolution, TCP connect + TLS handshake, HTTP(S) healthcheck. Параллельно выполняется периодический traceroute с детекцией изменений маршрута. Все метрики и обнаруженные аномалии записываются в единый JSONL-файл. TUI-дашборд отображает текущие значения, историю в виде braille-sparkline графиков и ленту событий.

Утилита мониторит один хост за запуск. Для мониторинга нескольких хостов запускается несколько экземпляров.

IPv6: в v1 поддерживаются как IPv4, так и IPv6 адреса. Если `TARGET` — доменное имя, разрешаемое в оба протокола, используется первый адрес из DNS-ответа (предпочтение IPv4, если доступен). Для явного указания протокола можно передать IPv4 или IPv6 адрес напрямую. `surge-ping` поддерживает ICMPv6, `hickory-resolver` — AAAA-записи, `trippy-core` — IPv6 traceroute.


### CLI-интерфейс

```
netprobe <TARGET> [OPTIONS]
```

Позиционный аргумент `TARGET` — домен или IP-адрес (обязательный). Если передан домен — при старте выполняется DNS resolve для получения IP. В JSONL-поле `target` записывается то, что было передано в аргументе (домен или IP). Поле `resolved_target` в `session_start` — результат обратного преобразования: если TARGET — домен, `resolved_target` содержит resolved IP; если TARGET — IP, `resolved_target` содержит результат reverse DNS (hostname) или null, если reverse DNS не удался. В TUI header формат: `<TARGET> (<resolved_target>)`.

Опции:

```
--log <PATH>             Путь к JSONL лог-файлу (по умолчанию: ./netprobe-<target>-<timestamp>.jsonl)
--port <PORT>            TCP/HTTP порт (по умолчанию: 443)
--http-path <PATH>       HTTP path для healthcheck (по умолчанию: /)
--no-http                Отключить HTTP(S) probing
--no-tls                 Отключить TLS (использовать plain HTTP)
--interval-icmp <MS>     Интервал ICMP ping в мс (по умолчанию: 1000)
--interval-dns <SEC>     Интервал DNS resolve в секундах (по умолчанию: 30)
--interval-tcp <SEC>     Интервал TCP/HTTP probe в секундах (по умолчанию: 10)
--interval-trace <SEC>   Интервал traceroute в секундах (по умолчанию: 60)
--history <N>            Размер ring buffer истории в сэмплах (по умолчанию: 3600)
--timeout-icmp <MS>      Таймаут одного ICMP probe в мс (по умолчанию: 2000)
--timeout-tcp <MS>       Таймаут TCP connect в мс (по умолчанию: 5000)
--timeout-dns <MS>       Таймаут DNS resolution в мс (по умолчанию: 5000)
--timeout-http <MS>      Таймаут HTTP response в мс (по умолчанию: 10000)
--dns-server <IP>        Явный DNS-сервер (по умолчанию: системный)
-q, --quiet              Без TUI, только логирование в файл
--version                Версия
--help                   Справка
```

Парсинг аргументов — через `clap` (derive API).


### Слои мониторинга и метрики

#### L3 — ICMP Ping

Метрики на каждый probe: RTT (мс), sequence number, TTL из ответа, статус (ok / timeout / error).

Агрегаты (скользящее окно и за сессию): min, avg, max, p50, p95, p99 RTT; jitter — среднее абсолютное отклонение между последовательными RTT: `mean(|rtt[i] - rtt[i-1]|)`; packet loss % (sent vs received); количество duplicate и reordered пакетов.

Стратегия реализации — гибридная (Option C):

1. Попытка открыть unprivileged ICMP socket (`SOCK_DGRAM` + `IPPROTO_ICMP`). Работает на Linux с kernel >= 3.0 при настроенном `net.ipv4.ping_group_range`.
2. Если не удалось — попытка raw socket (`SOCK_RAW`). Требует `CAP_NET_RAW` на Linux, root на macOS.
3. Если и это не удалось — fallback на subprocess: `ping -c 1 -W <timeout>` (Unix) или `ping -n 1 -w <timeout>` (Windows), парсинг stdout.

Crate: `surge-ping` для вариантов 1 и 2. Для варианта 3 — `tokio::process::Command` с парсингом вывода. Выбор стратегии происходит один раз при старте, результат логируется.

#### DNS Resolution

Метрики: resolution time (мс), список resolved IP-адресов, TTL из DNS-ответа, использованный DNS-сервер, статус (ok / nxdomain / servfail / timeout).

Детекция событий: появление нового IP в ответе, исчезновение IP, смена полного набора адресов.

Crate: `hickory-resolver` (бывший `trust-dns-resolver`).

#### L4 — TCP Connect

Метрики: TCP handshake time (мс) — время от `connect()` до установления соединения; статус (connected / refused / timeout / reset).

Реализация: `socket2` — создание неблокирующего TCP-сокета, `connect()` с замером времени. Порт по умолчанию 443 (настраивается через `--port`).

#### L7 — TLS + HTTP(S)

TLS-метрики: TLS handshake time (мс), согласованная TLS version (1.2, 1.3), cipher suite, сертификат сервера (subject, issuer, SAN, дата истечения, оставшееся количество дней).

HTTP-метрики: TTFB — Time To First Byte (мс), HTTP status code, total response time (мс).

Реализация TLS timing: прямое использование `rustls` поверх `socket2` TCP-соединения. Это позволяет замерить TCP connect и TLS handshake раздельно. После TLS-хэндшейка — извлечение `peer_certificates()` и парсинг leaf-сертификата через `x509-parser`.

Реализация HTTP: отправка минимального `GET <path> HTTP/1.1` запроса через уже установленное TLS-соединение и замер TTFB (время до первого байта ответа). Парсинг status line для получения кода ответа.

Альтернативный подход — использование `reqwest` с `tls_info(true)` для получения сертификата, но в этом случае TLS handshake timing недоступен. Поэтому для HTTP(S) probing используется низкоуровневый подход: `socket2` → `rustls` → raw HTTP request, что даёт полный контроль над таймингами каждой фазы.

Если передан `--no-http`, этот слой полностью отключается. Если передан `--no-tls`, используется plain TCP + HTTP (без TLS).

#### Traceroute

Метрики: количество хопов, для каждого хопа — IP-адрес (или `*` при timeout), RTT (мс), hostname (reverse DNS, опционально).

Детекция событий: изменение маршрута (diff текущего traceroute с предыдущим), появление/исчезновение хопов, изменение RTT на конкретных хопах более чем на 2σ.

Crate: `trippy-core` — встраиваемая библиотека с поддержкой ICMP/UDP/TCP traceroute, hop-by-hop RTT, multipath strategy. Требует тех же привилегий, что и ICMP raw sockets. Также: `trippy-privilege` для детекции наличия привилегий при старте.

Поведение при недостаточных привилегиях: если при старте `trippy-privilege` определяет отсутствие прав для raw sockets и ICMP prober работает в subprocess fallback режиме (вариант 3), traceroute полностью отключается. В TUI панель traceroute показывает сообщение «traceroute unavailable: insufficient privileges». Опция `--interval-trace` игнорируется. В JSONL-лог при старте записывается `"traceroute_available": false` в `session_start`.

#### Производные метрики

MOS score (Mean Opinion Score) — вычисляется по упрощённой модели E-model (ITU-T G.107):

```
effective_latency = avg_rtt + jitter * 2 + 10
R = 93.2 - (effective_latency / 40) - (packet_loss_pct * 2.5)
MOS = 1 + 0.035 * R + 0.000007 * R * (R - 60) * (100 - R)
```

Результат — число от 1.0 до 4.5, после вычисления clamped в диапазон `[1.0, 4.5]`. Отображается в заголовке дашборда.

Connection quality grade — буквенная оценка, производная от MOS: A (>= 4.0), B (>= 3.5), C (>= 3.0), D (>= 2.5), F (< 2.5).

Uptime % — доля успешных ICMP-проб за сессию.


### Anomaly Detection

Детекция аномалий работает в реальном времени на потоке ICMP-метрик. Каждая аномалия генерирует запись типа `event` в JSONL-лог и отображается в панели events дашборда.

Типы аномалий:

- `rtt_spike` — RTT превышает скользящее среднее на более чем 3σ (стандартных отклонения). Скользящее окно — последние 60 сэмплов.
- `loss_burst` — 3 или более последовательных потерянных пакетов.
- `jitter_spike` — jitter превышает скользящее среднее jitter на более чем 3σ. Скользящее окно — те же 60 сэмплов, что и для `rtt_spike`.
- `route_change` — traceroute обнаружил изменение маршрута по сравнению с предыдущим запуском.
- `dns_change` — набор resolved IP изменился.
- `cert_expiry_warning` — до истечения TLS-сертификата осталось менее 30 дней (порог в днях — кандидат на CLI-опцию в будущем).
- `http_error` — HTTP status code >= 400 или timeout.
- `tcp_refused` — TCP connection refused или reset.
- `hop_rtt_anomaly` — RTT на конкретном хопе traceroute отклонился более чем на 2σ от скользящего среднего для этого хопа (окно 10 сэмплов, warm-up 5 сэмплов).

Для вычисления скользящего среднего и σ используется скользящий вариант алгоритма Уэлфорда: ring buffer на 60 сэмплов, при вытеснении старого значения — пересчёт mean и M2. Это даёт амортизированную O(1) сложность на сэмпл при фиксированном размере окна. Warm-up период: детекция аномалий типа `rtt_spike` и `jitter_spike` активируется только после накопления минимум 30 сэмплов. До этого момента статистика накапливается, но пороги не проверяются (чтобы избежать ложных срабатываний при малом σ). В промежутке 30–59 сэмплов детекция активна, среднее и σ вычисляются по имеющимся данным (окно ещё не заполнено целиком).

Для per-hop RTT аномалий в traceroute используется аналогичный скользящий Welford, но с окном 10 сэмплов (traceroute выполняется реже — раз в 60 секунд) и порогом 2σ. Warm-up для per-hop: 5 сэмплов (≈5 минут при стандартном интервале).


### JSONL формат лога

Все записи — в одном файле, одна JSON-запись на строку. Поле `type` определяет тип записи.

Типы записей и их поля:

**icmp** — результат одного ICMP-проба:
```json
{"ts":"2026-03-18T14:23:05.123Z","type":"icmp","target":"1.1.1.1","seq":8142,"rtt_ms":14.2,"ttl":56,"status":"ok"}
```
Поле `status`: `ok`, `timeout`, `error`. При `timeout` или `error` поле `rtt_ms` отсутствует.

**dns** — результат DNS resolution:
```json
{"ts":"2026-03-18T14:23:30.001Z","type":"dns","target":"one.one.one.one","resolve_ms":4.2,"ips":["1.1.1.1","1.0.0.1"],"ttl_secs":286,"server":"192.168.1.1","status":"ok"}
```
Поле `status`: `ok`, `nxdomain`, `servfail`, `timeout`.

**tcp** — результат TCP connect probe:
```json
{"ts":"2026-03-18T14:23:35.050Z","type":"tcp","target":"1.1.1.1","port":443,"connect_ms":15.1,"status":"ok"}
```
Поле `status`: `ok`, `refused`, `timeout`, `reset`.

**tls** — результат TLS handshake (записывается совместно с tcp, но как отдельная запись):
```json
{"ts":"2026-03-18T14:23:35.065Z","type":"tls","target":"1.1.1.1","port":443,"handshake_ms":42.3,"version":"TLSv1.3","cipher":"TLS_AES_256_GCM_SHA384","cert_subject":"CN=one.one.one.one","cert_issuer":"CN=DigiCert","cert_san":["one.one.one.one","1.1.1.1","1.0.0.1"],"cert_expiry":"2026-06-15T00:00:00Z","cert_days_remaining":89,"status":"ok"}
```

**http** — результат HTTP(S) healthcheck:
```json
{"ts":"2026-03-18T14:23:35.130Z","type":"http","target":"1.1.1.1","port":443,"path":"/","ttfb_ms":78.4,"total_ms":82.1,"status_code":200,"status":"ok"}
```

**traceroute** — результат полного traceroute:
```json
{"ts":"2026-03-18T14:24:05.200Z","type":"traceroute","target":"1.1.1.1","hops":[{"hop":1,"ip":"192.168.1.1","rtt_ms":1.2,"host":"router.local"},{"hop":2,"ip":"10.0.0.1","rtt_ms":4.1,"host":null},{"hop":3,"ip":null,"rtt_ms":null,"host":null},{"hop":4,"ip":"1.1.1.1","rtt_ms":14.2,"host":"one.one.one.one"}],"hop_count":4,"status":"ok"}
```

**event** — обнаруженная аномалия:
```json
{"ts":"2026-03-18T14:22:51.000Z","type":"event","target":"1.1.1.1","event":"rtt_spike","severity":"warning","value":47.1,"threshold":32.4,"sigma":3.2,"message":"RTT spike: 47.1ms (3.2σ above mean)"}
```
Поле `severity`: `info`, `warning`, `critical`.

**session_start** — записывается при запуске:
```json
{"ts":"2026-03-18T14:00:00.000Z","type":"session_start","target":"1.1.1.1","resolved_target":"one.one.one.one","traceroute_available":true,"config":{"port":443,"interval_icmp_ms":1000,"interval_dns_sec":30,"interval_tcp_sec":10,"interval_trace_sec":60,"history_size":3600,"icmp_strategy":"unprivileged"}}
```

**session_end** — записывается при корректном завершении (Ctrl+C / `q`):
```json
{"ts":"2026-03-18T16:15:39.000Z","type":"session_end","target":"1.1.1.1","duration_sec":8139,"summary":{"icmp_sent":8139,"icmp_received":8115,"loss_pct":0.29,"rtt_avg_ms":18.7,"rtt_p95_ms":32.4,"uptime_pct":99.71,"mos":4.3,"grade":"A","events_total":7}}
```


### Архитектура

```
                         ┌──────────────────────┐
                         │     main.rs           │
                         │  CLI parsing (clap)   │
                         │  Config construction  │
                         └──────────┬───────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │      app.rs           │
                         │  Tokio runtime init   │
                         │  Task orchestration   │
                         └──────────┬───────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    │               │               │
                    ▼               ▼               ▼
          ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
          │  Probe Tasks │ │   TUI Task   │ │  Logger Task │
          └──────┬───────┘ └──────┬───────┘ └──────┬───────┘
                 │                │                │
                 ▼                │                │
    ┌─────────────────────┐      │                │
    │  ┌───────────────┐  │      │                │
    │  │  ICMP Prober  │──┤      │                │
    │  └───────────────┘  │      │                │
    │  ┌───────────────┐  │      │                │
    │  │  DNS Prober   │──┤      │                │
    │  └───────────────┘  │      │                │
    │  ┌───────────────┐  │      │                │
    │  │  TCP/TLS/HTTP │──┤      │                │
    │  │  Prober       │──┤      │                │
    │  └───────────────┘  │      │                │
    │  ┌───────────────┐  │      │                │
    │  │  Traceroute   │──┤      │                │
    │  │  Prober       │──┤      │                │
    │  └───────────────┘  │      │                │
    │  ┌───────────────┐  │      │                │
    │  │  Anomaly      │──┤      │                │
    │  │  Detector     │  │      │                │
    │  └───────────────┘  │      │                │
    └─────────┬───────────┘      │                │
              │                  │                │
              ▼                  ▼                ▼
    ┌─────────────────────────────────────────────────┐
    │              MetricsStore                        │
    │         Arc<RwLock<State>>                       │
    │                                                  │
    │  Ring buffers per metric type                    │
    │  Current aggregates (Welford online stats)      │
    │  Latest traceroute snapshot                     │
    │  Event log (bounded deque)                      │
    │  Session counters                               │
    └─────────────────────────────────────────────────┘
```

Все probe tasks записывают результаты в `MetricsStore` (через write lock) и отправляют JSONL-записи в logger task через `tokio::sync::mpsc` канал. TUI task читает из `MetricsStore` (через read lock) с частотой ~4 FPS (250мс). Logger task получает записи из канала и пишет в файл (буферизированный `BufWriter`, flush каждые 5 секунд или при event).

Anomaly detector — не отдельная задача, а вызывается внутри ICMP prober после каждого сэмпла (синхронно, O(1) по Уэлфорду). При обнаружении аномалии — запись отправляется и в MetricsStore (event log), и в logger channel.

Graceful shutdown: `tokio::signal::ctrl_c()` + `CancellationToken` от `tokio-util`. При получении сигнала все задачи завершаются, logger записывает `session_end`, файл закрывается.


### Структура модулей

```
netprobe/
├── Cargo.toml
├── src/
│   ├── main.rs              Entrypoint, CLI parsing, runtime init
│   ├── config.rs            Структура конфигурации из CLI-аргументов
│   ├── app.rs               Оркестрация задач, lifecycle
│   ├── store.rs             MetricsStore — shared state, ring buffers, aggregates
│   ├── probe/
│   │   ├── mod.rs           Общий trait Prober, типы результатов
│   │   ├── icmp.rs          ICMP prober (surge-ping + subprocess fallback)
│   │   ├── dns.rs           DNS prober (hickory-resolver)
│   │   ├── tcp.rs           TCP connect prober (socket2)
│   │   ├── tls.rs           TLS handshake prober (rustls)
│   │   ├── http.rs          HTTP healthcheck prober
│   │   └── traceroute.rs    Traceroute prober (trippy-core)
│   ├── anomaly.rs           Anomaly detection (Welford, thresholds)
│   ├── logger.rs            JSONL writer (mpsc receiver → BufWriter)
│   ├── models.rs            Serde structs для всех JSONL-записей
│   ├── tui/
│   │   ├── mod.rs           TUI app loop, event handling, terminal setup
│   │   ├── layout.rs        Макет панелей (ratatui Layout)
│   │   ├── header.rs        Виджет верхней строки (хост, время, MOS, grade)
│   │   ├── ping_panel.rs    Панель ICMP (sparkline, агрегаты)
│   │   ├── dns_panel.rs     Панель DNS
│   │   ├── tcp_tls_panel.rs Панель TCP + TLS + HTTP
│   │   ├── trace_panel.rs   Панель traceroute (hop list с барами)
│   │   ├── events_panel.rs  Панель событий (scrollable log)
│   │   ├── sparkline.rs     Кастомный braille sparkline виджет
│   │   ├── theme.rs         Цветовая палитра, стили
│   │   └── footer.rs        Нижняя строка (hotkeys)
│   └── util.rs              Вспомогательные функции (formatting, MOS calc)
```


### TUI — макет дашборда

Общая структура — вертикальный стек панелей, как в btop. Каждая панель обрамлена рамкой типа `Rounded` с заголовком на верхней границе.

```
┌─── netprobe ── 1.1.1.1 (one.one.one.one) ─── 14:23:05 ─── 02:15:39 ─────────────┐
│                                                                       MOS 4.3 [A] │
├─ ping ─────────────────────────────────────────────────────────────────────────────┤
│                                                                                    │
│  RTT  ⣀⣤⣶⣶⣤⣀⣀⣤⣀⣀⣤⣶⣶⣤⣤⣀⣀⣤⣶⣶⣤⣤⣀⣀⣤⣶⣤⣀⣀⣤⣀⣀⣀⣤⣶⣶⣤⣀⣀⣤⣶⣀⣀⣀            │
│       12ms ──────────────────────────────────── 47ms                               │
│                                                                                    │
│  Now: 14.2ms  Avg: 18.7ms  Min: 11.3ms  Max: 47.1ms  p95: 32.4ms                │
│  Jitter: 2.1ms   Loss: 0.3%   Sent: 8142   Recv: 8118                            │
│                                                                                    │
├─ dns ──────────────────────────────────────────────────────────────────────────────┤
│                                                                                    │
│  Resolve: 4.2ms   IPs: 1.1.1.1, 1.0.0.1   TTL: 286s   Server: 192.168.1.1       │
│  ⣀⣤⣀⣀⣀⣤⣀⣀⣤⣀⣀⣀⣀⣤⣀⣀⣀⣀⣀⣀⣀⣤⣀⣀⣀⣀⣤⣀⣀                                         │
│                                                                                    │
├─ tcp/tls/http ──────────────────────────────────────── port 443 ───────────────────┤
│                                                                                    │
│  TCP: 15.1ms   TLS: 42.3ms   TTFB: 78.4ms   Total: 82.1ms   HTTP 200            │
│  TLSv1.3  TLS_AES_256_GCM_SHA384  Cert: 84 days remaining                        │
│  ⣀⣤⣶⣤⣀⣀⣤⣀⣤⣶⣤⣀⣀⣤⣶⣤⣀⣀⣤⣶⣤⣀⣀⣤⣶⣤⣀                                         │
│                                                                                    │
├─ traceroute ──────────────────────────────────────────────── hops: 11 ─────────────┤
│                                                                                    │
│   1  192.168.1.1      1.2ms  ████                                                 │
│   2  10.0.0.1         4.1ms  ████████                                             │
│   3  72.14.215.85     8.3ms  ████████████████                                     │
│   4  * * *            ---                                                          │
│   5  142.250.46.241  12.1ms  ████████████████████████                             │
│  ...                                                                               │
│  11  1.1.1.1         14.2ms  ████████████████████████████                          │
│                                                                                    │
├─ events ───────────────────────────────────────────────────────────────────────────┤
│                                                                                    │
│  14:22:51  ▲ RTT spike: 47.1ms (3.2σ)                                             │
│  14:20:03  ● Route change: hop 4 changed                                          │
│  14:18:30  ▼ Loss burst: 3 consecutive                                            │
│  14:15:12  ◆ DNS: new IP 1.0.0.1                                                  │
│                                                                                    │
├────────────────────────────────── q:quit  t:force traceroute  r:reset stats  ?:help┤
└────────────────────────────────────────────────────────────────────────────────────┘
```

Пропорции по высоте (adaptive, в процентах от доступного терминала):

- Header: 1 строка (фиксированно)
- Ping panel: ~30%
- DNS panel: ~12%
- TCP/TLS/HTTP panel: ~15%
- Traceroute panel: ~20%
- Events panel: ~18%
- Footer: 1 строка (фиксированно)

При уменьшении терминала ниже минимальной высоты (< 24 строки) — скрытие traceroute и events панелей. При ширине < 80 — сокращение числовых значений.


### Цветовая палитра (btop-inspired)

Фон: терминальный default (прозрачность). Рамки: `Color::Rgb(100, 100, 100)` — приглушённый серый. Заголовки на рамках: `Color::Rgb(0, 170, 255)` — голубой.

Цвета для значений метрик (по уровню серьёзности):

- Excellent: `Color::Rgb(0, 255, 0)` — ярко-зелёный
- Good: `Color::Rgb(170, 255, 0)` — жёлто-зелёный
- Warning: `Color::Rgb(255, 170, 0)` — оранжевый
- Critical: `Color::Rgb(255, 0, 0)` — красный

Sparkline-графики: градиент от зелёного к красному в зависимости от значения. Текст меток: `Color::White`. Неактивные/вспомогательные элементы: `Color::DarkGray`.

Events panel — иконки по типу события с цветом severity: info — голубой, warning — оранжевый, critical — красный.


### Braille sparkline

Стандартный `Sparkline` виджет ratatui использует блочные символы (▁▂▃▄▅▆▇█). Для btop-стиля требуется кастомный виджет, рисующий braille dots (Unicode block U+2800–U+28FF).

Каждый braille-символ кодирует матрицу 2×4 точек. Это позволяет отобразить до 4 уровней высоты в каждой строке и 2 точки данных на символ по горизонтали. Для sparkline высотой в 2 строки терминала — разрешение 8 уровней по вертикали и 2× плотность данных по горизонтали по сравнению с блочными символами.

Реализация — кастомный `StatefulWidget` в `tui/sparkline.rs`. Принимает `&[f64]` (ring buffer slice), min/max для масштабирования, ширину в символах. Нормализует данные в диапазон [0, max_dots_height], для каждой пары значений вычисляет braille-символ, применяет цвет из градиента.


### Hotkeys

- `q` / `Ctrl+C` — выход (graceful shutdown, запись session_end)
- `t` — принудительный запуск traceroute (вне расписания)
- `r` — сброс статистики (обнуление агрегатов, очистка ring buffers, новая «подсессия» — не влияет на лог)
- `?` — popup с описанием hotkeys
- `↑` / `↓` — скролл events panel
- `Tab` — переключение фокуса между панелями (для скролла traceroute / events)


### Зависимости (Cargo.toml)

```toml
[dependencies]
ratatui = { version = "0.30", features = ["crossterm"] }
crossterm = "0.29"
tokio = { version = "1", features = ["full"] }
tokio-util = "0.7"                           # CancellationToken
clap = { version = "4", features = ["derive"] }
surge-ping = "0.8"
hickory-resolver = "0.25"
socket2 = { version = "0.5", features = ["all"] }
rustls = { version = "0.23", features = ["ring"] }  # ring как CryptoProvider
webpki-roots = "1"                           # Mozilla root certificates
x509-parser = "0.18"                         # Certificate parsing
trippy-core = "0.13"
trippy-privilege = "0.13"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
chrono = { version = "0.4", features = ["serde"] }
anyhow = "1"                                 # Error handling
regex = "1"                                  # Парсинг вывода subprocess ping
tracing = "0.1"
tracing-subscriber = "0.3"

[target.'cfg(windows)'.dependencies]
windows-sys = "0.59"                         # для subprocess fallback на Windows
```


### Обработка ошибок

Ошибки probers — не фатальны. Каждый prober оборачивает свои ошибки в enum `ProbeError` и записывает их в лог со статусом `error` / `timeout`. TUI показывает последнюю ошибку в соответствующей панели вместо метрик.

Фатальные ошибки (не удалось открыть лог-файл, не удалось инициализировать ни одну ICMP-стратегию, не удалось зарезолвить хост при старте) — приводят к завершению с `anyhow::Result` и понятным сообщением в stderr.

Panic handling: `std::panic::set_hook` для восстановления терминала (disable raw mode, show cursor) перед выводом паники.


### Будущие расширения (out of scope для v1)

Эти функции не входят в первую версию, но архитектура не должна их блокировать:

- Multi-target мониторинг (табы в TUI)
- Экспорт метрик в Prometheus (metrics endpoint)
- GeoIP lookup для traceroute хопов (AS numbers, geography)
- Настраиваемые пороги аномалий через CLI или конфигурационный файл
- Alerting (webhook, email при critical events)
- Replay mode — воспроизведение сессии из JSONL-лога в TUI
