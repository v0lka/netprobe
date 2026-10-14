## netprobe — роадмап для кодинг-агента

Роадмап разбит на 10 фаз. Каждая фаза завершается компилируемым проектом с работающей функциональностью, которую можно проверить. Фазы выстроены так, что каждая следующая опирается на артефакты предыдущей и не требует рефакторинга ранее написанного кода.

Граф зависимостей между фазами:

```
Phase 1 (скелет + CLI + конфиг)
  │
  └──► Phase 2 (модели + store + logger)
         │
         └──► Phase 3 (ICMP prober)
                │
                ├──► Phase 4 (DNS prober)
                │      │
                │      └──► Phase 5 (TCP + TLS + HTTP prober)
                │             │
                │             └──► Phase 6 (traceroute prober)
                │                    │
                │                    └──► Phase 7 (anomaly detection) ← зависит от 3-6
                │
                └──► Phase 8 (TUI — скелет + ping panel)
                       │
                       └──► Phase 9 (TUI — все панели) ← зависит от 8 + 7
                              │
                              └──► Phase 10 (оркестрация) ← зависит от 1-9
```

Рекомендуемый порядок выполнения: строго последовательно 1 → 2 → 3 → 4 → 5 → 6 → 7 → 8 → 9 → 10. Параллелизация возможна для фаз 4+8 (после завершения 3), но промпты написаны для последовательного выполнения.


---


### Phase 1 — Скелет проекта, CLI, конфигурация

Цель: `cargo build` компилируется, `cargo run -- 1.1.1.1 --help` выводит справку, все CLI-аргументы парсятся в структуру `Config`.

Задачи:

1.1. Инициализировать Rust-проект `cargo init netprobe` со структурой каталогов из спецификации (src/probe/, src/tui/).

1.2. Написать `Cargo.toml` со всеми зависимостями из спецификации. Убедиться, что `cargo check` проходит без ошибок.

1.3. Создать `src/config.rs` — структура `Config` со всеми полями, соответствующими CLI-опциям. Все поля имеют типы и значения по умолчанию согласно спецификации. Поле `log_path` — `PathBuf`, значение по умолчанию вычисляется динамически: `./netprobe-<target>-<timestamp>.jsonl` (в `Cli::into_config()`, а не как clap default).

1.4. Создать `src/main.rs` — clap derive struct `Cli` с позиционным аргументом `target` и всеми опциями из спецификации. Функция `Cli::into_config() -> Config` для преобразования CLI-аргументов в `Config`. Точка входа `main()` парсит аргументы, строит `Config`, печатает его в stderr для отладки и завершается.

1.5. Создать пустые файлы-заглушки для всех модулей из спецификации (probe/mod.rs, probe/icmp.rs, ..., tui/mod.rs, tui/layout.rs, ..., store.rs, logger.rs, models.rs, anomaly.rs, util.rs, app.rs) с минимальным содержимым (пустой `pub mod` или `// TODO`), чтобы модульная структура компилировалась.

1.6. Убедиться, что `cargo run -- 1.1.1.1` компилируется и запускается, `cargo run -- --help` выводит справку со всеми опциями, `cargo run -- 1.1.1.1 --port 80 --no-http --interval-icmp 500 --log /tmp/test.jsonl` корректно парсит все аргументы.

Критерий завершения: `cargo test` и `cargo build` проходят без ошибок, `--help` выводит документированную справку.


---


### Phase 2 — Модели данных, MetricsStore, JSONL-логгер

Цель: определены все структуры данных для JSONL-записей и shared state, логгер принимает записи через mpsc-канал и пишет их в файл.

Задачи:

2.1. Создать `src/models.rs` — serde-структуры для всех типов JSONL-записей: `IcmpRecord`, `DnsRecord`, `TcpRecord`, `TlsRecord`, `HttpRecord`, `TracerouteRecord` (с вложенным `HopRecord`), `EventRecord`, `SessionStartRecord` (включая поле `traceroute_available: bool`), `SessionEndRecord` (с вложенным `SessionSummary` внутри поля `summary`, и верхнеуровневым `duration_sec`). Каждая структура должна реализовывать `Serialize`. Добавить enum `LogRecord` с вариантами для каждого типа и `#[serde(tag = "type", rename_all = "snake_case")]` для дискриминации по полю `type` со значениями в lowercase (`icmp`, `dns`, `tcp`, `tls`, `http`, `traceroute`, `event`, `session_start`, `session_end`). Все поля, типы и имена — строго по спецификации JSONL-формата (секция «JSONL формат лога»). Опциональные поля (rtt_ms при timeout) — `Option<f64>` с `#[serde(skip_serializing_if = "Option::is_none")]`.

2.2. Написать unit-тесты для `models.rs` — сериализация каждого типа записи в JSON и проверка, что результат совпадает с примерами из спецификации (поля, их имена, вложенность). Тесты должны вызываться через `cargo test`.

2.3. Создать `src/store.rs` — структура `MetricsStore` с полями: `RingBuffer<f64>` для RTT-истории ICMP (размер из `Config::history`), `RingBuffer<f64>` для DNS resolution time, `RingBuffer<f64>` для TCP connect time, `RingBuffer<f64>` для TLS handshake time, `RingBuffer<f64>` для TTFB. Также: текущие агрегаты ICMP (min, max, avg, p50, p95, p99, jitter, sent, received, loss_pct, duplicates, reordered), последний результат DNS/TCP/TLS/HTTP, последний snapshot traceroute, deque событий (bounded, максимум 200 записей), время старта сессии, флаг `traceroute_available`. `RingBuffer<T>` — простая обёртка над `VecDeque<T>` с фиксированной ёмкостью. `MetricsStore` будет использоваться как `Arc<RwLock<MetricsStore>>`. Реализовать методы: `push_icmp_rtt(rtt: f64)`, `push_dns_resolve(ms: f64)`, `push_tcp_connect(ms: f64)`, `push_tls_handshake(ms: f64)`, `push_ttfb(ms: f64)`, `inc_icmp_duplicate()`, `inc_icmp_reordered()`, `set_latest_dns(...)`, `set_latest_tcp(...)`, `set_latest_tls(...)`, `set_latest_http(...)`, `set_latest_traceroute(...)`, `push_event(...)`, `icmp_rtt_history() -> &[f64]`, и аналогичные read-методы для TUI.

2.4. Написать unit-тесты для `store.rs` — проверка ring buffer overflow, корректность агрегатов (min/max/avg), push/read round-trip.

2.5. Создать `src/util.rs` — функция `compute_jitter(rtt_history: &[f64]) -> f64` — jitter как среднее абсолютное отклонение между последовательными RTT: `mean(|rtt[i] - rtt[i-1]|)` (при менее чем 2 сэмплах — 0.0). Функция `compute_mos(avg_rtt: f64, jitter: f64, loss_pct: f64) -> f64` по формуле E-model из спецификации с clamping в `[1.0, 4.5]`. Функция `mos_to_grade(mos: f64) -> char` (A/B/C/D/F по порогам из спецификации). Функция `format_duration(secs: u64) -> String` для отображения длительности сессии (HH:MM:SS).

2.6. Написать unit-тесты для `util.rs` — MOS для идеального соединения (0ms, 0% loss), MOS для плохого соединения (500ms, 20% loss), граничные условия clamping, все пороги grade.

2.7. Создать `src/logger.rs` — структура `Logger`. Метод `Logger::new(path: &Path) -> Result<(Logger, mpsc::Sender<LogRecord>)>` открывает файл, создаёт `BufWriter`, создаёт mpsc-канал (buffer size 1024), возвращает Logger и sender. Метод `Logger::run(self, mut rx: mpsc::Receiver<LogRecord>, cancel: CancellationToken)` — async loop: получает записи из канала, сериализует в JSON + newline, пишет в BufWriter. Flush каждые 5 секунд (через `tokio::time::interval`) или немедленно при записи типа `event`. При получении cancel — flush, закрытие файла.

2.8. Написать integration test для `logger.rs` — создать канал, отправить несколько записей разных типов, дождаться flush, прочитать файл и проверить, что каждая строка — валидный JSON с правильным `type`.

Критерий завершения: `cargo test` — все тесты проходят. Модели корректно сериализуются, store аккумулирует данные, logger записывает JSONL.


---


### Phase 3 — ICMP Prober

Цель: ICMP prober пингует хост, записывает результаты в MetricsStore и отправляет JSONL-записи в logger.

Задачи:

3.1. Создать `src/probe/mod.rs` — определить `enum ProbeError` (Timeout, SocketError, PermissionDenied, ParseError, Other) с `Display` и `Error`. Определить `enum IcmpStrategy` (Unprivileged, Raw, Subprocess) для логирования выбранной стратегии.

3.2. Создать `src/probe/icmp.rs` — структура `IcmpProber`. Конструктор `IcmpProber::new(target: IpAddr, timeout: Duration) -> Result<(Self, IcmpStrategy)>` реализует гибридную стратегию: (1) попытка создать `surge_ping::Client` с `SOCK_DGRAM` (unprivileged), (2) при ошибке — попытка с `SOCK_RAW` (raw), (3) при ошибке — fallback на subprocess. Выбранная стратегия сохраняется в поле и возвращается. Для subprocess-режима: реализовать внутреннюю async-функцию `ping_subprocess(target, timeout) -> Result<(f64, u8)>` (возвращает RTT и TTL), которая вызывает `tokio::process::Command` с `ping -c 1 -W <timeout_sec>` (Unix) или `ping -n 1 -w <timeout_ms>` (Windows) и парсит stdout regex-ом. Метод `IcmpProber::ping(&self, seq: u16) -> Result<IcmpResult>` — выполняет один ping по выбранной стратегии, возвращает `IcmpResult { rtt: Option<Duration>, ttl: Option<u8>, seq: u16, status: IcmpStatus }`. Для вариантов 1 и 2 (surge-ping): детектировать duplicate-ответы (ответ с уже виденным seq) и reordered-ответы (seq меньше последнего виденного) — инкрементировать соответствующие счётчики в store.

3.3. Создать async-функцию `icmp_probe_loop(prober: IcmpProber, store: Arc<RwLock<MetricsStore>>, log_tx: mpsc::Sender<LogRecord>, config: Arc<Config>, cancel: CancellationToken)` в том же файле — бесконечный цикл с `tokio::time::interval(config.interval_icmp)`: выполняет ping, записывает результат в store (push_icmp_rtt), формирует `IcmpRecord`, отправляет в log_tx. При cancel — выход из цикла.

3.4. Написать unit-тесты для парсинга subprocess output — подготовить фиксированные строки вывода `ping` (macOS, Linux, Windows формат) и проверить, что парсинг RTT и TTL корректен. Тесты не требуют реального вызова ping.

Критерий завершения: при запуске в изоляции (без TUI) prober выполняет пинги и записи появляются в JSONL-файле. `cargo test` проходит.


---


### Phase 4 — DNS Prober

Цель: DNS prober резолвит хост, записывает метрики, детектирует изменения IP.

Задачи:

4.1. Создать `src/probe/dns.rs` — структура `DnsProber`. Конструктор `DnsProber::new(target: &str, dns_server: Option<IpAddr>, timeout: Duration) -> Result<Self>` инициализирует `hickory_resolver::TokioAsyncResolver` (с системной конфигурацией или явным сервером). Поле `previous_ips: HashSet<IpAddr>` для детекции изменений.

4.2. Метод `DnsProber::resolve(&mut self) -> DnsResult` — выполняет lookup с замером времени (`Instant::now()` до/после), извлекает IP-адреса, TTL, определяет статус. Сравнивает текущий набор IP с `previous_ips` — при различии возвращает `DnsChangeInfo` (old_ips, new_ips) внутри `DnsResult`. НЕ формирует EventRecord напрямую — это ответственность Phase 7 AnomalyDetector.

4.3. Создать async-функцию `dns_probe_loop(...)` — аналогично ICMP: interval loop, resolve, запись в store, отправка DnsRecord в log_tx. Если DnsResult содержит DnsChangeInfo — сохранить его для последующей передачи в AnomalyDetector (интеграция в Phase 7).

4.4. Написать unit-тест для логики детекции изменений IP (без реального DNS): вызов с одним набором IP, затем с другим, проверка что dns_change генерируется.

Критерий завершения: prober резолвит DNS, записи dns и event (при смене IP) появляются в JSONL. `cargo test` проходит.


---


### Phase 5 — TCP + TLS + HTTP Prober

Цель: единый prober выполняет последовательно TCP connect → TLS handshake → HTTP GET и замеряет каждую фазу раздельно.

Задачи:

5.1. Создать `src/probe/tcp.rs` — async-функция `tcp_connect(target: IpAddr, port: u16, timeout: Duration) -> Result<(TcpStream, Duration)>` — создаёт `socket2::Socket` (nonblocking TCP), вызывает `connect()`, замеряет время handshake через `tokio::time::timeout` + `TcpStream::connect`, возвращает поток и длительность. При ошибке — возвращает `ProbeError` (Refused, Timeout, Reset).

5.2. Создать `src/probe/tls.rs` — async-функция `tls_handshake(stream: TcpStream, hostname: &str, timeout: Duration) -> Result<(TlsStream, Duration, TlsInfo)>` — создаёт `rustls::ClientConfig` с `webpki_roots`, `ring` CryptoProvider, выполняет TLS handshake с замером времени. После handshake извлекает из `rustls::ClientConnection`: TLS version, cipher suite, peer certificates. Парсит leaf-сертификат через `x509_parser` — извлекает subject, issuer, SAN, validity (not_after). Вычисляет days_remaining. Возвращает TlsStream, длительность и структуру `TlsInfo { version, cipher, subject, issuer, san, expiry, days_remaining }`.

5.3. Создать `src/probe/http.rs` — async-функция `http_probe(stream: &mut impl AsyncRead + AsyncWrite, host: &str, path: &str, timeout: Duration) -> Result<HttpResult>` — формирует минимальный HTTP/1.1 GET-запрос (`GET <path> HTTP/1.1\r\nHost: <host>\r\nConnection: close\r\n\r\n`), отправляет, замеряет TTFB (время до первого байта ответа), парсит status line для status code. Возвращает `HttpResult { ttfb, total_time, status_code }`.

5.4. Создать async-функцию `tcp_tls_http_probe_loop(...)` — interval loop: (1) TCP connect → запись TcpRecord, (2) если TLS включён — TLS handshake → запись TlsRecord + проверка cert_expiry_warning, (3) если HTTP включён — HTTP GET → запись HttpRecord. Каждый шаг опционален в зависимости от `Config::no_tls` и `Config::no_http`. При ошибке на любом шаге — логирование ошибки и переход к следующему циклу (не прерывает дальнейшие фазы внутри текущего цикла, т.к. без TCP нет TLS, без TLS нет HTTP — при ошибке TCP пропускается весь цикл).

5.5. Написать unit-тест для парсинга HTTP status line — набор фиксированных response строк и проверка извлечения status code.

Критерий завершения: prober выполняет TCP+TLS+HTTP probe, три типа записей (tcp, tls, http) появляются в JSONL. `cargo test` проходит.


---


### Phase 6 — Traceroute Prober

Цель: периодический traceroute с сохранением hop-by-hop данных и детекцией изменений маршрута.

Задачи:

6.1. Создать `src/anomaly.rs` (предварительно, будет расширена в Phase 7) — структура `WindowedWelford` с полями: ring buffer фиксированного размера (параметр `window_size`), count, mean, m2. При вставке нового значения: если буфер полон — вытесняется старое значение с пересчётом mean и M2. Методы: `new(window_size: usize, warm_up: usize)`, `push(value: f64)`, `mean() -> f64`, `stddev() -> f64`, `is_warm() -> bool`. Два предустановленных профиля: `WindowedWelford::icmp()` — window 60, warm-up 30; `WindowedWelford::hop()` — window 10, warm-up 5. Unit-тесты: push N значений, проверка mean/stddev, проверка вытеснения при переполнении окна, проверка is_warm.

6.2. Создать `src/probe/traceroute.rs` — структура `TracerouteProber`. Конструктор проверяет наличие привилегий через `trippy_privilege` — если нет, возвращает `Err` (и вызывающий код устанавливает `traceroute_available = false` в store). Хранит `previous_hops: Vec<Option<IpAddr>>` для детекции route_change и `hop_rtt_stats: HashMap<usize, WindowedWelford>` (hop-профиль: окно 10, warm-up 5) для детекции per-hop RTT аномалий.

6.3. Метод `TracerouteProber::trace(&mut self) -> TracerouteResult` — использует `trippy_core` для выполнения traceroute. Собирает hop-by-hop данные: IP (или None для timeout), RTT, hostname (reverse DNS, если доступен). Сравнивает текущий маршрут с `previous_hops` — при различии возвращает `RouteChangeInfo` с описанием изменённых хопов. Обновляет WindowedWelford для каждого хопа и при отклонении RTT > 2σ (только после warm-up 5 сэмплов) возвращает `HopRttAnomalyInfo`. НЕ отправляет события в store/log напрямую — только возвращает их вызывающему коду.

6.4. Создать async-функцию `traceroute_probe_loop(...)` — interval loop + поддержка принудительного запуска через `tokio::sync::Notify` (для hotkey `t` из TUI). При каждом запуске: trace → запись TracerouteRecord в log_tx → обновление store. События route_change и hop_rtt_anomaly, возвращённые из trace(), передаются в store и log_tx (через Phase 7 `AnomalyDetector::on_route_change` и `on_hop_rtt_anomaly`). Таким образом, Phase 6 только возвращает сырые данные, а формирование EventRecord с severity — ответственность Phase 7.

6.5. Написать unit-тест для логики детекции route_change — два набора хопов с различиями, проверка генерации RouteChangeInfo.

Критерий завершения: traceroute выполняется периодически, записи traceroute и event (при смене маршрута) появляются в JSONL. При отсутствии привилегий — корректно отключается. `cargo test` проходит.


---


### Phase 7 — Anomaly Detection

Цель: детектор аномалий анализирует поток ICMP-метрик в реальном времени и генерирует события.

Задачи:

7.1. Расширить `src/anomaly.rs` (WindowedWelford уже создан в Phase 6) — добавить структуру `AnomalyDetector`. Если Phase 6 по какой-то причине не создала WindowedWelford, создать её здесь.

7.2. Структура `AnomalyDetector` с полями: `rtt_stats: WindowedWelford` (icmp-профиль), `jitter_stats: WindowedWelford` (icmp-профиль), `last_rtt: Option<f64>` (для вычисления jitter как `|rtt[i] - rtt[i-1]|`), `consecutive_losses: u32`. Severity-маппинг для каждого типа аномалии: `rtt_spike` → warning, `jitter_spike` → warning, `loss_burst` → critical, `route_change` → warning, `dns_change` → info, `cert_expiry_warning` → warning (< 30 дней) / critical (< 7 дней), `http_error` → critical, `tcp_refused` → critical, `hop_rtt_anomaly` → warning. Методы:

- `on_icmp_ok(rtt_ms: f64) -> Vec<AnomalyEvent>` — вычисляет jitter как `|rtt_ms - last_rtt|` (если есть предыдущий), обновляет rtt_stats и jitter_stats, сбрасывает consecutive_losses, проверяет rtt_spike (>3σ) и jitter_spike (>3σ), только если is_warm(). Сохраняет rtt_ms в last_rtt. Возвращает вектор обнаруженных аномалий (0, 1 или 2).
- `on_icmp_loss() -> Option<AnomalyEvent>` — инкрементирует consecutive_losses, при достижении 3 — генерирует loss_burst.
- `on_dns_change(old_ips, new_ips) -> AnomalyEvent` — формирует dns_change event.
- `on_route_change(description) -> AnomalyEvent` — формирует route_change event.
- `on_hop_rtt_anomaly(hop, ip, rtt, mean, sigma) -> AnomalyEvent` — формирует hop_rtt_anomaly event (вызывается из traceroute prober).
- `on_cert_expiry(days: i64) -> Option<AnomalyEvent>` — если days < 30, генерирует cert_expiry_warning (severity warning); если days < 7, severity critical.
- `on_http_error(status_code, message) -> AnomalyEvent` — формирует http_error event.
- `on_tcp_refused(message) -> AnomalyEvent` — формирует tcp_refused event.

7.3. Интегрировать `AnomalyDetector` в `icmp_probe_loop` (Phase 3): после каждого ping вызывать `on_icmp_ok` или `on_icmp_loss`, полученные события отправлять в store и log_tx.

7.4. Интегрировать вызовы `on_dns_change` в dns_probe_loop, `on_route_change` в traceroute_probe_loop, `on_cert_expiry` и `on_http_error`/`on_tcp_refused` в tcp_tls_http_probe_loop.

7.5. Написать unit-тесты: (a) 30 стабильных ping → нет аномалий, (b) 30 стабильных ping + 1 spike → rtt_spike, (c) 3 loss подряд → loss_burst, (d) 29 сэмплов + spike → нет аномалии (warm-up), (e) cert 29 дней → cert_expiry_warning.

Критерий завершения: anomaly detector корректно детектирует все типы аномалий с warm-up периодом. События появляются в JSONL. `cargo test` — все тесты проходят.


---


### Phase 8 — TUI: скелет, тема, braille sparkline, ping panel

Цель: работающий TUI с header, ping panel (с braille sparkline), footer и hotkey обработкой. Остальные панели — заглушки.

Задачи:

8.1. Создать `src/tui/theme.rs` — структура `Theme` со всеми цветами из спецификации (border, title, excellent/good/warning/critical, white, dark_gray). Функция `color_for_rtt(rtt: f64, p25: f64, p75: f64, p95: f64) -> Color` — возвращает цвет по пороговым значениям. Функция `color_for_severity(severity: &str) -> Color`.

8.2. Создать `src/tui/sparkline.rs` — кастомный braille sparkline виджет. Структура `BrailleSparkline` с полями: data (&[f64]), min/max для масштабирования, height (в строках терминала, по умолчанию 2). Реализовать `StatefulWidget` trait (не Widget — StatefulWidget позволяет сохранять состояние рендера между кадрами). Логика: нормализация данных → отображение в braille dot matrix (2 точки данных на символ по горизонтали, 4 уровня на строку по вертикали) → рендеринг braille-символов (U+2800–U+28FF) с цветовым градиентом. Цвет каждого символа определяется средним значением двух data-points, которые он отображает, через `color_for_rtt`.

8.3. Создать `src/tui/mod.rs` — основной TUI loop. Функция `run_tui(store: Arc<RwLock<MetricsStore>>, config: Arc<Config>, cancel: CancellationToken, trace_notify: Arc<Notify>) -> Result<()>`. Инициализация: `crossterm::terminal::enable_raw_mode()`, `AlternateScreen`, `CrosstermBackend`, `Terminal::new(...)`. Panic hook: `std::panic::set_hook` для восстановления терминала. Event loop: `crossterm::event::poll(Duration::from_millis(250))` для клавиш, затем read lock на store и рендеринг. Обработка hotkeys: `q` → cancel.cancel(), `t` → trace_notify.notify_one(), `r` → store.write().reset(), `?` → toggle help popup, `↑`/`↓` → скролл events, `Tab` → переключение фокуса.

8.4. Создать `src/tui/layout.rs` — функция `build_layout(area: Rect) -> Layout` — вертикальный стек с пропорциями из спецификации (header 1 строка, ping 30%, dns 12%, tcp/tls 15%, traceroute 20%, events 18%, footer 1 строка). Адаптивность: при height < 24 — скрытие traceroute и events; при width < 80 — сокращённый формат числовых значений (без p95/p99, сокращённые метки).

8.5. Создать `src/tui/header.rs` — рендеринг верхней строки: `netprobe ── <target> (<hostname>) ── <time> ── <session_duration> ── MOS <value> [<grade>]`. MOS и grade — из store. Цвет MOS — по grade (A=excellent, B=good, C=warning, D/F=critical).

8.6. Создать `src/tui/ping_panel.rs` — панель ping. Block с `Borders::ALL`, `BorderType::Rounded`, title ` ping ` на верхней рамке. Содержимое: BrailleSparkline (RTT history из store), строка с min/max под ним, строка с Now/Avg/Min/Max/p95, строка с Jitter/Loss/Sent/Recv. Все числа с цветами по theme.

8.7. Создать `src/tui/footer.rs` — нижняя строка с hotkeys: `q:quit  t:force traceroute  r:reset stats  ?:help`.

8.8. Создать заглушки для остальных панелей (`dns_panel.rs`, `tcp_tls_panel.rs`, `trace_panel.rs`, `events_panel.rs`) — Block с title и текстом «waiting for data...». Каждая панель должна также уметь показывать состояние ошибки: если последний результат prober'а — ошибка, вместо метрик отображать сообщение об ошибке красным цветом (это поведение будет реализовано полностью в Phase 9, здесь — заложить структуру).

8.9. Интегрировать всё в `tui/mod.rs` — рендеринг layout → header → ping_panel → заглушки → footer.

Критерий завершения: `cargo run -- 1.1.1.1` запускает TUI, ping panel показывает live braille sparkline с RTT-данными, hotkeys работают, `q` корректно завершает. `cargo test` проходит.


---


### Phase 9 — TUI: все панели

Цель: все панели дашборда полностью реализованы и отображают данные из MetricsStore.

Задачи:

9.1. Реализовать `src/tui/dns_panel.rs` — Block с title ` dns `. Содержимое: текущее resolve time, список IP, TTL, DNS server. BrailleSparkline для истории resolve time. При dns_change — подсвечивание изменённых IP. При ошибке DNS (timeout/servfail) — вместо метрик показать сообщение об ошибке красным цветом.

9.2. Реализовать `src/tui/tcp_tls_panel.rs` — Block с title ` tcp/tls/http ── port <N> `. Содержимое: TCP connect time, TLS handshake time, TTFB, Total time, HTTP status code. TLS version, cipher, cert days remaining (с цветовым кодированием: зелёный > 60 дней, оранжевый 30–60, красный < 30). BrailleSparkline для истории TCP connect time. Если `--no-http` или `--no-tls` — соответствующие строки показывают «disabled». При ошибке prober'а (refused, timeout, TLS error) — показать последнюю ошибку красным вместо метрик.

9.3. Реализовать `src/tui/trace_panel.rs` — Block с title ` traceroute ── hops: <N> `. Содержимое: список хопов, для каждого — номер, IP (или `* * *`), RTT, горизонтальный bar (████) пропорциональный RTT. Bar цвет — по theme (зелёный для малого RTT, красный для большого). Скроллируемый при >10 хопов (через `Tab` фокус + `↑`/`↓`). При `traceroute_available = false` — текст «traceroute unavailable: insufficient privileges». При ошибке traceroute — показать ошибку красным.

9.4. Реализовать `src/tui/events_panel.rs` — Block с title ` events `. Содержимое: список последних событий из store.events (до 200). Каждое: timestamp (HH:MM:SS), иконка по типу (▲ rtt_spike, ▼ loss_burst, ● route_change, ◆ dns_change, ✦ cert_expiry, ✕ http_error/tcp_refused), сообщение. Цвет по severity. Скроллируемый (фокус через `Tab`, скролл `↑`/`↓`). Автоскролл к последнему событию, пока пользователь не начнёт ручной скролл.

9.5. Реализовать popup `?` — overlay поверх дашборда с описанием всех hotkeys. Закрывается по `?` или `Esc`.

9.6. Обновить `tui/mod.rs` — заменить заглушки на реальные панели, интегрировать фокус-менеджмент (Tab переключает focusable panels: trace, events).

Критерий завершения: все панели отображают live-данные, скролл работает в trace и events, popup `?` отображается корректно. Визуально приближено к стилю btop (braille графики, цвета, рамки с заголовками). `cargo test` проходит.


---


### Phase 10 — Оркестрация, lifecycle, graceful shutdown

Цель: все компоненты объединены в `app.rs`, приложение полноценно работает от запуска до завершения.

Задачи:

10.1. Создать `src/app.rs` — async-функция `run(config: Config) -> Result<()>`. Последовательность: (1) начальный DNS resolve TARGET → получение IP (если TARGET — домен): при dual-stack (IPv4 + IPv6) предпочтение IPv4, при явном указании IPv6-адреса — использовать IPv6 (поддержка ICMPv6, AAAA, IPv6 traceroute), (2) определение ICMP стратегии, (3) проверка привилегий для traceroute, (4) создание `MetricsStore`, (5) создание Logger + получение log_tx, (6) запись `session_start` в log, (7) создание `CancellationToken`, `Arc<Notify>` для traceroute, (8) spawn всех probe tasks (icmp_probe_loop, dns_probe_loop, tcp_tls_http_probe_loop, traceroute_probe_loop — если available), (9) spawn logger task, (10) если не `--quiet` — запуск TUI (в текущем tokio task, т.к. TUI блокирует), иначе — ожидание ctrl_c.

10.2. Graceful shutdown: при cancel (от TUI `q`, от `ctrl_c`, или от Ctrl+C в quiet mode) — все probe tasks завершаются (проверяют cancel token в каждом цикле), logger получает `session_end` запись (формируемую в app.rs из текущего состояния store), logger завершает flush и закрывает файл. TUI восстанавливает терминал (disable_raw_mode, LeaveAlternateScreen, show_cursor). Формат session_end — строго по спецификации: верхнеуровневые поля `target`, `duration_sec`, вложенный объект `summary` с полями `icmp_sent`, `icmp_received`, `loss_pct`, `rtt_avg_ms`, `rtt_p95_ms`, `uptime_pct`, `mos`, `grade`, `events_total`.

10.3. Обновить `src/main.rs` — `fn main()`: парсинг CLI → `Config`, инициализация `tracing_subscriber` (в файл, не в stderr, чтобы не мешать TUI), вызов `tokio::runtime::Runtime::new()?.block_on(app::run(config))`. Обработка результата: при ошибке — вывод в stderr и exit(1).

10.4. Убедиться, что `--quiet` режим работает: нет TUI, probers работают, JSONL пишется, Ctrl+C корректно завершает с session_end.

10.5. Убедиться, что при отсутствии привилегий для ICMP (subprocess fallback) и traceroute (disabled) приложение всё равно запускается и работает корректно с оставшимися probers.

10.6. Написать integration test: запуск `netprobe 127.0.0.1 --quiet --interval-icmp 100 --log /tmp/test.jsonl` на 3 секунды → проверка что JSONL содержит session_start, несколько icmp записей и session_end. Тест использует `assert_cmd` или `tokio::process::Command`.

10.7. Финальная проверка: `cargo clippy` без warnings, `cargo fmt --check`, `cargo test` — все тесты проходят, `cargo build --release`.

Критерий завершения: приложение полностью работоспособно. Запуск `netprobe 1.1.1.1` отображает TUI дашборд со всеми панелями, live-данными и braille-графиками. `netprobe 1.1.1.1 --quiet --log /tmp/probe.jsonl` ведёт только JSONL-лог. Graceful shutdown корректен. `cargo clippy`, `cargo test`, `cargo build --release` — без ошибок.


---


### Промпты для агента

Каждый промпт предназначен для отправки кодинг-агенту для реализации одной фазы. Промпт содержит: контекст (ссылку на спецификацию), scope фазы, атомарные задачи, критерии приёмки, ограничения.


#### Промпт — Phase 1

```
Ты реализуешь Phase 1 проекта netprobe — сетевой мониторинг на Rust + Ratatui.

Полная спецификация проекта находится в файле netprobe-spec.md — прочитай его целиком перед началом работы. В этой фазе ты работаешь только со скелетом проекта, CLI и конфигурацией.

Что нужно сделать:

1. Инициализируй Rust-проект `netprobe` со структурой каталогов из спецификации (src/probe/, src/tui/ и все файлы внутри).

2. Напиши Cargo.toml со ВСЕМИ зависимостями из секции «Зависимости (Cargo.toml)» спецификации. Запусти `cargo check` и убедись что компилируется.

3. Создай src/config.rs — структура Config со всеми полями, соответствующими CLI-опциям из спецификации (включая таймауты, интервалы, port, http_path, no_http, no_tls, quiet, history, dns_server, log_path, target). Все значения по умолчанию — из спецификации. Поле log_path — динамический default (`./netprobe-<target>-<timestamp>.jsonl`), вычисляемый в Cli::into_config(), а не как clap default.

4. Создай src/main.rs — clap derive struct Cli с позиционным аргументом target и всеми опциями (включая --version через #[command(version)]). Реализуй Cli::into_config() -> Config. В main() парсим аргументы, строим Config, печатаем debug-вывод в stderr.

5. Создай пустые файлы-заглушки для ВСЕХ модулей из спецификации (probe/mod.rs, probe/icmp.rs, probe/dns.rs, probe/tcp.rs, probe/tls.rs, probe/http.rs, probe/traceroute.rs, tui/mod.rs, tui/layout.rs, tui/header.rs, tui/ping_panel.rs, tui/dns_panel.rs, tui/tcp_tls_panel.rs, tui/trace_panel.rs, tui/events_panel.rs, tui/sparkline.rs, tui/theme.rs, tui/footer.rs, store.rs, logger.rs, models.rs, anomaly.rs, util.rs, app.rs) — каждый с минимальным содержимым чтобы проект компилировался.

Критерий завершения (проверь перед ответом):
- `cargo build` проходит без ошибок
- `cargo run -- --help` выводит справку со ВСЕМИ опциями из спецификации
- `cargo run -- 1.1.1.1 --port 80 --no-http --interval-icmp 500 --log /tmp/test.jsonl` корректно парсит аргументы
- Модульная структура полностью соответствует спецификации
```


#### Промпт — Phase 2

```
Ты реализуешь Phase 2 проекта netprobe — модели данных, MetricsStore и JSONL-логгер.

Полная спецификация проекта — в netprobe-spec.md. Phase 1 уже выполнена (скелет, CLI, Config). Прочитай спецификацию и существующий код перед началом работы.

Что нужно сделать:

1. src/models.rs — serde-структуры для ВСЕХ типов JSONL-записей из спецификации (секция «JSONL формат лога»): IcmpRecord, DnsRecord, TcpRecord, TlsRecord, HttpRecord, TracerouteRecord (с HopRecord), EventRecord, SessionStartRecord (включая traceroute_available: bool), SessionEndRecord (с вложенной структурой SessionSummary в поле summary + верхнеуровневое duration_sec). Enum LogRecord с #[serde(tag = "type", rename_all = "snake_case")] для дискриминации — значения type должны быть lowercase (icmp, dns, session_start и т.д.), а не PascalCase. Поля, имена, типы — строго по примерам JSONL из спецификации. Опциональные поля (rtt_ms при timeout) — Option с skip_serializing_if.

2. Unit-тесты для models.rs — сериализация каждого типа в JSON, проверка что выход совпадает с примерами из спецификации. ВАЖНО: проверить что поле "type" сериализуется в lowercase ("icmp", а не "Icmp"), что session_end содержит "duration_sec" и вложенный "summary", что session_start содержит "traceroute_available".

3. src/store.rs — MetricsStore с ring buffers (обёртка над VecDeque с фиксированной ёмкостью) для: RTT ICMP, DNS resolve time, TCP connect time, TLS handshake time, TTFB. Агрегаты ICMP (min/max/avg/p50/p95/p99, jitter, sent/received/loss_pct, duplicate count, reordered count). Последний результат каждого prober (включая статус — ok или последняя ошибка для отображения в TUI). Deque событий (max 200). Время старта. Все нужные push/get методы.

4. Unit-тесты для store.rs — ring buffer overflow, корректность агрегатов.

5. src/util.rs — compute_jitter (jitter = mean(|rtt[i] - rtt[i-1]|), при < 2 сэмплах → 0.0), compute_mos (формула E-model из спецификации, clamping [1.0, 4.5]), mos_to_grade (A/B/C/D/F), format_duration.

6. Unit-тесты для util.rs — jitter для последовательности [10, 20, 10, 20] = 10.0; MOS идеального/плохого соединения, clamping, все пороги grade.

7. src/logger.rs — Logger с mpsc-каналом. Logger::new() → (Logger, Sender<LogRecord>). Logger::run() — async loop: приём из канала → JSON serialize + newline → BufWriter. Flush каждые 5 секунд или немедленно при event. CancellationToken для graceful stop.

8. Integration test для logger.rs — канал → записи → flush → чтение файла → валидация JSON.

Критерий завершения:
- `cargo test` — ВСЕ тесты проходят
- Модели точно соответствуют JSONL-примерам из спецификации
- Logger реально пишет валидный JSONL в файл
```


#### Промпт — Phase 3

```
Ты реализуешь Phase 3 проекта netprobe — ICMP Prober.

Полная спецификация — в netprobe-spec.md. Phase 1-2 уже выполнены. Прочитай спецификацию (секция «L3 — ICMP Ping») и существующий код (config.rs, models.rs, store.rs, logger.rs) перед работой.

Что нужно сделать:

1. src/probe/mod.rs — enum ProbeError (Timeout, SocketError, PermissionDenied, ParseError, Other) с Display и Error. Enum IcmpStrategy (Unprivileged, Raw, Subprocess).

2. src/probe/icmp.rs — IcmpProber с гибридной стратегией из спецификации:
   - Вариант 1: surge_ping с SOCK_DGRAM (unprivileged)
   - Вариант 2: surge_ping с SOCK_RAW (raw)
   - Вариант 3: subprocess fallback — ping -c 1 (Unix) / ping -n 1 (Windows), парсинг stdout
   Стратегия выбирается один раз в конструкторе. Метод ping() выполняет один probe, возвращает IcmpResult (rtt, ttl, seq, status).

3. Async-функция icmp_probe_loop — interval loop: ping → запись в MetricsStore (push_icmp_rtt) → формирование IcmpRecord → отправка в log_tx. При cancel — выход.

4. Unit-тесты для парсинга subprocess output — фиксированные строки вывода ping (macOS формат, Linux формат, Windows формат) → проверка парсинга RTT и TTL.

Критерий завершения:
- При запуске в изоляции (без TUI) prober выполняет пинги
- JSONL-записи типа icmp корректно формируются
- Subprocess fallback парсит вывод ping на всех платформах
- `cargo test` проходит
```


#### Промпт — Phase 4

```
Ты реализуешь Phase 4 проекта netprobe — DNS Prober.

Полная спецификация — в netprobe-spec.md (секция «DNS Resolution»). Phase 1-3 уже выполнены. Прочитай спецификацию и существующий код перед работой.

Что нужно сделать:

1. src/probe/dns.rs — DnsProber. Конструктор инициализирует hickory_resolver::TokioAsyncResolver (системный конфиг или явный --dns-server). Хранит previous_ips: HashSet<IpAddr> для детекции изменений.

2. Метод resolve() — lookup с замером времени (Instant::now), извлечение IP, TTL, статус. Сравнение с previous_ips → возвращает DnsChangeInfo (old_ips, new_ips) внутри DnsResult, если набор изменился. НЕ формирует EventRecord напрямую — это делает AnomalyDetector (Phase 7).

3. Async-функция dns_probe_loop — interval loop: resolve → запись в store → DnsRecord в log_tx. Если DnsResult содержит DnsChangeInfo — сохранить для последующей передачи в AnomalyDetector (интеграция в Phase 7).

4. Unit-тест для детекции изменений IP — два вызова с разными наборами → проверка генерации события.

Критерий завершения:
- DNS-записи появляются в JSONL
- При смене IP генерируется event типа dns_change
- `cargo test` проходит
```


#### Промпт — Phase 5

```
Ты реализуешь Phase 5 проекта netprobe — TCP + TLS + HTTP Prober.

Полная спецификация — в netprobe-spec.md (секции «L4 — TCP Connect» и «L7 — TLS + HTTP(S)»). Phase 1-4 уже выполнены. Прочитай спецификацию и существующий код перед работой.

Это КЛЮЧЕВАЯ фаза — здесь реализуется низкоуровневый подход socket2 → rustls → raw HTTP для раздельного замера таймингов каждой фазы.

Что нужно сделать:

1. src/probe/tcp.rs — async tcp_connect(target, port, timeout) → (TcpStream, Duration). Использовать `socket2::Socket` для создания неблокирующего TCP-сокета с точным замером TCP handshake time (Instant::now до connect, Instant::now после). Затем конвертировать socket2::Socket в tokio::net::TcpStream. Причина: socket2 даёт точный контроль над моментом вызова connect() и его завершения, что необходимо для изолированного timing TCP handshake.

2. src/probe/tls.rs — async tls_handshake(stream, hostname, timeout) → (TlsStream, Duration, TlsInfo). rustls::ClientConfig с ring CryptoProvider и webpki_roots. Замер TLS handshake time. Извлечение: TLS version, cipher, peer_certificates. Парсинг leaf cert через x509_parser — subject, issuer, SAN, validity, days_remaining.

3. src/probe/http.rs — async http_probe(stream, host, path, timeout) → HttpResult. Минимальный GET запрос, замер TTFB (до первого байта ответа), парсинг status line → status_code.

4. Async-функция tcp_tls_http_probe_loop — interval loop: TCP → TcpRecord, TLS (если включён) → TlsRecord + проверка cert_expiry, HTTP (если включён) → HttpRecord. При ошибке TCP — пропуск всего цикла. Учитывай флаги Config::no_tls и Config::no_http.

5. Unit-тест для парсинга HTTP status line.

Критерий завершения:
- TCP, TLS, HTTP замеры работают раздельно с точными таймингами
- Три типа записей (tcp, tls, http) в JSONL
- cert_days_remaining корректно вычисляется
- `cargo test` проходит
```


#### Промпт — Phase 6

```
Ты реализуешь Phase 6 проекта netprobe — Traceroute Prober.

Полная спецификация — в netprobe-spec.md (секция «Traceroute»). Phase 1-5 уже выполнены. Прочитай спецификацию и существующий код перед работой.

Что нужно сделать:

1. src/probe/traceroute.rs — TracerouteProber. Конструктор проверяет привилегии через trippy_privilege. Если нет — возвращает Err (traceroute_available = false). Хранит previous_hops для детекции route_change и per-hop WindowedWelford (HashMap<hop_number, WindowedWelford>, hop-профиль: окно 10, warm-up 5) для детекции аномальных RTT.

2. Метод trace() → TracerouteResult — trippy_core traceroute. Сбор hop-by-hop: IP/None, RTT, hostname. Сравнение с previous_hops → возвращает RouteChangeInfo (если есть). Обновление per-hop WindowedWelford, при отклонении RTT > 2σ (после warm-up 5) → возвращает HopRttAnomalyInfo. Метод НЕ формирует EventRecord — только возвращает сырые данные (events формируются AnomalyDetector в Phase 7).

3. Async-функция traceroute_probe_loop — interval loop + tokio::sync::Notify для принудительного запуска (hotkey t). TracerouteRecord → log_tx, обновление store. route_change и hop_rtt_anomaly данные сохраняются для передачи в AnomalyDetector (интеграция в Phase 7, аналогично dns_probe_loop).

4. Unit-тест для детекции route_change — два набора хопов с различиями.

Важно: при недостаточных привилегиях traceroute полностью отключается. В session_start записывается traceroute_available: false (поле уже предусмотрено в SessionStartRecord, Phase 2). TUI-панель покажет сообщение (реализуется в Phase 9).

Критерий завершения:
- Traceroute записи в JSONL с hop-by-hop данными
- Route change детектируется
- При отсутствии привилегий — корректное отключение без краша
- `cargo test` проходит
```


#### Промпт — Phase 7

```
Ты реализуешь Phase 7 проекта netprobe — Anomaly Detection.

Полная спецификация — в netprobe-spec.md (секция «Anomaly Detection»). Phase 1-6 уже выполнены. Прочитай спецификацию и существующий код перед работой.

Что нужно сделать:

1. src/anomaly.rs — WindowedWelford уже создан в Phase 6 (task 6.1). Если по какой-то причине не существует — создать. Убедиться что WindowedWelford полностью функциональна (push, mean, stddev, is_warm, два профиля icmp/hop).

   Добавить в тот же файл AnomalyDetector с полями: rtt_stats и jitter_stats (оба WindowedWelford::icmp()), last_rtt: Option<f64> для вычисления jitter как |rtt[i] - rtt[i-1]|, consecutive_losses: u32. Методы:
   - on_icmp_ok(rtt_ms) → Vec<AnomalyEvent> — вычисляет jitter = |rtt_ms - last_rtt| (если есть предыдущий), пушит в rtt_stats и jitter_stats, сбрасывает consecutive_losses, проверяет rtt_spike (>3σ) и jitter_spike (>3σ) только если is_warm(), сохраняет last_rtt. Возвращает 0-2 аномалии.
   - on_icmp_loss() → Option<AnomalyEvent> — loss_burst при 3+ подряд
   - on_dns_change(old_ips, new_ips) → AnomalyEvent
   - on_route_change(description) → AnomalyEvent
   - on_hop_rtt_anomaly(hop, ip, rtt, mean, sigma) → AnomalyEvent
   - on_cert_expiry(days) → Option<AnomalyEvent> — warning при <30, critical при <7
   - on_http_error(status_code, message) → AnomalyEvent
   - on_tcp_refused(message) → AnomalyEvent

   Severity-маппинг для каждого типа:
   - rtt_spike → warning
   - jitter_spike → warning
   - loss_burst → critical
   - route_change → warning
   - dns_change → info
   - hop_rtt_anomaly → warning
   - cert_expiry_warning → warning (< 30 дней), critical (< 7 дней)
   - http_error → critical
   - tcp_refused → critical

2. Интегрируй AnomalyDetector в ВСЕ probe loops:
   - icmp_probe_loop: on_icmp_ok / on_icmp_loss после каждого ping
   - dns_probe_loop: при DnsChangeInfo из resolve() → вызов on_dns_change → отправка EventRecord
   - traceroute_probe_loop: при RouteChangeInfo → on_route_change; при HopRttAnomalyInfo → on_hop_rtt_anomaly → отправка EventRecord для каждого
   - tcp_tls_http_probe_loop: on_cert_expiry, on_http_error, on_tcp_refused

3. Обнаруженные события → push в store.events + отправка EventRecord в log_tx.

4. Unit-тесты:
   - 30 стабильных ping (rtt=20ms) → нет аномалий
   - 30 стабильных + 1 spike (rtt=200ms) → rtt_spike
   - 3 loss подряд → loss_burst
   - 29 сэмплов + spike → НЕТ аномалии (warm-up)
   - cert 29 дней → cert_expiry_warning, cert 31 день → ничего

Критерий завершения:
- Все типы аномалий из спецификации детектируются
- Warm-up 30 сэмплов соблюдается
- События появляются и в store, и в JSONL
- `cargo test` — ВСЕ тесты проходят
```


#### Промпт — Phase 8

```
Ты реализуешь Phase 8 проекта netprobe — TUI скелет с темой, braille sparkline и ping panel.

Полная спецификация — в netprobe-spec.md (секции «TUI — макет дашборда», «Цветовая палитра», «Braille sparkline», «Hotkeys»). Phase 1-7 уже выполнены. Прочитай спецификацию и ВЕСЬ существующий код перед работой.

Визуальный стиль — btop (см. спецификацию): рамки Rounded с заголовками на рамке, braille-графики, цветовая палитра excellent→critical.

Что нужно сделать:

1. src/tui/theme.rs — Theme со всеми цветами из спецификации. Функции color_for_rtt (по порогам p25/p75/p95), color_for_severity.

2. src/tui/sparkline.rs — КАСТОМНЫЙ braille sparkline виджет (не стандартный Sparkline из ratatui). Unicode U+2800–U+28FF. Каждый символ = 2 data points по горизонтали, 4 уровня по вертикали на строку. Высота: 2 строки = 8 уровней разрешения. Цветовой градиент по значению. Реализуй StatefulWidget trait (не Widget — StatefulWidget позволяет сохранять состояние между кадрами, это нужно для viewport tracking).

3. src/tui/mod.rs — TUI event loop: enable_raw_mode, AlternateScreen, Terminal. Panic hook для восстановления терминала. Poll 250ms для hotkeys, read lock на store, рендеринг. Hotkeys: q (cancel), t (trace notify), r (reset), ? (help popup), ↑↓ (scroll), Tab (focus).

4. src/tui/layout.rs — вертикальный стек с пропорциями из спецификации. Адаптивность: при height < 24 — скрытие traceroute и events; при width < 80 — сокращённый формат числовых значений (без p95/p99, сокращённые метки).

5. src/tui/header.rs — верхняя строка: netprobe ── target ── time ── session duration ── MOS [grade]. Цвета MOS по grade.

6. src/tui/ping_panel.rs — Block Rounded с title ` ping `. BrailleSparkline (RTT history), min/max labels, Now/Avg/Min/Max/p95, Jitter/Loss/Sent/Recv. Цвета по theme.

7. src/tui/footer.rs — hotkeys строка.

8. Заглушки для dns_panel, tcp_tls_panel, trace_panel, events_panel — Block с «waiting for data...». Каждая заглушка должна также поддерживать отображение ошибки prober'а красным цветом (структура для Phase 9).

9. Интегрировать всё в tui/mod.rs — рендеринг: layout → header → ping_panel → заглушки → footer.

Критерий завершения:
- `cargo run -- 1.1.1.1` запускает TUI
- Ping panel показывает LIVE braille sparkline с RTT
- Header обновляется каждый тик
- Hotkeys работают (q выходит, r сбрасывает)
- Визуально — btop стиль: braille dots, цветовой градиент, Rounded рамки
```


#### Промпт — Phase 9

```
Ты реализуешь Phase 9 проекта netprobe — все оставшиеся TUI-панели.

Полная спецификация — в netprobe-spec.md (секция «TUI — макет дашборда»). Phase 1-8 уже выполнены, ping panel и TUI скелет работают. Прочитай спецификацию и существующий код (особенно tui/theme.rs, tui/sparkline.rs, tui/ping_panel.rs как образец) перед работой.

Что нужно сделать:

1. src/tui/dns_panel.rs — Block ` dns `. Resolve time, IP list, TTL, server. BrailleSparkline для resolve time history. При ошибке DNS prober'а (timeout, servfail) — вместо метрик показать последнюю ошибку красным цветом.

2. src/tui/tcp_tls_panel.rs — Block ` tcp/tls/http ── port <N> `. TCP/TLS/TTFB/Total timings, HTTP status. TLS version, cipher, cert days remaining (цвет: зелёный >60d, оранжевый 30-60d, красный <30d). BrailleSparkline для TCP time. «disabled» при --no-http/--no-tls. При ошибке prober'а (refused, timeout, TLS error) — показать ошибку красным вместо метрик.

3. src/tui/trace_panel.rs — Block ` traceroute ── hops: N `. Hop list: номер, IP (или * * *), RTT, горизонтальный bar (████) пропорциональный RTT. Цвет bars по theme. Скролл при >10 хопов. При traceroute_available=false — «traceroute unavailable: insufficient privileges». При ошибке — показать ошибку красным.

4. src/tui/events_panel.rs — Block ` events `. Список событий: timestamp, иконка по типу (▲ spike, ▼ loss, ● route, ◆ dns, ✦ cert, ✕ error, ⬥ hop_rtt_anomaly), сообщение. Цвет по severity. Скролл, автоскролл к последнему (пока нет ручного скролла).

5. Help popup (?) — overlay с описанием hotkeys. Закрытие по ? или Esc.

6. Обнови tui/mod.rs — замени заглушки на реальные панели, добавь focus-менеджмент (Tab: trace ↔ events).

Критерий завершения:
- ВСЕ 6 панелей (header, ping, dns, tcp/tls/http, traceroute, events) отображают live-данные
- Скролл работает в trace и events
- Help popup отображается и закрывается
- Визуально — единый btop-стиль по всем панелям
```


#### Промпт — Phase 10

```
Ты реализуешь Phase 10 (ФИНАЛЬНАЯ) проекта netprobe — оркестрация, lifecycle, graceful shutdown.

Полная спецификация — в netprobe-spec.md (секция «Архитектура»). Phase 1-9 уже выполнены, все probers и TUI работают по отдельности. Прочитай спецификацию и ВЕСЬ существующий код перед работой.

Что нужно сделать:

1. src/app.rs — async fn run(config: Config) → Result<()>:
   - Начальный DNS resolve TARGET (если домен) → получение IP. IPv6 поддержка: при dual-stack (IPv4 + IPv6) предпочтение IPv4. Если TARGET — явный IPv6-адрес, использовать IPv6 (surge-ping поддерживает ICMPv6, hickory-resolver — AAAA, trippy-core — IPv6 traceroute)
   - Определение ICMP стратегии (гибридная Option C)
   - Проверка привилегий для traceroute (trippy_privilege)
   - Создание Arc<RwLock<MetricsStore>>
   - Создание Logger + mpsc канал
   - Запись session_start
   - Создание CancellationToken + Arc<Notify> для traceroute
   - tokio::spawn для КАЖДОГО probe loop (icmp, dns, tcp_tls_http, traceroute если available)
   - tokio::spawn для logger
   - Если не --quiet: запуск TUI (блокирующий)
   - Если --quiet: tokio::signal::ctrl_c().await

2. Graceful shutdown: cancel token → все задачи завершаются → формирование session_end из текущего store. Формат session_end — строго по спецификации: верхнеуровневые поля target и duration_sec, вложенный объект summary с полями icmp_sent, icmp_received (НЕ просто received), loss_pct, rtt_avg_ms (НЕ rtt_avg), rtt_p95_ms (НЕ rtt_p95), uptime_pct, mos, grade, events_total. → отправка в logger → logger flush и close → TUI восстанавливает терминал.

3. src/main.rs — парсинг CLI → Config, инициализация tracing_subscriber (в файл, НЕ в stderr), tokio Runtime → app::run(). При ошибке — stderr + exit(1).

4. Проверь --quiet режим: нет TUI, probers работают, JSONL пишется, Ctrl+C → session_end.

5. Проверь degraded режим: subprocess ICMP fallback + traceroute disabled — приложение работает.

6. Integration test: netprobe 127.0.0.1 --quiet --interval-icmp 100 --log /tmp/test.jsonl запуск на ~3 секунды → JSONL содержит session_start, icmp записи, session_end.

7. Финальная проверка: cargo clippy (без warnings), cargo fmt --check, cargo test, cargo build --release.

Критерий завершения:
- `cargo run -- 1.1.1.1` — полноценный TUI дашборд со всеми панелями и live-данными
- `cargo run -- 1.1.1.1 -q --log probe.jsonl` — headless мониторинг с JSONL
- Graceful shutdown (q или Ctrl+C) записывает session_end с итоговой статистикой
- cargo clippy, cargo test, cargo build --release — БЕЗ ОШИБОК
```
