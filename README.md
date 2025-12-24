# Image processing-server (unsharp)

Client 會讀取本地的 `lena.pgm` (8-bit P5)，透過自訂二進位協定送至 server，server 透過 IPC 與獨立的 unsharp process 在 shared memory 中做影像銳化處理，再把結果回傳給 client 儲存為 PGM 檔，同時在 client 端計算延遲與吞吐量統計。

## 專案架構

- **log.c / log.h**  
  - 提供簡單 thread-safe logger，支援四種 log level（DEBUG/INFO/WARN/ERROR）。  
  - 初始化：`log_init(const char *filepath, log_level_t level)`，`filepath == NULL` 則輸出到 stderr。

- **net.c / net.h**  
  - 封裝 TCP 監聽與連線：`net_listen(ip, port, backlog)`、`net_accept(listen_fd)`、`net_connect(ip, port)`、`net_close(fd)`。
  - `net_read_n` / `net_write_n` 是 legacy blocking I/O helper，現在實際應用層資料都走 TLS 封裝的 `tls_read_n` / `tls_write_n`。

- **tls.c / tls.h**  
  - 使用 OpenSSL 封裝 TLS：  
    - 全域初始化：`tls_global_init()` / `tls_global_cleanup()`。
    - Server 端：`tls_server_init(tls_server_t *s, "server.crt", "server.key")` 建立 `SSL_CTX`，`tls_server_wrap_fd(&s, fd)` 對已 accept 的 socket 做 `SSL_accept`。
    - Client 端：`tls_client_init(tls_client_t *c, "server.crt")` 使用自簽 cert 當 CA，`tls_client_wrap_fd(&c, fd, servername)` 做 `SSL_connect` 並驗證 hostname。
  - I/O：`tls_read_n(t, buf, n)` / `tls_write_n(t, buf, n)` 會在 TLS 之上保證讀寫剛好 n bytes（loop SSL_read / SSL_write + 處理 WANT_READ/WANT_WRITE）。

- **proto.c / proto.h**  
  - 定義自訂協定（big-endian）：

    | 欄位     | 長度 (bytes) | 說明                            |
    |----------|--------------|---------------------------------|
    | LEN      | 4            | 總長度（含 header+body）的位元組數。 |
    | OPCODE   | 2            | 操作碼（請求/回應類型）。|
    | FLAGS    | 1            | 保留未來使用。                  |
    | RESERVED | 1            | 保留未來使用。                  |
    | BODY     | 可變         | Payload。                       |

  - 主要 opcode：
    - `OPCODE_IMG_REQUEST` (0x0001)：送入影像請求。  
    - `OPCODE_IMG_RESPONSE` (0x8001)：回傳處理後影像。  
    - `OPCODE_HEARTBEAT` (0x0002)：健康檢查。  
    - `OPCODE_STATS_QUERY` / `OPCODE_STATS_REPLY`：保留。  
    - `OPCODE_ERROR` (0xFFFF)：錯誤訊息。  
  - API：`proto_encode` 負責組合 header+body 成連續 buffer；`proto_decode` 從接收到的 buffer 解析出 `proto_msg_t`，並為 body 配置可釋放的 heap；`proto_free` 釋放 body。

- **ipc.c / ipc.h**  
  - 使用 System V shared memory + semaphore (shm key `0x12340001`, sem key `0x12340002`) 建立共享狀態 `ipc_server_stats_t`：內含全域統計 + `MAX_JOBS` 個 job slot。
  - `job_t` 內容包含：`state` (JOB_EMPTY/JOB_READY/JOB_BUSY/JOB_DONE)、`owner_pid`、`width`、`height`、`pixels`、`input[]`、`output[]`。
  - 提供 `ipc_create` / `ipc_attach` / `ipc_destroy` / `ipc_lock` / `ipc_unlock` 等 helper。

- **server（主程式邏輯）**  
  - 建立 shared memory：`ipc_create(&g_ipc, SHM_KEY, SEM_KEY)`，並初始化所有 `jobs[i].state = JOB_EMPTY`。
  - TLS 初始化：`tls_global_init()`、`tls_server_init(&g_tls_server, "server.crt", "server.key")`。
  - `net_listen(ip=NULL, port, backlog=128)` 建立 TCP 監聽 socket。
  - 安裝 SIGINT handler：設定 `STATS->shutdown_flag = 1` 讓所有 process 優雅結束。
  - fork：  
    - 1 個 unsharp process：只在 shared memory 迴圈取 `JOB_READY` → `JOB_BUSY` → 做 unsharp → `JOB_DONE`。
    - N 個 worker process：負責 accept + TLS handshake + 協定處理。
  - master process 負責監控 child death，若 worker 或 unsharp 異常結束則在未 shutdown 狀態下 fork 新的來補上，且會把死掉 unsharp 名下 `JOB_BUSY` job 重設回 `JOB_READY` 以避免 job 遺失。

- **unsharp process / worker**  
  - `unsharp_loop()`：  
    - 迴圈：在 shared memory 找 `JOB_READY`，設為 `JOB_BUSY` 並記錄 `owner_pid = getpid()`，離開 critical section 後對 `job->input` 做 3x3 box blur 及 unsharp mask（`output = orig + k*(orig - blur)` with `k=8`），最後再進 critical section 把 job 設成 `JOB_DONE`。
  - `submit_unsharp_job()` / `wait_unsharp_and_build_reply()`：  
    - worker 收到 `OPCODE_IMG_REQUEST` 後，解析 body 的 `[w][h][pixels...]`，檢查張數不超過 `MAX_IMG_PIXELS`，從 shared memory 找 `JOB_EMPTY` slot 寫入資料設為 `JOB_READY`，等待該 job 變 `JOB_DONE` 後組成回應 body = 原始 8 bytes header + unsharp output。
  - `handle_connection(tls_ctx_t *t)`：  
    - 連續使用 `tls_read_n` 讀取 4 bytes LEN + 剩餘封包，`proto_decode` 成 `proto_msg_t`，更新共享統計的 `total_requests` / `total_bytes_in`。
    - 根據 opcode：  
      - `IMG_REQUEST` → 呼叫 `process_image_request`（走 unsharp pipeline）。  
      - `HEARTBEAT` → 回 `OPCODE_HEARTBEAT`。  
      - 其他 → 回 `OPCODE_ERROR` 及錯誤字串。  
    - 使用 `proto_encode` 編碼回覆並透過 `tls_write_n` 寫回 client，更新 `total_bytes_out`。
  - `worker_loop(listen_fd)`：  
    - 迴圈檢查 `shutdown_flag`，若未關閉則 `net_accept` 新連線 → `tls_server_wrap_fd` → `handle_connection`。

- **client**  
  - `tls_global_init()` + `tls_client_init(&g_tls_client, "server.crt")`，將 server 自簽 cert 當 trusted CA。
  - 讀取 `lena.pgm`：僅支援 P5、8-bit grayscale，解析 header (`P5`、width、height、maxval) 與 raw 像素。
  - 組 request body：  
    - body layout = `[w(4)][h(4)][pixels...]`，w/h 以 network order (`htonl`) 存放。
  - 建立多個 thread，每個 thread：  
    - 使用 `net_connect(ip, port)` 建立 TCP 連線，`tls_client_wrap_fd(&g_tls_client, fd, ip)` 升級為 TLS。
    - 迴圈 `requests_per_thread` 次：  
      - 建立 `proto_msg_t`，`opcode = OPCODE_IMG_REQUEST`，body 指向共用的 `img_body`。  
      - `proto_encode` → `tls_write_n` 發送。  
      - 先讀 LEN (4 bytes) 再讀剩餘封包 → `proto_decode`。  
      - 量測 request→reply 的延遲，若 opcode 是 `OPCODE_IMG_RESPONSE` 則更新統計（總數/成功數/latency sum/max），並在該 thread 第一個成功回覆時解析回覆中的 `[w][h][pixels...]` 另存為 `img/YYYYMMDD_threadX_lena.pgm`。
    - 完成後 `tls_close(t)` 關閉 TLS 與底層 fd。
  - main 結束時統計：`total_requests`、`success_requests`、平均延遲、最大延遲、透過量（成功數 / 總時間秒）。

## 建置方式

以下假設使用 gcc 與 OpenSSL 開發套件（含 header 與 lib）。

### 使用 Makefile

```makefile
CC = gcc
CFLAGS = -Wall -O2 -pthread
LDFLAGS = -lssl -lcrypto

SRV_OBJS = server.o ipc.o net.o proto.o log.o tls.o
CLI_OBJS = client.o net.o proto.o log.o tls.o

all: server client

server: $(SRV_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

client: $(CLI_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f server client *.o
```

## 執行步驟

### 1. 準備 TLS 憑證

```bash
openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt \
    -days 365 -nodes -subj "/CN=127.0.0.1"
```

- `server.crt`：server 端使用的證書，同時 client 端當 CA 信任。
- `server.key`：server 端私鑰檔，server 進程啟動時會載入。

### 2. 準備 lena.pgm

在 client 端所在目錄放一個 8-bit P5 PGM 格式的 `lena.pgm`，解析時只接受 `maxval <= 255`。

### 3. 啟動 server

```bash
# 預設 port = 9000, workers = 3
./server              # 或 ./server <port> <workers>
./server 9000 4
```

- server 啟動時會建立 shared memory、初始化統計與 job queue，fork 出 unsharp process + 多個 worker process。
- 支援 `Ctrl+C`（SIGINT）優雅關閉，會設 `shutdown_flag`，等待所有 child 結束後釋放 TLS / IPC 資源。

### 4. 啟動 client

```bash
# 預設 ip=127.0.0.1, port=9000, threads=1, req_per_thread=1
./client

# 多執行緒、多請求測試
./client 127.0.0.1 9000 8 50   # 8 threads, 每個 thread 送 50 次
```

- client 啟動會建立 `img/` 目錄（若不存在），負責把各 thread 第一個成功回覆存成 `img/YYYYMMDD_threadX_lena.pgm`。
- 結束時印出總請求數、成功數、平均延遲、最大延遲與吞吐量（req/s）。

## 協定與影像格式細節

### Request：`OPCODE_IMG_REQUEST`

- OPCODE：`0x0001`。
- BODY 格式：  

  | Offset | 長度 | 說明                            |
  |--------|------|---------------------------------|
  | 0      | 4    | width (network order, uint32)。 |
  | 4      | 4    | height (network order, uint32)。 |
  | 8      | N    | raw pixels，長度 = w * h bytes。 |

- 限制：`w * h <= 512 * 512`（由 `MAX_IMG_PIXELS` 定義）。

### Response：`OPCODE_IMG_RESPONSE`

- OPCODE：`0x8001`。
- BODY 格式與 request 相同（w/h header + unsharp 後的 pixels）。
- 若有錯誤（尺寸不符、job submit 失敗等），server 回 `OPCODE_ERROR` 並在 body 放錯誤字串（ASCII）。

### Unsharp 演算法

- 先對輸入影像套用 3x3 box blur（邊界採用 valid 邊界檢查，實際計算時只平均落在影像內的像素）。
- 之後使用：`output = orig + k * (orig - blur)`，其中 `k = 8.0`，最後 clamp 到 。

| 成員 | 負責模組 / 功能 | 主要檔案 | 備註 |
|------|-----------------|----------|------|
| 成員 A |                 |          |      |
| 成員 B |                 |          |      |
| 成員 C |                 |          |      |
