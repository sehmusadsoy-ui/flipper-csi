/* CSI Radar Ultimate 2.0: ESP32-S2, 20 MHz LLTF, framed UART protocol 3. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <math.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "esp_heap_caps.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "nvs_flash.h"
#include "nvs.h"

/* Wipe buffers that held credentials or raw commands. A plain memset right
 * before a variable goes out of scope may be removed by the optimizer
 * (CWE-14, CodeQL cpp/memset-may-be-deleted); volatile stores are kept. */
static void secure_zero(void* p, size_t n) {
    volatile unsigned char* v = (volatile unsigned char*)p;
    while(n--) *v++ = 0;
}
#include "driver/uart.h"
#include "ping/ping_sock.h"
#include "csi_motion.h"
#include "csi_protocol.h"

#define FLIPPER_UART     UART_NUM_1
#define SAMPLE_PERIOD_MS 50U
static const char* TAG = "csi_radar";
typedef struct {
    int8_t iq[128];
    uint8_t mac[6], skip;
    int8_t rssi;
    uint32_t ms;
} Sample;
typedef struct {
    char ssid[33];
    char password[65];
} Credentials;
static QueueHandle_t samples, commands;
static SemaphoreHandle_t tx_lock;
static portMUX_TYPE net_lock = portMUX_INITIALIZER_UNLOCKED;
static struct {
    bool connected, configured;
    uint8_t bssid[6];
    uint32_t generation, dropped;
    uint8_t reason;
    bool scan_done;
} net;
static esp_ping_handle_t ping_handle;
static uint32_t last_enqueued;
static bool enqueued_once;
static csi_motion_t motion; /* owned exclusively by engine_task */
static Credentials credentials;
static bool raw_enabled, scan_active;
static uint32_t scan_start;
static bool waterfall_enabled;
static uint32_t now_ms(void) {
    return (uint32_t)(esp_timer_get_time() / 1000);
}

static void send_payload(const char* payload) {
    char frame[CSI_LINE_CAP];
    if(!csi_frame(frame, sizeof(frame), payload)) return;
    xSemaphoreTake(tx_lock, portMAX_DELAY);
    uart_write_bytes(FLIPPER_UART, frame, strlen(frame));
    fputs(frame, stdout);
    xSemaphoreGive(tx_lock);
}
/* Wi-Fi driver task: copy only. Never wait or perform DSP here. */
static void csi_cb(void* ctx, wifi_csi_info_t* info) {
    (void)ctx;
    if(!info || !info->buf || info->len != 128 || info->rx_ctrl.cwb != 0 ||
       info->rx_ctrl.secondary_channel != 0 || info->rx_ctrl.sig_mode > 1)
        return;
    bool accept;
    portENTER_CRITICAL(&net_lock);
    accept = net.connected;
#if CONFIG_CSIRADAR_FILTER_BSSID
    accept = accept && memcmp(net.bssid, info->mac, 6) == 0;
#endif
    portEXIT_CRITICAL(&net_lock);
    if(!accept) return;
    uint32_t ms = now_ms();
    if(enqueued_once && ms - last_enqueued < SAMPLE_PERIOD_MS) return;
    Sample s = {.skip = info->first_word_invalid ? 4 : 0, .rssi = info->rx_ctrl.rssi, .ms = ms};
    memcpy(s.iq, info->buf, 128);
    memcpy(s.mac, info->mac, 6);
    if(xQueueSend(samples, &s, 0) == pdTRUE) {
        last_enqueued = ms;
        enqueued_once = true;
    } else {
        portENTER_CRITICAL(&net_lock);
        net.dropped++;
        portEXIT_CRITICAL(&net_lock);
    }
}
static void ping_stop(void) {
    if(ping_handle) {
        esp_ping_stop(ping_handle);
        esp_ping_delete_session(ping_handle);
        ping_handle = NULL;
    }
}
static void ping_start(uint32_t gateway) {
    ping_stop();
    esp_ping_config_t cfg = ESP_PING_DEFAULT_CONFIG();
    ip_addr_set_zero(&cfg.target_addr);
    cfg.target_addr.type = IPADDR_TYPE_V4;
    cfg.target_addr.u_addr.ip4.addr = gateway;
    cfg.count = ESP_PING_COUNT_INFINITE;
    cfg.interval_ms = CONFIG_CSIRADAR_PING_INTERVAL_MS;
    cfg.timeout_ms = 500;
    cfg.data_size = 32;
    cfg.task_stack_size = 3072;
    esp_ping_callbacks_t callbacks = {0};
    esp_err_t err = esp_ping_new_session(&cfg, &callbacks, &ping_handle);
    if(err == ESP_OK) err = esp_ping_start(ping_handle);
    if(err != ESP_OK) {
        ESP_LOGW(TAG, "ping unavailable: %s", esp_err_to_name(err));
        ping_stop();
    }
}
static void wifi_event(void* arg, esp_event_base_t base, int32_t id, void* data) {
    (void)arg;
    if(base == WIFI_EVENT && (id == WIFI_EVENT_STA_DISCONNECTED || id == WIFI_EVENT_STA_STOP)) {
        portENTER_CRITICAL(&net_lock);
        net.connected = false;
        net.generation++;
        if(id == WIFI_EVENT_STA_DISCONNECTED)
            net.reason = ((wifi_event_sta_disconnected_t*)data)->reason;
        portEXIT_CRITICAL(&net_lock);
        ping_stop();
    } else if(base == WIFI_EVENT && id == WIFI_EVENT_SCAN_DONE) {
        portENTER_CRITICAL(&net_lock);
        net.scan_done = true;
        portEXIT_CRITICAL(&net_lock);
    } else if(base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        wifi_ap_record_t ap;
        if(esp_wifi_sta_get_ap_info(&ap) != ESP_OK) return;
        portENTER_CRITICAL(&net_lock);
        memcpy(net.bssid, ap.bssid, 6);
        net.connected = true;
        net.reason = 0;
        net.generation++;
        portEXIT_CRITICAL(&net_lock);
        ip_event_got_ip_t* event = data;
        ping_start(event->ip_info.gw.addr);
    }
}
static esp_err_t configure_wifi(const Credentials* c) {
    wifi_config_t wc = {0};
    memcpy(wc.sta.ssid, c->ssid, strlen(c->ssid));
    memcpy(wc.sta.password, c->password, strlen(c->password));
    wc.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;
    wc.sta.pmf_cfg.capable = true;
    return esp_wifi_set_config(WIFI_IF_STA, &wc);
}
static esp_err_t save_credentials(const Credentials* c) {
    nvs_handle_t h;
    esp_err_t err = nvs_open("csi_radar", NVS_READWRITE, &h);
    if(err != ESP_OK) return err;
    err = nvs_set_blob(h, "wifi", c, sizeof(*c));
    if(err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);
    return err;
}
static void wifi_init(void) {
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    ESP_ERROR_CHECK(esp_netif_create_default_wifi_sta() ? ESP_OK : ESP_ERR_NO_MEM);
    wifi_init_config_t init = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&init));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, wifi_event, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, wifi_event, NULL));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    if(credentials.ssid[0]) ESP_ERROR_CHECK(configure_wifi(&credentials));
    ESP_ERROR_CHECK(esp_wifi_set_bandwidth(WIFI_IF_STA, WIFI_BW_HT20));
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));
    wifi_csi_config_t csi = {
        .lltf_en = true,
        .htltf_en = false,
        .stbc_htltf2_en = false,
        .ltf_merge_en = false,
        .channel_filter_en = false,
        .manu_scale = false,
        .shift = 0};
    ESP_ERROR_CHECK(esp_wifi_set_csi_config(&csi));
    ESP_ERROR_CHECK(esp_wifi_set_csi_rx_cb(csi_cb, NULL));
    ESP_ERROR_CHECK(esp_wifi_set_csi(true));
}
static void command(const char* text, bool connected) {
    uint32_t n;
    if(strcmp(text, "PING") == 0) {
        send_payload("ACK,PING,3");
        send_payload("HELLO,2.0.0,3,ESP32-S2");
    } else if(strcmp(text, "WF 0") == 0 || strcmp(text, "WF 1") == 0) {
        waterfall_enabled = text[3] == '1';
        send_payload("ACK,WF");
    } else if(strncmp(text, "FILT ", 5) == 0) {
        if(!csi_uint(text + 5, 0, 1, &n)) {
            send_payload("ERR,FILT");
            return;
        }
        if(motion.filter != n) {
            motion.filter = (uint8_t)n;
            csi_motion_reset(&motion);
        }
        send_payload("ACK,FILT");
    } else if(strcmp(text, "SCAN") == 0) {
        if(scan_active) {
            send_payload("ERR,SCAN_BUSY");
            return;
        }
        wifi_scan_config_t cfg = {.show_hidden = false};
        portENTER_CRITICAL(&net_lock);
        net.scan_done = false;
        portEXIT_CRITICAL(&net_lock);
        esp_err_t scan_err = esp_wifi_scan_start(&cfg, false);
        if(scan_err == ESP_ERR_WIFI_STATE) {
            esp_wifi_disconnect();
            scan_err = esp_wifi_scan_start(&cfg, false);
        }
        if(scan_err != ESP_OK) {
            send_payload("ERR,SCAN_BUSY");
            return;
        }
        scan_active = true;
        scan_start = now_ms();
        send_payload("ACK,SCAN");
    } else if(strncmp(text, "CFG ", 4) == 0) {
        char values[32];
        strlcpy(values, text + 4, sizeof(values));
        char* space = strchr(values, ' ');
        uint32_t t, mode;
        if(!space) {
            send_payload("ERR,CFG");
            return;
        }
        *space++ = 0;
        if(!csi_uint(values, CSI_THR_MIN, CSI_THR_MAX, &t) || !csi_uint(space, 0, 1, &mode)) {
            send_payload("ERR,CFG");
            return;
        }
        motion.threshold = (float)t / 1000;
        motion.automatic = mode != 0;
        if(motion.automatic && connected && motion.primed &&
           now_ms() - motion.last_ms < CSI_STALE_MS)
            csi_motion_calibrate(&motion, 100);
        send_payload("ACK,CFG");
    } else if(strcmp(text, "CAL") == 0 || strncmp(text, "CAL ", 4) == 0) {
        if(!connected || !motion.primed || now_ms() - motion.last_ms >= CSI_STALE_MS) {
            send_payload("ERR,NO_CSI");
            return;
        }
        n = 100;
        if(text[3] && !csi_uint(text + 4, 20, 2000, &n)) {
            send_payload("ERR,CAL");
            return;
        }
        csi_motion_calibrate(&motion, n);
        send_payload("ACK,CAL");
    } else if(strncmp(text, "THR ", 4) == 0) {
        if(!csi_uint(text + 4, CSI_THR_MIN, CSI_THR_MAX, &n)) {
            send_payload("ERR,THR");
            return;
        }
        motion.threshold = (float)n / 1000.0f;
        motion.automatic = false;
        send_payload("ACK,THR");
    } else if(strcmp(text, "SAVE") == 0) {
        nvs_handle_t h;
        esp_err_t err = nvs_open("csi_radar", NVS_READWRITE, &h);
        if(err == ESP_OK) {
            err = nvs_set_u32(h, "threshold", (uint32_t)(motion.threshold * 1000 + 0.5f));
            if(err == ESP_OK) err = nvs_set_u8(h, "automatic", motion.automatic ? 1 : 0);
            if(err == ESP_OK) err = nvs_commit(h);
            nvs_close(h);
        }
        send_payload(err == ESP_OK ? "ACK,SAVE" : "ERR,SAVE");
    } else if(strcmp(text, "RAW 0") == 0 || strcmp(text, "RAW 1") == 0) {
        raw_enabled = text[4] == '1';
        send_payload("ACK,RAW");
    } else if(strncmp(text, "WIFI ", 5) == 0) {
        char fields[200];
        if(strlen(text + 5) >= sizeof(fields)) {
            send_payload("ERR,WIFI");
            return;
        }
        strlcpy(fields, text + 5, sizeof(fields));
        char* space = strchr(fields, ' ');
        Credentials c = {0};
        if(!space) {
            send_payload("ERR,WIFI");
            return;
        }
        *space++ = 0;
        if(!csi_hex_decode(fields, c.ssid, sizeof(c.ssid)) ||
           !csi_hex_decode(space, c.password, sizeof(c.password)) || !c.ssid[0] ||
           strlen(c.password) < 8 || strlen(c.password) > 63) {
            send_payload("ERR,WIFI");
            return;
        }
        /* Persist one blob atomically. Credentials never appear in telemetry. */
        if(save_credentials(&c) != ESP_OK) {
            send_payload("ERR,SAVE");
            return;
        }
        portENTER_CRITICAL(&net_lock);
        net.connected = false;
        net.generation++;
        portEXIT_CRITICAL(&net_lock);
        if(scan_active) {
            esp_wifi_scan_stop();
            scan_active = false;
        }
        esp_err_t err = esp_wifi_stop();
        if(err == ESP_OK) err = configure_wifi(&c);
        if(err == ESP_OK) err = esp_wifi_start();
        if(err == ESP_OK) err = esp_wifi_set_ps(WIFI_PS_NONE);
        if(err == ESP_OK) err = esp_wifi_set_csi(true);
        if(err == ESP_OK) {
            credentials = c;
            portENTER_CRITICAL(&net_lock);
            net.configured = true;
            net.connected = false;
            net.generation++;
            portEXIT_CRITICAL(&net_lock);
            csi_motion_reset(&motion);
        }
        secure_zero(&c, sizeof(c));
        secure_zero(fields, sizeof(fields));
        send_payload(err == ESP_OK ? "ACK,WIFI" : "ERR,WIFI_APPLY");
    } else
        send_payload("ERR,CMD");
}
static void receive_byte(CsiLine* line, uint8_t byte) {
    if(!csi_line_feed(line, byte)) return;
    char* payload = csi_unframe(line->data);
    if(!payload) return;
    char cmd[CSI_LINE_CAP] = {0};
    strlcpy(cmd, payload, sizeof(cmd));
    if(xQueueSend(commands, cmd, 0) != pdTRUE) send_payload("ERR,BUSY");
    secure_zero(cmd, sizeof(cmd));
    secure_zero(line->data, sizeof(line->data));
}
static void uart_rx_task(void* arg) {
    (void)arg;
    CsiLine line = {0};
    uint8_t bytes[64];
    for(;;) {
        int n = uart_read_bytes(FLIPPER_UART, bytes, sizeof(bytes), pdMS_TO_TICKS(100));
        for(int i = 0; i < n; i++)
            receive_byte(&line, bytes[i]);
    }
}
static void usb_rx_task(void* arg) {
    (void)arg;
    CsiLine line = {0};
    for(;;) {
        int c = getchar();
        if(c != EOF)
            receive_byte(&line, (uint8_t)c);
        else {
            clearerr(stdin);
            vTaskDelay(pdMS_TO_TICKS(20));
        }
    }
}
static void raw_sample(const Sample* s) {
    static const char hex[] = "0123456789ABCDEF";
    char iq[257];
    for(unsigned i = 0; i < 128; i++) {
        iq[2 * i] = hex[(uint8_t)s->iq[i] >> 4];
        iq[2 * i + 1] = hex[(uint8_t)s->iq[i] & 15];
    }
    iq[256] = 0;
    xSemaphoreTake(tx_lock, portMAX_DELAY);
    printf("$RAW,%" PRIu32 ",%d,%u,%s\n", s->ms, s->rssi, s->skip, iq);
    xSemaphoreGive(tx_lock);
}
static void engine_task(void* arg) {
    (void)arg;
    uint32_t seq = 0, last_report = 0, last_rate = now_ms(), rate_pkts = 0, rate = 0;
    uint32_t generation = UINT32_MAX, last_connect = now_ms() - 5000, last_raw = 0, last_wave = 0;
    int rssi = 0;
    uint32_t last_status = 0, dsp_max_us = 0, sample_queue_high = 0;
    bool sample_seen = false;
    uint32_t last_sample_ms = 0;
    for(;;) {
        uint32_t now = now_ms(), gen, dropped;
        bool connected, configured;
        uint8_t bssid[6];
        portENTER_CRITICAL(&net_lock);
        gen = net.generation;
        connected = net.connected;
        configured = net.configured;
        dropped = net.dropped;
        memcpy(bssid, net.bssid, 6);
        portEXIT_CRITICAL(&net_lock);
        if(gen != generation) {
            csi_motion_reset(&motion);
            xQueueReset(samples);
            generation = gen;
            rate = 0;
            rate_pkts = motion.accepted;
            last_rate = now;
            sample_seen = false;
        }
        if(configured && !connected && !scan_active && now - last_connect >= 5000) {
            esp_err_t err = esp_wifi_connect();
            if(err != ESP_OK) ESP_LOGD(TAG, "connect: %s", esp_err_to_name(err));
            last_connect = now;
        }
        bool scan_done;
        portENTER_CRITICAL(&net_lock);
        scan_done = net.scan_done;
        net.scan_done = false;
        portEXIT_CRITICAL(&net_lock);
        if(scan_active && scan_done) {
            wifi_ap_record_t records[12];
            uint16_t count = 12;
            if(esp_wifi_scan_get_ap_records(&count, records) != ESP_OK) {
                send_payload("ERR,SCAN");
                count = 0;
            }
            unsigned shown = 0;
            for(unsigned i = 0; i < count; i++) {
                char ssid[33] = {0}, hex[65], p[160];
                memcpy(ssid, records[i].ssid, 32);
                if(!ssid[0]) continue;
                csi_hex_encode(ssid, hex, sizeof(hex));
                snprintf(
                    p,
                    sizeof(p),
                    "AP,%u,%d,%u,%u,%s",
                    shown++,
                    records[i].rssi,
                    records[i].primary,
                    records[i].authmode,
                    hex);
                send_payload(p);
            }
            char p[32];
            snprintf(p, sizeof(p), "APEND,%u", shown);
            send_payload(p);
            scan_active = false;
        }
        if(scan_active && now - scan_start > 10000) {
            esp_wifi_scan_stop();
            esp_wifi_clear_ap_list();
            scan_active = false;
            send_payload("ERR,SCAN_TIMEOUT");
        }
        char cmd[CSI_LINE_CAP];
        /* Bound command work so noise cannot starve sample processing. */
        if(xQueueReceive(commands, cmd, 0) == pdTRUE) {
            command(cmd, connected);
            secure_zero(cmd, sizeof(cmd));
            /* WIFI may have changed the connection; refresh before taking data. */
            uint32_t after_gen;
            portENTER_CRITICAL(&net_lock);
            after_gen = net.generation;
            portEXIT_CRITICAL(&net_lock);
            if(after_gen != gen) {
                vTaskDelay(pdMS_TO_TICKS(10));
                continue;
            }
        }
        Sample s;
        if(xQueueReceive(samples, &s, pdMS_TO_TICKS(10)) == pdTRUE && connected &&
#if CONFIG_CSIRADAR_FILTER_BSSID
           memcmp(s.mac, bssid, 6) == 0 &&
#endif
           now_ms() - s.ms < 250) {
            bool was_calibrating = motion.calibrating;
            int64_t dsp_start = esp_timer_get_time();
            bool accepted = csi_motion_feed(&motion, s.iq, 128, s.skip, s.ms);
            uint32_t dsp_us = (uint32_t)(esp_timer_get_time() - dsp_start);
            if(dsp_us > dsp_max_us) dsp_max_us = dsp_us;
            if(accepted) {
                if(motion.automatic && !motion.calibrated && !motion.calibrating &&
                   !motion.warmup_left && motion.cal_error <= 1)
                    csi_motion_calibrate(&motion, 100);
                if(waterfall_enabled && s.ms - last_wave >= 250) {
                    static const char hex[] = "0123456789ABCDEF";
                    char wave[98] = "WF,";
                    for(unsigned i = 0; i < 47; i++) {
                        wave[3 + i * 2] = hex[motion.spectrum[i] >> 4];
                        wave[4 + i * 2] = hex[motion.spectrum[i] & 15];
                    }
                    wave[97] = 0;
                    send_payload(wave);
                    last_wave = s.ms;
                }
                rssi = s.rssi;
                last_sample_ms = s.ms;
                sample_seen = true;
            }
            if(was_calibrating && !motion.calibrating)
                send_payload(motion.cal_error ? "EV,CAL,FAIL" : "EV,CAL,OK");
            if(raw_enabled && s.ms - last_raw >= 100) {
                raw_sample(&s);
                last_raw = s.ms;
            }
        }
        now = now_ms();
        if(now - last_rate >= 1000) {
            rate = (motion.accepted - rate_pkts) * 1000U / (now - last_rate);
            rate_pkts = motion.accepted;
            last_rate = now;
        }
        unsigned pending_samples = uxQueueMessagesWaiting(samples);
        if(pending_samples > sample_queue_high) sample_queue_high = pending_samples;
        if(now - last_status >= 1000) {
            uint8_t reason;
            portENTER_CRITICAL(&net_lock);
            reason = net.reason;
            portEXIT_CRITICAL(&net_lock);
            uint32_t age = sample_seen ? now - last_sample_ms : UINT32_MAX;
            unsigned quality =
                (age >= CSI_STALE_MS || rate < 5 || rssi < -90) ?
                    0 :
                    (unsigned)fminf(
                        (float)motion.quality,
                        (float)(rate > 20 ? 20 : rate) * 3 + (rssi >= -75 ? 40 : 20));
            char p[100];
            snprintf(
                p,
                sizeof(p),
                "STAT,%u,%u,%u,%u,%u,%u",
                motion.automatic ? 1 : 0,
                (unsigned)(motion.noise * 1000),
                quality,
                reason,
                motion.cal_error,
                motion.calibrated ? 1 : 0);
            send_payload(p);
            snprintf(
                p,
                sizeof(p),
                "PERF,%u,%lu,%lu,%u,%u,%u",
                (unsigned)heap_caps_get_free_size(MALLOC_CAP_8BIT),
                (unsigned long)dsp_max_us,
                (unsigned long)sample_queue_high,
                (unsigned)motion.filter,
                (unsigned)(motion.raw_score * 1000),
                (unsigned)(motion.mad * 1000));
            send_payload(p);
            last_status = now;
        }
        if(now - last_report >= 100) {
            uint32_t age = sample_seen ? now - last_sample_ms : UINT32_MAX;
            csi_state_t state = !configured         ? CSI_STATE_SETUP :
                                !connected          ? CSI_STATE_WIFI_DOWN :
                                age >= CSI_STALE_MS ? CSI_STATE_NO_CSI :
                                                      csi_motion_state(&motion);
            if(age >= CSI_STALE_MS && sample_seen) {
                csi_motion_reset(&motion);
                sample_seen = false;
            }
            int score = state <= CSI_STATE_CALIBRATING ? (int)(motion.score * 1000 + 0.5f) : 0;
            char payload[200];
            snprintf(
                payload,
                sizeof(payload),
                "CSI2,%" PRIu32 ",%d,%d,%d,%" PRIu32 ",%d,%" PRIu32 ",%" PRIu32 ",%" PRIu32
                ",%" PRIu32,
                seq++,
                score,
                rssi,
                state,
                motion.accepted,
                (int)(motion.threshold * 1000 + 0.5f),
                age,
                age >= CSI_STALE_MS ? 0 : rate,
                dropped + motion.rejected,
                csi_motion_progress(&motion));
            send_payload(payload);
            last_report = now;
        }
    }
}
void app_main(void) {
    esp_err_t err = nvs_flash_init();
    if(err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);
    csi_motion_init(&motion);
    strlcpy(credentials.ssid, CONFIG_CSIRADAR_WIFI_SSID, sizeof(credentials.ssid));
    strlcpy(credentials.password, CONFIG_CSIRADAR_WIFI_PASSWORD, sizeof(credentials.password));
    nvs_handle_t h;
    if(nvs_open("csi_radar", NVS_READONLY, &h) == ESP_OK) {
        Credentials saved = {0};
        size_t size = sizeof(saved);
        uint32_t threshold;
        uint8_t automatic;
        if(nvs_get_blob(h, "wifi", &saved, &size) == ESP_OK && size == sizeof(saved) &&
           memchr(saved.ssid, 0, sizeof(saved.ssid)) &&
           memchr(saved.password, 0, sizeof(saved.password)))
            credentials = saved;
        if(nvs_get_u32(h, "threshold", &threshold) == ESP_OK && threshold >= CSI_THR_MIN &&
           threshold <= CSI_THR_MAX)
            motion.threshold = (float)threshold / 1000;
        if(nvs_get_u8(h, "automatic", &automatic) == ESP_OK) motion.automatic = automatic == 1;
        secure_zero(&saved, sizeof(saved));
        nvs_close(h);
    }
    net.configured = credentials.ssid[0] != 0;
    samples = xQueueCreate(16, sizeof(Sample));
    commands = xQueueCreate(8, CSI_LINE_CAP);
    tx_lock = xSemaphoreCreateMutex();
    configASSERT(samples && commands && tx_lock);
    uart_config_t cfg = {
        .baud_rate = 115200,
        .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT};
    ESP_ERROR_CHECK(uart_driver_install(FLIPPER_UART, 1024, 0, 0, NULL, 0));
    ESP_ERROR_CHECK(uart_param_config(FLIPPER_UART, &cfg));
    ESP_ERROR_CHECK(uart_set_pin(
        FLIPPER_UART,
        CONFIG_CSIRADAR_UART_TX_PIN,
        CONFIG_CSIRADAR_UART_RX_PIN,
        UART_PIN_NO_CHANGE,
        UART_PIN_NO_CHANGE));
    setvbuf(stdin, NULL, _IONBF, 0);
    wifi_init();
    configASSERT(xTaskCreate(engine_task, "csi_engine", 6144, NULL, 4, NULL) == pdPASS);
    configASSERT(xTaskCreate(uart_rx_task, "csi_uart", 4096, NULL, 3, NULL) == pdPASS);
    configASSERT(xTaskCreate(usb_rx_task, "csi_usb", 4096, NULL, 2, NULL) == pdPASS);
    ESP_LOGI(
        TAG,
        "CSI Radar Ultimate 2.0; protocol 3; credentials configured: %s",
        net.configured ? "yes" : "no");
}
