#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_event.h"
#include "nvs_flash.h"
#include <string.h>
#include <ctype.h>

/* -------- banner -------- */
static void banner(void)
{
    printf("\n"
           "   ____    _    ___ _   _ ____  _____ ____\n"
           "  / ___|  / \\  |_ _| \\ | / ___|| ____/ ___|\n"
           " | |  _  / _ \\  | ||  \\| \\___ \\|  _|| |\n"
           " | |_| |/ ___ \\ | || |\\  |___) | |__| |___\n"
           "  \\____/_/   \\_\\___|_| \\_|____/|_____\\____|\n"
           "\n"
           "    IT'S BIRD HUNTING SEASON\n\n"
           "    Flock Safety Sniffer\n\n"
           "    https://gainsec.com\n\n"
           "Sending out the bird call and Sniffing...\n\n");
}

/* -------- utils -------- */
static char *strcasestr_local(const char *h, const char *n)
{
    if (!*n) return (char *)h;
    for (; *h; ++h) {
        const char *h1 = h, *n1 = n;
        while (*h1 && *n1 &&
               tolower((unsigned char)*h1) == tolower((unsigned char)*n1))
            ++h1, ++n1;
        if (!*n1) return (char *)h;
    }
    return NULL;
}

/* -------- 802.11 -------- */
typedef struct __attribute__((packed)) {
    uint16_t frame_ctrl;
    uint16_t duration_id;
    uint8_t  addr1[6];
    uint8_t  addr2[6];
    uint8_t  addr3[6];
    uint16_t seq_ctrl;
} wifi_ieee80211_mac_hdr_t;

/* -------- globals -------- */
static const char *TAG = "sniffer";
static volatile bool triggered = false;

/* -------- packet handler -------- */
static void wifi_sniffer_packet_handler(void *buf, wifi_promiscuous_pkt_type_t type)
{
    if (triggered) return;

    const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buf;
    const wifi_ieee80211_mac_hdr_t *hdr = (wifi_ieee80211_mac_hdr_t *)ppkt->payload;

    uint8_t fc0   = hdr->frame_ctrl & 0xFF;
    uint8_t stype = (fc0 >> 4) & 0x0F;
    uint8_t ftype = (fc0 >> 2) & 0x03;

    ESP_LOGI(TAG, "RX frame type=%d subtype=%d len=%d", ftype, stype, ppkt->rx_ctrl.sig_len);

    if (ftype == 0 && (stype == 8 || stype == 5)) {
        const uint8_t *ie = (const uint8_t *)ppkt->payload + sizeof(*hdr);
        int len = ppkt->rx_ctrl.sig_len - sizeof(*hdr);
        while (len >= 2) {
            uint8_t id = ie[0];
            uint8_t elen = ie[1];
            if (elen + 2 > len) break;
            if (id == 0 && elen) {
                char ssid[33];
                memset(ssid, 0, sizeof(ssid));
                int n = elen > 32 ? 32 : elen;
                memcpy(ssid, ie + 2, n);
                ssid[n] = '\0';
                ESP_LOGI(TAG, "AP SSID seen: %s", ssid);
                if (strcasestr_local(ssid, "flock")) {
                    ESP_LOGW(TAG, "ALERT: AP SSID \"%s\"", ssid);
                    triggered = true;
                    esp_wifi_set_promiscuous(false);
                    return;
                }
            }
            ie  += elen + 2;
            len -= elen + 2;
        }
    }

    if (ftype == 0 && stype == 4) {
        const uint8_t *ie = (const uint8_t *)ppkt->payload + sizeof(*hdr);
        int len = ppkt->rx_ctrl.sig_len - sizeof(*hdr);
        while (len >= 2) {
            uint8_t id = ie[0];
            uint8_t elen = ie[1];
            if (elen + 2 > len) break;
            if (id == 0 && elen) {
                char ssid[33];
                memset(ssid, 0, sizeof(ssid));
                int n = elen > 32 ? 32 : elen;
                memcpy(ssid, ie + 2, n);
                ssid[n] = '\0';
                ESP_LOGI(TAG, "Probe SSID seen: %s", ssid);
                if (strcasestr_local(ssid, "flock")) {
                    ESP_LOGW(TAG, "ALERT: client probe \"%s\"", ssid);
                    triggered = true;
                    esp_wifi_set_promiscuous(false);
                    return;
                }
            }
            ie  += elen + 2;
            len -= elen + 2;
        }
    }
}

/* -------- main -------- */
void app_main(void)
{
    banner();

    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL));
    ESP_ERROR_CHECK(esp_wifi_start());

    wifi_promiscuous_filter_t filt = { .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT };
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_filter(&filt));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(wifi_sniffer_packet_handler));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));

    static const uint8_t channels[] = {
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
        36, 40, 44, 48,
        149, 153, 157, 161, 165
    };
    const int num_channels = sizeof(channels) / sizeof(channels[0]);
    int ch_idx = 0;

    while (!triggered) {
        uint8_t ch = channels[ch_idx];
        ESP_LOGI(TAG, "Switching to channel %d", ch);
        esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
        ch_idx = (ch_idx + 1) % num_channels;
        vTaskDelay(pdMS_TO_TICKS(2500));
    }

    ESP_LOGW(TAG, "sniffer stopped");
    ESP_LOGW(TAG, "Happy Hunting");
    ESP_LOGW(TAG, "AutoPwn coming 09/27/25 :)");
    ESP_LOGW(TAG, "https://gainsec.com/");

}