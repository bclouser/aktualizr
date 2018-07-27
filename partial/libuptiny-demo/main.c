#include "periph/gpio.h"
#include "can/conn/isotp.h"
#include "xtimer.h"

#include "libuptiny/root.h"
#include "libuptiny/targets.h"

#define LIBUPTINY_ISOTP_SECONDARY_CANID 0x7E8
#define LIBUPTINY_ISOTP_PRIMARY_CANID 0x7D8

#define ISOTP_BUF_SIZE 1024
char isotp_buf[ISOTP_BUF_SIZE];
/* ISO/TP message format: 
 * <1-byte message type> <payload>
 * Message types:
 *   - 0x01 - getSerial
 *   - 0x41 - resp to getSerial
 *   - 0x02 - getHwId
 *   - 0x42 - resp to getHwId
 *   - 0x03 - getPublicKey
 *   - 0x43 - resp to getPublicKey
 *   - 0x04 - getRootVersion
 *   - 0x44 - resp to getRootVersion
 *   - 0x05 - getManifest
 *   - 0x45 - resp to getManifest
 *   - 0x06 - putRoot
 *   - 0x07 - putTargets
 *   - 0x08 - putImageChunk
 *   - 0x48 - acknowledge/error on putImageChunk
 *
 * Format of putImageChunk message:
 * <0x08> <1 byte total number of chunks> <1 byte sequence number> <payload>
 */

typedef enum {
  UPTANE_GET_SERIAL = 0x01,
  UPTANE_GET_SERIAL_RESP = 0x41,
  UPTANE_GET_HWID = 0x02,
  UPTANE_GET_HWID_RESP = 0x42,
  UPTANE_GET_PKEY = 0x03,
  UPTANE_GET_PKEY_RESP = 0x43,
  UPTANE_GET_ROOT_VER = 0x04,
  UPTANE_GET_ROOT_VER_RESP = 0x44,
  UPTANE_GET_MANIFEST = 0x05,
  UPTANE_GET_MANIFEST_RESP = 0x45,
  UPTANE_PUT_ROOT = 0x06,
  UPTANE_PUT_TARGETS = 0x07,
  UPTANE_PUT_IMAGE_CHUNK = 0x08,
  UPTANE_PUT_IMAGE_CHUNK_ACK_ERR = 0x48,
} uptane_isotp_message_type_t;

int uptane_recv(void) {
    int ret;
    uptane_root_t in_root;
    uptane_targets_t in_targets;

    struct isotp_options isotp_opt;
    memset(&isotp_opt, 0, sizeof(isotp_opt));

    isotp_opt.rx_id = LIBUPTINY_ISOTP_SECONDARY_CANID;
    isotp_opt.tx_id = LIBUPTINY_ISOTP_PRIMARY_CANID;

    conn_can_isotp_t conn_isotp;
    memset(&conn_isotp, 0, sizeof(conn_isotp));
    ret = conn_can_isotp_create(&conn_isotp, &isotp_opt, 0);

    if (ret < 0) {
        return ret;
    }

    ret = conn_can_isotp_bind(&conn_isotp);
    if (ret < 0) {
        return ret;
    }
    for(;;) {
      if ((ret = conn_can_isotp_recv(&conn_isotp, &isotp_buf, ISOTP_BUF_SIZE, 1000)) >= 0) {
        switch(isotp_buf[0]) {
		case  UPTANE_GET_SERIAL: {
			isotp_buf[0] = UPTANE_GET_SERIAL_RESP;
			const char* ecu_serial = state_get_ecuid();
			strncpy(isotp_buf+1, ecu_serial, ISOTP_BUF_SIZE-1);
			conn_can_isotp_send(&conn_isotp, &isotp_buf, 1 + strlen(ecu_serial), 0);
			break;
		}
		case  UPTANE_GET_HWID: {
			isotp_buf[0] = UPTANE_GET_HWID_RESP;
			const char* ecu_hwid = state_get_hwid();
			strncpy(isotp_buf+1, ecu_hwid, ISOTP_BUF_SIZE-1);
			conn_can_isotp_send(&conn_isotp, &isotp_buf, 1 + strlen(ecu_hwid), 0);
			break;
		}
		case  UPTANE_GET_PKEY:
			break;
		case  UPTANE_GET_ROOT_VER:
			break;
		case  UPTANE_GET_MANIFEST:
			break;
		case  UPTANE_PUT_ROOT:
			if (uptane_parse_root(isotp_buf+1, ret-1, &in_root)) {
				state_set_root(&in_root);
			} else {
				/*TODO: set error*/
			}
			break;
		case  UPTANE_PUT_TARGETS: {
			uint16_t targets_result = 0x0000;
			uptane_parse_targets_init();
			uptane_parse_targets_feed(isotp_buf+1, ret-1, &in_targets, &targets_result);
			if(targets_result == RESULT_END_FOUND) {
				state_set_targets(&in_targets);
			} else {
				/*TODO: set error*/
			}
			break;
		}
		case  UPTANE_PUT_IMAGE_CHUNK:
			isotp_buf[0] = UPTANE_PUT_IMAGE_CHUNK_ACK_ERR;
			isotp_buf[1] = 0x00;
			conn_can_isotp_send(&conn_isotp, &isotp_buf, 2, 0);
			break;
		default:
			break;
	}
      }
    }
}

int main(void)
{
    /*static conn_can_raw_t raw_conn;
    static struct can_filter filter = {
        .can_id = 0x7E8,
	.can_mask = 0x000007f8,
    };*/

    xtimer_sleep(1); // TODO: better way to wait till CAN gets initialized?

    uptane_recv();
    /*conn_can_raw_create(&raw_conn, &filter, 1, 0, 0);

    for(;;) {
      gpio_clear(LED0_PIN);
      gpio_set(LED1_PIN);
      gpio_clear(LED2_PIN);
      gpio_set(LED3_PIN);

      struct can_frame frame;
      //memset(frame.data, 0x55, 8);
      //frame.data[0] = 0x02;
      //frame.data[1] = 0x1;
      //frame.data[2] = 0x0;
      //frame.can_dlc = 8;
      //frame.can_id = 0x7DF;

      while(conn_can_raw_recv(&raw_conn, &frame, 1000) <= 0);
      //conn_can_raw_send(&raw_conn, &frame, 0);
      //xtimer_sleep(1);

      gpio_set(LED0_PIN);
      gpio_clear(LED1_PIN);
      gpio_set(LED2_PIN);
      gpio_clear(LED3_PIN);
      while(conn_can_raw_recv(&raw_conn, &frame, 1000) <= 0);

      //xtimer_sleep(1);
    }*/
    return 0;
}
