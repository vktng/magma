/*
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under
 * the terms found in the LICENSE file in the root of this source tree.
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *-------------------------------------------------------------------------------
 * For more information about the OpenAirInterface (OAI) Software Alliance:
 *      contact@openairinterface.org
 */

#pragma once

#include <stdint.h>

#include "lte/protos/oai/s1ap_state.pb.h"

#include "lte/gateway/c/core/oai/include/proto_map.hpp"
#include "lte/gateway/c/core/oai/lib/3gpp/3gpp_36.401.h"
#include "lte/gateway/c/core/oai/lib/3gpp/3gpp_36.413.h"

#ifdef __cplusplus
extern "C" {
#endif
#include "lte/gateway/c/core/oai/common/common_types.h"
#ifdef __cplusplus
}
#endif

// Forward declarations
struct enb_description_s;

#define S1AP_TIMER_INACTIVE_ID (-1)
#define S1AP_UE_CONTEXT_REL_COMP_TIMER 1  // in seconds

// Map- Key: uint32_t , Data: enb_description_t*
typedef magma::proto_map_s<uint32_t, struct enb_description_s*>
    map_uint32_enb_description_t;
typedef struct s1ap_state_s {
  // key:sctp_assoc_id, value: pointer to eNB_description_s
  map_uint32_enb_description_t enbs;
  // contains sctp association id, key is mme_ue_s1ap_id
  magma::proto_map_uint32_uint32_t mmeid2associd;

  uint32_t num_enbs;
} s1ap_state_t;

typedef struct s1ap_imsi_map_s {
  magma::proto_map_uint32_uint64_t mme_ueid2imsi_map;
} s1ap_imsi_map_t;

// The current s1 state of the MME relating to the specific eNB.
enum mme_s1_enb_state_s {
  S1AP_INIT,  /// The sctp association has been established but s1 hasn't been
              /// setup.
  S1AP_RESETING,  /// The s1state is resetting due to an SCTP reset on the bound
                  /// association.
  S1AP_READY,     ///< MME and eNB are S1 associated, UE contexts can be added
  S1AP_SHUTDOWN   /// The S1 state is being torn down due to sctp shutdown.
};

// Map- Key:comp_s1ap_id of uint64_t, Data: pointer to protobuf object,
// UeDescription
typedef magma::proto_map_s<uint64_t, magma::lte::oai::UeDescription*>
    map_uint64_ue_description_t;

/* Maximum no. of Broadcast PLMNs. Value is 6
 * 3gpp spec 36.413 section-9.1.8.4
 */
#define S1AP_MAX_BROADCAST_PLMNS 6
/* Maximum TAI Items configured, can be upto 256 */
#define S1AP_MAX_TAI_ITEMS 16

/* Supported TAI items includes TAC and Broadcast PLMNs */
typedef struct supported_tai_items_s {
  uint16_t tac;             ///< Supported TAC value
  uint8_t bplmnlist_count;  ///< Number of Broadcast PLMNs in the TAI
  plmn_t bplmns[S1AP_MAX_BROADCAST_PLMNS];  ///< List of Broadcast PLMNS
} supported_tai_items_t;

/* Supported TAs by eNB received in S1 Setup request message */
typedef struct supported_ta_list_s {
  uint8_t list_count;  ///< Number of TAIs in the list
  supported_tai_items_t
      supported_tai_items[S1AP_MAX_TAI_ITEMS];  ///< List of TAIs
} supported_ta_list_t;

/* Main structure representing eNB association over s1ap
 * Generated (or updated) every time a new S1SetupRequest is received.
 */
typedef struct enb_description_s {
  enum mme_s1_enb_state_s
      s1_state;  ///< State of the eNB specific S1AP association

  /** eNB related parameters **/
  /*@{*/
  char enb_name[150];          ///< Printable eNB Name
  uint32_t enb_id;             ///< Unique eNB ID
  uint8_t default_paging_drx;  ///< Default paging DRX interval for eNB
  supported_ta_list_t supported_ta_list;  ///< Supported TAs by eNB
  /*@}*/

  /** UE list for this eNB **/
  /*@{*/
  uint32_t nb_ue_associated;  ///< Number of NAS associated UE on this eNB
  magma::proto_map_uint32_uint64_t
      ue_id_coll;  ///< key: mme_ue_s1ap_id, value: comp_s1ap_id
  /*@}*/
  /** SCTP stuff **/
  /*@{*/
  sctp_assoc_id_t sctp_assoc_id;      ///< SCTP association id on this machine
  sctp_stream_id_t next_sctp_stream;  ///< Next SCTP stream
  sctp_stream_id_t instreams;   ///< Number of streams avalaible on eNB -> MME
  sctp_stream_id_t outstreams;  ///< Number of streams avalaible on MME -> eNB
  char ran_cp_ipaddr[16];    ///< Network byte order IP address of eNB SCTP end
                             ///< point
  uint8_t ran_cp_ipaddr_sz;  ///< IP addr size for ran_cp_ipaddr
  /*@}*/
} enb_description_t;
