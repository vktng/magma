/*
 *
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
 *------------------------------------------------------------------------------
 * For more information about the OpenAirInterface (OAI) Software Alliance:
 *      contact@openairinterface.org
 */
#include "lte/gateway/c/core/oai/tasks/s1ap/s1ap_state_converter.hpp"

namespace magma {
namespace lte {

S1apStateConverter::~S1apStateConverter() = default;
S1apStateConverter::S1apStateConverter() = default;

void S1apStateConverter::state_to_proto(s1ap_state_t* state,
                                        oai::S1apState* proto) {
  proto->Clear();

  // copy over enbs
  state_map_to_proto<map_uint32_enb_description_t, enb_description_t,
                     oai::EnbDescription>(state->enbs, proto->mutable_enbs(),
                                          enb_to_proto, LOG_S1AP);

  // copy over mmeid2associd
  mme_ue_s1ap_id_t mmeid;
  sctp_assoc_id_t sctp_assoc_id = 0;
  auto mmeid2associd = proto->mutable_mmeid2associd();

  if (state->mmeid2associd.isEmpty()) {
    OAILOG_DEBUG(LOG_S1AP, "No entries in mmeid2associd map");
  } else {
    *(proto->mutable_mmeid2associd()) = *(state->mmeid2associd.map);
  }

  uint32_t expected_enb_count = state->enbs.size();
  if (expected_enb_count != state->num_enbs) {
    OAILOG_ERROR(LOG_S1AP,
                 "Updating num_eNBs from maintained to actual count %u->%u",
                 state->num_enbs, expected_enb_count);
    state->num_enbs = expected_enb_count;
  }
  proto->set_num_enbs(state->num_enbs);
}

void S1apStateConverter::proto_to_state(const oai::S1apState& proto,
                                        s1ap_state_t* state) {
  proto_to_state_map<map_uint32_enb_description_t, oai::EnbDescription,
                     enb_description_t>(proto.enbs(), state->enbs, proto_to_enb,
                                        LOG_S1AP);

  *(state->mmeid2associd.map) = proto.mmeid2associd();
  state->num_enbs = proto.num_enbs();
  uint32_t expected_enb_count = state->enbs.size();
  OAILOG_WARNING(LOG_S1AP, "expected_enb_count:%d state->num_enbs :%d \n",
                 expected_enb_count, state->num_enbs);
  if (expected_enb_count != state->num_enbs) {
    OAILOG_WARNING(LOG_S1AP,
                   "Updating num_eNBs from maintained to actual count %u->%u",
                   state->num_enbs, expected_enb_count);
    state->num_enbs = expected_enb_count;
  }
}

void S1apStateConverter::enb_to_proto(enb_description_t* enb,
                                      oai::EnbDescription* proto) {
  proto->Clear();

  proto->set_enb_id(enb->enb_id);
  proto->set_s1_state(enb->s1_state);
  proto->set_enb_name(enb->enb_name);
  proto->set_default_paging_drx(enb->default_paging_drx);
  proto->set_nb_ue_associated(enb->nb_ue_associated);
  proto->set_sctp_assoc_id(enb->sctp_assoc_id);
  proto->set_next_sctp_stream(enb->next_sctp_stream);
  proto->set_instreams(enb->instreams);
  proto->set_outstreams(enb->outstreams);
  proto->set_ran_cp_ipaddr(enb->ran_cp_ipaddr);
  proto->set_ran_cp_ipaddr_sz(enb->ran_cp_ipaddr_sz);

  // store ue_ids
  *(proto->mutable_ue_id_map()) = *(enb->ue_id_coll.map);
  supported_ta_list_to_proto(&enb->supported_ta_list,
                             proto->mutable_supported_ta_list());
}

void S1apStateConverter::proto_to_enb(const oai::EnbDescription& proto,
                                      enb_description_t* enb) {
  memset(enb, 0, sizeof(*enb));

  enb->enb_id = proto.enb_id();
  enb->s1_state = (mme_s1_enb_state_s)proto.s1_state();
  strncpy(enb->enb_name, proto.enb_name().c_str(), sizeof(enb->enb_name));
  enb->default_paging_drx = proto.default_paging_drx();
  enb->nb_ue_associated = proto.nb_ue_associated();
  enb->sctp_assoc_id = proto.sctp_assoc_id();
  enb->next_sctp_stream = proto.next_sctp_stream();
  enb->instreams = proto.instreams();
  enb->outstreams = proto.outstreams();
  strncpy(enb->ran_cp_ipaddr, proto.ran_cp_ipaddr().c_str(),
          sizeof(enb->ran_cp_ipaddr));
  enb->ran_cp_ipaddr_sz = proto.ran_cp_ipaddr_sz();

  // load ues
  char S1AP_UE_MAP_NAME[] = "s1ap_ue_coll";
  proto_map_rc_t rc = {PROTO_MAP_OK};
  enb->ue_id_coll.map = new google::protobuf::Map<uint32_t, uint64_t>();
  enb->ue_id_coll.set_name(S1AP_UE_MAP_NAME);
  *(enb->ue_id_coll.map) = proto.ue_id_map();

  proto_to_supported_ta_list(&enb->supported_ta_list,
                             proto.supported_ta_list());
}
void S1apStateConverter::ue_to_proto(const oai::UeDescription* ue,
                                     oai::UeDescription* proto) {
  proto->Clear();
  proto->MergeFrom(*ue);
}

void S1apStateConverter::proto_to_ue(const oai::UeDescription& proto,
                                     oai::UeDescription* ue) {
  ue->Clear();
  ue->MergeFrom(proto);
}

void S1apStateConverter::s1ap_imsi_map_to_proto(
    const s1ap_imsi_map_t* s1ap_imsi_map, oai::S1apImsiMap* s1ap_imsi_proto) {
  *s1ap_imsi_proto->mutable_mme_ue_s1ap_id_imsi_map() =
      *(s1ap_imsi_map->mme_ueid2imsi_map.map);
}

void S1apStateConverter::proto_to_s1ap_imsi_map(
    const oai::S1apImsiMap& s1ap_imsi_proto, s1ap_imsi_map_t* s1ap_imsi_map) {
  *(s1ap_imsi_map->mme_ueid2imsi_map.map) =
      s1ap_imsi_proto.mme_ue_s1ap_id_imsi_map();
}

void S1apStateConverter::supported_ta_list_to_proto(
    const supported_ta_list_t* supported_ta_list,
    oai::SupportedTaList* supported_ta_list_proto) {
  supported_ta_list_proto->set_list_count(supported_ta_list->list_count);
  for (int idx = 0; idx < supported_ta_list->list_count; idx++) {
    OAILOG_DEBUG(LOG_S1AP, "Writing Supported TAI list at index %d", idx);
    oai::SupportedTaiItems* supported_tai_item =
        supported_ta_list_proto->add_supported_tai_items();
    supported_tai_item_to_proto(&supported_ta_list->supported_tai_items[idx],
                                supported_tai_item);
  }
}

void S1apStateConverter::proto_to_supported_ta_list(
    supported_ta_list_t* supported_ta_list_state,
    const oai::SupportedTaList& supported_ta_list_proto) {
  supported_ta_list_state->list_count = supported_ta_list_proto.list_count();
  for (int idx = 0; idx < supported_ta_list_state->list_count; idx++) {
    OAILOG_DEBUG(LOG_MME_APP, "reading supported ta list at index %d", idx);
    proto_to_supported_tai_items(
        &supported_ta_list_state->supported_tai_items[idx],
        supported_ta_list_proto.supported_tai_items(idx));
  }
}

void S1apStateConverter::supported_tai_item_to_proto(
    const supported_tai_items_t* state_supported_tai_item,
    oai::SupportedTaiItems* supported_tai_item_proto) {
  supported_tai_item_proto->set_tac(state_supported_tai_item->tac);
  supported_tai_item_proto->set_bplmnlist_count(
      state_supported_tai_item->bplmnlist_count);
  char plmn_array[PLMN_BYTES] = {0};
  for (int idx = 0; idx < state_supported_tai_item->bplmnlist_count; idx++) {
    plmn_array[0] =
        (char)(state_supported_tai_item->bplmns[idx].mcc_digit1 + ASCII_ZERO);
    plmn_array[1] =
        (char)(state_supported_tai_item->bplmns[idx].mcc_digit2 + ASCII_ZERO);
    plmn_array[2] =
        (char)(state_supported_tai_item->bplmns[idx].mcc_digit3 + ASCII_ZERO);
    plmn_array[3] =
        (char)(state_supported_tai_item->bplmns[idx].mnc_digit1 + ASCII_ZERO);
    plmn_array[4] =
        (char)(state_supported_tai_item->bplmns[idx].mnc_digit2 + ASCII_ZERO);
    plmn_array[5] =
        (char)(state_supported_tai_item->bplmns[idx].mnc_digit3 + ASCII_ZERO);
    supported_tai_item_proto->add_bplmns(plmn_array);
  }
}

void S1apStateConverter::proto_to_supported_tai_items(
    supported_tai_items_t* supported_tai_item_state,
    const oai::SupportedTaiItems& supported_tai_item_proto) {
  supported_tai_item_state->tac = supported_tai_item_proto.tac();
  supported_tai_item_state->bplmnlist_count =
      supported_tai_item_proto.bplmnlist_count();
  for (int idx = 0; idx < supported_tai_item_state->bplmnlist_count; idx++) {
    supported_tai_item_state->bplmns[idx].mcc_digit1 =
        (int)(supported_tai_item_proto.bplmns(idx)[0]) - ASCII_ZERO;
    supported_tai_item_state->bplmns[idx].mcc_digit2 =
        (int)(supported_tai_item_proto.bplmns(idx)[1]) - ASCII_ZERO;
    supported_tai_item_state->bplmns[idx].mcc_digit3 =
        (int)(supported_tai_item_proto.bplmns(idx)[2]) - ASCII_ZERO;
    supported_tai_item_state->bplmns[idx].mnc_digit1 =
        (int)(supported_tai_item_proto.bplmns(idx)[3]) - ASCII_ZERO;
    supported_tai_item_state->bplmns[idx].mnc_digit2 =
        (int)(supported_tai_item_proto.bplmns(idx)[4]) - ASCII_ZERO;
    supported_tai_item_state->bplmns[idx].mnc_digit3 =
        (int)(supported_tai_item_proto.bplmns(idx)[5]) - ASCII_ZERO;
  }
}
}  // namespace lte
}  // namespace magma
