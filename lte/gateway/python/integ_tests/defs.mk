# Copyright 2020 The Magma Authors.

# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

PROTO_LIST:=orc8r_protos lte_protos feg_protos

# Add the s1aptester integration tests
PRECOMMIT_TESTS = s1aptests/test_enable_ipv6_iface.py \
s1aptests/test_ipv6_non_nat_dp_ul_tcp.py \
s1aptests/test_disable_ipv6_iface.py

EXTENDED_TESTS = s1aptests/test_modify_mme_config_for_sanity.py \
s1aptests/test_restore_mme_config_after_sanity.py

NON_SANITY_TESTS = s1aptests/test_modify_config_for_non_sanity.py \
s1aptests/test_attach_detach_non_nat_dp_ul_tcp.py \
s1aptests/test_no_auth_resp_with_mme_restart_reattach.py \
s1aptests/test_attach_detach_rar_activation_reject.py \
s1aptests/test_paging_with_mme_restart.py \
s1aptests/test_no_identity_rsp_with_mme_restart.py \
s1aptests/test_agw_offload_idle_active_ue.py \
s1aptests/test_standalone_pdn_conn_req_with_apn_correction.py \
s1aptests/test_attach_esm_info_with_apn_correction.py \
s1aptests/test_enb_partial_reset_multi_ue.py \
s1aptests/test_attach_detach_with_pco_ipcp.py \
s1aptests/test_attach_complete_after_ics_timer_expiry.py \
s1aptests/test_send_error_ind_for_dl_nas_with_auth_req.py \
s1aptests/test_send_error_ind_for_erab_setup_req.py \
s1aptests/test_attach_detach_with_ipv6_pcscf_and_dns_addr.py \
s1aptests/test_concurrent_secondary_pdns.py \
s1aptests/test_concurrent_secondary_pdn_reject.py \
s1aptests/test_attach_detach_ipv6.py \
s1aptests/test_ipv4v6_secondary_pdn_rs_retransmit.py \
s1aptests/test_ipv4v6_secondary_pdn_spgw_initiated_ded_bearer.py \
s1aptests/test_ipv6_secondary_pdn_rs_retransmit.py \
s1aptests/test_ipv4v6_secondary_pdn.py \
s1aptests/test_ipv4v6_secondary_pdn_multi_ue.py \
s1aptests/test_ipv4v6_secondary_pdn_with_ded_bearer.py \
s1aptests/test_ipv6_secondary_pdn_with_ded_bearer.py \
s1aptests/test_ipv4v6_secondary_pdn_with_ded_bearer_multi_ue.py \
s1aptests/test_outoforder_erab_setup_rsp_dedicated_bearer.py \
s1aptests/test_secondary_pdn_with_dedicated_bearer_multiple_services_restart.py \
s1aptests/test_attach_esm_info_timerexpiration_max_retries.py \
s1aptests/test_attach_service_without_mac.py \
s1aptests/test_paging_request.py \
s1aptests/test_multi_enb_paging_request.py \
s1aptests/test_multi_enb_multi_ue_diff_tac.py \
s1aptests/test_enb_partial_reset_with_unknown_ue_s1ap_ids.py \
s1aptests/test_attach_auth_mac_failure.py \
s1aptests/test_attach_esm_information_timerexpiration.py \
s1aptests/test_attach_inactive_tau_with_combined_tala_update_reattach.py \
s1aptests/test_attach_active_tau_with_combined_tala_update_reattach.py \
s1aptests/test_activate_deactivate_multiple_dedicated.py \
s1aptests/test_sctp_shutdown_while_mme_is_stopped.py \
s1aptests/test_3495_timer_for_default_bearer_with_mme_restart.py \
s1aptests/test_3495_timer_for_dedicated_bearer_with_mme_restart.py \
s1aptests/test_attach_detach_with_corrupt_stateless_mme.py \
s1aptests/test_enb_partial_reset_multi_ue_with_mme_restart.py \
s1aptests/test_attach_ics_drop_with_mme_restart.py \
s1aptests/test_attach_mme_restart_detach_multi_ue.py \
s1aptests/test_no_auth_response_with_mme_restart.py \
s1aptests/test_no_esm_information_rsp_with_mme_restart.py \
s1aptests/test_no_smc_with_mme_restart_reattach.py \
s1aptests/test_no_attach_complete_with_mme_restart.py \
s1aptests/test_attach_ics_failure_with_mme_restart.py \
s1aptests/test_continuous_random_attach.py \
s1aptests/test_s1_handover_ping_pong.py \
s1aptests/test_s1_handover_cancel.py \
s1aptests/test_s1_handover_failure.py \
s1aptests/test_s1_handover_timer_expiry.py \
s1aptests/test_attach_and_mme_restart_loop_detach_and_mme_restart_loop_multi_ue.py \
s1aptests/test_restore_config_after_non_sanity.py

#---------------
# Non-Sanity: Failure/Stuck/Crashing Test Cases
# s1aptests/test_outoforder_erab_setup_rsp_default_bearer.py \ GitHubIssue 5992
# s1aptests/test_stateless_multi_ue_mixedstate_mme_restart.py \ GitHubIssue 5997
# s1aptests/test_attach_with_multiple_mme_restarts.py \ GitHubIssue 5997

# Non-Sanity: Flaky Test Cases
# s1aptests/test_attach_detach_two_pdns_with_tcptraffic.py \ GitHubIssue 9670
# s1aptests/test_agw_offload_mixed_idle_active_multiue.py \ GitHubIssue 6063
# s1aptests/test_attach_ul_udp_data_multi_ue.py \ Fails randomly with connection refused
# s1aptests/test_attach_dl_udp_data_multi_ue.py \ Fails randomly with connection refused
# s1aptests/test_attach_ul_tcp_data_multi_ue.py \ Fails randomly with connection refused
# s1aptests/test_attach_dl_tcp_data_multi_ue.py \ Fails randomly with connection refused
# s1aptests/test_attach_dl_ul_tcp_data_multi_ue.py \ Fails randomly with connection refused
# s1aptests/test_data_flow_after_service_request.py \ Fails randomly with connection refused
#---------------

# Sanity: Failure/Stuck/Crashing Test Cases
# s1aptests/test_attach_standalone_act_dflt_ber_ctxt_rej_ded_bearer_activation.py \ GitHubIssue 12779
#---------------
# Scalability Testing: These testcases are not supposed to be part of regular
# sanity testing because they will take too much time to execute, however they
# should run under CI automation on regular basis for load testing, with lesser
# frequency compared to sanity testing
#
# TODO: Add these testcases as part of CI automation
# s1aptests/test_scalability_attach_detach_multi_ue.py
#---------------

# TODO: Flaky ipv6 tests which randomly fail with connection refused
#s1aptests/test_ipv6_non_nat_dp_dl_tcp.py
#s1aptests/test_ipv6_non_nat_dp_ul_udp.py
#s1aptests/test_ipv6_non_nat_dp_dl_udp.py
#---------------

# TODO: Add ipv6 tests to integ test suite
# s1aptests/test_ipv4v6_non_nat_ul_tcp.py
# s1aptests/test_ipv4v6_non_nat_ded_bearer_ul_tcp.py
# s1aptests/test_ipv4v6_non_nat_ded_bearer_dl_tcp.py
# s1aptests/test_ipv6_non_nat_ded_bearer_ul_tcp.py
# s1aptests/test_ipv6_non_nat_ded_bearer_dl_tcp.py

# Add the s1aptester integration tests with federation gateway
FEDERATED_TESTS = s1aptests/test_attach_detach.py \
s1aptests/test_attach_detach_multi_ue.py \
s1aptests/test_attach_auth_failure.py \
s1aptests/test_no_auth_response.py \
s1aptests/test_nas_non_delivery_for_auth.py \
s1aptests/test_sctp_abort_after_auth_req.py \
s1aptests/test_sctp_shutdown_after_auth_req.py \
s1aptests/test_no_auth_resp_with_mme_restart_reattach.py \
s1aptests/test_send_error_ind_for_dl_nas_with_auth_req.py \
s1aptests/test_attach_auth_mac_failure.py \
s1aptests/test_no_auth_response_with_mme_restart.py \
s1aptests/test_no_security_mode_complete.py \
s1aptests/test_no_attach_complete.py \
s1aptests/test_attach_detach_security_algo_eea0_eia0.py \
s1aptests/test_attach_detach_security_algo_eea1_eia1.py \
s1aptests/test_attach_detach_security_algo_eea2_eia2.py \
s1aptests/test_attach_security_mode_reject.py \
s1aptests/test_attach_missing_imsi.py \
s1aptests/test_duplicate_attach.py \
s1aptests/test_attach_emergency.py \
s1aptests/test_attach_detach_after_ue_context_release.py \
s1aptests/test_attach_esm_information_wrong_apn.py \
s1aptests/test_attach_detach_secondary_pdn_invalid_apn.py \
s1aptests/test_standalone_pdn_conn_req_with_apn_correction.py


CLOUD_TESTS = cloud_tests/checkin_test.py \
cloud_tests/metrics_export_test.py \
cloud_tests/config_test.py

S1AP_TESTER_CFG=$(MAGMA_ROOT)/lte/gateway/python/integ_tests/data/s1ap_tester_cfg
S1AP_TESTER_PYTHON_PATH=$(S1AP_TESTER_ROOT)/bin

# Local integ tests are run on the magma access gateway, not the test VM
LOCAL_INTEG_TESTS = gxgy_tests
