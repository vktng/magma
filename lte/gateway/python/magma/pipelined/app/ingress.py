"""
Copyright 2022 The Magma Authors.

This source code is licensed under the BSD-style license found in the
LICENSE file in the root directory of this source tree.

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

from collections import namedtuple
from magma.pipelined.utils import get_virtual_iface_mac
from magma.pipelined.openflow.messages import MessageHub, MsgChannel
from ryu.ofproto.ofproto_v1_4 import OFPP_LOCAL
from magma.pipelined.openflow.magma_match import MagmaMatch
from magma.pipelined.app.base import MagmaController
from magma.pipelined.openflow import flows
from magma.pipelined.app.restart_mixin import DefaultMsgsMap, RestartMixin
from magma.pipelined.openflow.registers import (
    PASSTHROUGH_REG_VAL,
    # PROXY_TAG_TO_PROXY,
    REG_ZERO_VAL,
    # TUN_PORT_REG,
    Direction,
    load_direction,
)

INGRESS = "ingress"


class IngressController(RestartMixin, MagmaController):
    APP_NAME = "ingress"
    UPLINK_OVS_BRIDGE_NAME = 'uplink_br0'
    ARP_PROBE_FREQUENCY = 300
    # TODO: everything is needed?
    IngressConfig = namedtuple(
        'IngressConfig',
        [
            'gtp_port', 'uplink_port', 'mtr_ip', 'mtr_port', 'li_port_name',
            'enable_nat', 'non_nat_gw_probe_frequency', 'non_nat_arp_egress_port',
            'setup_type', 'uplink_gw_mac', 'he_proxy_port', 'he_proxy_eth_mac',
            'mtr_mac', 'virtual_mac',
        ],
    )


    def __init__(self, *args, **kwargs):
        super(IngressController, self).__init__(*args, **kwargs)
        self.config = self._get_config(kwargs['config'])
        self._li_port = None
        self.logger.info("ingress config: %s", self.config)
        self._ingress_tbl_num = self._service_manager.get_table_num(INGRESS)
        # following fields are only used in Non Nat config
        self.tbl_num = self._ingress_tbl_num
        self._clean_restart = kwargs['config']['clean_restart']
        self._msg_hub = MessageHub(self.logger)
        self._datapath = None

    def _get_default_flow_msgs(self, datapath) -> DefaultMsgsMap:
        """
        Gets the default flow msgs for pkt routing

        Args:
            datapath: ryu datapath struct
        Returns:
            The list of default msgs to add
        """
        return {
            self._ingress_tbl_num: self._get_default_ingress_flow_msgs(datapath),
        }

    def _get_ue_specific_flow_msgs(self, _):
        return {}

    def initialize_on_connect(self, datapath):
        self._datapath = datapath

    def cleanup_state(self):
        pass

    def _get_default_ingress_flow_msgs(self, dp):
        """
        Sets up the ingress table, the first step in the packet processing
        pipeline.

        This sets up flow rules to annotate packets with a metadata bit
        indicating the direction. Incoming packets are defined as packets
        originating from the LOCAL port, outgoing packets are defined as
        packets originating from the gtp port.

        All other packets bypass the pipeline.

        Note that the ingress rules do *not* install any flows that cause
        PacketIns (i.e., sends packets to the controller).

        Raises:
            MagmaOFError if any of the default flows fail to install.
        """
        parser = dp.ofproto_parser
        next_table = self._service_manager.get_next_table_num(INGRESS)
        msgs = []

        # set traffic direction bits

        # set a direction bit for incoming (internet -> UE) traffic.
        match = MagmaMatch(in_port=OFPP_LOCAL)
        actions = [load_direction(parser, Direction.IN)]
        msgs.append(
            flows.get_add_resubmit_next_service_flow_msg(
                dp,
                self._ingress_tbl_num, match, actions=actions,
                priority=flows.DEFAULT_PRIORITY, resubmit_table=next_table,
            ),
        )

        # set a direction bit for incoming (internet -> UE) traffic.
        match = MagmaMatch(in_port=self.config.uplink_port)
        actions = [load_direction(parser, Direction.IN)]
        msgs.append(
            flows.get_add_resubmit_next_service_flow_msg(
                dp, self._ingress_tbl_num, match,
                actions=actions,
                priority=flows.DEFAULT_PRIORITY,
                resubmit_table=next_table,
            ),
        )

        # Send RADIUS requests directly to li table
        if self._li_port:
            match = MagmaMatch(in_port=self._li_port)
            actions = [load_direction(parser, Direction.IN)]
            msgs.append(
                flows.get_add_resubmit_next_service_flow_msg(
                    dp, self._ingress_tbl_num,
                    match, actions=actions, priority=flows.DEFAULT_PRIORITY,
                    resubmit_table=self._li_table,
                ),
            )

        # set a direction bit for incoming (mtr -> UE) traffic.
        if self._mtr_service_enabled:
            match = MagmaMatch(in_port=self.config.mtr_port)
            actions = [load_direction(parser, Direction.IN)]
            msgs.append(
                flows.get_add_resubmit_next_service_flow_msg(
                    dp, self._ingress_tbl_num,
                    match, actions=actions, priority=flows.DEFAULT_PRIORITY,
                    resubmit_table=next_table,
                ),
            )

        if self.config.he_proxy_port != 0:
            match = MagmaMatch(in_port=self.config.he_proxy_port)
            actions = [load_direction(parser, Direction.IN)]
            msgs.append(
                flows.get_add_resubmit_next_service_flow_msg(
                    dp, self._ingress_tbl_num,
                    match, actions=actions, priority=flows.DEFAULT_PRIORITY,
                    resubmit_table=next_table,
                ),
            )

        if self.config.setup_type == 'CWF':
            # set a direction bit for outgoing (pn -> inet) traffic for remaining traffic
            ps_match_out = MagmaMatch()
            actions = [load_direction(parser, Direction.OUT)]
            msgs.append(
                flows.get_add_resubmit_next_service_flow_msg(
                    dp, self._ingress_tbl_num, ps_match_out,
                    actions=actions,
                    priority=flows.MINIMUM_PRIORITY,
                    resubmit_table=next_table,
                ),
            )
        else:
            # set a direction bit for outgoing (pn -> inet) traffic for remaining traffic
            # Passthrough is zero for packets from eNodeB GTP tunnels
            ps_match_out = MagmaMatch(passthrough=REG_ZERO_VAL)
            actions = [load_direction(parser, Direction.OUT)]
            msgs.append(
                flows.get_add_resubmit_next_service_flow_msg(
                    dp, self._ingress_tbl_num, ps_match_out,
                    actions=actions,
                    priority=flows.MINIMUM_PRIORITY,
                    resubmit_table=next_table,
                ),
            )

            # Passthrough is one for packets from remote PGW GTP tunnels, set direction
            # flag to IN for such packets.
            ps_match_in = MagmaMatch(passthrough=PASSTHROUGH_REG_VAL)
            actions = [load_direction(parser, Direction.IN)]
            msgs.append(
                flows.get_add_resubmit_next_service_flow_msg(
                    dp, self._ingress_tbl_num, ps_match_in,
                    actions=actions,
                    priority=flows.MINIMUM_PRIORITY,
                    resubmit_table=next_table,
                ),
            )

        return msgs

    # TODO: Is everything needed?
    def _get_config(self, config_dict):
        mtr_ip = None
        mtr_port = None
        li_port_name = None
        port_no = config_dict.get('uplink_port', None)
        setup_type = config_dict.get('setup_type', None)

        he_proxy_port = 0
        he_proxy_eth_mac = ''
        try:
            if 'proxy_port_name' in config_dict:
                he_proxy_port = BridgeTools.get_ofport(config_dict.get('proxy_port_name'))
                he_proxy_eth_mac = config_dict.get('he_proxy_eth_mac', PROXY_PORT_MAC)
        except DatapathLookupError:
            # ignore it
            self.logger.debug("could not parse proxy port config")

        if 'mtr_ip' in config_dict and 'mtr_interface' in config_dict and 'ovs_mtr_port_number' in config_dict:
            self._mtr_service_enabled = True
            mtr_ip = config_dict['mtr_ip']
            mtr_port = config_dict['ovs_mtr_port_number']
            mtr_mac = get_virtual_iface_mac(config_dict['mtr_interface'])
        else:
            mtr_ip = None
            mtr_mac = None
            mtr_port = None

        if 'li_local_iface' in config_dict:
            li_port_name = config_dict['li_local_iface']

        enable_nat = config_dict.get('enable_nat', True)
        non_nat_gw_probe_freq = config_dict.get(
            'non_nat_gw_probe_frequency',
            self.ARP_PROBE_FREQUENCY,
        )
        # In case of vlan tag on uplink_bridge, use separate port.
        sgi_vlan = config_dict.get('sgi_management_iface_vlan', "")
        if not sgi_vlan:
            non_nat_arp_egress_port = config_dict.get(
                'non_nat_arp_egress_port',
                self.UPLINK_OVS_BRIDGE_NAME,
            )
        else:
            non_nat_arp_egress_port = config_dict.get(
                'non_nat_arp_egress_port',
                self.NON_NAT_ARP_EGRESS_PORT,
            )
        virtual_iface = config_dict.get('virtual_interface', None)
        if enable_nat is True or setup_type != 'LTE':
            if virtual_iface is not None:
                virtual_mac = get_virtual_iface_mac(virtual_iface)
            else:
                virtual_mac = ""
        else:
            # override virtual mac from config file.
            virtual_mac = config_dict.get('virtual_mac', "")

        uplink_gw_mac = config_dict.get(
            'uplink_gw_mac',
            "ff:ff:ff:ff:ff:ff",
        )
        return self.IngressConfig(
            gtp_port=config_dict['ovs_gtp_port_number'],
            uplink_port=port_no,
            mtr_ip=mtr_ip,
            mtr_port=mtr_port,
            li_port_name=li_port_name,
            enable_nat=enable_nat,
            non_nat_gw_probe_frequency=non_nat_gw_probe_freq,
            non_nat_arp_egress_port=non_nat_arp_egress_port,
            setup_type=setup_type,
            uplink_gw_mac=uplink_gw_mac,
            he_proxy_port=he_proxy_port,
            he_proxy_eth_mac=he_proxy_eth_mac,
            mtr_mac=mtr_mac,
            virtual_mac=virtual_mac,
        )

    # TODO: Should this be abstract in restart_mixin.py ?
    def _wait_for_responses(self, chan, response_count):
        def fail(err):
            self.logger.error("Failed to install rule with error: %s", err)

        for _ in range(response_count):
            try:
                result = chan.get()
            except MsgChannel.Timeout:
                return fail("No response from OVS msg channel")
            if not result.ok():
                return fail(result.exception())

    def finish_init(self, _):
        pass