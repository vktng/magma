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

from magma.pipelined.openflow.messages import MessageHub, MsgChannel
from ryu.lib.packet import ether_types
from collections import namedtuple
from magma.pipelined.utils import get_virtual_iface_mac
from magma.pipelined.openflow import flows
from magma.pipelined.openflow.magma_match import MagmaMatch
from magma.pipelined.app.base import MagmaController
from magma.pipelined.app.restart_mixin import DefaultMsgsMap, RestartMixin
from magma.pipelined.openflow.registers import (
    PASSTHROUGH_REG_VAL,
    # PROXY_TAG_TO_PROXY,
    # REG_ZERO_VAL,
    # TUN_PORT_REG,
    Direction,
    # load_direction,
)

EGRESS = "egress"
PHYSICAL_TO_LOGICAL = "middle"


class MiddleController(RestartMixin, MagmaController):
    APP_NAME = "middle"

    # TODO: everything is needed?
    MiddleConfig = namedtuple(
        'MiddleConfig',
        [
            'gtp_port', 'uplink_port', 'mtr_ip', 'mtr_port', 'li_port_name',
            'enable_nat', 'non_nat_gw_probe_frequency', 'non_nat_arp_egress_port',
            'setup_type', 'uplink_gw_mac', 'he_proxy_port', 'he_proxy_eth_mac',
            'mtr_mac', 'virtual_mac',
        ],
    )

    ARP_PROBE_FREQUENCY = 300
    UPLINK_OVS_BRIDGE_NAME = 'uplink_br0'

    def __init__(self, *args, **kwargs):
        super(MiddleController, self).__init__(*args, **kwargs)
        self.config = self._get_config(kwargs['config'])
        self.logger.info("inout config: %s", self.config)
        # TODO Alex do we want this to be cofigurable from swagger?
        if self.config.mtr_ip:
            self._mtr_service_enabled = True
        else:
            self._mtr_service_enabled = False
        self._midle_tbl_num = \
            self._service_manager.get_table_num(PHYSICAL_TO_LOGICAL)
        self._egress_tbl_num = self._service_manager.get_table_num(EGRESS)
        # following fields are only used in Non Nat config
        self._clean_restart = kwargs['config']['clean_restart']
        self._datapath = None
        self.tbl_num = self._midle_tbl_num
        self._msg_hub = MessageHub(self.logger)
    
    def _get_default_flow_msgs(self, datapath) -> DefaultMsgsMap:
        """
        Gets the default flow msgs for pkt routing

        Args:
            datapath: ryu datapath struct
        Returns:
            The list of default msgs to add
        """
        return {
            self._midle_tbl_num: self._get_default_middle_flow_msgs(datapath),
        }

    def _get_ue_specific_flow_msgs(self, _):
        return {}

    def initialize_on_connect(self, datapath):
        self._datapath = datapath

    def cleanup_state(self):
        pass
    
    def _get_default_middle_flow_msgs(self, dp):
        """
        TODO: this needs to be adapted because of copypaste
        Egress table is the last table that a packet touches in the pipeline.
        Output downlink traffic to gtp port, uplink trafic to LOCAL

        Raises:
            MagmaOFError if any of the default flows fail to install.
        """
        msgs = []
        next_tbl = self._service_manager.get_next_table_num(PHYSICAL_TO_LOGICAL)

        # Allow passthrough pkts(skip enforcement and send to egress table)
        ps_match = MagmaMatch(passthrough=PASSTHROUGH_REG_VAL)
        msgs.append(
            flows.get_add_resubmit_next_service_flow_msg(
                dp,
                self._midle_tbl_num, ps_match, actions=[],
                priority=flows.PASSTHROUGH_PRIORITY,
                resubmit_table=self._egress_tbl_num,
            ),
        )

        match = MagmaMatch()
        msgs.append(
            flows.get_add_resubmit_next_service_flow_msg(
                dp,
                self._midle_tbl_num, match, actions=[],
                priority=flows.DEFAULT_PRIORITY, resubmit_table=next_tbl,
            ),
        )

        if self._mtr_service_enabled:
            msgs.extend(
                _get_vlan_egress_flow_msgs(
                    dp,
                    self._midle_tbl_num,
                    ether_types.ETH_TYPE_IP,
                    self.config.mtr_ip,
                    self.config.mtr_port,
                    priority=flows.UE_FLOW_PRIORITY,
                    direction=Direction.OUT,
                    dst_mac=self.config.mtr_mac,
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
        return self.MiddleConfig(
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

# TODO: Why is this not in the class?    
def _get_vlan_egress_flow_msgs(
    dp, table_no, eth_type, ip, out_port=None,
    priority=0, direction=Direction.IN, dst_mac=None,
):
    """
    Install egress flows
    Args:
        dp datapath
        table_no table to install flow
        out_port specify egress port, if None reg value is used
        priority flow priority
        direction packet direction.
    """
    msgs = []
    if out_port:
        output_reg = None
    else:
        output_reg = TUN_PORT_REG

    # Pass non vlan packet as it is.
    # TODO: add support to match IPv6 address
    if ip:
        match = MagmaMatch(
            direction=direction,
            eth_type=eth_type,
            vlan_vid=(0x0000, 0x1000),
            ipv4_dst=ip,
        )
    else:
        match = MagmaMatch(
            direction=direction,
            eth_type=eth_type,
            vlan_vid=(0x0000, 0x1000),
        )
    actions = []
    if dst_mac:
        actions.append(dp.ofproto_parser.NXActionRegLoad2(dst='eth_dst', value=dst_mac))

    msgs.append(
        flows.get_add_output_flow_msg(
            dp, table_no, match, actions,
            priority=priority, output_reg=output_reg, output_port=out_port,
        ),
    )

    # remove vlan header for out_port.
    if ip:
        match = MagmaMatch(
            direction=direction,
            eth_type=eth_type,
            vlan_vid=(0x1000, 0x1000),
            ipv4_dst=ip,
        )
    else:
        match = MagmaMatch(
            direction=direction,
            eth_type=eth_type,
            vlan_vid=(0x1000, 0x1000),
        )
    actions = [dp.ofproto_parser.OFPActionPopVlan()]
    if dst_mac:
        actions.append(dp.ofproto_parser.NXActionRegLoad2(dst='eth_dst', value=dst_mac))

    msgs.append(
        flows.get_add_output_flow_msg(
            dp, table_no, match, actions,
            priority=priority, output_reg=output_reg, output_port=out_port,
        ),
    )
    return msgs
