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

from magma.pipelined.app.base import MagmaController
from magma.pipelined.app.restart_mixin import DefaultMsgsMap, RestartMixin

EGRESS = "egress"


class EgressController(RestartMixin, MagmaController):
    APP_NAME = "egress"

    def __init__(self, *args, **kwargs):
        super(EgressController, self).__init__(*args, **kwargs)
        self._egress_tbl_num = self._service_manager.get_table_num(EGRESS)
        self._clean_restart = kwargs['config']['clean_restart']
        self._datapath = None
        self.tbl_num = self._egress_tbl_num

    def _get_default_flow_msgs(self, datapath) -> DefaultMsgsMap:
        """
        Gets the default flow msgs for pkt routing

        Args:
            datapath: ryu datapath struct
        Returns:
            The list of default msgs to add
        """
        return {
            self._egress_tbl_num: self._get_default_egress_flow_msgs(datapath, mac_addr=self.config.virtual_mac),
        }

    def _get_ue_specific_flow_msgs(self, _):
        return {}

    def initialize_on_connect(self, datapath):
        self._datapath = datapath

    def cleanup_state(self):
        pass