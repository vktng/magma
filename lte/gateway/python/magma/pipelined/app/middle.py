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

PHYSICAL_TO_LOGICAL = "middle"


class MiddleController(RestartMixin, MagmaController):
    APP_NAME = "middle"

    def __init__(self, *args, **kwargs):
        super(MiddleController, self).__init__(*args, **kwargs)
        self._midle_tbl_num = \
            self._service_manager.get_table_num(PHYSICAL_TO_LOGICAL)
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