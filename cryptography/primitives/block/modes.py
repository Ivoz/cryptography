# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import absolute_import, division, print_function

import os

__all__ = [
    "CBC",
    "CFB",
    "ECB",
    "OFB",
]


class Mode(object):

    def __init__(self, name, cipher):
        self.name = name
        self.cipher = cipher


class ModeWithIV(Mode):

    def __init__(self, name, cipher, initialization_vector=None):
        super(ModeWithIV, self).__init__(name, cipher)
        if initialization_vector is None:
            initialization_vector = os.urandom(cipher.block_size // 8)
        self.initialization_vector = initialization_vector


class CBC(ModeWithIV):
    pass


class CFB(ModeWithIV):
    pass


class ECB(Mode):
    pass


class OFB(ModeWithIV):
    pass
