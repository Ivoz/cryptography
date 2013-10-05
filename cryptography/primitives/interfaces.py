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

__all__ = [
    "Mode",
    "BlockCipher",
]

from enum import Enum
from cryptography.primitives.block import modes, ciphers


class Mode(Enum):
    CBC = modes.CBC
    CFB = modes.CFB
    ECB = modes.ECB
    OFB = modes.OFB

    def __call__(self, *args, **kwargs):
        return self.value(self.name, *args, **kwargs)


class Cipher(Enum):

    def __call__(self, *args, **kwargs):
        return self.value(self.name, *args, **kwargs)

    @property
    def key_sizes(self):
        return self.value.key_sizes


class BlockCipher(Cipher):
    AES = ciphers.AES

    @property
    def block_size(self):
        return self.value.block_size
