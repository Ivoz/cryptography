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

from enum import Enum

from cryptography.bindings import _default_api


class Operation(Enum):
    encrypt = 0
    decrypt = 1


class BlockCipher(object):
    def __init__(self, cipher, mode, key, api=None):
        super(BlockCipher, self).__init__()

        if api is None:
            api = _default_api

        self._api = api
        self._cipher = cipher
        self._ctx = None
        self.key = None
        self._mode = mode
        self._operation = None

    @property
    def cipher(self):
        return self._cipher

    @property
    def key_size(self):
        return len(self.key) * 8

    @property
    def mode(self):
        return self._mode

    @property
    def name(self):
        return "{0}-{1}-{2}".format(
            self.cipher.name, self.key_size, self.mode.name,
        )

    def initialize(self, operation=None):
        if self.key_size not in self.cipher.key_sizes:
            raise ValueError("Invalid key size ({0}) for {1}".format(
                self.key_size, self.cipher.name
            ))
        if operation is None:
            operation = self._operation
        assert isinstance(operation, Operation)
        if self._ctx is not None:
            del self._ctx
        self._ctx = self._api.create_block_cipher_context(self)

    def process(self, plaintext):
        if self._ctx is None:
            raise ValueError("BlockCipher was already finalized")

        if self._operation is None:
            raise ValueError("BlockCipher is not yet initialized")
        # TODO: allow for decryption
        elif self._operation is not Operation.encrypt:
            raise ValueError("BlockCipher cannot encrypt when the operation is"
                             " set to %s" % self._operation.name)

        return self._api.update_encrypt_context(self._ctx, plaintext)

    def finalize(self):
        if self._ctx is None:
            raise ValueError("BlockCipher was already finalized")

        if self._operation is Operation.encrypt:
            result = self._api.finalize_encrypt_context(self._ctx)
        else:
            raise ValueError("BlockCipher cannot finalize the unknown "
                             "operation %s" % self._operation.name)

        self._ctx = None
        return result
