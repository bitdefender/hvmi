#
# Copyright (c) 2020 Bitdefender
# SPDX-License-Identifier: Apache-2.0
#
"""

"""

import r2pipe
import os

class R2Wrapper:

    def __init__(self, f):

        # Initialize the pipe and information object
        self.pipe = r2pipe.open(f)
        self.info = self.pipe.cmdJ('ij')

        # Get the pdb file, load it
        self.pdb_file = self._pdb_file()
        self._load_pdb()

        # Get the data types and addresses as json
        pdb = self._read_pdb()['pdb']
        self.types = pdb[0]['types']
        self.addrs = pdb[1]['gvars']

    def _pdb_file(self):
        guid = self.info.bin.guid
        dbg_file = self.info.bin.dbg_file
        symstore = self.pipe.cmdj('ej')['pdb.symstore']
        
        return os.path.join(symstore, dbg_file, guid, dbg_file)

    def _download_pdb(self):
        f = self.pdb_file

        if not os.path.exists(f):
            self.pipe.cmd('idpd')

        return f

    def _load_pdb(self):
        self.pipe.cmd(f"idp {self._download_pdb()}")

    def _read_pdb(self):
        return self.pipe.syscmdj(f"rabin2 -Pj {self._download_pdb()}")

    def read_bytes(self, addr, size):
        b = bytes.fromhex(self.pipe.cmd(f"p8 {size} @ {addr}"))
        if len(b) != size:
            raise LookupError(f"Failed to read {size} bytes from {addr}")
        return b

    def section(self, addr):
        return self.pipe.cmdJ(f"iSj. @ {addr}")

    def size_for_basic_type(self, basic_type):
        if 'pointer' in basic_type:
            return self.info.bin.bits / 8
        if 'long long' in basic_type:
            return 8
        if 'long' in basic_type:
            return 4
        if 'short' in basic_type:
            return 2
        if 'char' in basic_type:
            return 1

