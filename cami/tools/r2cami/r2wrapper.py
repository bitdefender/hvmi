#
# Copyright (c) 2020 Bitdefender
# SPDX-License-Identifier: Apache-2.0
#
"""

"""

import r2pipe
import json
import re
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
        try:
            pdb = self._read_pdb_from_rabin()['pdb']
            self.types = pdb[0]['types']
            self.addrs = pdb[1]['gvars']
        except Exception:
            pdb = self._read_pdb_from_r2shell()
            self.types = pdb['types']
            self.addrs = pdb['gvars']

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

    def _read_pdb_from_rabin(self):
        return self.pipe.syscmdj(f"rabin2 -Pj {self._download_pdb()}")

    def _read_pdb_from_r2shell(self):
        # We would like to use cmdj here to get a json, but we can't since radare
        # doesn't handle section names as they are, aka non null terminated 8 byte
        # sequences. The result are funny invalid utf-8 strings...
        s = self.pipe.cmd(f"idpij")

        res = [re.compile(r'\\x[0-9a-fA-F]{2}'), re.compile(r'\\u[0-9a-fA-F]{4}')]

        for r in res:
            s = re.sub(r, '', s)

        return json.loads(s)

    def read_bytes(self, addr, size):
        b = bytes.fromhex(self.pipe.cmd(f"p8 {size} @ {addr}").strip())
        if len(b) != size:
            raise LookupError(f"Failed to read {size} bytes from {addr}")
        return b

    def section(self, addr):
        return self.pipe.cmdJ(f"iSj. @ {addr}")

    def size_for_basic_type(self, basic_type):
        if 'pointer' in basic_type or '*' in basic_type:
            return self.info.bin.bits / 8
        if 'long long' in basic_type or '64_t' in basic_type:
            return 8
        if 'long' in basic_type or '32_t' in basic_type:
            return 4
        if 'short' in basic_type or '16_t' in basic_type:
            return 2
        if 'char' in basic_type or '8_t' in basic_type:
            return 1

