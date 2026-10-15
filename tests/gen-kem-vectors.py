#!/usr/bin/env python3
"""Extract ML-KEM known answer vectors from libgcrypt's t-mlkem.inp.

Usage: gen-kem-vectors.py <t-mlkem.inp> <kem-vectors.h>

The data sets are the CAVP (FIPS 203) genkey/encap vectors and the first
decapsulation vector of each parameter set.  Only data is extracted.
"""
import re
import sys


def main():
    lines = open(sys.argv[1]).read().split('\n')
    section = 'decap'
    algo = None
    data = {'decap': {}, 'encap': {}, 'genkey': {}}
    cur = None
    for ln in lines:
        if ln.startswith('# Tests for encapsulation'):
            section = 'encap'
            continue
        if ln.startswith('# Tests for key generation'):
            section = 'genkey'
            continue
        if ln.startswith('#') or not ln.strip():
            continue
        m = re.match(r'\[Kyber-(\d+)\]', ln)
        if m:
            algo = m.group(1)
            data[section].setdefault(algo, [])
            cur = None
            continue
        k, v = ln.split(':', 1)
        k = k.strip()
        v = v.strip()
        if section == 'decap':
            if k == 'Public Key':
                cur = {}
                data[section][algo].append(cur)
            cur[k] = v
        else:
            if not data[section][algo]:
                data[section][algo].append({})
            data[section][algo][0][k] = v

    out = ['/* ML-KEM known answer vectors (CAVP / FIPS 203), extracted from the',
           ' * upstream libgcrypt test data file by gen-kem-vectors.py.  Do not',
           ' * edit. */',
           '#ifndef KEM_VECTORS_H', '#define KEM_VECTORS_H', '']

    def emit(name, hexstr):
        data = bytes.fromhex(hexstr)
        out.append('static const unsigned char %s[%d] = {' % (name, len(data)))
        for i in range(0, len(data), 12):
            out.append('    ' + ' '.join('0x%02x,' % b for b in data[i:i + 12]))
        out.append('};')
        out.append('')

    for algo in ('512', '768', '1024'):
        g = data['genkey'][algo][0]
        emit('mlkem%s_gen_z' % algo, g['z'])
        emit('mlkem%s_gen_d' % algo, g['d'])
        emit('mlkem%s_gen_ek' % algo, g['ek'])
        emit('mlkem%s_gen_dk' % algo, g['dk'])
        e = data['encap'][algo][0]
        emit('mlkem%s_enc_ek' % algo, e['ek'])
        emit('mlkem%s_enc_m' % algo, e['m'])
        emit('mlkem%s_enc_c' % algo, e['c'])
        emit('mlkem%s_enc_k' % algo, e['k'])
        d = data['decap'][algo][0]
        emit('mlkem%s_dec_dk' % algo, d['Secret Key'])
        emit('mlkem%s_dec_c' % algo, d['Ciphertext'])
        emit('mlkem%s_dec_k' % algo, d['Shared Secret A'])
    out.append('#endif /* KEM_VECTORS_H */')
    open(sys.argv[2], 'w').write('\n'.join(out) + '\n')
    print({s: {a: len(v) for a, v in d.items()} for s, d in data.items()})


if __name__ == '__main__':
    main()
