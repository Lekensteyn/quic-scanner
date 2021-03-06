#!/usr/bin/env python3
# Probe UDP servers for supported QUIC versions using multiple methods.
#
# Copyright 2020 Peter Wu <peter@lekensteyn.nl>
# Licensed under the MIT license <https://opensource.org/licenses/MIT>.
#
# Send QUIC packets which should solicit Version Negotiation packets. Multiple
# servers and started in parallel, cases are started with small delays in
# between. On read timeout, a case is retried. By default a textual summary is
# displayed, but a JSON report can be generated and read later.
# See 'get_probes()' for an explanation of the test cases.
#
# Example probing some servers and filtering the results:
#
#   ./probe_quic_versions.py --json -s all > probe-results.json
#   jq < probe-results.json '[.[] | select(.versions)]' | ./probe_quic_versions.py -r -
#
# Probe a single server with large VN packets, skip retries on read timeout:
#
#   ./probe_quic_versions.py -s quant.eggert.org:4433 --retries 1 -c '1a*'
#
# In an earlier QUANT version, it would crash and restart after a delay. As
# workaround, probe all but treat one specially:
#
#   ./probe_quic_versions.py --json -s all -s-quant.eggert.org:4433 > 1.json
#   ./probe_quic_versions.py --json -s quant.eggert.org:4433 --retries 1 --delay 15 > 2.json
#   jq -n '[inputs[]]' 1.json 2.json > probe-results.json
#
# Save yourself some time and fold common cases per server:
#
#   ./probe_quic_versions.py -r probe-results.json --summarize

import argparse
import asyncio
import collections
import fnmatch
import json
import socket

# Sampled from https://github.com/quicwg/base-drafts/wiki/Implementations
# Pandora (unreachable) and QUICKer (unmaintained?) have been omitted.
# The QUANT test server restarts 10 seconds after the last open connection or
# crash, so try --delay 15 and disable retries (--retries 1) if needed.
default_servers = [
    'quic.aiortc.org:443',                      # aioquic
    'quic.ogre.com:4433',                       # Apple Traffic Server (ats)
    'quic.rocks:4433',                          # Chromium
    'f5quic.com:4433',                          # f5
    'mew.org:4433',                             # Haskell quic
    'http3-test.litespeedtech.com:4433',        # Litespeed QUIC (lsquic)
    'quic.westus.cloudapp.azure.com:4433',      # MsQuic
    'fb.mvfst.net:443',                         # mvfst by Facebook
    'nghttp2.org:4433',                         # nghttp2
    'cloudflare-quic.com:443',                  # ngx_quic
    'test.privateoctopus.com:4433',             # picoquic
    'quant.eggert.org:4433',                    # QUANT (needs --delay 15)
    'quic.tech:4433',                           # quiche
    'quic.examp1e.net:4433',                    # quicly for H20 server
    'h3.stammw.eu:443',                         # quinn (rust implementation)
    'interop.seemann.io:443',                   # quic-go
    'ietf.akaquic.com:443',                     # Akamai QUIC
]


def get_probes():
    # Versions: VN version, invalid version, draft-01 version.
    # VN packets are expected to be ignored, others should trigger the same
    # result in an implementation.
    probe_headers = [
        ('00', build_long_header(version=0x00000000)),
        ('1a', build_long_header(version=0x1a1a1a1a)),
        ('ff', build_long_header(version=0xff000001)),
    ]
    probes = []
    # Minimum UDP datagram size
    MIN_SIZE = 1200
    for header_type, probe_header in probe_headers:
        padding = b'\0\0\0\0' * ((MIN_SIZE - len(probe_header) + 3) // 4 * 4)
        # VN with right size (larger than padding), too small VN, truncated VN.
        # small/trunc should fail (because they are smaller than padding).
        probes += [
            (header_type + 'large', probe_header + padding),
            (header_type + 'small', probe_header + b'\0\0\0\0'),
            (header_type + 'trunc', probe_header + padding + b'\0'),
        ]
    return probes


def build_long_header(type_byte=0x80, version=0, dcid=b'', scid=b''):
    return b''.join([
        type_byte.to_bytes(1, 'big'),
        version.to_bytes(4, 'big'),
        len(dcid).to_bytes(1, 'big'),
        dcid,
        len(scid).to_bytes(1, 'big'),
        scid,
    ])


def parse_header(resp):
    version = int.from_bytes(resp[1:1+4], 'big')
    offset = 5
    dcil, offset = resp[offset], offset + 1
    dcid, offset = resp[offset:offset+dcil], offset + dcil
    scil, offset = resp[offset], offset + 1
    scid, offset = resp[offset:offset+scil], offset + scil
    return version, offset


def parse_vn(resp):
    version, offset = parse_header(resp)
    assert version == 0, f'Bad version: {version}'
    versions = resp[offset:]
    while versions:
        version, versions = versions[:4], versions[4:]
        version = int.from_bytes(version, 'big')
        # Skip GREASEd versions.
        if (version & 0x0a0a0a0a) == 0x0a0a0a0a:
            continue
        yield version


async def check_server_once(host, port, pkt, read_timeout):
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect((host, port))
        sock.send(pkt)
        sock.setblocking(False)
        # Wait for a response
        resp = await asyncio.wait_for(loop.sock_recv(sock, 4096), read_timeout)
        return ', '.join('%08x' % v for v in parse_vn(resp))
    finally:
        sock.close()


async def check_server(host, port, pkt, *, retries=3, read_timeout=1.0):
    for i in range(retries):
        try:
            return await check_server_once(host, port, pkt, read_timeout)
        except asyncio.TimeoutError:
            if i == retries - 1:
                raise
            # Timeout: assume packet loss, so wait a bit and retry.
            await asyncio.sleep(1)


async def run_after(aw, delay):
    if delay:
        await asyncio.sleep(delay)
    return await aw


class Result:
    def __init__(self, server, case, *, versions=None, error=None):
        self.server = server
        self.case = case
        self.versions = versions
        self.error = error

    def copy(self):
        return Result(self.server, self.case, versions=self.versions,
                      error=self.error)

    def summary(self):
        if self.versions:
            text = f'Versions: {self.versions}'
        elif self.error == 'timeout':
            text = 'timeout'
        else:
            text = f'invalid: {self.error}'
        return text

    def __str__(self):
        return f'{self.server} - {self.case} - {self.summary()}'

    def to_json(self):
        obj = {
            'server': self.server,
            'case': self.case,
        }
        if self.versions:
            obj['versions'] = self.versions
        elif self.error:
            obj['error'] = self.error
        return obj

    @classmethod
    def from_json(cls, o):
        if 'versions' in o:
            return cls(o['server'], o['case'], versions=o['versions'])
        else:
            return cls(o['server'], o['case'], error=o['error'])


def group_results(all_results):
    new_results = []
    # Split all results per server (server -> list of results)
    results_by_server = {}
    for result in all_results:
        results_by_server.setdefault(result.server, []).append(result)
    # Merge cases with the same results.
    for results in results_by_server.values():
        buckets = {}
        for result in results:
            new_result = buckets.get(result.summary())
            if new_result:
                if type(new_result.case) != list:
                    new_result.case = [new_result.case]
                new_result.case.append(result.case)
            else:
                buckets[result.summary()] = result.copy()
        new_results += buckets.values()
    # Compress case descriptions assuming patterns from get_probes: the first
    # two chars mark the version, remaining chars the header type.
    for result in new_results:
        if type(result.case) == list:
            result.case = fold_cases(result.case)
    return new_results


def fold_cases(case_names):
    '''Fold a list of unique case names into one string.'''
    # Convert into a list of (version, header_type)
    tuples = [(name[:2], name[2:]) for name in case_names]
    # Find words with multiple occurrences
    for i in range(2):
        word_counts = collections.Counter(x[i] for x in tuples)
        words = [word for word, count in word_counts.items() if count > 1]
        for word in words:
            other_words = sorted(x[1-i] for x in tuples if x[i] == word)
            if i == 0:
                def join_word(x, other): return (x, other)
            else:
                def join_word(x, other): return (other, x)
            tuples.insert(0, join_word(word, '{%s}' % ','.join(other_words)))
            for other_word in other_words:
                tuples.remove(join_word(word, other_word))
    # Sort by versions
    tuples.sort(key=lambda t: t[0].replace('{', ''))
    return ' '.join('%s%s' % t for t in tuples)


async def summarize_result(who, what, aresult):
    try:
        versions = await aresult
        return Result(who, what, versions=versions)
    except asyncio.TimeoutError:
        return Result(who, what, error='timeout')
    except OSError as e:
        # OSError 111 - Connection refused
        return Result(who, what, error=str(e))


async def run_probes(servers, probes, delay, retries, read_timeout):
    results = []
    checks = []
    for server in servers:
        host, port = server.rsplit(':', 1)
        port = int(port)
        for i, (probe_type, pkt) in enumerate(probes):
            result = check_server(host, port, pkt, retries=retries,
                                  read_timeout=read_timeout)
            result = run_after(result, i * delay)
            summary = summarize_result(f'{host}:{port}', probe_type, result)
            checks += [summary]
    #print('Queued %d checks' % len(checks))
    return await asyncio.gather(*checks, return_exceptions=True)

parser = argparse.ArgumentParser()
parser.add_argument('-s', '--server', metavar='HOST:PORT', dest='servers', action='append',
                    help='Servers to check, "all" for some predefined ones, "help" to list all and exit. Prefix by "-" to remove an earlier item (e.g. added by "all")')
parser.add_argument('-c', '--case', metavar='CASE', dest='cases', action='append',
                    help='Override the cases to check, wildcards ("*" and "?") are supported. "help" to list all and exit')
parser.add_argument('-r', '--read-json', metavar='file.json', type=argparse.FileType('r'),
                    help='Read and summarize a previous JSON report. "-" for stdin')
parser.add_argument('--json', action='store_true',
                    help='Output results in JSON format')
parser.add_argument('--summarize', action='store_true',
                    help='Try to condense output by merging similar cases for a server')
parser.add_argument('--retries', type=int, default=3,
                    help='Maximum retries on timeout (default %(default)d)')
parser.add_argument('--delay', metavar='SECS', type=float, default=.3,
                    help='Delay between tests to the same server (default %(default)s)')
parser.add_argument('--read-timeout', metavar='SECS', type=float, default=1.0,
                    help='Time to wait for a server response (default %(default)s)')


async def main():
    args = parser.parse_args()

    servers = []
    if args.servers:
        for server_arg in args.servers:
            if server_arg.startswith('-'):
                servers.remove(server_arg[1:])
            elif server_arg == 'help':
                for s in default_servers:
                    print(s)
                return
            elif server_arg == 'all':
                for s in default_servers:
                    if not s in servers:
                        servers.append(s)
            elif not server_arg in servers:
                servers.append(server_arg)

    probes = get_probes()
    all_cases = [probe_type for probe_type, pkt in probes]
    cases = all_cases
    if args.cases:
        if args.cases == ['help']:
            for c in all_cases:
                print(c)
            return
        else:
            cases = set()
            for c in args.cases:
                matches = fnmatch.filter(all_cases, c)
                if not matches:
                    parser.error(f'--case {c} did not match any')
                cases.update(matches)
    probes = [(probe_type, pkt)
              for probe_type, pkt in probes if probe_type in cases]

    if not args.servers and not args.read_json:
        parser.error('Either --server or --read-json must be provided.')

    if args.read_json:
        results = []
        results = [Result.from_json(item)
                   for item in json.load(args.read_json)]
        if servers:
            results = [r for r in results if r.server in servers]
        results = [r for r in results if r.case in cases]
    else:
        results = await run_probes(servers, probes, args.delay, args.retries,
                                   args.read_timeout)
    if args.json:
        jresults = [result.to_json() for result in results]
        print(json.dumps(jresults, indent=4))
    else:
        if args.summarize:
            results = group_results(results)
        rows = [[r.server, r.case, r.summary()] for r in results]
        # Add one more space at the right and align up to a multiple of four.
        colsize = [max(len(c) for c in col) for col in list(zip(*rows))[:-1]]
        colsize = [(size + 4) // 4 * 4 for size in colsize]
        for row in rows:
            for i, size in enumerate(colsize):
                row[i] = row[i].ljust(size)
            print('- '.join(row))


if __name__ == '__main__':
    asyncio.run(main())
