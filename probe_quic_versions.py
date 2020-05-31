#!/usr/bin/env python3
# Probe UDP servers for supported QUIC versions using multiple methods.
#
# Copyright 2020 Peter Wu <peter@lekensteyn.nl>
# Licensed under the MIT license <http://opensource.org/licenses/MIT>.
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

import argparse
import asyncio
import fnmatch
import json
import socket

# Sampled from https://github.com/quicwg/base-drafts/wiki/Implementations
default_servers = [
    'quic.aiortc.org:443',
    'quic.ogre.com:4433',
    'quic.rocks:4433',
    'f5quic.com:4433',
    'mew.org:4433',
    'http3-test.litespeedtech.com:4433',
    'quic.westus.cloudapp.azure.com:4433',
    'fb.mvfst.net:443',
    'nghttp2.org:4433',
    'cloudflare-quic.com:443',
    'test.privateoctopus.com:4433',
    'quant.eggert.org:4433',
    'quic.tech:4433',
    'quicker.edm.uhasselt.be:4433',
    'quic.examp1e.net:4433',
    'ietf.akaquic.com:443',
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

    def __str__(self):
        if self.versions:
            text = f'Versions: {self.versions}'
        elif self.error == 'timeout':
            text = 'timeout'
        else:
            text = f'invalid: {self.error}'
        return f'{self.server:38} - {self.case} - {text}'

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
                    help='Servers to check, "all" for some predefined ones, "help" to list all and exit')
parser.add_argument('-c', '--case', metavar='CASE', dest='cases', action='append',
                    help='Override the cases to check, wildcards ("*" and "?") are supported. "help" to list all and exit')
parser.add_argument('-r', '--read-json', metavar='file.json', type=argparse.FileType('r'),
                    help='Read and summarize a previous JSON report. "-" for stdin')
parser.add_argument('--json', action='store_true',
                    help='Output results in JSON format')
parser.add_argument('--retries', type=int, default=3,
                    help='Maximum retries on timeout (default %(default)d)')
parser.add_argument('--delay', metavar='SECS', type=float, default=.3,
                    help='Delay between tests to the same server (default %(default)s)')
parser.add_argument('--read-timeout', metavar='SECS', type=float, default=1.0,
                    help='Time to wait for a server response (default %(default)s)')


async def main():
    args = parser.parse_args()

    servers = args.servers
    if servers:
        if servers == ['all']:
            servers = default_servers
        elif servers == ['help']:
            for s in default_servers:
                print(s)
            return

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
        for result in results:
            print(result)


if __name__ == '__main__':
    asyncio.run(main())
