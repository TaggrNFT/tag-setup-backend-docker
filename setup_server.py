import argparse
import asyncio
import binascii
import json
import struct
import traceback

import aiohttp
from Crypto.Util import strxor

from aiohttp import web
from asyncio import Queue

from ntag.build_sun import create_ndef
from config import URL, ADMIN_AUTH_CODE
from ntag.ev2 import AuthenticateEV2, CommMode, CryptoComm
from derive import derive_tag_key, calculate_tag_hash, calculate_tag_secret, wrap_uid

from ntag.mf_crc32 import mf_crc32
from virtual_card import VirtualCard, globalUIDMutex
from validate_ecc import validate_ntag424


def require(condition) -> None:
    if not condition:
        raise RuntimeError("Condition failed")


async def get_file_comm_mode(vc: VirtualCard, comm: CryptoComm, file_no: bytes):
    resp = await vc.transceive(comm.wrap_cmd(0xF5, CommMode.MAC, file_no))
    status, res = comm.unwrap_res(resp, CommMode.MAC)
    require(status == b"\x91\x00")
    val = res[1] & 3

    if val == 0:
        return CommMode.PLAIN
    elif val == 2:
        return CommMode.MAC
    elif val == 3:
        return CommMode.FULL

    raise RuntimeError("Unknown communication mode")


async def get_key_version(vc: VirtualCard, key_no: bytes):
    comm = CryptoComm(b"\x00" * 16)
    resp = await vc.transceive(comm.wrap_cmd(0x64, CommMode.PLAIN, key_no))
    status, res = comm.unwrap_res(resp, CommMode.PLAIN)
    require(status == b"\x91\x00")
    return res


async def auth_change_key(vc: VirtualCard, comm: CryptoComm, key_value: bytes, key_no: int):
    resp = await vc.transceive(comm.wrap_cmd(0x64, CommMode.MAC, bytes([key_no])))
    status, key_v = comm.unwrap_res(resp, CommMode.MAC)
    require(status == b"\x91\x00")

    if key_v == b"\x00":
        old_key = b"\x00" * 16
        new_key = key_value
        payload = strxor.strxor(old_key, new_key) + b"\x01" + struct.pack("<I", mf_crc32(new_key))
        resp = await vc.transceive(comm.wrap_cmd(0xC4, CommMode.FULL, bytes([key_no]), payload))
        require(comm.unwrap_res(resp, CommMode.PLAIN)[0] == b"\x91\x00")


async def init_isodep_tech(vc: VirtualCard) -> bytes:
    comm = CryptoComm(b"\x00" * 16)

    # select NDEF application
    resp = await vc.transceive(b"\x00\xA4\x04\x00\x07\xD2\x76\x00\x00\x85\x01\x01\x00")
    require(resp == b"\x90\x00")

    # get tag version
    resp = await vc.transceive(comm.wrap_cmd(0x60, CommMode.PLAIN))
    status, res = comm.unwrap_res(resp, CommMode.PLAIN)
    require(status == b"\x91\xAF")

    # for non-TT tag:
    if res == b"\x04\x04\x02\x30\x00\x11\x05":
        supports_tt = False
    elif res == b"\x04\x04\x08\x30\x00\x11\x05":
        supports_tt = True
    else:
        raise RuntimeError("Unsupported type of the tag.")

    resp = await vc.transceive(comm.wrap_cmd(0xAF, CommMode.PLAIN))
    status, res = comm.unwrap_res(resp, CommMode.PLAIN)
    require(status == b"\x91\xAF")
    require(res == b"\x04\x04\x02\x01\x02\x11\x05")

    resp = await vc.transceive(comm.wrap_cmd(0xAF, CommMode.PLAIN))
    status, res = comm.unwrap_res(resp, CommMode.PLAIN)
    require(status == b"\x91\x00")

    master_key_v = await get_key_version(vc, b"\x00")

    if len(vc.uid) == 7:
        # the tag is not initialized yet, perform originality check
        resp = await vc.transceive(comm.wrap_cmd(0x3C, CommMode.PLAIN, b"", b"\x00"))
        status, res = comm.unwrap_res(resp, CommMode.PLAIN)

        require(status == b"\x91\x90")
        require(validate_ntag424(vc.uid, res))

        tag_hash = calculate_tag_hash(vc.uid)
    elif len(vc.uid) == 4:
        # the tag is already initialized and has random UID enabled,
        # skip originality check

        # the tag must already have keys changed
        require(master_key_v == b"\x01")

        # read tag_hash out of the URL encoded in NDEF
        resp = await vc.transceive(comm.wrap_cmd(0xAD, CommMode.PLAIN, b"\x02", b"\x00\x00\x00\xFF\x00\x00"))
        status, res = comm.unwrap_res(resp, CommMode.PLAIN)
        enc_offset = res.find(b"enc=")

        try:
            tag_hash = binascii.unhexlify(res[enc_offset + 4:enc_offset + 4 + 32])
        except binascii.Error:
            raise RuntimeError("Failed to fetch tag_hash from encoded URL")

        require(len(tag_hash) == 16)
    else:
        raise RuntimeError("Unsupported UID length.")

    master_key_v = await get_key_version(vc, b"\x00")

    if master_key_v == b"\x00":
        auth = AuthenticateEV2(b"\x00" * 16)
        resp = await vc.transceive(auth.get_init_packet(b"\x00"))
        resp = await vc.transceive(auth.part1(resp))
        comm = auth.part2(resp)

        # change master key
        resp = await vc.transceive(
            comm.wrap_cmd(0xC4, CommMode.FULL, b"\x00", derive_tag_key(tag_hash, 0) + b"\x01"))
        require(comm.unwrap_res(resp, CommMode.PLAIN)[0] == b"\x91\x00")

    auth = AuthenticateEV2(derive_tag_key(tag_hash, 0))
    resp = await vc.transceive(auth.get_init_packet(b"\x00"))
    resp = await vc.transceive(auth.part1(resp))
    comm = auth.part2(resp)

    for key_no in range(1, 5):
        await auth_change_key(vc, comm, derive_tag_key(tag_hash, key_no), key_no)

    resp = await vc.transceive(comm.wrap_cmd(0x51, CommMode.FULL))
    status, res = comm.unwrap_res(resp, CommMode.FULL)
    real_uid = res[0:7]

    encoded_ndef, encoded_file_access = create_ndef(URL, tag_hash.hex().upper().encode('ascii'), calculate_tag_secret(tag_hash), with_tt=supports_tt)

    resp = await vc.transceive(comm.wrap_cmd(0x5F, CommMode.FULL, b"\x01", b"\x03\x00\xE0"))
    require(comm.unwrap_res(resp, CommMode.MAC)[0] == b"\x91\x00")

    # ensure SDM disabled to reset read counter to 0
    resp = await vc.transceive(comm.wrap_cmd(0x5F, CommMode.FULL, b"\x02", b"\x03\x00\xE0"))
    require(comm.unwrap_res(resp, CommMode.MAC)[0] == b"\x91\x00")

    # enable SDM
    file_2_access = encoded_file_access
    resp = await vc.transceive(comm.wrap_cmd(0x5F, CommMode.FULL, b"\x02", file_2_access))
    require(comm.unwrap_res(resp, CommMode.MAC)[0] == b"\x91\x00")

    resp = await vc.transceive(comm.wrap_cmd(0x5F, CommMode.FULL, b"\x03", b"\x03\x00\x00"))
    require(comm.unwrap_res(resp, CommMode.MAC)[0] == b"\x91\x00")

    ndef_file_contents = encoded_ndef
    resp = await vc.transceive(
        comm.wrap_cmd(0x8D, CommMode.FULL, b"\x02\x00\x00\x00" + bytes([len(ndef_file_contents)]) + b"\x00\x00",
                      ndef_file_contents))
    require(comm.unwrap_res(resp, CommMode.MAC)[0] == b"\x91\x00")

    # enable random UID
    resp = await vc.transceive(comm.wrap_cmd(0x5C, CommMode.FULL, b"\x00", b"\x02"))
    require(comm.unwrap_res(resp, CommMode.PLAIN)[0] == b"\x91\x00")

    if supports_tt:
        resp = await vc.transceive(comm.wrap_cmd(0x5C, CommMode.FULL, b"\x07", b"\x01\x00"))
        require(comm.unwrap_res(resp, CommMode.PLAIN)[0] == b"\x91\x00")

    return real_uid


async def packet_consumer(vc: VirtualCard) -> None:
    try:
        packet = await vc.queue.get()
        require(packet.get('type') == 'operation')
        require(packet.get('operation') == 'setup')
        require(packet.get('uid'))
        require(packet.get('authCode') == ADMIN_AUTH_CODE)

        cardUID = binascii.unhexlify(packet.get('uid'))
        vc.uid = cardUID
        globalUIDMutex.add_uid(vc.uid)

        print('tech', packet.get('uid'), packet.get('tech'))

        if packet.get('tech') == 'IsoDep':
            real_uid = await init_isodep_tech(vc)
        else:
            raise RuntimeError("Unsupported tag technology.")

        await vc.ws.send_json({"type": "modal", "message": "Done."})
    except Exception as e:
        traceback.print_exc()
        await vc.ws.send_json({"type": "modal", "message": "Error occurred, check server logs for details."})

    print("done")
    globalUIDMutex.remove_uid(vc.uid)
    await vc.close()


async def websocket_handler(request):
    print('connected')
    ws = web.WebSocketResponse()
    await ws.prepare(request)

    queue = Queue()
    vc = VirtualCard(ws, queue)
    packet_processor = asyncio.ensure_future(packet_consumer(vc))

    async for msg in ws:
        if msg.type == aiohttp.WSMsgType.TEXT:
            packet_raw = msg.data
            packet = json.loads(packet_raw)
            await queue.put(packet)
        elif msg.type == aiohttp.WSMsgType.ERROR:
            print('ws connection closed with exception %s' %
                  ws.exception())

    packet_processor.cancel()
    print('websocket connection closed')

    return ws


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Tag Setup Server')
    parser.add_argument('--host', type=str, nargs='?',
                        help='address to listen on')
    parser.add_argument('--port', type=int, nargs='?',
                        help='port to listen on')

    args = parser.parse_args()

    app = web.Application()
    app.add_routes([web.get('/setup', websocket_handler)])
    web.run_app(app, host=args.host, port=args.port)
