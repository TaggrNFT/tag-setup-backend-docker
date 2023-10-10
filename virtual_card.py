import binascii


class UIDMutex:
    def __init__(self):
        self.connected_uids = []

    def add_uid(self, uid):
        if uid in self.connected_uids:
            raise RuntimeError("A card with this UID is already connected.")

        self.connected_uids.append(uid)

    def remove_uid(self, uid):
        try:
            self.connected_uids.remove(uid)
        except ValueError:
            # ignore
            pass


class VirtualCard:
    def __init__(self, ws, queue, machineId):
        self.ws = ws
        self.queue = queue
        self.uid = None
        self.machineId = machineId

    async def recv(self):
        packet = await self.queue.get()

        if packet.get('type') == 'error':
            if packet.get('kind') == 'lost-tag':
                print('lost tag')
                raise RuntimeError('lost tag')

        assert packet.get('type') == 'response'
        data = binascii.unhexlify(packet['data'])
        print('recv', data.hex())
        return data

    async def send(self, command: bytes) -> None:
        print('send', command.hex())
        await self.ws.send_json({"type": "command", "data": command.hex()})

    async def send_raw(self, command: dict) -> None:
        print('meta', command)
        await self.ws.send_json(command)

    async def transceive(self, command: bytes) -> bytes:
        await self.send(command)
        return await self.recv()

    async def close(self):
        await self.ws.close()


globalUIDMutex = UIDMutex()
