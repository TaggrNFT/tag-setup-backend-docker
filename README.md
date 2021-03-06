# Tag Setup Backend

Server backend for "Tag Setup PC" project. Used to initialize and protect blank NFC tags.

## Installation

```
apt-get install -y python3 python3-pip
pip3 install -r requirements.txt
cp config.dist.py config.py
# TODO adjust settings in config.py
```

## Configuration

| Key           | Description               |
| ------------- | ------------------- |
| `ADMIN_AUTH_CODE` | Password that needs to be entered in the Tag Setup PC App. |
| `URL` | URL that has to be encoded on the tag. Markers containing `@` signs must be retained unmodified. |
| `MASTER_KEY` | Master keys for derivation. Should be set to random 16 byte values (hex encoded). |
| `TAG_HASH_KEY` | Key for derivation of "tag hashes". Should be set to random 16 byte values (hex encoded). |
| `TAG_SECRET_KEY` | Key for derivation of "tag secrets". Should be set to random 16 byte values (hex encoded). |
| `PBKDF_ROUNDS` | Number of rounds used for key derivation. |

## Usage

```
usage: setup_server.py [-h] [--host [HOST]] [--port [PORT]]

Tag Setup Server

optional arguments:
  -h, --help     show this help message and exit
  --host [HOST]  address to listen on
  --port [PORT]  port to listen on
```

By default, a server listening on 0.0.0.0:8080 is launched.

## Docker usage

The configuration has to be provided through environment variables.

```
sudo docker build -t nfc-setup .
sudo docker run \
    -e NFC_ADMIN_AUTH_CODE=testing \
    -e NFC_MASTER_KEY_0=d4787e885637c02c1333518846b2629e \
    -e NFC_MASTER_KEY_1=7a5037005d55e31ed9c99c45a2614f48 \
    -e NFC_MASTER_KEY_2=1c2ae7f57341a520a7d4bbf5be7a805b \
    -e NFC_MASTER_KEY_3=4fdf0fc1e1125de5b98701cf7ce98aef \
    -e NFC_MASTER_KEY_4=a1928a184d4e7393628af81803d1beac \
    -e NFC_TAG_HASH_KEY=b57bcd4a8a8499624858f2dc5b19ef02 \
    -e NFC_TAG_SECRET_KEY=c952c99d41713968dee6ca1c2a63a412 \
    -e NFC_PBKDF_ROUNDS=1000 \
    -e NFC_URL=http://10.0.0.44:5000/demo \
    -p 8080:8080 \
    -it nfc-setup
```
