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

| Key               | Description
| ----------------- | -------------------
| `ADMIN_AUTH_CODE` | Password that needs to be entered in the Tag Setup PC App.
| `URL`             | URL that has to be encoded on the tag. Markers containing `@` signs must be retained unmodified.
| `UPDATE_URL`      | API URL to be called after a Tag is Encoded and has a UID. `uid` and `machineId` will be sent as POST data.
| `MASTER_KEY`      | Master keys for derivation. Should be set to random 16 byte values (hex encoded).
| `TAG_HASH_KEY`    | Key for derivation of "tag hashes". Should be set to random 16 byte values (hex encoded).
| `TAG_SECRET_KEY`  | Key for derivation of "tag secrets". Should be set to random 16 byte values (hex encoded).
| `PBKDF_ROUNDS`    | Number of rounds used for key derivation.

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
    -e UPDATE_URL=http://127.0.0.1/api/newtag \
    -p 8080:8080 \
    -it nfc-setup
```


## Google Cloud Usage

Create Continuous Deployment for Container:
  - https://cloud.google.com/build/docs/securing-builds/configure-access-for-cloud-build-service-account
  - https://cloud.google.com/build/docs/automating-builds/create-manage-triggers
  - https://cloud.google.com/run/docs/quickstarts/deploy-continuously

  - Navigate to Google Cloud Run
    - https://console.cloud.google.com/run?authuser=0&hl=en&project=taggr-admin-staging

  - Create Service
    - Select "Continuously deploy new revisions from a source repository"
      - Click "Set up with cloud build"
        - Connect to Github
        - Select Repository "tag-setup-backend-docker"
        - Select a Branch "main" or "staging"
        - Build Type: Dockerfile
        - Source location: /Dockerfile
      - Click "Save"
    - Service Name: "[project-id]-tag-writer-ci"
    - Region: us-central1
    - Select "Allow unauthenticated invocations"
    - Open the "Container, Networking, Security" section
      - Under "Container" tab:
        - Add Env Vars for App
    - Click "Create"

    At this point the build will likely fail, if so:
    - Click "Edit Continuous Deployment" button at the top
    - Set Region to "us-central1"
    - Set Configuration Type to "Dockerfile"
    - Set the Dockerfile name input box explicitly to "Dockerfile"
    - Edit the Image Name to be less than 100 chars (use $SHORT_SHA at the end)
    - Uncheck the option "Send build logs to Github"
    - Clear the "Service account email" field in order to use the default Cloud Build Service Account
    - Click "Save"

  If the Service is not being updated by the Trigger:
    - Ensure the Service has the correct "Label" for the Trigger
      - Find the Trigger ID (not name)
        - Go to Cloud Build -> History
        - Find the last Build that succeeded from the Trigger
        - Click on the Build ID link
        - Open the "Execution Details" tab
        - Find the Trigger ID and copy
      - Go to Cloud Run
        - Check the checkbox beside the Service
        - on the right side of the screen a panel will open for "permissions" and "labels"
        - Click the "labels" tab
          - edit the "gcb-trigger-id" and paste the Trigger ID from above
          - edit the "gcb-trigger-region" to be "us-central1"
          - click "Save"
      The service should now auto-update to the correct container image

  - Run the Trigger to Test
