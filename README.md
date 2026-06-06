# Relay

Relay is a Windows-only local HTTP server that syncs clipboard text, images, and small/medium files between a Windows PC and Apple Shortcuts clients on iPhone or macOS.

The Windows PC is always the Relay server. iPhone and macOS devices are clients only.

## Navigation

* [Requirements](#requirements)
* [Quick Setup](#quick-setup)
* [Apple Shortcuts](#apple-shortcuts)
* [API Contract](#api-contract)
* [Security Notes](#security-notes)
* [File Size Limits](#file-size-limits)
* [Configuration](#configuration)
* [Developer Notes](#developer-notes)

## Requirements

* Windows 10 or later
* Node.js 18 or later
* .NET Framework 4.x compiler (`csc.exe`), normally included with Windows/.NET Framework
* iPhone or macOS device on the same local network

## Quick Setup

1. Install dependencies:

   ```powershell
   npm install
   ```

2. Run setup:

   ```powershell
   npm run setup
   ```

3. Copy one server URL from the setup output. Use it without a trailing slash, for example:

   ```text
   http://192.168.1.25:3080
   ```

4. Copy the generated Bearer Token into your Apple Shortcut.

5. Start Relay:

   ```powershell
   npm start
   ```

You can also double-click `Start Relay.vbs`. It opens a visible command window, runs `setup.js` first if `.env` is missing, then starts Relay. Stop the server with `CTRL+C` or by closing the command window.

## Apple Shortcuts

Install the shortcuts on your iPhone or macOS device:

* [Relay Send](https://www.icloud.com/shortcuts/01152728aafd4f4f80110de0db7161c3)
* [Relay Get](https://www.icloud.com/shortcuts/efbdb3c2c59a4e7a9d53a07744cf00f5)

Configure each Shortcut with:

* Server URL: `http://YOUR_PC_IP:3080`
* Bearer Token: `Bearer YOUR_TOKEN_HERE`
* No trailing slash on the Server URL
* Same local network as the Windows PC

Try the `.local` URL from setup first. If it does not work, use the IP address. A wrong IP address can make Shortcuts wait until the request times out.

## API Contract

All endpoints require:

```http
Authorization: Bearer YOUR_TOKEN_HERE
```

### `GET /status`

Returns:

```json
{ "ok": true, "server": "relay", "ip": "192.168.1.50" }
```

### `GET /relay`

Returns one of:

```json
{ "type": "empty" }
{ "type": "text", "data": "hello" }
{ "type": "image", "mimeType": "image/png", "data": "BASE64_PNG" }
{ "type": "file", "name": "example.pdf", "data": "BASE64_FILE" }
```

### `POST /relay`

Accepts:

```json
{ "type": "text", "data": "hello" }
{ "type": "image", "data": "BASE64_PNG" }
```

Text data may be empty; that clears the Windows clipboard.

### `POST /file`

Accepts:

```json
{ "name": "example.pdf", "data": "BASE64_FILE" }
```

Saves the file into the Windows user's `Downloads\Relay` folder.

### `GET /file`

Reads an existing file from an allowed Windows path:

```text
GET /file?path=C:\Users\YourName\Documents\example.pdf
```

By default, files are limited to the user's home directory. Configure `ALLOWED_FILE_ROOTS` in `.env` to allow more roots.

### `GET /files`

Lists the 50 most recent files saved by `POST /file`.

Errors are JSON responses with an `error` field.

## Security Notes

Relay uses HTTP on your local network. Do not expose it to the internet, do not port-forward it, and do not run it on public Wi-Fi unless you understand the risk.

Relay checks:

* Bearer JWT token authentication
* LAN/loopback IP filtering
* Rate limiting
* Request body size limits
* Path traversal protection for `GET /file`
* Real path checks to block symlink/junction escapes
* Filename sanitization for uploaded files

If `ALLOWED_SUBNET` is empty, private LAN IPs and loopback are allowed. If `ALLOWED_SUBNET` is set, only addresses with that prefix and loopback are allowed.

Never commit `.env`, `relay-token.txt`, `node_modules`, `certs`, logs, or generated files. If a token or secret is ever published, run:

```powershell
npm run reset
```

Then update your Shortcuts with the new Bearer Token.

## File Size Limits

Relay currently transfers images and files as base64 inside JSON. This is simple and works well for text, screenshots, images, and small/medium files, but very large files are not recommended.

Defaults:

* JSON body limit: 50 MB
* Text body limit: 200 MB
* Clipboard copied file limit: 100 MB (`CLIPBOARD_MAX_FILE_MB`)
* Clipboard helper output buffer: 220 MB (`HELPER_MAX_BUFFER_MB`)

Base64 adds about 33 percent overhead, so realistic file sizes are lower than the raw request limits.

## Configuration

Local configuration is written to `.env` by `npm run setup`.

Important values:

* `PORT=3080`
* `JWT_SECRET=...`
* `ALLOWED_SUBNET=`
* `JWT_MAX_AGE=`
* `RATE_LIMIT_MAX=60`
* `RATE_LIMIT_WINDOW_MS=60000`
* `HELPER_MAX_BUFFER_MB=220`
* `CLIPBOARD_MAX_FILE_MB=100`
* `ALLOWED_FILE_ROOTS=`

Leave `ALLOWED_SUBNET` empty for normal home LAN use. Set it only if you need a stricter prefix such as `192.168.1.`.

## Developer Notes

Useful commands:

```powershell
npm run setup
npm start
npm run reset
```

The C# clipboard helper is generated and compiled into the system temp directory. It is rebuilt when the embedded source or helper version changes.
