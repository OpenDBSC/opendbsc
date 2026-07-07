# opendbsc

A **Device Bound Session Credentials (DBSC)** library and example server

## Features

- DBSC session creation / registration / refresh protocol
- ES256, RS256 JWT proof signature verification (OpenSSL)
- Session stores: memory, SQLite, Redis
- mongoose-based HTTPS server wrapper
- Doxygen documentation support

## Dependencies

### System packages

The following packages must be installed before building.

```bash
# Debian/Ubuntu
sudo apt update
sudo apt install build-essential cmake pkg-config libssl-dev libsqlite3-dev

# RHEL/CentOS/Fedora
sudo dnf install gcc cmake pkgconfig openssl-devel sqlite-devel
```

### Vendored libraries

Cloned directly into `libs/`.

```bash
mkdir -p libs
git clone https://github.com/redis/hiredis.git libs/hiredis
git clone https://github.com/cesanta/mongoose.git libs/mongoose
```

### CMake FetchContent

Fetched automatically at build time.

- [cJSON](https://github.com/DaveGamble/cJSON)
- [uuidv7-h](https://github.com/LiosK/uuidv7-h)

## Build

```bash
cd opendbsc
cmake -B build
cmake --build build -j4
```

Build outputs:

- `build/libopendbsc.a`: static library
- `build/server`: example HTTPS server

## TLS certificates

The example server requires a TLS certificate and private key at `cert/cert.pem` and `cert/key.pem` relative to the working directory. **Do not commit certificates to git.** Generate them locally:

### Option 1: OpenSSL (self-signed, quick test only)

```bash
mkdir -p cert
openssl req -x509 -newkey rsa:2048 -keyout cert/key.pem -out cert/cert.pem -sha256 -days 7 -nodes -subj "/CN=localhost"
```

### Option 2: mkcert (recommended for local development)

```bash
# Install mkcert first, then:
mkdir -p cert
mkcert -cert-file cert/cert.pem -key-file cert/key.pem localhost 127.0.0.1 ::1
```

## Running the example server

```bash
# Memory backend
./build/server memory

# SQLite backend
./build/server sqlite

# Redis backend (requires redis-server)
./build/server redis
```

The default address is `https://0.0.0.0:8447`.

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET`  | `/` | Static page (`examples/static/index.html`) |
| `POST` | `/login` | Form-based login (`username`, `password`) |
| `POST` | `/dbsc/register` | DBSC registration (`Secure-Session-Response`) |
| `POST` | `/dbsc/refresh` | DBSC refresh (`Sec-Secure-Session-Id`, `Secure-Session-Response`) |
| `GET`  | `/api/status` | Server status |
| `GET`  | `/api/me` | Current session info |
| `GET`  | `/api/events` | Event log |

## Project structure

```
opendbsc/
├── include/          # Public headers
├── src/
│   ├── algo/         # UUID/challenge utilities
│   ├── protocol/     # header, instruction, jwt
│   ├── session/      # Session model
│   ├── store/        # memory/sqlite/redis store
│   ├── manager/      # DBSC manager
│   └── wrapper/      # mongoose HTTP wrapper
├── examples/         # Example server and static files
├── libs/             # Vendored dependencies (hiredis, mongoose)
├── cert/             # TLS certificates (generated locally, gitignore)
├── build/            # Build output (gitignore)
└── CMakeLists.txt
```

## Documentation

If Doxygen is installed:

```bash
doxygen Doxyfile
```

Generated documentation can be viewed at `docs/html/index.html`.

## License

This project is distributed under the MIT License. See [LICENSE](LICENSE) for details. Vendored third-party libraries retain their own licenses.
