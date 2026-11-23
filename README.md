# Erikslund mmproxy

**Keep the original client IP and port at a Linux backend.** This C++26 daemon accepts HAProxy
PROXY headers from trusted relays. It removes the header, then forwards TCP or UDP payloads to a
configured loopback backend using the client’s source address. It is based on
[go-mmproxy](https://github.com/path-network/go-mmproxy).

## Deploy beside your backend

Use a Linux host. The proxy and backend share the same network namespace so the backend sees the
client's IP and port. For example, configure a TCP mining backend on `127.0.0.1:3333` and expose the
proxy on the host's private relay-facing IP at port `8443`.

1. Bind the backend to loopback. In this example it listens on `127.0.0.1:3333` and receives raw
   application data after mmproxy removes the PROXY header.

   If mmproxy is the only ingress for `erikslund-solo-pool`, leave `proxy_protocol_from` unset in
   the pool configuration. The pool reads the original client address from the TCP socket.
2. Copy the relay allowlist.

   ```bash
   cp conf/allowed-subnets.example.txt conf/allowed-subnets.txt
   ```

3. Replace the example entries with each relay's source IP as the proxy sees it. Use one address
   or CIDR per line, such as `10.42.0.5/32`.
4. Add the IPv4 reply route and rule. The backend replies to the client's real IP, and this rule
   keeps that reply on loopback, where the proxy's transparent socket receives it:

   ```text
   1. relay   -> mmproxy   the PROXY header says the client is 198.51.100.7:50000
   2. mmproxy -> backend   connects from 198.51.100.7:50000 with IP_TRANSPARENT
   3. backend -> mmproxy   replies to 198.51.100.7:50000, kept on lo by the rule
   4. mmproxy -> relay     forwards the reply on the client's original stream
   ```

   Without the rule, step 3 sends the reply out of the host and the connection hangs. This example
   uses table `123` and priority `10000`; pick ones that are free on your host.

   ```bash
   sudo ip route add local 0.0.0.0/0 dev lo table 123
   ```

   ```bash
   sudo ip rule add priority 10000 from 127.0.0.0/8 iif lo lookup 123
   ```

5. For an IPv6 backend, add the IPv6 route and rule as well.

   ```bash
   sudo ip -6 route add local ::/0 dev lo table 123
   ```

   ```bash
   sudo ip -6 rule add priority 10000 from ::1/128 iif lo lookup 123
   ```

6. Persist the rules with your host's network manager. On a systemd host, the
   [routes unit](#run-under-systemd) installs them at boot.
7. Configure each relay to send a PROXY header: v1 or v2 on every TCP connection, or v2 on every
   UDP datagram.
8. Create a system account for the proxy. A process that shares the proxy's UID could join its
   listening port and take connections, so no other account or container may use it.

   ```bash
   sudo useradd --system --no-create-home --shell /usr/sbin/nologin mmproxy
   ```

9. Start the proxy as that account. `MMPROXY_LISTEN` must be an address assigned to the host. For
   UDP, also set `MMPROXY_PROTOCOL=udp`.

   ```bash
   MMPROXY_UID=$(id -u mmproxy) \
   MMPROXY_LISTEN=10.42.0.10:8443 \
   MMPROXY_BACKEND_V4=127.0.0.1:3333 \
   MMPROXY_ALLOWED_SUBNETS=./conf/allowed-subnets.txt \
   docker compose -f compose.prod.yaml up --build -d
   ```

10. Check the log for the ready line, such as
    `mmproxy 0.1.0 ready (4 workers, 65536 connections or flows)`.

    ```bash
    docker compose -f compose.prod.yaml logs proxy
    ```

**Protect the relay path.** Limit ingress to your relays at the network boundary. The IP allowlist
checks the immediate socket peer. Each trusted relay can assert a client IP and port, so use an
isolated or authenticated network path, especially with UDP.

## Run under systemd

**Use the hardened units in [`deploy/systemd/`](deploy/systemd/) on a host without Docker.** Each
listener and transport runs as its own instance, such as `erikslund-mmproxy@tcp`. A shared routes
unit installs the reply routes from [step 4](#deploy-beside-your-backend) and removes them on stop.

1. Build the binary on the host. GCC 16 is the tested compiler, as in the Docker image.

   ```bash
   cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF
   ```

   ```bash
   cmake --build build
   ```

2. Install the binary to `/usr/local/bin`. It links the C++ runtime statically, so it needs only
   the host's glibc.

   ```bash
   sudo cmake --install build
   ```

3. Install both units.

   ```bash
   sudo install -m 0644 deploy/systemd/erikslund-mmproxy@.service deploy/systemd/erikslund-mmproxy-routes.service /etc/systemd/system/
   ```

4. Install the instance settings.

   ```bash
   sudo install -D -m 0644 conf/tcp.env.example /etc/erikslund-mmproxy/tcp.env
   ```

5. Replace the example `--listen` address in `/etc/erikslund-mmproxy/tcp.env` with the host's
   relay-facing IP and port.
6. Install the relay allowlist from [step 3](#deploy-beside-your-backend).

   ```bash
   sudo install -m 0644 conf/allowed-subnets.txt /etc/erikslund-mmproxy/allowed-subnets.txt
   ```

7. Start the instance.

   ```bash
   sudo systemctl daemon-reload
   ```

   ```bash
   sudo systemctl enable --now erikslund-mmproxy@tcp
   ```

8. Check the journal for the ready line.

   ```bash
   journalctl -u erikslund-mmproxy@tcp
   ```

## Configure the proxy

Run one instance per listener and transport. An IPv6 ingress socket accepts IPv6 relay connections.
The source address carried in the header selects the backend family independently of the ingress
family. For example, an IPv4 relay can carry an IPv6 client to `[::1]:3333`.

| Option | Default | Example |
| --- | --- | --- |
| `--listen` | `127.0.0.1:8443` | `10.42.0.10:8443` or `'[::]:8443'` |
| `--backend-v4` / `--backend-v6` | At least one required | `127.0.0.1:3333` / `'[::1]:3333'` |
| `--allow` / `--allowed-subnets` | At least one relay required | `--allow 10.42.0.5/32` or `--allowed-subnets conf/allowed-subnets.txt` |
| `--protocol` | `tcp` | `--protocol udp` |
| `--workers` | Usable CPUs, up to 8, for TCP; 1 for UDP | `--workers 4` |
| `--max-connections` | 65536 across workers | `--max-connections 20000` |
| `--header-timeout-ms` | 2000 | `--header-timeout-ms 1000` |
| `--connect-timeout-ms` | 3000 | `--connect-timeout-ms 1500` |
| `--idle-timeout-ms` | 300000 for TCP | `--idle-timeout-ms 0` disables idle expiry |
| `--udp-timeout-ms` | 60000 | `--udp-timeout-ms 15000` |
| `--user-timeout-ms` | Off | `--user-timeout-ms 120000` drops a relay that stops acknowledging data after 2 minutes. |
| `--mark` | 0, kernel default | `--mark 42` sets the backend socket mark |
| `--max-header-bytes` | 4096 | `--max-header-bytes 16384` for a relay that sends large TLVs |
| `--allow-local-relays` | Off | Needed when the allowlist covers this host, such as `127.0.0.1` for a relay on the same machine |
| `--allow-any-relay` | Off | Needed for a `0.0.0.0/0` or `::/0` entry, which lets every host claim client addresses |
