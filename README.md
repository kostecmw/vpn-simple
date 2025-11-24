# Extremely Simple VPN

**DO NOT USE IN PRODUCTION !!!**

A toy-level VPN implementation using Go, TUN interfaces, and simple routing.
Intended strictly for learning and experimentation.

---

## Prerequisites

### Client & Server

* Golang
* make
* git

---

## Setup (Client & Server)

1. Copy `.env` from the example:

```
cp .env.example .env
```

2. Edit `.env` and set:

```
CLIENT_IP=<public client IP>
SERVER_IP=<public server IP>
```

---

## Server Setup

1. **Build the server app**

```
make server
```

2. **Run initial setup (once only)**

```
sudo ./setup_server_once.sh
```

3. **Start the server service**

```
sudo ./start_server.sh
```

4. **Set up the virtual interface**

```
sudo ./setup_server.sh
```

---

## Client Setup

1. **Build the client app**

```
make client
```

2. **Start the client service**

```
sudo ./start_client.sh
```

3. **Set up the virtual interface**

```
sudo ./setup_client.sh
```

---

## Testing (Client Side)

Check tunnel reachability:

```
ping 10.0.0.1
```

Check external IP routed through VPN:

```
curl ifconfig.me
```

---

## Warning

This is **not** a secure, production-ready VPN.
It lacks proper encryption, authentication, key exchange, and security hardening.
