# Traceroute

This is a simple Python script that performs a traceroute to a given host using
the Scapy library.

## Requirements

- Python 3.x
- Scapy library

## Installation

1. Clone the repository:

```
git clone https://github.com/AIM1rage/Traceroute.git
```

2. Install the required dependencies:

```
pip install scapy
```


## Usage

```
python traceroute.py [-h] [-seq SEQ] [-ttl TTL] [-c C] [-d D] [-t T] [-s S] host
```

Perform a traceroute to a specified host.

### Positional Arguments:

- `host` - The IP address or domain name to trace the route to.

### Optional Arguments:

- `-h, --help` - Show the help message and exit.
- `-seq SEQ` - Additional sequence number (default: 42).
- `-ttl TTL` - Maximum time-to-live value (default: 30).
- `-c C` - Requests count (default: 3).
- `-d D` - Delay between requests in seconds (default: 0).
- `-t T` - Request timeout in seconds (default: 1).
- `-s S` - Packet size (default: 40)

## Example

To trace the route to `habrahabr.ru` with optional arguments: ttl = 10 and t = 2 (seconds):

```
python traceroute.py habrahabr.ru -ttl 10 -t 2
```

## Testing
In order to test my code, you can run the script using the following command (Windows only!)

```
python -m unittest -v traceroute_should.TracerouteTest
```
