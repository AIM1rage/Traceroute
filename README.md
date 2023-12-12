# Traceroute

This is a simple Python script that performs a traceroute to a given host using
the scapy and the ipwhois libraries (IPv6 supported)

## Requirements

- Python 3.x
- scapy library
- ipwhois library

## Installation

1. Clone the repository:

```
git clone https://github.com/AIM1rage/Traceroute.git
```

2. Install the required dependencies:

```
pip install -r requirements.txt
```

## Usage

```
python traceroute.py [-t] [-n] [-v] host
```

Perform a traceroute to a specified host.

### Positional Arguments:

- `host` - The IP address or domain name to trace the route to.

### Optional Arguments:

- `-h, --help` - Show the help message and exit.


- `-t` — timeout for waiting for a response (default is 2s)
- `-n` — maximum number of requests
- `-v` — output the autonomous system number for each IP address

## Example

To trace the route to public Google DNS `8.8.8.8` with optional arguments:
ttl = 10 and t = 2 (seconds):

```
python traceroute.py 8.8.8.8 -n 10 -t 0.3
```

## Testing

In order to test my code, you can run the script using the following command (
Windows only!)

```
python -m unittest -v traceroute_should.TracerouteTest
```
