## Proposed Python module framework

The repository is now organized as a package-first Python project:

```text
src/obstacle_bridge/
  bridge.py                  # primary bridge/session implementation
  transfer.py                # transport/framing implementation
  tools/
    overlay_tty.py           # interactive UDP/TCP test terminal
    extract_udp_debug.py     # debug/pcap extraction helper
tests/
  unit/
  integration/
scripts/
  run_udp_bidir_tests.py     # async virtual transport harness
docs/
  README.md
  README_TESTING.md
```

The supported entry points now use the packaged implementation directly, with
`ObstacleBridge.py` retained as the repository-root launcher for the bridge
itself while tooling is invoked from its maintained location under `scripts/`.

I like to change the way how ChannelMux is controlled in terms of the UDP/TCP servers and clients.

As an CLI argument I like to tell the instance:
Please setup a UDP or TCP server port number z, when client APP connects to it, please instruct instance on other side to establish a UDP/TCP connection to host:port (always from a new dynamic port). 
Today only one UDP and one TCP server is provided
it should possible to setup none, one or multiple TCP servers on different ports, same for UDP

Example
Server side:
--own-servers tcp,80,0.0.0.0,tcp,127.0.0.1,88
Explanation:
Offer a tcp server listening on port 80, binding to 0.0.0.0 on TCP connection income on server, as accepted&connected on server, generate on peer a tcp client connection to 127.0.0.1:88 using an dynamic source port. Route all data bidirectionally between the accepted&connected TCP connection and the established TCP client connection on peer side.

Multiple connections
--own-servers "tcp,80,0.0.0.0,tcp,127.0.0.1,80 tcp,22,0.0.0.0,tcp,127.0.0.1,22 tcp,3128,0.0.0.0,tcp,127.0.0.1,3128 udp,16666,0.0.0.0,udp,127.0.0.1,16666"

thus ObstacleBridge.py provides tcp servers listening on port 80,22,3128 and udp server on port 16666.


Remove legacy CLI, no need for backward compatibility
--udp-role client 
--udp-target-host
--udp-target-port
--tcp-role client 
--tcp-target-host 
--tcp-target-port 

Format of app message OPEN can be changed freely to instruct peer opening corresponding client connection. No backward compatibility for app message OPEN required

Include knowledge gain we got from UDPConnection in respect to UDP transport for UDP server
        transport, protocol = await self._loop.create_datagram_endpoint(
            _factory, local_addr=listen, family=socket.AF_UNSPEC
        )
Transport needs to be peer free connected, in this transport datagram from different origins will be received, Based on known source addr, port deceided if it is a new or existing connection.
UDP Connection close/time out when with source addr,port combination for more than 20s no data was exchanged, thus eighter received or sent 

Option A, full updated ChannelMux code
please keep/include existing features as - but not limited to -
-extensive verbose logging in case of LOG debug: 
--TCP/UDP Server, listener port state  transitions
--per communication channel, traffic status as count of rx and tx bytes, CRC32 of rx bytes, CRC32 of tx bytes
-TCP backpressure feature
-restart listener ports in case they close for whatever reason
-Limited reading from UDP/TCP ports to avoid exceeding 65535bytes app messages

Certificate
----------- 
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=localhost"


I tested the new ChannelMux component#
# Bridge server
#
python ObstacleBridge.py  --bind443 0.0.0.0 --port443 443  --debug-session-udp --debug-peer-udp --log DEBUG --log-file br_server.txt
#
# Bridge client
#
python ObstacleBridge.py --bind443 0.0.0.0 --peer 127.0.0.1 --peer-port 443 --port443 0 --own-servers "udp,16667,0.0.0.0,udp,127.0.0.1,16666" --debug-session-udp --debug-peer-udp --debug-session-out-port 41000 --debug-session-in-port 41001 --debug-peer-out-port 41002 --debug-peer-in-port 41003 --log DEBUG --log-file br_client.txt
#br_server.txt attached. Please filter those elements for ChannelMux. What data went in/out on App message side, which data went out on UDP side ?
