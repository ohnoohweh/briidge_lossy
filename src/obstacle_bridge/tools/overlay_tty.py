#!/usr/bin/env python3
#
# overlay_tty.py – raw UDP/TCP terminal with loop-safe echo
# Features:
#   • avoids infinite echo loop using message types:
#         0x01 = local keypress
#         0x02 = echo from peer (do not forward)
#   • exit sequence detection: ":q"
#
#
# Command examples
#
# UDP pair
#
# python overlay_tty.py --proto udp --role server --port 16666
#
# python overlay_tty.py --proto udp --role client --host 127.0.0.1 --connect-port 16666
#
# TCP pair
#
# python overlay_tty.py --proto tcp --role server --port 3128
#
# python overlay_tty.py --proto tcp --role client --host 127.0.0.1 --connect-port 3128
#

import argparse
import asyncio
import logging
import os
import sys

IS_WINDOWS = os.name == "nt"

# ---------------------------------------------------------
# Cross‑platform raw keyboard input (NO LOCAL ECHO)
# ---------------------------------------------------------
if IS_WINDOWS:
    import msvcrt

    async def read_keyboard():
        loop = asyncio.get_running_loop()

        def _getch():
            return msvcrt.getch()

        while True:
            ch = await loop.run_in_executor(None, _getch)
            yield ch

    def set_raw_mode():
        return None

    def restore_mode(_old):
        pass

else:
    import tty
    import termios

    async def read_keyboard():
        loop = asyncio.get_running_loop()
        reader = asyncio.StreamReader()
        proto = asyncio.StreamReaderProtocol(reader)
        await loop.connect_read_pipe(lambda: proto, sys.stdin)
        while True:
            b = await reader.read(1)
            if not b:
                break
            yield b

    def set_raw_mode():
        if sys.stdin.isatty():
            fd = sys.stdin.fileno()
            old = termios.tcgetattr(fd)
            tty.setraw(fd)
            return old
        return None

    def restore_mode(old):
        if old and sys.stdin.isatty():
            termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, old)


# ---------------------------------------------------------
# UDP protocol with safe remote echo
# ---------------------------------------------------------
class UDPProto(asyncio.DatagramProtocol):
    def __init__(self, log, role, on_recv):
        self.log = log
        self.role = role
        self.on_recv = on_recv
        self.peer = None
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport
        self.log.info("UDP transport ready")

    def datagram_received(self, data, addr):
        if self.role == "server":
            if self.peer != addr:
                self.peer = addr
                self.log.info(f"Learned peer {addr[0]}:{addr[1]}")

        if not data:
            return

        msg_type = data[0]
        payload = data[1:]

        # Always print received payload
        self.on_recv(payload)

        # Echo only if this is original user input (0x01)
        if msg_type == 0x01:
            echo = b"\x02" + payload
            if self.role == "server":
                if self.peer:
                    self.transport.sendto(echo, self.peer)
            else:
                self.transport.sendto(echo)


# ---------------------------------------------------------
# TCP reader: safe echo logic
# ---------------------------------------------------------
async def tcp_reader(reader, writer, on_recv, log):
    while True:
        data = await reader.read(4096)
        if not data:
            log.info("TCP peer closed connection")
            break

        msg_type = data[0]
        payload = data[1:]

        on_recv(payload)

        # Echo back only original user input
        if msg_type == 0x01:
            writer.write(b"\x02" + payload)
            await writer.drain()


# ---------------------------------------------------------
# Runner
# ---------------------------------------------------------
class Runner:
    def __init__(self, args, log):
        self.args = args
        self.log = log
        self.transport = None
        self.udp_proto = None

        self.tcp_writer = None
        self.tcp_reader_task = None
        self.tcp_server = None

        self.stdin_task = None
        self.term_old = None
        self.stop_evt = asyncio.Event()

    # ----------------- UDP -----------------
    async def start_udp(self):
        loop = asyncio.get_running_loop()

        def on_recv(data):
            sys.stdout.buffer.write(data)
            sys.stdout.flush()

        if self.args.role == "server":
            local_addr = (self.args.listen_bind, self.args.port)
            remote_addr = None
        else:
            local_addr = (self.args.bind, 0)
            remote_addr = (self.args.host, self.args.connect_port)

        transport, proto = await loop.create_datagram_endpoint(
            lambda: UDPProto(self.log, self.args.role, on_recv),
            local_addr=local_addr,
            remote_addr=remote_addr
        )

        self.transport = transport
        self.udp_proto = proto

    # ----------------- TCP -----------------
    async def start_tcp(self):
        def on_recv(data):
            try:
                os.write(sys.stdout.fileno(), data)
            except Exception:
                sys.stdout.buffer.write(data)
            sys.stdout.flush()

        if self.args.role == "server":
            async def handle(reader, writer):
                peer = writer.get_extra_info("peername")
                self.log.info(f"TCP client connected: {peer}")
                self.tcp_writer = writer
                self.tcp_reader_task = asyncio.create_task(
                    tcp_reader(reader, writer, on_recv, self.log)
                )

            self.tcp_server = await asyncio.start_server(
                handle, self.args.listen_bind, self.args.port
            )
            self.log.info(f"TCP server listening on {self.args.listen_bind}:{self.args.port}")

        else:
            reader, writer = await asyncio.open_connection(
                self.args.host, self.args.connect_port
            )
            self.log.info("TCP connected")
            self.tcp_writer = writer
            self.tcp_reader_task = asyncio.create_task(
                tcp_reader(reader, writer, on_recv, self.log)
            )

    # ----------------- stdin → network + exit detection -----------------
    async def pump_stdin(self):
        self.exit_buffer = bytearray()
        EXIT_SEQUENCE = b":q"

        async for key in read_keyboard():

            # ---- Exit detection ----
            self.exit_buffer += key
            if len(self.exit_buffer) > len(EXIT_SEQUENCE):
                self.exit_buffer = self.exit_buffer[-len(EXIT_SEQUENCE):]

            if self.exit_buffer == EXIT_SEQUENCE:
                os.write(sys.stdout.fileno(), b"\n[exit requested]\n")
                self.stop_evt.set()
                return
            # -----------------------

            # Original user keypress → message type 0x01
            packet = b"\x01" + key

            if self.args.proto == "udp":
                if self.args.role == "server":
                    # server sends to learned peer or to its connected remote
                    if self.udp_proto.peer:
                        self.transport.sendto(packet, self.udp_proto.peer)
                    else:
                        self.transport.sendto(packet)
                else:  # UDP client
                    # connected UDP socket -> send directly
                    if self.transport is not None:
                        self.transport.sendto(packet)
                    else:
                        self.log.warning("UDP client transport not ready; key dropped")
            else:
                if self.tcp_writer:
                    self.tcp_writer.write(packet)
                    await self.tcp_writer.drain()

    # ----------------- run/stop -----------------
    async def run(self):
        self.term_old = set_raw_mode()

        if self.args.proto == "udp":
            await self.start_udp()
        else:
            await self.start_tcp()

        self.stdin_task = asyncio.create_task(self.pump_stdin())

        try:
            await self.stop_evt.wait()
        finally:
            await self.stop()

    async def stop(self):
        if self.stdin_task:
            self.stdin_task.cancel()
            try:
                await self.stdin_task
            except:
                pass

        restore_mode(self.term_old)

        if self.args.proto == "tcp" and self.tcp_writer:
            self.tcp_writer.close()
            await self.tcp_writer.wait_closed()

        if self.args.proto == "udp" and self.transport:
            self.transport.close()


# ---------------------------------------------------------
# CLI
# ---------------------------------------------------------
def parse_args(argv=None):
    p = argparse.ArgumentParser(description="Raw UDP/TCP terminal with safe remote echo")
    p.add_argument("--proto", choices=["udp", "tcp"], default="udp")
    p.add_argument("--role", choices=["server", "client"], required=True)
    p.add_argument("--listen-bind", default="0.0.0.0")
    p.add_argument("--port", type=int, default=16666)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--connect-port", type=int, default=16666)
    p.add_argument("--bind", default="0.0.0.0")
    p.add_argument("--log", default="INFO")
    return p.parse_args(argv)

def main(argv=None):
    args = parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(message)s"
    )
    log = logging.getLogger("overlay_tty")
    runner = Runner(args, log)
    try:
        asyncio.run(runner.run())
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()