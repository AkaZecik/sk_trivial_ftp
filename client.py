#!/usr/bin/env python3

import argparse
import hashlib
import logging
import socket
import sys

error_types = {
    0: b'Not defined',
    1: b'File not found',
    2: b'Access violation',
    3: b'Disk full or allocation exceeded',
    4: b'Illegal TFTP operation',
    5: b'Unknown transfer ID',
    6: b'File already exists',
    7: b'No such user'
}


def print_sock_info(sock):
    logging.debug('local socket port: {}'.format(sock.getsockname()))


def send_rrq(sock, host_name, filename, options):
    logging.debug("Sending RRQ to {}".format(host_name))
    packet = b'\x00\x01' + bytes(filename, 'ascii') + b'\x00octet\x00'

    for option, value in options.items():
        logging.debug("Option {} := {}".format(option, value))
        packet += bytes(option, 'ascii') + b'\x00' + bytes(value, 'ascii') + b'\x00'

    sock.sendto(packet, (host_name, 69))
    return packet, (host_name, 69)


def split_oack(packet):
    opcode = int.from_bytes(packet[0:2], 'big')
    options = dict()
    opt_pos = 2
    opt = None

    for i in range(opt_pos, len(packet)):
        if packet[i] == 0:
            text = packet[opt_pos:i].decode('ascii')

            if opt is None:
                opt = text
            else:
                options[opt] = text
                opt = None

            opt_pos = i + 1

    return opcode, options


def send_error(sock, host_addr, err_code, msg):
    logging.debug("Sending error of type '{}' and message '{}' to {}".format(err_code, msg, host_addr))
    packet = b'\x00\x05' + int.to_bytes(err_code, 2, 'big') + (
        error_types[err_code] if msg is None else bytes(msg, 'ascii')) + b'\x00'
    sock.sendto(packet, host_addr)
    return packet, host_addr


def send_ack(sock, host_addr, block):
    logging.debug("Sending ACK {}".format(block))
    packet = b'\x00\x04' + int.to_bytes(block, 2, 'big')
    sock.sendto(packet, host_addr)
    return packet, host_addr


def resend_packet(sock, packet_data):
    logging.debug("Resending packet {}".format(packet_data))
    sock.sendto(packet_data[0], packet_data[1])


def print_error(packet):
    error_code = int.from_bytes(packet[2:4], 'big')
    error_message = packet[4:-1].decode('ascii')
    logging.debug(error_types[error_code] if error_message == '' else error_message)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='TFTP client file reader')
    parser.add_argument('server', type=str, help='name of the server')
    parser.add_argument('filename', type=str, help='name of the file to download')
    parser.add_argument('--blocksize', type=int, help='size of one block of data', default=512)
    parser.add_argument('--windowsize', type=int, help='window size', default=1)
    parser.add_argument('--timeout', type=float, help='timeout in seconds', default=1.0)
    parser.add_argument('--retries', type=int, help='number of retries', default=10)
    parser.add_argument('--debug', action='store_true', default=False, help='show debug info')
    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.CRITICAL)

    server_name = args.server
    server_port = None
    block_size = 512
    window_start = 1
    window_size = 1
    blocks = [None] * window_size
    hasher = hashlib.md5()

    options = {
        'blksize': str(args.blocksize),
        'windowsize': str(args.windowsize),
        'timeout': str(args.timeout),
        'retries': str(args.retries)
    }

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.0)
    last_packet = send_rrq(sock, args.server, args.filename, options)
    expected_end = -1
    retries = 10
    try_counter = 0

    while window_start != expected_end and retries >= try_counter:
        try:
            (packet, (host_name, host_port)) = sock.recvfrom(max(512, 4 + block_size))
            logging.debug("Received packet from {}".format((host_name, host_port)))

            if server_port is None:
                server_port = host_port
                logging.debug("Server port set to {}".format(server_port))

            if host_port != server_port:
                send_error(sock, (host_name, host_port), 0, "I'm not talking to you!")
            else:
                opcode = int.from_bytes(packet[0:2], 'big')
                logging.debug("opcode: {}".format(opcode))

                if opcode == 5:
                    print_error(packet)
                    sys.exit(1)
                elif opcode == 3:
                    block = int.from_bytes(packet[2:4], 'big')
                    data = packet[4:]
                    logging.debug("block: {}".format(block))
                    logging.debug("data: {}".format(data))
                    logging.debug("window_start: {}".format(window_start))
                    logging.debug("blocks: {}".format(blocks))

                    if window_start <= block < window_start + window_size:
                        id = block - window_start

                        if blocks[id] is None:
                            blocks[id] = data
                            logging.debug("blocks[{}] = data".format(id))
                            try_counter = 0

                            if blocks.count(None) != 0:
                                continue
                    elif window_start <= block + 65536 < window_start + window_size:
                        id = block + 65536 - window_start

                        if blocks[id] is None:
                            blocks[id] = data
                            logging.debug("blocks[{}] = data".format(id))
                            try_counter = 0

                            if blocks.count(None) != 0:
                                continue

                    logging.debug("blocks: {}".format(blocks))
                    logging.debug("blocks.count(None): {}".format(blocks.count(None)))
                elif opcode == 6 and window_start == 1:
                    _, options = split_oack(packet)
                    logging.debug("Got OACK with options {}".format(options))

                    if 'blksize' in options:
                        block_size = int(options['blksize'])

                    if 'windowsize' in options:
                        window_size = int(options['windowsize'])
                        blocks = [None] * window_size

                    if 'timeout' in options:
                        sock.settimeout(float(options['timeout']))

                    if 'retries' in options:
                        retries = int(options['retries'])

                    last_packet = send_ack(sock, (server_name, server_port), 0)
                    continue
        except socket.timeout:
            try_counter += 1

        counter = 0

        for part in blocks:
            if part is not None:
                hasher.update(part)
                counter += 1

                if len(part) < block_size:
                    expected_end = (window_start + counter) % 65536
                    break
            else:
                break

        blocks = [None] * window_size

        if counter == 0:
            resend_packet(sock, last_packet)
        else:
            last_packet = send_ack(sock, (server_name, server_port), (window_start + counter - 1) % 65536)
            window_start = (window_start + counter) % 65536

    print(hasher.hexdigest())
