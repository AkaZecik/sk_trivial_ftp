#!/usr/bin/env python3

import argparse
import logging
import socket
import random

ADDR = 'localhost'  # json.load(urllib.request.urlopen('https://api.ipify.org/?format=json'))['ip']

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


def split_rrq(packet):
    opcode = int.from_bytes(packet[0:2], 'big')
    filename = None
    mode = None
    opt_pos = None

    for i in range(2, len(packet)):
        if packet[i] == 0:
            filename = packet[2:i].decode('ascii')
            opt_pos = i + 1
            break

    for i in range(opt_pos, len(packet)):
        if packet[i] == 0:
            mode = packet[2:i].decode('ascii')
            opt_pos = i + 1
            break

    options = dict()
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

    logging.debug("RRQ packet: [{}][{}][{}]".format(opcode, filename, options))
    return opcode, filename, mode, options


def send_oack(sock, client_addr, options):
    packet = b'\x00\x06'

    for option, value in options.items():
        packet += bytes(option, 'ascii') + b'\x00' + bytes(value, 'ascii') + b'\x00'

    sock.sendto(packet, client_addr)
    return packet, client_addr


def send_data(sock, client_addr, block, data):
    logging.debug("Sending data {} as block {} to {}".format(data, block, client_addr))
    packet = b'\x00\x03' + int.to_bytes(block, 2, 'big') + data
    sock.sendto(packet, client_addr)
    return packet, client_addr


def send_error(sock, host_addr, err_type, msg):
    logging.debug("Sending error of type '{}' and message '{}' to {}".format(err_type, msg, host_addr))
    packet = b'\x00\x05' + int.to_bytes(err_type, 2, 'big') + (
        error_types[err_type] if msg is None else bytes(msg, 'ascii')) + b'\x00'
    sock.sendto(packet, host_addr)
    return packet, host_addr


def resend_packet(sock, packet_data):
    logging.debug("Resending packet {}".format(packet_data))
    sock.sendto(packet_data[0], packet_data[1])


def print_sock_info(sock):
    logging.debug('local socket port: {}'.format(sock.getsockname()))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='TFTP client file reader')
    parser.add_argument('port', type=int, help='port number to listen at')
    parser.add_argument('directory', type=str, help='directory to serve files from')
    parser.add_argument('--debug', action='store_true', default=False, help='show debug info')
    parser.add_argument('--noise', action='store_true', default=False, help='simulate noisy transmission')
    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.CRITICAL)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((ADDR, args.port))
    print_sock_info(server_socket)
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_socket.settimeout(1.0)

    while True:
        (packet, client_addr) = server_socket.recvfrom(512)
        logging.debug("Received packet: {}".format(packet))
        opcode = int.from_bytes(packet[0:2], 'big')
        retries = 10

        if opcode == 1:
            (opcode, filename, mode, options) = split_rrq(packet)
            resp_options = dict()
            block_size = 512
            window_start = 1
            window_size = 1
            last_pos = 0
            expected_end = -1

            if 'blksize' in options:
                resp_options['blksize'] = options['blksize']
                block_size = int(options['blksize'])

            if 'windowsize' in options:
                resp_options['windowsize'] = options['windowsize']
                window_size = int(options['windowsize'])

            if 'timeout' in options:
                resp_options['timeout'] = options['timeout']
                client_socket.settimeout(float(options['timeout']))

            if 'retries' in options:
                resp_options['retries'] = options['retries']
                retries = int(options['retries'])

            while len(resp_options) > 0:
                send_oack(client_socket, client_addr, resp_options)

                try:
                    packet = client_socket.recv(4)
                    opcode = int.from_bytes(packet[0:2], 'big')
                    logging.debug("Packet received after OACK: {}".format(packet))
                    logging.debug("Opcode: {}".format(opcode))

                    if opcode == 4:
                        block = int.from_bytes(packet[2:4], 'big')
                        logging.debug("Block: {}".format(block))

                        if block == 0:
                            break
                    elif opcode == 5:
                        sending = False
                        break
                except socket.timeout:
                    continue

            logging.debug("Starting with blksize: {}".format(block_size))
            logging.debug("Starting with windowsize: {}".format(window_size))

            try_counter = 0

            try:
                with open(args.directory + '/' + filename, 'rb') as file:
                    while window_start != expected_end and retries >= try_counter:
                        file.seek(last_pos)
                        logging.debug("Seek position is {}".format(last_pos))
                        logging.debug("Window start is {}".format(window_start))

                        for i in range(window_size):
                            data = file.read(block_size)

                            if not args.noise or random.uniform(0, 1) < 0.9:
                                send_data(client_socket, client_addr, (window_start + i) % 65536, data)

                            if len(data) < block_size:
                                expected_end = (window_start + i + 1) % 65536
                                logging.debug("Reading last block, expected_end is {}".format(expected_end))
                                break

                        try:
                            while True:
                                packet = client_socket.recv(4)
                                opcode = int.from_bytes(packet[0:2], 'big')
                                logging.debug("Received packet {}".format(packet))

                                if opcode == 4:
                                    block = int.from_bytes(packet[2:4], 'big')

                                    if window_start <= block < window_start + window_size:
                                        increment = (block - window_start + 1)
                                        last_pos += increment * block_size
                                        window_start = (window_start + increment) % 65536
                                        try_counter = 0
                                        break
                                    elif window_start <= block + 65536 < window_start + window_size:
                                        increment = (block + 65536 - window_start + 1)
                                        last_pos += increment * block_size
                                        window_start = (window_start + increment) % 65536
                                        try_counter = 0
                                        break
                                elif opcode == 5:
                                    break
                        except socket.timeout:
                            try_counter += 1
            except IOError:
                send_error(client_socket, client_addr, 1, None)

            logging.debug("Finished\n")
