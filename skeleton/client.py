"""
Client entrypoint.

!!! DO NOT MODIFY THIS FILE !!!

"""

import argparse
import sys

import requests

from your_code import Client

#
# Network communications
#


SERVER_HOSTNAME = "cs523-server"
TOR_PROXY = "socks5h://localhost:9050"
TOR_HOSTNAME_FILENAME = "/client/tor/hidden_service/hostname"


class SimpleHTTPError(Exception):
    """An unexpected HTTP status was received."""


#
# Parser
#


def main(args):
    """Parse the arguments given to the client, and call the appropriate method."""

    parser = argparse.ArgumentParser(description="Client for CS-523 project.")
    subparsers = parser.add_subparsers(help="Command")

    parser_get_pk = subparsers.add_parser(
        "get-pk", help="Retrieve the public key from the server."
    )
    parser_get_pk.add_argument(
        "-o",
        "--out",
        help="Name of the file in which to write the public key.",
        type=argparse.FileType("wb"),
        default=sys.stdout,
    )
    parser_get_pk.add_argument(
        "-t",
        "--tor",
        help="Use Tor to connect to the server.",
        action="store_const",
        const=True,
        default=False,
    )
    parser_get_pk.set_defaults(callback=client_get_pk)

    parser_register = subparsers.add_parser(
        "register", help="Register the client to the server."
    )
    parser_register.add_argument(
        "-p",
        "--pub",
        help="Name of the file from which to read the public key.",
        type=argparse.FileType("rb"),
        default=sys.stdin,
    )
    parser_register.add_argument(
        "-o",
        "--out",
        help="Name of the file in which to write the attribute-based credential.",
        type=argparse.FileType("wb"),
        default=sys.stdout,
    )
    parser_register.add_argument(
        "-a",
        "--attributes",
        help="String representing the attributes.",
        type=str,
        required=True,
    )
    parser_register.add_argument(
        "-t",
        "--tor",
        help="Use Tor to connect to the server.",
        action="store_const",
        const=True,
        default=False,
    )
    parser_register.add_argument(
        "-u", "--user", help="User name.", type=str, required=True
    )

    parser_register.set_defaults(callback=client_register)

    parser_loc = subparsers.add_parser("loc", help="Part 1 of the CS-523 exercise.")
    parser_loc.add_argument(
        "-p",
        "--pub",
        help="Name of the file from which to read the public key.",
        type=argparse.FileType("rb"),
        required=True,
    )
    parser_loc.add_argument(
        "-c",
        "--cred",
        help="Name of the file from which to read the attribute-based credential.",
        type=argparse.FileType("rb"),
        required=True,
    )
    parser_loc.add_argument(
        "-r",
        "--reveal",
        help="Attributes to reveal. (format: attr1,attr2,attr3).",
        type=str,
        required=True,
    )
    parser_loc.add_argument(
        "-t",
        "--tor",
        help="Use Tor to connect to the server.",
        action="store_const",
        const=True,
        default=False,
    )
    parser_loc.add_argument("lat", help="Latitude.", type=float)
    parser_loc.add_argument("lon", help="Longitude.", type=float)
    parser_loc.set_defaults(callback=client_loc)

    parser_grid = subparsers.add_parser("grid", help="Part 3 of the CS-523 exercise.")
    parser_grid.add_argument(
        "-p",
        "--pub",
        help="Name of the file from which to read the public key.",
        type=argparse.FileType("rb"),
        required=True,
    )
    parser_grid.add_argument(
        "-c",
        "--cred",
        help="Name of the file from which to read the attribute-based credential.",
        type=argparse.FileType("rb"),
        required=True,
    )
    parser_grid.add_argument(
        "-r", "--reveal", help="Attributes to reveal.", type=str, required=True
    )
    parser_grid.add_argument(
        "-t",
        "--tor",
        help="Use Tor to connect to the server.",
        action="store_const",
        const=True,
        default=False,
    )
    parser_grid.add_argument("cell_id", help="Cell identifier.", type=int)
    parser_grid.set_defaults(callback=client_grid)

    namespace = parser.parse_args(args)

    if "callback" in namespace:
        namespace.callback(namespace)

    else:
        parser.print_help()


def read_hostname(hostname_filename):
    """Retrieve an hostname from a file."""

    with open(hostname_filename, "r") as hostname_file:
        hostname = hostname_file.read().strip()

    return hostname


def get_conn_params(use_tor):
    """Compute connections parameters."""
    if use_tor:
        host = read_hostname(TOR_HOSTNAME_FILENAME)
        proxy = TOR_PROXY
    else:
        host = "{}:8080".format(SERVER_HOSTNAME)
        proxy = None

    return host, proxy


def create_session(proxy):
    """Create a Requests session."""

    session = requests.session()

    if proxy:
        session.proxies = {"http": proxy, "https": proxy}

    return session


def client_get_pk(args):
    """Handle `get-pk` subcommand."""

    public_key_fd = args.out

    try:
        host, proxy = get_conn_params(args.tor)

        url = "http://{}/public-key".format(host)

        # Done in a proper way, we would use HTTPS instead of HTTP.
        session = create_session(proxy)
        res = session.get(url=url)

        if res.status_code != 200:
            raise SimpleHTTPError(
                "The client failed to retrieve the public key from the server!"
            )

        public_key = res.content

        public_key_fd.write(public_key)
        public_key_fd.flush()

    finally:
        args.out.close()


def client_register(args):
    """Handle `register` subcommand."""

    try:
        public_key = args.pub.read()

    finally:
        args.pub.close()

    try:
        anon_cred_fd = args.out

        username = args.user
        attributes = args.attributes

        client = Client()
        issuance_req, state = client.prepare_registration(
            public_key, username, attributes
        )

        host, proxy = get_conn_params(args.tor)

        url = "http://{}/register".format(host)
        params = {
            "username": username,
            "attributes": attributes,
            "issuance_req": issuance_req,
        }

        # Done in a proper way, we would use HTTPS instead of HTTP.
        session = create_session(proxy)
        res = session.post(url=url, params=params)

        if res.status_code != 200:
            raise SimpleHTTPError("The client failed to register to the server!")

        issuance_res = res.content

        anon_cred = client.proceed_registration_response(
            public_key, issuance_res, state
        )

        anon_cred_fd.write(anon_cred)
        anon_cred_fd.flush()

    finally:
        args.out.close()


def client_loc(args):
    """Handle `loc` subcommand."""

    try:
        lat = args.lat
        lon = args.lon
        attrs_revealed = args.reveal
        public_key = args.pub.read()
        anon_cred = args.cred.read()

    finally:
        args.pub.close()
        args.cred.close()

    client = Client()
    message = ("{},{}".format(lat, lon)).encode("utf-8")
    signature = client.sign_request(public_key, anon_cred, message, attrs_revealed)

    host, proxy = get_conn_params(args.tor)

    url = "http://{}/poi-loc".format(host)
    params = {
        "lat": lat,
        "lon": lon,
        "attrs_revealed": attrs_revealed,
        "signature": signature,
    }

    # Done in a proper way, we would use HTTPS instead of HTTP.
    session = create_session(proxy)
    res = session.get(url=url, params=params)

    if res.status_code != 200:
        raise SimpleHTTPError("Invalid return code {}!".format(res.status_code))

    res_json = res.json()

    poi_ids = res_json["poi_list"]

    if not poi_ids:
        print("Sigh... nothing interesting nearby.")

    # No signature, etc... for retrieving the info about the PoIs themselves.
    for poi_id in poi_ids:
        url = "http://{}/poi".format(host)
        params = {"poi_id": poi_id}
        res = session.get(url=url, params=params)
        if res.status_code != 200:
            raise SimpleHTTPError("Invalid return code {}!".format(res.status_code))

        poi = res.json()
        print('You are near "{}".'.format(poi["poi_name"]))


def client_grid(args):
    """Handle `grid` subcommand."""

    try:
        cell_id = args.cell_id
        attrs_revealed = args.reveal
        public_key = args.pub.read()
        anon_cred = args.cred.read()

    finally:
        args.pub.close()
        args.cred.close()

    client = Client()
    message = ("{}".format(cell_id)).encode("utf-8")
    signature = client.sign_request(public_key, anon_cred, message, attrs_revealed)

    host, proxy = get_conn_params(args.tor)

    url = "http://{}/poi-grid".format(host)
    params = {
        "cell_id": cell_id,
        "attrs_revealed": attrs_revealed,
        "signature": signature,
    }

    # Done in a proper way, we would use HTTPS instead of HTTP.
    session = create_session(proxy)
    res = session.get(url=url, params=params)

    if res.status_code != 200:
        raise SimpleHTTPError("Invalid return code {}!".format(res.status_code))

    res_json = res.json()

    poi_ids = res_json["poi_list"]

    if not poi_ids:
        print("Sigh... nothing interesting nearby.")

    # No signature, etc... for retrieving the info about the PoIs themselves.
    for poi_id in poi_ids:
        url = "http://{}/poi".format(host)
        params = {"poi_id": poi_id}
        res = session.get(url=url, params=params)
        if res.status_code != 200:
            raise SimpleHTTPError("Invalid return code {}!".format(res.status_code))

        poi = res.json()
        print('You are near "{}".'.format(poi["poi_name"]))


if __name__ == "__main__":
    main(sys.argv[1:])
