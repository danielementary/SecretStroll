"""
Server entrypoint.

!!! DO NOT MODIFY THIS FILE !!!

"""

import argparse
import json
import random
import sys

from flask import Flask, jsonify, make_response, request
from flask_sqlalchemy import SQLAlchemy

from your_code import Server


def main(args):
    """Parse the arguments given to the server, and call the appropriate method."""

    parser = argparse.ArgumentParser(description="Server for CS-523 project.")
    subparsers = parser.add_subparsers(help="Command")

    parser_gen = subparsers.add_parser(
        "gen-ca", help="Generate a pair of secret and public keys."
    )
    parser_gen.add_argument(
        "-a",
        "--attributes",
        help="Valid attributes recognised by the server.",
        type=str,
        required=True,
    )
    parser_gen.add_argument(
        "-p",
        "--pub",
        help="Name of the file in which to write the public key.",
        type=argparse.FileType("wb"),
        required=True,
    )
    parser_gen.add_argument(
        "-s",
        "--sec",
        help="Name of the file in which to write the secret key.",
        type=argparse.FileType("wb"),
        required=True,
    )

    parser_gen.set_defaults(callback=server_gen_ca)

    parser_run = subparsers.add_parser("run", help="Run the server.")
    parser_run.add_argument(
        "-p",
        "--pub",
        help="Name of the file containing the public key.",
        type=argparse.FileType("rb"),
        required=True,
    )
    parser_run.add_argument(
        "-s",
        "--sec",
        help="Name of the file containing the secret key.",
        type=argparse.FileType("rb"),
        required=True,
    )

    parser_run.set_defaults(callback=server_run)

    namespace = parser.parse_args(args)

    if "callback" in namespace:
        namespace.callback(namespace)

    else:
        parser.print_help()


def server_gen_ca(args):
    """Handle `gen-ca` subcommand."""

    public_key_fd = args.pub
    secret_key_fd = args.sec
    attributes = args.attributes

    try:
        public_key, secret_key = Server.generate_ca(attributes)

        public_key_fd.write(public_key)
        secret_key_fd.write(secret_key)

        public_key_fd.flush()
        secret_key_fd.flush()

    finally:
        args.pub.close()
        args.sec.close()


def server_run(args):
    """Handle `run` subcommand."""

    # pylint: disable=global-statement
    global PUBLIC_KEY
    global SECRET_KEY
    global SERVER

    try:
        PUBLIC_KEY = args.pub.read()
        SECRET_KEY = args.sec.read()

    finally:
        args.pub.close()
        args.sec.close()

    SERVER = Server()

    host = "0.0.0.0"
    port = 8080

    APP.run(host=host, port=port, debug=True)


APP = Flask(__name__)


DB = SQLAlchemy()


class PoI(DB.Model):
    """A PoI object consists of the following:

    poi_id -- ID of the PoI
    poi_name -- Name of the PoI
    poi_address -- Address of the PoI
    grid_id -- Grid in which the PoI is present
    poi_ratings -- List of ratings for the PoI.

    """

    poi_id = DB.Column(DB.Integer, primary_key=True)
    poi_name = DB.Column(DB.String)
    poi_address = DB.Column(DB.String)
    grid_id = DB.Column(DB.Integer)
    poi_ratings = DB.Column(DB.String)

    def to_dict(self):
        """
        Return a dictionary representation of the object.
        """
        return dict(
            poi_id=self.poi_id,
            poi_name=self.poi_name,
            poi_address=self.poi_address,
            grid_id=self.grid_id,
            poi_ratings=self.poi_ratings,
        )


APP.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///fingerprint.db"
APP.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
DB.app = APP
DB.init_app(APP)


PUBLIC_KEY = None
SECRET_KEY = None
SERVER = None


@APP.route("/public-key", methods=["GET"])
def get_public_key():
    """Handle requests for public key."""
    return PUBLIC_KEY, 200


@APP.route("/register", methods=["POST"])
def register():
    """Handle registrations."""
    username = request.files.get("username").read().decode("utf-8")
    attributes = request.files.get("attributes").read().decode("utf-8")
    issuance_req = request.files.get("issuance_req").read()
    anon_cred = SERVER.register(SECRET_KEY, issuance_req, username, attributes)

    res = make_response(anon_cred)
    return res


def convert_loc_to_gridval(loc):
    """Placeholder function. Final function would convert the location to a grid value."""
    return int(loc)


@APP.route("/poi-loc", methods=["GET"])
def get_poi_loc():
    """Takes in a latitude and longitude as input, returns a list of associated POIs."""

    lat = float(request.args.get("lat"))
    lon = float(request.args.get("lon"))
    attrs_revealed = request.args.get("attrs_revealed")
    signature = request.args.get("signature")
    message = ("{},{}".format(lat, lon)).encode("utf-8")

    valid = SERVER.check_request_signature(
        PUBLIC_KEY, message, attrs_revealed, signature
    )

    if not valid:
        return "Invalid signature", 401

    # PoIs are within coordinates (46.5, 6.55) and (46.57, 6.65)
    # mapped to a 10 x 10 grid
    if 46.5 <= lat <= 46.57 and 6.55 <= lon <= 6.65:
        cell_x = ((lat - 46.5) / 0.07) * 10
        cell_y = ((lon - 6.55) / 0.1) * 10
        cell_id = int(cell_x + (cell_y * 10))
        records = PoI.query.filter_by(grid_id=cell_id).all()

        if records:
            poi_list = [record.to_dict()["poi_id"] for record in records]
            poi_list_res = {"poi_list": poi_list}
        else:
            poi_list_res = {"poi_list": []}
    else:
        poi_list_res = {"poi_list": []}

    return jsonify(poi_list_res)


@APP.route("/poi-grid", methods=["GET"])
def get_poi_list():
    """Takes in a cell ID as input, returns a list of associated POIs."""

    cell_id = int(request.args.get("cell_id"))
    attrs_revealed = request.args.get("attrs_revealed")
    signature = request.args.get("signature")
    message = ("{}".format(cell_id)).encode("utf-8")

    valid = SERVER.check_request_signature(
        PUBLIC_KEY, message, attrs_revealed, signature
    )

    if not valid:
        return "Invalid signature", 401

    records = PoI.query.filter_by(grid_id=cell_id).all()

    if records:
        poi_list = [record.to_dict()["poi_id"] for record in records]
        poi_list_res = {"poi_list": poi_list}

    else:
        return "Not found", 404

    return jsonify(poi_list_res)


@APP.route("/poi", methods=["GET"])
def get_poi_info():
    """Takes in a PoI ID as input, returns information about that PoI.
    We have a paramter 'noise_factor' for tuning.
    This is used to slightly alter the size of responses sent by the server.
    Server adds padding records based on the noise factor. Do not change 
    the noise code, this is used to simulate slight variations in traces
    from the server."""

    poi_id = request.args.get('poi_id')
    noise_factor = 10

    records = PoI.query.filter_by(poi_id=int(poi_id)).all()
    if records:
        poi_info = records[0].to_dict()
        poi_info["poi_ratings"] = json.loads(poi_info["poi_ratings"])

        random_length = random.randint(0, noise_factor)
        padding = [-1 for x in range(0, random_length)]
        poi_info["padding"] = padding

    else:
        return "Not found", 404

    return jsonify(poi_info)


if __name__ == "__main__":
    main(sys.argv[1:])
