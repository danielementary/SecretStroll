"""
Classes that you need to complete.
"""

# Optional import
from serialization import jsonpickle
from credential import *
from petrelic.multiplicative.pairing import G1, G2
from petrelic.bn import Bn


class Server:
    """Server"""

    @staticmethod
    def generate_ca(valid_attributes):
        """Initializes the credential system. Runs exactly once in the
        beginning. Decides on schemes public parameters and choses a secret key
        for the server.

        Args:
            valid_attributes (string): a list of all valid attributes. Users cannot
            get a credential with a attribute which is not included here.

            Note: You can use JSON to encode valid_attributes in the string.

        Returns:
            (tuple): tuple containing:
                byte[] : server's pubic information
                byte[] : server's secret key
            You are free to design this as you see fit, but all commuincations
            needs to be encoded as byte arrays.
        """
        attr_list = valid_attributes.split(',')
        nb_attributes = len(attr_list)

        gen_g1 = G1.generator()
        gen_g2 = G2.generator()
        exp = [G1.order().random() for _ in range(nb_attributes + 1)]

        pk = [gen_g1] + [gen_g1 ** i for i in exp[1:]] + [gen_g2] + [gen_g2 ** i for i in exp]
        sk = gen_g1 ** exp[0]

        sk = [sk, pk, attr_list]
        pk = [pk, attr_list]


        return (jsonpickle.encode(pk).encode(), jsonpickle.encode(sk).encode())


    def register(self, server_sk, issuance_request, username, attributes):
        """ Registers a new account on the server.

        Args:
            server_sk (byte []): the server's secret key (serialized)
            issuance_request (bytes[]): The issuance request (serialized)
            username (string): username
            attributes (string): attributes

            Note: You can use JSON to encode attributes in the string.

        Return:
            response (bytes[]): the client should be able to build a credential
            with this response.
        """
        sk = jsonpickle.decode(server_sk)
        attributes = attributes.split(',')

        #Check if attributes chosen are valid
        for attr in attributes:
            if attr not in sk[2]:
                raise RuntimeError("Revealed attributes are not valid")  

        response = Issuer.issue(sk, jsonpickle.decode(issuance_request), username, attributes)
        return jsonpickle.encode(response).encode()

    def check_request_signature(
        self, server_pk, message, revealed_attributes, signature
    ):
        """

        Args:
            server_pk (byte[]): the server's public key (serialized)
            message (byte[]): The message to sign
            revealed_attributes (string): revealed attributes
            signature (bytes[]): user's autorization (serialized)

            Note: You can use JSON to encode revealed_attributes in the string.

        Returns:
            valid (boolean): is signature valid
        """
        signature = jsonpickle.decode(signature)
        pk = jsonpickle.decode(server_pk)

        #Sanitization in case revealed_info is empty
        public_attrs = revealed_attributes.split(',')
        while '' in public_attrs:
            public_attrs.remove('')

        #Check if attributes revealed are valid
        for attr in public_attrs:
            if attr not in pk[1]:
                raise RuntimeError("Revealed attributes are not valid")        

        return signature.verify(pk[0], public_attrs, message)


class Client:
    """Client"""

    def prepare_registration(self, server_pk, username, attributes):
        """Prepare a request to register a new account on the server.

        Args:
            server_pk (byte[]): a server's public key (serialized)
            username (string): username
            attributes (string): user's attributes

            Note: You can use JSON to encode attributes in the string.

        Return:
            tuple:
                byte[]: an issuance request
                (private_state): You can use state to store and transfer information
                from prepare_registration to proceed_registration_response.
                You need to design the state yourself.
        """
        pk = jsonpickle.decode(server_pk)
        attributes = attributes.split(',')
        request,t = AnonCredential.create_issue_request(pk[0], attributes)

        return request.serialize(), (t,attributes)

    def proceed_registration_response(self, server_pk, server_response, private_state):
        """Process the response from the server.

        Args:
            server_pk (byte[]): a server's public key (serialized)
            server_response (byte[]): the response from the server (serialized)
            private_state (private_state): state from the prepare_registration
            request corresponding to this response

        Return:
            credential (byte []): create an attribute-based credential for the user
        """
        credential = AnonCredential.receive_issue_response(jsonpickle.decode(server_pk)[0],jsonpickle.decode(server_response), private_state)
        return jsonpickle.encode(credential).encode()

    def sign_request(self, server_pk, credential, message, revealed_info):
        """Signs the request with the clients credential.

        Arg:
            server_pk (byte[]): a server's public key (serialized)
            credential (byte[]): client's credential (serialized)
            message (byte[]): message to sign
            revealed_info (string): attributes which need to be authorized

            Note: You can use JSON to encode revealed_info.

        Returns:
            byte []: message's signature (serialized)
        """
        revealed_attr = revealed_info.split(',')
        credential = jsonpickle.decode(credential)

        #Sanitization in case revealed_info is empty
        while '' in revealed_attr:
            revealed_attr.remove('')

        #Check if attributes revealed are valid
        for attr in revealed_attr:
            if attr not in credential.attributes:
                raise RuntimeError("Revealed attributes are not in the credential")

        
        signature = credential.sign(message, revealed_attr)

        return signature.serialize()
