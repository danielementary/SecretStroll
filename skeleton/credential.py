# The goal of this skeleton is helping you start with the credential.
# Following this API is not mandatory and you can change it as you see fit.
# This skeleton only provides major classes/functionality that you need. You 
# should define more classes and functions.

# Hint: for a clean code, you should create classes for messages that you want
# to pass between user and issuer. The serialization helps you with (de)serializing them
# (network API expects byte[] as input).

from serialization import jsonpickle
from petrelic.multiplicative.pairing import G1, G2, GT
from petrelic.bn import Bn
import hashlib


class PSSignature(object):
    """PS's Multi-message signature from section 4.2
    
    **Important** This class has no direct use in the project.

    Implementing this class allows you to get familiar with coding crypto schemes
    and its simplicity in comparison with the ABC scheme allows you to realize
    misunderstandings/problems early on.
    """
    @classmethod
    def generate_key(cls):
        gen = G2.generator()
        sk = [G1.order().random(),G1.order().random()]
        pk = [gen] + [gen ** i for i in sk]
        return sk, pk

    @classmethod
    def sign(cls, sk, messages):
        m = Bn.from_binary(hashlib.sha256(messages).digest())
        h = G1.generator() ** G1.order().random()   
        while h == G1.neutral_element():
            h = G1.generator() ** G1.order().random()
        sig = [h, h ** (sk[0] + sk[1] * m)]
        return sig
        
    @classmethod
    def verify(cls, pk, messages, signature):
        m = Bn.from_binary(hashlib.sha256(messages).digest())
        is_gen = signature[0] == G1.neutral_element()
        is_valid = signature[0].pair(pk[1] * pk[2] ** m) == signature[1].pair(pk[0])
        return is_valid and not is_gen


class Issuer(object):
    """Allows the server to issue credentials"""

    def setup(self, secret_key, valid_attributes):
        """Decides the public parameters of the scheme and generates a key for
        the issuer.

        Args:
            valid_attributes (string): all valid attributes. The issuer
            will never be called with a value outside this list
        """
        print("issuer_setup")
        pass

    def get_serialized_public_key(self):
        """Returns the public parameters and the public key of the issuer.

        Args:
            No input

        Returns:
            byte[]: issuer's public params and key
        """
        pass

    def get_serialized_secret_key(self):
        """Returns the secret key of the issuer.

        Args:
            No input

        Returns:
            byte[]: issuer's secret params and key
        """
        pass
    @staticmethod
    def issue(sk, request, username, attributes):
        """Issues a credential for a new user. 

        This function should receive a issuance request from the user
        (AnonCredential.create_issue_request), and a list of known attributes of the
        user (e.g. the server received bank notes for subscriptions x, y, and z).

        You should design the issue_request as you see fit.
        """
        #Derive challenge
        challenge = hashlib.sha256(jsonpickle.encode(request.C).encode())
        challenge.update(jsonpickle.encode(request.commitment).encode())
        challenge.update(jsonpickle.encode(request.server_pk).encode())
        challenge = Bn.from_binary(challenge.digest())

        challenge_valid = challenge == request.challenge

        candidate = request.C ** request.challenge
        for e in zip(request.server_pk, request.response):
            candidate = candidate * e[0] ** e[1]
        
        proof_valid = request.commitment == candidate

        print(len(request.response))

        if proof_valid and challenge_valid:
            u = G1.order().random()
            sig = (request.server_pk[0] ** u,(sk * request.C) ** u)
            return sig
        else :
            raise ValueError


class AnonCredential(object):
    """An AnonCredential"""

    @staticmethod
    def create_issue_request(server_pk, attributes):
        """Gets all known attributes (subscription) of a user and creates an issuance request.
        You are allowed to add extra attributes to the issuance.

        You should design the issue_request as you see fit.
        """
        attributes = [Bn.from_binary(hashlib.sha256(attr.encode()).digest()) for attr in attributes]
        gen_g1 = server_pk[0]
        t = G1.order().random()

        #Gen C
        C = gen_g1 ** t
        for e in zip(server_pk[1:], attributes):
            C = C * e[0] ** e[1]
        
        #Gen commitment
        comm_values = [G1.order().random() for _ in range(len(attributes) + 1)]
        comm = gen_g1 ** comm_values[0]
        for e in zip(server_pk[1:], comm_values[1:]):
            comm  = comm * e[0] ** e[1]
        
        #Gen challenge
        challenge = hashlib.sha256(jsonpickle.encode(C).encode())
        challenge.update(jsonpickle.encode(comm).encode())
        challenge.update(jsonpickle.encode(server_pk).encode())
        challenge = Bn.from_binary(challenge.digest())

        #Generate response
        response = [e[0].mod_sub(challenge * e[1],G1.order()) for e in zip(comm_values, [t] + attributes)]


        candidate = C ** challenge
        for e in zip(server_pk, response):
            candidate = candidate * e[0] ** e[1]


        return IssuanceRequest(C, comm, challenge, response, server_pk),t


    @staticmethod
    def receive_issue_response(response, t):
        """This function finishes the credential based on the response of issue.

        Hint: you need both secret values from the create_issue_request and response
        from issue to build the credential.

        You should design the issue_request as you see fit.
        """
        return (response[0], response[1] / (response[0] ** t))

    def sign(self, message, revealed_attr):
        """Signs the message.

        Args:
            message (byte []): message
            revealed_attr (string []): a list of revealed attributes

        Return:
            Signature: signature
        """
        pass


class Signature(object):
    """A Signature"""

    def verify(self, issuer_public_info, public_attrs, message):
        """Verifies a signature.

        Args:
            issuer_public_info (): output of issuer's 'get_serialized_public_key' method
            public_attrs (dict): public attributes
            message (byte []): list of messages

        returns:
            valid (boolean): is signature valid
        """
        pass

    def serialize(self):
        """Serialize the object to a byte array.

        Returns: 
            byte[]: a byte array 
        """
        pass

    @staticmethod
    def deserialize(data):
        """Deserializes the object from a byte array.

        Args: 
            data (byte[]): a byte array 

        Returns:
            Signature
        """
        pass


class IssuanceRequest(object):
    """An Issuance Request"""
    def __init__(self, C, commitment, challenge, response, server_pk):
        self.C = C
        self.commitment = commitment
        self.challenge = challenge
        self.response = response
        self.server_pk = server_pk
    
    def serialize(self):
        data = jsonpickle.encode(self)
        return data.encode()

    @staticmethod
    def deserialize(data):
        return jsonpickle.decode(data)