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
        p = G1.order()
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

    def setup(self, valid_attributes):
        """Decides the public parameters of the scheme and generates a key for
        the issuer.

        Args:
            valid_attributes (string): all valid attributes. The issuer
            will never be called with a value outside this list
        """
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

    def issue():
        """Issues a credential for a new user. 

        This function should receive a issuance request from the user
        (AnonCredential.create_issue_request), and a list of known attributes of the
        user (e.g. the server received bank notes for subscriptions x, y, and z).

        You should design the issue_request as you see fit.
        """
        pass


class AnonCredential(object):
    """An AnonCredential"""

    def create_issue_request():
        """Gets all known attributes (subscription) of a user and creates an issuance request.
        You are allowed to add extra attributes to the issuance.

        You should design the issue_request as you see fit.
        """
        pass

    def receive_issue_response():
        """This function finishes the credential based on the response of issue.

        Hint: you need both secret values from the create_issue_request and response
        from issue to build the credential.

        You should design the issue_request as you see fit.
        """
        pass

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
