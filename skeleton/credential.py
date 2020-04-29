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

    @staticmethod
    def issue(sk, request, username, attributes):
        """Issues a credential for a new user. 

        This function should receive a issuance request from the user
        (AnonCredential.create_issue_request), and a list of known attributes of the
        user (e.g. the server received bank notes for subscriptions x, y, and z).

        You should design the issue_request as you see fit.
        """
        #extract public and secret key
        secret_key = sk[0]
        public_key = sk[1]

        #Derive challenge
        challenge = hashlib.sha256(jsonpickle.encode(request.C).encode())
        challenge.update(jsonpickle.encode(request.commitment).encode())
        challenge.update(jsonpickle.encode(public_key).encode())
        challenge = Bn.from_binary(challenge.digest())

        #Compare the derived challenge to the received challenge
        challenge_valid = challenge == request.challenge

        #Compute the zkp
        candidate = request.C ** challenge
        for e in zip(public_key, request.response):
            candidate = candidate * e[0] ** e[1]
        

        proof_valid = request.commitment == candidate

        #If the proof and the derived challenge is valid, sig the credential
        if proof_valid and challenge_valid:
            u = G1.order().random()
            sig = (public_key[0] ** u,(secret_key * request.C) ** u)
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


        return IssuanceRequest(C, comm, challenge, response),t


    @staticmethod
    def receive_issue_response(response, t):
        """This function finishes the credential based on the response of issue.

        Hint: you need both secret values from the create_issue_request and response
        from issue to build the credential.

        You should design the issue_request as you see fit.
        """
        return (response[0], response[1] / (response[0] ** t))

    @staticmethod
    def sign(server_pk, credential, message, revealed_attr):
        """Signs the message.

        Args:
            message (byte []): message
            revealed_attr (string []): a list of revealed attributes

        Return:
            Signature: signature
        """
        #public_key separation
        nb_attr_public_key = (len(self.server_pk) - 3) // 2
        gen_g1_pk = self.server_pk[0]
        public_key1 = self.server_pk[1:nb_attr_public_key + 1]
        gen_g2_pk = self.server_pk[nb_attr_public_key + 1]
        x_g2_pk = self.server_pk[nb_attr_public_key + 2]
        public_key2 = self.server_pk[nb_attr_public_key + 3:]

        #Gen signature
        r = G1.order().random()
        t = G1.order().random()
        signature = (self.credential[0] ** r, (self.credential[1] * self.credential[0]**t)**r)

        #attributes work
        revealed_attributes_idx = [self.attributes.index(attr) for attr in self.attributes if attr in revealed_attr]
        revealed_attributes_bn = [Bn.from_binary(hashlib.sha256(attr.encode()).digest()) for attr in revealed_attr]
        hidden_attributes_idx = [self.attributes.index(attr) for attr in self.attributes if attr not in revealed_attr]
        hidden_attributes_bn = [Bn.from_binary(hashlib.sha256(attr.encode()).digest()) for attr in self.attributes if attr not in revealed_attr]


        #Gen C (left-hand side)
        C = signature[1].pair(gen_g2_pk) / signature[0].pair(x_g2_pk)
        for i in range(len(revealed_attr)):
            C = C * signature[0].pair(public_key2[revealed_attributes_idx[i]]) ** (-revealed_attributes_bn[i] % G1.order())
        

        #Gen commitment (to prove right-hand side)
        comm_values = [G1.order().random() for _ in range(len(hidden_attributes_idx) + 1)]
        comm = signature[0].pair(gen_g2_pk) ** comm_values[0]
        for e in zip(hidden_attributes_idx, comm_values[1:]):
            comm = comm * signature[0].pair(public_key2[e[0]])**e[1]


        #Gen Challenge
        challenge = hashlib.sha256(jsonpickle.encode(C).encode())
        challenge.update(jsonpickle.encode(comm).encode())
        challenge.update(jsonpickle.encode(self.server_pk).encode())
        challenge.update(message)
        challenge = Bn.from_binary(challenge.digest())

        #Gen Responses
        response = [e[0].mod_sub(challenge * e[1],G1.order()) for e in zip(comm_values, [t] + hidden_attributes_bn)]


        return Signature(signature, comm, challenge, response, revealed_attributes_idx)


class Signature(object):
    """A Signature"""

    def __init__(self, signature, commitment, challenge, response, attributes_idx):
        self.signature = signature
        self.commitment = commitment
        self.challenge = challenge
        self.response = response
        self.attributes_idx = attributes_idx

    def verify(self, issuer_public_info, public_attrs, message):
        """Verifies a signature.

        Args:
            issuer_public_info (): output of issuer's 'get_serialized_public_key' method
            public_attrs (dict): public attributes
            message (byte []): list of messages

        returns:
            valid (boolean): is signature valid
        """
        #public_key separation
        nb_attr_public_key = (len(issuer_public_info) - 3) // 2
        gen_g1_pk = issuer_public_info[0]
        public_key1 = issuer_public_info[1:nb_attr_public_key + 1]
        gen_g2_pk = issuer_public_info[nb_attr_public_key + 1]
        x_g2_pk = issuer_public_info[nb_attr_public_key + 2]
        public_key2 = issuer_public_info[nb_attr_public_key + 3:]

        #attributes work
        nb_attr = len(self.response) - 1 + len(public_attrs)
        public_attributes_idx = self.attributes_idx
        public_attributes_bn = [Bn.from_binary(hashlib.sha256(attr.encode()).digest()) for attr in public_attrs]
        hidden_attributes_idx = [i for i in range(nb_attr) if i not in public_attributes_idx]


        #Gen C (left-hand side)
        C = self.signature[1].pair(gen_g2_pk) / self.signature[0].pair(x_g2_pk)
        for i in range(len(public_attrs)):
            C = C * self.signature[0].pair(public_key2[public_attributes_idx[i]]) ** (-public_attributes_bn[i] % G1.order())

        #Gen Challenge
        challenge = hashlib.sha256(jsonpickle.encode(C).encode())
        challenge.update(jsonpickle.encode(self.commitment).encode())
        challenge.update(jsonpickle.encode(issuer_public_info).encode())
        challenge.update(message)
        challenge = Bn.from_binary(challenge.digest())

        #check challenge
        challenge_valid = challenge == self.challenge

        #Compute zkp
        candidate = C ** challenge * self.signature[0].pair(gen_g2_pk) ** self.response[0]
        for e in zip(hidden_attributes_idx, self.response[1:]):
            candidate = candidate * self.signature[0].pair(public_key2[e[0]]) ** e[1]

        proof_valid = candidate == self.commitment


        return challenge_valid and proof_valid 

    def serialize(self):
        """Serialize the object to a byte array.

        Returns: 
            byte[]: a byte array 
        """
        data = jsonpickle.encode(self)
        return data.encode()

    @staticmethod
    def deserialize(data):
        """Deserializes the object from a byte array.

        Args: 
            data (byte[]): a byte array 

        Returns:
            Signature
        """
        return jsonpickle.decode(data)


class IssuanceRequest(object):
    """An Issuance Request"""
    def __init__(self, C, commitment, challenge, response):
        self.C = C
        self.commitment = commitment
        self.challenge = challenge
        self.response = response
    
    def serialize(self):
        data = jsonpickle.encode(self)
        return data.encode()

    @staticmethod
    def deserialize(data):
        return jsonpickle.decode(data)