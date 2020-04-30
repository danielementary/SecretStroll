from credential import *
from your_code import *
import petrelic.multiplicative.pairing
from petrelic.multiplicative.pairing import G1, G2
from serialization import jsonpickle

import pytest


def test_generate_ca():
    '''
    General test for key parameters
    '''
    attributes = "a,b,c,d,e"
    nb_attributes = len(attributes.split(','))

    pk, sk = Server.generate_ca(attributes)
    sk = jsonpickle.decode(sk)
    pk = jsonpickle.decode(pk)

    #key length check
    assert(len(pk[0]) == nb_attributes * 2 + 3)
    assert(len(pk[1]) == nb_attributes)
    assert(len(sk) == 3)
    assert(isinstance(sk[0], petrelic.multiplicative.pairing.G1Element))
    assert(len(sk[1]) == len(pk[0]))
    assert(len(sk[2]) == nb_attributes)


def test_credentials_difference():
    '''
    Test if for a request with same parameters, the credentials are different.
    Test if for a identical request, credentials are different.
    '''

    attributes = "a,b,c,d,e"
    chosen_attr = "c,d,e"
    username = "username"

    pk, sk = Server.generate_ca(attributes)

    #Client registration preparation
    issue_request1, private_state1 = Client().prepare_registration(pk, username, chosen_attr)
    issue_request2, private_state2 = Client().prepare_registration(pk, username, chosen_attr)

    #Registration server-side
    response1 = Server().register(sk, issue_request1, username, chosen_attr)
    response1_2 = Server().register(sk, issue_request1, username, chosen_attr)
    response2 = Server().register(sk, issue_request2, username, chosen_attr)

    #Client credential building
    credential1 = Client().proceed_registration_response(pk, response1, private_state1)
    credential1_2 = Client().proceed_registration_response(pk, response1_2, private_state1)
    credential2 = Client().proceed_registration_response(pk, response2, private_state2)


    #Check that issuance requests are different
    assert(issue_request1 != issue_request2)

    #Check response are different
    assert(response1 != response2)

    #Check credentials are different
    assert(credential1 != credential2)
    assert(credential1 != credential1_2)


def test_tampered_credential():
    '''
    Test if a user can have a response to a request if the credential is wrong
    '''

    attributes = "a,b,c,d,e"
    chosen_attr = "d,e"
    revealed_attr = "e"
    username = "chaplinc"
    message = "46.5 6.6".encode()

    pk, sk = Server.generate_ca(attributes)

    #Registration process
    issue_request, private_state = Client().prepare_registration(pk, username, chosen_attr)
    response = Server().register(sk, issue_request, username, chosen_attr)
    credential = Client().proceed_registration_response(pk, response, private_state)

    #Tampering the credential
    credential = jsonpickle.decode(credential)
    credential.credential = (credential.credential[0] ** 2, credential.credential[1])
    credential = jsonpickle.encode(credential).encode()

    #Request a service
    signature = Client().sign_request(pk, credential, message, revealed_attr)
    
    assert(not Server().check_request_signature(pk, message, revealed_attr, signature))


def test_correct_credential():
    '''
    Test if a user can have a response to a request if the credential is correct
    '''

    attributes = "computer_science,biology,life_science,epidemiology"
    chosen_attr = "computer_science"
    revealed_attr = "computer_science"
    username = "vetterlim"
    message = "46.5 6.5".encode()

    pk, sk = Server.generate_ca(attributes)

    #Registration process
    issue_request, private_state = Client().prepare_registration(pk, username, chosen_attr)
    response = Server().register(sk, issue_request, username, chosen_attr)
    credential = Client().proceed_registration_response(pk, response, private_state)

    #Request a service
    signature = Client().sign_request(pk, credential, message, revealed_attr)
    
    assert(Server().check_request_signature(pk, message, revealed_attr, signature))

def test_correct_credential_no_attributes():
    '''
    Test if a user can have a response to a request if the credential is correct, with no revealed attributes
    '''

    attributes = "alpha,beta,gamma,delta,eta"
    chosen_attr = "alpha,beta,gamma,delta,eta"
    revealed_attr = ""
    username = "gannimo"
    message = "46.4 6.5".encode()

    pk, sk = Server.generate_ca(attributes)

    #Registration process
    issue_request, private_state = Client().prepare_registration(pk, username, chosen_attr)
    response = Server().register(sk, issue_request, username, chosen_attr)
    credential = Client().proceed_registration_response(pk, response, private_state)

    #Request a service
    signature = Client().sign_request(pk, credential, message, revealed_attr)
    
    assert(Server().check_request_signature(pk, message, revealed_attr, signature))


def test_wrong_revealed_attr():
    '''
    Test if a user can have a response to a request if the credential revealed unobtained attributes
    '''

    attributes = "alpha,beta,gamma,delta,eta"
    chosen_attr = "alpha,gamma,delta,eta"
    revealed_attr = "beta"
    username = "troncosoc"
    message = "46.4 6.5".encode()

    pk, sk = Server.generate_ca(attributes)

    with pytest.raises(RuntimeError):
    #Registration process
        issue_request, private_state = Client().prepare_registration(pk, username, chosen_attr)
        response = Server().register(sk, issue_request, username, chosen_attr)
        credential = Client().proceed_registration_response(pk, response, private_state)

        #Request a service
        signature = Client().sign_request(pk, credential, message, revealed_attr)
        
        Server().check_request_signature(pk, message, revealed_attr, signature)

