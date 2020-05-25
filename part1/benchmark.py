from your_code import *




attributes = "a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z,A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,Z"
username = "vetterlim"
message = "46.5 6.5".encode()


def test_key_generation(benchmark):
    '''
    Benchmark for key generation
    '''
    benchmark(Server.generate_ca,attributes)


def credential_issuance(pk, chosen_attr, sk):
    '''
    Function for complete credential issuance request
    '''
    issue_request, private_state = Client().prepare_registration(pk, username, chosen_attr)
    response = Server().register(sk, issue_request, username, chosen_attr)
    credential = Client().proceed_registration_response(pk, response, private_state)

def test_credential_issuance(benchmark):
    '''
    Benchmark for credential issuance
    '''
    #Setup
    chosen_attr = "q,r,s,t,u,v,w,x,y,z,A,B,C,D,E,F,G"
    pk, sk = Server.generate_ca(attributes)

    #Benchmark
    benchmark(credential_issuance, pk, chosen_attr, sk)


def test_credential_showing(benchmark):
    '''
    Benchmark for credential showing, i.e signing a message
    '''
    #Setup
    chosen_attr = "q,r,s,t,u,v,w,x,y,z,A,B,C,D,E,F,G"
    revealed_attr = "v,w,x,y,z,A,B"
    pk, sk = Server.generate_ca(attributes)
    issue_request, private_state = Client().prepare_registration(pk, username, chosen_attr)
    response = Server().register(sk, issue_request, username, chosen_attr)
    credential = Client().proceed_registration_response(pk, response, private_state)

    #benchmark
    benchmark(Client().sign_request,pk, credential, message, revealed_attr)

def test_credential_checking(benchmark):
    '''
    Benchmark for credential checking
    '''
    #Setup
    chosen_attr = "q,r,s,t,u,v,w,x,y,z,A,B,C,D,E,F,G"
    revealed_attr = "v,w,x,y,z,A,B"
    pk, sk = Server.generate_ca(attributes)
    issue_request, private_state = Client().prepare_registration(pk, username, chosen_attr)
    response = Server().register(sk, issue_request, username, chosen_attr)
    credential = Client().proceed_registration_response(pk, response, private_state)
    signature = Client().sign_request(pk, credential, message, revealed_attr)

    #benchmark
    benchmark(Server().check_request_signature, pk, message, revealed_attr, signature)
