from your_code import *
import client


'''
This benchmark need to be run in the client docker, with a running server.
The server must have a public key with the attributes below.
'''

attributes = "a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z,A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,Z"


client.main(["get-pk","-o","key-client.pub"])

def test_registration(benchmark):
    '''
    Benchmark for credential issuance
    '''
    #Setup
    chosen_attr = "q,r,s,t,u,v,w,x,y,z,A,B,C,D,E,F,G"

    #Benchmark
    benchmark(client.main, ["register", "-p", "key-client.pub", "-o","attr.cred", "-u", "vetterlim", "-a", chosen_attr])


def test_credential_checking(benchmark):
    revealed_attr = "v,w,x,y,z,A,B"
    #out of bound coordinates, so we do not bench the PoIs fetching
    lat = "42"
    lon = "42"
    #benchmark
    benchmark(client.main,["loc", "-p", "key-client.pub", "-c", "attr.cred", "-r", revealed_attr, lat, lon])
