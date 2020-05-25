# Part 1
Since the executables for the client and the server were provided, they will not be detailed here.
Please note that the attributes should be encoded as a comma separated list.

## Tests
Ensure that the pytest package is installed. If it is not the case, install it with :
```
pip3 install pytest
```

The tests are located in `test.py` and can be run using the following command : 
```
pytest test.py
```

## Benchmark

Benchmarks require the pytest-benchmark package to be installed. If it is not the case, install it with :
```
pip3 install pytest-benchmark
```

### Offline benchmark

Offline benchmarks are located in `benchmark.py` and can be run using the following command : 
```
pytest benchmark.py
```

### Online benchmark

Online benchmarks are located in `benchmark_net.py` and require a running server with specific attributes. You can configure it by running the following command :
```
$ python3 server.py gen-ca -a 'a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z,A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,Z' -s key.sec -p key.pub
$ python3 server.py run -s key.sec -p key.pub
```

