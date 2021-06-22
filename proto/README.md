# Proto

This code provides a solid base upon which you could build a network interface for PAPR. Three main things exist in this folder.
1. `grpc_server.py` -- code that could be used by an issuer
2. `grpc_user.py` -- provides a framework of gRPC methods that could be filled with PAPR-procedure-logic
3. `papr.proto` -- gRPC messages have been implemented

To compile the .proto-files you will need to download a few dependencies (see https://grpc.io/docs/languages/python/quickstart/) and then issue the following commands (from src):

```
python -m grpc_tools.protoc -Iproto --python_out=prototest --grpc_python_out=prototest proto/papr.proto
python -m grpc_tools.protoc -Iproto --python_out=papr --grpc_python_out=papr proto/papr.proto
```

Please note that the implementation of `papr_user_grpc.py` and `grpc_server.py` are both outdated. The logic should be replaced by the code available in the papr-folder.