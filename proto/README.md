python -m grpc_tools.protoc -Iproto --python_out=prototest --grpc_python_out=prototest proto/papr.proto
python -m grpc_tools.protoc -Iproto --python_out=papr --grpc_python_out=papr proto/papr.proto