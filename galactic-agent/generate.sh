#!/bin/bash
# Requirements:
# - apt install protobuf-compiler
# - go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
# - go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
find api -type f -name '*.proto' |while read file; do
    dir=$(dirname ${file})
    grep -q rpc ${file}
    if [ $? -eq 0 ]; then
        echo "Generate gRPC ${file}"
        protoc -I ${dir} \
            --go_out=${dir} \
            --go_opt=paths=source_relative \
            --go-grpc_out=${dir} \
            --go-grpc_opt=paths=source_relative \
            ${file}
    else
        echo "Generate protobuf ${file}"
        protoc -I ${dir} \
            --go_out=${dir} \
            --go_opt=paths=source_relative \
            ${file}
    fi
done
