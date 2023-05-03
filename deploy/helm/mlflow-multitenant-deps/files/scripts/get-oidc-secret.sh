#!/bin/bash -xeu

if ! kubectl get secret "${SECRET_NAME}" ; then
    echo "Secret doesn't exist, skipping step"
    exit 0
fi

for field in client-id client-secret cookie-secret; do
    kubectl get secret "${SECRET_NAME}" --template '{{ index .data "'"${field}"'" }}' > "/tmp/${field}"
done
