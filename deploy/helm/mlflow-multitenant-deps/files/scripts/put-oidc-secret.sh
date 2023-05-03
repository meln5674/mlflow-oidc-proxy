#!/bin/bash -xeu

if ! kubectl get secret "${SECRET_NAME}" ; then
    echo "Secret doesn't exist, creating whole-cloth"
    ARGS=()
    for field in client-id client-secret cookie-secret; do
        ARGS+=( --from-field "${field}=/tmp/${field}" )
    done
    kubectl create secret generic "${SECRET_NAME}" "${ARGS[@]}"
    exit 0
fi

for field in client-id client-secret cookie-secret; do
    kubectl patch secret "${SECRET_NAME}" --patch=/dev/stdin <<EOF
data:
  ${field}: $(cat "/tmp/${field}" | base64)
EOF
done
