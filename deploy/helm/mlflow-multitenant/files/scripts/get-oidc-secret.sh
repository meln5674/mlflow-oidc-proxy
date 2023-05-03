#!/bin/bash -xeu

function get-secret {
    secret_name=$1
    dir=$2
    shift 2
    if kubectl get secret "${secret_name}" ; then
        mkdir -p "${dir}"
        for field in "$@"; do
            kubectl get secret "${secret_name}" \
                --template '{{ index .data "'"${field}"'" }}' \
                | base64 -d > "${dir}/${field}"
        done
    else
        echo "Secret ${secret_name} doesn't exist, skipping fetch"
    fi
}

get-secret "${SECRET_NAME}" /tmp client-id client-secret cookie-secret
while read -r client_id secret_name ; do
    get-secret "${secret_name}" "/tmp/extra-clients/${client_id}" client-id client-secret
done <<< "${EXTRA_CLIENTS:-}"
