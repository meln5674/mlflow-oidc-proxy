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

if [ -n "${USER_SECRETS:-}" ]; then
    while read -r user secret_name ; do
        get-secret "${secret_name}" "/tmp/${user}" AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
    done <<< "${USER_SECRETS:-}"
fi
