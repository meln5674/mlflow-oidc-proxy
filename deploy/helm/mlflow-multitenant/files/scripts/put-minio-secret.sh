#!/bin/bash -xeu

function put-secret {
    secret_name=$1
    dir=$2
    shift 2
    if kubectl get secret "${secret_name}" ; then
        for field in "$@"; do
            kubectl patch secret "${secret_name}" --patch-file=/dev/stdin <<EOF
        data:
          ${field}: $(cat "${dir}/${field}" | base64 -w0)
EOF
        done
    else
        echo "Secret ${secret_name} doesn't exist, creating whole-cloth"
        ARGS=()
        for field in "$@"; do
            ARGS+=( --from-file "${field}=${dir}/${field}" )
        done
        kubectl create secret generic "${secret_name}" "${ARGS[@]}"
    fi
}

if [ -n "${USER_SECRETS:-}" ]; then
    while read -r user secret_name ; do
        put-secret "${secret_name}" "/tmp/${user}" AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
    done <<< "${USER_SECRETS:-}"
fi
