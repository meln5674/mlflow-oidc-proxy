#!/bin/bash -xeu

function random-alphanumeric {
    len=$1
    tr -dc A-Za-z0-9 </dev/urandom | head -c "${len}"
}

function ensure-random-alphanumeric {
    path=$1
    len=$2
    if ! [ -f "${path}" ] ; then
        random-alphanumeric "${len}" > "${path}"
    fi
}

function policy-for-bucket {
    bucket=$1
    cat <<EOF
{
   "Version": "2012-10-17",
   "Statement": [
      {
         "Effect": "Allow",
         "Action": [
            "s3:ListBucket"
         ],
         "Resource": [
            "arn:aws:s3:::${bucket}"
         ]
      },
      {
         "Effect": "Allow",
         "Action": [
            "s3:GetObject",
            "s3:PutObject",
            "s3:DeleteObject"
         ],
         "Resource": [
            "arn:aws:s3:::${bucket}/*"
         ]
      }
   ]
}
EOF
}

ALIAS=minio
mc alias set "${ALIAS}" "${MINIO_URL}" "${MINIO_USER}" "${MINIO_PASSWORD}"

while ! mc ping "${ALIAS}" --error-count 1 --count 1; do
    echo "Minio is still starting up, waiting..."
done

while read -r user access_key bucket ; do
    access_key_file="/tmp/${user}/AWS_ACCESS_KEY_ID"
    secret_key_file="/tmp/${user}/AWS_SECRET_ACCESS_KEY"
    mkdir -p "/tmp/${user}"
    if ! [ -f "${access_key_file}" ]; then
        echo -n "${access_key}" > "${access_key_file}"
    fi
    access_key="$(cat "${access_key_file}")"
    ensure-random-alphanumeric "${secret_key_file}" 64 
    secret_key="$(cat "${secret_key_file}")"
    if ! mc stat "${ALIAS}/${bucket}" ; then
        mc mb "${ALIAS}/${bucket}"
    fi
    if ! mc admin user info "${ALIAS}" "${access_key}" ; then
        mc admin user add "${ALIAS}" "${access_key}" "${secret_key}"
    fi
    policy="${user}"
    if ! mc admin policy info "${ALIAS}" "${policy}" ; then
        policy-for-bucket "${bucket}" | mc admin policy create "${ALIAS}" "${policy}" /dev/stdin
    fi
    if ! mc admin policy entities "${ALIAS}" --user "${access_key}" | grep -v 'User:' | grep "${policy}"; then 
        mc admin policy attach "${ALIAS}" "${policy}" --user "${access_key}"
    fi
done <<< "${USER_BUCKETS}"
