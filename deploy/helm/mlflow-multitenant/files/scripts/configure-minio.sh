#!/bin/bash -xeu

set -o pipefail

function random-alphanumeric {
    len=$1
    (tr -dc A-Za-z0-9 </dev/urandom || true) | head -c "${len}"
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
while ! ALIAS_SET_LOG=$(mc alias set "${ALIAS}" "${MINIO_URL}" "${MINIO_USER}" "${MINIO_PASSWORD}" 2>&1 | tee /dev/stderr) ; do
    if grep -q 'Server not initialized, please try again.' <<< "${ALIAS_SET_LOG}" ; then
        echo 'Minio is having a moment, please wait...'
        sleep 15
    else
        exit 1
    fi
done

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

        while ! mc admin policy info "${ALIAS}" "${policy}" ; do
            echo "Waiting for policy visibility..."
            sleep 5
        done
    fi
    if ! mc admin policy entities "${ALIAS}" --user "${access_key}" | grep -v 'User:' | grep "${policy}"; then 
        # Minio has a defect where policies are created, and possibly even show up as existing, but fail to attach.
        # This seems to be exaserbated when the system is under heavy load, and is likely due to replication lag.
        # This is a brute force workaround where we check if the error message contains the "does not exist" message,
        # and try again after a few seconds, but fail as normal if that message is not present
        while ! ATTACH_LOG=$(mc admin policy attach "${ALIAS}" "${policy}" --user "${access_key}" 2>&1 | tee /dev/stderr) ; do
           if grep -q 'Specified canned policy does not exist' <<< "${ATTACH_LOG}" ; then
               echo 'Minio is having a moment, please wait...'
               sleep 15
           else
               exit 1
           fi
       done
    fi
done <<< "${USER_BUCKETS}"
