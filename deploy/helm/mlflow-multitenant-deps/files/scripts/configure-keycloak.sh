#!/bin/bash -xeu

if ! stat "/tmp/cookie-secret" ; then
    tr -dc A-Za-z0-9 </dev/urandom | head -c 64 > /tmp/cookie-secret
fi

# rm -f /tmp/trust.jks
# 
# keytool -import \
#     -keystore /tmp/trust.jks \
#     -storepass truststore-password \
#     -file /opt/bitnami/keycloak/certs/tls.crt \
#     -noprompt
# kcadm.sh config truststore \
#     --trustpass truststore-password /tmp/trust.jks
# kcadm.sh config credentials \
#     --server https://keycloak.default.svc.cluster.local/ \
#     --realm master \
#     --user admin \
#     --password adminPassword \
#     --client admin-cli
if ! kcadm.sh get realms -F realm | grep -q '"'"${MLFLOW_REALM}"'"'; then
    kcadm.sh create realms -s realm="${MLFLOW_REALM}" -s enabled=true 
fi

if stat "/tmp/client-id" && [ "$(cat /tmp/client-id)" == "${MLFLOW_CLIENT_ID}" ] && stat "/tmp/client-secret ; then
    echo "Client ID/Secret appears to already be configured, skipping. Delete the kubernetes secret and re-run the chart if you wish to regenerate the secret"
    exit 0
fi

if ! kcadm.sh get clients \
        -r integration-test \
        -q clientId="${MLFLOW_CLIENT_ID}" \
        -F clientId \
        | tee /dev/stderr \
        | grep -q "${MLFLOW_CLIENT_ID}" \
        ; then
    client_uid=$(
        kcadm.sh create clients \
            -r integration-test \
            -s clientId="${MLFLOW_CLIENT_ID}" \
            -s clientAuthenticatorType=client-secret \
            -s "redirectUris=[\"${MLFLOW_CALLBACK_URL}\"]"  \
            -i
    )
    kcadm.sh create clients/${client_uid}/client-secret \
        -r integration-test
else
    client_uid=$(
        kcadm.sh get clients \
            -r integration-test \
            -q clientId="${MLFLOW_CLIENT_ID}" \
            -F id \
            | tee /dev/stderr \
            | grep '"id"' \
            | sed -E 's/.*"id" : "([^"]+)".*/\1/' \
            | tee /dev/stderr
    )
fi
kcadm.sh get clients/${client_uid}/client-secret \
    -r integration-test \
    -F value \
    | tee /dev/stderr \
    | grep '"value"' \
    | sed -E 's/.*"value" : "([^"]+)".*/\1/' \
    | tee /dev/stderr \
    > "/tmp/client-secret
