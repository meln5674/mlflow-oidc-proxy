rm -f /tmp/trust.jks
keytool -import \
    -keystore /tmp/trust.jks \
    -storepass truststore-password \
    -file /opt/bitnami/keycloak/certs/tls.crt \
    -noprompt
kcadm.sh config truststore \
    --trustpass truststore-password /tmp/trust.jks
kcadm.sh config credentials \
    --server https://keycloak.default.svc.cluster.local/ \
    --realm master \
    --user admin \
    --password adminPassword \
    --client admin-cli
if ! kcadm.sh get realms -F realm | grep -q '"integration-test"'; then
    kcadm.sh create realms -s realm=integration-test -s enabled=true 
fi

while read -r client_id callback ; do
    if stat "/tmp/client-secrets/${client_id}" ; then
        continue
    fi
    
    mkdir -p /tmp/client-secrets
    if ! kcadm.sh get clients \
            -r integration-test \
            -q clientId="${client_id}" \
            -F clientId \
            | tee /dev/stderr \
            | grep -q "${client_id}" \
            ; then
        client_uid=$(
            kcadm.sh create clients \
                -r integration-test \
                -s clientId="${client_id}" \
                -s clientAuthenticatorType=client-secret \
                -s "redirectUris=[\"https://${client_id}.mlflow-oidc-proxy-it.cluster/${callback}\"]"  \
                -i
        )
        kcadm.sh create clients/${client_uid}/client-secret \
            -r integration-test
    else
        client_uid=$(
            kcadm.sh get clients \
                -r integration-test \
                -q clientId="${client_id}" \
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
        > "/tmp/client-secrets/${client_id}"
done <<EOF
jupyterhub hub/oauth_callback
mlflow oauth2/callback
EOF

for tenant in 1 2; do
    if ! kcadm.sh get "roles/tenant-${tenant}" \
            -r integration-test \
            -F name \
            ; then
        kcadm.sh create roles \
            -r integration-test \
            -s name="tenant-${tenant}" \
            -i
    fi
    if ! kcadm.sh get users \
            -r integration-test \
            -q username=test \
            -F username \
            | tee /dev/stderr \
            | grep -q '"test"' \
            ; then
        user_id=$(
            kcadm.sh create users \
                -r integration-test \
                -s username=test \
                -s email=test@test.test \
                -s realmRoles='["tenant-'"${tenant}"'"]' \
                -s emailVerified=true \
                -s credentials='[{"type": "password", "value": "test", "temporary": false}]' \
                -s enabled=true
        )
    else
        user_id=$(
            kcadm.sh get users \
                -r integration-test \
                -q username=test \
                -F id \
                | tee /dev/stderr \
                | grep '"id"' \
                | sed -E 's/.*"id" : "([^"]+)".*/\1/' \
                | tee /dev/stderr
        )
    fi
done
