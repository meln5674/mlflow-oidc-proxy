rm -f /tmp/trust.jks


keytool -import \
    -keystore /tmp/trust.jks \
    -storepass truststore-password \
    -file /opt/bitnami/keycloak/certs/tls.crt \
    -noprompt
kcadm.sh config truststore \
    --trustpass truststore-password /tmp/trust.jks
kcadm.sh config credentials \
    --server "${KEYCLOAK_URL}" \
    --realm master \
    --user admin \
    --password adminPassword \
    --client admin-cli

if [ -z "${USERS_ONLY}" ]; then

if ! kcadm.sh get realms -F realm | grep -q '"'"${REALM}"'"'; then
    kcadm.sh create realms -s realm="${REALM}" -s enabled=true 
fi


while read -r client_id callback ; do
    if stat "/tmp/client-secrets/${client_id}" ; then
        continue
    fi
    
    mkdir -p /tmp/client-secrets
    if ! kcadm.sh get clients \
            -r "${REALM}" \
            -q clientId="${client_id}" \
            -F clientId \
            | tee /dev/stderr \
            | grep -q "${client_id}" \
            ; then
        client_uid=$(
            kcadm.sh create clients \
                -r "${REALM}" \
                -s clientId="${client_id}" \
                -s clientAuthenticatorType=client-secret \
                -s "redirectUris=[\"https://${client_id}.mlflow-oidc-proxy-it.cluster/${callback}\"]"  \
                -i
        )
        kcadm.sh create clients/${client_uid}/client-secret \
            -r "${REALM}"
    else
        client_uid=$(
            kcadm.sh get clients \
                -r "${REALM}" \
                -q clientId="${client_id}" \
                -F id \
                | tee /dev/stderr \
                | grep '"id"' \
                | sed -E 's/.*"id" : "([^"]+)".*/\1/' \
                | tee /dev/stderr
        )
    fi
    kcadm.sh get clients/${client_uid}/client-secret \
        -r "${REALM}" \
        -F value \
        | tee /dev/stderr \
        | grep '"value"' \
        | sed -E 's/.*"value" : "([^"]+)".*/\1/' \
        | tee /dev/stderr \
        > "/tmp/client-secrets/${client_id}"

    roles_scope_id="$(kcadm.sh get client-scopes \
        --format csv \
        -r "${REALM}" \
        -F name,id \
        | tee /dev/stderr \
        | grep -E '^"roles",' \
        | tee /dev/stderr \
        | sed -E 's/^"roles","([^"]+)"/\1/g' \
        | tee /dev/stderr
    )"
    roles_mapper_id="$(kcadm.sh get "client-scopes/${roles_scope_id}/protocol-mappers/models" \
        --format csv \
        -r "${REALM}" \
        -F name,id \
        | tee /dev/stderr \
        | grep -E '^"realm roles",' \
        | tee /dev/stderr \
        | sed -E 's/^"realm roles","([^"]+)"/\1/g' \
        | tee /dev/stderr
    )"
    kcadm.sh update "client-scopes/${roles_scope_id}/protocol-mappers/models/${roles_mapper_id}" \
        -r "${REALM}" \
        -s 'config."id.token.claim"=true'

done <<EOF
jupyterhub hub/oauth_callback
mlflow oauth2/callback
EOF

fi

for tenant in 1 2; do
    if ! kcadm.sh get "roles/tenant-${tenant}" \
            -r "${REALM}" \
            -F name \
            ; then
        kcadm.sh create roles \
            -r "${REALM}" \
            -s name="tenant-${tenant}" \
            -i
    fi
    if ! kcadm.sh get users \
            -r "${REALM}" \
            -q username="tenant-${tenant}" \
            -F username \
            | tee /dev/stderr \
            | grep -q '"'"tenant-${tenant}"'"' \
            ; then
        user_id=$(
            kcadm.sh create users \
                -r "${REALM}" \
                -s username="tenant-${tenant}" \
                -s email="tenant-${tenant}@test.test" \
                -s emailVerified=true \
                -s credentials='[{"type": "password", "value": "test", "temporary": false}]' \
                -s enabled=true
        )
    else
        user_id=$(
            kcadm.sh get users \
                -r "${REALM}" \
                -q username=test \
                -F id \
                | tee /dev/stderr \
                | grep '"id"' \
                | sed -E 's/.*"id" : "([^"]+)".*/\1/' \
                | tee /dev/stderr
        )
    fi

    kcadm.sh add-roles \
        -r "${REALM}" \
        --rolename "tenant-${tenant}" \
        --uusername "tenant-${tenant}"
done
