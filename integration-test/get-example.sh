#!/bin/bash -xeu

if [ -z "${MLFLOW_TRACKING_TOKEN:-}" ] && [ -z "${MLFLOW_TRACKING_CLIENT_CERT_AND_KEY:-}" ]; then
    echo 'MLFLOW_TRACKING_TOKEN and MLFLOW_TRACKING_CLIENT_CERT_AND_KEY not set, navigate to https://mlflow.mlflow-oidc-proxy-it.cluster/oauth2/sign_in to generate your token'
    exit 1
fi

rm -rf mlflow-example
rm -f get-example-done*
git clone https://github.com/alfozan/mlflow-example.git
cp /mnt/host/mlflow-oidc-proxy/integration-test/MLflow-example-notebook.ipynb mlflow-example/

pip install --user -r mlflow-example/requirements.txt

if [ -n "${MLFLOW_TRACKING_CLIENT_CERT_AND_KEY:-}" ]; then
    MLFLOW_TRACKING_CLIENT_CERT_PATH="$(mktemp)"
    cat > "${MLFLOW_TRACKING_CLIENT_CERT_PATH}" <<< "${MLFLOW_TRACKING_CLIENT_CERT_AND_KEY}"
fi

cat > mlflow-example/mlflow-config.json <<EOF
{
    "url": "${MLFLOW_TRACKING_URI}",
    "cert-path": "/etc/ssl/certs/ca-certificates.crt",
    "token": "${MLFLOW_TRACKING_TOKEN:-}",
    "client-cert-path": "${MLFLOW_TRACKING_CLIENT_CERT_PATH:-}"
}
EOF

touch get-example-done-${TEST_TS}
