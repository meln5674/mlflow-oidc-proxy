#!/bin/bash -xeu

if [ -z "${MLFLOW_TRACKING_TOKEN" ]; then
    echo 'MLFLOW_TRACKING_TOKEN not set, navigate to https://mlflow.mlflow-oidc-proxy-it.cluster/oauth2/sign_in to generate your token"
    exit 1
fi

if ! [ -d mlflow-example ]; then
    git clone https://github.com/alfozan/mlflow-example.git
fi
cp /mnt/host/mlflow-oidc-proxy/integration-test/MLflow-example-notebook.ipynb mlflow-example/

pip install --user -r mlflow-example/requirements.txt

cat > mlflow-example/mlflow-config.json <<EOF
{
    "url": "https://mlflow.mlflow-oidc-proxy-it.cluster/tenants/tenant-1/",
    "token": "${MLFLOW_TRACKING_TOKEN}",
    "cert-path": "/etc/ssl/certs/ca-certificates.crt"
}
EOF
