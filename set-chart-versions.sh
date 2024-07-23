#!/bin/bash -xeu

# This script sets the chart versions, given a destination helm repository, git commit SHA, and optionally a git tag.
# If the tag is empty, each chart version is set to the current version, suffixed with that sha
# If the tag is non-empty, each chart version is set to that tag
# Because the multitenant chart depends on the standalone chart, the provided repo is set as the dependency url
# Finally, the appVersion of each is set to the tag, if present, else the sha, with no prefix or suffix

HELM_REPO=$1
GIT_SHA=$2
GIT_TAG=${3:-}

CHART_DIR=${CHART_DIR:-deploy/helm}
YQ=${YQ:-yq}

CHART_APPVERSION="${GIT_TAG:-${GIT_SHA}}"
if [ -n "${GIT_TAG}" ]; then
  NEW_VERSION_EXPR='"'"${GIT_TAG}"'"'
else
  NEW_VERSION_EXPR='.version + "-'"${GIT_SHA}"'"'
fi
for chart in mlflow-oidc-proxy mlflow-multitenant-deps mlflow-multitenant; do
    ${YQ} -i '.version = '"${NEW_VERSION_EXPR}"'' "${CHART_DIR}/${chart}/Chart.yaml"
done
${YQ} -i '.appVersion = "'"${CHART_APPVERSION}"'"' "${CHART_DIR}/mlflow-oidc-proxy/Chart.yaml"
STANDALONE_CHART_VERSION="$(yq '.version' "${CHART_DIR}/mlflow-oidc-proxy/Chart.yaml")"
${YQ} -i '(.dependencies[] | select(.name == "mlflow-oidc-proxy")).version |= "'"${STANDALONE_CHART_VERSION}"'"' "${CHART_DIR}/mlflow-multitenant/Chart.yaml"
${YQ} -i '(.dependencies[] | select(.name == "mlflow-oidc-proxy")).repository |= "'"${HELM_REPO}"'"' "${CHART_DIR}/mlflow-multitenant/Chart.yaml"
