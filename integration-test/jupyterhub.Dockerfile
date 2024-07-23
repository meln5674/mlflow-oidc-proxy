ARG PROXY_CACHE=
ARG BASE_IMAGE_REPO=jupyterhub/k8s-singleuser-sample
ARG BASE_IMAGE_TAG=2.0.0

FROM ${PROXY_CACHE}${BASE_IMAGE_REPO}:${BASE_IMAGE_TAG}

USER 0

RUN apt-get update \
 && apt-get install -y wget unzip graphviz curl

#  && pip install ipython-oidc-client \
#  && jupyter nbextension install --py ipython_oidc_client \
#  && jupyter nbextension enable --py ipython_oidc_client \
#  && jupyter serverextension enable --py ipython_oidc_client

RUN pip install papermill

ARG MLFLOW_VERSION=2.13.0
RUN git clone https://github.com/alfozan/mlflow-example.git \
 && sed -i 's/mlflow>=.*/mlflow=='"${MLFLOW_VERSION}"'/' mlflow-example/requirements.txt \
 && pip install --user -r mlflow-example/requirements.txt

USER jovyan

ENV PATH=/home/jovyan/.local/bin:${PATH}
