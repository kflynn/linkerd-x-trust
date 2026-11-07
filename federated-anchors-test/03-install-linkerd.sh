#!bash

GATEWAY_API_VERSION=v1.6.3
GATEWAY_API_URL=https://github.com/kubernetes-sigs/gateway-api/releases/download/$GATEWAY_API_VERSION/standard-install.yaml

kubectl --context east create namespace linkerd

linkerd x-trust --context east \
    bundle add --create certs/anchor1.crt
linkerd x-trust --context east \
    identity update --create \
    certs/{east-anchor1.crt,east-id1.crt,east-id1.key}

kubectl --context east apply -f $GATEWAY_API_URL

linkerd --context east install --crds | kubectl apply --context east -f -

linkerd --context east install \
  --set identity.issuer.scheme=kubernetes.io/tls \
  --set identity.externalCA=true \
    | kubectl apply --context east -f -

kubectl --context west create namespace linkerd

linkerd  x-trust --context west \
    bundle add --create certs/anchor1.crt
linkerd  x-trust --context west \
    identity update --create \
    certs/{west-anchor1.crt,west-id1.crt,west-id1.key}

kubectl --context west apply -f $GATEWAY_API_URL

linkerd --context west install --crds | kubectl apply --context west -f -

linkerd --context west install \
  --set identity.issuer.scheme=kubernetes.io/tls \
  --set identity.externalCA=true \
    | kubectl apply --context west -f -

linkerd --context east check
linkerd --context west check
