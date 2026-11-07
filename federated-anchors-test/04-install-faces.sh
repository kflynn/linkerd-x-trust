#!bash

#@SHOW

kubectl --context east create namespace faces
kubectl --context east annotate namespace faces \
    linkerd.io/inject=enabled

helm upgrade --install --kube-context east \
    faces -n faces \
    oci://ghcr.io/buoyantio/faces-chart \
    --set gui.serviceType=LoadBalancer \
    --set backend.errorFraction=0 \
    --set face.errorFraction=0 \
    --set defaultReplicas=2

kubectl --context west create namespace faces
kubectl --context west annotate namespace faces \
    linkerd.io/inject=enabled

helm upgrade --install --kube-context west \
    faces -n faces \
    oci://ghcr.io/buoyantio/faces-chart \
    --set gui.serviceType=LoadBalancer \
    --set backend.errorFraction=0 \
    --set face.errorFraction=0 \
    --set defaultReplicas=2

kubectl --context east rollout status -n faces deploy
kubectl --context west rollout status -n faces deploy
