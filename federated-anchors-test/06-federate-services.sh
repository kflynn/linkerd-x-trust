#!bash

#@SHOW

kubectl --context east -n faces label \
    svc/smiley mirror.linkerd.io/federated=member
kubectl --context west -n faces label \
    svc/smiley mirror.linkerd.io/federated=member
kubectl --context east -n faces label \
    svc/color mirror.linkerd.io/federated=member
kubectl --context west -n faces label \
    svc/color mirror.linkerd.io/federated=member

kubectl --context east -n faces get svc
kubectl --context west -n faces get svc

linkerd --context east diagnostics endpoints \
    smiley-federated.faces.svc.cluster.local
linkerd --context west diagnostics endpoints \
    smiley-federated.faces.svc.cluster.local

kubectl --context east set env -n faces deploy/face \
          SMILEY_SERVICE=smiley-federated \
          COLOR_SERVICE=color-federated
kubectl rollout status -n faces deploy/face

kubectl --context east delete -n faces deploy smiley
kubectl --context east delete -n faces deploy color

linkerd --context east diagnostics endpoints \
    smiley-federated.faces.svc.cluster.local
linkerd --context west diagnostics endpoints \
    color-federated.faces.svc.cluster.local

