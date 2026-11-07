#!bash

#@SHOW

linkerd --context east multicluster install \
          --values east-mc-values.yaml \
        | kubectl --context east apply -f -

linkerd --context west multicluster install \
          --values west-mc-values.yaml \
        | kubectl --context west apply -f -

linkerd --context east multicluster check
linkerd --context west multicluster check

linkerd --context east multicluster link-gen \
          --cluster-name=east > east-link.yaml
linkerd --context west multicluster link-gen \
          --cluster-name=west > west-link.yaml

kubectl --context east apply -f west-link.yaml
kubectl --context west apply -f east-link.yaml
