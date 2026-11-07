#!bash

#@SHOW

cd certs

linkerd x-trust --context east \
   issuer generate anchor1.crt anchor1.key \
   --identity "east-anchor.linkerd.cluster.local" \
   --pathlen 1 \
   east-anchor2.crt east-anchor2.key

linkerd x-trust --context east \
   issuer generate east-anchor2.crt east-anchor2.key \
   --identity "east-issuer.linkerd.cluster.local" \
   east-id2.crt east-id2.key

linkerd x-trust --context east \
   identity update \
   east-anchor1.crt east-id1.crt east-anchor2.crt east-id2.crt \
   east-id1.key

kubectl --context east rollout restart -n linkerd deploy
kubectl --context east rollout status -n linkerd deploy
kubectl --context east rollout restart -n faces deploy
kubectl --context east rollout status -n faces deploy

linkerd x-trust --context east \
   identity update \
   east-anchor1.crt east-id1.crt east-anchor2.crt east-id2.crt \
   east-id2.key

kubectl --context east rollout restart -n linkerd deploy
kubectl --context east rollout status -n linkerd deploy
kubectl --context east rollout restart -n faces deploy
kubectl --context east rollout status -n faces deploy

linkerd x-trust --context east \
   identity update \
   east-anchor2.crt east-id2.crt \
   east-id2.key

kubectl --context east rollout restart -n linkerd deploy
kubectl --context east rollout status -n linkerd deploy
kubectl --context east rollout restart -n faces deploy
kubectl --context east rollout status -n faces deploy
