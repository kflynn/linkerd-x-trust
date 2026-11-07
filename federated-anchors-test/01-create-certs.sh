#!bash

#@SHOW

cd certs
rm *

linkerd x-trust anchor generate --pathlen 2 \
   anchor1.crt anchor1.key

linkerd x-trust issuer generate anchor1.crt anchor1.key \
   --identity "east-anchor.linkerd.cluster.local" \
   --pathlen 1 \
   east-anchor1.crt east-anchor1.key

linkerd x-trust issuer generate anchor1.crt anchor1.key \
   --identity "west-anchor.linkerd.cluster.local" \
   --pathlen 1 \
   west-anchor1.crt west-anchor1.key

linkerd x-trust issuer generate east-anchor1.crt east-anchor1.key \
   --identity "east-issuer.linkerd.cluster.local" \
   east-id1.crt east-id1.key

linkerd x-trust issuer generate west-anchor1.crt west-anchor1.key \
   --identity "west-issuer.linkerd.cluster.local" \
   west-id1.crt west-id1.key
