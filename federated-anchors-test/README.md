# Federated Anchors Test

This is a complete test of federated anchors, start to finish. It will
start up two k3d clusters on the same network, set up flat-network
Linkerd multicluster using federated anchors, install Faces, and then
rotate one cluster's cluster anchor while you watch Faces to make sure it
stays happy. Transient errors in the browser are OK (Faces isn't built to
gracefully drain connections before pods exit) but persistent errors are
not.

```bash
export KUBECONFIG=$HOME/.kube/fed-test.yaml

bash 01-create-certs.sh
bash 02-create-clusters.sh
bash 03-install-linkerd.sh
bash 04-install-faces.sh
```

At this point, `kubectl --context east get svc -n faces` should show you
the `face` Service. If you have working load balancers you can point a
browser to `http://face-service-ip/`; if not, use a port-forward. You
should see grinning faces on blue backgrounds.

At every step below, you should continue to see grinning faces on blue
backgrounds.

```bash
bash 05-setup-multicluster.sh
bash 06-federate-services.sh
bash 07-rotate-east.sh
```
