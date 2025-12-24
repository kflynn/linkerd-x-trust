# linkerd-x-trust

This is an **experimental** extension to the Linkerd CLI to manage and
view the trust hierarchy. It's believed to be safe as long as your RBAC
is set up reasonably, and it is distributed in the hope that it will be
useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
[LICENSE](LICENSE) file for details.

## tl;dr:

Build the extension with `make`, then copy the `linkerd-x-trust` binary
somewhere in your `PATH`. After that, the `linkerd` CLI will have access
to the `x-trust` command. Run

```bash
linkerd x-trust --help
```

for full usage information. When getting started, the most useful command
is definitely

```bash
linkerd x-trust chain
```

to get an overview of what your trust hierarchy looks like.

## Bootstrapping a Cluster

Another example: bootstrapping a completely empty cluster from the CLI:

First, generate a trust anchor and an identity issuer.

```bash
rm -rf certs
mkdir certs

linkerd x-trust anchor generate \
  certs/anchor.{crt,key}

linkerd x-trust issuer generate \
  certs/anchor.{crt,key} \
  certs/issuer.{crt,key}
```

Next, use these to bootstrap the trust hierarchy that Linkerd will use.

```bash
linkerd x-trust bundle add --create certs/anchor.crt
linkerd x-trust identity update --create certs/issuer.{crt,key}
```

Finally, install Linkerd with the external CA option. (Obviously you
could use Helm for this just as easily.)

```bash
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.3.0/standard-install.yaml

linkerd install --crds | kubectl apply -f -

linkerd install \
  --set identity.issuer.scheme=kubernetes.io/tls \
  --set identity.externalCA=true \
    | kubectl apply -f -
```

At this point Linkerd should be up and running:

```bash
linkerd check
```

**NOTE:** As a guard against trying to use this in production, by default
`linkerd x-trust` will generate a 30-day trust anchor and a 14-day
identity issuer.

## Using x-trust with cert-manager

### Bootstrapping

First, install cert-manager. Do this _before_ installing Linkerd.

```bash
helm repo add jetstack https://charts.jetstack.io --force-update

helm install \
  cert-manager jetstack/cert-manager \
  --namespace cert-manager \
  --create-namespace \
  --set crds.enabled=true

kubectl rollout status -n cert-manager deploy
```

Next, create the `linkerd` namespace so that cert-manager has a place to
write the identity issuer Secret.

```bash
kubectl create namespace linkerd
```

Use `linkerd x-trust cm bootstrap` to generate bootstrap cert-manager
manifests. **YOU WILL NEED TO EDIT THE BOOTSTRAP MANIFESTS BEFORE
APPLYING THEM TO YOUR CLUSTER.** This is deliberate: it's very important
that you review the cert-manager configuration and make sure that what
you apply is appropriate for your organization's security needs.

```bash
linkerd x-trust cm bootstrap > cert-manager-bootstrap.yaml
$EDITOR cert-manager-bootstrap.yaml
kubectl apply -f cert-manager-bootstrap.yaml
```

Check to make sure all is well:

```bash
kubectl get secret -n cert-manager linkerd-trust-anchor
kubectl get secret -n linkerd linkerd-identity-issuer
```

Bootstrap the Linkerd trust bundle:

```bash
linkerd x-trust bundle add --create \
  --secret linkerd-trust-anchor --secret-namespace cert-manager
linkerd x-trust bundle
linkerd x-trust identity
```

Finally, install Linkerd with the external CA option. (Obviously you
could use Helm for this just as easily.)

```bash
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.3.0/standard-install.yaml

linkerd install --crds | kubectl apply -f -

linkerd install \
  --set identity.issuer.scheme=kubernetes.io/tls \
  --set identity.externalCA=true \
    | kubectl apply -f -
```

At this point, Linkerd should be up and running.

```bash
linkerd check
linkerd x-trust chain
```

### Rotating the trust anchor

First, use `cmctl` to trigger a certificate rotation for the trust
anchor.

```bash
cmctl renew linkerd-trust-anchor -n cert-manager
```

Next, use `linkerd x-trust bundle add` to add the new trust anchor to
the Linkerd trust bundle.

```bash
linkerd x-trust bundle add \
  --secret linkerd-trust-anchor --secret-namespace cert-manager
linkerd x-trust chain
```

Restart the Linkerd control plane.

```bash
kubectl rollout restart deploy -n linkerd
kubectl rollout status deploy -n linkerd
```

Restart the data planes, however you normally do that in your cluster.

```bash
for namespace in ... ...; do
  kubectl rollout restart deploy -n $namespace
  kubectl rollout status deploy -n $namespace
done
```

Next, rotate the identity issuer certificate.

```bash
cmctl renew linkerd-identity-issuer -n linkerd
linkerd x-trust chain
```

Restart the Linkerd control plane and data planes again.

```bash
kubectl rollout restart deploy -n linkerd
kubectl rollout status deploy -n linkerd

for namespace in ... ...; do
  kubectl rollout restart deploy -n $namespace
  kubectl rollout status deploy -n $namespace
done

linkerd x-trust chain
```

Drop the original trust anchor from the trust bundle. The easiest way to
do this is to look at the output of `linkerd x-trust chain` to find the
Subject Key ID (SKI) of the original trust anchor, then:

```bash
linkerd x-trust bundle remove --id $originalSKI
linkerd x-trust chain
```

Finish up by restarting the world.

```bash
kubectl rollout restart deploy -n linkerd
kubectl rollout status deploy -n linkerd

for namespace in ... ...; do
  kubectl rollout restart deploy -n $namespace
  kubectl rollout status deploy -n $namespace
done
```

### Rotating the identity issuer

Use `cmctl` to trigger a certificate rotation for the identity issuer.

```bash
cmctl renew linkerd-identity-issuer -n linkerd
linkerd x-trust chain
```

Running `x-trust chain` will probably show a mismatch between the
identity issuer persisted in the `linkerd-identity-issuer` Secret and the
one served by the identity controller. You can either wait a couple of
minutes for the identity controller to notice the new certificate, or you
can restart the control plane to speed things up:

```bash
kubectl rollout restart deploy -n linkerd
kubectl rollout status deploy -n linkerd
```

After that, your workloads will automatically start picking up the new
identity issuer as their proxies periodically refresh their workload
certificates over (by default) the next couple of days. You can also
restart all your data planes to speed this up, however you need to do
that for your application (usually doing a `kubectl rollout restart` in
every application namespace).

## Linkerd Extensions

The [Linkerd service mesh](https://linkerd.io) includes a simple but
powerful extension mechanism: anything in `PATH` with the name
`linkerd-$extension` is automatically available to the CLI as `linkerd
$extension`. (This is basically the same mechanism as extensions for
`kubectl`.)

### Building the Extension

`linkerd-x-trust` is written in Go using toolchain 1.25.5. Assuming you
have go correctly set up:

- To build, just run `make`.

   - If needed, you can set `GOARCH` and `GOOS` as needed (e.g. `make GOOS=linux GOARCH=amd64`
     to cross-compile for an x86 Kubernetes environment on a Mac).

- To clean everything up, use `make clean`.

### Installing the Extension

After building the extension, copy the `linkerd-x-trust` binary anywhere
in your `$PATH`. The `linkerd` CLI will automatically pick it up.

## The Sources

The sources for the CLI part of this extension are in the `cmd`
directory. Start reading with `cmd/main.go`.

More details about writing a CLI extension are available in
[EXTENSIONS.md] in the main [Linkerd2 repo]. `linkerd-x-trust` isn't
quite compliant with this guide, since it does _not_ implement the
required `install` and `uninstall` commands -- there's nothing for it to
install or uninstall!

It also doesn't currently implement the `check` command, but this is
planned.

[EXTENSIONS.md]: https://github.com/linkerd/linkerd2/blob/main/EXTENSIONS.md
[Linkerd2 repo]: https://github.com/linkerd/linkerd2/
