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
