package utils

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"

	"github.com/linkerd/linkerd2/pkg/k8s"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Utilities stolen from linkerd/linkerd2/cli/cmd/identity.go

type certificate struct {
	pod         string
	container   string
	Certificate []*x509.Certificate
	err         error
}

func GetCertificate(k8sAPI *k8s.KubernetesAPI, pods []corev1.Pod, portName string, emitLog bool) []certificate {
	var certificates []certificate
	for _, pod := range pods {
		container, err := GetContainerWithPort(pod, portName)
		if err != nil {
			certificates = append(certificates, certificate{
				pod: pod.GetName(),
				err: err,
			})
			return certificates
		}
		cert, err := GetContainerCertificate(k8sAPI, pod, container, portName, emitLog)
		certificates = append(certificates, certificate{
			pod:         pod.GetName(),
			container:   container.Name,
			Certificate: cert,
			err:         err,
		})
	}
	return certificates
}

func GetContainerWithPort(pod corev1.Pod, portName string) (corev1.Container, error) {
	var container corev1.Container
	if pod.Status.Phase != corev1.PodRunning {
		return container, fmt.Errorf("pod not running: %s", pod.GetName())
	}

	containers := append(pod.Spec.InitContainers, pod.Spec.Containers...)
	for _, c := range containers {
		if c.Name != k8s.ProxyContainerName {
			continue
		}
		for _, p := range c.Ports {
			if p.Name == portName {
				return c, nil
			}
		}
	}
	return container, fmt.Errorf("failed to find %s port in %s container for given pod spec", portName, k8s.ProxyContainerName)
}

func GetContainerCertificate(k8sAPI *k8s.KubernetesAPI, pod corev1.Pod, container corev1.Container, portName string, emitLog bool) ([]*x509.Certificate, error) {
	portForward, err := k8s.NewContainerMetricsForward(k8sAPI, pod, container, emitLog, portName)
	if err != nil {
		return nil, err
	}

	defer portForward.Stop()
	if err = portForward.Init(); err != nil {
		fmt.Fprintf(os.Stderr, "Error running port-forward: %s\n", err)
		return nil, err
	}

	certURL := portForward.URLFor("")
	return GetCertResponse(certURL, pod)
}

func GetCertResponse(url string, pod corev1.Pod) ([]*x509.Certificate, error) {
	serverName, err := k8s.PodIdentity(&pod)
	if err != nil {
		return nil, err
	}
	connURL := strings.TrimPrefix(url, "http://")
	conn, err := tls.Dial("tcp", connURL, &tls.Config{
		// We want to connect directly to a proxy port to dump its certificate. We don't necessarily
		// want to verify the server's certificate, since this is purely for diagnostics and may be
		// used when a proxy's issuer doesn't match the control plane's trust root.
		//nolint:gosec
		InsecureSkipVerify: true,
		ServerName:         serverName,
	})

	if err != nil {
		return nil, err
	}

	cert := conn.ConnectionState().PeerCertificates
	return cert, nil
}

func GetPods(ctx context.Context, clientset kubernetes.Interface, namespace string, selector string, args []string) ([]corev1.Pod, error) {
	if len(args) > 0 {
		var pods []corev1.Pod
		for _, arg := range args {
			pod, err := clientset.CoreV1().Pods(namespace).Get(ctx, arg, metav1.GetOptions{})
			if err != nil {
				return nil, err
			}
			pods = append(pods, *pod)
		}
		return pods, nil
	}

	podList, err := clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: selector,
	})
	if err != nil {
		return nil, err
	}

	return podList.Items, nil
}

func GetWorkloadCertFromIdentity(ctx context.Context, k8sAPI *k8s.KubernetesAPI, namespace string) (*x509.Certificate, *x509.Certificate, error) {
	// Find the linkerd-identity pod
	pods, err := k8sAPI.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: "linkerd.io/control-plane-component=identity",
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to list identity pods: %w", err)
	}

	if len(pods.Items) == 0 {
		return nil, nil, fmt.Errorf("no linkerd-identity pods found in namespace %s", namespace)
	}

	pod := pods.Items[0]

	// Get the container
	container, err := GetContainerWithPort(pod, k8s.ProxyAdminPortName)
	if err != nil {
		return nil, nil, err
	}

	// Port-forward to the proxy and get certificates
	certs, err := GetContainerCertificate(k8sAPI, pod, container, k8s.ProxyAdminPortName, false)
	if err != nil {
		return nil, nil, err
	}

	if len(certs) < 2 {
		return nil, nil, fmt.Errorf("expected at least 2 certificates from identity pod, got %d", len(certs))
	}

	// First cert is the workload cert, second is the issuer
	return certs[0], certs[1], nil
}
