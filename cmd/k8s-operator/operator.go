// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

// tailscale-operator provides a way to expose services running in a Kubernetes
// cluster to your Tailnet.
package main

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/go-logr/zapr"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/oauth2/clientcredentials"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	kzap "sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/manager/signals"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"tailscale.com/client/tailscale"
	"tailscale.com/hostinfo"
	"tailscale.com/ipn"
	"tailscale.com/ipn/store/kubestore"
	"tailscale.com/tsnet"
	"tailscale.com/types/logger"
	"tailscale.com/version"
)

func main() {
	// Required to use our client API. We're fine with the instability since the
	// client lives in the same repo as this code.
	tailscale.I_Acknowledge_This_API_Is_Unstable = true

	var (
		tsNamespace       = defaultEnv("OPERATOR_NAMESPACE", "")
		tslogging         = defaultEnv("OPERATOR_LOGGING", "info")
		image             = defaultEnv("PROXY_IMAGE", "tailscale/tailscale:latest")
		priorityClassName = defaultEnv("PROXY_PRIORITY_CLASS_NAME", "")
		tags              = defaultEnv("PROXY_TAGS", "tag:k8s")
	)

	var opts []kzap.Opts
	switch tslogging {
	case "info":
		opts = append(opts, kzap.Level(zapcore.InfoLevel))
	case "debug":
		opts = append(opts, kzap.Level(zapcore.DebugLevel))
	case "dev":
		opts = append(opts, kzap.UseDevMode(true), kzap.Level(zapcore.DebugLevel))
	}
	zlog := kzap.NewRaw(opts...).Sugar()
	logf.SetLogger(zapr.NewLogger(zlog.Desugar()))

	s, tsClient := initTSNet(zlog)
	defer s.Close()
	restConfig := config.GetConfigOrDie()
	maybeLaunchAPIServerProxy(zlog, restConfig, s)
	runReconcilers(zlog, s, tsNamespace, restConfig, tsClient, image, priorityClassName, tags)
}

// initTSNet initializes the tsnet.Server and logs in to Tailscale. It uses the
// CLIENT_ID_FILE and CLIENT_SECRET_FILE environment variables to authenticate
// with Tailscale.
func initTSNet(zlog *zap.SugaredLogger) (*tsnet.Server, *tailscale.Client) {
	hostinfo.SetApp("k8s-operator")
	var (
		clientIDPath     = defaultEnv("CLIENT_ID_FILE", "")
		clientSecretPath = defaultEnv("CLIENT_SECRET_FILE", "")
		hostname         = defaultEnv("OPERATOR_HOSTNAME", "tailscale-operator")
		kubeSecret       = defaultEnv("OPERATOR_SECRET", "")
		operatorTags     = defaultEnv("OPERATOR_INITIAL_TAGS", "tag:k8s-operator")
	)
	startlog := zlog.Named("startup")
	if clientIDPath == "" || clientSecretPath == "" {
		startlog.Fatalf("CLIENT_ID_FILE and CLIENT_SECRET_FILE must be set")
	}
	clientID, err := os.ReadFile(clientIDPath)
	if err != nil {
		startlog.Fatalf("reading client ID %q: %v", clientIDPath, err)
	}
	clientSecret, err := os.ReadFile(clientSecretPath)
	if err != nil {
		startlog.Fatalf("reading client secret %q: %v", clientSecretPath, err)
	}
	credentials := clientcredentials.Config{
		ClientID:     string(clientID),
		ClientSecret: string(clientSecret),
		TokenURL:     "https://login.tailscale.com/api/v2/oauth/token",
	}
	tsClient := tailscale.NewClient("-", nil)
	tsClient.HTTPClient = credentials.Client(context.Background())

	s := &tsnet.Server{
		Hostname: hostname,
		Logf:     zlog.Named("tailscaled").Debugf,
	}
	if kubeSecret != "" {
		st, err := kubestore.New(logger.Discard, kubeSecret)
		if err != nil {
			startlog.Fatalf("creating kube store: %v", err)
		}
		s.Store = st
	}
	if err := s.Start(); err != nil {
		startlog.Fatalf("starting tailscale server: %v", err)
	}
	lc, err := s.LocalClient()
	if err != nil {
		startlog.Fatalf("getting local client: %v", err)
	}

	ctx := context.Background()
	loginDone := false
	machineAuthShown := false
waitOnline:
	for {
		startlog.Debugf("querying tailscaled status")
		st, err := lc.StatusWithoutPeers(ctx)
		if err != nil {
			startlog.Fatalf("getting status: %v", err)
		}
		switch st.BackendState {
		case "Running":
			break waitOnline
		case "NeedsLogin":
			if loginDone {
				break
			}
			caps := tailscale.KeyCapabilities{
				Devices: tailscale.KeyDeviceCapabilities{
					Create: tailscale.KeyDeviceCreateCapabilities{
						Reusable:      false,
						Preauthorized: true,
						Tags:          strings.Split(operatorTags, ","),
					},
				},
			}
			authkey, _, err := tsClient.CreateKey(ctx, caps)
			if err != nil {
				startlog.Fatalf("creating operator authkey: %v", err)
			}
			if err := lc.Start(ctx, ipn.Options{
				AuthKey: authkey,
			}); err != nil {
				startlog.Fatalf("starting tailscale: %v", err)
			}
			if err := lc.StartLoginInteractive(ctx); err != nil {
				startlog.Fatalf("starting login: %v", err)
			}
			startlog.Debugf("requested login by authkey")
			loginDone = true
		case "NeedsMachineAuth":
			if !machineAuthShown {
				startlog.Infof("Machine approval required, please visit the admin panel to approve")
				machineAuthShown = true
			}
		default:
			startlog.Debugf("waiting for tailscale to start: %v", st.BackendState)
		}
		time.Sleep(time.Second)
	}
	return s, tsClient
}

// runReconcilers starts the controller-runtime manager and registers the
// ServiceReconciler. It blocks forever.
func runReconcilers(zlog *zap.SugaredLogger, s *tsnet.Server, tsNamespace string, restConfig *rest.Config, tsClient *tailscale.Client, image, priorityClassName, tags string) {
	var (
		isDefaultLoadBalancer = defaultBool("OPERATOR_DEFAULT_LOAD_BALANCER", false)
	)
	startlog := zlog.Named("startReconcilers")
	// For secrets and statefulsets, we only get permission to touch the objects
	// in the controller's own namespace. This cannot be expressed by
	// .Watches(...) below, instead you have to add a per-type field selector to
	// the cache that sits a few layers below the builder stuff, which will
	// implicitly filter what parts of the world the builder code gets to see at
	// all.
	nsFilter := cache.ByObject{
		Field: client.InNamespace(tsNamespace).AsSelector(),
	}
	mgr, err := manager.New(restConfig, manager.Options{
		Cache: cache.Options{
			ByObject: map[client.Object]cache.ByObject{
				&corev1.Secret{}:      nsFilter,
				&appsv1.StatefulSet{}: nsFilter,
			},
		},
	})
	if err != nil {
		startlog.Fatalf("could not create manager: %v", err)
	}

	svcFilter := handler.EnqueueRequestsFromMapFunc(serviceHandler)
	svcChildFilter := handler.EnqueueRequestsFromMapFunc(managedResourceHandlerForType("svc"))
	eventRecorder := mgr.GetEventRecorderFor("tailscale-operator")
	ssr := &tailscaleSTSReconciler{
		Client:                 mgr.GetClient(),
		tsnetServer:            s,
		tsClient:               tsClient,
		defaultTags:            strings.Split(tags, ","),
		operatorNamespace:      tsNamespace,
		proxyImage:             image,
		proxyPriorityClassName: priorityClassName,
	}
	err = builder.
		ControllerManagedBy(mgr).
		Named("service-reconciler").
		Watches(&corev1.Service{}, svcFilter).
		Watches(&appsv1.StatefulSet{}, svcChildFilter).
		Watches(&corev1.Secret{}, svcChildFilter).
		Complete(&ServiceReconciler{
			ssr:                   ssr,
			Client:                mgr.GetClient(),
			logger:                zlog.Named("service-reconciler"),
			isDefaultLoadBalancer: isDefaultLoadBalancer,
		})
	if err != nil {
		startlog.Fatalf("could not create controller: %v", err)
	}
	ingressChildFilter := handler.EnqueueRequestsFromMapFunc(managedResourceHandlerForType("ingress"))
	err = builder.
		ControllerManagedBy(mgr).
		For(&networkingv1.Ingress{}).
		Watches(&appsv1.StatefulSet{}, ingressChildFilter).
		Watches(&corev1.Secret{}, ingressChildFilter).
		Watches(&corev1.Service{}, ingressChildFilter).
		Complete(&IngressReconciler{
			ssr:      ssr,
			recorder: eventRecorder,
			Client:   mgr.GetClient(),
			logger:   zlog.Named("ingress-reconciler"),
		})
	if err != nil {
		startlog.Fatalf("could not create controller: %v", err)
	}

	startlog.Infof("Startup complete, operator running, version: %s", version.Long())
	if err := mgr.Start(signals.SetupSignalHandler()); err != nil {
		startlog.Fatalf("could not start manager: %v", err)
	}
}

type tsClient interface {
	CreateKey(ctx context.Context, caps tailscale.KeyCapabilities) (string, *tailscale.Key, error)
	DeleteDevice(ctx context.Context, nodeStableID string) error
}

func isManagedResource(o client.Object) bool {
	ls := o.GetLabels()
	return ls[LabelManaged] == "true"
}

func isManagedByType(o client.Object, typ string) bool {
	ls := o.GetLabels()
	return isManagedResource(o) && ls[LabelParentType] == typ
}

func parentFromObjectLabels(o client.Object) types.NamespacedName {
	ls := o.GetLabels()
	return types.NamespacedName{
		Namespace: ls[LabelParentNamespace],
		Name:      ls[LabelParentName],
	}
}
func managedResourceHandlerForType(typ string) handler.MapFunc {
	return func(_ context.Context, o client.Object) []reconcile.Request {
		if !isManagedByType(o, typ) {
			return nil
		}
		return []reconcile.Request{
			{NamespacedName: parentFromObjectLabels(o)},
		}
	}

}

func serviceHandler(_ context.Context, o client.Object) []reconcile.Request {
	if isManagedByType(o, "svc") {
		// If this is a Service managed by a Service we want to enqueue its parent
		return []reconcile.Request{{NamespacedName: parentFromObjectLabels(o)}}

	}
	if isManagedResource(o) {
		// If this is a Servce managed by a resource that is not a Service, we leave it alone
		return nil
	}
	// If this is not a managed Service we want to enqueue it
	return []reconcile.Request{
		{
			NamespacedName: types.NamespacedName{
				Namespace: o.GetNamespace(),
				Name:      o.GetName(),
			},
		},
	}

}
