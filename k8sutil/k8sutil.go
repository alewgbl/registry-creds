package k8sutil

import (
	"time"

	"github.com/Sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
	coreType "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/pkg/api/v1"
	"k8s.io/client-go/pkg/fields"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

// KubeInterface abstracts the k8s api
type KubeInterface interface {
	Secrets(namespace string) coreType.SecretInterface
	Namespaces() coreType.NamespaceInterface
	ServiceAccounts(namespace string) coreType.ServiceAccountInterface
	Core() coreType.CoreV1Interface
}

// UtilInterface is the struct behind
type UtilInterface struct {
	Kclient    KubeInterface
	MasterHost string
	Log        logrus.FieldLogger
}

// New creates a new instance of k8sutil
func New(kubeCfgFile, masterHost string) (*UtilInterface, error) {
	log := logrus.WithField("function", "newKubeClient")
	client, err := newKubeClient(kubeCfgFile)
	if err != nil {
		log.Fatalf("Could not init Kubernetes client! [%s]", err)
	}

	k := &UtilInterface{
		Kclient:    client,
		MasterHost: masterHost,
		Log:        logrus.WithField("struct", "UtilInterface"),
	}

	return k, nil
}

// newKubeClient creates a new instance of the kubernetes API client
func newKubeClient(kubeCfgFile string) (KubeInterface, error) {
	log := logrus.WithField("function", "newKubeClient")
	var client *kubernetes.Clientset
	// Should we use in cluster or out of cluster config
	if len(kubeCfgFile) == 0 {
		log.Info("Using InCluster k8s config")
		cfg, err := rest.InClusterConfig()
		if err != nil {
			return nil, err
		}

		client, err = kubernetes.NewForConfig(cfg)
		if err != nil {
			return nil, err
		}
	} else {
		log.Infof("Using OutOfCluster k8s config with kubeConfigFile: %s", kubeCfgFile)
		cfg, err := clientcmd.BuildConfigFromFlags("", kubeCfgFile)
		if err != nil {
			log.Error("Got error trying to create client: ", err)
			return nil, err
		}

		client, err = kubernetes.NewForConfig(cfg)
		if err != nil {
			return nil, err
		}
	}

	return client, nil
}

// GetNamespaces returns all namespaces
func (k *UtilInterface) GetNamespaces() (*v1.NamespaceList, error) {
	log := k.Log.WithField("function", "GetNamespaces")
	namespaces, err := k.Kclient.Namespaces().List(v1.ListOptions{})
	if err != nil {
		log.Error("Error getting namespaces: ", err)
		return nil, err
	}

	return namespaces, nil
}

// GetSecret get a secret
func (k *UtilInterface) GetSecret(namespace, secretname string) (*v1.Secret, error) {
	log := k.Log.WithField("function", "GetSecret")
	secret, err := k.Kclient.Secrets(namespace).Get(secretname)
	if err != nil {
		log.Error("Error getting secret: ", err)
		return nil, err
	}

	return secret, nil
}

// CreateSecret creates a secret
func (k *UtilInterface) CreateSecret(namespace string, secret *v1.Secret) error {
	log := k.Log.WithField("function", "CreateSecret")
	_, err := k.Kclient.Secrets(namespace).Create(secret)
	if err != nil {
		log.Error("Error creating secret: ", err)
		return err
	}

	return nil
}

// UpdateSecret updates a secret
func (k *UtilInterface) UpdateSecret(namespace string, secret *v1.Secret) error {
	log := k.Log.WithField("function", "UpdateSecret")
	_, err := k.Kclient.Secrets(namespace).Update(secret)
	if err != nil {
		log.Error("Error updating secret: ", err)
		return err
	}

	return nil
}

// GetServiceAccount updates a secret
func (k *UtilInterface) GetServiceAccount(namespace, name string) (*v1.ServiceAccount, error) {
	log := k.Log.WithField("function", "GetServiceAccount")
	sa, err := k.Kclient.ServiceAccounts(namespace).Get(name)
	if err != nil {
		log.Error("Error getting service account: ", err)
		return nil, err
	}

	return sa, nil
}

// UpdateServiceAccount updates a secret
func (k *UtilInterface) UpdateServiceAccount(namespace string, sa *v1.ServiceAccount) error {
	log := k.Log.WithField("function", "UpdateServiceAccount")
	_, err := k.Kclient.ServiceAccounts(namespace).Update(sa)
	if err != nil {
		log.Error("Error updating service account: ", err)
		return err
	}

	return nil
}

func (k *UtilInterface) WatchNamespaces(resyncPeriod time.Duration, handler func(*v1.Namespace) error) {
	stopC := make(chan struct{})
	_, c := cache.NewInformer(
		cache.NewListWatchFromClient(k.Kclient.Core().RESTClient(), "namespaces", v1.NamespaceAll, fields.Everything()),
		&v1.Namespace{},
		resyncPeriod,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				if err := handler(obj.(*v1.Namespace)); err != nil {
					logrus.WithField("function", "AddFunc").
						Errorf("error handling add request: %s", err.Error())
				}
			},
			UpdateFunc: func(_ interface{}, obj interface{}) {
				if err := handler(obj.(*v1.Namespace)); err != nil {
					logrus.WithField("function", "UpdateFunc").
						Errorf("error handling update request: %s", err.Error())
				}
			},
		},
	)
	c.Run(stopC)
}
