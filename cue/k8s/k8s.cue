// Package k8s holds the Kubernetes object schemas the CUE packages share
// (TR-46, issue #192): the structure the repo's CUE-owned manifests carry.
// Every schema stays open like the API server's structural validation (`...`
// on every object): unknown fields pass, the carried fields get checked.
// The full per-field semantics stay documented in the manifests' headers
// (the deployment/dx1/manifests files); this package owns the shape.
package k8s

#Metadata: {
	name:       string
	namespace?: string
	labels?: {[string]: string}
	...
}

#Object: {
	apiVersion: string
	kind:       string
	metadata:   #Metadata
	...
}

#Probe: {
	httpGet: {
		path: string
		port: int | string
		...
	}
	initialDelaySeconds?: int
	periodSeconds?:       int
	...
}

#Container: {
	name:             string
	image:            string
	imagePullPolicy?: "Always" | "IfNotPresent" | "Never"
	ports?: [...{
		name:          string
		containerPort: int
		...
	}]
	env?: [...{
		name:   string
		value?: string
		...
	}]
	args?: [...string]
	readinessProbe?: #Probe
	livenessProbe?:  #Probe
	...
}

#PodSpec: {
	containers: [...#Container]
	serviceAccountName?: string
	...
}

#Namespace: #Object & {
	apiVersion: "v1"
	kind:       "Namespace"
}

#Deployment: #Object & {
	apiVersion: "apps/v1"
	kind:       "Deployment"
	spec: {
		replicas?: int
		selector: {matchLabels: {[string]: string}}
		template: {
			metadata?: {labels?: {[string]: string}, ...}
			spec: #PodSpec
		}
		...
	}
}

#Service: #Object & {
	apiVersion: "v1"
	kind:       "Service"
	spec: {
		selector?: {[string]: string}
		ports: [...{
			name:        string
			port:        int
			targetPort?: string | int
			...
		}]
		...
	}
}

#ConfigMap: #Object & {
	apiVersion: "v1"
	kind:       "ConfigMap"
	data: {[string]: string}
	...
}

#Gateway: #Object & {
	apiVersion: "gateway.networking.k8s.io/v1"
	kind:       "Gateway"
	spec: {
		gatewayClassName: string
		listeners: [...{
			name:      string
			port:      int
			protocol:  "HTTP" | "HTTPS"
			hostname?: string
			allowedRoutes?: {
				kinds?: [...{
					group: string
					kind:  string
					...
				}]
				namespaces?: {from: "All" | "Same" | "None", ...}
				...
			}
			...
		}]
		...
	}
}

#HTTPRoute: #Object & {
	apiVersion: "gateway.networking.k8s.io/v1"
	kind:       "HTTPRoute"
	spec: {
		parentRefs?: [...{
			name:       string
			namespace?: string
			kind?:      string
			...
		}]
		hostnames?: [...string]
		rules?: [...{
			matches?: [...{
				path?: {
					type:  "PathPrefix" | "Exact"
					value: string
					...
				}
				...
			}]
			backendRefs?: [...{
				group?:  string
				kind?:   string
				name:    string
				port?:   int
				weight?: int
				...
			}]
			...
		}]
		...
	}
}

#ServiceAccount: #Object & {
	apiVersion: "v1"
	kind:       "ServiceAccount"
}

#Role: #Object & {
	apiVersion: "rbac.authorization.k8s.io/v1"
	kind:       "Role"
	rules: [...{
		apiGroups: [...string]
		resources: [...string]
		verbs: [...string]
		...
	}]
}

#RoleBinding: #Object & {
	apiVersion: "rbac.authorization.k8s.io/v1"
	kind:       "RoleBinding"
	roleRef: {
		kind:     string
		name:     string
		apiGroup: string
		...
	}
	subjects?: [...{
		kind:       string
		name:       string
		namespace?: string
		...
	}]
}

#AnyObject: #Namespace | #Deployment | #Service | #ConfigMap |
	#Gateway | #HTTPRoute | #ServiceAccount | #Role | #RoleBinding
