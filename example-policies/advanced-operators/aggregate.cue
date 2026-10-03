// example-policies/advanced-operators/aggregate.cue
// Demonstrates projection paths ([*]), counted forEach, message templates
// that name the failing element, compare subsetOf, rule `when` and forEach
// `where`.
package advanced

aggregatePolicy: {
	apiVersion: "policy.garmr.io/v1"
	kind:       "Policy"
	metadata: {
		name:      "aggregate-checks"
		namespace: "advanced-operators"
	}
	spec: {
		description: "Checks across all containers of a pod"
		target: resources: [{kind: "test-aggregate"}]
		rules: [
			{
				id:          "AGG-001"
				description: "Total CPU across containers must not exceed 4"
				severity:    "high"
				// spec.containers[*].cpu is the list of every container's cpu.
				expr: compare: {
					left: {func: {name: "sum", args: [{path: "spec.containers[*].cpu"}]}}
					op: "<="
					right: {literal: 4}
				}
				message: "{{metadata.name}} requests more than 4 CPUs in total"
			},
			{
				id:          "AGG-002"
				description: "At most one container may run privileged"
				severity:    "critical"
				expr: forEach: {
					path: "spec.containers"
					as:   "c"
					count: lessThanOrEqual: 1
					condition: match: {path: "c.securityContext.privileged", equals: true}
				}
				message: "{{.count}} containers run privileged; at most 1 may"
			},
			{
				id:          "AGG-003"
				description: "Every container port must be declared"
				severity:    "medium"
				expr: forEach: {
					path: "spec.containers"
					as:   "c"
					// Containers without ports have nothing to check.
					where: match: {path: "c.ports", exists: true}
					condition: forEach: {
						path: "c.ports"
						as:   "p"
						condition: compare: {left: {path: "p.containerPort"}, op: "in", right: {path: "spec.declaredPorts"}}
					}
				}
				message: "container {{c.name}} exposes undeclared port {{p.containerPort}}"
			},
			{
				id:          "AGG-004"
				description: "Container names must be unique"
				severity:    "medium"
				expr: match: {path: "spec.containers[*].name", unique: true}
			},
			{
				id:          "AGG-005"
				description: "In production, every container must set a memory limit"
				severity:    "high"
				when: match: {path: "metadata.labels.env", equals: "prod"}
				expr: forEach: {
					path: "spec.containers"
					as:   "c"
					condition: match: {path: "c.resources.limits.memory", exists: true}
				}
				message: "production container {{c.name}} has no memory limit"
			},
		]
		enforcement: action: "deny"
	}
}

selectorPolicy: {
	apiVersion: "policy.garmr.io/v1"
	kind:       "Policy"
	metadata: {
		name:      "service-selectors"
		namespace: "advanced-operators"
	}
	spec: {
		description: "Each Service must select the Deployment of the same name"
		target: resources: [{kind: "test-bundle"}]
		rules: [{
			id:          "SEL-001"
			description: "Service selector must match its Deployment's pod labels"
			severity:    "high"
			expr: forEach: {
				path: "services"
				as:   "s"
				condition: forEach: {
					path: "deployments"
					as:   "d"
					where: compare: {left: {path: "d.metadata.name"}, op: "==", right: {path: "s.metadata.name"}}
					condition: compare: {left: {path: "s.spec.selector"}, op: "subsetOf", right: {path: "d.spec.template.metadata.labels"}}
				}
			}
			message: "service {{s.metadata.name}} does not select the pods of deployment {{d.metadata.name}}"
		}]
		enforcement: action: "deny"
	}
}
