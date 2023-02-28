package containerscan

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateBogusHash(t *testing.T) {
	tests := []struct {
		name string
		wlid string
		want string
	}{
		{
			name: "kube-proxy",
			wlid: "wlid://cluster-minikube/namespace-kube-system/daemonset-kube-proxy",
			want: "5485464254446115801",
		},
		{
			name: "coredns",
			wlid: "wlid://cluster-bez-longrun3/namespace-kube-system/deployment-coredns",
			want: "16878991644547272844",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, GenerateBogusHash(tt.wlid), "GenerateWorkloadHash(%v)", tt.wlid)
		})
	}
}

func TestGenerateWorkloadHash(t *testing.T) {
	tests := []struct {
		name string
		wlid string
		want string
	}{
		{
			name: "kube-proxy",
			wlid: "wlid://cluster-minikube/namespace-kube-system/daemonset-kube-proxy",
			want: "8248822369989173472",
		},
		{
			name: "coredns",
			wlid: "wlid://cluster-bez-longrun3/namespace-kube-system/deployment-coredns",
			want: "12836087988784946749",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, GenerateWorkloadHash(tt.wlid), "GenerateWorkloadHash(%v)", tt.wlid)
		})
	}
}
