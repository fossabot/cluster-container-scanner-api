package v1

import (
	"github.com/armosec/armoapi-go/apis"
	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/cluster-container-scanner-api/containerscan"
)

type ScanResultReport struct {
	Designators     armotypes.PortalDesignator                         `json:"designators"`
	Summary         *containerscan.CommonContainerScanSummaryResult    `json:"summary,omitempty"`
	ContainerScanID string                                             `json:"containersScanID"`
	Vulnerabilities []containerscan.CommonContainerVulnerabilityResult `json:"vulnerabilities"`
	PaginationInfo  apis.PaginationMarks                               `json:"paginationInfo"`
	Timestamp       int64                                              `json:"timestamp"`
}
