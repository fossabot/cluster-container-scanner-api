package v2

import (
	"github.com/armosec/armoapi-go/apis"
	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/cluster-container-scanner-api/containerscan"
)

type ScanResultReport struct {
	Designators      armotypes.PortalDesignator                       `json:"designators"`
	Timestamp        int64                                            `json:"timestamp"`
	ContainerScanID  string                                           `json:"containersScanID"`
	Vulnerabilities  []containerscan.ContainerScanVulnerabilityResult `json:"vulnerabilities"`
	Summary          containerscan.ContainerScanSummaryResult         `json:"summary,omitempty"`
	PaginationInfo   apis.PaginationMarks                             `json:"paginationInfo"`
	HasRelevancyData bool                                             `json:"hasRelevancyData"`
}

type Vulnerability struct {
	Name               string                                   `json:"name"`
	ImageID            string                                   `json:"imageID"`
	ImageTag           string                                   `json:"imageTag"`
	RelatedPackageName string                                   `json:"packageName"`
	PackageVersion     string                                   `json:"packageVersion"`
	Link               string                                   `json:"link"`
	Description        string                                   `json:"description"`
	Severity           string                                   `json:"severity"`
	SeverityScore      int                                      `json:"severityScore"`
	Fixes              containerscan.VulFixes                   `json:"fixedIn"`
	IsRelevant         *bool                                    `json:"isRelevant,omitempty"`
	UrgentCount        int                                      `json:"urgent"`
	NeglectedCount     int                                      `json:"neglected"`
	HealthStatus       string                                   `json:"healthStatus"`
	Categories         containerscan.VulnerabilityCategory      `json:"categories"`
	ExceptionApplied   []armotypes.VulnerabilityExceptionPolicy `json:"exceptionApplied,omitempty"` // Active relevant exceptions
}
