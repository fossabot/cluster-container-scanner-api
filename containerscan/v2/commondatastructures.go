package v2

import (
	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/cluster-container-scanner-api/containerscan"
)

type CommonContainerScanSummaryResult struct {
	SeverityStats                 containerscan.SeverityStats
	Designators                   armotypes.PortalDesignator               `json:"designators"`
	Context                       []armotypes.ArmoContext                  `json:"context"`
	JobIDs                        []string                                 `json:"jobIDs"`
	CustomerGUID                  string                                   `json:"customerGUID"`
	ContainerScanID               string                                   `json:"containersScanID"`
	Timestamp                     int64                                    `json:"timestamp"`
	WLID                          string                                   `json:"wlid"`
	ImageID                       string                                   `json:"imageID"`
	ImageTag                      string                                   `json:"imageTag"`
	ClusterName                   string                                   `json:"clusterName"`
	Namespace                     string                                   `json:"namespace"`
	ContainerName                 string                                   `json:"containerName"`
	PackagesName                  []string                                 `json:"packages"`
	ListOfDangerousArtifcats      []string                                 `json:"listOfDangerousArtifcats"`
	Status                        string                                   `json:"status"`
	Registry                      string                                   `json:"registry"`
	ImageTagSuffix                string                                   `json:"imageTagSuffix"`
	SeveritiesStats               []containerscan.SeverityStats            `json:"severitiesStats"`
	ExcludedSeveritiesStats       []containerscan.SeverityStats            `json:"excludedSeveritiesStats,omitempty"`
	Version                       string                                   `json:"version"`
	Vulnerabilities               []containerscan.ShortVulnerabilityResult `json:"vulnerabilities"`
	ImageSignatureValid           bool                                     `json:"imageSignatureValid,omitempty"`
	ImageHasSignature             bool                                     `json:"imageHasSignature,omitempty"`
	ImageSignatureValidationError string                                   `json:"imageSignatureValidationError,omitempty"`
}

type CommonContainerVulnerabilityResult struct {
	Designators       armotypes.PortalDesignator               `json:"designators"`
	Context           []armotypes.ArmoContext                  `json:"context"`
	WLID              string                                   `json:"wlid"`
	ContainerScanID   string                                   `json:"containersScanID"`
	Layers            []containerscan.ESLayer                  `json:"layers"`
	LayersNested      []containerscan.ESLayer                  `json:"layersNested"`
	Timestamp         int64                                    `json:"timestamp"`
	IsLastScan        int                                      `json:"isLastScan"`
	IsFixed           int                                      `json:"isFixed"`
	IntroducedInLayer string                                   `json:"layerHash"`
	RelevantLinks     []string                                 `json:"links"`                       // shitty SE practice
	RelatedExceptions []armotypes.VulnerabilityExceptionPolicy `json:"relatedExceptions,omitempty"` // configured in portal
	Vulnerability     `json:",inline"`
}
