package containerscan

import (
	"github.com/armosec/armoapi-go/apis"

	"github.com/armosec/armoapi-go/armotypes"
)

//!!!!!!!!!!!!EVERY CHANGE IN THESE STRUCTURES => CHANGE gojayunmarshaller ASWELL!!!!!!!!!!!!!!!!!!!!!!!!

// ScanResultReport - the report given from scanner to event receiver
type ScanResultReport struct {
	Designators              armotypes.PortalDesignator `json:"designators"`
	CustomerGUID             string                     `json:"customerGUID"`
	ImgTag                   string                     `json:"imageTag"`
	ImgHash                  string                     `json:"imageHash"`
	WLID                     string                     `json:"wlid"`
	ContainerName            string                     `json:"containerName"`
	Timestamp                int64                      `json:"timestamp"`
	Layers                   LayersList                 `json:"layers"`
	ListOfDangerousArtifcats []string                   `json:"listOfDangerousArtifcats"`
	Session                  apis.SessionChain          `json:"session,omitempty"`

	ImageSignatureValid           bool   `json:"imageSignatureValid,omitempty"`
	ImageHasSignature             bool   `json:"imageHasSignature,omitempty"`
	ImageSignatureValidationError string `json:"imageSignatureValidationError,omitempty"`
}

// ScanResultReportV1 replaces ScanResultReport
type ScanResultReportV1 struct {
	Designators      armotypes.PortalDesignator           `json:"designators"`
	Timestamp        int64                                `json:"timestamp"`
	ContainerScanID  string                               `json:"containersScanID"`
	Vulnerabilities  []CommonContainerVulnerabilityResult `json:"vulnerabilities"`
	Summary          *CommonContainerScanSummaryResult    `json:"summary,omitempty"`
	PaginationInfo   apis.PaginationMarks                 `json:"paginationInfo"`
	HasRelevancyData bool                                 `json:"hasRelevancyData"`
}

// ScanResultLayer - represents a single layer from container scan result
type ScanResultLayer struct {
	LayerHash       string              `json:"layerHash"`
	ParentLayerHash string              `json:"parentLayerHash"`
	Vulnerabilities VulnerabilitiesList `json:"vulnerabilities"`
	Packages        LinuxPkgs           `json:"packageToFile"`
}

type VulnerabilityCategory struct {
	IsRCE bool `json:"isRce"`
}

// Vulnerability - a vul object
type Vulnerability struct {
	Name               string                                   `json:"name"`
	ImageID            string                                   `json:"imageHash"`
	ImageTag           string                                   `json:"imageTag"`
	RelatedPackageName string                                   `json:"packageName"`
	PackageVersion     string                                   `json:"packageVersion"`
	Link               string                                   `json:"link"`
	Description        string                                   `json:"description"`
	Severity           string                                   `json:"severity"`
	SeverityScore      int                                      `json:"severityScore"`
	Fixes              VulFixes                                 `json:"fixedIn"`
	IsRelevant         *bool                                    `json:"isRelevant,omitempty"`
	UrgentCount        int                                      `json:"urgent"`
	NeglectedCount     int                                      `json:"neglected"`
	HealthStatus       string                                   `json:"healthStatus"`
	Categories         VulnerabilityCategory                    `json:"categories"`
	ExceptionApplied   []armotypes.VulnerabilityExceptionPolicy `json:"exceptionApplied,omitempty"` // Active relevant exceptions
}

// FixedIn when and which pkg was fixed (which version as well)
type FixedIn struct {
	Name    string `json:"name"`
	ImgTag  string `json:"imageTag"`
	Version string `json:"version"`
}

// LinuxPackage- Linux package representation
type LinuxPackage struct {
	PackageName    string   `json:"packageName"`
	Files          PkgFiles `json:"files"`
	PackageVersion string   `json:"version"`
}

// PackageFile - s.e
type PackageFile struct {
	Filename string `json:"name"`
}

// types to provide unmarshalling:

// VulnerabilitiesList -s.e
type LayersList []ScanResultLayer

// VulnerabilitiesList -s.e
type VulnerabilitiesList []Vulnerability

// LinuxPkgs - slice of linux pkgs
type LinuxPkgs []LinuxPackage

// VulFixes - information bout when/how this vul was fixed
type VulFixes []FixedIn

// PkgFiles - slice of files belong to specific pkg
type PkgFiles []PackageFile
