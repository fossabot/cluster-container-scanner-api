package v2

import (
	"github.com/armosec/armoapi-go/apis"
	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/cluster-container-scanner-api/containerscan"
)

func (r *ScanResultReport) IsLastReport() bool {
	return r.PaginationInfo.IsLastReport
}

func (r *ScanResultReport) GetDesignators() armotypes.PortalDesignator {
	return r.Designators
}

func (r *ScanResultReport) GetContainerScanID() string {
	return r.ContainerScanID
}

func (r *ScanResultReport) GetTimestamp() int64 {
	return r.Timestamp
}

func (r *ScanResultReport) GetWorkloadHash() string {
	return r.GetDesignators().Attributes["workloadHash"]
}

func (r *ScanResultReport) GetCustomerGUID() string {
	return r.GetSummary().GetCustomerGUID()
}

func (r *ScanResultReport) GetSummary() containerscan.ContainerScanSummaryResult {
	return r.Summary
}

func (r *ScanResultReport) GetVulnerabilities() []containerscan.ContainerScanVulnerabilityResult {
	return r.Vulnerabilities
}

func (r *ScanResultReport) GetVersion() string {
	return "v2"
}

func (r *ScanResultReport) SetDesignators(designators armotypes.PortalDesignator) {
	r.Designators = designators
}

func (r *ScanResultReport) SetContainerScanID(containerScanID string) {
	r.GetSummary().SetContainerScanID(containerScanID)
}

func (r *ScanResultReport) SetTimestamp(timestamp int64) {
	r.Timestamp = timestamp
}

func (r *ScanResultReport) SetWorkloadHash(workloadHash string) {
	r.GetDesignators().Attributes["workloadHash"] = workloadHash
}

func (r *ScanResultReport) SetCustomerGUID(customerGUID string) {
	r.GetSummary().SetCustomerGUID(customerGUID)
}

func (r *ScanResultReport) SetSummary(summary containerscan.ContainerScanSummaryResult) {
	r.Summary = summary
}

func (r *ScanResultReport) SetVulnerabilities(vulnerabilities []containerscan.ContainerScanVulnerabilityResult) {
	r.Vulnerabilities = vulnerabilities
}

func (r *ScanResultReport) SetPaginationInfo(paginationInfo apis.PaginationMarks) {
	r.PaginationInfo = paginationInfo
}

func (r *ScanResultReport) GetPaginationInfo() apis.PaginationMarks {
	return r.PaginationInfo
}

// ContainerScanSummaryResult
func (summary *CommonContainerScanSummaryResult) GetContext() []armotypes.ArmoContext {
	return summary.Context
}

func (summary *CommonContainerScanSummaryResult) GetWLID() string {
	return summary.WLID
}

func (summary *CommonContainerScanSummaryResult) GetImageTag() string {
	return summary.ImageTag
}

func (summary *CommonContainerScanSummaryResult) GetImageID() string {
	return summary.ImageID
}

func (summary *CommonContainerScanSummaryResult) GetSeverityStats() containerscan.SeverityStats {
	return summary.SeverityStats
}

func (summary *CommonContainerScanSummaryResult) GetClusterName() string {
	return summary.ClusterName
}

func (summary *CommonContainerScanSummaryResult) GetNamespace() string {
	return summary.Namespace
}

func (summary *CommonContainerScanSummaryResult) GetContainerName() string {
	return summary.ContainerName
}

func (summary *CommonContainerScanSummaryResult) GetStatus() string {
	return summary.Status
}

func (summary *CommonContainerScanSummaryResult) GetSeveritiesStats() []containerscan.SeverityStats {
	return summary.SeveritiesStats
}

func (summary *CommonContainerScanSummaryResult) GetRegistry() string {
	return summary.Registry
}

func (summary *CommonContainerScanSummaryResult) GetImageTageSuffix() string {
	return summary.ImageTagSuffix
}

func (summary *CommonContainerScanSummaryResult) GetVersion() string {
	return summary.Version
}

func (summary *CommonContainerScanSummaryResult) GetDesignators() armotypes.PortalDesignator {
	return summary.Designators
}

func (summary *CommonContainerScanSummaryResult) GetCustomerGUID() string {
	return summary.CustomerGUID
}

func (summary *CommonContainerScanSummaryResult) GetContainerScanID() string {
	return summary.ContainerScanID
}

func (summary *CommonContainerScanSummaryResult) GetTimestamp() int64 {
	return summary.Timestamp
}

func (summary *CommonContainerScanSummaryResult) GetJobIDs() []string {
	return summary.JobIDs
}

func (summary *CommonContainerScanSummaryResult) Validate() bool {
	return summary.CustomerGUID != "" && summary.ContainerScanID != "" && (summary.ImageID != "" || summary.ImageTag != "") && summary.Timestamp > 0
}
func (summary *CommonContainerScanSummaryResult) SetDesignators(designators armotypes.PortalDesignator) {
	summary.Designators = designators
}

func (summary *CommonContainerScanSummaryResult) SetCustomerGUID(customerGUID string) {
	summary.CustomerGUID = customerGUID
}

func (summary *CommonContainerScanSummaryResult) SetContainerScanID(containerScanID string) {
	summary.ContainerScanID = containerScanID
}

func (summary *CommonContainerScanSummaryResult) SetContext(context []armotypes.ArmoContext) {
	summary.Context = context
}

func (summary *CommonContainerScanSummaryResult) SetWLID(wlid string) {
	summary.WLID = wlid
}

func (summary *CommonContainerScanSummaryResult) SetImageTag(imageTag string) {
	summary.ImageTag = imageTag
}

func (summary *CommonContainerScanSummaryResult) SetImageID(imageID string) {
	summary.ImageID = imageID
}

func (summary *CommonContainerScanSummaryResult) SetSeverityStats(severityStats containerscan.SeverityStats) {
	summary.SeverityStats = severityStats
}

func (summary *CommonContainerScanSummaryResult) SetSeveritiesStats(severitiesStats []containerscan.SeverityStats) {
	summary.SeveritiesStats = severitiesStats
}

func (summary *CommonContainerScanSummaryResult) SetClusterName(clusterName string) {
	summary.ClusterName = clusterName
}

func (summary *CommonContainerScanSummaryResult) SetNamespace(namespace string) {
	summary.Namespace = namespace
}

func (summary *CommonContainerScanSummaryResult) SetContainerName(containerName string) {
	summary.ContainerName = containerName
}

func (summary *CommonContainerScanSummaryResult) SetStatus(status string) {
	summary.Status = status
}

func (summary *CommonContainerScanSummaryResult) SetRegistry(registry string) {
	summary.Registry = registry
}

func (summary *CommonContainerScanSummaryResult) SetImageTageSuffix(imageTageSuffix string) {
	summary.ImageTagSuffix = imageTageSuffix
}

func (summary *CommonContainerScanSummaryResult) SetVersion(version string) {
	summary.Version = version
}

func (summary *CommonContainerScanSummaryResult) SetTimestamp(timestamp int64) {
	summary.Timestamp = timestamp
}

func (vul *CommonContainerVulnerabilityResult) GetWLID() string {
	return vul.WLID
}

// ContainerScanVulnerabilityResult
func (c *CommonContainerVulnerabilityResult) GetDesignators() armotypes.PortalDesignator {
	return c.Designators
}

func (c *CommonContainerVulnerabilityResult) GetContext() []armotypes.ArmoContext {
	return c.Context
}

func (c *CommonContainerVulnerabilityResult) GetContainerScanID() string {
	return c.ContainerScanID
}

func (c *CommonContainerVulnerabilityResult) GetLayers() []containerscan.ESLayer {
	return c.Layers
}

func (c *CommonContainerVulnerabilityResult) GetLayersNested() []containerscan.ESLayer {
	return c.LayersNested
}

func (c *CommonContainerVulnerabilityResult) GetTimestamp() int64 {
	return c.Timestamp
}

func (c *CommonContainerVulnerabilityResult) GetIsLastScan() int {
	return c.IsLastScan
}

func (c *CommonContainerVulnerabilityResult) GetIsFixed() int {
	return c.IsFixed
}

func (c *CommonContainerVulnerabilityResult) GetIntroducedInLayer() string {
	return c.IntroducedInLayer
}

func (c *CommonContainerVulnerabilityResult) GetRelevantLinks() []string {
	return c.RelevantLinks
}

func (c *CommonContainerVulnerabilityResult) GetRelatedExceptions() []armotypes.VulnerabilityExceptionPolicy {
	return c.RelatedExceptions
}

func (c *CommonContainerVulnerabilityResult) GetVulnerability() containerscan.ContainerScanVulnerability {
	return c.Vulnerability
}

func (c *CommonContainerVulnerabilityResult) SetVulnerability(vulnerability containerscan.ContainerScanVulnerability) {
	c.Vulnerability = vulnerability
}

func (c *CommonContainerVulnerabilityResult) SetDesignators(designators armotypes.PortalDesignator) {
	c.Designators = designators
}

func (c *CommonContainerVulnerabilityResult) SetContext(context []armotypes.ArmoContext) {
	c.Context = context
}

func (c *CommonContainerVulnerabilityResult) SetWLID(wlid string) {
	c.WLID = wlid
}

func (c *CommonContainerVulnerabilityResult) SetContainerScanID(containerScanID string) {
	c.ContainerScanID = containerScanID
}

func (c *CommonContainerVulnerabilityResult) SetLayers(layers []containerscan.ESLayer) {
	c.Layers = layers
}

func (c *CommonContainerVulnerabilityResult) SetLayersNested(layersNested []containerscan.ESLayer) {
	c.LayersNested = layersNested
}

func (c *CommonContainerVulnerabilityResult) SetTimestamp(timestamp int64) {
	c.Timestamp = timestamp
}

func (c *CommonContainerVulnerabilityResult) SetIsLastScan(isLastScan int) {
	c.IsLastScan = isLastScan
}

func (c *CommonContainerVulnerabilityResult) SetIsFixed(isFixed int) {
	c.IsFixed = isFixed
}

func (c *CommonContainerVulnerabilityResult) SetIntroducedInLayer(introducedInLayer string) {
	c.IntroducedInLayer = introducedInLayer
}

func (c *CommonContainerVulnerabilityResult) SetRelevantLinks(relevantLinks []string) {
	c.RelevantLinks = relevantLinks
}

func (c *CommonContainerVulnerabilityResult) SetRelatedExceptions(relatedExceptions []armotypes.VulnerabilityExceptionPolicy) {
	c.RelatedExceptions = relatedExceptions
}

// Vulnerability
func (v *Vulnerability) GetName() string {
	return v.Name
}

func (v *Vulnerability) GetImageID() string {
	return v.ImageID
}

func (v *Vulnerability) GetImageTag() string {
	return v.ImageTag
}

func (v *Vulnerability) GetRelatedPackageName() string {
	return v.RelatedPackageName
}

func (v *Vulnerability) GetPackageVersion() string {
	return v.PackageVersion
}

func (v *Vulnerability) GetLink() string {
	return v.Link
}

func (v *Vulnerability) GetDescription() string {
	return v.Description
}

func (v *Vulnerability) GetSeverity() string {
	return v.Severity
}

func (v *Vulnerability) GetSeverityScore() int {
	return v.SeverityScore
}

func (v *Vulnerability) GetFixes() containerscan.VulFixes {
	return v.Fixes
}

func (v *Vulnerability) GetUrgentCount() int {
	return v.UrgentCount
}

func (v *Vulnerability) GetNeglectedCount() int {
	return v.NeglectedCount
}

func (v *Vulnerability) GetHealthStatus() string {
	return v.HealthStatus
}

func (v *Vulnerability) GetCategories() containerscan.VulnerabilityCategory {
	return v.Categories
}

func (v *Vulnerability) GetExceptionApplied() []armotypes.VulnerabilityExceptionPolicy {
	return v.ExceptionApplied
}

func (v *Vulnerability) SetName(name string) {
	v.Name = name
}

func (v *Vulnerability) SetImageHash(imageID string) {
	v.ImageID = imageID
}

func (v *Vulnerability) SetImageTag(imageTag string) {
	v.ImageTag = imageTag
}

func (v *Vulnerability) SetRelatedPackageName(relatedPackageName string) {
	v.RelatedPackageName = relatedPackageName
}

func (v *Vulnerability) SetPackageVersion(packageVersion string) {
	v.PackageVersion = packageVersion
}

func (v *Vulnerability) SetLink(link string) {
	v.Link = link
}

func (v *Vulnerability) SetDescription(description string) {
	v.Description = description
}

func (v *Vulnerability) SetSeverity(severity string) {
	v.Severity = severity
}

func (v *Vulnerability) SetSeverityScore(severityScore int) {
	v.SeverityScore = severityScore
}

func (v *Vulnerability) SetFixes(fixes containerscan.VulFixes) {
	v.Fixes = fixes
}

func (v *Vulnerability) SetUrgentCount(urgentCount int) {
	v.UrgentCount = urgentCount
}

func (v *Vulnerability) SetNeglectedCount(neglectedCount int) {
	v.NeglectedCount = neglectedCount
}

func (v *Vulnerability) SetHealthStatus(healthStatus string) {
	v.HealthStatus = healthStatus
}

func (v *Vulnerability) SetCategories(categories containerscan.VulnerabilityCategory) {
	v.Categories = categories
}

func (v *Vulnerability) SetExceptionApplied(exceptionApplied []armotypes.VulnerabilityExceptionPolicy) {
	v.ExceptionApplied = exceptionApplied
}

func (v *Vulnerability) HasRelevancyData() bool {
	return true
}

func NewScanReport() containerscan.ScanReport {
	return &ScanResultReport{}
}

func NewContainerScanSummaryResult() containerscan.ContainerScanSummaryResult {
	return &CommonContainerScanSummaryResult{}
}

func NewContainerScanVulnerabilityResult() containerscan.ContainerScanVulnerabilityResult {
	return &CommonContainerVulnerabilityResult{
		WLID: "",
	}
}
