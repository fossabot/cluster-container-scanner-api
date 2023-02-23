package containerscan

import (
	"fmt"
	"hash/fnv"

	"github.com/armosec/armoapi-go/apis"
	"github.com/armosec/armoapi-go/armotypes"
)

func NewCommonContainerVulnerabilityResult() ContainerScanVulnerabilityResult {
	return &CommonContainerVulnerabilityResult{}
}

// ContainerScanVulnerabilityResult
func (c *CommonContainerVulnerabilityResult) GetDesignators() armotypes.PortalDesignator {
	return c.Designators
}

func (c *CommonContainerVulnerabilityResult) GetContext() []armotypes.ArmoContext {
	return c.Context
}

func (c *CommonContainerVulnerabilityResult) GetWLID() string {
	return c.WLID
}

func (c *CommonContainerVulnerabilityResult) GetContainerScanID() string {
	return c.ContainerScanID
}

func (c *CommonContainerVulnerabilityResult) GetLayers() []ESLayer {
	return c.Layers
}

func (c *CommonContainerVulnerabilityResult) GetLayersNested() []ESLayer {
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

func (c *CommonContainerVulnerabilityResult) GetVulnerability() VulnerabilityResult {
	return &c.Vulnerability
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

func (c *CommonContainerVulnerabilityResult) SetLayers(layers []ESLayer) {
	c.Layers = layers
}

func (c *CommonContainerVulnerabilityResult) SetLayersNested(layersNested []ESLayer) {
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

// ContainerScanSummaryResult
func NewContainerScanSummaryResult() ContainerScanSummaryResult {
	return &CommonContainerScanSummaryResult{}
}

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

func (summary *CommonContainerScanSummaryResult) GetSeverityStats() SeverityStats {
	return summary.SeverityStats
}

func (summary *CommonContainerScanSummaryResult) GetSeveritiesStats() []SeverityStats {
	return summary.SeveritiesStats
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
	return summary.CustomerGUID != "" && summary.ContainerScanID != "" && (summary.ImageTag != "" || summary.ImageID != "") && summary.Timestamp > 0
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

func (summary *CommonContainerScanSummaryResult) SetSeverityStats(severityStats SeverityStats) {
	summary.SeverityStats = severityStats
}

func (summary *CommonContainerScanSummaryResult) SetSeveritiesStats(severitiesStats []SeverityStats) {
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

// Vulnerability
func NewVulnerability() VulnerabilityResult {
	return &Vulnerability{}
}

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

func (v *Vulnerability) GetFixes() VulFixes {
	return v.Fixes
}

func (v *Vulnerability) GetIsRelevant() *bool {
	return v.IsRelevant
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

func (v *Vulnerability) GetCategories() VulnerabilityCategory {
	return v.Categories
}

func (v *Vulnerability) GetExceptionApplied() []armotypes.VulnerabilityExceptionPolicy {
	return v.ExceptionApplied
}

func (v *Vulnerability) SetName(name string) {
	v.Name = name
}

func (v *Vulnerability) SetImageID(ImageID string) {
	v.ImageID = ImageID
}

func (v *Vulnerability) SetImageTag(ImageTag string) {
	v.ImageTag = ImageTag
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

func (v *Vulnerability) SetFixes(fixes VulFixes) {
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

func (v *Vulnerability) SetCategories(categories VulnerabilityCategory) {
	v.Categories = categories
}

func (v *Vulnerability) SetExceptionApplied(exceptionApplied []armotypes.VulnerabilityExceptionPolicy) {
	v.ExceptionApplied = exceptionApplied
}

func (v *Vulnerability) SetIsRelevant(isRelevant *bool) {
	v.IsRelevant = isRelevant
}

// ScanResultReportV1
func NewScanResultReportV1() ScanReport {
	return &ScanResultReportV1{}
}

func (v *ScanResultReport) AsFNVHash() string {
	hasher := fnv.New64a()
	hasher.Write([]byte(fmt.Sprintf("%v", *v)))
	return fmt.Sprintf("%v", hasher.Sum64())
}

func (r *ScanResultReportV1) IsLastReport() bool {
	return r.PaginationInfo.IsLastReport
}

func (r *ScanResultReportV1) GetDesignators() armotypes.PortalDesignator {
	return r.Designators
}

func (r *ScanResultReportV1) GetContainerScanID() string {
	return r.ContainerScanID
}

func (r *ScanResultReportV1) GetTimestamp() int64 {
	return r.Timestamp
}

func (r *ScanResultReportV1) GetWorkloadHash() string {
	return r.GetDesignators().Attributes["workloadHash"]
}

func (r *ScanResultReportV1) GetCustomerGUID() string {
	return r.GetSummary().GetCustomerGUID()
}

func (r *ScanResultReportV1) GetSummary() ContainerScanSummaryResult {
	if r.Summary == nil {
		return nil
	}
	return r.Summary
}

func (r *ScanResultReportV1) GetHasRelevancyData() bool {
	return r.HasRelevancyData
}

func (r *ScanResultReportV1) GetVulnerabilities() []ContainerScanVulnerabilityResult {
	var vulnerabilities []ContainerScanVulnerabilityResult
	for _, vul := range r.Vulnerabilities {
		vulnerabilities = append(vulnerabilities, &vul)
	}
	return vulnerabilities
}

func NewContainerScanVulnerabilityResult() ContainerScanVulnerabilityResult {
	return &CommonContainerVulnerabilityResult{}
}

func (r *ScanResultReportV1) GetVersion() string {
	return "v1"
}

func (r *ScanResultReportV1) GetPaginationInfo() apis.PaginationMarks {
	return r.PaginationInfo
}

func (r *ScanResultReportV1) SetDesignators(designators armotypes.PortalDesignator) {
	r.Designators = designators
}

func (r *ScanResultReportV1) SetContainerScanID(containerScanID string) {
	r.GetSummary().SetContainerScanID(containerScanID)
}

func (r *ScanResultReportV1) SetTimestamp(timestamp int64) {
	r.Timestamp = timestamp
}

func (r *ScanResultReportV1) SetWorkloadHash(workloadHash string) {
	r.GetDesignators().Attributes["workloadHash"] = workloadHash
}

func (r *ScanResultReportV1) SetCustomerGUID(customerGUID string) {
	r.GetSummary().SetCustomerGUID(customerGUID)
}

func (r *ScanResultReportV1) SetPaginationInfo(paginationInfo apis.PaginationMarks) {
	r.PaginationInfo = paginationInfo
}
