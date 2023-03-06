package containerscan

import "github.com/armosec/armoapi-go/armotypes"

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

func (summary *CommonContainerScanSummaryResult) SetWLID(wlid string) {
	summary.WLID = wlid
}

func (summary *CommonContainerScanSummaryResult) SetImageTag(imageTag string) {
	summary.ImageTag = imageTag
}

func (summary *CommonContainerScanSummaryResult) SetImageID(imageID string) {
	summary.ImageID = imageID
}

func (summary *CommonContainerScanSummaryResult) SetContext(context []armotypes.ArmoContext) {
	summary.Context = context
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

func (summary *CommonContainerScanSummaryResult) GetHasRelevancyData() bool {
	return summary.HasRelevancyData
}

func (summary *CommonContainerScanSummaryResult) SetHasRelevancyData(hasRelevancy bool) {
	summary.HasRelevancyData = hasRelevancy
}
