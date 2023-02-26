package containerscan

import (
	"fmt"
	"hash/fnv"

	"github.com/armosec/armoapi-go/apis"
	"github.com/armosec/armoapi-go/armotypes"
)

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
	r.ContainerScanID = containerScanID
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
