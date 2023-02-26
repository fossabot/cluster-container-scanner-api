package containerscan

import (
	"testing"

	"github.com/armosec/armoapi-go/apis"
	"github.com/armosec/armoapi-go/armotypes"
	"github.com/stretchr/testify/assert"
)

func TestIsLastReport(t *testing.T) {
	lastReport := ScanResultReportV1{PaginationInfo: apis.PaginationMarks{IsLastReport: true}}
	if !lastReport.IsLastReport() {
		t.Errorf("Expected IsLastReport() to return true for the last report, but it returned false")
	}

	notLastReport := ScanResultReportV1{PaginationInfo: apis.PaginationMarks{IsLastReport: false}}
	if notLastReport.IsLastReport() {
		t.Errorf("Expected IsLastReport() to return false for a report that is not the last, but it returned true")
	}
}

func TestGetContainerScanID(t *testing.T) {
	report := ScanResultReportV1{ContainerScanID: "12345"}
	if report.GetContainerScanID() != "12345" {
		t.Errorf("Expected GetContainerScanID() to return \"12345\", but it returned %q", report.GetContainerScanID())
	}
}

func TestGetTimestamp(t *testing.T) {
	report := ScanResultReportV1{Timestamp: 1234567890}
	if report.GetTimestamp() != 1234567890 {
		t.Errorf("Expected GetTimestamp() to return 1234567890, but it returned %d", report.GetTimestamp())
	}
}

func TestGetWorkloadHash(t *testing.T) {
	report := ScanResultReportV1{Designators: armotypes.PortalDesignator{Attributes: map[string]string{"workloadHash": "hash123"}}}
	if report.GetWorkloadHash() != "hash123" {
		t.Errorf("Expected GetWorkloadHash() to return \"hash123\", but it returned %q", report.GetWorkloadHash())
	}
}

func TestGetCustomerGUID(t *testing.T) {
	report := ScanResultReportV1{Summary: &CommonContainerScanSummaryResult{CustomerGUID: "abc123"}}
	if report.GetCustomerGUID() != "abc123" {
		t.Errorf("Expected GetCustomerGUID() to return \"abc123\", but it returned %q", report.GetCustomerGUID())
	}
}

func TestSetWorkloadHash(t *testing.T) {
	designators := armotypes.PortalDesignator{Attributes: map[string]string{"workloadHash": ""}}
	report := ScanResultReportV1{Designators: designators}

	workloadHash := "abc123"
	report.SetWorkloadHash(workloadHash)

	if report.GetDesignators().Attributes["workloadHash"] != workloadHash {
		t.Errorf("SetWorkloadHash failed, expected %s but got %s", workloadHash, report.GetDesignators().Attributes["workloadHash"])
	}
}

func TestSetCustomerGUID(t *testing.T) {
	summary := CommonContainerScanSummaryResult{CustomerGUID: ""}
	report := ScanResultReportV1{Summary: &summary}

	customerGUID := "123abc"
	report.SetCustomerGUID(customerGUID)

	if report.GetSummary().GetCustomerGUID() != customerGUID {
		t.Errorf("SetCustomerGUID failed, expected %s but got %s", customerGUID, report.GetSummary().GetCustomerGUID())
	}
}

func TestGetSummary(t *testing.T) {
	report := ScanResultReportV1{Summary: &CommonContainerScanSummaryResult{}}

	assert.Equal(t, report.GetSummary(), report.Summary)

	report.Summary = nil
	assert.Nil(t, report.GetSummary())
}

func TestGetPaginationInfo(t *testing.T) {
	report := ScanResultReportV1{PaginationInfo: apis.PaginationMarks{IsLastReport: true}}
	assert.Equal(t, report.GetPaginationInfo(), report.PaginationInfo)
}

func TestSetPaginationInfo(t *testing.T) {
	report := ScanResultReportV1{}
	paginationInfo := apis.PaginationMarks{IsLastReport: true}
	report.SetPaginationInfo(paginationInfo)
	assert.Equal(t, report.GetPaginationInfo(), paginationInfo)
}
