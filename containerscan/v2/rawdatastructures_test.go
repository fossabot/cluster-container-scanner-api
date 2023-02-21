package v2

import (
	_ "embed"
	"strings"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/francoispqt/gojay"
	"github.com/stretchr/testify/assert"
)

//go:embed testdata/scanReportRelevant.json
var scanReportJson string

func TestScanResultReportDecoding(t *testing.T) {
	scanReport := &ScanResultReport{}
	er := gojay.NewDecoder(strings.NewReader(scanReportJson)).DecodeObject(scanReport)
	if er != nil {
		t.Errorf("decode failed due to: %v", er.Error())
	}
	assert.Equal(t, "5969736482532194479", scanReport.ContainerScanID)
	assert.Equal(t, int64(1656250322), scanReport.Timestamp)

	// validate designators
	assert.Equal(t, armotypes.DesignatorAttributes, scanReport.Designators.DesignatorType)
	assert.Equal(t, "myCluster", scanReport.Designators.Attributes[armotypes.AttributeCluster])
	assert.Equal(t, "8190928904639901517", scanReport.Designators.Attributes[armotypes.AttributeWorkloadHash])
	assert.Equal(t, "myName", scanReport.Designators.Attributes[armotypes.AttributeName])
	assert.Equal(t, "myNS", scanReport.Designators.Attributes[armotypes.AttributeNamespace])
	assert.Equal(t, "deployment", scanReport.Designators.Attributes[armotypes.AttributeKind])
	assert.Equal(t, "e57ec5a0-695f-4777-8366-1c64fada00a0", scanReport.Designators.Attributes[armotypes.AttributeCustomerGUID])
	assert.Equal(t, "myContainer", scanReport.Designators.Attributes[armotypes.AttributeContainerName])

	assert.Equal(t, true, scanReport.IsRelevancy)

}
