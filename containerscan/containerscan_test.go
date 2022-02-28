package containerscan

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/francoispqt/gojay"
)

func TestDecodeScanWIthDangearousArtifacts(t *testing.T) {
	rhs := &ScanResultReport{}
	er := gojay.NewDecoder(strings.NewReader(nginxScanJSON)).DecodeObject(rhs)
	if er != nil {
		t.Errorf("decode failed due to: %v", er.Error())
	}
	sumObj := rhs.Summarize()
	if sumObj.Registry != "" {
		t.Errorf("sumObj.Registry = %v", sumObj.Registry)
	}
	if sumObj.VersionImage != "nginx:1.18.0" {
		t.Errorf("sumObj.VersionImage = %v", sumObj.Registry)
	}
	if sumObj.ImgTag != "nginx:1.18.0" {
		t.Errorf("sumObj.ImgTag = %v", sumObj.ImgTag)
	}
	if sumObj.Status != "Success" {
		t.Errorf("sumObj.Status = %v", sumObj.Status)
	}
	if len(sumObj.ListOfDangerousArtifcats) != 3 {
		t.Errorf("sumObj.ListOfDangerousArtifcats = %v", sumObj.ListOfDangerousArtifcats)
	}
}

func TestUnmarshalScanReport(t *testing.T) {
	ds := GenerateContainerScanReportMock()
	str1 := ds.AsFNVHash()
	rhs := &ScanResultReport{}

	bolB, _ := json.Marshal(ds)
	r := bytes.NewReader(bolB)

	er := gojay.NewDecoder(r).DecodeObject(rhs)
	if er != nil {
		t.Errorf("marshalling failed due to: %v", er.Error())
	}

	if rhs.AsFNVHash() != str1 {
		t.Errorf("marshalling failed different values after marshal:\nOriginal:\n%v\nParsed:\n%v\n\n===\n", string(bolB), rhs)
	}
}

func TestUnmarshalScanReport1(t *testing.T) {
	ds := Vulnerability{}
	if err := GenerateVulnerability(&ds); err != nil {
		t.Errorf("%v\n%v\n", ds, err)
	}
}

func TestGetByPkgNameSuccess(t *testing.T) {
	ds := GenerateContainerScanReportMock()
	a := ds.Layers[0].GetFilesByPackage("coreutils")
	if a != nil {

		fmt.Printf("%+v\n", *a)
	}

}

func TestGetByPkgNameMissing(t *testing.T) {
	ds := GenerateContainerScanReportMock()
	a := ds.Layers[0].GetFilesByPackage("s")
	if a != nil && len(*a) > 0 {
		t.Errorf("expected - no such package should be in that layer %v\n\n; found - %v", ds, a)
	}

}

func TestCalculateFixed(t *testing.T) {
	res := CalculateFixed([]FixedIn{{
		Name:    "",
		ImgTag:  "",
		Version: "",
	}})
	if res != 0 {
		t.Errorf("wrong fix status: %v", res)
	}
}

func TestIsRCE(t *testing.T) {
	ds := Vulnerability{}

	ds.Description = "Online Railway Reservation System 1.0 - Remote Code Execution (RCE) (Unauthenticated)"
	if true != ds.IsRCE() {
		t.Errorf("IsRCE failed")
	}
	ds.Description = "Gerapy 0.9.7 - Remote Code Execution (RCE) (Authenticated)"
	if true != ds.IsRCE() {
		t.Errorf("IsRCE failed")
	}
	ds.Description = "FORCEHENEW"
	if false != ds.IsRCE() {
		t.Errorf("IsRCE failed")
	}
}

func TestReportValidate(t *testing.T) {
	scanresult := &ScanResultReport{}

	if scanresult.Validate() {
		t.Error("empty scan passed validation")
	}
	scanresult.Timestamp = time.Now().Unix()
	scanresult.ImgHash = "fsdfsdf"
	scanresult.ImgTag = "yuy43434"
	scanresult.CustomerGUID = "<MY_GUID>"
	if scanresult.Validate() {
		t.Error("invalid customer guid passed validation")
	}
	scanresult.CustomerGUID = ""
	if scanresult.Validate() {
		t.Error("empty CustomerGUID passed validation")
	}
	scanresult.ImgHash = ""
	scanresult.ImgTag = ""
	scanresult.CustomerGUID = "8c338c97-383e-4083-a42f-d9b4e0448b13"
	if scanresult.Validate() {
		t.Error("empty scan passed validation")
	}
	scanresult.Timestamp = 0
	scanresult.ImgHash = "fsdfsdf"
	scanresult.ImgTag = "yuy43434"
	if scanresult.Validate() {
		t.Error("empty timestamp passed validation")
	}
	scanresult.Timestamp = time.Now().Unix()
	scanresult.ImgHash = "fsdfsdf"
	scanresult.ImgTag = "yuy43434"
	if !scanresult.Validate() {
		t.Error("valid timestamp failed the validation")
	}
}
