package containerscan

import (
	"fmt"
	"hash/fnv"
	"regexp"
	"strings"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/google/uuid"
)

func (layer *ScanResultLayer) GetFilesByPackage(pkgname string) (files *PkgFiles) {
	for _, pkg := range layer.Packages {
		if pkg.PackageName == pkgname {
			return &pkg.Files
		}
	}

	return &PkgFiles{}
}

func (layer *ScanResultLayer) GetPackagesNames() []string {
	pkgsNames := []string{}
	for _, pkg := range layer.Packages {
		pkgsNames = append(pkgsNames, pkg.PackageName)
	}
	return pkgsNames
}

func generateWorkloadHash(context map[string]string) string {
	strForHash := context["cluster"] + context["nameapce"] + context["kind"] + context["name"] + context["containerName"]
	hasher := fnv.New64a()
	hasher.Write([]byte(strForHash))
	return fmt.Sprintf("%v", hasher.Sum64())
}

func (scanresult *ScanResultReport) GetDesignatorsNContext() (*armotypes.PortalDesignator, []armotypes.ArmoContext) {

	designatorsObj := armotypes.AttributesDesignatorsFromWLID(scanresult.WLID)
	designatorsObj.Attributes["containerName"] = scanresult.ContainerName
	designatorsObj.Attributes["workloadHash"] = generateWorkloadHash(designatorsObj.Attributes)
	designatorsObj.Attributes["customerGUID"] = scanresult.CustomerGUID

	//Copy all missing attributes
	for k := range scanresult.Designators.Attributes {
		if _, ok := designatorsObj.Attributes[k]; !ok {
			designatorsObj.Attributes[k] = scanresult.Designators.Attributes[k]
		}
	}

	contextObj := armotypes.DesignatorToArmoContext(designatorsObj, "designators")
	return designatorsObj, contextObj
}

func (scanresult *ScanResultReport) Validate() bool {
	if scanresult.CustomerGUID == "" || (scanresult.ImgHash == "" && scanresult.ImgTag == "") || scanresult.Timestamp <= 0 {
		return false
	}

	if _, err := uuid.Parse(scanresult.CustomerGUID); err != nil {
		return false
	}

	//TODO validate layers & vuls

	return true
}

func (v *Vulnerability) IsRCE() bool {
	desc := strings.ToLower(v.Description)

	isRCE, _ := regexp.MatchString(`[^A-Za-z]rce[^A-Za-z]`, v.Description)

	return isRCE || strings.Contains(desc, "remote code execution") || strings.Contains(desc, "remote command execution") || strings.Contains(desc, "arbitrary code") || strings.Contains(desc, "code execution") || strings.Contains(desc, "code injection") || strings.Contains(desc, "command injection") || strings.Contains(desc, "inject arbitrary commands")
}

func (scanresult *ScanResultReportV1) Validate() bool {
	if scanresult.CustomerGUID == "" || scanresult.ContainerScanID == "" || scanresult.Timestamp <= 0 {
		return false
	}

	if _, err := uuid.Parse(scanresult.CustomerGUID); err != nil {
		return false
	}
	return true
}

func (scanresult *ScanResultReportV1) GetDesignatorsNContext() (*armotypes.PortalDesignator, []armotypes.ArmoContext) {

	designatorsObj := armotypes.AttributesDesignatorsFromWLID(scanresult.WLID)
	designatorsObj.Attributes["containerName"] = scanresult.ContainerName
	designatorsObj.Attributes["workloadHash"] = generateWorkloadHash(designatorsObj.Attributes)
	designatorsObj.Attributes["customerGUID"] = scanresult.CustomerGUID

	//Copy all missing attributes
	for k := range scanresult.Designators.Attributes {
		if _, ok := designatorsObj.Attributes[k]; !ok {
			designatorsObj.Attributes[k] = scanresult.Designators.Attributes[k]
		}
	}

	contextObj := armotypes.DesignatorToArmoContext(designatorsObj, "designators")
	return designatorsObj, contextObj
}
