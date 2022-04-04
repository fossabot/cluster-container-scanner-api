package grypeadapter

import (
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/armosec/armoapi-go/armotypes"
	cs "github.com/armosec/cluster-container-scanner-api/containerscan"
	"github.com/golang/glog"
)

func AnchoreStructConversion(anchore_vuln_struct *models.Document) (*cs.LayersList, error) {
	layersList := make(cs.LayersList, 0)

	if anchore_vuln_struct.Source != nil {
		parentLayerHash := ""
		var map_target map[string]interface{}
		map_target = anchore_vuln_struct.Source.Target.(map[string]interface{})

		for _, l := range map_target["layers"].([]interface{}) {
			layer := l.(map[string]interface{})
			scanRes := cs.ScanResultLayer{
				LayerHash:       layer["digest"].(string),
				ParentLayerHash: parentLayerHash,
			}
			scanRes.Vulnerabilities = make(cs.VulnerabilitiesList, 0)
			parentLayerHash = layer["digest"].(string)
			for _, match := range anchore_vuln_struct.Matches {
				for _, location := range match.Artifact.Locations {
					if location.FileSystemID == layer["digest"].(string) {
						var version string
						var description string
						if len(match.Vulnerability.Fix.Versions) != 0 {
							version = match.Vulnerability.Fix.Versions[0]
						} else {
							version = ""
						}
						if len(match.RelatedVulnerabilities) != 0 {
							description = match.RelatedVulnerabilities[0].Description
						} else {
							description = ""
						}
						vuln := cs.Vulnerability{
							Name:               match.Vulnerability.ID,
							ImgHash:            map_target["manifestDigest"].(string),
							ImgTag:             map_target["userInput"].(string),
							RelatedPackageName: match.Artifact.Name,
							PackageVersion:     match.Artifact.Version,
							Link:               match.Vulnerability.DataSource,
							Description:        description,
							Severity:           match.Vulnerability.Severity,
							Fixes: []cs.FixedIn{
								cs.FixedIn{
									Name:    match.Vulnerability.Fix.State,
									ImgTag:  map_target["userInput"].(string),
									Version: version,
								},
							},
						}
						scanRes.Vulnerabilities = append(scanRes.Vulnerabilities, vuln)
						break
					}
				}
			}

			layersList = append(layersList, scanRes)
		}
	}

	return &layersList, nil
}

func GrypeResToScanResultReport(grypeReport *models.Document) *cs.ScanResultReport {
	layersList, err := AnchoreStructConversion(grypeReport)
	if err != nil {
		glog.Error("GrypeResToScanResultReport fail convert grype to CVE layers list with err %v", err)
	}
	final_report := cs.ScanResultReport{
		CustomerGUID:  "",
		ImgTag:        "",
		ImgHash:       "",
		WLID:          "",
		ContainerName: "",
		Timestamp:     0,
		Layers:        *layersList,
		// ListOfDangerousArtifcats: listOfBash,
		// Session: scanCmd.Session,
		Designators: armotypes.PortalDesignator{
			Attributes: map[string]string{},
		},
	}

	return &final_report
}
