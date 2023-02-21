package v2

import "github.com/francoispqt/gojay"

func (scan *ScanResultReport) UnmarshalJSONObject(dec *gojay.Decoder, key string) (err error) {
	switch key {
	case "timestamp":
		err = dec.Int64(&(scan.Timestamp))
	case "containersScanID":
		err = dec.String(&(scan.ContainerScanID))
	case "designators":
		err = dec.Object(&(scan.Designators))
	case "hasRelevancyData":
		err = dec.Bool(&(scan.HasRelevancyData))
	}

	return err
}

func (scan *ScanResultReport) NKeys() int {
	return 4
}

func (v *Vulnerability) UnmarshalJSONObject(dec *gojay.Decoder, key string) (err error) {

	switch key {
	case "name":
		err = dec.String(&(v.Name))

	case "imageTag":
		err = dec.String(&(v.ImageTag))

	case "imageID":
		err = dec.String(&(v.ImageID))

	case "packageName":
		err = dec.String(&(v.RelatedPackageName))

	case "packageVersion":
		err = dec.String(&(v.PackageVersion))

	case "link":
		err = dec.String(&(v.Link))

	case "description":
		err = dec.String(&(v.Description))

	case "severity":
		err = dec.String(&(v.Severity))

	case "fixedIn":
		err = dec.Array(&(v.Fixes))

	case "isRelevant":
		err = dec.Bool(v.IsRelevant)

	}

	return err
}

func (v *Vulnerability) NKeys() int {
	return 10
}
