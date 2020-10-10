package dn

import (
	"encoding/asn1"
	"encoding/hex"
	"reflect"
	"testing"
)

var (
	oidCountry      = []int{2, 5, 4, 6}
	oidOrganization = []int{2, 5, 4, 10}
	oidLocality     = []int{2, 5, 4, 7}
	a, _            = hex.DecodeString("13024A50")             //PrintableString "JP"
	b, _            = hex.DecodeString("13024A504A504A504A50") //Broken PrintableString binary
	ia5, _          = hex.DecodeString("1603616263")           //IA5String "abc"
	p, _            = hex.DecodeString("1303616263")           //PrintableString "abc"
	utf8, _         = hex.DecodeString("0C03616263")           //Utf8String "abc"
	bmp, _          = hex.DecodeString("1E06006100620063")     //BMPString "abc"
	ia5d, _         = hex.DecodeString("1603616264")           //IA5String "abd"
	pd, _           = hex.DecodeString("1303616264")           //PrintableString "abd"
	utf8d, _        = hex.DecodeString("0C03616264")           //Utf8String "abd"
	bmpd, _         = hex.DecodeString("1E06006100620064")     //BMPString "abd"

	brokenAtv = attribute{
		Oid: oidOrganization,
		RawValue: asn1.RawValue{
			Tag:       asn1.TagPrintableString,
			FullBytes: b,
		},
	}
	wrongDcAtv = attribute{
		Oid: oidDomainComponent,
		RawValue: asn1.RawValue{
			Tag:       asn1.TagPrintableString,
			FullBytes: a,
		},
	}
	ia5Atv = attribute{
		Oid: oidDomainComponent,
		RawValue: asn1.RawValue{
			Tag:       asn1.TagIA5String,
			FullBytes: ia5,
		},
	}
	pAtv = attribute{
		Oid: oidOrganization,
		RawValue: asn1.RawValue{
			Tag:       asn1.TagPrintableString,
			FullBytes: p,
		},
	}
	utf8Atv = attribute{
		Oid: oidOrganization,
		RawValue: asn1.RawValue{
			Tag:       asn1.TagUTF8String,
			FullBytes: utf8,
		},
	}
	bmpAtv = attribute{
		Oid: oidOrganization,
		RawValue: asn1.RawValue{
			Tag:       asn1.TagBMPString,
			FullBytes: bmp,
		},
	}
	ia5dAtv = attribute{
		Oid: oidDomainComponent,
		RawValue: asn1.RawValue{
			Tag:       asn1.TagIA5String,
			FullBytes: ia5d,
		},
	}
	pdAtv = attribute{
		Oid: oidOrganization,
		RawValue: asn1.RawValue{
			Tag:       asn1.TagPrintableString,
			FullBytes: pd,
		},
	}
	utf8dAtv = attribute{
		Oid: oidOrganization,
		RawValue: asn1.RawValue{
			Tag:       asn1.TagUTF8String,
			FullBytes: utf8d,
		},
	}
	bmpdAtv = attribute{
		Oid: oidOrganization,
		RawValue: asn1.RawValue{
			Tag:       asn1.TagBMPString,
			FullBytes: bmpd,
		},
	}

	dn1 = []rdnSET{[]attribute{pAtv}}
	dn2 = []rdnSET{[]attribute{pAtv}, []attribute{pdAtv}}
	dn3 = []rdnSET{[]attribute{pAtv}, []attribute{pdAtv}, []attribute{utf8Atv}}
	dn4 = []rdnSET{[]attribute{pdAtv}}
	dn5 = []rdnSET{[]attribute{pdAtv}, []attribute{pAtv}, []attribute{utf8Atv}}
	dn6 = []rdnSET{[]attribute{pAtv}, []attribute{brokenAtv}}
	dn7 = []rdnSET{[]attribute{pAtv}, []attribute{wrongDcAtv}}

	//C=JP(PrintableString),O=BAR(UTF8String)+O=FOO(UTF8String),CN=ABC(UTF8String)
	hdn1 = "3035310b3009060355040613024a503118300a060355040a0c03424152300a060355040a0c03464f4f310c300a06035504030c03414243"

	dn1b, _ = hex.DecodeString(hdn1)
	hatv1   = "3009060355040613024A50"   //C=JP(PrintableString)
	hatv2   = "300A060355040A0C03424152" //O=BAR(UTF8String)
	hatv3   = "300A060355040A0C03464F4F" //O=FOO(UTF8String)
	hatv4   = "300A06035504030C03414243" //CN=ABC(UTF8String)
	rdn1    = []attribute{parseAtv(hatv1)}
	rdn2    = []attribute{parseAtv(hatv2), parseAtv(hatv3)}
	rdn3    = []attribute{parseAtv(hatv4)}

	//Broken DN
	hBrokenDn = "3035310b3009060355040613024a503118300a060355040a0c03424152300a060355040a0c03464f4f310c300a06035504030c034142431111111"
	brdnb, _  = hex.DecodeString(hBrokenDn)

	//C=JP(PrintableString),CN=ABC(UTF8String)
	hdn2    = "301b310b3009060355040613024a50310c300a06035504030c03414243"
	dn2b, _ = hex.DecodeString(hdn2)
	//C=JP(PrintableString),CN=ABC(PrintableString)
	hdn3    = "301b310b3009060355040613024a50310c300a06035504031303414243"
	dn3b, _ = hex.DecodeString(hdn3)
	//C=JP(PrintableString),CN=abc(UTF8String)
	hdn4    = "301b310b3009060355040613024a50310c300a06035504030c03616263"
	dn4b, _ = hex.DecodeString(hdn4)
	//C=JP(PrintableString),CN=ABC(BMPString)
	hdn5    = "301e310b3009060355040613024a50310f300d06035504031e06004100420043"
	dn5b, _ = hex.DecodeString(hdn5)

	//C=US(PrintableString),CN=DEF(UTF8String)
	hdn6    = "301b310b3009060355040613025553310c300a06035504030c03444546"
	dn6b, _ = hex.DecodeString(hdn6)

	//C=JP(PrintableString),DC=com(IA5String),DC=example(PrintableString),CN=abc(UTF8String)
	hdn7    = "3049310b3009060355040613024a5031133011060a0992268993f22c6401191603636f6d31173015060a0992268993f22c64011913076578616d706c65310c300a06035504030c03616263"
	dn7b, _ = hex.DecodeString(hdn7)

	//C=JP(PrintableString),O=FOO(BMPString),CN=ABC(PrintableString)
	hdn8    = "302c310b3009060355040613024a50310f300d060355040a1e060046004f004f310c300a06035504030c03414243"
	dn8b, _ = hex.DecodeString(hdn8)
)

func parseAtv(h string) (atv attribute) {
	bytes, _ := hex.DecodeString(h)
	if r, err := asn1.Unmarshal(bytes, &atv); err != nil || len(r) != 0 {
		panic("")
	}
	return atv
}

func TestCompare(t *testing.T) {
	type args struct {
		issuer  []byte
		subject []byte
	}
	tests := []struct {
		name       string
		args       args
		wantResult bool
		wantErr    bool
	}{
		{"Same characters, Same Encoding", args{issuer: dn2b, subject: dn2b}, true, false},
		{"Same characters, Same Encoding(PrintableString,BMPString,UTF8String)", args{issuer: dn8b, subject: dn8b}, true, false},
		{"Upper/Lower case characters, Same Encoding", args{issuer: dn2b, subject: dn3b}, true, false},
		{"Same characters, Different Encoding(PrintableString,UTF8String)", args{issuer: dn2b, subject: dn3b}, true, false},
		{"Same characters, Different Encoding(PrintableString,BMPString)", args{issuer: dn2b, subject: dn5b}, false, false},
		{"Same characters, Multi RDN", args{issuer: dn1b, subject: dn1b}, true, false},
		{"Different characters, Same Encoding", args{issuer: dn2b, subject: dn6b}, false, false},
		{"Wrong Encoding domain component", args{issuer: dn7b, subject: dn7b}, false, true},
		{"Broken data", args{issuer: brdnb, subject: brdnb}, false, true},
		{"Issuer is blank", args{issuer: []byte{}, subject: brdnb}, false, true},
		{"Subject is blank", args{issuer: brdnb, subject: []byte{}}, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotResult, err := Compare(tt.args.issuer, tt.args.subject)
			if (err != nil) != tt.wantErr {
				t.Errorf("Compare() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotResult != tt.wantResult {
				t.Errorf("Compare() gotResult = %v, want %v", gotResult, tt.wantResult)
			}
		})
	}
}

func Test_parseDn(t *testing.T) {
	type args struct {
		dnBytes []byte
	}
	tests := []struct {
		name    string
		args    args
		wantDn  dn
		wantErr bool
	}{
		{"OK", args{dnBytes: dn1b}, dn{rdn1, rdn2, rdn3}, false},
		{"Broken Data", args{dnBytes: brdnb}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotDn, err := parseDn(tt.args.dnBytes)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseDn() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotDn, tt.wantDn) {
				t.Errorf("parseDn() gotDn = %v, want %v", gotDn, tt.wantDn)
			}
		})
	}
}

func Test_compareDistinguishedName(t *testing.T) {
	type args struct {
		xd []rdnSET
		yd []rdnSET
	}
	tests := []struct {
		name       string
		args       args
		wantResult bool
		wantErr    bool
	}{
		{"DNs are same, have 1 rdnSET", args{xd: dn1, yd: dn1}, true, false},
		{"DNs are same, have 2 rdnSET", args{xd: dn2, yd: dn2}, true, false},
		{"DNs are same, have 3 rdnSET", args{xd: dn3, yd: dn3}, true, false},
		{"DNs are not same, have 1 rdnSET", args{xd: dn1, yd: dn4}, false, false},
		{"DNs are not same, have 3 rdnSET", args{xd: dn3, yd: dn5}, false, false},
		{"DNs are not same, have different number of rdnSET", args{xd: dn1, yd: dn3}, false, false},
		{"DNs are same, have 2 rdnSET and have broken rdnSET", args{xd: dn6, yd: dn6}, false, true},
		{"DNs are same, have 2 rdnSET and have wrong rdnSET", args{xd: dn7, yd: dn7}, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotResult, err := compareDistinguishedName(tt.args.xd, tt.args.yd)
			if (err != nil) != tt.wantErr {
				t.Errorf("compareDistinguishedName() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotResult != tt.wantResult {
				t.Errorf("compareDistinguishedName() gotResult = %v, want %v", gotResult, tt.wantResult)
			}
		})
	}
}

func Test_compareRelativeDistinguishedName(t *testing.T) {
	type args struct {
		xr rdnSET
		yr rdnSET
	}
	tests := []struct {
		name       string
		args       args
		wantResult bool
		wantErr    bool
	}{
		{"RDNs are same, have 1 element", args{xr: []attribute{pAtv}, yr: []attribute{pAtv}}, true, false},
		{"RDNs are same, have 2 elements", args{xr: []attribute{pAtv, pdAtv}, yr: []attribute{pAtv, pdAtv}}, true, false},
		{"RDNs are same, have 2 elements", args{xr: []attribute{bmpAtv, pAtv}, yr: []attribute{pAtv, bmpAtv}}, true, false},
		{"RDNs are same, have 3 elements", args{xr: []attribute{pAtv, ia5Atv, bmpAtv}, yr: []attribute{ia5Atv, pAtv, bmpAtv}}, true, false},
		{"RDNs are not same, have 1 element", args{xr: []attribute{pAtv}, yr: []attribute{ia5dAtv}}, false, false},
		{"RDNs are not same, have 3 elements", args{xr: []attribute{pAtv, ia5Atv, bmpAtv}, yr: []attribute{ia5Atv, pdAtv, bmpAtv}}, false, false},
		{"RDNs are not same, have different number of elements", args{xr: []attribute{pAtv, pdAtv}, yr: []attribute{pAtv}}, false, false},
		{"RDNs are same, have 2 elements and have broken element", args{xr: []attribute{pAtv, brokenAtv}, yr: []attribute{pAtv, brokenAtv}}, false, true}, // Unknown

	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotResult, err := compareRelativeDistinguishedName(tt.args.xr, tt.args.yr)
			if (err != nil) != tt.wantErr {
				t.Errorf("compareRelativeDistinguishedName() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotResult != tt.wantResult {
				t.Errorf("compareRelativeDistinguishedName() gotResult = %v, want %v", gotResult, tt.wantResult)
			}
		})
	}
}

func Test_findMatchedAttribute(t *testing.T) {
	type args struct {
		atv attribute
		r   rdnSET
	}
	tests := []struct {
		name       string
		args       args
		wantResult bool
		wantRest   rdnSET
		wantErr    bool
	}{
		{"RDN has 1 elements and 1 match", args{atv: pAtv, r: []attribute{pAtv}}, true, []attribute{}, false},
		{"RDN has 1 elements and No match", args{atv: pAtv, r: []attribute{bmpAtv}}, false, []attribute{bmpAtv}, false},
		{"RDN has 2 elements and 1 match", args{atv: pAtv, r: []attribute{pAtv, pAtv}}, true, []attribute{pAtv}, false},
		{"RDN has 2 elements and 1 match", args{atv: pAtv, r: []attribute{utf8Atv, pAtv}}, true, []attribute{pAtv}, false},
		{"RDN has 3 elements and 1 match", args{atv: pAtv, r: []attribute{utf8Atv, pAtv, pAtv}}, true, []attribute{pAtv, pAtv}, false},
		{"RDN has 2 elements and No match", args{atv: ia5Atv, r: []attribute{pAtv, pAtv}}, false, []attribute{pAtv, pAtv}, false},
		{"RDN has 2 elements and 1 is broken", args{atv: pAtv, r: []attribute{ia5Atv, brokenAtv}}, false, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotResult, gotRest, err := findMatchedAttribute(tt.args.atv, tt.args.r)
			if (err != nil) != tt.wantErr {
				t.Errorf("findMatchedAttribute() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotResult != tt.wantResult {
				t.Errorf("findMatchedAttribute() gotResult = %v, want %v", gotResult, tt.wantResult)
			}
			if !reflect.DeepEqual(gotRest, tt.wantRest) {
				t.Errorf("findMatchedAttribute() gotRest = %v, want %v", gotRest, tt.wantRest)
			}
		})
	}
}

func Test_removeAttribute1(t *testing.T) {
	type args struct {
		index int
		r     rdnSET
	}
	tests := []struct {
		name       string
		args       args
		wantResult rdnSET
		wantErr    bool
	}{
		{"Remove element[0] from 2 elements", args{index: 0, r: []attribute{utf8Atv, pAtv}}, []attribute{pAtv}, false},
		{"Remove element[0] from 1 element", args{index: 0, r: []attribute{utf8Atv}}, []attribute{}, false},
		{"Remove element[1] from 1 element", args{index: 1, r: []attribute{utf8Atv}}, nil, true},
		{"Remove element[-1] from 1 element", args{index: -1, r: []attribute{utf8Atv}}, nil, true},
		{"Remove element[1] from 2 elements", args{index: 1, r: []attribute{utf8Atv, pAtv}}, []attribute{utf8Atv}, false},
		{"Remove element[1] from 3 elements", args{index: 1, r: []attribute{utf8Atv, pAtv, bmpAtv}}, []attribute{utf8Atv, bmpAtv}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotResult, err := removeAttribute(tt.args.index, tt.args.r)
			if (err != nil) != tt.wantErr {
				t.Errorf("removeAttribute() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotResult, tt.wantResult) {
				t.Errorf("removeAttribute() gotResult = %v, want %v", gotResult, tt.wantResult)
			}
		})
	}
}

func Test_compareAttribute(t *testing.T) {

	type args struct {
		x attribute
		y attribute
	}
	tests := []struct {
		name       string
		args       args
		wantResult bool
		wantErr    bool
	}{
		//Add isProhibit Error case
		{"Different OID", args{x: attribute{Oid: oidCountry}, y: attribute{Oid: oidLocality}}, false, false},
		{"Broken String x", args{x: brokenAtv, y: attribute{Oid: oidOrganization}}, false, true},
		{"Broken String y", args{x: attribute{Oid: oidOrganization}, y: brokenAtv}, false, true},
		{"Wrong Encode domainComponent x", args{x: wrongDcAtv, y: ia5Atv}, false, true},
		{"Wrong Encode domainComponent y", args{x: ia5Atv, y: wrongDcAtv}, false, true},
		{"Compare domainComponent", args{x: ia5Atv, y: ia5Atv}, true, false},
		{"Compare UTF8String and UTF8String", args{x: utf8Atv, y: utf8Atv}, true, false},
		{"Compare PrintableString and PrintableString", args{x: pAtv, y: pAtv}, true, false},
		{"Compare UTF8String and PrintableString", args{x: utf8Atv, y: pAtv}, true, false},
		{"Compare PrintableString and IA5String", args{x: pAtv, y: ia5Atv}, false, false},
		{"Compare PrintableString and BMPString", args{x: pAtv, y: bmpAtv}, false, false},
		{"Compare BMPString and BMPString", args{x: bmpAtv, y: bmpAtv}, true, false},
		{"Compare BMPString and IA5String", args{x: bmpAtv, y: ia5Atv}, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotResult, err := compareAttribute(tt.args.x, tt.args.y)
			if (err != nil) != tt.wantErr {
				t.Errorf("compareAttribute() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotResult != tt.wantResult {
				t.Errorf("compareAttribute() gotResult = %v, want %v", gotResult, tt.wantResult)
			}
		})
	}
}

func Test_isComparableDirectoryString1(t *testing.T) {
	type args struct {
		tx int
		ty int
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"PrintableString PrintableString", args{asn1.TagPrintableString, asn1.TagPrintableString}, true},
		{"PrintableString UTF8String", args{asn1.TagPrintableString, asn1.TagUTF8String}, true},
		{"UTF8String PrintableString", args{asn1.TagUTF8String, asn1.TagPrintableString}, true},
		{"UTF8String UTF8String", args{asn1.TagUTF8String, asn1.TagUTF8String}, true},
		{"PrintableString TeletexString", args{asn1.TagPrintableString, asn1.TagT61String}, false},
		{"UTF8String BMPString", args{asn1.TagUTF8String, asn1.TagBMPString}, false},
		{"IA5String UTF8String", args{asn1.TagIA5String, asn1.TagUTF8String}, false},
		{"IA5String IA5String", args{asn1.TagIA5String, asn1.TagIA5String}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isComparableDirectoryString(tt.args.tx, tt.args.ty); got != tt.want {
				t.Errorf("isComparableDirectoryString() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_compareByCaseInsensitiveExactMatch(t *testing.T) {
	type args struct {
		s string
		t string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"abc123-,abc123-", args{"abc123-", "abc123-"}, true},
		{"abc123-,Abc123-", args{"abc123-", "AbC123-"}, true},
		{"abc123-,xyz123-", args{"abc123-", "xyz123-"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := compareByCaseInsensitiveExactMatch(tt.args.s, tt.args.t); got != tt.want {
				t.Errorf("compareByCaseInsensitiveExactMatch() = %v, want %v", got, tt.want)
			}
		})
	}
}

//Add more cases
func Test_compareByCaseIgnoreMatch(t *testing.T) {
	type args struct {
		s string
		t string
	}
	tests := []struct {
		name       string
		args       args
		wantResult bool
		wantErr    bool
	}{
		{"abc123-,abc123-", args{"abc123-", "abc123-"}, true, false},
		{"abc123-,Abc123-", args{"abc123-", "AbC123-"}, true, false},
		{"abc123-,xyz123-", args{"abc123-", "xyz123-"}, false, false},
		{" foo ,foo", args{" foo ", "foo"}, true, false},
		{"foo bar, Foo  bar ", args{"foo bar", "Foo  bar "}, true, false},
		{"漢字, 漢字　　", args{"漢字", " 漢字　　"}, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotResult, err := compareByCaseIgnoreMatch(tt.args.s, tt.args.t)
			if (err != nil) != tt.wantErr {
				t.Errorf("compareByCaseIgnoreMatch() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotResult != tt.wantResult {
				t.Errorf("compareByCaseIgnoreMatch() gotResult = %v, want %v", gotResult, tt.wantResult)
			}
		})
	}
}

func Test_compareByBinaryComparison(t *testing.T) {
	type args struct {
		x []byte
		y []byte
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"Equal", args{[]byte{0x12, 0x34}, []byte{0x12, 0x34}}, true},
		{"Not Equal", args{[]byte{0x12, 0x34}, []byte{0x12, 0x32}}, false},
		{"Blank", args{[]byte{}, []byte{}}, false},}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := compareByBinaryComparison(tt.args.x, tt.args.y); got != tt.want {
				t.Errorf("compareByBinaryComparison() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_toString(t *testing.T) {
	case1, _ := hex.DecodeString("130141")
	case2, _ := hex.DecodeString("0C0141")
	case3, _ := hex.DecodeString("160141")
	case4, _ := hex.DecodeString("16014141")
	type args struct {
		src []byte
	}
	tests := []struct {
		name    string
		args    args
		wantS   string
		wantErr bool
	}{
		{"PrintableString", args{case1}, "A", false},
		{"UTF8String", args{case2}, "A", false},
		{"IA5String", args{case3}, "A", false},
		{"Broken Data", args{case4}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotS, err := toString(tt.args.src)
			if (err != nil) != tt.wantErr {
				t.Errorf("toString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotS != tt.wantS {
				t.Errorf("toString() gotS = %v, want %v", gotS, tt.wantS)
			}
		})
	}
}

func Test_stringPrepare(t *testing.T) {
	type args struct {
		s string
	}
	tests := []struct {
		name    string
		args    args
		want    []rune
		wantErr bool
	}{
		{"abc123-", args{"abc123-"}, []rune(" abc123- "), false},
		{"Abc123-", args{"Abc123-"}, []rune(" abc123- "), false},
		{"foo bar", args{"foo bar"}, []rune(" foo  bar "), false},
		{"    foo bar   ", args{"foo bar"}, []rune(" foo  bar "), false},
		{" foo            bar ", args{"foo bar"}, []rune(" foo  bar "), false},
		{"パパ", args{"パパ"}, []rune(" パパ "), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := stringPrepare(tt.args.s)
			if (err != nil) != tt.wantErr {
				t.Errorf("stringPrepare() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("stringPrepare() got = %v, want %v", got, tt.want)
			}
		})
	}
}
