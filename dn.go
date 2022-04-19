//Package dn implements comparison of distinguished name described in RFC 5280( Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile) section-7
/*
Comparison algorithm is following:

1) Check two distinguished names have the same number of RDNs, for each RDN in DN1 there is a matching RDN in DN2, and the matching RDNs appear in the same order in both DNs.

2) Check two relative distinguished names have the same number of naming attributes and for each naming attribute in RDN1 there is a matching naming attribute in RDN2.

3) Check two naming attributes are the same types and the values of the attributes are matched. The rules for value of the attribute matching are:
  3-1. If two naming attributes are domain component, then they are compared by case-insensitive exact match( RFC5280-section7.2, 7.3).
  3-2. If both two naming attributes of values are encoded in UTF8String or PrintableString, then they are compared by caseIgnoreMatch( RFC4517section-4.2.11) after processing with the string preparation algorithm( RFC4518, RFC5280-section7.1).
  3-3. If any other cases, then two naming attributes of values are compared by binary comparison( RFC5280-section7.1).
*/
package dn

import (
	"bytes"
	"encoding/asn1"
	"errors"
	"github.com/tardevnull/ldapstrprep"
	"strings"
)

//https://tools.ietf.org/html/rfc5280#appendix-A.1
//Oid-domainComponent   AttributeType ::= { 0 9 2342 19200300 100 1 25 }
var oidDomainComponent = asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}

type dn []rdnSET

type rdnSET []attribute

type attribute struct {
	Oid      asn1.ObjectIdentifier
	RawValue asn1.RawValue
}

//Compare reports whether issuer and subject matches.
func Compare(issuer []byte, subject []byte) (result bool, err error) {
	var s []rdnSET
	var i []rdnSET

	if len(issuer) == 0 {
		//https://tools.ietf.org/html/rfc5280#section-4.1.2.4
		//The issuer field MUST contain a non-empty distinguished name (DN)
		return false, errors.New("dn: the issuer field must contain a non-empty distinguished name")
	}

	if len(subject) == 0 {
		//issuer is not blank, but subject is blank
		return false, nil
	}

	if i, err = parseDn(issuer); err != nil {
		return false, err
	}
	if s, err = parseDn(subject); err != nil {
		return false, err
	}
	return compareDistinguishedName(i, s)
}

//parseDn decodes dnBytes, which is encoded as Distinguished Name, to dn.
func parseDn(dnBytes []byte) (dn dn, err error) {
	if rest, err := asn1.Unmarshal(dnBytes, &dn); err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, errors.New("dn: failed to parse distinguished name")
	}
	return dn, err
}

//compareDistinguishedName reports whether xd and yd matches.
func compareDistinguishedName(xd []rdnSET, yd []rdnSET) (result bool, err error) {
	if len(xd) != len(yd) {
		return false, nil
	}

	for i := 0; i < len(xd); i++ {
		isMatched := false
		if isMatched, err = compareRelativeDistinguishedName(xd[i], yd[i]); err != nil {
			return false, err
		}
		if isMatched == false {
			return false, nil
		}
	}
	return true, nil

}

//compareRelativeDistinguishedName reports whether xr and yr matches.
func compareRelativeDistinguishedName(xr rdnSET, yr rdnSET) (result bool, err error) {
	if len(xr) != len(yr) {
		return false, nil
	}

	rest := yr
	for i := 0; i < len(xr); i++ {
		isFound := false
		if isFound, rest, err = findMatchedAttribute(xr[i], rest); err != nil {
			return false, err
		}
		if isFound == false {
			return false, nil
		}
	}
	return true, nil
}

//findMatchedAttribute finds RDN r contains attribute atv and if r contains atv, then return true and RDN which removed atv from r.
func findMatchedAttribute(atv attribute, r rdnSET) (result bool, rest rdnSET, err error) {
	isFound := false
	rest = r
	for i := 0; i < len(r); i++ {
		if isFound, err = compareAttribute(atv, rest[i]); err != nil {
			return false, nil, err
		}
		if isFound {
			if rest, err = removeAttribute(i, rest); err != nil {
				return false, nil, err
			}
			break
		}
	}
	return isFound, rest, nil
}

//removeAttribute removes attribute specified by index i from r and returns it.
func removeAttribute(index int, r rdnSET) (result rdnSET, err error) {
	if index < 0 || index >= len(r) {
		return nil, errors.New("dn: rdnSET bounds out of range")
	}
	result = make(rdnSET, len(r), len(r))
	copy(result, r)
	result = append(result[:index], result[index+1:]...)
	return result, nil
}

//compareAttribute reports whether attribute x and attribute y matches.
//1. If both attributes are domain component, then they are compared by case-insensitive exact match.
//2. If both of attributes of values are encoded in UTF8String or PrintableString, then they are compared by caseIgnoreMatch(RFC4517) after processing with the string preparation algorithm(RFC4518).
//3. If any other cases, then attributes of values are compared by binary comparison.
func compareAttribute(x attribute, y attribute) (result bool, err error) {
	if !x.Oid.Equal(y.Oid) {
		return false, nil
	}

	var s string
	if s, err = toString(x.RawValue.FullBytes); err != nil {
		return false, err
	}
	var t string
	if t, err = toString(y.RawValue.FullBytes); err != nil {
		return false, err
	}

	//https://tools.ietf.org/html/rfc5280#section-4.1.2.4
	//In addition, implementations of this specification MUST be prepared
	//to receive the domainComponent attribute, as defined in [RFC4519].
	//
	//https://tools.ietf.org/html/rfc5280#section-7.3
	//Conforming implementations shall perform a case-insensitive exact
	//match when comparing domainComponent attributes in distinguished
	//names, as described in Section 7.2.
	//
	//https://tools.ietf.org/html/rfc5280#section-7.2
	//When comparing DNS names for equality, conforming implementations
	//MUST perform a case-insensitive exact match on the entire DNS name.
	if x.Oid.Equal(oidDomainComponent) && y.Oid.Equal(oidDomainComponent) {
		//https://tools.ietf.org/html/rfc5280#appendix-A
		//DomainComponent ::=  IA5String
		if x.RawValue.Tag != asn1.TagIA5String || y.RawValue.Tag != asn1.TagIA5String {
			return false, errors.New("dn: domain component should be IA5String")
		}
		return compareByCaseInsensitiveExactMatch(s, t), nil
	}

	//https://tools.ietf.org/html/rfc5280#section-7.1
	//Conforming implementations MUST
	//support UTF8String and PrintableString.
	//
	//https://tools.ietf.org/html/rfc5280#section-4.1.2.6
	//Implementations of this
	//specification MAY use the comparison rules in Section 7.1 to process
	//unfamiliar attribute types (i.e., for name chaining) whose attribute
	//values use one of the encoding options from DirectoryString.
	if isComparableDirectoryString(x.RawValue.Tag, y.RawValue.Tag) {
		return compareByCaseIgnoreMatch(s, t) //check definition -<undefined case
	}

	//https://tools.ietf.org/html/rfc5280#section-4.1.2.6
	//Binary comparison should be used when unfamiliar attribute types include
	//attribute values with encoding options other than those found in
	//DirectoryString.
	//
	//https://tools.ietf.org/html/rfc5280#section-8
	//Inconsistent application of name comparison rules can result in
	//acceptance of invalid X.509 certification paths or rejection of valid
	//ones.  The X.500 series of specifications defines rules for comparing
	//distinguished names that require comparison of strings without regard
	//to case, character set, multi-character white space substring, or
	//leading and trailing white space.  This specification relaxes these
	//requirements, requiring support for binary comparison at a minimum.
	return compareByBinaryComparison(x.RawValue.FullBytes, y.RawValue.FullBytes), nil
}

//isComparableDirectoryString reports whether tx and ty is comparable by Case Ignore Match.
//If tx and ty are UTF8String tag or PrintableString tag ,then returns true.
//Any other cases, returns false.
func isComparableDirectoryString(tx int, ty int) bool {
	//https://tools.ietf.org/html/rfc5280#section-7.1
	//Implementations may encounter certificates and CRLs with
	//names encoded using TeletexString, BMPString, or UniversalString, but
	//support for these is OPTIONAL.

	isXComparable := false
	isYComparable := false

	//check tag of x is PrintableString or UTF8String
	switch tx {
	case asn1.TagUTF8String:
		isXComparable = true
	case asn1.TagPrintableString:
		isXComparable = true
	default:
		isXComparable = false
	}

	//check tag of y is PrintableString or UTF8String
	switch ty {
	case asn1.TagUTF8String:
		isYComparable = true
	case asn1.TagPrintableString:
		isYComparable = true
	default:
		isYComparable = false
	}
	return isXComparable && isYComparable
}

//compareByCaseIgnoreMatch compares s with t by case-insensitive exact match.
func compareByCaseInsensitiveExactMatch(s string, t string) bool {
	//https://tools.ietf.org/html/rfc5280#section-7.1
	return strings.EqualFold(s, t)
}

//compareByCaseIgnoreMatch compares s with t by CaseIgnore Match.
func compareByCaseIgnoreMatch(s string, t string) (result bool, err error) {
	var sr []rune
	var tr []rune

	if sr, err = stringPrepare(s); err != nil {
		return false, err
	}

	if tr, err = stringPrepare(t); err != nil {
		return false, err
	}

	if string(sr) == string(tr) {
		return true, nil
	}

	return false, nil
}

//compareByBinaryComparison compares x with b by Binary Comparison.
func compareByBinaryComparison(x []byte, y []byte) bool {
	if len(x) == 0 || len(y) == 0 {
		return false
	}
	if !bytes.Equal(x, y) {
		return false
	}
	return true
}

//toString decodes src ,which is encoded as ASN.1 string, to string.
func toString(src []byte) (s string, err error) {
	if rest, err := asn1.Unmarshal(src, &s); err != nil {
		return "", err
	} else if len(rest) != 0 {
		return "", errors.New("dn: trailing data after ASN.1 of string")
	}
	return s, nil
}

//stringPrepare performs the six-step string preparation algorithm described in [RFC4518] for s.
func stringPrepare(s string) ([]rune, error) {
	//https://tools.ietf.org/html/rfc4518#section-2
	//TODO modify ldapstrprep
	//1. Transcode
	u := ldapstrprep.Transcode(s)
	//2. Map
	u = ldapstrprep.MapCharacters(u, true)
	//3. Normalize
	u = ldapstrprep.Normalize(u)
	//4. Prohibit
	if isProhibited, err := ldapstrprep.IsProhibited(u); isProhibited == true {
		return nil, err
	}
	//5. Check Bidi
	//Do nothing.
	//6. Insignificant Character Handling
	u = ldapstrprep.ApplyInsignificantSpaceHandling(u)
	return u, nil
}
