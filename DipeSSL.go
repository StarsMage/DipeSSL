// SSL it's me^-^

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"
	"time"
)


var asciiArt = `
     ▒▓█    ▄▓▒ ▓ ▒█▀▀▀▄    ▄░█▀▀▀▀▄   ▄▒░▀▀▄ ` + "\x1b[95m" + ` ▄▒░▀▀▄` + "\x1b[0m" + `   ▄▒░     
     ▐▒▓   ▒░▀  ▒ ▀    ▒▄  ▒░▀      ░ ▓▒▀   ▓ ` + "\x1b[95m" + `▓▒▀   ▓` + "\x1b[0m" + `  ▒░▀      
      ▐▓  ▒░▀   ░▌     ▄▀ ▒░▀         ▒░    ▒ ` + "\x1b[95m" + `▒░    ▒ ` + "\x1b[0m" + `▒░▀       
▄█▀▀▀░ ▒  ▓▒░   ░▒▄   ▄▀  ▓▒░▄▄▄▄▀▀    ░░▄  ░ ` + "\x1b[95m" + ` ░░▄  ░` + "\x1b[0m" + ` ▓▒░       
▒    ▀ █▄  ▒░   ▒ ▓▒░█▀    ▓▒▀▀   ▀▀▄   ▀▀░▒▄  ` + "\x1b[95m" + ` ▀▀░▒▄ ` + "\x1b[0m" + ` ▒░     ▄ 
▓▌     ▄▀   ░█  ▓           ▓▒      ▒ ▄▄   ▒▓ ` + "\x1b[95m" + `▄▄   ▒▓  ` + "\x1b[0m" + ` ▒░     █
 ▒▄   ▄█     ░█ ▒▌           ▀▄▄▄▄▄▀  ░▄  ▄░▒ ` + "\x1b[95m" + `░▄  ▄░▒  ` + "\x1b[0m" + `  ░░▄▄▄▀ 
  ▒░░█▀       ░ ▓▒                    ▓█▄░▓▀  ` + "\x1b[95m" + `▓█▄░▓▀  ` + "\x1b[0m" + `    ░     
              █                       ▒ ░     ` + "\x1b[95m" + `▒ ░     ` + "\x1b[0m" + `    █     
                                      ░      ` + "\x1b[95m" + ` ░      ` + "\x1b[0m" + `                                           
`




var name = "01100100 01101001 01110000 01100101 01010011 01010011 01001100 "

type CertParam struct {
	CN string // Common name 
	SANs []string // subject alternativite names
	ValidityDay int // validity 
	ECDSAType string // type ECDSA encode
}

type Subject struct {
	C string // country
	O string // organization
	OU string // organization unit
	L string // locality
	ST string // province/state
}

type Path struct {
	CertPath string // path certificate
	KeyPath string // path key
}

func createKey(ECDSA string) (*ecdsa.PrivateKey, error) {
	curve := elliptic.P256()
	switch(strings.TrimSpace(strings.ToLower(ECDSA))){
	case "p-256": curve = elliptic.P256()
	case "p-384": curve = elliptic.P384()
	case "p-521": curve = elliptic.P521()
	default: fmt.Println("undefiend ECDSA type")
	}
	fmt.Printf("USING %s\n",strings.TrimSpace(ECDSA))

	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil { return nil, errors.New("failed generate private key")}

	return privateKey, nil
}

func createX509Certificate(privateKey *ecdsa.PrivateKey,cp CertParam,subject Subject) ([]byte, error) {
	SerialNumberLimit := new(big.Int).Lsh(big.NewInt(1),128)
	SerialNumber, err := rand.Int(rand.Reader, SerialNumberLimit)
	if err != nil {
		return nil, errors.New("failed to generate serial number")
	}


	tempSertData := x509.Certificate{
		SerialNumber: SerialNumber,
		Subject: pkix.Name{
			Organization: []string{subject.O},
			CommonName: cp.CN,
		},
		DNSNames: cp.SANs,
		NotBefore: time.Now(),
		NotAfter: time.Now().Add(time.Duration(cp.ValidityDay) * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA: false,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &tempSertData,&tempSertData,&privateKey.PublicKey,privateKey)
	if err != nil || len(derBytes) == 0 { return nil, errors.New("failed to create certificate")}

	return derBytes, nil
}

func saveAndKeyToPEM(certificate []byte, privKey *ecdsa.PrivateKey, certPath, keyPath string) error {

	// certificate
	certFile, err := os.Create(certPath)
	if err != nil { return fmt.Errorf("failed to create cert file: %w", err) }

	defer certFile.Close()

	certPemBlock := &pem.Block{
		Type: "CERTIFICATE",
		Bytes: certificate,
	}

	if err := pem.Encode(certFile, certPemBlock); err != nil { return fmt.Errorf("failed to write cert to pem: %w", err)}

	//

	// key
	keyFile, err := os.Create(keyPath)
	if err != nil { return fmt.Errorf("failed to create key file: %w", err) }

	defer keyFile.Close()

	keyDerBytes, err := x509.MarshalECPrivateKey(privKey)
	if err != nil { return fmt.Errorf("failed to marshal ecdsa private key: %w", err) }

	keyPemBlock := &pem.Block{
		Type: "EC PRIVATE KEY",
		Bytes: keyDerBytes,
	}

	if err := pem.Encode(keyFile, keyPemBlock); err != nil { return  fmt.Errorf("failed to write key to pem: %w", err)}
	//

	return nil

}

func main() {

	// banner 
	fmt.Println(asciiArt)
	for i:=0;i<len(name);i++{fmt.Print("-")}
	fmt.Println()
	fmt.Println(time.Now())
	//

	//------- CertParam ----
    commonName := flag.String("cn","","common name SSL certificate.Required field.") // CN
	subjAltName := flag.String("san","","SAN(subject alternativite name) SSL certificate.EXAMPLE - hoster.com,hostok.com,hostomer.com,hostitron.com") // SAN
	validityDay := flag.Int("day",365,"Validity(Days). Standart - 365 days.")
	typeECDSA := flag.String("ecdsa","P-256","Type ECDSA encode. Standart - P-256.")

	//----------------------

	//------ Subject -------
	country := flag.String("c","","Country. Required field. Format - RU,US,EN.")
	organization := flag.String("o","","Organization. Required field. Format = My compane LLC.")
	organizationUint := flag.String("ou","","Organization Uint. Required field. Format = IT Department.")
	locality := flag.String("l","","Locality. Required field. Format = Berlin.")
	stateProvince := flag.String("s","","State/Province. Required field. Format = State Washington.")

	//---------------------

	//------- Path ---------
	certPath := flag.String("pc","","Path certificate. Required Field. C:\\ilovedipessl\\ or home\\ilovedipessl\\")
	keyPath := flag.String("pk","","Path key. Required Field. C:\\ilovedipessl\\ or home\\ilovedipessl\\")

	//----------------------
	
	// parse
	flag.Parse()
	//

	if  *country == "" || *organization == ""  || *organizationUint == "" || *locality == "" ||
	*stateProvince == "" || *commonName == "" || *certPath == "" || *keyPath == "" {flag.PrintDefaults(); log.Fatal("required field dont using!")}


	// Struct create
		// Certificate parametr
		UserCertParam := CertParam{
			CN: strings.TrimSpace(*commonName),
			SANs: strings.Split(*subjAltName,","),
			ValidityDay: *validityDay,
			ECDSAType: strings.TrimSpace(*typeECDSA),
		}

		// Subject
		UserSubject := Subject{
			C: strings.TrimSpace(*country),
			O: strings.TrimSpace(*organization),
			OU: strings.TrimSpace(*organizationUint),
			L: strings.TrimSpace(*locality),
			ST: strings.TrimSpace(*stateProvince),
		}

		// Path
		UserPath := Path{
			CertPath: strings.TrimSpace(*certPath),
			KeyPath: strings.TrimSpace(*keyPath),
		}
	//

	// create keys
	privateKey, err := createKey(UserCertParam.ECDSAType)
	if err != nil { panic(err) }
		// check len
			fmt.Printf("hex key : %v\n", privateKey)
		//
	//

	// create x509 certificate
	certificateX509, err := createX509Certificate(privateKey, UserCertParam,UserSubject)
		// check len
			fmt.Printf("length binary certificate : %d\n", len(certificateX509))
		//

	//

	// save certificat
	if err := saveAndKeyToPEM(certificateX509, privateKey,UserPath.CertPath,UserPath.KeyPath); err != nil { panic(err) }
	//

	fmt.Println("EXECUTE!")
	fmt.Println(name)
}