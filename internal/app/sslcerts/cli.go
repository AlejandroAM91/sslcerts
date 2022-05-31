package sslcerts

import (
	"bufio"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"os"
	"strings"

	"github.com/urfave/cli/v2"
)

const (
	cliFlagCAName          = "ca"
	cliFlagCertName        = "cert"
	cliFlagInteractiveName = "interactive"
	cliFlagKeyName         = "key"
	cliFlagOutName         = "out"

	cliDefaultKey  = "certkey.pem"
	cliDefaultPKey = "certpub.pem"
	cliDefaultReq  = "cert.csr"
	cliDefaultCert = "cert.crt"
)

func Cli() *cli.App {
	return &cli.App{
		Name:    "sslcerts",
		Usage:   "Generates ssl keys and certificates",
		Version: VERSION,
		Commands: []*cli.Command{
			{
				Name:  "key",
				Usage: "Generates ssl private keys",
				Flags: []cli.Flag{
					cliFlagOut(cliDefaultKey, "Generated private key output file"),
				},
				Action: cliActionKey,
			},
			{
				Name:  "pkey",
				Usage: "Generates ssl public keys",
				Flags: []cli.Flag{
					cliFlagKey(),
					cliFlagOut(cliDefaultPKey, "Generated public key output file"),
				},
				Action: cliActionPKey,
			},
			{
				Name:  "req",
				Usage: "Generates ssl certificate signing requests",
				Flags: []cli.Flag{
					cliFlagInteractive(),
					cliFlagKey(),
					cliFlagOut(cliDefaultReq, "Generated certificate signing request output file"),
				},
				Action: cliActionReq,
			},
			{
				Name:  "cert",
				Usage: "Generates ssl certificate",
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:  cliFlagCAName,
						Usage: "Indicates this signing certificate is for a Certificate Authority",
					},
					cliFlagCert("Parent certificate to use. If empty then the certificate is self-signed"),
					cliFlagKey(),
					cliFlagOut(cliDefaultCert, "Generated certificate output file"),
				},
				Action:    cliActionCert,
				ArgsUsage: "<csr>...",
			},
		},
	}
}

func cliActionKey(ctx *cli.Context) error {
	oname := ctx.String(cliFlagOutName)

	_, err := createPrivateKey(oname)
	if err != nil {
		return cli.Exit(err, 1)
	}
	return nil
}

func cliActionPKey(ctx *cli.Context) error {
	kname := ctx.String(cliFlagKeyName)
	oname := ctx.String(cliFlagOutName)

	key, err := readCreatePrivateKey(kname)
	if err != nil {
		return cli.Exit(err, 1)
	}

	_, err = createPublicKey(oname, key)
	if err != nil {
		return cli.Exit(err, 1)
	}
	return nil
}

func cliActionReq(ctx *cli.Context) error {
	kname := ctx.String(cliFlagKeyName)
	oname := ctx.String(cliFlagOutName)

	key, err := readCreatePrivateKey(kname)
	if err != nil {
		return cli.Exit(err, 1)
	}

	var subj pkix.Name
	if ctx.NArg() > 0 {
		cliParseSubj(ctx.Args().Slice(), &subj)
	}
	if ctx.Bool(cliFlagInteractiveName) {
		cliInteractiveSubj(&subj)
	}
	fmt.Println(subj)

	err = createCertificateRequest(oname, key, subj)
	if err != nil {
		return cli.Exit(err, 1)
	}
	return nil
}

func cliActionCert(ctx *cli.Context) error {
	pcert := ctx.String(cliFlagCertName)
	kname := ctx.String(cliFlagKeyName)
	oname := ctx.String(cliFlagOutName)
	ca := ctx.Bool(cliFlagCAName)

	if ctx.NArg() == 0 {
		return cli.Exit("no csr file provided", 1)
	}

	key, err := readCreatePrivateKey(kname)
	if err != nil {
		return cli.Exit(err, 1)
	}

	var cert *x509.Certificate
	if pcert != "" {
		cert, err = readCertificate(pcert)
		if err != nil {
			return cli.Exit(err, 1)
		}
	}

	req, err := readCertificateRequest(ctx.Args().First())
	if err != nil {
		return cli.Exit(err, 1)
	}

	if err = req.CheckSignature(); err != nil {
		return cli.Exit(err, 1)
	}

	err = createCertificate(oname, req, cert, key, ca)
	if err != nil {
		return cli.Exit(err, 1)
	}
	return nil
}

func cliFlagCert(usage string) cli.Flag {
	return &cli.StringFlag{
		Name:  cliFlagCertName,
		Usage: usage,
	}
}

func cliFlagInteractive() cli.Flag {
	return &cli.BoolFlag{
		Name:    cliFlagInteractiveName,
		Aliases: []string{"i"},
		Usage:   "Allows to request extra info interactively",
	}
}

func cliFlagKey() cli.Flag {
	return &cli.StringFlag{
		Name:  cliFlagKeyName,
		Value: cliDefaultKey,
		Usage: "Private key to use. Generated if not exists",
	}
}

func cliFlagOut(value, usage string) cli.Flag {
	return &cli.StringFlag{
		Name:    cliFlagOutName,
		Aliases: []string{"o"},
		Value:   value,
		Usage:   usage,
	}
}

func cliInteractiveSubj(subj *pkix.Name) {
	if len(subj.Country) == 0 {
		promptSubj("Country Name (2 letter code)", &subj.Country)
	}
	if len(subj.Province) == 0 {
		promptSubj("Province", &subj.Province)
	}
	if len(subj.Locality) == 0 {
		promptSubj("Locality", &subj.Locality)
	}

	if len(subj.Organization) == 0 {
		promptSubj("Organization", &subj.Organization)
	}
	if len(subj.OrganizationalUnit) == 0 {
		promptSubj("Organizational Unit", &subj.OrganizationalUnit)
	}

	if len(subj.CommonName) == 0 {
		v := prompt("Common Name (FQDN or your name)")
		if v != "" {
			subj.CommonName = v
		}
	}
}

func cliParseSubj(args []string, subj *pkix.Name) {
	for _, arg := range args {
		param := strings.Split(arg, "=")
		switch param[0] {
		case "C":
			subj.Country = []string{param[1]}
		case "CN":
			subj.CommonName = param[1]
		case "L":
			subj.Locality = []string{param[1]}
		case "O":
			subj.Organization = []string{param[1]}
		case "OU":
			subj.OrganizationalUnit = []string{param[1]}
		case "ST":
			subj.Province = []string{param[1]}
		}
	}
}

func promptSubj(label string, subj *[]string) {
	v := prompt(label)
	if v != "" {
		*subj = []string{v}
	}
}

func prompt(label string) string {
	fmt.Print(label + ": ")
	s := bufio.NewReader(os.Stdin)
	input, _ := s.ReadString('\n')
	return strings.TrimSpace(input)
}
