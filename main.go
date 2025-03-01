package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/bluesky-social/indigo/api/agnostic"
	"github.com/bluesky-social/indigo/api/atproto"
	"github.com/bluesky-social/indigo/api/bsky"
	"github.com/bluesky-social/indigo/atproto/crypto"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/bluesky-social/indigo/lex/util"
	"github.com/bluesky-social/indigo/util/cliutil"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/acme/autocert"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func main() {
	app := &cli.App{
		Name:  "achilles",
		Usage: "A basic labeler implementation",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "port",
				Aliases: []string{"p"},
				Value:   "8080",
				Usage:   "HTTP server port (used when TLS is disabled)",
			},
			&cli.StringFlag{
				Name:    "domain",
				Aliases: []string{"d"},
				Usage:   "Domain name for automatic TLS certificate (enables HTTPS)",
			},
			&cli.BoolFlag{
				Name:  "tls",
				Value: false,
				Usage: "Enable TLS with provided domain name",
			},
			&cli.StringFlag{
				Name:  "cert-dir",
				Value: "./.cache/certs",
				Usage: "Directory to cache TLS certificates",
			},
			&cli.StringFlag{
				Name:  "db-path",
				Value: "./achilles.db",
				Usage: "Path to SQLite database file",
			},
		},
		Commands: []*cli.Command{
			setupAccountCmd,
			adjustDidDocCmd,
			generateKeypairCmd,
		},
		Action: runServer,
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

var generateKeypairCmd = &cli.Command{
	Name: "generate-key",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name: "auth",
		},
		&cli.StringFlag{
			Name:  "pds-host",
			Value: "https://bsky.social",
		},
		&cli.StringFlag{
			Name:  "keyfile",
			Value: "priv.key",
		},
	},
	Action: func(cctx *cli.Context) error {

		sec, err := crypto.GeneratePrivateKeyP256()
		if err != nil {
			return err
		}
		privMultibase := sec.Multibase()

		if err := os.WriteFile(cctx.String("keyfile"), []byte(privMultibase), 0660); err != nil {
			return err
		}

		return nil
	},
}

var adjustDidDocCmd = &cli.Command{
	Name: "adjust-did",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name: "auth",
		},
		&cli.StringFlag{
			Name:  "pds-host",
			Value: "https://bsky.social",
		},
		&cli.StringFlag{
			Name:     "labeler-host",
			Required: true,
		},
		&cli.StringFlag{
			Name:     "private-key",
			Required: true,
		},
	},
	Action: func(cctx *cli.Context) error {
		client, err := cliutil.GetXrpcClient(cctx, true)
		if err != nil {
			return err
		}

		pkdata, err := os.ReadFile(cctx.String("private-key"))
		if err != nil {
			return err
		}

		privk, err := crypto.ParsePrivateMultibase(string(pkdata))
		if err != nil {
			return err
		}

		ctx := context.TODO()

		/*
					  "verificationMethod": [
			    {
			      "id": "did:plc:n3timvoib5nau7gvwd6cshap#atproto",
			      "type": "Multikey",
			      "controller": "did:plc:n3timvoib5nau7gvwd6cshap",
			      "publicKeyMultibase": "zQ3shWAFF3uWjMhomnE6ZKVZJctC9LChqWVZkL2K7jAKktLgF"
			    },
			    {
			      "id": "did:plc:n3timvoib5nau7gvwd6cshap#atproto_label",
			      "type": "Multikey",
			      "controller": "did:plc:n3timvoib5nau7gvwd6cshap",
			      "publicKeyMultibase": "zQ3shcnfWLQN1bY4d2patsEAYFzy4xp1zdckEvHsV7S4ocTnC"
			    }
			  ],
			  "service": [
			    {
			      "id": "#atproto_pds",
			      "type": "AtprotoPersonalDataServer",
			      "serviceEndpoint": "https://chanterelle.us-west.host.bsky.network"
			    },
			    {
			      "id": "#atproto_labeler",
			      "type": "AtprotoLabeler",
			      "serviceEndpoint": "https://bladerunner.club"
			    }
		*/

		data, err := fetchPLCData(ctx, "https://plc.directory", syntax.DID(client.Auth.Did))
		if err != nil {
			return err
		}

		data.Services["atproto_labeler"] = PLCService{
			Type:     "AtprotoLabeler",
			Endpoint: cctx.String("labeler-host"),
		}

		pubk, err := privk.PublicKey()
		if err != nil {
			return err
		}

		data.VerificationMethods["atproto_label"] = pubk.DIDKey()

		if err := atproto.IdentityRequestPlcOperationSignature(ctx, client); err != nil {
			return err
		}

		reader := bufio.NewReader(os.Stdin)
		fmt.Println("enter code from email: ")
		token, _ := reader.ReadString('\n')

		token = strings.TrimSpace(token)

		b, err := json.Marshal(data)
		if err != nil {
			return err
		}

		fmt.Println(string(b))

		var input agnostic.IdentitySignPlcOperation_Input
		if err := json.Unmarshal(b, &input); err != nil {
			return err
		}

		input.Token = &token

		signedOp, err := agnostic.IdentitySignPlcOperation(ctx, client, &input)
		if err != nil {
			return err
		}

		if err := agnostic.IdentitySubmitPlcOperation(ctx, client, &agnostic.IdentitySubmitPlcOperation_Input{
			Operation: signedOp.Operation,
		}); err != nil {
			return fmt.Errorf("failed to submit: %w", err)
		}

		return nil
	},
}

var setupAccountCmd = &cli.Command{
	Name: "setup-account",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name: "auth",
		},
		&cli.StringFlag{
			Name:  "pds-host",
			Value: "https://bsky.social",
		},
	},
	Action: func(cctx *cli.Context) error {
		client, err := cliutil.GetXrpcClient(cctx, true)
		if err != nil {
			return err
		}

		ctx := context.TODO()

		fi, err := os.Open(cctx.Args().First())
		if err != nil {
			return err
		}
		defer fi.Close()

		var rec bsky.LabelerService
		if err := json.NewDecoder(fi).Decode(&rec); err != nil {
			return err
		}

		rec.CreatedAt = time.Now().Format(time.RFC3339)

		rkey := "self"
		resp, err := atproto.RepoCreateRecord(ctx, client, &atproto.RepoCreateRecord_Input{
			Collection: "app.bsky.labeler.service",
			Record: &util.LexiconTypeDecoder{
				Val: &rec,
			},
			Repo: client.Auth.Did,
			Rkey: &rkey,
		})
		if err != nil {
			return err
		}

		fmt.Println(resp.Uri)

		return nil
	},
}

type Server struct {
	DB   *gorm.DB
	Echo *echo.Echo
}

func (s *Server) handleQueryLabels(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]string{
		"status": "not implemented yet",
	})
}

func runServer(cctx *cli.Context) error {
	port := cctx.String("port")
	domain := cctx.String("domain")
	tlsEnabled := cctx.Bool("tls")
	certDir := cctx.String("cert-dir")
	dbPath := cctx.String("db-path")

	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	e := echo.New()

	srv := &Server{
		DB:   db,
		Echo: e,
	}

	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	// Routes
	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "Hello, Achilles!")
	})
	e.GET("/xrpc/com.atproto.label.queryLabels", srv.handleQueryLabels)

	// Ensure certificate cache directory exists
	if tlsEnabled && domain != "" {
		if err := os.MkdirAll(certDir, 0755); err != nil {
			return fmt.Errorf("failed to create certificate cache directory: %w", err)
		}
	}

	// Start server with or without TLS
	if tlsEnabled && domain != "" {
		// Auto TLS with Let's Encrypt
		e.AutoTLSManager.Cache = autocert.DirCache(certDir)
		e.AutoTLSManager.HostPolicy = autocert.HostWhitelist(domain)

		// Start HTTP server for redirecting HTTP to HTTPS
		go func() {
			httpEngine := echo.New()
			httpEngine.Pre(middleware.HTTPSRedirect())
			log.Printf("HTTP server starting on :80 (redirecting to HTTPS)")
			if err := httpEngine.Start(":80"); err != http.ErrServerClosed {
				log.Printf("HTTP redirect server error: %v", err)
			}
		}()

		fmt.Printf("Server starting with TLS on https://%s\n", domain)
		return e.StartAutoTLS(":443")
	}

	// Start regular HTTP server
	serverAddr := fmt.Sprintf(":%s", port)
	fmt.Printf("Server starting on http://localhost%s\n", serverAddr)
	return e.Start(serverAddr)
}

type PLCService struct {
	Type     string `json:"type"`
	Endpoint string `json:"endpoint"`
}

type PLCData struct {
	DID                 string                `json:"did"`
	VerificationMethods map[string]string     `json:"verificationMethods"`
	RotationKeys        []string              `json:"rotationKeys"`
	AlsoKnownAs         []string              `json:"alsoKnownAs"`
	Services            map[string]PLCService `json:"services"`
}

func fetchPLCData(ctx context.Context, plcHost string, did syntax.DID) (*PLCData, error) {
	if plcHost == "" {
		return nil, fmt.Errorf("PLC host not configured")
	}

	url := fmt.Sprintf("%s/%s/data", plcHost, did)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("PLC HTTP request failed")
	}
	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var d PLCData
	if err := json.Unmarshal(respBytes, &d); err != nil {
		return nil, err
	}
	return &d, nil
}
