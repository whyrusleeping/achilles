package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bluesky-social/indigo/api/agnostic"
	"github.com/bluesky-social/indigo/api/atproto"
	"github.com/bluesky-social/indigo/api/bsky"
	"github.com/bluesky-social/indigo/atproto/crypto"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/bluesky-social/indigo/events"
	"github.com/bluesky-social/indigo/lex/util"
	"github.com/bluesky-social/indigo/util/cliutil"
	"github.com/gorilla/websocket"
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
			&cli.StringFlag{
				Name:  "private-key",
				Value: "priv.key",
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
		_, err = atproto.RepoDeleteRecord(ctx, client, &atproto.RepoDeleteRecord_Input{
			Collection: "app.bsky.labeler.service",
			Repo:       client.Auth.Did,
			Rkey:       rkey,
		})
		if err != nil {
			fmt.Println("deleting old record: ", err)
		}

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
	Sk   crypto.PrivateKeyExportable

	Events *events.EventManager
}

func (s *Server) handleQueryLabels(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]string{
		"status": "not implemented yet",
	})
}

var (
	upgrader = websocket.Upgrader{}
)

func (s *Server) handleSubscribeLabels(c echo.Context) error {
	var since *int64
	if sinceVal := c.QueryParam("cursor"); sinceVal != "" {
		sval, err := strconv.ParseInt(sinceVal, 10, 64)
		if err != nil {
			return err
		}
		since = &sval
	}

	ctx, cancel := context.WithCancel(c.Request().Context())
	defer cancel()

	// TODO: authhhh
	conn, err := websocket.Upgrade(c.Response(), c.Request(), c.Response().Header(), 10<<10, 10<<10)
	if err != nil {
		return fmt.Errorf("upgrading websocket: %w", err)
	}

	defer conn.Close()

	lastWriteLk := sync.Mutex{}
	lastWrite := time.Now()

	// Start a goroutine to ping the client every 30 seconds to check if it's
	// still alive. If the client doesn't respond to a ping within 5 seconds,
	// we'll close the connection and teardown the consumer.
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				lastWriteLk.Lock()
				lw := lastWrite
				lastWriteLk.Unlock()

				if time.Since(lw) < 30*time.Second {
					continue
				}

				if err := conn.WriteControl(websocket.PingMessage, []byte{}, time.Now().Add(5*time.Second)); err != nil {
					slog.Warn("failed to ping client", "err", err)
					cancel()
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	conn.SetPingHandler(func(message string) error {
		err := conn.WriteControl(websocket.PongMessage, []byte(message), time.Now().Add(time.Second*60))
		if err == websocket.ErrCloseSent {
			return nil
		} else if e, ok := err.(net.Error); ok && e.Temporary() {
			return nil
		}
		return err
	})

	// Start a goroutine to read messages from the client and discard them.
	go func() {
		for {
			_, _, err := conn.ReadMessage()
			if err != nil {
				slog.Warn("failed to read message from client", "err", err)
				cancel()
				return
			}
		}
	}()

	events, cleanup, err := s.Events.Subscribe(ctx, "", func(evt *events.XRPCStreamEvent) bool { return true }, since)
	if err != nil {
		return err
	}
	defer cleanup()

	for {
		select {
		case evt, ok := <-events:
			if !ok {
				slog.Error("event stream closed unexpectedly")
				return nil
			}

			wc, err := conn.NextWriter(websocket.BinaryMessage)
			if err != nil {
				slog.Error("failed to get next writer", "err", err)
				return err
			}

			if evt.Preserialized != nil {
				_, err = wc.Write(evt.Preserialized)
			} else {
				err = evt.Serialize(wc)
			}
			if err != nil {
				return fmt.Errorf("failed to write event: %w", err)
			}

			if err := wc.Close(); err != nil {
				slog.Warn("failed to flush-close our event write", "err", err)
				return nil
			}

			lastWriteLk.Lock()
			lastWrite = time.Now()
			lastWriteLk.Unlock()
		case <-ctx.Done():
			return nil
		}
	}
}

func runServer(cctx *cli.Context) error {
	port := cctx.String("port")
	domain := cctx.String("domain")
	tlsEnabled := cctx.Bool("tls")
	certDir := cctx.String("cert-dir")
	dbPath := cctx.String("db-path")
	privKey := cctx.String("private-key")

	pkb, err := os.ReadFile(privKey)
	if err != nil {
		return err
	}

	privk, err := crypto.ParsePrivateMultibase(string(pkb))
	if err != nil {
		return err
	}

	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	persist, err := events.NewDbPersistence(db, nil, nil)
	if err != nil {
		return err
	}

	em := events.NewEventManager(persist)

	e := echo.New()

	srv := &Server{
		DB:     db,
		Echo:   e,
		Sk:     privk,
		Events: em,
	}

	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	// Routes
	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "Hello, Achilles!")
	})
	e.GET("/xrpc/com.atproto.label.queryLabels", srv.handleQueryLabels)
	e.GET("/xrpc/com.atproto.label.subscribeLabels", srv.handleQueryLabels)

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
