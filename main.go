package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/bluesky-social/indigo/api/atproto"
	"github.com/bluesky-social/indigo/api/bsky"
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
		Commands: []*cli.Command{setupAccountCmd},
		Action:   runServer,
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
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
