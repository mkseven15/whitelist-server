package main

import (
	"context"
	"database/sql"
	"log"
	"net"
	"net/http"
	"os"
	"strings" // Added string manipulation package

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	_ "github.com/lib/pq" // Postgres driver
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/reflection"

	pb "github.com/youruser/whitelist-server/proto"
	"github.com/youruser/whitelist-server/internal/service"
)

func main() {
	// 1. Config
	dbURL := os.Getenv("DB_URL")
	if dbURL == "" {
		log.Fatal("DB_URL environment variable is required")
	}

	// Render provides the PORT variable. Default to 8080 if running locally.
	httpPort := os.Getenv("PORT")
	if httpPort == "" {
		httpPort = "8080"
	}
	
	// Internal gRPC port (not exposed to public internet directly on Render)
	grpcPort := "50051"

	// 2. Database Connection
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatalf("Failed to open db connection: %v", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		log.Fatalf("Failed to ping db: %v", err)
	}
	log.Println("Connected to Supabase")

	// 3. Start gRPC Server (Internal)
	lis, err := net.Listen("tcp", ":"+grpcPort)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	s := grpc.NewServer()
	whitelistService := service.NewWhitelistService(db)
	pb.RegisterWhitelistServiceServer(s, whitelistService)
	reflection.Register(s)

	go func() {
		log.Printf("gRPC server listening internally at %v", lis.Addr())
		if err := s.Serve(lis); err != nil {
			log.Fatalf("failed to serve: %v", err)
		}
	}()

	// 4. Start HTTP Gateway (Public)
	// The gateway connects to the internal gRPC server
	conn, err := grpc.Dial("localhost:"+grpcPort, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("did not connect to gRPC: %v", err)
	}
	defer conn.Close()

	mux := runtime.NewServeMux(
		runtime.WithIncomingHeaderMatcher(customMatcher),
	)

	err = pb.RegisterWhitelistServiceHandler(context.Background(), mux, conn)
	if err != nil {
		log.Fatalf("Failed to register gateway: %v", err)
	}

	gwServer := &http.Server{
		Addr:    ":" + httpPort,
		Handler: corsMiddleware(mux),
	}

	log.Printf("HTTP Gateway listening publicly on port %s", httpPort)
	log.Fatal(gwServer.ListenAndServe())
}

// customMatcher allows specific headers to pass through to the gRPC context
func customMatcher(key string) (string, bool) {
	// FIX: Go converts headers to Canonical format (e.g. X-Access-Token)
	// We must lowercase the key to match our switch cases correctly.
	switch strings.ToLower(key) {
	case "x-access-token":
		return strings.ToLower(key), true
	case "x-admin-secret":
		return strings.ToLower(key), true
	default:
		return runtime.DefaultHeaderMatcher(key)
	}
}

// corsMiddleware adds CORS headers for web compatibility
func corsMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, x-access-token, x-admin-secret")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		h.ServeHTTP(w, r)
	})
}
