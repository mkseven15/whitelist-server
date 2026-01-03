package service

import (
	"context"
	"database/sql"
	"log"
	"os"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/mkseven15/whitelist-server/proto"
)

type WhitelistService struct {
	pb.UnimplementedWhitelistServiceServer
	db *sql.DB
}

// NewWhitelistService initializes the service AND starts the background cleaner
func NewWhitelistService(db *sql.DB) *WhitelistService {
	s := &WhitelistService{db: db}
	
	// Start Automatic Token Cleanup in the background
	go s.cleanupExpiredTokens()
	
	return s
}

// cleanupExpiredTokens runs every minute to remove old tokens from DB
func (s *WhitelistService) cleanupExpiredTokens() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	
	for range ticker.C {
		// Delete tokens where 'expires_at' is in the past
		_, err := s.db.Exec("DELETE FROM access_tokens WHERE expires_at < NOW()")
		if err != nil {
			log.Printf("Error cleaning up tokens: %v", err)
		}
	}
}

func (s *WhitelistService) checkAdmin(ctx context.Context) error {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "metadata missing")
	}
	values := md.Get("x-admin-secret")
	if len(values) == 0 || values[0] != os.Getenv("ADMIN_SECRET") {
		return status.Error(codes.PermissionDenied, "invalid admin secret")
	}
	return nil
}

// 1. GetAuthToken: Now validates API Key before issuing token
func (s *WhitelistService) GetAuthToken(ctx context.Context, req *pb.GetTokenRequest) (*pb.AuthTokenResponse, error) {
	// Validate Input
	if req.ApiKey == "" {
		return nil, status.Error(codes.InvalidArgument, "API Key required")
	}

	// Check DB: Key must exist AND (ExpiresAt is NULL OR ExpiresAt > Now)
	var exists bool
	query := `SELECT EXISTS(
		SELECT 1 FROM api_keys 
		WHERE key = $1 
		AND (expires_at IS NULL OR expires_at > NOW())
	)`
	
	err := s.db.QueryRow(query, req.ApiKey).Scan(&exists)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "DB Check Failed: %v", err)
	}
	if !exists {
		return nil, status.Error(codes.Unauthenticated, "Invalid or Expired API Key")
	}

	// Generate Token
	var token string
	err = s.db.QueryRow("INSERT INTO access_tokens DEFAULT VALUES RETURNING token").Scan(&token)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate token: %v", err)
	}

	return &pb.AuthTokenResponse{
		Token:            token,
		ExpiresInSeconds: 30,
	}, nil
}

// 2. ValidateLicense
func (s *WhitelistService) ValidateLicense(ctx context.Context, req *pb.ValidateRequest) (*pb.ValidateResponse, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no metadata")
	}
	tokens := md.Get("x-access-token")
	if len(tokens) == 0 {
		return nil, status.Error(codes.Unauthenticated, "missing x-access-token header")
	}

	// Validate & Burn Token
	res, err := s.db.Exec("DELETE FROM access_tokens WHERE token = $1 AND expires_at > NOW()", tokens[0])
	if err != nil {
		return nil, status.Errorf(codes.Internal, "db error: %v", err)
	}
	rowsAffected, _ := res.RowsAffected()
	if rowsAffected == 0 {
		return nil, status.Error(codes.Unauthenticated, "invalid or expired access token")
	}

	// Validate License
	var isActive bool
	var storedHwid sql.NullString
	query := "SELECT is_active, hwid FROM licenses WHERE license_key = $1 AND product_id = $2"
	err = s.db.QueryRow(query, req.LicenseKey, req.ProductId).Scan(&isActive, &storedHwid)

	if err == sql.ErrNoRows {
		return &pb.ValidateResponse{Valid: false, Message: "License not found"}, nil
	} else if err != nil {
		return nil, status.Errorf(codes.Internal, "db error: %v", err)
	}

	if !isActive {
		return &pb.ValidateResponse{Valid: false, Message: "License is suspended"}, nil
	}

	if req.Hwid != "" {
		if !storedHwid.Valid || storedHwid.String == "" {
			_, _ = s.db.Exec("UPDATE licenses SET hwid = $1 WHERE license_key = $2", req.Hwid, req.LicenseKey)
		} else if storedHwid.String != req.Hwid {
			return &pb.ValidateResponse{Valid: false, Message: "HWID mismatch"}, nil
		}
	}

	return &pb.ValidateResponse{Valid: true, Message: "Authenticated"}, nil
}

// 3. UpdateLicense (Admin)
func (s *WhitelistService) UpdateLicense(ctx context.Context, req *pb.UpdateLicenseRequest) (*emptypb.Empty, error) {
	if err := s.checkAdmin(ctx); err != nil { return nil, err }

	_, err := s.db.Exec(`
		INSERT INTO licenses (license_key, product_id, is_active)
		VALUES ($1, $2, $3)
		ON CONFLICT (license_key) 
		DO UPDATE SET product_id = $2, is_active = $3
	`, req.LicenseKey, req.ProductId, req.IsActive)

	if err != nil { return nil, status.Errorf(codes.Internal, "upsert failed: %v", err) }
	return &emptypb.Empty{}, nil
}

// 4. DeleteLicense (Admin)
func (s *WhitelistService) DeleteLicense(ctx context.Context, req *pb.DeleteLicenseRequest) (*emptypb.Empty, error) {
	if err := s.checkAdmin(ctx); err != nil { return nil, err }
	_, err := s.db.Exec("DELETE FROM licenses WHERE license_key = $1", req.LicenseKey)
	if err != nil { return nil, status.Errorf(codes.Internal, "delete failed: %v", err) }
	return &emptypb.Empty{}, nil
}
