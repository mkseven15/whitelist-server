package service

import (
	"context"
	"database/sql"
	"os"

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

func NewWhitelistService(db *sql.DB) *WhitelistService {
	return &WhitelistService{db: db}
}

// Helper to check admin secret
func (s *WhitelistService) checkAdmin(ctx context.Context) error {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "metadata missing")
	}
	
	// Check for x-admin-secret header
	values := md.Get("x-admin-secret")
	if len(values) == 0 || values[0] != os.Getenv("ADMIN_SECRET") {
		return status.Error(codes.PermissionDenied, "invalid admin secret")
	}
	return nil
}

// 1. GetAuthToken: Creates a short-lived token in Supabase
func (s *WhitelistService) GetAuthToken(ctx context.Context, _ *emptypb.Empty) (*pb.AuthTokenResponse, error) {
	var token string
	// Insert and return the generated UUID
	err := s.db.QueryRow("INSERT INTO access_tokens DEFAULT VALUES RETURNING token").Scan(&token)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate token: %v", err)
	}

	return &pb.AuthTokenResponse{
		Token:            token,
		ExpiresInSeconds: 30,
	}, nil
}

// 2. ValidateLicense: Checks token validity AND license validity
func (s *WhitelistService) ValidateLicense(ctx context.Context, req *pb.ValidateRequest) (*pb.ValidateResponse, error) {
	// A. Validate Access Token (One-Time Use)
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no metadata")
	}
	
	tokens := md.Get("x-access-token")
	if len(tokens) == 0 {
		return nil, status.Error(codes.Unauthenticated, "missing x-access-token header")
	}
	accessToken := tokens[0]

	// Check if token exists and is valid (delete it immediately to ensure one-time use)
	res, err := s.db.Exec("DELETE FROM access_tokens WHERE token = $1 AND expires_at > NOW()", accessToken)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "db error: %v", err)
	}
	rowsAffected, _ := res.RowsAffected()
	if rowsAffected == 0 {
		return nil, status.Error(codes.Unauthenticated, "invalid or expired access token")
	}

	// B. Validate License Key
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
		return &pb.ValidateResponse{Valid: false, Message: "License is banned or inactive"}, nil
	}

	// Optional: HWID Locking
	if req.Hwid != "" {
		if !storedHwid.Valid || storedHwid.String == "" {
			// Lock to this HWID
			_, _ = s.db.Exec("UPDATE licenses SET hwid = $1 WHERE license_key = $2", req.Hwid, req.LicenseKey)
		} else if storedHwid.String != req.Hwid {
			return &pb.ValidateResponse{Valid: false, Message: "HWID mismatch"}, nil
		}
	}

	return &pb.ValidateResponse{Valid: true, Message: "Authenticated"}, nil
}

// 3. UpdateLicense (Admin)
func (s *WhitelistService) UpdateLicense(ctx context.Context, req *pb.UpdateLicenseRequest) (*emptypb.Empty, error) {
	if err := s.checkAdmin(ctx); err != nil {
		return nil, err
	}

	_, err := s.db.Exec(`
		INSERT INTO licenses (license_key, product_id, is_active)
		VALUES ($1, $2, $3)
		ON CONFLICT (license_key) 
		DO UPDATE SET product_id = $2, is_active = $3
	`, req.LicenseKey, req.ProductId, req.IsActive)

	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to upsert: %v", err)
	}

	return &emptypb.Empty{}, nil
}

// 4. DeleteLicense (Admin)
func (s *WhitelistService) DeleteLicense(ctx context.Context, req *pb.DeleteLicenseRequest) (*emptypb.Empty, error) {
	if err := s.checkAdmin(ctx); err != nil {
		return nil, err
	}

	_, err := s.db.Exec("DELETE FROM licenses WHERE license_key = $1", req.LicenseKey)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to delete: %v", err)
	}

	return &emptypb.Empty{}, nil
}
