package custom

import (
	"math"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/service"

	"github.com/gin-gonic/gin"
)

// InternalHandler 提供内部同步接口（供 NextJS 调用）
type InternalHandler struct {
	userService         *service.UserService
	billingCacheService *service.BillingCacheService
	cfg                 *config.Config
}

// NewInternalHandler 创建内部接口处理器
func NewInternalHandler(
	userService *service.UserService,
	billingCacheService *service.BillingCacheService,
	cfg *config.Config,
) *InternalHandler {
	return &InternalHandler{
		userService:         userService,
		billingCacheService: billingCacheService,
		cfg:                 cfg,
	}
}

// SyncBalanceRequest 为余额同步请求体
type SyncBalanceRequest struct {
	UserID        int64    `json:"user_id" binding:"required"`
	BalancePoints *int64   `json:"balance_points,omitempty"`
	BalanceUSD    *float64 `json:"balance_usd,omitempty"`
	Balance       *float64 `json:"balance,omitempty"`
}

// RegisterInternalRoutes 注册内部接口（供 NextJS 调用）
func RegisterInternalRoutes(r *gin.Engine, handler *InternalHandler, cfg *config.Config) {
	if r == nil || handler == nil {
		return
	}
	if cfg == nil || !cfg.NextJS.Enabled {
		return
	}

	internal := r.Group("/api/internal")
	internal.Use(internalSecretMiddleware(cfg))
	{
		internal.POST("/balance/sync", handler.SyncBalance)
	}
}

// SyncBalance 同步用户余额（内部接口）
func (h *InternalHandler) SyncBalance(c *gin.Context) {
	var req SyncBalanceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "Invalid request: "+err.Error())
		return
	}

	balanceUSD, ok := h.resolveBalanceUSD(&req)
	if !ok {
		response.BadRequest(c, "Balance is required")
		return
	}
	if !isFiniteFloat64(balanceUSD) {
		response.BadRequest(c, "Balance must be a finite number")
		return
	}

	balanceUSD = roundBalanceUSD(balanceUSD)

	if err := h.userService.SetBalance(c.Request.Context(), req.UserID, balanceUSD); err != nil {
		response.ErrorFrom(c, err)
		return
	}
	if h.billingCacheService != nil {
		_ = h.billingCacheService.InvalidateUserBalance(c.Request.Context(), req.UserID)
	}

	response.Success(c, gin.H{
		"user_id": req.UserID,
		"balance": balanceUSD,
	})
}

func (h *InternalHandler) resolveBalanceUSD(req *SyncBalanceRequest) (float64, bool) {
	if req.BalancePoints != nil {
		pointsToUSD := 10000
		if h.cfg != nil && h.cfg.NextJS.PointsToUSD > 0 {
			pointsToUSD = h.cfg.NextJS.PointsToUSD
		}
		return float64(*req.BalancePoints) / float64(pointsToUSD), true
	}
	if req.BalanceUSD != nil {
		return *req.BalanceUSD, true
	}
	if req.Balance != nil {
		return *req.Balance, true
	}
	return 0, false
}

func isFiniteFloat64(v float64) bool {
	return !math.IsNaN(v) && !math.IsInf(v, 0)
}

func roundBalanceUSD(v float64) float64 {
	const precision = 10000.0
	return math.Round(v*precision) / precision
}

func internalSecretMiddleware(cfg *config.Config) gin.HandlerFunc {
	expected := ""
	if cfg != nil {
		expected = cfg.NextJS.InternalSecret
	}
	return func(c *gin.Context) {
		secret := c.GetHeader("X-Internal-Secret")
		if expected == "" || secret == "" || secret != expected {
			response.Unauthorized(c, "Invalid internal secret")
			c.Abort()
			return
		}
		c.Next()
	}
}
