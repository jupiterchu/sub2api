package custom

import (
	"github.com/Wei-Shaw/sub2api/internal/config"
	customservice "github.com/Wei-Shaw/sub2api/internal/custom/service"
	"github.com/Wei-Shaw/sub2api/internal/service"

	"github.com/google/wire"
)

// ProvideInternalHandler wires InternalHandler with billing cache support.
func ProvideInternalHandler(
	userService *service.UserService,
	billingCacheService *service.BillingCacheService,
	cfg *config.Config,
) *InternalHandler {
	return NewInternalHandler(userService, billingCacheService, cfg)
}

// ProviderSet 用于装配自定义集成（如 NextJS BFF 钩子）。
var ProviderSet = wire.NewSet(
	customservice.NewNextJSService,
	customservice.NewNextJSUsageHook,
	ProvideInternalHandler,
	wire.Bind(new(service.UsageRecordedHook), new(*customservice.NextJSUsageHook)),
)
