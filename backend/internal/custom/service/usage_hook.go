// Package service 提供用量记录相关的钩子。
// 这里实现了计费后向 NextJS 发送用量数据的 webhook。
package service

import (
	"log"

	"github.com/Wei-Shaw/sub2api/internal/service"
)

// NextJSUsageHook 使用 NextJS webhook 实现 service.UsageRecordedHook。
type NextJSUsageHook struct {
	nextjsService *NextJSService
}

// NewNextJSUsageHook 创建 NextJS 用量钩子。
func NewNextJSUsageHook(nextjsService *NextJSService) *NextJSUsageHook {
	return &NextJSUsageHook{
		nextjsService: nextjsService,
	}
}

// OnUsageRecorded 向 NextJS 发送用量数据。
func (h *NextJSUsageHook) OnUsageRecorded(apiKey *service.APIKey, model string, inputTokens, outputTokens, cacheReadTokens, cacheWriteTokens int, cost float64) {
	if h == nil || h.nextjsService == nil || !h.nextjsService.IsEnabled() {
		return
	}
	if apiKey == nil {
		return
	}

	userID := apiKey.UserID
	var sub2apiBalanceUSD *float64
	if apiKey.User != nil {
		userID = apiKey.User.ID
		balance := apiKey.User.Balance
		sub2apiBalanceUSD = &balance
	}

	rateMultiplier := 1.0
	if h.nextjsService != nil && h.nextjsService.cfg != nil && h.nextjsService.cfg.Default.RateMultiplier > 0 {
		rateMultiplier = h.nextjsService.cfg.Default.RateMultiplier
	}
	if apiKey != nil && apiKey.Group != nil && apiKey.Group.RateMultiplier > 0 {
		rateMultiplier = apiKey.Group.RateMultiplier
	}
	if rateMultiplier <= 0 {
		rateMultiplier = 1.0
	}
	totalCost := cost / rateMultiplier

	_, err := h.nextjsService.SendUsageWebhook("", userID, model, inputTokens, outputTokens, cacheReadTokens, cacheWriteTokens, cost, totalCost, rateMultiplier, sub2apiBalanceUSD)
	if err != nil {
		log.Printf("[NextJS] Failed to send usage webhook: %v", err)
	}
}
