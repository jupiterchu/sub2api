// Package service 提供 NextJS BFF 集成相关的自定义服务。
// 相关代码独立存放，以减少对主代码的侵入，便于合并上游更新。
package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/google/uuid"
)

// UsageWebhookRequest 表示发送给 NextJS 的用量数据。
type UsageWebhookRequest struct {
	// RequestID 是每次 webhook 调用的唯一标识（UUID v4），用于接收端做幂等去重。
	RequestID        string  `json:"requestId"`
	Event            string  `json:"event"`
	APIKey           string  `json:"apiKey,omitempty"`
	UserID           int64   `json:"userId,omitempty"`
	Model            string  `json:"model"`
	InputTokens      int     `json:"inputTokens"`
	OutputTokens     int     `json:"outputTokens"`
	CacheReadTokens  int     `json:"cacheReadTokens,omitempty"`
	CacheWriteTokens int     `json:"cacheWriteTokens,omitempty"`
	Cost             float64 `json:"cost"`
	TotalCost        float64 `json:"totalCost"`
	RateMultiplier   float64 `json:"rateMultiplier"`
	Timestamp        int64   `json:"timestamp"`
	// Sub2APIBalanceUSD 为 sub2api 侧估算的 USD 余额（可选）。
	Sub2APIBalanceUSD *float64 `json:"sub2api_balance_usd,omitempty"`
}

// UsageWebhookResponse 表示用量 webhook 的响应。
type UsageWebhookResponse struct {
	Success   bool   `json:"success"`
	Message   string `json:"message,omitempty"`
	Error     string `json:"error,omitempty"`
	Timestamp string `json:"timestamp"`
	// BalancePoints 为积分余额（1 USD = N 积分）
	BalancePoints *int64 `json:"balance_points,omitempty"`
	// BalanceUSD 为 USD 余额（可选）
	BalanceUSD *float64 `json:"balance_usd,omitempty"`
	// Balance 兼容字段（按 USD 处理）
	Balance *float64 `json:"balance,omitempty"`
}

// NextJSService 负责与 NextJS 后端通信。
type NextJSService struct {
	cfg        *config.Config
	httpClient *http.Client
}

// NewNextJSService 创建 NextJS 服务实例。
func NewNextJSService(cfg *config.Config) *NextJSService {
	timeout := time.Duration(cfg.NextJS.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	return &NextJSService{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
}

// IsEnabled 返回 NextJS 集成是否启用。
func (s *NextJSService) IsEnabled() bool {
	return s.cfg.NextJS.Enabled
}

// GetPointsToUSD 返回积分转换比例。
func (s *NextJSService) GetPointsToUSD() int {
	if s.cfg.NextJS.PointsToUSD > 0 {
		return s.cfg.NextJS.PointsToUSD
	}
	return 10000
}

// SendUsageWebhook 发送用量数据到 NextJS。
func (s *NextJSService) SendUsageWebhook(apiKey string, userID int64, model string, inputTokens, outputTokens, cacheReadTokens, cacheWriteTokens int, cost, totalCost, rateMultiplier float64, sub2apiBalanceUSD *float64) (*UsageWebhookResponse, error) {
	if !s.cfg.NextJS.Enabled {
		return nil, nil
	}

	timeout := time.Duration(s.cfg.NextJS.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req := UsageWebhookRequest{
		RequestID:         uuid.New().String(),
		Event:             "usage",
		APIKey:            apiKey,
		UserID:            userID,
		Model:             model,
		InputTokens:       inputTokens,
		OutputTokens:      outputTokens,
		CacheReadTokens:   cacheReadTokens,
		CacheWriteTokens:  cacheWriteTokens,
		Cost:              cost,
		TotalCost:         totalCost,
		RateMultiplier:    rateMultiplier,
		Timestamp:         time.Now().UnixMilli(),
		Sub2APIBalanceUSD: sub2apiBalanceUSD,
	}

	var resp UsageWebhookResponse
	if err := s.doRequestWithRetry(ctx, "POST", "/api/internal/webhooks/usage", req, &resp); err != nil {
		return nil, err
	}

	return &resp, nil
}

// doRequestWithRetry 执行带重试的 HTTP 请求。
func (s *NextJSService) doRequestWithRetry(ctx context.Context, method, path string, body any, result any) error {
	var lastErr error

	retryCount := s.cfg.NextJS.RetryCount
	if retryCount < 0 {
		retryCount = 2
	}

	retryDelay := time.Duration(s.cfg.NextJS.RetryDelaySeconds) * time.Second
	if retryDelay <= 0 {
		retryDelay = 1 * time.Second
	}

	for attempt := 0; attempt <= retryCount; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(retryDelay):
			}
		}

		err := s.doRequest(ctx, method, path, body, result)
		if err == nil {
			return nil
		}

		lastErr = err
		log.Printf("[NextJS] Request failed (attempt %d/%d): %v", attempt+1, retryCount+1, err)
	}

	return lastErr
}

// doRequest 执行一次 HTTP 请求。
func (s *NextJSService) doRequest(ctx context.Context, method, path string, body any, result any) error {
	url := s.cfg.NextJS.BaseURL + path

	var reqBody io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal request body: %w", err)
		}
		reqBody = bytes.NewReader(jsonBody)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Internal-Secret", s.cfg.NextJS.InternalSecret)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("do request: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code %d: %s", resp.StatusCode, string(respBody))
	}

	if result != nil {
		if err := json.Unmarshal(respBody, result); err != nil {
			return fmt.Errorf("unmarshal response: %w", err)
		}
	}

	return nil
}
