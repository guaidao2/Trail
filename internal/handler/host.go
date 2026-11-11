package handler

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"trail/internal/audit"
	"trail/internal/database"
	"trail/internal/hostclient"
	"trail/internal/security"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// HostInspectionScheduler 把「某台主机的定期巡检」建成 cron 批量任务队列。
// 由 AgentHandler 实现：巡检需要批量任务的内存调度器，否则新建队列不会被 cron 扫描到。
type HostInspectionScheduler interface {
	ScheduleHostInspection(host *database.Host, cronExpr, ownerUserID string, executeNow bool) (string, error)
}

// HostHandler 暴露纳管主机的 REST 接口。凭据只以密文入库，读接口永远不回显明文。
type HostHandler struct {
	db        *database.DB
	logger    *zap.Logger
	box       *security.SecretBox
	audit     *audit.Service
	scheduler HostInspectionScheduler
}

// errSecretBoxUnavailable 表示进程内没有可用的凭据加密实例（通常是密钥加载失败）。
var errSecretBoxUnavailable = errors.New("凭据加密未初始化")

func NewHostHandler(db *database.DB, logger *zap.Logger, box *security.SecretBox) *HostHandler {
	return &HostHandler{db: db, logger: logger, box: box}
}

func (h *HostHandler) SetAudit(svc *audit.Service) { h.audit = svc }

// SetInspectionScheduler 注入巡检调度器（批量任务 cron）。
func (h *HostHandler) SetInspectionScheduler(s HostInspectionScheduler) { h.scheduler = s }

func hostAccess(c *gin.Context, permission string) database.RBACListAccess {
	if session, ok := security.CurrentSession(c); ok {
		return database.RBACListAccess{UserID: session.UserID, Scope: session.ScopeFor(permission)}
	}
	return database.RBACListAccess{}
}

type hostUpsertRequest struct {
	Name        string `json:"name"`
	Address     string `json:"address"`
	Protocol    string `json:"protocol"`
	Port        int    `json:"port"`
	Username    string `json:"username"`
	AuthType    string `json:"auth_type"`
	Password    string `json:"password"`
	PrivateKey  string `json:"private_key"`
	Passphrase  string `json:"passphrase"`
	Group       string `json:"group_name"`
	Environment string `json:"environment"`
	Tags        string `json:"tags"`
	Remark      string `json:"remark"`
}

type hostExecRequest struct {
	Command        string `json:"command" binding:"required"`
	TimeoutSeconds int    `json:"timeout_seconds"`
}

type hostUploadRequest struct {
	Path          string `json:"path" binding:"required"`
	ContentBase64 string `json:"content_base64" binding:"required"`
	Mode          string `json:"mode"`
}

// List 列出当前用户可见的主机。
func (h *HostHandler) List(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("page_size", "50"))
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	if page < 1 {
		page = 1
	}
	filter := database.HostFilter{
		Keyword:     c.Query("keyword"),
		Group:       c.Query("group"),
		Environment: c.Query("environment"),
		Status:      c.Query("status"),
		Protocol:    c.Query("protocol"),
	}
	list, total, err := h.db.ListHosts(limit, (page-1)*max(limit, 1), filter, hostAccess(c, "host:read"))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "读取主机列表失败"})
		return
	}
	items := make([]*database.Host, 0, len(list))
	for _, item := range list {
		items = append(items, publicHost(item))
	}
	c.JSON(http.StatusOK, gin.H{"hosts": items, "total": total, "page": page, "page_size": limit})
}

// Get 读取单台主机。
func (h *HostHandler) Get(c *gin.Context) {
	host, ok := h.loadAccessibleHost(c, "host:read")
	if !ok {
		return
	}
	c.JSON(http.StatusOK, publicHost(host))
}

// Create 纳管一台主机，凭据在此处加密。
func (h *HostHandler) Create(c *gin.Context) {
	var req hostUpsertRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求参数不合法"})
		return
	}
	secretCipher, passphraseCipher, err := h.encryptCredentials(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	session, hasSession := security.CurrentSession(c)
	owner := ""
	if hasSession {
		owner = session.UserID
	}
	host, err := h.db.CreateHost(&database.Host{
		Name:             req.Name,
		Address:          req.Address,
		Protocol:         req.Protocol,
		Port:             req.Port,
		Username:         req.Username,
		AuthType:         req.AuthType,
		GroupName:        req.Group,
		Env:              req.Environment,
		Tags:             req.Tags,
		Remark:           req.Remark,
		SecretCipher:     secretCipher,
		PassphraseCipher: passphraseCipher,
		OwnerID:          owner,
	})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if hasSession {
		_ = h.db.SetResourceOwner("host", host.ID, session.UserID)
	}
	if h.audit != nil {
		h.audit.RecordOK(c, "host", "create", "纳管主机", "host", host.ID, map[string]interface{}{
			"address": host.Address, "protocol": host.Protocol, "port": host.Port,
		})
	}
	c.JSON(http.StatusOK, publicHost(host))
}

// Update 更新主机信息；未提供凭据时保留原密文。
func (h *HostHandler) Update(c *gin.Context) {
	host, ok := h.loadAccessibleHost(c, "host:write")
	if !ok {
		return
	}
	var req hostUpsertRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求参数不合法"})
		return
	}
	secretCipher, passphraseCipher, err := h.encryptCredentials(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	updated, err := h.db.UpdateHost(&database.Host{
		ID:               host.ID,
		Name:             req.Name,
		Address:          req.Address,
		Protocol:         req.Protocol,
		Port:             req.Port,
		Username:         req.Username,
		AuthType:         req.AuthType,
		GroupName:        req.Group,
		Env:              req.Environment,
		Tags:             req.Tags,
		Remark:           req.Remark,
		SecretCipher:     secretCipher,
		PassphraseCipher: passphraseCipher,
	})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if h.audit != nil {
		h.audit.RecordOK(c, "host", "update", "更新主机", "host", updated.ID, map[string]interface{}{
			"address": updated.Address, "protocol": updated.Protocol, "port": updated.Port,
		})
	}
	c.JSON(http.StatusOK, publicHost(updated))
}

// Delete 删除主机。
func (h *HostHandler) Delete(c *gin.Context) {
	host, ok := h.loadAccessibleHost(c, "host:write")
	if !ok {
		return
	}
	if err := h.db.DeleteHost(host.ID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "删除主机失败"})
		return
	}
	if h.audit != nil {
		h.audit.RecordOK(c, "host", "delete", "删除主机", "host", host.ID, map[string]interface{}{
			"address": host.Address,
		})
	}
	c.JSON(http.StatusOK, gin.H{"deleted": true})
}

// Probe 测试连通性并回写状态与系统信息。
func (h *HostHandler) Probe(c *gin.Context) {
	host, ok := h.loadAccessibleHost(c, "host:read")
	if !ok {
		return
	}
	opts, err := h.clientOptions(host)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	result, probeErr := hostclient.Probe(ctx, opts)
	status := "online"
	errMsg := ""
	if probeErr != nil || !result.Online {
		status = "offline"
		if probeErr != nil {
			errMsg = probeErr.Error()
		} else {
			errMsg = result.Error
		}
	}
	_ = h.db.UpdateHostProbe(host.ID, status, errMsg, result.OSInfo)
	if status == "online" && strings.TrimSpace(host.HostKey) == "" && strings.TrimSpace(result.HostKey) != "" {
		// 首次信任（TOFU）：记录指纹，后续连接按它校验，防止凭据发给被替换的主机。
		_ = h.db.SetHostKey(host.ID, result.HostKey)
	}
	if h.audit != nil {
		h.audit.RecordOK(c, "host", "probe", "主机连通性探测", "host", host.ID, map[string]interface{}{
			"status": status, "error": errMsg,
		})
	}
	c.JSON(http.StatusOK, gin.H{
		"online":      result.Online,
		"status":      status,
		"error":       errMsg,
		"os_info":     result.OSInfo,
		"remote_user": result.RemoteUser,
		"remote_host": result.RemoteHostname,
		"host_key":    result.HostKey,
		"duration_ms": result.Duration.Milliseconds(),
	})
}

// ClearHostKey 清空已信任的主机密钥指纹，供主机重装换钥后重新信任。
func (h *HostHandler) ClearHostKey(c *gin.Context) {
	host, ok := h.loadAccessibleHost(c, "host:write")
	if !ok {
		return
	}
	if err := h.db.ClearHostKey(host.ID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if h.audit != nil {
		h.audit.RecordOK(c, "host", "clear-host-key", "清空主机密钥指纹", "host", host.ID, nil)
	}
	updated, err := h.db.GetHost(host.ID)
	if err != nil || updated == nil {
		c.JSON(http.StatusOK, gin.H{"cleared": true})
		return
	}
	c.JSON(http.StatusOK, publicHost(updated))
}

// Exec 在主机上执行一条命令。用户主动触发，需 host:exec 权限并全量审计。
func (h *HostHandler) Exec(c *gin.Context) {
	host, ok := h.loadAccessibleHost(c, "host:exec")
	if !ok {
		return
	}
	var req hostExecRequest
	if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.Command) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "command 不能为空"})
		return
	}
	timeout := time.Duration(req.TimeoutSeconds) * time.Second
	if timeout <= 0 || timeout > 10*time.Minute {
		timeout = 60 * time.Second
	}
	opts, err := h.clientOptions(host)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout+5*time.Second)
	defer cancel()
	res, execErr := hostclient.Exec(ctx, opts, req.Command, timeout)
	if h.audit != nil {
		detail := map[string]interface{}{
			"command": req.Command, "exit_code": -1,
		}
		if res != nil {
			detail["exit_code"] = res.ExitCode
		}
		if execErr != nil {
			detail["error"] = execErr.Error()
			h.audit.RecordFail(c, "host", "exec", "主机命令执行失败", detail)
		} else {
			h.audit.RecordOK(c, "host", "exec", "主机命令执行", "host", host.ID, detail)
		}
	}
	if res == nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": execErr.Error()})
		return
	}
	payload := gin.H{
		"stdout":      res.Stdout,
		"stderr":      res.Stderr,
		"exit_code":   res.ExitCode,
		"duration_ms": res.Duration.Milliseconds(),
	}
	if execErr != nil {
		payload["error"] = execErr.Error()
		c.JSON(http.StatusBadGateway, payload)
		return
	}
	c.JSON(http.StatusOK, payload)
}

type hostInspectionScheduleRequest struct {
	Cron       string `json:"cron"`
	ExecuteNow bool   `json:"execute_now"`
}

// ScheduleInspection 为某台主机建立定期巡检计划（cron 批量任务），可选立即跑一次。
func (h *HostHandler) ScheduleInspection(c *gin.Context) {
	host, ok := h.loadAccessibleHost(c, "host:write")
	if !ok {
		return
	}
	if h.scheduler == nil {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "巡检调度未启用"})
		return
	}
	var req hostInspectionScheduleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求参数不合法"})
		return
	}
	cron := strings.TrimSpace(req.Cron)
	if cron == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cron 表达式不能为空"})
		return
	}
	session, _ := security.CurrentSession(c)
	queueID, err := h.scheduler.ScheduleHostInspection(host, cron, session.UserID, req.ExecuteNow)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if h.audit != nil {
		h.audit.RecordOK(c, "host", "schedule_inspection", "建立主机巡检计划", "host", host.ID, map[string]interface{}{
			"cron": cron, "queue_id": queueID, "execute_now": req.ExecuteNow,
		})
	}
	c.JSON(http.StatusOK, gin.H{"queue_id": queueID, "cron": cron})
}

// Upload 上传文件（base64 入参，走 SSH exec 通道）。
func (h *HostHandler) Upload(c *gin.Context) {
	host, ok := h.loadAccessibleHost(c, "host:exec")
	if !ok {
		return
	}
	var req hostUploadRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求参数不合法"})
		return
	}
	content, err := base64.StdEncoding.DecodeString(req.ContentBase64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "content_base64 不是合法 base64"})
		return
	}
	opts, err := h.clientOptions(host)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if err := hostclient.UploadFile(ctx, opts, req.Path, content, req.Mode); err != nil {
		if h.audit != nil {
			h.audit.RecordFail(c, "host", "upload", "主机文件上传失败", map[string]interface{}{
				"path": req.Path, "error": err.Error(),
			})
		}
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	if h.audit != nil {
		h.audit.RecordOK(c, "host", "upload", "主机文件上传", "host", host.ID, map[string]interface{}{
			"path": req.Path, "bytes": len(content),
		})
	}
	c.JSON(http.StatusOK, gin.H{"uploaded": true, "bytes": len(content)})
}

// Download 下载文件（base64 返回）。
func (h *HostHandler) Download(c *gin.Context) {
	host, ok := h.loadAccessibleHost(c, "host:exec")
	if !ok {
		return
	}
	path := strings.TrimSpace(c.Query("path"))
	if path == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "path 不能为空"})
		return
	}
	opts, err := h.clientOptions(host)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	content, err := hostclient.DownloadFile(ctx, opts, path)
	if err != nil {
		if h.audit != nil {
			h.audit.RecordFail(c, "host", "download", "主机文件下载失败", map[string]interface{}{
				"path": path, "error": err.Error(),
			})
		}
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	if h.audit != nil {
		h.audit.RecordOK(c, "host", "download", "主机文件下载", "host", host.ID, map[string]interface{}{
			"path": path, "bytes": len(content),
		})
	}
	c.JSON(http.StatusOK, gin.H{
		"path":           path,
		"bytes":          len(content),
		"content_base64": base64.StdEncoding.EncodeToString(content),
	})
}

// loadAccessibleHost 读取路径参数指定的主机并校验访问权，失败时已写好响应。
func (h *HostHandler) loadAccessibleHost(c *gin.Context, permission string) (*database.Host, bool) {
	id := strings.TrimSpace(c.Param("id"))
	host, err := h.db.GetHost(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "读取主机失败"})
		return nil, false
	}
	if host == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "主机不存在"})
		return nil, false
	}
	if !hostAccessAllowed(h.db, hostAccess(c, permission), host.ID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "无权访问该主机"})
		return nil, false
	}
	return host, true
}

func hostAccessAllowed(db *database.DB, access database.RBACListAccess, hostID string) bool {
	if strings.TrimSpace(access.UserID) == "" || access.Scope == database.RBACScopeAll {
		return true
	}
	return db.UserCanAccessResource(access.UserID, access.Scope, "host", hostID)
}

// encryptCredentials 把请求里的明文凭据加密；未提供时返回空串（表示保持原值）。
func (h *HostHandler) encryptCredentials(req hostUpsertRequest) (string, string, error) {
	if h.box == nil {
		return "", "", errSecretBoxUnavailable
	}
	secret := strings.TrimSpace(req.Password)
	if secret == "" {
		secret = strings.TrimSpace(req.PrivateKey)
	}
	cipherText, err := h.box.Encrypt(secret)
	if err != nil {
		return "", "", err
	}
	passphraseCipher, err := h.box.Encrypt(strings.TrimSpace(req.Passphrase))
	if err != nil {
		return "", "", err
	}
	return cipherText, passphraseCipher, nil
}

// clientOptions 解密凭据并组装连接参数。明文只在内存中使用。
func (h *HostHandler) clientOptions(host *database.Host) (hostclient.Options, error) {
	if h.box == nil {
		return hostclient.Options{}, errSecretBoxUnavailable
	}
	secret, err := h.box.Decrypt(host.SecretCipher)
	if err != nil {
		return hostclient.Options{}, err
	}
	passphrase, err := h.box.Decrypt(host.PassphraseCipher)
	if err != nil {
		return hostclient.Options{}, err
	}
	opts := hostclient.Options{
		Protocol:   host.Protocol,
		Address:    host.Address,
		Port:       host.Port,
		Username:   host.Username,
		HostKeyPin: host.HostKey,
	}
	if strings.EqualFold(host.AuthType, "key") {
		opts.PrivateKey = secret
		opts.Passphrase = passphrase
	} else {
		opts.Password = secret
	}
	return opts, nil
}

// publicHost 返回给前端的视图：不带任何凭据字段。
func publicHost(host *database.Host) *database.Host {
	if host == nil {
		return nil
	}
	out := *host
	out.SecretCipher = ""
	out.PassphraseCipher = ""
	return &out
}
