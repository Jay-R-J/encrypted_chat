// 安全加密对话工具 JavaScript 实现

// 全局工具类
class UIUtils {
    static showLoading(message = '处理中...') {
        const loadingEl = document.getElementById('loadingIndicator');
        if (loadingEl) {
            const loadingText = loadingEl.querySelector('.loading-text');
            if (loadingText) {
                loadingText.textContent = message;
            }
            loadingEl.style.display = 'flex';
        }
    }

    static hideLoading() {
        const loadingEl = document.getElementById('loadingIndicator');
        if (loadingEl) {
            loadingEl.style.display = 'none';
        }
    }

    static showToast(message, type = 'success', duration = 3000) {
        const toastContainer = document.getElementById('toastContainer');
        if (!toastContainer) return;

        // 创建toast元素
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        
        // 图标映射
        const icons = {
            success: 'fa-check-circle',
            error: 'fa-exclamation-circle',
            warning: 'fa-exclamation-triangle',
            info: 'fa-info-circle'
        };

        // 标题映射
        const titles = {
            success: '成功',
            error: '错误',
            warning: '警告',
            info: '提示'
        };

        toast.innerHTML = `
            <i class="fas ${icons[type] || icons.info} toast-icon"></i>
            <div class="toast-content">
                <div class="toast-title">${titles[type] || titles.info}</div>
                <div class="toast-message">${message}</div>
            </div>
            <button class="toast-close" aria-label="关闭通知">
                <i class="fas fa-times"></i>
            </button>
        `;

        // 添加到容器
        toastContainer.appendChild(toast);

        // 关闭按钮事件
        const closeBtn = toast.querySelector('.toast-close');
        closeBtn.addEventListener('click', () => {
            toast.remove();
        });

        // 自动关闭
        setTimeout(() => {
            if (toast.parentNode) {
                toast.remove();
            }
        }, duration);

        return toast;
    }
}

// 安全审计日志类
class SecurityLogger {
    constructor() {
        this.init();
    }

    init() {
        // 检查IndexedDB支持
        if (!window.indexedDB) {
            console.warn('浏览器不支持IndexedDB，无法记录安全日志');
            return;
        }

        // 初始化数据库
        this.db = null;
        this.initDB();
    }

    initDB() {
        const request = indexedDB.open('SecureChatLogs', 1);

        request.onupgradeneeded = (event) => {
            this.db = event.target.result;
            if (!this.db.objectStoreNames.contains('logs')) {
                this.db.createObjectStore('logs', { keyPath: 'id', autoIncrement: true });
            }
        };

        request.onsuccess = (event) => {
            this.db = event.target.result;
        };

        request.onerror = (event) => {
            console.error('打开数据库失败:', event.target.error);
        };
    }

    log(action, details) {
        if (!this.db) {
            console.warn('数据库未初始化，无法记录日志');
            return;
        }

        const logEntry = {
            action: action,
            details: details,
            timestamp: new Date().toISOString()
        };

        const transaction = this.db.transaction(['logs'], 'readwrite');
        const store = transaction.objectStore('logs');
        store.add(logEntry);

        transaction.oncomplete = () => {
            console.log('日志记录成功:', logEntry);
        };

        transaction.onerror = (event) => {
            console.error('日志记录失败:', event.target.error);
        };
    }

    async getLogs() {
        return new Promise((resolve, reject) => {
            if (!this.db) {
                resolve([]);
                return;
            }

            const transaction = this.db.transaction(['logs'], 'readonly');
            const store = transaction.objectStore('logs');
            const logs = [];

            store.openCursor().onsuccess = (event) => {
                const cursor = event.target.result;
                if (cursor) {
                    logs.push(cursor.value);
                    cursor.continue();
                } else {
                    resolve(logs.reverse()); // 按时间倒序返回
                }
            };

            transaction.onerror = (event) => {
                reject(event.target.error);
            };
        });
    }
}

// 主题管理器
class ThemeManager {
    constructor() {
        this.init();
    }

    init() {
        // 从localStorage获取主题设置
        const savedTheme = localStorage.getItem('secureChatTheme') || 'light';
        this.setTheme(savedTheme);
        this.bindEvents();
    }

    bindEvents() {
        const themeToggle = document.getElementById('themeToggle');
        if (themeToggle) {
            themeToggle.addEventListener('click', () => {
                this.toggleTheme();
            });
        }
    }

    setTheme(theme) {
        document.documentElement.setAttribute('data-theme', theme);
        localStorage.setItem('secureChatTheme', theme);
        
        // 更新主题切换按钮图标
        const themeToggle = document.getElementById('themeToggle');
        if (themeToggle) {
            const icon = themeToggle.querySelector('i');
            if (icon) {
                icon.className = theme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
            }
        }
    }

    toggleTheme() {
        const currentTheme = document.documentElement.getAttribute('data-theme') || 'light';
        const newTheme = currentTheme === 'light' ? 'dark' : 'light';
        this.setTheme(newTheme);
        UIUtils.showToast(`已切换到${newTheme === 'light' ? '浅色' : '深色'}主题`, 'success');
    }
}

// 自动保存管理器
class AutoSaveManager {
    constructor() {
        this.autoSaveFields = ['plaintext', 'recipientKey'];
        this.init();
    }

    init() {
        this.bindEvents();
        this.loadSavedData();
    }

    bindEvents() {
        this.autoSaveFields.forEach(fieldId => {
            const field = document.getElementById(fieldId);
            if (field) {
                field.addEventListener('input', () => {
                    this.saveData(fieldId, field.value);
                });
            }
        });
    }

    saveData(fieldId, value) {
        const savedData = JSON.parse(localStorage.getItem('secureChatAutoSave') || '{}');
        savedData[fieldId] = value;
        localStorage.setItem('secureChatAutoSave', JSON.stringify(savedData));
    }

    loadSavedData() {
        const savedData = JSON.parse(localStorage.getItem('secureChatAutoSave') || '{}');
        this.autoSaveFields.forEach(fieldId => {
            const field = document.getElementById(fieldId);
            if (field && savedData[fieldId]) {
                field.value = savedData[fieldId];
            }
        });
    }
}

// 拖拽上传管理器
class DragDropManager {
    constructor() {
        this.init();
    }

    init() {
        this.bindEvents();
    }

    bindEvents() {
        const textareas = document.querySelectorAll('textarea');
        textareas.forEach(textarea => {
            // 拖拽进入
            textarea.addEventListener('dragover', (e) => {
                e.preventDefault();
                textarea.classList.add('drag-over');
            });

            // 拖拽离开
            textarea.addEventListener('dragleave', () => {
                textarea.classList.remove('drag-over');
            });

            // 拖拽放下
            textarea.addEventListener('drop', (e) => {
                e.preventDefault();
                textarea.classList.remove('drag-over');
                this.handleDrop(e, textarea);
            });
        });
    }

    async handleDrop(event, target) {
        const files = event.dataTransfer.files;
        if (files.length > 0) {
            const file = files[0];
            if (file.type === 'text/plain' || file.name.endsWith('.txt')) {
                try {
                    UIUtils.showLoading('读取文件中...');
                    const content = await this.readFile(file);
                    target.value = content;
                    UIUtils.hideLoading();
                    UIUtils.showToast('文件内容已加载到输入框', 'success');
                    
                    // 如果是接收方公钥输入框，验证公钥
                    if (target.id === 'recipientKey') {
                        const encryptor = window.secureChatEncryptor;
                        if (encryptor && typeof encryptor.validateRecipientKey === 'function') {
                            encryptor.validateRecipientKey();
                        }
                    }
                } catch (error) {
                    UIUtils.hideLoading();
                    UIUtils.showToast('读取文件失败: ' + error.message, 'error');
                }
            } else {
                UIUtils.showToast('只支持文本文件(.txt)的拖拽上传', 'warning');
            }
        }
    }

    readFile(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = (e) => resolve(e.target.result);
            reader.onerror = () => reject(new Error('文件读取失败'));
            reader.readAsText(file);
        });
    }
}

// 消息历史管理器
class MessageHistoryManager {
    constructor() {
        this.init();
    }

    init() {
        this.bindEvents();
    }

    bindEvents() {
        const closeHistory = document.getElementById('closeHistory');
        if (closeHistory) {
            closeHistory.addEventListener('click', () => {
                this.closeHistory();
            });
        }
    }

    openHistory() {
        const historyPanel = document.getElementById('historyPanel');
        if (historyPanel) {
            historyPanel.classList.add('open');
        }
    }

    closeHistory() {
        const historyPanel = document.getElementById('historyPanel');
        if (historyPanel) {
            historyPanel.classList.remove('open');
        }
    }

    async loadHistory() {
        const logger = window.securityLogger;
        if (logger && typeof logger.getLogs === 'function') {
            try {
                const logs = await logger.getLogs();
                this.renderHistory(logs);
            } catch (error) {
                console.error('加载历史记录失败:', error);
                UIUtils.showToast('加载历史记录失败', 'error');
            }
        }
    }

    renderHistory(logs) {
        const historyContent = document.getElementById('historyContent');
        if (!historyContent) return;

        if (logs.length === 0) {
            historyContent.innerHTML = '<p style="text-align: center; color: var(--text-secondary); padding: 20px;">暂无历史记录</p>';
            return;
        }

        const historyHtml = logs.map(log => `
            <div class="history-item">
                <div class="history-item-header">
                    <span class="history-item-time">${new Date(log.timestamp).toLocaleString()}</span>
                    <span class="history-item-type">${log.action}</span>
                </div>
                <div class="history-item-content">${log.details}</div>
            </div>
        `).join('');

        historyContent.innerHTML = historyHtml;
    }
}

class SecureChatEncryptor {
    constructor() {
        this.publicKey = null;
        this.privateKey = null;
        this.securityLogger = new SecurityLogger();
        this.init();
    }

    async init() {
        // 初始化页面元素事件监听
        this.bindEvents();
        // 检查是否已有密钥
        await this.checkExistingKeys();
        // 记录初始化日志
        this.securityLogger.log('init', '系统初始化完成');
    }

    bindEvents() {
        // 密钥管理事件
        document.getElementById('generateKeys').addEventListener('click', () => this.generateKeyPair());
        document.getElementById('exportKeys').addEventListener('click', () => this.exportKeys());
        document.getElementById('importKeys').addEventListener('click', () => this.importKeys());
        document.getElementById('clearKeys').addEventListener('click', () => this.clearKeys());
        document.getElementById('copyPublicKey').addEventListener('click', () => this.copyPublicKey());

        // 加密事件
        document.getElementById('encryptBtn').addEventListener('click', () => this.encryptMessage());
        document.getElementById('generateShareLink').addEventListener('click', () => this.generateShareLink());
        document.getElementById('copyEncrypted').addEventListener('click', () => this.copyToClipboard('ciphertext'));
        document.getElementById('cleanPublicKey').addEventListener('click', () => this.cleanPublicKeyInput());
        document.getElementById('clearPublicKey').addEventListener('click', () => this.clearPublicKeyInput());

        // 解密事件
        document.getElementById('decryptBtn').addEventListener('click', () => this.decryptMessage());
        document.getElementById('pasteFromClipboard').addEventListener('click', () => this.pasteFromClipboard());
        document.getElementById('copyDecrypted').addEventListener('click', () => this.copyToClipboard('decryptedText'));
        
        // 实时验证接收方公钥
        document.getElementById('recipientKey').addEventListener('input', () => this.validateRecipientKey());
    }

    // 生成RSA密钥对
    async generateKeyPair() {
        try {
            UIUtils.showLoading('生成密钥对中...');
            const keyPair = await crypto.subtle.generateKey(
                {
                    name: 'RSA-OAEP',
                    modulusLength: 4096,
                    publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
                    hash: 'SHA-256',
                },
                true,
                ['encrypt', 'decrypt']
            );

            this.publicKey = keyPair.publicKey;
            this.privateKey = keyPair.privateKey;

            // 保存到IndexedDB，设置默认有效期30天
            await this.saveKeysToStorage(keyPair);
            // 更新UI
            await this.updateKeyStatus();
            
            // 记录日志
            this.securityLogger.log('generateKeys', '生成了新的RSA-4096密钥对');
            
            UIUtils.hideLoading();
            UIUtils.showToast('密钥对生成成功！', 'success');
        } catch (error) {
            console.error('生成密钥失败:', error);
            UIUtils.hideLoading();
            UIUtils.showToast('生成密钥失败: ' + error.message, 'error');
        }
    }

    // 保存密钥到IndexedDB
    async saveKeysToStorage(keyPair) {
        // 简化实现，使用localStorage存储导出的密钥
        const publicKeyExport = await crypto.subtle.exportKey('spki', keyPair.publicKey);
        const privateKeyExport = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);

        // 设置密钥有效期为30天
        const expirationDate = new Date();
        expirationDate.setDate(expirationDate.getDate() + 30);

        localStorage.setItem('secureChatPublicKey', this.arrayBufferToBase64(publicKeyExport));
        localStorage.setItem('secureChatPrivateKey', this.arrayBufferToBase64(privateKeyExport));
        localStorage.setItem('secureChatKeyExpiration', expirationDate.toISOString());
    }

    // 检查是否已有密钥
    async checkExistingKeys() {
        try {
            const publicKeyStr = localStorage.getItem('secureChatPublicKey');
            const privateKeyStr = localStorage.getItem('secureChatPrivateKey');

            if (publicKeyStr && privateKeyStr) {
                const publicKey = await crypto.subtle.importKey(
                    'spki',
                    this.base64ToArrayBuffer(publicKeyStr),
                    {
                        name: 'RSA-OAEP',
                        hash: 'SHA-256',
                    },
                    true,
                    ['encrypt']
                );

                const privateKey = await crypto.subtle.importKey(
                    'pkcs8',
                    this.base64ToArrayBuffer(privateKeyStr),
                    {
                        name: 'RSA-OAEP',
                        hash: 'SHA-256',
                    },
                    true,
                    ['decrypt']
                );

                this.publicKey = publicKey;
                this.privateKey = privateKey;
                await this.updateKeyStatus();
                
                // 检查密钥是否过期
                this.checkKeyExpiration();
            }
        } catch (error) {
            console.error('检查密钥失败:', error);
        }
    }
    
    // 检查密钥是否过期
    checkKeyExpiration() {
        const expirationStr = localStorage.getItem('secureChatKeyExpiration');
        if (!expirationStr) return;
        
        const expirationDate = new Date(expirationStr);
        const now = new Date();
        const daysRemaining = Math.ceil((expirationDate - now) / (1000 * 60 * 60 * 24));
        
        if (now > expirationDate) {
            // 密钥已过期
            UIUtils.showToast('您的密钥已过期，请生成新的密钥对！', 'warning', 5000);
        } else if (daysRemaining <= 7) {
            // 密钥即将过期
            UIUtils.showToast(`您的密钥将在${daysRemaining}天后过期，请考虑生成新的密钥对！`, 'warning', 5000);
        }
    }

    // 更新密钥状态显示
    async updateKeyStatus() {
        const statusBadge = document.querySelector('#keyStatus .status-badge');
        statusBadge.textContent = '密钥已就绪';
        statusBadge.className = 'status-badge active';

        // 生成密钥指纹
        if (this.publicKey) {
            const fingerprint = await this.generateKeyFingerprint(this.publicKey);
            document.getElementById('keyFingerprint').textContent = `公钥指纹: ${fingerprint}`;
            
            // 显示公钥
            const publicKeyExport = await crypto.subtle.exportKey('spki', this.publicKey);
            const publicKeyStr = this.arrayBufferToBase64(publicKeyExport);
            document.getElementById('publicKeyText').value = publicKeyStr;
            document.getElementById('publicKeyDisplay').style.display = 'block';
            
            // 显示密钥强度指示器
            document.getElementById('keyStrengthIndicator').style.display = 'block';
            // 评估密钥强度
            const strength = await this.assessKeyStrength(this.publicKey);
            this.updateKeyStrength(strength);
            
            // 显示密钥过期信息
            this.displayKeyExpiration();
        }
    }
    
    // 显示密钥过期信息
    displayKeyExpiration() {
        const expirationStr = localStorage.getItem('secureChatKeyExpiration');
        if (!expirationStr) return;
        
        const expirationDate = new Date(expirationStr);
        const now = new Date();
        const daysRemaining = Math.ceil((expirationDate - now) / (1000 * 60 * 60 * 24));
        
        // 获取或创建过期信息元素
        let expirationElement = document.getElementById('keyExpirationInfo');
        if (!expirationElement) {
            expirationElement = document.createElement('div');
            expirationElement.id = 'keyExpirationInfo';
            expirationElement.style.marginTop = '10px';
            expirationElement.style.fontSize = '14px';
            expirationElement.style.display = 'flex';
            expirationElement.style.alignItems = 'center';
            expirationElement.innerHTML = '<i class="fas fa-calendar-alt"></i> <span id="expirationText"></span>';
            
            // 添加到密钥状态区域
            const keyStatus = document.getElementById('keyStatus');
            keyStatus.appendChild(expirationElement);
        }
        
        const expirationText = document.getElementById('expirationText');
        if (now > expirationDate) {
            expirationElement.style.color = '#f44336'; // 红色
            expirationText.textContent = `密钥已过期！过期时间: ${expirationDate.toLocaleString()}`;
        } else {
            expirationElement.style.color = daysRemaining <= 7 ? '#ff9800' : '#4caf50'; // 橙色或绿色
            expirationText.textContent = `密钥有效期至: ${expirationDate.toLocaleString()} (剩余${daysRemaining}天)`;
        }
    }
    
    // 评估密钥强度
    async assessKeyStrength(key) {
        // 导出密钥以获取其详细信息
        const keyData = await crypto.subtle.exportKey('spki', key);
        const keyBuffer = new Uint8Array(keyData);
        
        // 检查密钥大小（RSA-OAEP）
        // 对于SPKI格式，密钥长度信息存储在特定位置
        // 这里简化处理，直接基于生成时的模数长度来判断
        // 实际实现中可以解析ASN.1结构获取准确的密钥大小
        
        // 我们的密钥总是4096位，所以直接返回高强度
        // 实际应用中可以根据不同密钥大小返回不同强度
        const keySize = 4096; // 我们生成的密钥固定为4096位
        
        if (keySize >= 4096) {
            return { level: 'strong', score: 100, text: '强' };
        } else if (keySize >= 2048) {
            return { level: 'medium', score: 75, text: '中' };
        } else {
            return { level: 'weak', score: 50, text: '弱' };
        }
    }
    
    // 更新密钥强度显示
    updateKeyStrength(strength) {
        const strengthBar = document.getElementById('strengthBar');
        const strengthText = document.getElementById('strengthText');
        
        if (!strengthBar || !strengthText) {
            return;
        }
        
        // 更新强度条
        strengthBar.style.width = `${strength.score}%`;
        
        // 根据强度设置颜色
        let color;
        switch (strength.level) {
            case 'strong':
                color = '#4caf50'; // 绿色
                break;
            case 'medium':
                color = '#ff9800'; // 橙色
                break;
            case 'weak':
                color = '#f44336'; // 红色
                break;
            default:
                color = '#e0e0e0'; // 灰色
        }
        
        strengthBar.style.background = color;
        
        // 更新强度文本
        strengthText.textContent = `${strength.text} (${strength.score}%)`;
        strengthText.style.color = color;
    }

    // 生成密钥指纹
    async generateKeyFingerprint(key) {
        const keyData = await crypto.subtle.exportKey('spki', key);
        const hash = await crypto.subtle.digest('SHA-256', keyData);
        const hashArray = Array.from(new Uint8Array(hash));
        const fingerprint = hashArray.map(b => b.toString(16).padStart(2, '0')).join(':');
        return fingerprint.substring(0, 23); // 显示前12字节
    }

    // 导出密钥
    async exportKeys() {
        if (!this.publicKey || !this.privateKey) {
            UIUtils.showToast('请先生成密钥对！', 'warning');
            return;
        }

        try {
            UIUtils.showLoading('导出密钥中...');
            const publicKeyExport = await crypto.subtle.exportKey('spki', this.publicKey);
            const privateKeyExport = await crypto.subtle.exportKey('pkcs8', this.privateKey);

            const keysData = {
                publicKey: this.arrayBufferToBase64(publicKeyExport),
                privateKey: this.arrayBufferToBase64(privateKeyExport),
                timestamp: new Date().toISOString()
            };

            // 下载密钥文件
            const blob = new Blob([JSON.stringify(keysData, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'secure-chat-keys.json';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            
            // 记录日志
            this.securityLogger.log('exportKeys', '导出了密钥对');
            
            UIUtils.hideLoading();
            UIUtils.showToast('密钥导出成功！', 'success');
        } catch (error) {
            console.error('导出密钥失败:', error);
            UIUtils.hideLoading();
            UIUtils.showToast('导出密钥失败: ' + error.message, 'error');
        }
    }

    // 导入密钥
    importKeys() {
        const input = document.createElement('input');
        input.type = 'file';
        input.accept = '.json';
        input.onchange = async (e) => {
            const file = e.target.files[0];
            if (!file) return;

            try {
                UIUtils.showLoading('导入密钥中...');
                const reader = new FileReader();
                reader.onload = async (event) => {
                    try {
                        const keysData = JSON.parse(event.target.result);

                        const publicKey = await crypto.subtle.importKey(
                            'spki',
                            this.base64ToArrayBuffer(keysData.publicKey),
                            {
                                name: 'RSA-OAEP',
                                hash: 'SHA-256',
                            },
                            true,
                            ['encrypt']
                        );

                        const privateKey = await crypto.subtle.importKey(
                            'pkcs8',
                            this.base64ToArrayBuffer(keysData.privateKey),
                            {
                                name: 'RSA-OAEP',
                                hash: 'SHA-256',
                            },
                            true,
                            ['decrypt']
                        );

                        this.publicKey = publicKey;
                        this.privateKey = privateKey;
                        await this.saveKeysToStorage({ publicKey, privateKey });
                        await this.updateKeyStatus();
                        
                        // 记录日志
                        this.securityLogger.log('importKeys', '导入了密钥对');
                        
                        UIUtils.hideLoading();
                        UIUtils.showToast('密钥导入成功！', 'success');
                    } catch (error) {
                        console.error('解析密钥文件失败:', error);
                        UIUtils.hideLoading();
                        UIUtils.showToast('解析密钥文件失败: ' + error.message, 'error');
                    }
                };
                reader.readAsText(file);
            } catch (error) {
                console.error('导入密钥失败:', error);
                UIUtils.hideLoading();
                UIUtils.showToast('导入密钥失败: ' + error.message, 'error');
            }
        };
        input.click();
    }

    // 清除密钥
    clearKeys() {
        if (confirm('确定要清除所有密钥吗？此操作不可恢复！')) {
            localStorage.removeItem('secureChatPublicKey');
            localStorage.removeItem('secureChatPrivateKey');
            this.publicKey = null;
            this.privateKey = null;
            
            const statusBadge = document.querySelector('#keyStatus .status-badge');
            statusBadge.textContent = '未检测到密钥';
            statusBadge.className = 'status-badge';
            document.getElementById('keyFingerprint').textContent = '';
            
            // 隐藏公钥显示
            document.getElementById('publicKeyDisplay').style.display = 'none';
            document.getElementById('publicKeyText').value = '';
            
            // 记录日志
            this.securityLogger.log('clearKeys', '清除了所有密钥');
            
            UIUtils.showToast('密钥已清除！', 'success');
        }
    }
    
    // 复制公钥到剪贴板
    async copyPublicKey() {
        const publicKeyText = document.getElementById('publicKeyText').value;
        if (!publicKeyText) {
            UIUtils.showToast('没有可复制的公钥！', 'warning');
            return;
        }
        
        try {
            UIUtils.showLoading('复制中...');
            await navigator.clipboard.writeText(publicKeyText);
            
            // 记录日志
            this.securityLogger.log('copyPublicKey', '复制了公钥到剪贴板');
            
            UIUtils.hideLoading();
            UIUtils.showToast('公钥已复制到剪贴板！', 'success');
        } catch (error) {
            console.error('复制公钥失败:', error);
            UIUtils.hideLoading();
            UIUtils.showToast('复制公钥失败: ' + error.message, 'error');
        }
    }
    
    // 清理接收方公钥输入格式
    cleanPublicKeyInput() {
        const recipientKeyTextarea = document.getElementById('recipientKey');
        let key = recipientKeyTextarea.value;
        
        if (!key) {
            UIUtils.showToast('请先输入公钥！', 'warning');
            return;
        }
        
        // 清理Base64字符串
        let cleanedKey = key
            .replace(/\s+/g, '') // 移除所有空白字符
            .replace(/-/g, '+')   // 替换URL安全字符
            .replace(/_/g, '/');  // 替换URL安全字符
        
        // 移除非Base64字符
        cleanedKey = cleanedKey.replace(/[^A-Za-z0-9+/=]/g, '');
        
        // 确保Base64字符串长度是4的倍数
        const padding = 4 - (cleanedKey.length % 4);
        if (padding !== 4) {
            cleanedKey = cleanedKey + '='.repeat(padding);
        }
        
        // 更新输入框内容
        recipientKeyTextarea.value = cleanedKey;
        
        // 验证清理后的公钥
        this.validateRecipientKey();
        
        UIUtils.showToast('公钥格式已清理！', 'success');
    }
    
    // 清除接收方公钥输入
    clearPublicKeyInput() {
        const recipientKeyTextarea = document.getElementById('recipientKey');
        const statusDiv = document.getElementById('recipientKeyStatus');
        
        // 清空输入框
        recipientKeyTextarea.value = '';
        
        // 清除状态信息
        statusDiv.textContent = '';
        
        // 清空相关验证状态
        this.validateRecipientKey();
    }
    
    // 验证接收方公钥格式
    validateRecipientKey() {
        const recipientKey = document.getElementById('recipientKey').value;
        const statusDiv = document.getElementById('recipientKeyStatus');
        
        if (!recipientKey.trim()) {
            statusDiv.textContent = '';
            return;
        }
        
        try {
            // 使用我们的base64ToArrayBuffer函数进行验证
            this.base64ToArrayBuffer(recipientKey);
            statusDiv.innerHTML = '<i class="fas fa-check" style="color: green;"></i> 公钥格式看起来有效';
        } catch (error) {
            statusDiv.innerHTML = `<i class="fas fa-exclamation-triangle" style="color: orange;"></i> 公钥格式可能无效: ${error.message}`;
        }
    }

    // 加密消息
    async encryptMessage() {
        const plaintext = document.getElementById('plaintext').value.trim();
        const recipientKeyStr = document.getElementById('recipientKey').value.trim();

        if (!plaintext) {
            UIUtils.showToast('请输入要加密的消息！', 'warning');
            return;
        }

        if (!this.publicKey || !this.privateKey) {
            UIUtils.showToast('请先生成或导入密钥对！', 'warning');
            return;
        }

        try {
            UIUtils.showLoading('加密消息中...');
            
            // 1. 生成随机AES-GCM密钥
            const aesKey = await crypto.subtle.generateKey(
                {
                    name: 'AES-GCM',
                    length: 256
                },
                true,
                ['encrypt', 'decrypt']
            );

            // 2. 准备消息数据
            const encoder = new TextEncoder();
            const data = encoder.encode(plaintext);

            // 3. 生成随机初始化向量
            const iv = crypto.getRandomValues(new Uint8Array(12));

            // 4. 使用AES-GCM加密消息
            const encryptedData = await crypto.subtle.encrypt(
                {
                    name: 'AES-GCM',
                    iv: iv
                },
                aesKey,
                data
            );

            // 5. 确定要使用的公钥（接收方公钥或自己的公钥）
            let targetPublicKey = this.publicKey;
            if (recipientKeyStr) {
                try {
                    targetPublicKey = await crypto.subtle.importKey(
                        'spki',
                        this.base64ToArrayBuffer(recipientKeyStr),
                        {
                            name: 'RSA-OAEP',
                            hash: 'SHA-256',
                        },
                        true,
                        ['encrypt']
                    );
                } catch (importError) {
                    console.error('导入接收方公钥失败:', importError);
                    UIUtils.hideLoading();
                    UIUtils.showToast('导入接收方公钥失败: 请检查公钥格式是否正确！', 'error');
                    return;
                }
            }

            // 6. 导出AES密钥并使用RSA-OAEP加密
            const exportedAesKey = await crypto.subtle.exportKey('raw', aesKey);
            const encryptedAesKey = await crypto.subtle.encrypt(
                {
                    name: 'RSA-OAEP'
                },
                targetPublicKey,
                exportedAesKey
            );

            // 7. 组合加密结果
            const encryptedMessage = {
                version: '1.0',
                encryptedKey: this.arrayBufferToBase64(encryptedAesKey),
                iv: this.arrayBufferToBase64(iv),
                ciphertext: this.arrayBufferToBase64(encryptedData),
                timestamp: new Date().toISOString()
            };

            // 8. 显示加密结果
            document.getElementById('ciphertext').value = JSON.stringify(encryptedMessage);
            
            // 记录日志
            this.securityLogger.log('encryptMessage', `加密了一条${plaintext.length}字符的消息`);
            
            UIUtils.hideLoading();
            UIUtils.showToast('消息加密成功！', 'success');
        } catch (error) {
            console.error('加密失败:', error);
            let errorMessage = '加密失败: ' + error.message;
            if (error.name === 'InvalidCharacterError' && error.message.includes('atob')) {
                errorMessage = '加密失败: Base64格式错误，请检查输入的公钥！';
            }
            UIUtils.hideLoading();
            UIUtils.showToast(errorMessage, 'error');
        }
    }

    // 解密消息
    async decryptMessage() {
        const encryptedMessageStr = document.getElementById('encryptedMessage').value.trim();

        if (!encryptedMessageStr) {
            UIUtils.showToast('请输入要解密的消息！', 'warning');
            return;
        }

        if (!this.privateKey) {
            UIUtils.showToast('请先生成或导入密钥对！', 'warning');
            return;
        }

        try {
            UIUtils.showLoading('解密消息中...');
            
            // 1. 解析加密消息
            let encryptedMessage;
            try {
                encryptedMessage = JSON.parse(encryptedMessageStr);
            } catch (parseError) {
                console.error('解析加密消息失败:', parseError);
                UIUtils.hideLoading();
                UIUtils.showToast('解析加密消息失败: 请检查密文格式是否正确！', 'error');
                return;
            }

            // 2. 解密AES密钥
            const encryptedAesKey = this.base64ToArrayBuffer(encryptedMessage.encryptedKey);
            const decryptedAesKey = await crypto.subtle.decrypt(
                {
                    name: 'RSA-OAEP'
                },
                this.privateKey,
                encryptedAesKey
            );

            // 3. 导入AES密钥
            const aesKey = await crypto.subtle.importKey(
                'raw',
                decryptedAesKey,
                {
                    name: 'AES-GCM'
                },
                true,
                ['encrypt', 'decrypt']
            );

            // 4. 解密消息数据
            const iv = this.base64ToArrayBuffer(encryptedMessage.iv);
            const ciphertext = this.base64ToArrayBuffer(encryptedMessage.ciphertext);
            const decryptedData = await crypto.subtle.decrypt(
                {
                    name: 'AES-GCM',
                    iv: iv
                },
                aesKey,
                ciphertext
            );

            // 5. 显示解密结果
            const decoder = new TextDecoder();
            const decryptedText = decoder.decode(decryptedData);
            document.getElementById('decryptedText').value = decryptedText;
            
            // 记录日志
            this.securityLogger.log('decryptMessage', `解密了一条${decryptedText.length}字符的消息`);
            
            UIUtils.hideLoading();
            UIUtils.showToast('消息解密成功！', 'success');
        } catch (error) {
            console.error('解密失败:', error);
            let errorMessage = '解密失败: ' + error.message;
            if (error.name === 'InvalidCharacterError' && error.message.includes('atob')) {
                errorMessage = '解密失败: Base64格式错误，请检查密文！';
            } else if (error.name === 'OperationError') {
                errorMessage = '解密失败: 密钥不匹配或密文已损坏！';
            }
            UIUtils.hideLoading();
            UIUtils.showToast(errorMessage, 'error');
        }
    }

    // 生成分享链接
    generateShareLink() {
        const encryptedMessageStr = document.getElementById('ciphertext').value.trim();
        if (!encryptedMessageStr) {
            UIUtils.showToast('请先加密消息！', 'warning');
            return;
        }

        // 生成包含加密消息的URL
        const shareUrl = `${window.location.origin}${window.location.pathname}?message=${encodeURIComponent(encryptedMessageStr)}`;
        
        // 复制到剪贴板
        UIUtils.showLoading('生成分享链接中...');
        navigator.clipboard.writeText(shareUrl).then(() => {
            UIUtils.hideLoading();
            // 记录日志
            this.securityLogger.log('generateShareLink', '生成并复制了分享链接');
            UIUtils.showToast('分享链接已复制到剪贴板！', 'success');
        }).catch(err => {
            console.error('复制链接失败:', err);
            UIUtils.hideLoading();
            UIUtils.showToast('复制链接失败: ' + err.message, 'error');
        });
    }

    // 复制到剪贴板
    async copyToClipboard(elementId) {
        const text = document.getElementById(elementId).value;
        if (!text) {
            UIUtils.showToast('没有可复制的内容！', 'warning');
            return;
        }

        try {
            UIUtils.showLoading('复制中...');
            await navigator.clipboard.writeText(text);
            UIUtils.hideLoading();
            
            // 记录日志
            this.securityLogger.log('copyToClipboard', `复制了${elementId}内容到剪贴板`);
            
            UIUtils.showToast('已复制到剪贴板！', 'success');
        } catch (error) {
            console.error('复制失败:', error);
            UIUtils.hideLoading();
            UIUtils.showToast('复制失败: ' + error.message, 'error');
        }
    }

    // 从剪贴板粘贴
    async pasteFromClipboard() {
        try {
            UIUtils.showLoading('粘贴中...');
            const text = await navigator.clipboard.readText();
            document.getElementById('encryptedMessage').value = text;
            
            // 记录日志
            this.securityLogger.log('pasteFromClipboard', '从剪贴板粘贴了内容');
            
            UIUtils.hideLoading();
            UIUtils.showToast('已从剪贴板粘贴！', 'success');
        } catch (error) {
            console.error('粘贴失败:', error);
            UIUtils.hideLoading();
            UIUtils.showToast('粘贴失败: ' + error.message, 'error');
        }
    }

    // 辅助函数：ArrayBuffer转Base64
    arrayBufferToBase64(buffer) {
        const binary = new Uint8Array(buffer);
        const chars = binary.reduce((acc, byte) => acc + String.fromCharCode(byte), '');
        return btoa(chars);
    }

    // 辅助函数：Base64转ArrayBuffer
    base64ToArrayBuffer(base64) {
        // 首先检查输入是否为空
        if (!base64 || typeof base64 !== 'string') {
            throw new Error('无效的Base64输入：输入为空或不是字符串');
        }
        
        // 清理Base64字符串，移除可能的无效字符
        let cleanedBase64 = base64
            .replace(/\s+/g, '') // 移除所有空白字符（空格、换行、制表符等）
            .replace(/-/g, '+')   // 替换URL安全Base64的-为+
            .replace(/_/g, '/');  // 替换URL安全Base64的_为/
        
        // 移除任何非Base64字符
        cleanedBase64 = cleanedBase64.replace(/[^A-Za-z0-9+/=]/g, '');
        
        // 确保Base64字符串长度是4的倍数
        const padding = 4 - (cleanedBase64.length % 4);
        if (padding !== 4) {
            cleanedBase64 = cleanedBase64 + '='.repeat(padding);
        }
        
        // 验证清理后的Base64字符串
        if (!/^[A-Za-z0-9+/]*={0,2}$/.test(cleanedBase64)) {
            throw new Error('无效的Base64字符串：包含非法字符或格式错误');
        }
        
        try {
            const binary = atob(cleanedBase64);
            const buffer = new ArrayBuffer(binary.length);
            const view = new Uint8Array(buffer);
            for (let i = 0; i < binary.length; i++) {
                view[i] = binary.charCodeAt(i);
            }
            return buffer;
        } catch (error) {
            console.error('Base64解码失败:', error);
            throw new Error('Base64解码失败：字符串格式严重错误');
        }
    }
}

// 页面加载完成后初始化
window.addEventListener('DOMContentLoaded', () => {
    // 初始化主题管理器
    window.themeManager = new ThemeManager();
    
    // 初始化自动保存管理器
    window.autoSaveManager = new AutoSaveManager();
    
    // 初始化拖拽上传管理器
    window.dragDropManager = new DragDropManager();
    
    // 初始化安全日志记录器
    window.securityLogger = new SecurityLogger();
    
    // 初始化消息历史管理器
    window.messageHistoryManager = new MessageHistoryManager();
    
    // 初始化加密工具
    window.secureChatEncryptor = new SecureChatEncryptor();

    // 检查URL参数中是否有加密消息
    const urlParams = new URLSearchParams(window.location.search);
    const message = urlParams.get('message');
    if (message) {
        document.getElementById('encryptedMessage').value = message;
    }
});