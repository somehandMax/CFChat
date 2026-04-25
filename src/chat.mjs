// =======================================================================================
// Cloudflare Worker Chat Room - 重构版
// 适配CF Worker环境，支持6位数字口令、房主权限、拉黑/踢人/转让、文件传输、AES加密
// =======================================================================================

import HTML from "./chat.html";

// ===============================
// 错误码定义模块
// ===============================
const ERROR_CODES = {
  1001: { code: 1001, msg: "口令错误" },
  1002: { code: 1002, msg: "房间已关闭新用户加入" },
  1003: { code: 1003, msg: "您已被该房间拉黑，无法进入" },
  1004: { code: 1004, msg: "房间关闭新用户加入" },
  1005: { code: 1005, msg: "房间密码错误" },
  1006: { code: 1006, msg: "无权操作，仅房主可执行此操作" },
  1007: { code: 1007, msg: "目标用户不在房间内" },
  1008: { code: 1008, msg: "不能对自己执行此操作" },
  1009: { code: 1009, msg: "名称过长" },
  1010: { code: 1010, msg: "消息过长" },
  1011: { code: 1011, msg: "传输请求参数错误" },
  1012: { code: 1012, msg: "房间不存在或已重置" },
  9999: { code: 9999, msg: "服务器内部错误" }
};

function makeError(code) {
  const e = ERROR_CODES[code] || ERROR_CODES[9999];
  return JSON.stringify({ error: e.msg, errorCode: e.code });
}

// ===============================
// 工具函数模块
// ===============================

// 生成6位纯数字口令
function generateSixDigitCode() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

// 生成AES-256密钥 (32字节随机数，base64编码)
function generateAesKey() {
  const arr = new Uint8Array(32);
  crypto.getRandomValues(arr);
  return btoa(String.fromCharCode(...arr));
}

// ===============================
// HTTP错误处理包装器
// ===============================
async function handleErrors(request, func) {
  try {
    return await func();
  } catch (err) {
    console.error("Worker error:", err);
    if (request.headers.get("Upgrade") == "websocket") {
      let pair = new WebSocketPair();
      pair[1].accept();
      pair[1].send(makeError(9999));
      pair[1].close(1011, "会话设置期间未捕获的异常");
      return new Response(null, { status: 101, webSocket: pair[0] });
    } else {
      return new Response(err.stack, { status: 500 });
    }
  }
}

// ===============================
// 主Worker入口
// ===============================
export default {
  async fetch(request, env) {
    return await handleErrors(request, async () => {
      let url = new URL(request.url);
      let path = url.pathname.slice(1).split('/');

      if (!path[0]) {
        return new Response(HTML, { headers: { "Content-Type": "text/html;charset=UTF-8" } });
      }

      switch (path[0]) {
        case "api":
          return handleApiRequest(path.slice(1), request, env);
        default:
          return new Response("未找到", { status: 404 });
      }
    });
  }
};

// ===============================
// API路由处理模块
// ===============================
async function handleApiRequest(path, request, env) {
  const url = new URL(request.url);

  switch (path[0]) {
    case "room": {
      // POST /api/room -> 创建新房间，返回6位数字口令
      if (!path[1]) {
        if (request.method == "POST") {
          let id = env.rooms.newUniqueId();
          return new Response(id.toString(), { headers: { "Access-Control-Allow-Origin": "*" } });
        } else {
          return new Response("方法不允许", { status: 405 });
        }
      }

      // 处理 /api/room/{roomCode}/...
      let roomCode = path[1];
      // 校验6位数字口令格式
      if (!/^\d{6}$/.test(roomCode)) {
        return new Response(makeError(1012), { status: 400, headers: { "Content-Type": "application/json" } });
      }

      let id = env.rooms.idFromName("room:" + roomCode);
      let roomObject = env.rooms.get(id);
      let newUrl = new URL(request.url);
      newUrl.pathname = "/" + path.slice(2).join("/");
      return roomObject.fetch(newUrl, request);
    }

    case "admin": {
      const requestKey = url.searchParams.get("key");
      const actualAdminSecretKey = env.ADMIN_SECRET_KEY || "del";
      if (requestKey !== actualAdminSecretKey) {
        return new Response("未经授权。密钥不匹配或未设置。", { status: 401 });
      }

      switch (path[1]) {
        case "clear-room": {
          const roomId = path[2];
          if (!roomId) {
            return new Response("请提供要清空的房间名称或 ID。", { status: 400 });
          }
          let id = env.rooms.idFromName("room:" + roomId);
          try {
            let roomObject = env.rooms.get(id);
            const clearResponse = await roomObject.fetch(new URL("https://dummy-url/clear-messages"));
            if (clearResponse.ok) {
              return new Response(`房间 '${roomId}' 的聊天记录已清空。`, { status: 200 });
            } else {
              const errorText = await clearResponse.text();
              return new Response(`清空失败：${errorText}`, { status: clearResponse.status });
            }
          } catch (error) {
            console.error("清空聊天记录时发生错误:", error);
            return new Response(`清空聊天记录时发生内部错误: ${error.message}`, { status: 500 });
          }
        }

        case "clear-rate-limits": {
          try {
            const targetIp = url.searchParams.get("ip");
            if (!targetIp) {
              return new Response("请提供要清空速率限制的 IP 地址。", { status: 400 });
            }
            let limiterId = env.limiters.idFromName(targetIp);
            let limiterObject = env.limiters.get(limiterId);
            const clearResponse = await limiterObject.fetch(new URL("https://dummy-url/clear-limit"));
            if (clearResponse.ok) {
              return new Response(`IP '${targetIp}' 的速率限制已清空。`, { status: 200 });
            } else {
              const errorText = await clearResponse.text();
              return new Response(`清空IP速率限制失败：${errorText}`, { status: clearResponse.status });
            }
          } catch (error) {
            console.error("清空速率限制时发生错误:", error);
            return new Response(`清空速率限制时发生内部错误: ${error.message}`, { status: 500 });
          }
        }

        default:
          return new Response("未找到管理操作。", { status: 404 });
      }
    }

    default:
      return new Response("未找到", { status: 404 });
  }
}

// =======================================================================================
// ChatRoom Durable Object 类 - 状态管理与WebSocket处理
// =======================================================================================
export class ChatRoom {
  constructor(state, env) {
    this.state = state;
    this.storage = state.storage;
    this.env = env;
    this.sessions = new Map(); // WebSocket -> session
    this.lastTimestamp = 0;

    // 房间核心状态（将从storage恢复）
    this.roomState = {
      ownerId: null,        // 房主session ID
      userOrder: [],        // 用户入房顺序 [{sessionId, name}]
      blacklist: [],        // 拉黑列表 [{sessionId, name}]
      settings: {
        passwordHash: null, // 密码MD5哈希
        allowNewUsers: true // 允许新用户加入
      },
      aesKey: null,         // 房间AES加密密钥
      created: false        // 房间是否已创建
    };

    // 从休眠状态恢复WebSocket
    this.state.getWebSockets().forEach((webSocket) => {
      let meta = webSocket.deserializeAttachment() || {};
      let limiterId = this.env.limiters.idFromString(meta.limiterId);
      let limiter = new RateLimiterClient(
        () => this.env.limiters.get(limiterId),
        err => webSocket.close(1011, err.stack)
      );
      let blockedMessages = [];
      this.sessions.set(webSocket, { ...meta, limiter, blockedMessages, webSocket });
    });
  }

  // 从Storage加载房间状态
  async loadRoomState() {
    try {
      const stored = await this.storage.get("roomState");
      if (stored) {
        this.roomState = stored;
      }
    } catch (e) {
      console.error("加载房间状态失败:", e);
    }
  }

  // 保存房间状态到Storage
  async saveRoomState() {
    try {
      await this.storage.put("roomState", this.roomState);
    } catch (e) {
      console.error("保存房间状态失败:", e);
    }
  }

  // 处理HTTP请求
  async fetch(request) {
    return await handleErrors(request, async () => {
      let url = new URL(request.url);

      switch (url.pathname) {
        case "/websocket": {
          if (request.headers.get("Upgrade") != "websocket") {
            return new Response("需要 WebSocket", { status: 400 });
          }
          let ip = request.headers.get("CF-Connecting-IP");
          let pair = new WebSocketPair();
          await this.handleSession(pair[1], ip);
          return new Response(null, { status: 101, webSocket: pair[0] });
        }

        case "/clear-messages": {
          await this.clearAllMessages();
          return new Response("聊天记录已清空。", { status: 200 });
        }

        default:
          return new Response("未找到", { status: 404 });
      }
    });
  }

  // 清空房间所有数据
  async clearAllMessages() {
    await this.storage.deleteAll();
    this.roomState = {
      ownerId: null,
      userOrder: [],
      blacklist: [],
      settings: { passwordHash: null, allowNewUsers: true },
      aesKey: null,
      created: false
    };
    this.sessions.clear();
    this.lastTimestamp = 0;
    console.log(`房间已重置: ${this.state.id}`);
  }

  // 获取session唯一标识
  getSessionId(webSocket) {
    const meta = webSocket.deserializeAttachment() || {};
    return meta.sessionId || crypto.randomUUID();
  }

  // 处理WebSocket会话连接
  async handleSession(webSocket, ip) {
    await this.loadRoomState();
    this.state.acceptWebSocket(webSocket);

    // 生成或恢复sessionId
    let sessionId = this.getSessionId(webSocket);
    let limiterId = this.env.limiters.idFromName(ip);
    let limiter = new RateLimiterClient(
      () => this.env.limiters.get(limiterId),
      err => webSocket.close(1011, err.stack)
    );

    let session = {
      sessionId,
      limiterId,
      limiter,
      blockedMessages: [],
      name: null,
      ip,
      webSocket,
      quit: false
    };

    webSocket.serializeAttachment({
      ...webSocket.deserializeAttachment(),
      sessionId,
      limiterId: limiterId.toString()
    });

    this.sessions.set(webSocket, session);

    // 发送房间状态同步（用于重连场景）
    session.blockedMessages.push(JSON.stringify({
      type: "roomState",
      ownerId: this.roomState.ownerId,
      userOrder: this.roomState.userOrder,
      aesKey: this.roomState.aesKey,
      settings: this.roomState.settings
    }));
  }

  // 处理WebSocket消息
  async webSocketMessage(webSocket, msg) {
    try {
      let session = this.sessions.get(webSocket);
      if (!session || session.quit) {
        webSocket.close(1011, "WebSocket 已损坏");
        return;
      }

      // 速率限制检查
      if (!session.limiter.checkLimit()) {
        webSocket.send(JSON.stringify({ error: "您的IP受到速率限制，请稍后再试", errorCode: 2001 }));
        return;
      }

      let data = JSON.parse(msg);

      // 处理不同类型的消息
      switch (data.type) {
        case "join": {
          // 用户入房请求
          await this.handleJoin(webSocket, session, data);
          break;
        }
        case "chat": {
          await this.handleChat(webSocket, session, data);
          break;
        }
        case "kick": {
          await this.handleKick(webSocket, session, data);
          break;
        }
        case "blacklist": {
          await this.handleBlacklist(webSocket, session, data);
          break;
        }
        case "transferOwner": {
          await this.handleTransferOwner(webSocket, session, data);
          break;
        }
        case "updateSettings": {
          await this.handleUpdateSettings(webSocket, session, data);
          break;
        }
        case "fileRequest": {
          await this.handleFileRequest(webSocket, session, data);
          break;
        }
        case "fileResponse": {
          await this.handleFileResponse(webSocket, session, data);
          break;
        }
        case "fileChunk": {
          await this.handleFileChunk(webSocket, session, data);
          break;
        }
        case "fileStatus": {
          await this.handleFileStatus(webSocket, session, data);
          break;
        }
        default: {
          // 兼容旧版纯消息格式
          if (!session.name) {
            await this.handleLegacyJoin(webSocket, session, data);
          } else {
            await this.handleLegacyChat(webSocket, session, data);
          }
        }
      }
    } catch (err) {
      console.error("webSocketMessage error:", err);
      webSocket.send(makeError(9999));
    }
  }

  // ===============================
  // 入房处理模块
  // ===============================
  async handleJoin(webSocket, session, data) {
    const { name, roomCode, passwordHash } = data;

    // 检查房间是否已关闭新用户加入
    if (this.roomState.created && !this.roomState.settings.allowNewUsers) {
      // 如果是房主重连，允许进入
      if (session.sessionId !== this.roomState.ownerId) {
        webSocket.send(makeError(1004));
        webSocket.close(1008, "房间关闭新用户加入");
        return;
      }
    }

    // 检查拉黑列表
    const isBlacklisted = this.roomState.blacklist.some(b => b.sessionId === session.sessionId);
    if (isBlacklisted) {
      webSocket.send(makeError(1003));
      webSocket.close(1008, "已被拉黑");
      return;
    }

    // 校验密码（如果设置了密码）
    if (this.roomState.settings.passwordHash) {
      if (passwordHash !== this.roomState.settings.passwordHash) {
        webSocket.send(makeError(1005));
        return;
      }
    }

    // 设置用户名
    session.name = "" + (name || "匿名");
    if (session.name.length > 32) {
      webSocket.send(makeError(1009));
      webSocket.close(1009, "名称过长");
      return;
    }

    webSocket.serializeAttachment({
      ...webSocket.deserializeAttachment(),
      name: session.name
    });

    // 初始化房间（首个用户成为房主）
    if (!this.roomState.created) {
      this.roomState.created = true;
      this.roomState.ownerId = session.sessionId;
      this.roomState.aesKey = generateAesKey();
      await this.saveRoomState();
    }

    // 添加到用户顺序列表
    const existingIndex = this.roomState.userOrder.findIndex(u => u.sessionId === session.sessionId);
    if (existingIndex === -1) {
      this.roomState.userOrder.push({ sessionId: session.sessionId, name: session.name });
      await this.saveRoomState();
    } else {
      // 更新名称
      this.roomState.userOrder[existingIndex].name = session.name;
      await this.saveRoomState();
    }

    // 发送排队消息（历史记录等）
    await this.sendBacklog(session);

    // 广播用户加入
    this.broadcast({
      type: "userJoined",
      name: session.name,
      sessionId: session.sessionId,
      userOrder: this.roomState.userOrder,
      ownerId: this.roomState.ownerId
    });

    webSocket.send(JSON.stringify({ type: "ready", sessionId: session.sessionId }));
  }

  // 发送历史记录
  async sendBacklog(session) {
    // 发送在线用户列表
    for (let s of this.sessions.values()) {
      if (s.name && s.sessionId !== session.sessionId) {
        session.blockedMessages.push(JSON.stringify({
          type: "userJoined",
          name: s.name,
          sessionId: s.sessionId
        }));
      }
    }

    // 加载最近100条聊天记录
    try {
      let storage = await this.storage.list({ reverse: true, limit: 100 });
      let backlog = [...storage.values()].filter(v => typeof v === 'string');
      backlog.reverse();
      backlog.forEach(value => {
        session.blockedMessages.push(value);
      });
    } catch (e) {
      console.error("加载历史记录失败:", e);
    }

    // 发送房间状态
    session.blockedMessages.push(JSON.stringify({
      type: "roomState",
      ownerId: this.roomState.ownerId,
      userOrder: this.roomState.userOrder,
      aesKey: this.roomState.aesKey,
      settings: this.roomState.settings
    }));

    // 发送排队消息
    session.blockedMessages.forEach(queued => {
      try {
        session.webSocket.send(queued);
      } catch (e) {}
    });
    session.blockedMessages = [];
  }

  // ===============================
  // 聊天消息处理模块
  // ===============================
  async handleChat(webSocket, session, data) {
    if (!session.name) {
      webSocket.send(makeError(1012));
      return;
    }

    let message = "" + (data.message || "");
    if (message.length > 256) {
      webSocket.send(makeError(1010));
      return;
    }

    let timestamp = Math.max(Date.now(), this.lastTimestamp + 1);
    this.lastTimestamp = timestamp;

    let payload = {
      type: "chat",
      name: session.name,
      sessionId: session.sessionId,
      message: message,
      timestamp: timestamp
    };

    let dataStr = JSON.stringify(payload);
    this.broadcast(dataStr);

    // 保存消息
    let key = "msg:" + new Date(timestamp).toISOString() + ":" + crypto.randomUUID();
    await this.storage.put(key, dataStr);
  }

  // ===============================
  // 房主权限：踢人处理模块
  // ===============================
  async handleKick(webSocket, session, data) {
    // 校验房主权限
    if (session.sessionId !== this.roomState.ownerId) {
      webSocket.send(makeError(1006));
      return;
    }

    const targetSessionId = data.targetSessionId;
    if (!targetSessionId) {
      webSocket.send(makeError(1007));
      return;
    }

    if (targetSessionId === session.sessionId) {
      webSocket.send(makeError(1008));
      return;
    }

    // 查找目标用户
    let targetWs = null;
    let targetSession = null;
    for (let [ws, s] of this.sessions) {
      if (s.sessionId === targetSessionId) {
        targetWs = ws;
        targetSession = s;
        break;
      }
    }

    if (!targetSession) {
      webSocket.send(makeError(1007));
      return;
    }

    // 从用户列表移除
    this.roomState.userOrder = this.roomState.userOrder.filter(u => u.sessionId !== targetSessionId);
    await this.saveRoomState();

    // 断开目标用户连接
    try {
      targetWs.send(JSON.stringify({
        type: "kicked",
        msg: "您已被房主踢出房间"
      }));
      targetWs.close(1008, "已被踢出房间");
    } catch (e) {}

    // 广播用户离开
    this.broadcast({
      type: "userQuit",
      name: targetSession.name,
      sessionId: targetSessionId,
      userOrder: this.roomState.userOrder,
      ownerId: this.roomState.ownerId
    });

    // 确认操作成功
    webSocket.send(JSON.stringify({
      type: "kickSuccess",
      targetSessionId,
      targetName: targetSession.name
    }));
  }

  // ===============================
  // 房主权限：拉黑处理模块
  // ===============================
  async handleBlacklist(webSocket, session, data) {
    // 校验房主权限
    if (session.sessionId !== this.roomState.ownerId) {
      webSocket.send(makeError(1006));
      return;
    }

    const targetSessionId = data.targetSessionId;
    const action = data.action; // 'add' or 'remove'

    if (!targetSessionId) {
      webSocket.send(makeError(1007));
      return;
    }

    if (targetSessionId === session.sessionId) {
      webSocket.send(makeError(1008));
      return;
    }

    if (action === "add") {
      // 查找目标用户
      let targetSession = null;
      for (let s of this.sessions.values()) {
        if (s.sessionId === targetSessionId) {
          targetSession = s;
          break;
        }
      }

      if (!targetSession) {
        // 可能用户已离线，尝试从userOrder查找
        const userInfo = this.roomState.userOrder.find(u => u.sessionId === targetSessionId);
        if (userInfo) {
          this.roomState.blacklist.push({ sessionId: targetSessionId, name: userInfo.name });
          this.roomState.userOrder = this.roomState.userOrder.filter(u => u.sessionId !== targetSessionId);
          await this.saveRoomState();
          webSocket.send(JSON.stringify({
            type: "blacklistSuccess",
            action: "add",
            targetSessionId,
            targetName: userInfo.name
          }));
          this.broadcast({
            type: "userQuit",
            name: userInfo.name,
            sessionId: targetSessionId,
            userOrder: this.roomState.userOrder,
            ownerId: this.roomState.ownerId
          });
        } else {
          webSocket.send(makeError(1007));
        }
        return;
      }

      // 添加到黑名单
      this.roomState.blacklist.push({ sessionId: targetSessionId, name: targetSession.name });
      this.roomState.userOrder = this.roomState.userOrder.filter(u => u.sessionId !== targetSessionId);
      await this.saveRoomState();

      // 断开目标用户
      try {
        targetSession.webSocket.send(JSON.stringify({
          type: "blacklisted",
          msg: "您已被房主拉黑"
        }));
        targetSession.webSocket.close(1008, "已被拉黑");
      } catch (e) {}

      // 广播
      this.broadcast({
        type: "userQuit",
        name: targetSession.name,
        sessionId: targetSessionId,
        userOrder: this.roomState.userOrder,
        ownerId: this.roomState.ownerId
      });

      webSocket.send(JSON.stringify({
        type: "blacklistSuccess",
        action: "add",
        targetSessionId,
        targetName: targetSession.name
      }));
    } else if (action === "remove") {
      // 从黑名单移除
      const idx = this.roomState.blacklist.findIndex(b => b.sessionId === targetSessionId);
      if (idx !== -1) {
        const removed = this.roomState.blacklist.splice(idx, 1)[0];
        await this.saveRoomState();
        webSocket.send(JSON.stringify({
          type: "blacklistSuccess",
          action: "remove",
          targetSessionId,
          targetName: removed.name
        }));
      } else {
        webSocket.send(makeError(1007));
      }
    }
  }

  // ===============================
  // 房主权限：转让房主处理模块
  // ===============================
  async handleTransferOwner(webSocket, session, data) {
    if (session.sessionId !== this.roomState.ownerId) {
      webSocket.send(makeError(1006));
      return;
    }

    const targetSessionId = data.targetSessionId;
    if (!targetSessionId) {
      webSocket.send(makeError(1007));
      return;
    }

    if (targetSessionId === session.sessionId) {
      webSocket.send(makeError(1008));
      return;
    }

    // 确认目标用户在房间内
    const targetInRoom = this.roomState.userOrder.some(u => u.sessionId === targetSessionId);
    if (!targetInRoom) {
      webSocket.send(makeError(1007));
      return;
    }

    // 更新房主
    const oldOwnerId = this.roomState.ownerId;
    this.roomState.ownerId = targetSessionId;

    // 调整用户顺序：新房主置顶，原房主回到原位置
    let newOrder = this.roomState.userOrder.filter(u => u.sessionId !== targetSessionId);
    const targetUser = this.roomState.userOrder.find(u => u.sessionId === targetSessionId);
    newOrder.unshift(targetUser);
    this.roomState.userOrder = newOrder;

    await this.saveRoomState();

    // 广播房主变更
    this.broadcast({
      type: "ownerChanged",
      newOwnerId: targetSessionId,
      oldOwnerId: oldOwnerId,
      userOrder: this.roomState.userOrder
    });

    webSocket.send(JSON.stringify({
      type: "transferSuccess",
      newOwnerId: targetSessionId
    }));
  }

  // ===============================
  // 房间设置处理模块
  // ===============================
  async handleUpdateSettings(webSocket, session, data) {
    if (session.sessionId !== this.roomState.ownerId) {
      webSocket.send(makeError(1006));
      return;
    }

    const { passwordHash, allowNewUsers } = data.settings || {};

    if (passwordHash !== undefined) {
      this.roomState.settings.passwordHash = passwordHash || null;
    }
    if (allowNewUsers !== undefined) {
      this.roomState.settings.allowNewUsers = !!allowNewUsers;
    }

    await this.saveRoomState();

    // 广播设置变更
    this.broadcast({
      type: "settingsUpdated",
      settings: this.roomState.settings
    });

    webSocket.send(JSON.stringify({
      type: "updateSettingsSuccess",
      settings: this.roomState.settings
    }));
  }

  // ===============================
  // 文件传输中转模块（Worker仅透传）
  // ===============================
  async handleFileRequest(webSocket, session, data) {
    if (!session.name) {
      webSocket.send(makeError(1012));
      return;
    }

    const { targetSessionId, fileMeta } = data;
    if (!targetSessionId || !fileMeta) {
      webSocket.send(makeError(1011));
      return;
    }

    // 查找目标用户并转发
    let targetSession = null;
    for (let s of this.sessions.values()) {
      if (s.sessionId === targetSessionId) {
        targetSession = s;
        break;
      }
    }

    if (!targetSession) {
      webSocket.send(makeError(1007));
      return;
    }

    // 透传文件传输请求
    try {
      targetSession.webSocket.send(JSON.stringify({
        type: "fileRequest",
        fromSessionId: session.sessionId,
        fromName: session.name,
        fileMeta: fileMeta
      }));
    } catch (e) {
      webSocket.send(JSON.stringify({ error: "转发文件请求失败", errorCode: 2002 }));
    }
  }

  async handleFileResponse(webSocket, session, data) {
    const { targetSessionId, accepted, fileMeta } = data;
    if (!targetSessionId) return;

    let targetSession = null;
    for (let s of this.sessions.values()) {
      if (s.sessionId === targetSessionId) {
        targetSession = s;
        break;
      }
    }

    if (targetSession) {
      try {
        targetSession.webSocket.send(JSON.stringify({
          type: "fileResponse",
          fromSessionId: session.sessionId,
          fromName: session.name,
          accepted,
          fileMeta
        }));
      } catch (e) {}
    }
  }

  async handleFileChunk(webSocket, session, data) {
    const { targetSessionId, chunkIndex, totalChunks, chunkData } = data;
    if (!targetSessionId) return;

    let targetSession = null;
    for (let s of this.sessions.values()) {
      if (s.sessionId === targetSessionId) {
        targetSession = s;
        break;
      }
    }

    if (targetSession) {
      try {
        targetSession.webSocket.send(JSON.stringify({
          type: "fileChunk",
          fromSessionId: session.sessionId,
          fromName: session.name,
          chunkIndex,
          totalChunks,
          chunkData
        }));
      } catch (e) {}
    }
  }

  async handleFileStatus(webSocket, session, data) {
    const { targetSessionId, status, fileMeta } = data;
    if (!targetSessionId) return;

    let targetSession = null;
    for (let s of this.sessions.values()) {
      if (s.sessionId === targetSessionId) {
        targetSession = s;
        break;
      }
    }

    if (targetSession) {
      try {
        targetSession.webSocket.send(JSON.stringify({
          type: "fileStatus",
          fromSessionId: session.sessionId,
          fromName: session.name,
          status,
          fileMeta
        }));
      } catch (e) {}
    }
  }

  // ===============================
  // 兼容旧版协议的处理
  // ===============================
  async handleLegacyJoin(webSocket, session, data) {
    // 将旧版格式转换为新版join
    await this.handleJoin(webSocket, session, {
      type: "join",
      name: data.name,
      roomCode: "legacy"
    });
  }

  async handleLegacyChat(webSocket, session, data) {
    await this.handleChat(webSocket, session, {
      type: "chat",
      message: data.message
    });
  }

  // ===============================
  // WebSocket关闭/错误处理模块
  // ===============================
  async closeOrErrorHandler(webSocket) {
    let session = this.sessions.get(webSocket);
    if (!session) return;

    session.quit = true;
    this.sessions.delete(webSocket);

    if (session.name) {
      // 从用户列表移除
      this.roomState.userOrder = this.roomState.userOrder.filter(
        u => u.sessionId !== session.sessionId
      );

      // 检查是否还有在线用户
      const hasOnlineUsers = Array.from(this.sessions.values()).some(s => s.name && !s.quit);

      if (!hasOnlineUsers) {
        // 最后一个用户断开，触发房间重置
        console.log(`房间 ${this.state.id} 最后一个用户断开，执行重置`);
        await this.clearAllMessages();
      } else {
        await this.saveRoomState();
        // 广播用户离开
        this.broadcast({
          type: "userQuit",
          name: session.name,
          sessionId: session.sessionId,
          userOrder: this.roomState.userOrder,
          ownerId: this.roomState.ownerId
        });
      }
    }
  }

  async webSocketClose(webSocket, code, reason, wasClean) {
    await this.closeOrErrorHandler(webSocket);
  }

  async webSocketError(webSocket, error) {
    await this.closeOrErrorHandler(webSocket);
  }

  // ===============================
  // 广播消息模块
  // ===============================
  broadcast(message) {
    if (typeof message !== "string") {
      message = JSON.stringify(message);
    }

    let quitters = [];
    this.sessions.forEach((session, webSocket) => {
      if (session.quit) return;

      if (session.name) {
        try {
          webSocket.send(message);
        } catch (err) {
          session.quit = true;
          quitters.push(session);
          this.sessions.delete(webSocket);
        }
      } else {
        session.blockedMessages.push(message);
      }
    });

    quitters.forEach(quitter => {
      if (quitter.name) {
        this.broadcast({
          type: "userQuit",
          name: quitter.name,
          sessionId: quitter.sessionId,
          userOrder: this.roomState.userOrder,
          ownerId: this.roomState.ownerId
        });
      }
    });
  }
}

// =======================================================================================
// RateLimiter Durable Object 类
// =======================================================================================
export class RateLimiter {
  constructor(state, env) {
    this.state = state;
    this.storage = state.storage;
    this.nextAllowedTime = 0;
    this.loadState();
  }

  async loadState() {
    const storedTime = await this.storage.get("nextAllowedTime");
    if (storedTime) {
      this.nextAllowedTime = storedTime;
    }
  }

  async fetch(request) {
    return await handleErrors(request, async () => {
      let url = new URL(request.url);

      switch (url.pathname) {
        case "/clear-limit": {
          await this.clearLimit();
          return new Response("速率限制已清空。", { status: 200 });
        }
        default:
          let now = Date.now() / 1000;
          this.nextAllowedTime = Math.max(now, this.nextAllowedTime);

          if (request.method == "POST") {
            this.nextAllowedTime += 5;
            await this.storage.put("nextAllowedTime", this.nextAllowedTime);
          }

          let cooldown = Math.max(0, this.nextAllowedTime - now - 20);
          return new Response(cooldown);
      }
    });
  }

  async clearLimit() {
    await this.storage.delete("nextAllowedTime");
    this.nextAllowedTime = 0;
    console.log(`RateLimiter ID: ${this.state.id} - 速率限制已清空。`);
  }
}

// =======================================================================================
// RateLimiterClient 类
// =======================================================================================
class RateLimiterClient {
  constructor(getLimiterStub, reportError) {
    this.getLimiterStub = getLimiterStub;
    this.reportError = reportError;
    this.limiter = getLimiterStub();
    this.inCooldown = false;
  }

  checkLimit() {
    if (this.inCooldown) {
      return false;
    }
    this.inCooldown = true;
    this.callLimiter();
    return true;
  }

  async callLimiter() {
    try {
      let response;
      try {
        response = await this.limiter.fetch("https://dummy-url", { method: "POST" });
      } catch (err) {
        this.limiter = this.getLimiterStub();
        response = await this.limiter.fetch("https://dummy-url", { method: "POST" });
      }

      let cooldown = +(await response.text());
      await new Promise(resolve => setTimeout(resolve, cooldown * 1000));
      this.inCooldown = false;
    } catch (err) {
      this.reportError(err);
    }
  }
}
