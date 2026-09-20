/* 输入法管理器 · 前端逻辑 */
(function () {
  "use strict";

  let state = { enabled: [], installed: [], disabled: [], lock: null };
  let dragSrc = null;
  let pendingAction = null;

  const $ = (id) => document.getElementById(id);

  // ---------------- 工具 ----------------
  function toast(msg, type) {
    const t = $("toast");
    t.textContent = msg;
    t.className = "toast " + (type || "ok");
    clearTimeout(t._timer);
    t._timer = setTimeout(() => t.classList.add("hidden"), 2600);
  }

  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
    }[c]));
  }

  function nameOfTip(tip, list) {
    const it = (list || state.enabled).find((x) => x.tip === tip);
    return it ? it.name : tip;
  }

  function confirmModal(title, text, onOk, okText) {
    $("modalTitle").textContent = title;
    $("modalText").textContent = text;
    $("modalOk").textContent = okText || "确认";
    $("modalMask").classList.remove("hidden");
    pendingAction = onOk;
  }

  // ---------------- 渲染 ----------------
  // 显示列表 = 启用项 + 停用项（停用项暗色保留在列表）
  function displayList() {
    const enabledItems = state.enabled.map((x) => ({ ...x, off: false }));
    const offItems = state.disabled.map((tip) => {
      const inst = state.installed.find((i) => i.tip === tip);
      return { tip: tip, name: inst ? inst.name : tip, is_default: false, off: true };
    });
    return enabledItems.concat(offItems);
  }

  function renderEnabled() {
    const ul = $("imeList");
    const items = displayList();
    if (!items.length) {
      ul.innerHTML = '<li class="empty">未启用任何输入法</li>';
      ul.classList.remove("scroll");
      return;
    }
    // 数量超过阈值才启用滚动，正常全部展示
    ul.classList.toggle("scroll", items.length > 6);
    ul.innerHTML = "";
    items.forEach((it, i) => {
      const off = !!it.off;
      const li = document.createElement("li");
      li.className = "ime-item" + (off ? " off" : "");
      li.draggable = !off;
      li.dataset.tip = it.tip;
      li.innerHTML =
        '<span class="ime-order">' + (off ? "–" : (i + 1)) + "</span>" +
        '<span class="ime-name">' + esc(it.name) + "</span>" +
        (it.is_default ? '<span class="ime-badge default">默认</span>' : "") +
        (off ? '<span class="ime-badge off-tag">已停用</span>' : "") +
        '<label class="switch mini" title="' + (off ? "重新启用该输入法" : "停用该输入法（保留在列表，变暗显示）") + '">' +
        '<input type="checkbox" data-act="toggle-ime"' + (off ? "" : " checked") + ">" +
        '<span class="slider"></span></label>' +
        '<span class="ime-actions">' +
        (off ? "" :
          '<button class="glass-btn small btn-default" data-act="default" title="设为全局默认">' +
          '<svg class="def-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6L9 17l-5-5"/></svg>设为默认</button>') +
        '<button class="btn-del" data-act="remove" title="' + (off ? "从列表彻底移除" : "从启用列表移除") + '">' +
        '<svg class="svgIcon" viewBox="0 0 448 512"><path d="M135.2 17.7L128 32H32C14.3 32 0 46.3 0 64S14.3 96 32 96H416c17.7 0 32-14.3 32-32s-14.3-32-32-32H320l-7.2-14.3C307.4 6.8 296.3 0 284.2 0H163.8c-12.1 0-23.2 6.8-28.6 17.7zM416 128H32L53.2 467c1.6 25.3 22.6 45 47.9 45H346.9c25.3 0 46.3-19.7 47.9-45L416 128z"/></svg>' +
        "</button></span>";
      ul.appendChild(li);
    });
    bindDrag(ul);
  }

  function bindDrag(ul) {
    ul.querySelectorAll(".ime-item").forEach((li) => {
      li.addEventListener("dragstart", () => {
        dragSrc = li;
        li.classList.add("dragging");
      });
      li.addEventListener("dragend", () => {
        li.classList.remove("dragging");
        ul.querySelectorAll(".ime-item").forEach((x) => x.classList.remove("drag-over"));
        dragSrc = null;
      });
      li.addEventListener("dragover", (e) => {
        e.preventDefault();
        li.classList.add("drag-over");
      });
      li.addEventListener("dragleave", () => li.classList.remove("drag-over"));
      li.addEventListener("drop", (e) => {
        e.preventDefault();
        if (!dragSrc || dragSrc === li) return;
        const items = Array.from(ul.querySelectorAll(".ime-item:not(.off)"));
        const from = items.indexOf(dragSrc);
        const to = items.indexOf(li);
        if (from < 0 || to < 0) return;
        const tips = state.enabled.map((x) => x.tip);
        const [moved] = tips.splice(from, 1);
        tips.splice(to, 0, moved);
        applyOrder(tips);
      });
    });
  }

  function renderInstalled() {
    const ul = $("installedList");
    $("installedCount").textContent = "共 " + state.installed.length + " 个";
    if (!state.installed.length) {
      ul.innerHTML = '<li class="empty">未检测到输入法</li>';
      return;
    }
    ul.innerHTML = "";
    state.installed.forEach((it) => {
      const li = document.createElement("li");
      li.className = "installed-item";
      const on = it.in_use;
      li.innerHTML =
        '<span class="name">' + esc(it.name) + "</span>" +
        '<span class="state ' + (on ? "on" : "off") + '">' + (on ? "启用中" : "未启用") + "</span>" +
        (on ? "" : '<button class="btn-add" data-act="enable" title="启用该输入法">' +
          '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><path d="M12 5v14M5 12h14"/></svg></button>');
      ul.appendChild(li);
    });
  }

  function renderDefault() {
    const def = state.enabled.find((x) => x.is_default);
    $("defaultBox").innerHTML = def
      ? '<div class="default-current">' + esc(def.name) + "</div>"
      : '<div class="default-current" style="color:var(--text-dim)">未设置</div>';
  }

  function renderLock() {
    const lk = state.lock || {};
    const badge = $("lockBadge");
    const txt = $("lockBadgeText");
    const aclOn = !!(lk.acl && (lk.acl.profile_locked || lk.acl.ctf_locked || lk.acl.subkeys_locked));
    if (lk.locked) {
      badge.className = "lock-badge locked";
      txt.textContent = "已锁定 · ACL固化+守护中";
      $("lockBtn").classList.add("hidden");
      $("unlockBtn").classList.remove("hidden");
      $("lockHint").textContent = "顺序已物理固化（注册表拒绝写入），后台守护兜底";
    } else if (aclOn) {
      badge.className = "lock-badge locked";
      txt.textContent = "ACL 已固化 · 守护未运行";
      $("lockBtn").classList.add("hidden");
      $("unlockBtn").classList.remove("hidden");
      $("lockHint").textContent = "顺序已物理锁定，不受程序退出影响";
    } else {
      badge.className = "lock-badge";
      txt.textContent = "未锁定";
      $("lockBtn").classList.remove("hidden");
      $("unlockBtn").classList.add("hidden");
      $("lockHint").textContent = "锁定后固化注册表 ACL，拒绝第三方改写顺序";
    }
    if (lk.diff && lk.diff.changed) {
      badge.className = "lock-badge tampered";
      txt.textContent = "检测到篡改，已恢复";
    }
    const logBox = $("watchdogLog");
    if (lk.log && lk.log.length) {
      logBox.innerHTML = lk.log.map((l) =>
        '<div' + (l.indexOf("篡改") >= 0 ? ' class="warn"' : "") + ">" + esc(l) + "</div>").join("");
    } else {
      logBox.innerHTML = '<div style="color:var(--text-dim)">暂无守护记录</div>';
    }
  }

  function renderAll() {
    renderEnabled();
    renderInstalled();
    renderDefault();
    renderLock();
  }

  // ---------------- 数据 ----------------
  async function loadAll() {
    const r = await eel.get_all()();
    if (!r.ok) { toast(r.message || "加载失败", "err"); return; }
    state.enabled = r.enabled;
    state.installed = r.installed;
    state.disabled = r.disabled || [];
    state.lock = r.lock;
    renderAll();
  }

  async function applyOrder(tips) {
    const r = await eel.apply_order(tips)();
    if (r.ok) { toast("顺序已更新"); await loadAll(); }
    else toast(r.message || "应用顺序失败", "err");
  }

  // ---------------- 事件 ----------------
  $("imeList").addEventListener("click", (e) => {
    const btn = e.target.closest("[data-act]");
    if (!btn) return;
    const li = btn.closest(".ime-item");
    const tip = li.dataset.tip;
    if (btn.dataset.act === "default") {
      eel.set_default(tip)().then((r) => {
        if (r.ok) { toast(r.message); loadAll(); }
        else toast(r.message, "err");
      });
    } else if (btn.dataset.act === "remove") {
      if (li.classList.contains("off")) {
        // 停用项：彻底从列表移除（清停用记录）
        eel.remove_disabled(tip)().then((r) => {
          if (r.ok) { toast(r.message); loadAll(); }
          else toast(r.message, "err");
        });
      } else {
        const it = state.enabled.find((x) => x.tip === tip);
        confirmModal("移除输入法", "将「" + it.name + "」从启用列表移除？\n（不会卸载程序，可随时重新启用）", () => {
          eel.remove_ime(tip)().then((r) => {
            if (r.ok) { toast(r.message); loadAll(); }
            else toast(r.message, "err");
          });
        });
      }
    }
  });

  $("imeList").addEventListener("change", (e) => {
    const sw = e.target.closest("[data-act=toggle-ime]");
    if (!sw) return;
    const li = sw.closest(".ime-item");
    const tip = li.dataset.tip;
    const turningOff = !sw.checked;
    // 关闭开关：立即暗化反馈；打开开关：立即提亮反馈
    if (turningOff) {
      li.classList.add("off");
      const order = li.querySelector(".ime-order");
      if (order) order.textContent = "–";
    } else {
      li.classList.remove("off");
    }
    eel.toggle_ime(tip)().then((r) => {
      if (r.ok) { toast(r.message); }
      else toast(r.message, "err");
      loadAll(); // 以真实状态刷新还原
    });
  });

  $("installedList").addEventListener("click", (e) => {
    const btn = e.target.closest("[data-act]");
    if (!btn) return;
    const li = btn.closest(".installed-item");
    const name = li.querySelector(".name").textContent;
    const it = state.installed.find((x) => x.name === name);
    if (btn.dataset.act === "enable" && it) {
      eel.enable_ime(it.clsid, it.profile || "", "0x00000804")().then((r) => {
        if (r.ok) { toast(r.message); loadAll(); }
        else toast(r.message, "err");
      });
    }
  });

  $("lockBtn").addEventListener("click", () => {
    const btn = $("lockBtn");
    btn.classList.remove("locking");
    void btn.offsetWidth; // 重新触发动画
    btn.classList.add("locking");
    eel.lock()().then((r) => {
      if (r.ok) { toast("顺序已锁定：ACL 固化 + 守护"); loadAll(); }
      else { toast(r.message, "err"); btn.classList.remove("locking"); }
    });
  });

  $("unlockBtn").addEventListener("click", () => {
    confirmModal("解除锁定", "将移除注册表 ACL 固化并停止守护。\n此后输入法更新、其他程序均可自由修改顺序。", () => {
      const btn = $("unlockBtn");
      btn.classList.remove("unlocking");
      void btn.offsetWidth;
      btn.classList.add("unlocking");
      eel.unlock()().then((r) => {
        if (r.ok) { toast(r.message); loadAll(); }
        else { toast(r.message, "err"); btn.classList.remove("unlocking"); }
      });
    });
  });

  $("modalCancel").addEventListener("click", () => {
    $("modalMask").classList.add("hidden");
    pendingAction = null;
  });
  $("modalOk").addEventListener("click", () => {
    const fn = pendingAction;
    $("modalMask").classList.add("hidden");
    pendingAction = null;
    if (fn) fn();
  });
  $("modalMask").addEventListener("click", (e) => {
    if (e.target === $("modalMask")) { $("modalMask").classList.add("hidden"); pendingAction = null; }
  });

  // ---------------- 等比缩放（以 1080x760 为设计基准） ----------------
  const DESIGN_W = 1080;
  const DESIGN_H = 760;
  function fitScale() {
    const scale = Math.max(0.5, Math.min(window.innerWidth / DESIGN_W, window.innerHeight / DESIGN_H));
    document.body.style.zoom = scale.toFixed(4);
    // body 最小高度撑满视口（flex 布局吸收空隙），放大不留底
    document.body.style.minHeight = Math.round(window.innerHeight / scale) + "px";
    // fixed 层反向缩放，保证弹窗/toast 始终铺满或贴合视口
    const inv = (1 / scale).toFixed(4);
    const mask = $("modalMask");
    const toastEl = $("toast");
    if (mask) mask.style.zoom = inv;
    if (toastEl) toastEl.style.zoom = inv;
  }
  window.addEventListener("resize", fitScale);

  // ---------------- 启动 ----------------
  fitScale();
  loadAll();
  setInterval(loadAll, 10000);
})();
