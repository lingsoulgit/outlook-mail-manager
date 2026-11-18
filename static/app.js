(() => {
    "use strict";

    const csrfToken = () => document.querySelector('meta[name="csrf-token"]')?.content || "";

    function toast(message, type = "") {
        let root = document.getElementById("toast-root");
        if (!root) {
            root = document.createElement("div");
            root.id = "toast-root";
            document.body.appendChild(root);
        }
        const item = document.createElement("div");
        item.className = `toast ${type}`;
        item.textContent = message;
        root.appendChild(item);
        setTimeout(() => item.remove(), 5000);
    }

    async function request(url, options = {}) {
        const headers = new Headers(options.headers || {});
        if ((options.method || "GET").toUpperCase() !== "GET") {
            headers.set("X-CSRF-Token", csrfToken());
        }
        const response = await fetch(url, {...options, headers});
        const contentType = response.headers.get("content-type") || "";
        const body = contentType.includes("application/json") ? await response.json() : null;
        if (!response.ok) {
            throw new Error(body?.error || body?.detail || `HTTP ${response.status}`);
        }
        return body;
    }

    async function copyText(value) {
        try {
            if (navigator.clipboard?.writeText) {
                await navigator.clipboard.writeText(value);
                return true;
            }
        } catch (_error) {
            // Fall back for browsers that deny the asynchronous clipboard API.
        }

        const textarea = document.createElement("textarea");
        textarea.value = value;
        textarea.setAttribute("readonly", "");
        textarea.style.position = "fixed";
        textarea.style.opacity = "0";
        textarea.style.pointerEvents = "none";
        document.body.appendChild(textarea);
        textarea.select();
        try {
            return document.execCommand("copy");
        } catch (_error) {
            return false;
        } finally {
            textarea.remove();
        }
    }

    function initDefaultMicrosoftFetchMode() {
        const inputs = [...document.querySelectorAll('input[name="default_ms_fetch_mode"]')];
        if (!inputs.length) return;
        let savedValue = inputs.find((input) => input.checked)?.value || "graph";
        inputs.forEach((input) => input.addEventListener("change", async () => {
            if (!input.checked || input.value === savedValue) return;
            inputs.forEach((item) => {
                item.disabled = true;
            });
            try {
                await request("/api/settings/default-ms-fetch-mode", {
                    method: "POST",
                    headers: {"Content-Type": "application/json"},
                    body: JSON.stringify({fetch_mode: input.value}),
                });
                savedValue = input.value;
                toast(`新账号默认取件方式已切换为 ${input.value.toUpperCase()}`, "ok");
            } catch (error) {
                const previous = inputs.find((item) => item.value === savedValue);
                if (previous) previous.checked = true;
                toast(`保存默认取件方式失败：${error.message}`, "err");
            } finally {
                inputs.forEach((item) => {
                    item.disabled = false;
                });
            }
        }));
    }

    function initMicrosoftOAuth() {
        const root = document.getElementById("microsoft-oauth");
        if (!root) return;

        const clientIdInput = document.getElementById("microsoft-client-id");
        const startButton = document.getElementById("microsoft-oauth-start");
        const panel = document.getElementById("microsoft-oauth-panel");
        const code = document.getElementById("microsoft-oauth-code");
        const link = document.getElementById("microsoft-oauth-link");
        const status = document.getElementById("microsoft-oauth-status");
        let activeFlow = 0;

        const copyLoginCode = async () => {
            const value = code.textContent.trim();
            if (!value) return false;
            const copied = await copyText(value);
            if (copied) {
                toast("登录代码已复制，请在 Microsoft 页面按 Ctrl+V 粘贴", "ok");
            } else {
                toast("浏览器未允许复制，请手动选中登录代码", "err");
            }
            return copied;
        };

        code.addEventListener("click", copyLoginCode);
        code.addEventListener("keydown", (event) => {
            if (event.key !== "Enter" && event.key !== " ") return;
            event.preventDefault();
            copyLoginCode();
        });

        const schedulePoll = (flowId, retryAfter, generation) => {
            const delay = Math.max(1, Number(retryAfter) || 5) * 1000;
            setTimeout(async () => {
                if (generation !== activeFlow) return;
                try {
                    const data = await request("/api/oauth/microsoft/device/poll", {
                        method: "POST",
                        headers: {"Content-Type": "application/json"},
                        body: JSON.stringify({flow_id: flowId}),
                    });
                    if (generation !== activeFlow) return;
                    if (data.status === "pending") {
                        status.textContent = data.message || "等待你在 Microsoft 页面完成授权...";
                        schedulePoll(flowId, data.retry_after, generation);
                        return;
                    }
                    status.textContent = `${data.email} 已${data.outcome === "added" ? "添加" : "更新"}，即将返回账号总览...`;
                    startButton.textContent = "授权完成";
                    toast(`Microsoft 账号 ${data.email} 已保存`, "ok");
                    setTimeout(() => {
                        location.href = "/";
                    }, 1200);
                } catch (error) {
                    if (generation !== activeFlow) return;
                    status.textContent = `授权失败：${error.message}`;
                    startButton.disabled = false;
                    startButton.textContent = "重新使用 Microsoft 登录";
                    toast(`Microsoft 登录失败：${error.message}`, "err");
                }
            }, delay);
        };

        startButton.addEventListener("click", async () => {
            const clientId = clientIdInput.value.trim();
            if (!clientId) {
                toast("请先填写 Microsoft client_id", "err");
                clientIdInput.focus();
                return;
            }

            activeFlow += 1;
            const generation = activeFlow;
            startButton.disabled = true;
            startButton.textContent = "正在连接 Microsoft...";
            panel.hidden = true;
            status.textContent = "等待授权...";
            const popup = window.open("about:blank", "_blank");
            if (popup) popup.opener = null;

            try {
                const data = await request("/api/oauth/microsoft/device/start", {
                    method: "POST",
                    headers: {"Content-Type": "application/json"},
                    body: JSON.stringify({client_id: clientId}),
                });
                if (generation !== activeFlow) return;
                code.textContent = data.user_code;
                link.href = data.verification_uri;
                panel.hidden = false;
                const copied = await copyText(data.user_code);
                if (generation !== activeFlow) return;
                status.textContent = copied
                    ? "登录代码已自动复制，请在 Microsoft 页面按 Ctrl+V 粘贴并完成授权..."
                    : "浏览器未允许自动复制，请点击上方登录代码复制后完成授权...";
                startButton.textContent = "等待 Microsoft 授权...";
                if (popup && !popup.closed) popup.location.replace(data.verification_uri);
                if (copied) toast("登录代码已自动复制", "ok");
                schedulePoll(data.flow_id, data.retry_after, generation);
            } catch (error) {
                if (popup && !popup.closed) popup.close();
                status.textContent = `连接失败：${error.message}`;
                panel.hidden = false;
                startButton.disabled = false;
                startButton.textContent = "使用 Microsoft 登录";
                toast(`Microsoft 登录失败：${error.message}`, "err");
            }
        });
    }

    async function fetchAccount(button) {
        const id = button.dataset.accountId;
        button.disabled = true;
        button.textContent = "取件中...";
        try {
            const data = await request(`/fetch/${id}`, {method: "POST"});
            if (data.partial) {
                toast(`取件部分完成：已保存 ${data.fetched} 封邮件；${data.error}`, "err");
            } else {
                toast(data.fetched > 0
                    ? `取件完成：新增 ${data.fetched} 封邮件`
                    : "取件完成：没有新邮件", "ok");
            }
            setTimeout(() => location.reload(), 800);
        } catch (error) {
            toast(`取件失败：${error.message}`, "err");
            button.disabled = false;
            button.textContent = "取件";
        }
    }

    async function fetchAll(button, healthCheck = false) {
        button.disabled = true;
        button.textContent = healthCheck ? "检测中..." : "批量取件中...";
        try {
            const data = await request(healthCheck ? "/check-all" : "/fetch-all", {method: "POST"});
            toast(healthCheck
                    ? `健康检测完成\n可用: ${data.success} 个，异常: ${data.failed} 个`
                    : `批量取件完成\n成功: ${data.success} 个，失败: ${data.failed} 个，新增: ${data.total_emails} 封`,
                data.failed > 0 ? "err" : "ok");
            setTimeout(() => location.reload(), 1200);
        } catch (error) {
            toast(`${healthCheck ? "检测" : "批量取件"}失败：${error.message}`, "err");
            button.disabled = false;
            button.textContent = healthCheck ? "🩺 一键检测" : "⚡ 全部取件";
        }
    }

    function initNotifications() {
        const toggle = document.getElementById("notification-toggle");
        const panel = document.getElementById("notification-panel");
        const overlay = document.getElementById("notification-overlay");
        const closeButton = document.getElementById("notification-close");
        const count = document.getElementById("notification-count");
        const list = document.getElementById("notification-list");
        const permissionButton = document.getElementById("notification-permission");
        const readAllButton = document.getElementById("notification-read-all");
        if (!toggle || !panel || !overlay || !list) return;

        let pollBusy = false;

        const accountUrl = (item) => `/account/${encodeURIComponent(item.account_id)}`;

        const formatTime = (value) => {
            const parsed = new Date(value);
            if (Number.isNaN(parsed.getTime())) return "刚刚";
            return parsed.toLocaleString("zh-CN", {
                month: "2-digit",
                day: "2-digit",
                hour: "2-digit",
                minute: "2-digit",
            });
        };

        const setPanelOpen = (open) => {
            panel.hidden = !open;
            overlay.hidden = !open;
            toggle.setAttribute("aria-expanded", String(open));
        };

        const updateCount = (value) => {
            const unread = Math.max(0, Number(value) || 0);
            count.textContent = unread > 99 ? "99+" : String(unread);
            count.hidden = unread === 0;
            if (readAllButton) readAllButton.disabled = unread === 0;
        };

        const markReadAndOpen = async (item) => {
            try {
                await request(`/api/notifications/${item.id}/read`, {method: "POST"});
            } catch (_error) {
                // Navigation is still useful if the read marker cannot be saved.
            }
            location.href = accountUrl(item);
        };

        const renderNotifications = (items) => {
            list.replaceChildren();
            if (!items.length) {
                const empty = document.createElement("div");
                empty.className = "notification-empty";
                empty.textContent = "暂时没有新邮件提醒";
                list.appendChild(empty);
                return;
            }

            for (const item of items) {
                const card = document.createElement("article");
                card.className = `notification-item${item.read_at ? "" : " unread"}`;

                const top = document.createElement("div");
                top.className = "notification-item-top";
                const account = document.createElement("div");
                account.className = "notification-account";
                account.textContent = item.account_email;
                account.title = item.account_email;
                const created = document.createElement("time");
                created.className = "notification-time";
                created.textContent = formatTime(item.created_at);
                top.append(account, created);

                const subject = document.createElement("div");
                subject.className = "notification-subject";
                subject.textContent = item.subject || "(无主题)";
                const sender = document.createElement("div");
                sender.className = "notification-sender";
                sender.textContent = item.sender ? `来自：${item.sender}` : "发件人未知";

                card.append(top, subject, sender);
                if (item.preview) {
                    const preview = document.createElement("p");
                    preview.className = "notification-preview";
                    preview.textContent = item.preview;
                    card.appendChild(preview);
                }

                const actions = document.createElement("div");
                actions.className = "notification-actions";
                const view = document.createElement("button");
                view.type = "button";
                view.className = "btn btn-sm";
                view.textContent = "查看邮件";
                view.addEventListener("click", () => markReadAndOpen(item));
                actions.append(view);
                card.appendChild(actions);
                list.appendChild(card);
            }
        };

        const showNewNotification = (item) => {
            const title = `${item.account_email} 收到新邮件`;
            const lines = [item.subject || "(无主题)", item.sender, item.preview].filter(Boolean);
            if ("Notification" in window && Notification.permission === "granted") {
                try {
                    const desktop = new Notification(title, {
                        body: lines.join("\n"),
                        tag: `mail-manager-${item.id}`,
                    });
                    desktop.onclick = () => {
                        desktop.close();
                        window.focus();
                        markReadAndOpen(item);
                    };
                    return;
                } catch (_error) {
                    // In-app notification remains available on insecure origins.
                }
            }
            toast(`${title}\n${lines.slice(0, 2).join("\n")}`, "ok");
        };

        const syncPermissionButton = () => {
            if (!permissionButton) return;
            if (!("Notification" in window) || Notification.permission === "granted") {
                permissionButton.hidden = true;
                return;
            }
            permissionButton.hidden = false;
            permissionButton.disabled = Notification.permission === "denied";
            permissionButton.textContent = Notification.permission === "denied"
                ? "浏览器已禁止桌面通知"
                : "启用浏览器桌面通知";
        };

        const poll = async () => {
            if (pollBusy) return;
            pollBusy = true;
            try {
                const data = await request("/api/notifications/poll", {method: "POST"});
                updateCount(data.unread_count);
                renderNotifications(data.notifications || []);
                (data.pending || []).forEach(showNewNotification);
            } catch (_error) {
                // Session expiry and temporary network errors are handled on the next poll.
            } finally {
                pollBusy = false;
            }
        };

        toggle.addEventListener("click", () => {
            const open = panel.hidden;
            setPanelOpen(open);
            if (open) poll();
        });
        closeButton?.addEventListener("click", () => setPanelOpen(false));
        overlay.addEventListener("click", () => setPanelOpen(false));
        document.addEventListener("keydown", (event) => {
            if (event.key === "Escape" && !panel.hidden) setPanelOpen(false);
        });
        permissionButton?.addEventListener("click", async () => {
            if (!("Notification" in window)) return;
            try {
                const permission = await Notification.requestPermission();
                syncPermissionButton();
                toast(permission === "granted" ? "浏览器桌面通知已启用" : "浏览器未允许桌面通知", permission === "granted" ? "ok" : "err");
            } catch (_error) {
                toast("当前访问地址不支持浏览器桌面通知", "err");
            }
        });
        readAllButton?.addEventListener("click", async () => {
            readAllButton.disabled = true;
            try {
                await request("/api/notifications/read-all", {method: "POST"});
                await poll();
            } catch (error) {
                toast(`标记已读失败：${error.message}`, "err");
                readAllButton.disabled = false;
            }
        });
        document.addEventListener("visibilitychange", () => {
            if (!document.hidden) poll();
        });

        syncPermissionButton();
        poll();
        setInterval(poll, 30_000);
    }

    async function setFetchMode(select) {
        const form = new FormData();
        form.append("fetch_mode", select.value);
        form.append("csrf_token", csrfToken());
        try {
            await request(`/account/${select.dataset.accountId}/prefs`, {method: "POST", body: form});
            select.dataset.previous = select.value;
            toast(`取件方式已切换为 ${select.value.toUpperCase()}`, "ok");
        } catch (error) {
            toast(`切换失败：${error.message}`, "err");
            select.value = select.dataset.previous;
        }
    }

    function submitExport(ids) {
        if (!ids.length) {
            toast("请先选择账号", "err");
            return;
        }
        const password = prompt("请输入当前管理员密码");
        if (!password) return;
        const form = document.createElement("form");
        form.method = "post";
        form.action = "/export";
        form.hidden = true;
        const fields = [["csrf_token", csrfToken()], ["current_password", password]];
        for (const id of ids) fields.push(["account_id", id]);
        for (const [name, value] of fields) {
            const input = document.createElement("input");
            input.name = name;
            input.value = value;
            form.appendChild(input);
        }
        document.body.appendChild(form);
        form.submit();
        setTimeout(() => form.remove(), 1000);
    }

    function initInbox() {
        const state = document.getElementById("inbox-state");
        const button = document.getElementById("load-more-btn");
        if (!state || !button) return;
        let page = Number(state.dataset.page);
        let loaded = Number(state.dataset.loaded);
        const accountId = state.dataset.accountId;
        const folder = state.dataset.folder;
        button.addEventListener("click", async () => {
            button.disabled = true;
            button.textContent = "加载中...";
            try {
                const data = await request(`/api/account/${accountId}/emails?folder=${encodeURIComponent(folder)}&page=${page + 1}`);
                const tbody = document.getElementById("mail-tbody");
                document.getElementById("empty-row")?.remove();
                for (const message of data.emails) {
                    const row = document.createElement("tr");
                    const from = document.createElement("td");
                    from.style.maxWidth = "260px";
                    from.style.overflow = "hidden";
                    from.style.textOverflow = "ellipsis";
                    from.style.whiteSpace = "nowrap";
                    from.textContent = (message.from || "").slice(0, 50);
                    const subject = document.createElement("td");
                    const link = document.createElement("a");
                    link.href = `/email/${message.id}`;
                    link.textContent = (message.subject || "").slice(0, 80) || "(无主题)";
                    subject.appendChild(link);
                    const date = document.createElement("td");
                    date.style.color = "var(--text-dim)";
                    date.style.whiteSpace = "nowrap";
                    date.textContent = message.date || "-";
                    const folderCell = document.createElement("td");
                    const badge = document.createElement("span");
                    badge.className = "badge";
                    badge.textContent = message.folder;
                    folderCell.appendChild(badge);
                    row.append(from, subject, date, folderCell);
                    tbody.appendChild(row);
                }
                page = data.page;
                loaded += data.emails.length;
                document.getElementById("page-info").textContent = `已加载 ${loaded} / ${data.total} 封`;
                if (page >= data.total_pages) {
                    button.remove();
                    return;
                }
            } catch (error) {
                toast(`加载失败：${error.message}`, "err");
            }
            button.disabled = false;
            button.textContent = "加载更多";
        });
    }

    let updateBusy = false;

    async function checkForUpdate(fresh = false) {
        const widget = document.getElementById("version-widget");
        if (!widget || updateBusy) return;
        const status = widget.querySelector(".version-status");
        const button = widget.querySelector(".version-update");
        widget.classList.add("is-current");
        status.textContent = "已是最新";
        // updateBusy = true;
        // try {
        //     const data = await request(`/api/update/status${fresh ? "?fresh=1" : ""}`);
        //     widget.classList.remove("failed");
        //     if (!data.update_available) {
        //         widget.classList.add("is-current");
        //         status.textContent = "已是最新";
        //         return;
        //     }
        //     widget.classList.add("has-update");
        //     status.textContent = `可更新至 v${data.latest_version}`;
        //     button.hidden = false;
        //     button.dataset.version = data.latest_version;
        // } catch (error) {
        //     widget.classList.add("failed");
        //     status.textContent = "检查失败 · 点击重试";
        //     widget.title = error.message;
        // } finally {
        //     updateBusy = false;
        // }
    }

    async function applyUpdate(button) {
        if (!confirm(`安装 v${button.dataset.version} 并重启服务？`)) return;
        button.disabled = true;
        button.textContent = "更新中...";
        try {
            await request("/api/update/apply", {
                method: "POST",
                headers: {"Content-Type": "application/json"},
                body: JSON.stringify({version: button.dataset.version}),
            });
            button.textContent = "正在重启...";
            toast("更新已安装，服务正在重启，页面将在几秒后刷新...", "ok");
            setTimeout(() => location.reload(), 5000);
        } catch (error) {
            toast(`更新失败：${error.message}`, "err");
            button.disabled = false;
            button.textContent = "⬆ 安装新版本";
        }
    }

    function initAccountMoreMenus() {
        const triggers = [...document.querySelectorAll(".js-account-more")];
        if (!triggers.length) return;

        const menuFor = (trigger) => document.getElementById(trigger.getAttribute("aria-controls"));
        const closeMenu = (trigger) => {
            const menu = menuFor(trigger);
            if (menu) menu.hidden = true;
            trigger.setAttribute("aria-expanded", "false");
        };
        const closeAll = (except = null) => {
            triggers.forEach((trigger) => {
                if (trigger !== except) closeMenu(trigger);
            });
        };
        const positionMenu = (trigger, menu) => {
            const triggerRect = trigger.getBoundingClientRect();
            const menuWidth = menu.offsetWidth;
            const menuHeight = menu.offsetHeight;
            const edge = 8;
            let left = triggerRect.right - menuWidth;
            let top = triggerRect.bottom + 6;
            if (top + menuHeight > window.innerHeight - edge) {
                top = triggerRect.top - menuHeight - 6;
            }
            left = Math.min(Math.max(edge, left), window.innerWidth - menuWidth - edge);
            top = Math.max(edge, top);
            menu.style.left = `${left}px`;
            menu.style.top = `${top}px`;
        };

        triggers.forEach((trigger) => {
            trigger.addEventListener("click", () => {
                const menu = menuFor(trigger);
                if (!menu) return;
                const shouldOpen = menu.hidden;
                closeAll(trigger);
                if (!shouldOpen) {
                    closeMenu(trigger);
                    return;
                }
                menu.hidden = false;
                trigger.setAttribute("aria-expanded", "true");
                positionMenu(trigger, menu);
                menu.querySelector('[role="menuitem"]')?.focus();
            });
        });

        document.addEventListener("click", (event) => {
            if (!event.target.closest(".account-more")) closeAll();
        });
        document.addEventListener("keydown", (event) => {
            if (event.key !== "Escape") return;
            const active = triggers.find((trigger) => trigger.getAttribute("aria-expanded") === "true");
            if (!active) return;
            closeMenu(active);
            active.focus();
        });
        window.addEventListener("resize", () => closeAll());
        document.addEventListener("scroll", () => closeAll(), true);
    }

    function initStatFilters() {
        const form = document.querySelector(".filter-bar");
        const statusSelect = form?.querySelector('select[name="status"]');
        const buttons = [...document.querySelectorAll(".js-stat-filter")];
        if (!form || !statusSelect || !buttons.length) return;

        buttons.forEach((button) => {
            button.addEventListener("click", () => {
                const nextStatus = button.dataset.status || "";
                if (statusSelect.value === nextStatus) return;
                statusSelect.value = nextStatus;
                buttons.forEach((item) => {
                    item.setAttribute("aria-pressed", String((item.dataset.status || "") === nextStatus));
                });
                if (typeof form.requestSubmit === "function") form.requestSubmit();
                else form.submit();
            });
        });
    }

    document.addEventListener("DOMContentLoaded", () => {
        const proxyModeInputs = document.querySelectorAll('input[name="global_proxy_mode"]');
        const manualProxyFields = document.getElementById("manual-proxy-fields");
        const manualProxyInput = document.getElementById("global-proxy");
        const syncProxyMode = () => {
            const selected = document.querySelector('input[name="global_proxy_mode"]:checked')?.value;
            const manual = selected === "manual";
            if (manualProxyFields) manualProxyFields.hidden = !manual;
            if (manualProxyInput) manualProxyInput.required = manual;
        };
        proxyModeInputs.forEach((input) => input.addEventListener("change", syncProxyMode));
        syncProxyMode();
        initDefaultMicrosoftFetchMode();
        initStatFilters();
        initAccountMoreMenus();
        document.querySelectorAll(".js-fetch-account").forEach((button) =>
            button.addEventListener("click", () => fetchAccount(button)));
        document.getElementById("fetch-all-btn")?.addEventListener("click", (event) => fetchAll(event.currentTarget));
        document.getElementById("check-all-btn")?.addEventListener("click", (event) => fetchAll(event.currentTarget, true));
        document.querySelectorAll(".js-fetch-mode").forEach((select) =>
            select.addEventListener("change", () => setFetchMode(select)));
        document.querySelectorAll(".js-auto-submit").forEach((select) =>
            select.addEventListener("change", () => select.form.submit()));
        document.querySelectorAll("form[data-confirm]").forEach((form) =>
            form.addEventListener("submit", (event) => {
                if (!confirm(form.dataset.confirm)) event.preventDefault();
            }));
        document.getElementById("select-all")?.addEventListener("change", (event) => {
            document.querySelectorAll(".account-check").forEach((box) => {
                box.checked = event.currentTarget.checked;
            });
        });
        document.getElementById("export-selected")?.addEventListener("click", () => {
            const ids = [...document.querySelectorAll(".account-check:checked")].map((box) => box.value);
            submitExport(ids);
        });
        document.getElementById("export-all")?.addEventListener("click", () => {
            submitExport(["all"]);
        });
        document.getElementById("version-widget")?.addEventListener("click", () => checkForUpdate(true));
        document.querySelector(".version-update")?.addEventListener("click", (event) => {
            event.stopPropagation();
            applyUpdate(event.currentTarget);
        });
        initMicrosoftOAuth();
        initNotifications();
        initInbox();
        checkForUpdate();
    });
})();
