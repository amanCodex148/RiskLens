/**
 * RiskLens Frontend Application Controller - Theme Toggle (AMOLED Black <-> Clean Light)
 * Handles live telemetry rendering, Chart.js visualizations, currency toggling,
 * investment optimization, What-If simulation, compliance radar, and AI Copilot.
 */

const USD_INR_RATE = 84.0;
let currentCurrency = "INR"; // "INR" or "USD"
let currentTheme = localStorage.getItem("risklens_theme") || "dark"; // "dark" or "light"
let currentActiveTab = "boardroom";

// Authentication state
let currentUser = null;
let authToken = localStorage.getItem("risklens_auth_token") || sessionStorage.getItem("risklens_auth_token") || null;

// Dynamic VaR state (data-driven & user-selectable)
let currentVaRMode = "auto"; // "auto" or "manual"
let activeVaRConfidence = 0.95; // 0.90, 0.95, 0.99, etc.
let currentCurvePoints = [];

// HTML Entity Sanitizer to prevent DOM-based XSS
function escapeHtml(str) {
    if (str === null || str === undefined) return "";
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

// Global Non-Intrusive Floating Toast Notification System
function showToast(message, type = "info", duration = 3500) {
    let container = document.getElementById("toast-container");
    if (!container) {
        container = document.createElement("div");
        container.id = "toast-container";
        container.className = "fixed bottom-5 right-5 z-[9999] flex flex-col space-y-2 pointer-events-none max-w-sm w-full px-4";
        document.body.appendChild(container);
    }

    const toast = document.createElement("div");
    const bgStyles = type === "success"
        ? "bg-[#06150e]/95 text-emerald-300 border-emerald-500/40 shadow-emerald-950/40"
        : type === "error"
        ? "bg-[#16080b]/95 text-rose-300 border-rose-500/40 shadow-rose-950/40"
        : type === "warning"
        ? "bg-[#181106]/95 text-amber-300 border-amber-500/40 shadow-amber-950/40"
        : "bg-[#0b0c14]/95 text-indigo-300 border-indigo-500/40 shadow-indigo-950/40";

    toast.className = `pointer-events-auto p-3.5 rounded-xl shadow-2xl border text-xs flex items-center justify-between space-x-2 transition-all duration-300 transform translate-y-3 opacity-0 backdrop-blur-md ${bgStyles}`;

    const iconName = type === "success" ? "check-circle" : type === "error" ? "alert-circle" : type === "warning" ? "alert-triangle" : "info";

    toast.innerHTML = `
        <div class="flex items-center space-x-2.5">
            <i data-lucide="${iconName}" class="w-4 h-4 flex-shrink-0"></i>
            <span class="font-medium leading-snug">${escapeHtml(message)}</span>
        </div>
        <button class="text-zinc-400 hover:text-white p-0.5 rounded transition flex-shrink-0" onclick="this.closest('.toast-item')?.remove() || this.parentElement.remove()" title="Dismiss">
            <i data-lucide="x" class="w-3.5 h-3.5"></i>
        </button>
    `;
    toast.classList.add("toast-item");

    container.appendChild(toast);
    if (window.lucide) lucide.createIcons();

    requestAnimationFrame(() => {
        toast.classList.remove("translate-y-3", "opacity-0");
        toast.classList.add("translate-y-0", "opacity-100");
    });

    setTimeout(() => {
        toast.classList.remove("translate-y-0", "opacity-100");
        toast.classList.add("translate-y-3", "opacity-0");
        setTimeout(() => toast.remove(), 350);
    }, duration);
}

// Global data stores
let riskSummaryData = null;
let lossBreakdownData = null;
let assetInventoryData = [];
let availableScenarios = [];
let activeScenarioId = "SCEN-MFA-ALL";
let optimizerLoaded = false;
let complianceLoaded = false;

// Chart instances
let lossExceedanceChart = null;
let buDistributionChart = null;
let lossBreakdownChart = null;
let efficientFrontierChart = null;
let complianceRadarChart = null;
let epssCvssChart = null;

// Dynamic Chart Colors depending on Active Theme
function getChartThemeColors() {
    const isLight = (currentTheme === "light");
    return {
        gridColor: isLight ? "rgba(0, 0, 0, 0.07)" : "rgba(255, 255, 255, 0.06)",
        tickColor: isLight ? "#475569" : "#a1a1aa",
        radarGrid: isLight ? "rgba(0, 0, 0, 0.09)" : "rgba(255, 255, 255, 0.08)",
        radarPointLabel: isLight ? "#334155" : "#e4e4e7",
        doughnutBorder: isLight ? "#ffffff" : "#000000",
        tooltipBg: isLight ? "#1e293b" : "#09090b",
        tooltipBorder: isLight ? "#cbd5e1" : "#27272a",
        tooltipTitle: "#ffffff",
        tooltipBody: isLight ? "#f8fafc" : "#e4e4e7"
    };
}

// Theme Application & Toggle
function applyTheme(theme, redrawCharts = true) {
    currentTheme = theme;
    localStorage.setItem("risklens_theme", theme);

    const body = document.body;
    const icon = document.getElementById("theme-toggle-icon");
    const btn = document.getElementById("theme-toggle-btn");

    const loginIcon = document.getElementById("login-theme-toggle-icon");
    const loginBtn = document.getElementById("login-theme-toggle-btn");

    if (theme === "light") {
        body.classList.add("light-theme");
        if (icon) {
            icon.setAttribute("data-lucide", "moon");
            icon.className = "w-4 h-4 text-indigo-600";
        }
        if (btn) btn.title = "Switch to Dark AMOLED Theme";

        if (loginIcon) {
            loginIcon.setAttribute("data-lucide", "moon");
            loginIcon.className = "w-4 h-4 text-indigo-600";
        }
        if (loginBtn) loginBtn.title = "Switch to Dark AMOLED Theme";
    } else {
        body.classList.remove("light-theme");
        if (icon) {
            icon.setAttribute("data-lucide", "sun");
            icon.className = "w-4 h-4 text-amber-400";
        }
        if (btn) btn.title = "Switch to Clean Light Theme";

        if (loginIcon) {
            loginIcon.setAttribute("data-lucide", "sun");
            loginIcon.className = "w-4 h-4 text-amber-400";
        }
        if (loginBtn) loginBtn.title = "Switch to Clean Light Theme";
    }

    if (window.lucide) lucide.createIcons();

    if (redrawCharts && currentUser) {
        if (lossExceedanceChart) { lossExceedanceChart.destroy(); lossExceedanceChart = null; }
        if (buDistributionChart) { buDistributionChart.destroy(); buDistributionChart = null; }
        if (lossBreakdownChart) { lossBreakdownChart.destroy(); lossBreakdownChart = null; }
        if (efficientFrontierChart) { efficientFrontierChart.destroy(); efficientFrontierChart = null; }
        if (complianceRadarChart) { complianceRadarChart.destroy(); complianceRadarChart = null; }
        if (epssCvssChart) { epssCvssChart.destroy(); epssCvssChart = null; }

        if (riskSummaryData) renderExecutiveDashboard(riskSummaryData);
        if (lossBreakdownData && riskSummaryData) renderBreakdownCharts(riskSummaryData, lossBreakdownData);
        const sliderEl = document.getElementById("budget-slider");
        if (sliderEl) fetchOptimization(parseFloat(sliderEl.value));
        if (assetInventoryData && assetInventoryData.length > 0) renderEpssCvssScatter(assetInventoryData);
        if (document.getElementById("complianceRadarChart") && !document.getElementById("tab-compliance").classList.contains("hidden")) {
            loadCompliance();
        }
    }
}

function toggleTheme() {
    const nextTheme = (currentTheme === "dark") ? "light" : "dark";
    applyTheme(nextTheme, true);
}

// Currency Formatter
function formatMoney(amountInr, forceCurrency = null) {
    const currency = forceCurrency || currentCurrency;
    if (amountInr === undefined || amountInr === null || isNaN(amountInr)) return "--";

    if (currency === "INR") {
        const absVal = Math.abs(amountInr);
        const sign = amountInr < 0 ? "-" : "";
        if (absVal >= 10000000) {
            return `${sign}₹ ${(absVal / 10000000).toFixed(2)} Cr`;
        } else if (absVal >= 100000) {
            return `${sign}₹ ${(absVal / 100000).toFixed(2)} Lakh`;
        } else {
            return `${sign}₹ ${Math.round(absVal).toLocaleString("en-IN")}`;
        }
    } else {
        const valUsd = amountInr / USD_INR_RATE;
        const absUsd = Math.abs(valUsd);
        const sign = valUsd < 0 ? "-" : "";
        if (absUsd >= 1000000) {
            return `${sign}$ ${(absUsd / 1000000).toFixed(2)} M`;
        } else if (absUsd >= 1000) {
            return `${sign}$ ${(absUsd / 1000).toFixed(1)} k`;
        } else {
            return `${sign}$ ${Math.round(absUsd).toLocaleString("en-US")}`;
        }
    }
}

// Currency Switcher
function setCurrency(curr) {
    currentCurrency = curr;
    const inrBtn = document.getElementById("currency-inr-btn");
    const usdBtn = document.getElementById("currency-usd-btn");

    if (curr === "INR") {
        inrBtn.className = "px-2.5 sm:px-3 py-1 text-xs font-semibold rounded-lg bg-indigo-600 text-white shadow-md transition-all";
        usdBtn.className = "px-2.5 sm:px-3 py-1 text-xs font-medium text-zinc-400 hover:text-white rounded-lg transition-all";
    } else {
        usdBtn.className = "px-2.5 sm:px-3 py-1 text-xs font-semibold rounded-lg bg-indigo-600 text-white shadow-md transition-all";
        inrBtn.className = "px-2.5 sm:px-3 py-1 text-xs font-medium text-zinc-400 hover:text-white rounded-lg transition-all";
    }

    // Update EAL card currency badge
    const ealCurrencyIcon = document.getElementById("kpi-eal-currency-icon");
    if (ealCurrencyIcon) ealCurrencyIcon.textContent = curr === "INR" ? "₹" : "$";

    // Update investment optimizer preset buttons
    const p1 = document.getElementById("opt-preset-1");
    const p2 = document.getElementById("opt-preset-2");
    const p3 = document.getElementById("opt-preset-3");
    const p4 = document.getElementById("opt-preset-4");
    if (p1 && p2 && p3 && p4) {
        if (curr === "INR") {
            p1.textContent = "₹25 Lakh";
            p2.textContent = "₹50 Lakh";
            p3.textContent = "₹1.00 Cr";
            p4.textContent = "₹2.00 Cr";
        } else {
            p1.textContent = "$30k";
            p2.textContent = "$60k";
            p3.textContent = "$120k";
            p4.textContent = "$240k";
        }
    }

    // Refresh all rendered numbers and charts
    if (riskSummaryData) renderExecutiveDashboard(riskSummaryData);
    const sliderVal = document.getElementById("budget-slider").value;
    updateSliderLabel(sliderVal);
    fetchOptimization(parseFloat(sliderVal));
    if (assetInventoryData.length > 0) renderAssetsTable(assetInventoryData);
}

// Tab Switching
function switchTab(tabName) {
    if (tabName === "copilot" || tabName === "ai") {
        openCopilotModal();
        return;
    }

    currentActiveTab = tabName;
    updateContextualTopicPills(tabName);

    document.querySelectorAll(".tab-content").forEach(el => el.classList.add("hidden"));
    document.querySelectorAll(".tab-btn").forEach(el => {
        el.classList.remove("active");
        el.classList.remove("text-white");
        el.classList.add("text-zinc-400");
    });

    const activeSection = document.getElementById(`tab-${tabName}`);
    if (activeSection) activeSection.classList.remove("hidden");

    const activeBtn = document.querySelector(`.tab-btn[data-tab="${tabName}"]`);
    if (activeBtn) {
        activeBtn.classList.add("active");
        activeBtn.classList.remove("text-zinc-400");
        activeBtn.classList.add("text-white");
    }

    // Re-render Lucide icons
    if (window.lucide) lucide.createIcons();

    // Trigger tab-specific fetches lazily or when charts need recreation
    if (tabName === "optimizer" && (!optimizerLoaded || !efficientFrontierChart)) {
        const sliderVal = document.getElementById("budget-slider")?.value || 10000000.0;
        fetchOptimization(parseFloat(sliderVal));
    }
    if (tabName === "compliance" && (!complianceLoaded || !complianceRadarChart)) loadCompliance();
    if (tabName === "assets" && assetInventoryData.length === 0) loadAssets();
    if (tabName === "scenarios" && availableScenarios.length === 0) loadScenarios();

    // Ensure all visible charts immediately resize to current device viewport
    requestAnimationFrame(() => {
        resizeAllVisibleCharts();
    });
}

function resizeAllVisibleCharts() {
    const allCharts = [lossExceedanceChart, buDistributionChart, lossBreakdownChart, efficientFrontierChart, complianceRadarChart, epssCvssChart];
    allCharts.forEach(chart => {
        if (chart && chart.ctx && chart.ctx.canvas && chart.ctx.canvas.offsetParent !== null) {
            chart.resize();
        }
    });
}

window.addEventListener("resize", () => {
    resizeAllVisibleCharts();
});

window.addEventListener("orientationchange", () => {
    setTimeout(resizeAllVisibleCharts, 150);
});

function refreshActiveTabViews() {
    const optTab = document.getElementById("tab-optimizer");
    if (optTab && !optTab.classList.contains("hidden")) {
        const sliderEl = document.getElementById("budget-slider");
        if (sliderEl) fetchOptimization(parseFloat(sliderEl.value));
    }
    const compTab = document.getElementById("tab-compliance");
    if (compTab && !compTab.classList.contains("hidden")) {
        loadCompliance();
    }
    const scenPanel = document.getElementById("scenario-results-panel");
    if (scenPanel) scenPanel.classList.add("hidden");
}

// ---------------- TAB 1: EXECUTIVE BOARDROOM ----------------
async function loadExecutiveDashboard() {
    try {
        const res = await fetch("/api/risk/summary");
        if (!res.ok) {
            const errData = await res.json().catch(() => ({}));
            showToast(errData.detail || "Failed to load executive risk summary", "error");
            return;
        }
        const sumRes = await res.json();
        riskSummaryData = sumRes;
        lossBreakdownData = {
            by_bu_inr: sumRes.loss_by_bu_inr,
            by_bu_usd: sumRes.loss_by_bu_usd,
            by_tier_inr: sumRes.loss_by_tier_inr,
            by_tier_usd: sumRes.loss_by_tier_usd,
            primary_losses_inr: sumRes.primary_loss_breakdown_inr,
            secondary_losses_inr: sumRes.secondary_loss_breakdown_inr
        };
        renderExecutiveDashboard(sumRes);
        renderBreakdownCharts(sumRes, lossBreakdownData);
    } catch (err) {
        console.error("Error loading executive dashboard:", err);
        showToast("Network error loading dashboard metrics", "error");
    }
}

function renderExecutiveDashboard(data) {
    // KPI Cards
    const scoreEl = document.getElementById("kpi-risk-score");
    const levelEl = document.getElementById("kpi-risk-level");
    scoreEl.innerText = data.enterprise_risk_score;

    if (data.enterprise_risk_score >= 80) {
        levelEl.innerText = "CRITICAL EXPOSURE";
        levelEl.className = "px-2 py-0.5 rounded-full badge-high font-medium text-[11px]";
    } else if (data.enterprise_risk_score >= 50) {
        levelEl.innerText = "ELEVATED RISK";
        levelEl.className = "px-2 py-0.5 rounded-full bg-amber-500/10 text-amber-300 font-medium text-[11px] border border-amber-500/40";
    } else {
        levelEl.innerText = "CONTROLLED";
        levelEl.className = "px-2 py-0.5 rounded-full badge-optimal font-medium text-[11px]";
    }

    document.getElementById("kpi-eal").innerText = formatMoney(data.expected_annual_loss_inr);
    document.getElementById("kpi-cvar95").innerText = formatMoney(data.cvar_95_inr);

    currentCurvePoints = data.loss_exceedance_curve || [];

    // Dynamically adapt VaR confidence level according to active data
    const recPercentile = data.recommended_var_percentile || 95;
    if (currentVaRMode === "auto") {
        activeVaRConfidence = recPercentile / 100.0;
    }

    const autoLabel = document.getElementById("var-auto-pct-label");
    if (autoLabel) {
        autoLabel.innerText = `(${recPercentile}%)`;
    }

    const dataVarTag = document.getElementById("lec-data-var-tag");
    if (dataVarTag) {
        dataVarTag.classList.remove("hidden");
        if (currentVaRMode === "auto") {
            dataVarTag.innerText = `⚡ Auto: ${recPercentile}% VaR - ${data.recommended_var_reason || 'Data Profile'}`;
        } else {
            dataVarTag.innerText = `Manual: ${Math.round(activeVaRConfidence * 100)}% VaR Selected`;
        }
    }

    updateVaRControlsUI(data);

    // Top Risk Drivers Table
    const tbody = document.getElementById("top-risk-assets-tbody");
    tbody.innerHTML = "";
    const totalEalVal = data.expected_annual_loss_inr || 1;
    const rankBadges = [
        "bg-rose-500/20 text-rose-300 border-rose-500/30",
        "bg-amber-500/20 text-amber-300 border-amber-500/30",
        "bg-yellow-500/20 text-yellow-300 border-yellow-500/30",
        "bg-zinc-800/80 text-zinc-400 border-zinc-700/60",
        "bg-zinc-800/80 text-zinc-400 border-zinc-700/60"
    ];

    data.top_risk_assets.forEach((asset, idx) => {
        const tr = document.createElement("tr");
        tr.className = "hover:bg-[#131316] transition border-b border-[#18181b]";
        const isTier1 = String(asset.criticality || '').includes('Tier 1');
        const isTier2 = String(asset.criticality || '').includes('Tier 2');
        const epssVal = Number(asset.max_epss || 0);
        const epssPct = (epssVal * 100).toFixed(1);
        const ealPct = ((asset.eal_inr / totalEalVal) * 100).toFixed(1);

        tr.innerHTML = `
            <td class="py-2.5 px-3">
                <span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${rankBadges[idx] || rankBadges[3]}">#${idx + 1}</span>
            </td>
            <td class="py-2.5 px-3">
                <div class="font-medium text-white">${escapeHtml(asset.asset_name)}</div>
                <div class="text-[10px] font-mono text-zinc-500">${escapeHtml(asset.asset_id)}</div>
            </td>
            <td class="py-2.5 px-3 text-zinc-400 whitespace-nowrap">${escapeHtml(asset.business_unit)}</td>
            <td class="py-2.5 px-3">
                <span class="px-2.5 py-0.5 rounded-full text-[10px] font-semibold whitespace-nowrap inline-flex items-center gap-1.5 shadow-sm ${
                    isTier1
                        ? 'badge-crown'
                        : isTier2
                            ? 'bg-sky-500/15 text-sky-300 border border-sky-500/30'
                            : 'bg-zinc-800/70 text-zinc-300 border border-zinc-700/60'
                }">
                    <span class="w-1.5 h-1.5 rounded-full ${isTier1 ? 'bg-amber-400' : isTier2 ? 'bg-sky-400' : 'bg-zinc-400'}"></span>
                    <span>${escapeHtml(asset.criticality)}</span>
                </span>
            </td>
            <td class="py-2.5 px-3">
                <div class="flex items-center space-x-1.5">
                    <span class="font-mono text-rose-400 font-semibold">${escapeHtml(asset.top_cve)}</span>
                    ${epssVal >= 0.85 ? '<span class="px-1.5 py-0.2 rounded text-[9px] bg-rose-500/20 text-rose-300 border border-rose-500/40 font-bold uppercase tracking-wider">KEV</span>' : ''}
                </div>
                <div class="text-[10px] text-zinc-400 mt-0.5 font-medium flex items-center gap-1.5">
                    <span class="inline-block w-1.5 h-1.5 rounded-full ${epssVal >= 0.5 ? 'bg-rose-500 animate-pulse' : 'bg-amber-400'}"></span>
                    <span>EPSS ${epssPct}% Likelihood</span>
                </div>
            </td>
            <td class="py-2.5 px-3 text-right">
                <div class="font-mono font-bold text-amber-300 text-xs">${formatMoney(asset.eal_inr)}</div>
                <div class="text-[10px] text-zinc-500 font-mono">${ealPct}% of EAL</div>
            </td>
        `;
        tbody.appendChild(tr);
    });

    // Render Loss Exceedance Curve
    renderLossExceedanceChart(data.loss_exceedance_curve);
}

function updateVaRControlsUI(data) {
    if (!data && riskSummaryData) data = riskSummaryData;
    if (!data) return;

    const confPct = Math.round(activeVaRConfidence * 100);

    // Update dynamic selector button highlights
    const btnAuto = document.getElementById("var-btn-auto");
    const btn90 = document.getElementById("var-btn-90");
    const btn95 = document.getElementById("var-btn-95");
    const btn99 = document.getElementById("var-btn-99");

    const activeBtnClass = "px-2.5 py-1 rounded-lg text-xs font-semibold bg-indigo-600 text-white shadow-sm transition";
    const inactiveBtnClass = "px-2 py-1 rounded-lg text-xs font-medium text-zinc-400 hover:text-white transition";

    if (btnAuto) btnAuto.className = (currentVaRMode === "auto") ? activeBtnClass : inactiveBtnClass;
    if (btn90) btn90.className = (currentVaRMode !== "auto" && confPct === 90) ? activeBtnClass : inactiveBtnClass;
    if (btn95) btn95.className = (currentVaRMode !== "auto" && confPct === 95) ? activeBtnClass : inactiveBtnClass;
    if (btn99) btn99.className = (currentVaRMode !== "auto" && confPct === 99) ? activeBtnClass : inactiveBtnClass;

    // Update KPI card quick buttons
    [90, 95, 99].forEach(p => {
        const kpiBtn = document.getElementById(`kpi-var-btn-${p}`);
        if (kpiBtn) {
            if (confPct === p) {
                kpiBtn.className = "px-1.5 py-0.5 rounded bg-cyan-500/20 text-cyan-300 font-bold border border-cyan-500/30 transition";
            } else {
                kpiBtn.className = "px-1.5 py-0.5 rounded hover:bg-zinc-800 text-zinc-400 font-normal transition";
            }
        }
    });

    // Update Top KPI Card figures dynamically according to active VaR confidence
    const kpiTitle = document.getElementById("kpi-var-title");
    const kpiVal = document.getElementById("kpi-var95");
    const kpiSub = document.getElementById("kpi-var-subtitle");
    const kpiBadge = document.getElementById("kpi-var-badge");

    let valInr = data.var_95_inr;
    if (confPct === 99) {
        valInr = data.var_99_inr;
    } else if (confPct === 90) {
        valInr = data.var_90_inr || (data.loss_exceedance_curve ? (data.loss_exceedance_curve.find(p => Math.abs(p.exceedance_probability - 0.10) < 0.01)?.loss_amount_inr || data.var_95_inr * 0.90) : data.var_95_inr * 0.90);
    } else if (confPct === 95) {
        valInr = data.var_95_inr;
    } else {
        const pt = (data.loss_exceedance_curve || []).find(p => Math.abs(p.exceedance_probability - (1.0 - activeVaRConfidence)) < 0.015);
        if (pt) valInr = pt.loss_amount_inr;
    }

    if (kpiTitle) kpiTitle.innerText = `${confPct}% Value at Risk (VaR)`;
    if (kpiVal) kpiVal.innerText = formatMoney(valInr);
    if (kpiSub) {
        if (confPct >= 99) {
            kpiSub.innerText = "Max annual loss at 99% confidence (1-in-100 yr tail risk)";
        } else if (confPct <= 90) {
            kpiSub.innerText = "Max annual loss at 90% confidence (1-in-10 yr operational)";
        } else {
            kpiSub.innerText = "Max annual loss at 95% confidence (1-in-20 yr standard)";
        }
    }
    if (kpiBadge) {
        kpiBadge.innerText = (currentVaRMode === "auto") ? `Auto (${confPct}%)` : `Manual (${confPct}%)`;
    }
}

function setVaRConfidence(conf) {
    if (conf === "auto") {
        currentVaRMode = "auto";
        const rec = (riskSummaryData && riskSummaryData.recommended_var_percentile) || 95;
        activeVaRConfidence = rec / 100.0;
        showToast(`Dynamic VaR set to Auto: ${rec}% based on active enterprise data profile`, "info");
    } else {
        currentVaRMode = "manual";
        activeVaRConfidence = parseFloat(conf);
        const pct = Math.round(activeVaRConfidence * 100);
        showToast(`VaR confidence level set to ${pct}%`, "info");
    }

    const dataVarTag = document.getElementById("lec-data-var-tag");
    if (dataVarTag && riskSummaryData) {
        dataVarTag.classList.remove("hidden");
        if (currentVaRMode === "auto") {
            const rec = riskSummaryData.recommended_var_percentile || 95;
            dataVarTag.innerText = `⚡ Auto: ${rec}% VaR - ${riskSummaryData.recommended_var_reason || 'Dataset Profile'}`;
        } else {
            dataVarTag.innerText = `Manual: ${Math.round(activeVaRConfidence * 100)}% VaR Selected`;
        }
    }

    if (riskSummaryData) {
        updateVaRControlsUI(riskSummaryData);
    }
    if (currentCurvePoints && currentCurvePoints.length > 0) {
        renderLossExceedanceChart(currentCurvePoints);
    }
}

function renderLossExceedanceChart(curvePoints) {
    if (!curvePoints || curvePoints.length === 0) return;
    currentCurvePoints = curvePoints;
    const canvas = document.getElementById("lossExceedanceChart");
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (lossExceedanceChart) {
        lossExceedanceChart.destroy();
        lossExceedanceChart = null;
    }

    const colors = getChartThemeColors();
    const isLight = (currentTheme === "light");

    const labels = curvePoints.map(p => `${(p.exceedance_probability * 100).toFixed(0)}%`);
    const values = curvePoints.map(p => currentCurrency === "INR" ? (p.loss_amount_inr / 10000000) : (p.loss_amount_usd / 1000000));
    const unitLabel = currentCurrency === "INR" ? "Loss in ₹ Crores" : "Loss in $ Millions";

    // Target exceedance probability for the active VaR confidence
    const targetExceedance = 1.0 - activeVaRConfidence;
    const targetLabel = `${Math.round(targetExceedance * 100)}%`;
    let varIdx = labels.indexOf(targetLabel);
    if (varIdx === -1) {
        let minDiff = Infinity;
        curvePoints.forEach((p, idx) => {
            const diff = Math.abs(p.exceedance_probability - targetExceedance);
            if (diff < minDiff) {
                minDiff = diff;
                varIdx = idx;
            }
        });
    }
    if (varIdx < 0 || varIdx >= curvePoints.length) varIdx = 1;

    const activePoint = curvePoints[varIdx] || curvePoints[1];
    const activeConfPct = Math.round((1.0 - activePoint.exceedance_probability) * 100);

    // Update dynamic VaR badge in card header
    const varEl = document.getElementById("lec-header-var");
    if (varEl && activePoint) {
        varEl.textContent = `${activeConfPct}% VaR: ${formatMoney(activePoint.loss_amount_inr)}`;
        if (activeConfPct >= 99) {
            varEl.className = "text-xs bg-rose-500/15 text-rose-300 px-2.5 py-1.5 rounded-xl border border-rose-500/30 font-mono font-bold tracking-tight shadow-sm";
        } else if (activeConfPct >= 95) {
            varEl.className = "text-xs bg-amber-500/15 text-amber-300 px-2.5 py-1.5 rounded-xl border border-amber-500/30 font-mono font-bold tracking-tight shadow-sm";
        } else {
            varEl.className = "text-xs bg-cyan-500/15 text-cyan-300 px-2.5 py-1.5 rounded-xl border border-cyan-500/30 font-mono font-bold tracking-tight shadow-sm";
        }
    }

    // Vertical gradient under curve
    let gradientFill = null;
    try {
        gradientFill = ctx.createLinearGradient(0, 0, 0, 220);
        gradientFill.addColorStop(0, isLight ? "rgba(99, 102, 241, 0.28)" : "rgba(99, 102, 241, 0.32)");
        gradientFill.addColorStop(1, "rgba(99, 102, 241, 0.01)");
    } catch (e) {
        gradientFill = "rgba(99, 102, 241, 0.12)";
    }

    // Custom annotation plugin for dynamic VaR drop-line & floating badge
    const lossExceedanceVaRPlugin = {
        id: "lossExceedanceVaRPlugin",
        afterDraw: (chart) => {
            const { ctx, chartArea } = chart;
            if (!chartArea) return;
            const { top, bottom, left, right } = chartArea;

            if (varIdx !== -1 && chart.getDatasetMeta(0).data[varIdx]) {
                const pt = chart.getDatasetMeta(0).data[varIdx];
                const x = pt.x;
                const y = pt.y;

                ctx.save();

                const lineColor = activeConfPct >= 99 ? "rgba(244, 63, 94, 0.85)" : (activeConfPct >= 95 ? "rgba(245, 158, 11, 0.85)" : "rgba(6, 182, 212, 0.85)");
                const ringColor = activeConfPct >= 99 ? "rgba(244, 63, 94, 0.5)" : (activeConfPct >= 95 ? "rgba(245, 158, 11, 0.5)" : "rgba(6, 182, 212, 0.5)");
                const textColor = activeConfPct >= 99 ? "#f43f5e" : (activeConfPct >= 95 ? "#f59e0b" : "#06b6d4");

                // Vertical dashed drop-line from dynamic VaR point down to X axis
                ctx.setLineDash([4, 4]);
                ctx.lineWidth = 1.35;
                ctx.strokeStyle = lineColor;
                ctx.beginPath();
                ctx.moveTo(x, y);
                ctx.lineTo(x, bottom);
                ctx.stroke();
                ctx.setLineDash([]);

                // Pulsing highlight ring around the active point
                ctx.beginPath();
                ctx.arc(x, y, 9.5, 0, 2 * Math.PI);
                ctx.strokeStyle = ringColor;
                ctx.lineWidth = 2.5;
                ctx.stroke();

                // Floating VaR badge above point
                const varVal = values[varIdx];
                const varText = `${activeConfPct}% VaR: ${currentCurrency === 'INR' ? '₹' + varVal.toFixed(1) + ' Cr' : '$' + varVal.toFixed(1) + ' M'}`;
                ctx.font = "bold 9.5px Inter, system-ui, sans-serif";
                const textW = ctx.measureText(varText).width;
                const badgeW = textW + 14;
                const badgeH = 19;
                const badgeX = Math.max(left + 6, Math.min(right - badgeW - 6, x - badgeW / 2));
                const badgeY = Math.max(top + 4, y - 28);

                ctx.fillStyle = isLight ? "#ffffff" : "#09090b";
                ctx.beginPath();
                ctx.roundRect(badgeX, badgeY, badgeW, badgeH, 5);
                ctx.fill();

                ctx.strokeStyle = lineColor;
                ctx.lineWidth = 1.25;
                ctx.stroke();

                ctx.fillStyle = textColor;
                ctx.textAlign = "center";
                ctx.textBaseline = "middle";
                ctx.fillText(varText, badgeX + badgeW / 2, badgeY + badgeH / 2);

                ctx.restore();
            }
        }
    };

    lossExceedanceChart = new Chart(ctx, {
        type: "line",
        data: {
            labels: labels,
            datasets: [{
                label: unitLabel,
                data: values,
                borderColor: "#6366f1",
                borderWidth: 2.5,
                backgroundColor: gradientFill,
                fill: true,
                tension: 0.35,
                pointRadius: (c) => (c.dataIndex === varIdx ? 7 : 4.5),
                pointBackgroundColor: (c) => (c.dataIndex === varIdx ? (activeConfPct >= 99 ? "#f43f5e" : (activeConfPct >= 95 ? "#f59e0b" : "#06b6d4")) : "#818cf8"),
                pointBorderColor: "#ffffff",
                pointBorderWidth: (c) => (c.dataIndex === varIdx ? 2.5 : 1.25),
                pointHoverRadius: (c) => (c.dataIndex === varIdx ? 9.5 : 7)
            }]
        },
        plugins: [lossExceedanceVaRPlugin],
        options: {
            responsive: true,
            maintainAspectRatio: false,
            layout: {
                padding: { left: 8, right: 14, top: 14, bottom: 6 }
            },
            onClick: (evt, elements) => {
                if (elements && elements.length > 0) {
                    const idx = elements[0].index;
                    if (curvePoints[idx]) {
                        const clickedConf = 1.0 - curvePoints[idx].exceedance_probability;
                        setVaRConfidence(clickedConf);
                    }
                }
            },
            animation: { duration: 300 },
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: colors.tooltipBg,
                    borderColor: "rgba(99, 102, 241, 0.4)",
                    borderWidth: 1.5,
                    padding: 12,
                    cornerRadius: 8,
                    titleColor: colors.tooltipTitle,
                    bodyColor: colors.tooltipBody,
                    titleFont: { size: 11, weight: "bold" },
                    bodyFont: { size: 11, lineHeight: 1.5 },
                    callbacks: {
                        title: (tooltipItems) => {
                            const lbl = tooltipItems[0].label;
                            const conf = (100 - parseInt(lbl)).toFixed(0);
                            return `Exceedance Likelihood: ${lbl} (${conf}% Confidence)`;
                        },
                        label: (ctx) => {
                            const val = ctx.raw;
                            const idx = ctx.dataIndex;
                            const lines = [
                                `Annual Loss Exceedance: ${currentCurrency === 'INR' ? '₹ ' + val.toFixed(2) + ' Cr' : '$ ' + val.toFixed(2) + ' M'}`
                            ];
                            if (idx === 0) {
                                lines.push("⚡ 99% Tail Risk (VaR 99% - 1-in-100 Year Worst-Case / Basel III)");
                            } else if (idx === 1) {
                                lines.push("🚨 95% Value at Risk (VaR 95% - 1-in-20 Year Enterprise Loss)");
                            } else if (idx === 2) {
                                lines.push("⚠️ 90% Value at Risk (VaR 90% - 1-in-10 Year Operational Loss)");
                            } else if (idx === 5) {
                                lines.push("📊 50% Median Expected Annual Loss");
                            }
                            return lines;
                        }
                    }
                }
            },
            scales: {
                x: {
                    offset: true,
                    title: {
                        display: true,
                        text: "Annual Exceedance Probability (Likelihood)",
                        color: colors.tickColor,
                        font: { size: 10, weight: "600" }
                    },
                    grid: { color: colors.gridColor },
                    ticks: { color: colors.tickColor, font: { size: 10 } }
                },
                y: {
                    title: {
                        display: true,
                        text: unitLabel,
                        color: colors.tickColor,
                        font: { size: 10, weight: "600" }
                    },
                    grid: { color: colors.gridColor },
                    ticks: {
                        color: colors.tickColor,
                        font: { size: 10 },
                        callback: (v) => currentCurrency === "INR" ? `₹${v} Cr` : `$${v} M`
                    }
                }
            }
        }
    });
}

function renderBreakdownCharts(summary, breakdown) {
    const colors = getChartThemeColors();
    const isLight = (currentTheme === "light");

    const BU_DISPLAY_NAMES = {
        "Retail Banking & Payments": "Retail Banking",
        "Cards & Wealth Management": "Cards & Wealth",
        "Corporate & Treasury": "Corp Treasury",
        "Cloud & Core Infrastructure": "Cloud Infra",
        "Enterprise Operations & HR": "Enterprise Ops"
    };

    const rawKeys = Object.keys(summary.loss_by_bu_inr);
    const buLabels = rawKeys.map(k => BU_DISPLAY_NAMES[k] || k.split(" ")[0]);
    const buValues = Object.values(summary.loss_by_bu_inr);
    const totalBuLoss = buValues.reduce((a, b) => a + b, 0);

    const buCanvas = document.getElementById("buDistributionChart");
    if (buCanvas) {
        if (buDistributionChart) {
            buDistributionChart.destroy();
            buDistributionChart = null;
        }

        const buCtx = buCanvas.getContext("2d");
        let hoveredSliceIdx = null;

        // Custom Center KPI Plugin for Doughnut
        const buCenterTextPlugin = {
            id: "buCenterTextPlugin",
            afterDraw: (chart) => {
                const { ctx, chartArea } = chart;
                if (!chartArea) return;
                const { left, right, top, bottom } = chartArea;
                const meta = chart.getDatasetMeta(0);
                const centerX = (meta && meta.data && meta.data[0]) ? meta.data[0].x : (left + right) / 2;
                const centerY = (meta && meta.data && meta.data[0]) ? meta.data[0].y : (top + bottom) / 2;

                ctx.save();
                ctx.textAlign = "center";
                ctx.textBaseline = "middle";

                if (hoveredSliceIdx !== null && buLabels[hoveredSliceIdx]) {
                    const label = buLabels[hoveredSliceIdx];
                    const val = buValues[hoveredSliceIdx];
                    const pct = totalBuLoss > 0 ? ((val / totalBuLoss) * 100).toFixed(1) : "0";
                    const color = chart.data.datasets[0].backgroundColor[hoveredSliceIdx];

                    ctx.font = "bold 9.5px Inter, system-ui, sans-serif";
                    ctx.fillStyle = color;
                    ctx.fillText(label.toUpperCase(), centerX, centerY - 15);

                    ctx.font = "bold 15px Inter, system-ui, sans-serif";
                    ctx.fillStyle = isLight ? "#0f172a" : "#ffffff";
                    ctx.fillText(formatMoney(val), centerX, centerY + 1);

                    ctx.font = "500 9.5px Inter, system-ui, sans-serif";
                    ctx.fillStyle = isLight ? "#64748b" : "#a1a1aa";
                    ctx.fillText(`${pct}% of Total Risk`, centerX, centerY + 17);
                } else {
                    ctx.font = "bold 9px Inter, system-ui, sans-serif";
                    ctx.fillStyle = isLight ? "#64748b" : "#a1a1aa";
                    ctx.fillText("TOTAL EXPOSURE", centerX, centerY - 15);

                    ctx.font = "bold 15px Inter, system-ui, sans-serif";
                    ctx.fillStyle = isLight ? "#0f172a" : "#ffffff";
                    ctx.fillText(formatMoney(totalBuLoss), centerX, centerY + 1);

                    ctx.font = "500 9.5px Inter, system-ui, sans-serif";
                    ctx.fillStyle = "#10b981";
                    ctx.fillText("5 Business Units", centerX, centerY + 17);
                }

                ctx.restore();
            }
        };

        buDistributionChart = new Chart(buCtx, {
            type: "doughnut",
            data: {
                labels: buLabels,
                datasets: [{
                    data: buValues,
                    backgroundColor: ["#3b82f6", "#06b6d4", "#8b5cf6", "#f59e0b", "#ec4899"],
                    borderWidth: 0,
                    spacing: 3,         // Modern gap between slices
                    borderRadius: 4,    // Rounded pill edges for segments
                    hoverOffset: 6
                }]
            },
            plugins: [buCenterTextPlugin],
            options: {
                responsive: true,
                maintainAspectRatio: false,
                layout: {
                    padding: { left: 4, right: 4, top: 4, bottom: 6 }
                },
                animation: { duration: 300 },
                onHover: (event, activeElements) => {
                    const newIdx = (activeElements && activeElements.length > 0) ? activeElements[0].index : null;
                    if (hoveredSliceIdx !== newIdx) {
                        hoveredSliceIdx = newIdx;
                        buDistributionChart.draw();
                    }
                },
                plugins: {
                    legend: {
                        position: "bottom",
                        labels: {
                            color: isLight ? "#475569" : "#e4e4e7",
                            boxWidth: 7,
                            boxHeight: 7,
                            usePointStyle: true,
                            pointStyle: "circle",
                            padding: 8,
                            font: { size: 9.5, weight: "500" },
                            generateLabels: (chart) => {
                                const data = chart.data;
                                return data.labels.map((label, i) => {
                                    const val = data.datasets[0].data[i];
                                    const pct = totalBuLoss > 0 ? ((val / totalBuLoss) * 100).toFixed(1) : "0";
                                    return {
                                        text: `${label} (${pct}%)`,
                                        fillStyle: data.datasets[0].backgroundColor[i],
                                        strokeStyle: data.datasets[0].backgroundColor[i],
                                        fontColor: isLight ? "#475569" : "#e4e4e7",
                                        pointStyle: "circle",
                                        hidden: false,
                                        index: i
                                    };
                                });
                            }
                        }
                    },
                    tooltip: {
                        enabled: false // Center cutout dynamically displays the division KPI without overlapping collisions
                    }
                },
                cutout: "72%"
            }
        });
    }

    const prim = breakdown.primary_losses_inr || summary.primary_loss_breakdown_inr || {};
    const sec = breakdown.secondary_losses_inr || summary.secondary_loss_breakdown_inr || {};
    const barValues = [
        prim.downtime_inr || 0,
        prim.incident_response_inr || 0,
        prim.system_recovery_inr || 0,
        sec.regulatory_penalties_inr || 0,
        sec.breach_liability_inr || 0,
        sec.reputational_churn_inr || 0
    ];

    const primSum = (prim.downtime_inr || 0) + (prim.incident_response_inr || 0) + (prim.system_recovery_inr || 0);
    const secSum = (sec.regulatory_penalties_inr || 0) + (sec.breach_liability_inr || 0) + (sec.reputational_churn_inr || 0);

    const primPill = document.getElementById("loss-primary-sum");
    if (primPill) primPill.textContent = `Primary: ${formatMoney(primSum)}`;
    const secPill = document.getElementById("loss-secondary-sum");
    if (secPill) secPill.textContent = `Secondary: ${formatMoney(secSum)}`;

    const breakdownCanvas = document.getElementById("lossBreakdownChart");
    if (breakdownCanvas) {
        if (lossBreakdownChart) {
            lossBreakdownChart.destroy();
            lossBreakdownChart = null;
        }

        const breakdownCtx = breakdownCanvas.getContext("2d");

        // Subtle gradient fills for primary & secondary bars
        const primaryBarGrad = breakdownCtx.createLinearGradient(0, 0, 0, 200);
        primaryBarGrad.addColorStop(0, "#3b82f6");
        primaryBarGrad.addColorStop(1, "#1d4ed8");

        const primaryLightGrad = breakdownCtx.createLinearGradient(0, 0, 0, 200);
        primaryLightGrad.addColorStop(0, "#60a5fa");
        primaryLightGrad.addColorStop(1, "#2563eb");

        const primarySoftGrad = breakdownCtx.createLinearGradient(0, 0, 0, 200);
        primarySoftGrad.addColorStop(0, "#93c5fd");
        primarySoftGrad.addColorStop(1, "#3b82f6");

        const secondaryBarGrad = breakdownCtx.createLinearGradient(0, 0, 0, 200);
        secondaryBarGrad.addColorStop(0, "#f43f5e");
        secondaryBarGrad.addColorStop(1, "#be123c");

        const secondaryLightGrad = breakdownCtx.createLinearGradient(0, 0, 0, 200);
        secondaryLightGrad.addColorStop(0, "#fb7185");
        secondaryLightGrad.addColorStop(1, "#e11d48");

        const secondarySoftGrad = breakdownCtx.createLinearGradient(0, 0, 0, 200);
        secondarySoftGrad.addColorStop(0, "#fda4af");
        secondarySoftGrad.addColorStop(1, "#f43f5e");

        // Custom plugin to draw crisp data values on top of each bar
        const lossBreakdownDataLabelsPlugin = {
            id: "lossBreakdownDataLabelsPlugin",
            afterDatasetsDraw: (chart) => {
                const { ctx } = chart;
                ctx.save();
                const meta = chart.getDatasetMeta(0);
                if (meta && meta.data) {
                    meta.data.forEach((bar, idx) => {
                        const val = barValues[idx];
                        if (val > 0) {
                            const formatted = formatMoney(val);
                            ctx.font = "bold 9px Inter, system-ui, sans-serif";
                            ctx.fillStyle = idx < 3 ? (isLight ? "#1d4ed8" : "#93c5fd") : (isLight ? "#be123c" : "#fda4af");
                            ctx.textAlign = "center";
                            ctx.textBaseline = "bottom";
                            ctx.fillText(formatted, bar.x, Math.max(chart.chartArea.top + 8, bar.y - 3));
                        }
                    });
                }
                ctx.restore();
            }
        };

        lossBreakdownChart = new Chart(breakdownCtx, {
            type: "bar",
            data: {
                labels: [
                    ["Downtime", "(Direct)"],
                    ["Forensics", "(Response)"],
                    ["Recovery", "(Systems)"],
                    ["Reg. Fines", "(DPDP/SEBI)"],
                    ["Breach Liab.", "(Legal)"],
                    ["Reputation", "(Churn)"]
                ],
                datasets: [{
                    label: "Loss Component",
                    data: barValues,
                    backgroundColor: [
                        primaryBarGrad, primaryLightGrad, primarySoftGrad,
                        secondaryBarGrad, secondaryLightGrad, secondarySoftGrad
                    ],
                    borderRadius: 5,
                    borderSkipped: false,
                    maxBarThickness: 42
                }]
            },
            plugins: [lossBreakdownDataLabelsPlugin],
            options: {
                responsive: true,
                maintainAspectRatio: false,
                layout: {
                    padding: { top: 18, bottom: 4, left: 2, right: 6 }
                },
                animation: { duration: 250 },
                plugins: {
                    legend: {
                        display: true,
                        position: "top",
                        align: "end",
                        labels: {
                            boxWidth: 8,
                            boxHeight: 8,
                            usePointStyle: true,
                            pointStyle: "rectRounded",
                            padding: 10,
                            font: { size: 9.5, weight: "500" },
                            color: isLight ? "#475569" : "#e4e4e7",
                            generateLabels: () => [
                                {
                                    text: `Primary Losses (${formatMoney(primSum)})`,
                                    fillStyle: "#3b82f6",
                                    strokeStyle: "#3b82f6",
                                    fontColor: isLight ? "#475569" : "#e4e4e7",
                                    pointStyle: "rectRounded",
                                    hidden: false,
                                    index: 0
                                },
                                {
                                    text: `Secondary Losses (${formatMoney(secSum)})`,
                                    fillStyle: "#f43f5e",
                                    strokeStyle: "#f43f5e",
                                    fontColor: isLight ? "#475569" : "#e4e4e7",
                                    pointStyle: "rectRounded",
                                    hidden: false,
                                    index: 1
                                }
                            ]
                        }
                    },
                    tooltip: {
                        backgroundColor: colors.tooltipBg,
                        borderColor: colors.tooltipBorder,
                        borderWidth: 1.5,
                        padding: 10,
                        cornerRadius: 8,
                        titleColor: colors.tooltipTitle,
                        bodyColor: colors.tooltipBody,
                        titleFont: { size: 11, weight: "bold" },
                        bodyFont: { size: 10.5 },
                        callbacks: {
                            title: (items) => {
                                const raw = items[0].label;
                                return Array.isArray(raw) ? raw.join(" ") : raw;
                            },
                            label: (ctx) => {
                                const idx = ctx.dataIndex;
                                const isPrim = idx < 3;
                                const cat = isPrim ? "Primary Loss (Direct Harm)" : "Secondary Loss (External Harm)";
                                return [
                                    `${cat}: ${formatMoney(ctx.raw)}`,
                                    `Share of Total: ${((ctx.raw / (primSum + secSum || 1)) * 100).toFixed(1)}%`
                                ];
                            }
                        }
                    }
                },
                scales: {
                    x: {
                        grid: { display: false },
                        ticks: {
                            color: colors.tickColor,
                            font: { size: 9.5, weight: "500" },
                            maxRotation: 0,
                            minRotation: 0
                        }
                    },
                    y: {
                        grid: { color: colors.gridColor },
                        ticks: {
                            color: colors.tickColor,
                            font: { size: 9 },
                            callback: (v) => formatMoney(v)
                        }
                    }
                }
            }
        });
    }
}


// ---------------- TAB 2: INVESTMENT OPTIMIZER ----------------
let debounceTimer = null;

function updatePresetHighlight(val) {
    const presets = [
        { id: "opt-preset-1", val: 2500000 },
        { id: "opt-preset-2", val: 5000000 },
        { id: "opt-preset-3", val: 10000000 },
        { id: "opt-preset-4", val: 20000000 }
    ];
    presets.forEach(p => {
        const btn = document.getElementById(p.id);
        if (!btn) return;
        if (Math.abs(val - p.val) < 10000) {
            btn.className = "px-2.5 py-1 text-xs rounded-lg bg-indigo-600 text-white font-medium border border-indigo-500 shadow-md shadow-indigo-600/30 transition whitespace-nowrap";
        } else {
            btn.className = "px-2.5 py-1 text-xs rounded-lg bg-[#111114] hover:bg-[#1c1c20] text-zinc-300 border border-[#222225] transition whitespace-nowrap";
        }
    });
}

function onBudgetSliderChange(val) {
    updateSliderLabel(val);
    updatePresetHighlight(val);
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => {
        fetchOptimization(parseFloat(val));
    }, 250);
}

function setBudget(val) {
    const slider = document.getElementById("budget-slider");
    if (slider) slider.value = val;
    updateSliderLabel(val);
    updatePresetHighlight(val);
    fetchOptimization(val);
}

function updateSliderLabel(val) {
    const label = document.getElementById("slider-budget-label");
    if (!label) return;
    if (currentCurrency === 'INR') {
        label.innerText = `${formatMoney(val)} (~$${(val / USD_INR_RATE / 1000).toFixed(0)}k USD)`;
    } else {
        label.innerText = `${formatMoney(val)} (~₹${(val / 10000000).toFixed(2)} Cr)`;
    }
}

async function fetchOptimization(budgetInr) {
    try {
        const res = await fetch("/api/optimize", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ budget_inr: budgetInr })
        });
        if (!res.ok) {
            const errData = await res.json().catch(() => ({}));
            showToast(errData.detail || "Portfolio optimization calculation failed", "error");
            return;
        }
        const opt = await res.json();
        optimizerLoaded = true;
        renderOptimizationResults(opt);
    } catch (err) {
        console.error("Optimization failed:", err);
        showToast("Error connecting to optimization service", "error");
    }
}

function renderOptimizationResults(opt) {
    document.getElementById("opt-spent").innerText = formatMoney(opt.total_spent_inr);
    document.getElementById("opt-utilization").innerText = `${opt.budget_utilization_pct}% allocated`;
    document.getElementById("opt-reduction").innerText = formatMoney(opt.net_risk_reduction_inr);
    document.getElementById("opt-rosi").innerText = `${opt.portfolio_rosi_pct.toLocaleString()}%`;
    document.getElementById("opt-post-eal").innerText = formatMoney(opt.post_mitigation_eal_inr);
    document.getElementById("opt-controls-count").innerText = `${opt.selected_initiatives.length} / 10`;

    document.getElementById("diminishing-returns-badge").innerText = `Optimal Zone Ceiling: ${formatMoney(opt.diminishing_returns_threshold_inr)}`;

    // Render Initiatives Table
    const tbody = document.getElementById("initiatives-tbody");
    tbody.innerHTML = "";
    opt.selected_initiatives.forEach(init => {
        const tr = document.createElement("tr");
        tr.className = "hover:bg-[#131316] transition bg-[#08170e]/50 border-b border-[#18181b]";
        tr.innerHTML = `
            <td class="py-2.5 px-3">
                <span class="px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-500/10 text-emerald-300 border border-emerald-500/40 flex items-center space-x-1 w-fit">
                    <i data-lucide="check" class="w-3 h-3"></i>
                    <span>Funded</span>
                </span>
            </td>
            <td class="py-2.5 px-3">
                <div class="font-medium text-white">${escapeHtml(init.title)}</div>
                <div class="text-[10px] text-zinc-500 font-mono">${escapeHtml(init.initiative_id)}</div>
            </td>
            <td class="py-2.5 px-3 text-zinc-400">${escapeHtml(init.category)}</td>
            <td class="py-2.5 px-3 text-right font-mono font-medium text-zinc-200">${formatMoney(init.cost_inr)}</td>
            <td class="py-2.5 px-3 text-right font-mono font-bold text-emerald-400">${formatMoney(init.annual_risk_reduction_inr)}</td>
            <td class="py-2.5 px-3 text-right font-mono font-bold text-cyan-300">${init.rosi_percentage.toLocaleString()}%</td>
            <td class="py-2.5 px-3 text-zinc-400 text-[11px]">${escapeHtml((init.target_assets || []).join(", "))}</td>
        `;
        tbody.appendChild(tr);
    });

    if (window.lucide) lucide.createIcons();

    // Render Efficient Frontier Chart
    renderEfficientFrontier(opt.efficient_frontier, opt.diminishing_returns_threshold_inr);
}

function renderEfficientFrontier(frontierPoints, thresholdInr) {
    if (!frontierPoints || frontierPoints.length === 0) return;
    const canvas = document.getElementById("efficientFrontierChart");
    if (!canvas) return;

    if (efficientFrontierChart) {
        efficientFrontierChart.destroy();
        efficientFrontierChart = null;
    }

    const ctx = canvas.getContext("2d");
    const colors = getChartThemeColors();
    const isLight = (currentTheme === "light");

    const isUsd = (currentCurrency === "USD");
    const divisor = isUsd ? (USD_INR_RATE * 1000000) : 10000000;
    const reductionLabel = isUsd ? "Annual Risk Reduction ($ M)" : "Annual Risk Reduction (₹ Cr)";
    const spendLabel = isUsd ? "Actual Capital Invested ($ M)" : "Actual Capital Invested (₹ Cr)";

    // Update active budget pill in header
    const currentSliderVal = parseFloat(document.getElementById("budget-slider")?.value || 10000000);
    const activePill = document.getElementById("frontier-active-budget-pill");
    if (activePill) {
        activePill.textContent = `Selected: ${formatMoney(currentSliderVal)}`;
    }

    // Find closest index for active slider budget
    let activeBudgetIdx = 0;
    let minDiff = Infinity;
    frontierPoints.forEach((p, idx) => {
        const diff = Math.abs(p.budget_inr - currentSliderVal);
        if (diff < minDiff) {
            minDiff = diff;
            activeBudgetIdx = idx;
        }
    });

    // Find threshold index for diminishing returns zone
    const threshVal = thresholdInr || 18000000.0;
    let threshIdx = -1;
    let minThreshDiff = Infinity;
    frontierPoints.forEach((p, idx) => {
        const diff = Math.abs(p.budget_inr - threshVal);
        if (diff < minThreshDiff) {
            minThreshDiff = diff;
            threshIdx = idx;
        }
    });

    const labels = frontierPoints.map(p => formatMoney(p.budget_inr));
    const reductions = frontierPoints.map(p => p.risk_reduction_inr / divisor);
    const spends = frontierPoints.map(p => p.spent_inr / divisor);

    // Dynamic gradient under Risk Reduction curve
    let reductionGrad = null;
    try {
        reductionGrad = ctx.createLinearGradient(0, 0, 0, 260);
        reductionGrad.addColorStop(0, isLight ? "rgba(16, 185, 129, 0.25)" : "rgba(16, 185, 129, 0.28)");
        reductionGrad.addColorStop(1, "rgba(16, 185, 129, 0.01)");
    } catch (e) {
        reductionGrad = "rgba(16, 185, 129, 0.10)";
    }

    // Custom Canvas Plugin: Diminishing Returns Shaded Zone + Active Budget Guideline & Floating Badge
    const frontierGuidePlugin = {
        id: "frontierGuidePlugin",
        beforeDraw: (chart) => {
            const { ctx, chartArea } = chart;
            if (!chartArea || threshIdx === -1) return;
            const meta = chart.getDatasetMeta(0);
            if (!meta || !meta.data || !meta.data[threshIdx]) return;

            const tPt = meta.data[threshIdx];
            ctx.save();

            // Shaded "Diminishing Returns" zone
            ctx.fillStyle = isLight ? "rgba(244, 63, 94, 0.04)" : "rgba(244, 63, 94, 0.06)";
            ctx.fillRect(tPt.x, chartArea.top, chartArea.right - tPt.x, chartArea.bottom - chartArea.top);

            // Subtle vertical dashed boundary
            ctx.setLineDash([4, 4]);
            ctx.lineWidth = 1.25;
            ctx.strokeStyle = "rgba(245, 158, 11, 0.65)";
            ctx.beginPath();
            ctx.moveTo(tPt.x, chartArea.top);
            ctx.lineTo(tPt.x, chartArea.bottom);
            ctx.stroke();
            ctx.setLineDash([]);

            // Label tag on boundary
            ctx.font = "bold 9px Inter, system-ui, sans-serif";
            ctx.fillStyle = "rgba(245, 158, 11, 0.85)";
            ctx.textAlign = "left";
            ctx.textBaseline = "top";
            ctx.fillText("⚑ Sweet Spot Ceiling", tPt.x + 6, chartArea.top + 6);

            ctx.restore();
        },
        afterDraw: (chart) => {
            const { ctx, chartArea } = chart;
            if (!chartArea || activeBudgetIdx === -1) return;
            const meta0 = chart.getDatasetMeta(0);
            const meta1 = chart.getDatasetMeta(1);
            if (!meta0 || !meta0.data || !meta0.data[activeBudgetIdx]) return;

            const aPt = meta0.data[activeBudgetIdx];
            const sPt = meta1 && meta1.data ? meta1.data[activeBudgetIdx] : null;

            ctx.save();

            // Vertical dashed guideline for active budget selection
            ctx.setLineDash([3, 3]);
            ctx.lineWidth = 1.5;
            ctx.strokeStyle = "rgba(99, 102, 241, 0.75)";
            ctx.beginPath();
            ctx.moveTo(aPt.x, chartArea.top);
            ctx.lineTo(aPt.x, chartArea.bottom);
            ctx.stroke();
            ctx.setLineDash([]);

            // Pulsing highlight ring on active risk reduction point
            ctx.beginPath();
            ctx.arc(aPt.x, aPt.y, 8, 0, 2 * Math.PI);
            ctx.strokeStyle = "rgba(16, 185, 129, 0.5)";
            ctx.lineWidth = 2.5;
            ctx.stroke();

            // Ring on capital spent point
            if (sPt) {
                ctx.beginPath();
                ctx.arc(sPt.x, sPt.y, 6, 0, 2 * Math.PI);
                ctx.strokeStyle = "rgba(129, 140, 248, 0.5)";
                ctx.lineWidth = 2;
                ctx.stroke();
            }

            // Floating badge above active point
            const activePointData = frontierPoints[activeBudgetIdx];
            const activeBadgeText = `● Budget: ${formatMoney(activePointData.budget_inr)}`;
            ctx.font = "bold 9.5px Inter, system-ui, sans-serif";
            const textWidth = ctx.measureText(activeBadgeText).width;
            const badgeW = textWidth + 14;
            const badgeH = 18;
            const badgeX = Math.max(chartArea.left + 4, Math.min(chartArea.right - badgeW - 4, aPt.x - badgeW / 2));
            const badgeY = Math.max(chartArea.top + 4, aPt.y - 25);

            ctx.fillStyle = isLight ? "#ffffff" : "#09090b";
            ctx.beginPath();
            ctx.roundRect(badgeX, badgeY, badgeW, badgeH, 4);
            ctx.fill();

            ctx.strokeStyle = "rgba(99, 102, 241, 0.8)";
            ctx.lineWidth = 1;
            ctx.stroke();

            ctx.fillStyle = "#818cf8";
            ctx.textAlign = "center";
            ctx.textBaseline = "middle";
            ctx.fillText(activeBadgeText, badgeX + badgeW / 2, badgeY + badgeH / 2);

            ctx.restore();
        }
    };

    const maxSpend = Math.max(...spends, 0.1);
    const rightAxisMax = Math.ceil(maxSpend * 1.35 * 2) / 2;

    efficientFrontierChart = new Chart(ctx, {
        type: "line",
        data: {
            labels: labels,
            datasets: [
                {
                    label: reductionLabel,
                    data: reductions,
                    borderColor: "#10b981",
                    borderWidth: 2.25,
                    backgroundColor: reductionGrad,
                    fill: true,
                    tension: 0.3,
                    pointRadius: (c) => (c.dataIndex === activeBudgetIdx ? 6.5 : 4),
                    pointBackgroundColor: (c) => (c.dataIndex === activeBudgetIdx ? "#10b981" : "#34d399"),
                    pointBorderColor: "#ffffff",
                    pointBorderWidth: (c) => (c.dataIndex === activeBudgetIdx ? 2 : 1),
                    pointHoverRadius: 8,
                    yAxisID: "y"
                },
                {
                    label: spendLabel,
                    data: spends,
                    borderColor: "#818cf8",
                    borderWidth: 2,
                    borderDash: [5, 4],
                    tension: 0.25,
                    pointRadius: (c) => (c.dataIndex === activeBudgetIdx ? 5.5 : 3),
                    pointBackgroundColor: (c) => (c.dataIndex === activeBudgetIdx ? "#6366f1" : "#818cf8"),
                    pointBorderColor: "#ffffff",
                    pointBorderWidth: 1,
                    pointHoverRadius: 7,
                    yAxisID: "y1"
                }
            ]
        },
        plugins: [frontierGuidePlugin],
        options: {
            responsive: true,
            maintainAspectRatio: false,
            layout: {
                padding: { left: 8, right: 12, top: 16, bottom: 6 }
            },
            animation: { duration: 300 },
            plugins: {
                legend: {
                    position: "top",
                    align: "center",
                    labels: {
                        color: colors.tickColor,
                        font: { size: 10, weight: "500" },
                        boxWidth: 8,
                        boxHeight: 8,
                        usePointStyle: true,
                        pointStyle: "circle",
                        padding: 12
                    }
                },
                tooltip: {
                    backgroundColor: colors.tooltipBg,
                    borderColor: colors.tooltipBorder,
                    borderWidth: 1.5,
                    padding: 12,
                    cornerRadius: 8,
                    titleColor: colors.tooltipTitle,
                    bodyColor: colors.tooltipBody,
                    titleFont: { size: 11, weight: "bold" },
                    bodyFont: { size: 10.5, lineHeight: 1.5 },
                    callbacks: {
                        title: (items) => `Budget Ceiling: ${items[0].label}`,
                        label: (ctx) => {
                            const p = frontierPoints[ctx.dataIndex];
                            if (!p) return `${ctx.dataset.label}: ${formatMoney(ctx.raw * divisor)}`;
                            if (ctx.datasetIndex === 0) {
                                return [
                                    `🛡️ Annual Risk Reduction: ${formatMoney(p.risk_reduction_inr)}`,
                                    `🎯 Funded Controls: ${p.initiatives_count} Initiatives`
                                ];
                            } else {
                                const util = p.budget_inr > 0 ? ((p.spent_inr / p.budget_inr) * 100).toFixed(0) : "0";
                                return [
                                    `💰 Capital Invested: ${formatMoney(p.spent_inr)} (${util}% of budget)`
                                ];
                            }
                        }
                    }
                }
            },
            scales: {
                x: {
                    offset: true, // Prevents 5L and 3Cr points from clipping against canvas border walls
                    title: {
                        display: true,
                        text: "Security Budget Allocation (Ceiling)",
                        color: colors.tickColor,
                        font: { size: 10, weight: "600" }
                    },
                    grid: { color: colors.gridColor },
                    ticks: {
                        color: colors.tickColor,
                        font: { size: 9.5, weight: "500" },
                        maxRotation: 0,
                        minRotation: 0
                    }
                },
                y: {
                    type: "linear",
                    position: "left",
                    title: {
                        display: true,
                        text: reductionLabel,
                        color: "#10b981",
                        font: { size: 10, weight: "bold" }
                    },
                    grid: { color: colors.gridColor },
                    ticks: {
                        color: "#10b981",
                        font: { size: 9.5 },
                        callback: (v) => isUsd ? `$${v.toFixed(1)}M` : `₹${v.toFixed(1)}Cr`
                    }
                },
                y1: {
                    type: "linear",
                    position: "right",
                    min: 0,
                    max: rightAxisMax,
                    title: {
                        display: true,
                        text: spendLabel,
                        color: "#818cf8",
                        font: { size: 10, weight: "bold" }
                    },
                    grid: { drawOnChartArea: false }, // Avoid duplicate gridlines
                    ticks: {
                        color: "#818cf8",
                        font: { size: 9.5 },
                        callback: (v) => isUsd ? `$${v.toFixed(1)}M` : `₹${v.toFixed(1)}Cr`
                    }
                }
            }
        }
    });
}


// ---------------- TAB 3: WHAT-IF SCENARIOS ----------------
async function loadScenarios() {
    try {
        const res = await fetch("/api/scenarios/list");
        if (!res.ok) {
            showToast("Failed to fetch scenario models", "error");
            return;
        }
        availableScenarios = await res.json();
        renderScenariosGrid(availableScenarios);
    } catch (err) {
        console.error("Failed to load scenarios:", err);
        showToast("Error connecting to scenario service", "error");
    }
}

function renderScenariosGrid(scenarios) {
    const grid = document.getElementById("scenarios-selector-grid");
    if (!grid) return;
    grid.innerHTML = "";

    if (!activeScenarioId && scenarios.length > 0) {
        activeScenarioId = scenarios[0].id;
    }

    scenarios.forEach((scen) => {
        const card = document.createElement("div");
        const isSelected = (scen.id === activeScenarioId);
        card.id = `scenario-card-${scen.id}`;
        card.className = `p-4 rounded-xl border cursor-pointer transition ${
            isSelected
                ? 'bg-[#0f0e21] border-indigo-500 shadow-lg shadow-indigo-950/50'
                : 'bg-[#0b0b0e] border-[#1e1e22] hover:border-[#333338]'
        }`;
        card.onclick = () => selectScenario(scen.id);
        card.innerHTML = `
            <div class="flex items-center justify-between pointer-events-none">
                <span class="text-[10px] uppercase font-semibold text-zinc-400">${escapeHtml(scen.category)}</span>
                <span class="px-1.5 py-0.5 rounded text-[9px] font-bold ${
                    scen.impact_type === 'Risk Reduction' ? 'bg-emerald-500/10 text-emerald-300 border border-emerald-500/30' : 'bg-rose-500/10 text-rose-300 border border-rose-500/30'
                }">${escapeHtml(scen.impact_type)}</span>
            </div>
            <h4 class="text-xs font-bold text-white mt-2 leading-snug pointer-events-none">${escapeHtml(scen.title)}</h4>
        `;
        grid.appendChild(card);
    });

    const activeScen = scenarios.find(s => s.id === activeScenarioId) || scenarios[0];
    if (activeScen) {
        const titleEl = document.getElementById("active-scenario-title");
        const descEl = document.getElementById("active-scenario-desc");
        if (titleEl) titleEl.innerText = activeScen.title;
        if (descEl) descEl.innerText = `Category: ${activeScen.category} | Impact Profile: ${activeScen.impact_type}`;
    }
}

function selectScenario(scenarioId) {
    activeScenarioId = scenarioId;
    const scen = availableScenarios.find(s => s.id === scenarioId);
    if (!scen) return;

    // Reset previous scenario results to prevent displaying stale metrics
    const panel = document.getElementById("scenario-results-panel");
    if (panel) panel.classList.add("hidden");

    const titleEl = document.getElementById("active-scenario-title");
    const descEl = document.getElementById("active-scenario-desc");
    if (titleEl) titleEl.innerText = scen.title;
    if (descEl) descEl.innerText = `Category: ${scen.category} | Impact Profile: ${scen.impact_type}`;

    // Update active highlight on cards directly without re-rendering or infinite recursion
    availableScenarios.forEach(s => {
        const card = document.getElementById(`scenario-card-${s.id}`);
        if (card) {
            if (s.id === scenarioId) {
                card.className = 'p-4 rounded-xl border cursor-pointer transition bg-[#0f0e21] border-indigo-500 shadow-lg shadow-indigo-950/50';
            } else {
                card.className = 'p-4 rounded-xl border cursor-pointer transition bg-[#0b0b0e] border-[#1e1e22] hover:border-[#333338]';
            }
        }
    });
}

async function executeActiveScenario() {
    const btn = document.getElementById("run-scenario-btn");
    btn.disabled = true;
    btn.innerHTML = `<span class="animate-spin mr-2">⏳</span> Simulating...`;

    try {
        const res = await fetch("/api/scenarios/simulate", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ scenario_id: activeScenarioId })
        });
        if (!res.ok) {
            const errData = await res.json().catch(() => ({}));
            showToast(errData.detail || "What-If simulation failed", "error");
            return;
        }
        const result = await res.json();
        renderScenarioResults(result);
    } catch (err) {
        console.error("Scenario simulation failed:", err);
        showToast("Error running scenario simulation", "error");
    } finally {
        btn.disabled = false;
        btn.innerHTML = `<i data-lucide="play" class="w-4 h-4"></i><span>Run Simulation</span>`;
        if (window.lucide) lucide.createIcons();
    }
}

function renderScenarioResults(res) {
    const panel = document.getElementById("scenario-results-panel");
    panel.classList.remove("hidden");

    document.getElementById("scen-base-eal").innerText = formatMoney(res.baseline_eal_inr);
    document.getElementById("scen-new-eal").innerText = formatMoney(res.scenario_eal_inr);

    const deltaCard = document.getElementById("scen-delta-card");
    const deltaVal = document.getElementById("scen-delta-val");
    const deltaBadge = document.getElementById("scen-delta-badge");

    deltaVal.innerText = formatMoney(res.delta_eal_inr);

    if (res.delta_eal_inr < 0) {
        deltaCard.className = "p-4 rounded-xl border border-emerald-500/30 bg-[#06150e]";
        deltaVal.className = "text-xl font-bold text-emerald-400 mt-1 block";
        deltaBadge.innerText = `${Math.abs(res.delta_percentage).toFixed(1)}% financial risk mitigated`;
        deltaBadge.className = "text-[11px] font-semibold text-emerald-300";
    } else {
        deltaCard.className = "p-4 rounded-xl border border-rose-500/30 bg-[#16070a]";
        deltaVal.className = "text-xl font-bold text-rose-400 mt-1 block";
        deltaBadge.innerText = `+${res.delta_percentage.toFixed(1)}% financial risk surge`;
        deltaBadge.className = "text-[11px] font-semibold text-rose-300";
    }

    document.getElementById("scen-ai-summary").innerText = res.ai_executive_summary;

    const driversList = document.getElementById("scen-drivers-list");
    driversList.innerHTML = "";
    res.key_drivers.forEach(driver => {
        const li = document.createElement("li");
        li.className = "flex items-start space-x-2";
        li.innerHTML = `
            <i data-lucide="chevron-right" class="w-3.5 h-3.5 text-indigo-400 flex-shrink-0 mt-0.5"></i>
            <span>${escapeHtml(driver)}</span>
        `;
        driversList.appendChild(li);
    });

    if (window.lucide) lucide.createIcons();
}


// ---------------- TAB 4: COMPLIANCE & FRAMEWORKS ----------------
async function loadCompliance() {
    try {
        const [frameworksRes, reportRes] = await Promise.all([
            fetch("/api/compliance/frameworks"),
            fetch("/api/compliance/report")
        ]);
        if (!frameworksRes.ok || !reportRes.ok) {
            showToast("Failed to load compliance audit framework data", "error");
            return;
        }
        const frameworks = await frameworksRes.json();
        const report = await reportRes.json();
        complianceLoaded = true;
        renderComplianceRadar(frameworks);
        renderFrameworksList(frameworks, report);
    } catch (err) {
        console.error("Compliance loading failed:", err);
        showToast("Network error loading compliance frameworks", "error");
    }
}

function renderComplianceRadar(frameworks) {
    if (!frameworks || frameworks.length === 0) return;
    const canvas = document.getElementById("complianceRadarChart");
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (complianceRadarChart) complianceRadarChart.destroy();

    const colors = getChartThemeColors();
    const labels = frameworks.map(f => f.framework_name.split(" ")[0]);
    const scores = frameworks.map(f => f.overall_compliance_pct);

    complianceRadarChart = new Chart(ctx, {
        type: "radar",
        data: {
            labels: labels,
            datasets: [{
                label: "Compliance Posture %",
                data: scores,
                backgroundColor: currentTheme === "light" ? "rgba(16, 185, 129, 0.20)" : "rgba(16, 185, 129, 0.15)",
                borderColor: "#10b981",
                pointBackgroundColor: "#34d399",
                pointBorderColor: colors.doughnutBorder,
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: { duration: 250 },
            scales: {
                r: {
                    angleLines: { color: colors.radarGrid },
                    grid: { color: colors.radarGrid },
                    suggestedMin: 40,
                    suggestedMax: 100,
                    ticks: { color: colors.tickColor, backdropColor: "transparent", font: { size: 9 } },
                    pointLabels: { color: colors.radarPointLabel, font: { size: 10, weight: "bold" } }
                }
            },
            plugins: {
                legend: { display: false }
            }
        }
    });
}

function renderFrameworksList(frameworks, report) {
    const container = document.getElementById("frameworks-list");
    if (!container) return;
    container.innerHTML = "";

    frameworks.forEach(fw => {
        const div = document.createElement("div");
        div.className = "bg-[#0c0c0f] p-4 rounded-xl border border-[#1f1f22] space-y-3";
        div.innerHTML = `
            <div class="flex items-center justify-between">
                <div>
                    <h4 class="text-sm font-bold text-white">${escapeHtml(fw.framework_name)}</h4>
                    <p class="text-[11px] text-zinc-400">${escapeHtml(fw.regulatory_mandate)}</p>
                </div>
                <div class="text-right">
                    <span class="text-lg font-extrabold text-emerald-400">${fw.overall_compliance_pct}%</span>
                    <span class="text-[10px] text-zinc-500 block">${escapeHtml(fw.status)}</span>
                </div>
            </div>
            <div class="grid grid-cols-2 sm:grid-cols-3 gap-2 text-[10px] bg-[#070709] p-2.5 rounded-lg border border-[#18181b]">
                ${Object.entries(fw.category_scores).map(([k, v]) => `
                    <div>
                        <span class="text-zinc-400 block truncate">${escapeHtml(k)}</span>
                        <span class="font-bold text-zinc-200">${v}%</span>
                    </div>
                `).join('')}
            </div>
        `;
        container.appendChild(div);
    });

    if (report && report.critical_audit_findings && report.critical_audit_findings.length > 0) {
        const findingsSection = document.createElement("div");
        findingsSection.className = "mt-6 pt-4 border-t border-[#1f1f22] space-y-3";
        findingsSection.innerHTML = `
            <div class="flex items-center justify-between">
                <h4 class="text-xs font-bold text-zinc-300 uppercase tracking-wider flex items-center space-x-1.5">
                    <i data-lucide="alert-triangle" class="w-3.5 h-3.5 text-amber-400"></i>
                    <span>Regulatory Deficiencies & Audit Findings (${report.critical_audit_findings.length})</span>
                </h4>
                <span class="text-[10px] text-zinc-500">Continuous Audit Engine</span>
            </div>
            <div class="space-y-2.5">
                ${report.critical_audit_findings.map(f => `
                    <div class="bg-[#09090c] p-3 rounded-xl border border-[#1c1c20] space-y-1.5">
                        <div class="flex items-center justify-between text-[11px]">
                            <div class="flex items-center space-x-2">
                                <span class="px-1.5 py-0.5 rounded text-[9px] font-bold ${
                                    f.severity === 'CRITICAL' ? 'bg-rose-500/10 text-rose-400 border border-rose-500/30' :
                                    f.severity === 'HIGH' ? 'bg-amber-500/10 text-amber-400 border border-amber-500/30' :
                                    'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                                }">${escapeHtml(f.severity)}</span>
                                <span class="font-mono text-zinc-400">${escapeHtml(f.finding_id)}</span>
                            </div>
                            <span class="text-[10px] text-indigo-400 font-mono">${escapeHtml(f.framework_clause)}</span>
                        </div>
                        <p class="text-xs text-zinc-200 leading-snug">${escapeHtml(f.description)}</p>
                        <div class="text-[10px] text-rose-300/90 bg-rose-500/5 px-2 py-1 rounded border border-rose-500/10">
                            <strong>Monetary Exposure:</strong> ${escapeHtml(f.associated_monetary_risk)}
                        </div>
                        <div class="text-[10px] text-emerald-300/90 bg-emerald-500/5 px-2 py-1 rounded border border-emerald-500/10">
                            <strong>Remediation:</strong> ${escapeHtml(f.recommended_remediation)}
                        </div>
                    </div>
                `).join('')}
            </div>
        `;
        container.appendChild(findingsSection);
        if (window.lucide) lucide.createIcons();
    }
}

async function downloadBoardReport() {
    try {
        const res = await fetch("/api/compliance/report");
        if (!res.ok) throw new Error("Server error generating report");
        const report = await res.json();
        const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `RiskLens_Board_Compliance_Audit_${new Date().toISOString().slice(0, 10)}.json`;
        a.click();
        URL.revokeObjectURL(url);
        showToast("Board compliance audit package exported successfully.", "success");
    } catch (err) {
        showToast("Failed to export compliance report: " + err.message, "error");
    }
}


// ---------------- TAB 5: ASSET & TELEMETRY EXPLORER ----------------
async function loadAssets() {
    try {
        const res = await fetch("/api/assets");
        if (!res.ok) {
            showToast("Failed to fetch enterprise asset telemetry", "error");
            return;
        }
        assetInventoryData = await res.json();
        const headerBadge = document.getElementById("header-telemetry-badge");
        if (headerBadge) {
            headerBadge.textContent = `${assetInventoryData.length} Assets Live`;
        }
        renderAssetsTable(assetInventoryData);
        renderEpssCvssScatter(assetInventoryData);
    } catch (err) {
        console.error("Asset load failed:", err);
        showToast("Error loading asset telemetry", "error");
    }
}

function renderAssetsTable(assets) {
    const tbody = document.getElementById("assets-tbody");
    tbody.innerHTML = "";

    assets.forEach(asset => {
        const tr = document.createElement("tr");
        tr.className = "hover:bg-[#131316] transition border-b border-[#18181b]";
        const rawCves = asset.vulnerabilities || [];
        const sortedCves = rawCves.slice().sort((a, b) => {
            const scoreA = (a.is_cisa_kev ? 100 : 0) + (a.epss_score || 0) * 10 + (a.cvss_score || 0);
            const scoreB = (b.is_cisa_kev ? 100 : 0) + (b.epss_score || 0) * 10 + (b.cvss_score || 0);
            return scoreB - scoreA;
        });
        const topCve = sortedCves.length > 0 ? sortedCves[0] : null;

        tr.innerHTML = `
            <td class="py-2.5 px-3">
                <div class="font-medium text-white">${escapeHtml(asset.name)}</div>
                <div class="text-[10px] font-mono text-zinc-500">${escapeHtml(asset.asset_id)} • ${escapeHtml(asset.ip_or_endpoint)}</div>
            </td>
            <td class="py-2.5 px-3 text-zinc-300">${escapeHtml(asset.business_unit)}</td>
            <td class="py-2.5 px-3">
                <span class="px-2 py-0.5 rounded text-[10px] font-semibold ${String(asset.criticality || '').includes('Tier 1') ? 'badge-crown' : 'bg-[#18181b] text-zinc-300 border border-[#27272a]'}">
                    ${escapeHtml(asset.criticality)}
                </span>
            </td>
            <td class="py-2.5 px-3 text-right font-mono text-zinc-200">${formatMoney(asset.revenue_per_hour_inr)}</td>
            <td class="py-2.5 px-3 font-mono text-zinc-400">${Number(asset.pii_records_count || 0).toLocaleString()}</td>
            <td class="py-2.5 px-3">
                <span class="text-[11px] text-emerald-400 font-medium">${(asset.controls || []).length} Enforced</span>
            </td>
            <td class="py-2.5 px-3">
                ${topCve ? `
                    <span class="font-mono text-rose-400 font-bold">${escapeHtml(topCve.cve_id)}</span>
                    <span class="text-[10px] text-zinc-400 block">CVSS ${topCve.cvss_score} | EPSS ${(topCve.epss_score*100).toFixed(0)}%</span>
                ` : `<span class="text-zinc-600">None detected</span>`}
            </td>
        `;
        tbody.appendChild(tr);
    });
}

function filterAssetsTable(query) {
    const q = query.toLowerCase().trim();
    if (!q) {
        renderAssetsTable(assetInventoryData);
        return;
    }
    const filtered = assetInventoryData.filter(a =>
        (a.name || "").toLowerCase().includes(q) ||
        (a.business_unit || "").toLowerCase().includes(q) ||
        (a.asset_id || "").toLowerCase().includes(q) ||
        (a.vulnerabilities || []).some(v => (v.cve_id || "").toLowerCase().includes(q) || (v.title || "").toLowerCase().includes(q))
    );
    renderAssetsTable(filtered);
}

function renderEpssCvssScatter(assets) {
    if (!assets || assets.length === 0) return;
    const canvas = document.getElementById("epssCvssChart");
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (epssCvssChart) epssCvssChart.destroy();

    const colors = getChartThemeColors();
    const isLight = (currentTheme === "light");

    // Collect all vulnerabilities across assets
    const dataPoints = [];
    assets.forEach(a => {
        (a.vulnerabilities || []).forEach(v => {
            const rawEpss = v.epss_score <= 1.0 ? v.epss_score * 100 : v.epss_score;
            dataPoints.push({
                rawCvss: Number(v.cvss_score),
                rawEpss: Number(rawEpss),
                cve: v.cve_id || "CVE-UNKNOWN",
                title: v.title || "Vulnerability Finding",
                asset: a.name || "Asset",
                criticality: a.criticality || "Tier 1",
                isKev: Boolean(v.is_cisa_kev),
                daysOpen: v.days_open || 0,
                attackVector: v.attack_vector || "Network"
            });
        });
    });

    // Update dynamic summary tally cards
    const totalCves = dataPoints.length;
    const kevCount = dataPoints.filter(p => p.isKev).length;
    const q1Count = dataPoints.filter(p => p.rawCvss >= 7.0 && p.rawEpss >= 50.0).length;
    const q2Count = dataPoints.filter(p => p.rawCvss >= 7.0 && p.rawEpss < 50.0).length;
    const q3Count = dataPoints.filter(p => p.rawCvss < 7.0 && p.rawEpss >= 50.0).length;
    const q4Count = dataPoints.filter(p => p.rawCvss < 7.0 && p.rawEpss < 50.0).length;

    const totalEl = document.getElementById("stat-epss-total");
    if (totalEl) totalEl.textContent = totalCves;
    const kevEl = document.getElementById("stat-epss-kev");
    if (kevEl) kevEl.textContent = kevCount;
    const q1El = document.getElementById("stat-epss-q1");
    if (q1El) q1El.textContent = q1Count;
    const q2El = document.getElementById("stat-epss-q2");
    if (q2El) q2El.textContent = q2Count;
    const q3El = document.getElementById("stat-epss-q3");
    if (q3El) q3El.textContent = q3Count;
    const q4El = document.getElementById("stat-epss-q4");
    if (q4El) q4El.textContent = q4Count;

    // Organic 2D dispersion for clustered / co-located points
    const clusterMap = {};
    dataPoints.forEach(p => {
        const key = `${p.rawCvss.toFixed(1)}_${Math.round(p.rawEpss / 6) * 6}`;
        if (!clusterMap[key]) clusterMap[key] = [];
        clusterMap[key].push(p);
    });

    dataPoints.forEach(p => {
        const key = `${p.rawCvss.toFixed(1)}_${Math.round(p.rawEpss / 6) * 6}`;
        const cluster = clusterMap[key];
        if (cluster.length > 1) {
            const idx = cluster.indexOf(p);
            const total = cluster.length;
            // Fan out horizontally by ±0.14 CVSS so points don't stack into vertical poles
            const xOffset = (idx - (total - 1) / 2) * 0.15;
            // Alternate slight vertical micro-spread (±1.5%)
            const yOffset = ((idx % 2 === 0 ? 1 : -1) * Math.ceil(idx / 2)) * 1.5;
            p.x = Math.max(4.1, Math.min(10.05, +(p.rawCvss + xOffset).toFixed(2)));
            p.y = Math.max(1, Math.min(100, +(p.rawEpss + yOffset).toFixed(1)));
        } else {
            p.x = p.rawCvss;
            p.y = p.rawEpss;
        }
    });

    // Custom inline plugin for symmetrical 4-Quadrant shading, boundary dashed lines, and badges
    const epssCvssQuadrantPlugin = {
        id: "epssCvssQuadrantPlugin",
        beforeDraw: (chart) => {
            const { ctx, chartArea, scales } = chart;
            if (!chartArea || !scales.x || !scales.y) return;
            const { left, right, top, bottom } = chartArea;

            const xMid = scales.x.getPixelForValue(7.0);
            const yMid = scales.y.getPixelForValue(50.0);

            ctx.save();

            // 1. Quadrant Background Tints (subtle, non-distracting)
            // Q1: Upper-Right (Critical / Weaponized)
            ctx.fillStyle = isLight ? "rgba(244, 63, 94, 0.08)" : "rgba(244, 63, 94, 0.07)";
            ctx.fillRect(xMid, top, right - xMid, yMid - top);

            // Q2: Lower-Right (Theoretical Severity)
            ctx.fillStyle = isLight ? "rgba(245, 158, 11, 0.06)" : "rgba(245, 158, 11, 0.035)";
            ctx.fillRect(xMid, yMid, right - xMid, bottom - yMid);

            // Q3: Upper-Left (Opportunistic Threat)
            ctx.fillStyle = isLight ? "rgba(99, 102, 241, 0.06)" : "rgba(99, 102, 241, 0.035)";
            ctx.fillRect(left, top, xMid - left, yMid - top);

            // Q4: Lower-Left (Standard Hygiene)
            ctx.fillStyle = isLight ? "rgba(56, 189, 248, 0.04)" : "rgba(56, 189, 248, 0.02)";
            ctx.fillRect(left, yMid, xMid - left, bottom - yMid);

            // 2. Dashed Dividing Lines
            ctx.lineWidth = 1.25;
            ctx.setLineDash([5, 4]);

            // Vertical CVSS 7.0 High-Severity Threshold Line
            ctx.strokeStyle = "rgba(244, 63, 94, 0.45)";
            ctx.beginPath();
            ctx.moveTo(xMid, top);
            ctx.lineTo(xMid, bottom);
            ctx.stroke();

            // Horizontal EPSS 50% Exploit-Likelihood Threshold Line
            ctx.strokeStyle = "rgba(244, 63, 94, 0.45)";
            ctx.beginPath();
            ctx.moveTo(left, yMid);
            ctx.lineTo(right, yMid);
            ctx.stroke();

            ctx.setLineDash([]);

            // Helper to draw clean pill badges
            function drawBadge(text, x, y, bg, border, color, align = "left") {
                ctx.font = "bold 9.5px Inter, system-ui, sans-serif";
                const metrics = ctx.measureText(text);
                const textWidth = metrics.width;
                const padX = 7;
                const padY = 3.5;
                const boxW = textWidth + padX * 2;
                const boxH = 17;
                let startX = x;
                if (align === "right") startX = x - boxW;
                else if (align === "center") startX = x - boxW / 2;

                ctx.fillStyle = bg;
                ctx.beginPath();
                ctx.roundRect(startX, y, boxW, boxH, 4);
                ctx.fill();

                ctx.strokeStyle = border;
                ctx.lineWidth = 1;
                ctx.stroke();

                ctx.fillStyle = color;
                ctx.textAlign = "left";
                ctx.textBaseline = "middle";
                ctx.fillText(text, startX + padX, y + boxH / 2);
            }

            // 3. Elegant Non-Colliding Quadrant Watermark Badges
            // Q1: Placed on the left side of Q1 (xMid + 14) so it never collides with CVE points at CVSS 9.2-10.0
            drawBadge("🚨 Q1: CRITICAL / WEAPONIZED", xMid + 14, top + 10,
                isLight ? "rgba(254, 226, 226, 0.85)" : "rgba(30, 10, 15, 0.75)",
                "rgba(244, 63, 94, 0.4)", "#f43f5e", "left");

            // Q2: Placed at bottom-right of Q2
            drawBadge("⚠️ Q2: THEORETICAL SEVERITY", right - 12, bottom - 26,
                isLight ? "rgba(254, 243, 199, 0.85)" : "rgba(30, 20, 10, 0.75)",
                "rgba(245, 158, 11, 0.4)", isLight ? "#d97706" : "#f59e0b", "right");

            // Q3: Placed at top-left of Q3
            drawBadge("⚡ Q3: OPPORTUNISTIC THREAT", left + 12, top + 10,
                isLight ? "rgba(238, 242, 255, 0.85)" : "rgba(15, 15, 35, 0.75)",
                "rgba(129, 140, 248, 0.4)", isLight ? "#4f46e5" : "#818cf8", "left");

            // Q4: Placed at bottom-left of Q4
            drawBadge("ℹ️ Q4: STANDARD HYGIENE", left + 12, bottom - 26,
                isLight ? "rgba(241, 245, 249, 0.85)" : "rgba(15, 23, 42, 0.75)",
                "rgba(56, 189, 248, 0.4)", isLight ? "#0284c7" : "#38bdf8", "left");

            // 4. Threshold Badges along the Dividers (non-overlapping)
            // Vertical Threshold Marker at bottom center near xMid
            drawBadge("CVSS 7.0 High", xMid, bottom - 26,
                isLight ? "#ffffff" : "#09090b", "rgba(244, 63, 94, 0.6)", "#f43f5e", "center");

            // Horizontal Threshold Marker on left near yMid
            drawBadge("EPSS 50%", left + 12, yMid - 22,
                isLight ? "#ffffff" : "#09090b", "rgba(244, 63, 94, 0.6)", "#f43f5e", "left");

            ctx.restore();
        }
    };

    // Separate datasets into intuitive visual tiers
    const kevPoints = dataPoints.filter(p => p.isKev);
    const q2Points = dataPoints.filter(p => !p.isKev && p.rawCvss >= 7.0 && p.rawEpss < 50.0);
    const q3Points = dataPoints.filter(p => !p.isKev && p.rawCvss < 7.0 && p.rawEpss >= 50.0);
    const q4Points = dataPoints.filter(p => !p.isKev && p.rawCvss < 7.0 && p.rawEpss < 50.0);
    const nonKevQ1Points = dataPoints.filter(p => !p.isKev && p.rawCvss >= 7.0 && p.rawEpss >= 50.0);

    const datasets = [
        {
            label: "CISA KEV / Actively Exploited (Q1)",
            data: kevPoints,
            backgroundColor: "#f43f5e",
            borderColor: "#ffffff",
            borderWidth: 1.5,
            pointRadius: 6.5,
            pointHoverRadius: 9
        }
    ];

    if (nonKevQ1Points.length > 0) {
        datasets.push({
            label: "Critical Unpatched Weaponized (Q1)",
            data: nonKevQ1Points,
            backgroundColor: "#fb7185",
            borderColor: "#ffffff",
            borderWidth: 1.25,
            pointRadius: 6,
            pointHoverRadius: 8.5
        });
    }

    if (q2Points.length > 0) {
        datasets.push({
            label: "Theoretical High Severity (Q2)",
            data: q2Points,
            backgroundColor: "#f59e0b",
            borderColor: "#ffffff",
            borderWidth: 1.25,
            pointRadius: 6,
            pointHoverRadius: 8.5
        });
    }

    if (q3Points.length > 0) {
        datasets.push({
            label: "Opportunistic Threat (Q3)",
            data: q3Points,
            backgroundColor: "#818cf8",
            borderColor: "#ffffff",
            borderWidth: 1.25,
            pointRadius: 6,
            pointHoverRadius: 8.5
        });
    }

    if (q4Points.length > 0) {
        datasets.push({
            label: "Standard Hygiene (Q4)",
            data: q4Points,
            backgroundColor: "#38bdf8",
            borderColor: "#ffffff",
            borderWidth: 1.25,
            pointRadius: 5.5,
            pointHoverRadius: 8
        });
    }

    epssCvssChart = new Chart(ctx, {
        type: "scatter",
        data: { datasets },
        plugins: [epssCvssQuadrantPlugin],
        options: {
            responsive: true,
            maintainAspectRatio: false,
            layout: {
                padding: {
                    left: 12,
                    right: 28,
                    top: 14,
                    bottom: 10
                }
            },
            animation: { duration: 300 },
            plugins: {
                legend: {
                    display: true,
                    position: "top",
                    labels: {
                        color: colors.tickColor,
                        font: { size: 11, weight: "500" },
                        boxWidth: 9,
                        boxHeight: 9,
                        usePointStyle: true,
                        pointStyle: "circle",
                        padding: 16
                    }
                },
                tooltip: {
                    backgroundColor: colors.tooltipBg,
                    borderColor: "rgba(244, 63, 94, 0.4)",
                    borderWidth: 1.5,
                    padding: 12,
                    cornerRadius: 8,
                    titleColor: colors.tooltipTitle,
                    bodyColor: colors.tooltipBody,
                    titleFont: { size: 12, weight: "bold" },
                    bodyFont: { size: 11, lineHeight: 1.5 },
                    callbacks: {
                        title: (tooltipItems) => {
                            const p = tooltipItems[0].raw;
                            return `${p.cve}: ${p.title}`;
                        },
                        label: (tooltipItem) => {
                            const p = tooltipItem.raw;
                            const kevBadge = p.isKev ? "🚨 Actively Exploited in Wild (CISA KEV)" : "🛡️ Standard Advisory (Not in CISA KEV)";
                            let quadrantName = "";
                            let recAction = "";
                            if (p.rawCvss >= 7.0 && p.rawEpss >= 50.0) {
                                quadrantName = "Q1: Critical Weaponized Risk";
                                recAction = "Immediate 24–48h hotfix / patch deployment required";
                            } else if (p.rawCvss >= 7.0 && p.rawEpss < 50.0) {
                                quadrantName = "Q2: High Theoretical Severity";
                                recAction = "Deploy compensating EDR/WAF controls & threat watch";
                            } else if (p.rawCvss < 7.0 && p.rawEpss >= 50.0) {
                                quadrantName = "Q3: Opportunistic Threat";
                                recAction = "Fast automated fleet patch (automated bot exploits detected)";
                            } else {
                                quadrantName = "Q4: Standard Hygiene";
                                recAction = "Standard 30–60 day scheduled maintenance cycle";
                            }

                            return [
                                `Target Asset: ${p.asset} (${p.criticality})`,
                                `Technical Severity: CVSS ${p.rawCvss.toFixed(1)} / 10.0`,
                                `Exploit Likelihood: EPSS ${p.rawEpss.toFixed(1)}%`,
                                `CISA Status: ${kevBadge}`,
                                `Decision Quadrant: ${quadrantName}`,
                                `Recommended SLA: ${recAction}`
                            ];
                        }
                    }
                }
            },
            scales: {
                x: {
                    title: {
                        display: true,
                        text: "Technical Severity Score (CVSS v3.1 / v4.0)",
                        color: colors.tickColor,
                        font: { size: 11, weight: "bold" },
                        padding: { top: 8 }
                    },
                    min: 4.0,
                    max: 10.2,
                    grid: { color: colors.gridColor },
                    ticks: {
                        color: colors.tickColor,
                        stepSize: 1.0,
                        callback: (v) => (v <= 10.0 ? (v === 10 ? "10.0" : v.toFixed(1)) : "")
                    }
                },
                y: {
                    title: {
                        display: true,
                        text: "Exploitation Likelihood (EPSS %)",
                        color: colors.tickColor,
                        font: { size: 11, weight: "bold" },
                        padding: { bottom: 8 }
                    },
                    min: 0,
                    max: 104,
                    grid: { color: colors.gridColor },
                    ticks: {
                        color: colors.tickColor,
                        stepSize: 20,
                        callback: (v) => (v <= 100 ? `${v}%` : "")
                    }
                }
            }
        }
    });
}


// ---------------- POPUP AI CYBER RISK COPILOT (RiskLens Memory & History) ----------------
let copilotSessionId = localStorage.getItem("risklens_copilot_session_id");
if (!copilotSessionId) {
    copilotSessionId = "sess_" + Math.random().toString(36).substring(2, 12);
    localStorage.setItem("risklens_copilot_session_id", copilotSessionId);
}
let copilotHistoryLoaded = false;

async function openCopilotModal() {
    const modal = document.getElementById("copilot-modal");
    if (modal) {
        modal.classList.remove("hidden");
        updateContextualTopicPills(currentActiveTab);
        const input = document.getElementById("copilot-input");
        if (input) setTimeout(() => input.focus(), 100);
        const chatWindow = document.getElementById("copilot-chat-window");
        if (chatWindow) chatWindow.scrollTop = chatWindow.scrollHeight;

        // Automatically load persistent conversation memory if not yet loaded
        if (!copilotHistoryLoaded) {
            await loadCopilotHistory();
        }
    }
    if (window.lucide) lucide.createIcons();
}

function closeCopilotModal() {
    const modal = document.getElementById("copilot-modal");
    if (modal) modal.classList.add("hidden");
}

function updateCopilotMemoryBadge(turnsCount) {
    const textEl = document.getElementById("copilot-memory-text");
    if (textEl) {
        if (turnsCount > 0) {
            textEl.innerText = `Memory: ${turnsCount} turns`;
        } else {
            textEl.innerText = "Memory Active";
        }
    }
}

async function loadCopilotHistory() {
    try {
        const headers = {};
        if (authToken) headers["Authorization"] = `Bearer ${authToken}`;
        const res = await fetch(`/api/assistant/history?session_id=${encodeURIComponent(copilotSessionId)}`, { headers });
        if (!res.ok) return;
        const data = await res.json();
        const messages = data.messages || [];

        if (messages.length > 0) {
            const chatWindow = document.getElementById("copilot-chat-window");
            if (chatWindow) {
                chatWindow.innerHTML = "";
                messages.forEach(msg => {
                    if (msg.role === "user") {
                        const userDiv = document.createElement("div");
                        userDiv.className = "flex items-start justify-end space-x-2";
                        userDiv.innerHTML = `
                            <div class="p-3.5 rounded-2xl rounded-tr-none text-xs sm:text-sm bg-gradient-to-r from-purple-600 to-indigo-600 text-white max-w-xl shadow-md shadow-purple-600/30 leading-relaxed">
                                ${escapeHtml(msg.content)}
                            </div>
                        `;
                        chatWindow.appendChild(userDiv);
                    } else {
                        const botDiv = document.createElement("div");
                        botDiv.className = "flex items-start space-x-3";
                        const formatted = renderCopilotMarkdown(msg.content, msg.suggested_next_questions || []);
                        botDiv.innerHTML = `
                            <div class="h-7 w-7 rounded-lg bg-purple-600/20 border border-purple-500/30 text-purple-400 flex items-center justify-center flex-shrink-0 mt-0.5">
                                <i data-lucide="bot" class="w-3.5 h-3.5"></i>
                            </div>
                            <div class="copilot-bot-bubble bg-[#131722] border border-[#1e2330] p-4 rounded-2xl rounded-tl-sm text-xs sm:text-sm text-zinc-200 leading-relaxed max-w-2xl shadow-sm" data-raw-content="${escapeHtml(msg.content).replace(/"/g, '&quot;')}">
                                ${formatted}
                            </div>
                        `;
                        chatWindow.appendChild(botDiv);
                    }
                });
                chatWindow.scrollTop = chatWindow.scrollHeight;
                if (window.lucide) lucide.createIcons();
            }
            updateCopilotMemoryBadge(messages.length);
        }
        copilotHistoryLoaded = true;
    } catch (e) {
        console.warn("Could not load copilot history from backend:", e);
    }
}

async function clearCopilotChat() {
    try {
        const headers = {};
        if (authToken) headers["Authorization"] = `Bearer ${authToken}`;
        await fetch(`/api/assistant/history?session_id=${encodeURIComponent(copilotSessionId)}`, {
            method: "DELETE",
            headers
        });
    } catch (e) {
        console.warn("Failed to clear backend chat memory:", e);
    }

    // Refresh local session ID for a fresh clean memory thread
    copilotSessionId = "sess_" + Math.random().toString(36).substring(2, 12);
    localStorage.setItem("risklens_copilot_session_id", copilotSessionId);
    copilotHistoryLoaded = true;

    const chatWindow = document.getElementById("copilot-chat-window");
    if (chatWindow) {
        chatWindow.innerHTML = `
            <div class="flex items-start space-x-3">
                <div class="h-7 w-7 rounded-lg bg-purple-600/20 border border-purple-500/30 text-purple-400 flex items-center justify-center flex-shrink-0 mt-0.5">
                    <i data-lucide="sparkles" class="w-3.5 h-3.5"></i>
                </div>
                <div class="bg-[#131722] border border-[#1e2330] p-4 rounded-2xl rounded-tl-sm text-zinc-200 leading-relaxed max-w-xl shadow-sm space-y-2">
                    <p>Conversation history and memory reset. I am the <strong>RiskLens Integrated AI Assistant</strong>:</p>
                    <ul class="text-xs text-zinc-300 space-y-1 pl-4 list-disc">
                        <li><strong>AI Risk Identification & 5x5 Matrix Scoring</strong> (inherent vs. residual risk, crown jewel assets & root causes).</li>
                        <li><strong>AI Mitigation Recommendations</strong> (P0/P1/P2 practical controls, implementation steps, effort, team ownership & ROSI).</li>
                        <li><strong>AI Risk Reports & Dossiers</strong> (Executive summaries, risk assessments, mitigation plans, department-wise summaries with evidence & assumptions).</li>
                        <li><strong>Every single dashboard & component</strong> (Boardroom, Optimizer, What-If Studio, Compliance Radar, Asset Explorer, Data Exchange).</li>
                        <li><strong>How it works & mathematical models</strong> (Open FAIR™ standard, 10k Monte Carlo runs, 0-1 Knapsack MILP, ROSI, Beta-PERT & Poisson).</li>
                    </ul>
                    <p class="text-[11px] text-zinc-400 pt-1">Click any topic above or ask any question below!</p>
                </div>
            </div>
        `;
        if (window.lucide) lucide.createIcons();
    }
    updateCopilotMemoryBadge(0);
    showToast("Conversation memory cleared successfully.", "info");
}

function triggerDocUpload() {
    const input = document.getElementById("copilot-doc-file-input");
    if (input) {
        input.value = "";
        input.click();
    }
}

async function handleDocFileSelected(event) {
    const file = event.target.files && event.target.files[0];
    if (!file) return;

    openCopilotModal();
    const chatWindow = document.getElementById("copilot-chat-window");

    // Show user upload badge in chat
    const userDiv = document.createElement("div");
    userDiv.className = "flex items-start justify-end space-x-2";
    const fileSizeKb = (file.size / 1024).toFixed(1);
    userDiv.innerHTML = `
        <div class="p-3.5 rounded-2xl rounded-tr-none text-xs sm:text-sm bg-gradient-to-r from-purple-600 to-indigo-600 text-white max-w-xl shadow-md shadow-purple-600/30 leading-relaxed flex items-center space-x-2.5">
            <i data-lucide="file-text" class="w-4 h-4 text-cyan-300 flex-shrink-0"></i>
            <div>
                <div class="font-bold">Uploaded Document for Intelligence Analysis</div>
                <div class="text-[11px] text-purple-200">${escapeHtml(file.name)} (${fileSizeKb} KB)</div>
            </div>
        </div>
    `;
    chatWindow.appendChild(userDiv);
    chatWindow.scrollTop = chatWindow.scrollHeight;

    // Show loading spinner in chat
    const botLoading = document.createElement("div");
    botLoading.className = "flex items-start space-x-3";
    botLoading.innerHTML = `
        <div class="h-7 w-7 rounded-lg bg-purple-600/20 border border-purple-500/30 text-purple-400 flex items-center justify-center flex-shrink-0 mt-0.5">
            <i data-lucide="sparkles" class="w-3.5 h-3.5 animate-spin"></i>
        </div>
        <div class="bg-[#131722] border border-[#1e2330] p-3.5 rounded-2xl rounded-tl-sm text-xs sm:text-sm text-zinc-400 leading-relaxed max-w-xl">
            Analyzing <strong>${escapeHtml(file.name)}</strong> with Document Intelligence... Extracting risks, controls, policies & vulnerabilities with 5x5 matrix scoring...
        </div>
    `;
    chatWindow.appendChild(botLoading);
    chatWindow.scrollTop = chatWindow.scrollHeight;
    if (window.lucide) lucide.createIcons();

    try {
        const formData = new FormData();
        formData.append("file", file);
        formData.append("session_id", copilotSessionId);

        const headers = {};
        if (authToken) headers["Authorization"] = `Bearer ${authToken}`;

        const res = await fetch("/api/assistant/document-intelligence/upload", {
            method: "POST",
            headers: headers,
            body: formData
        });

        if (!res.ok) {
            const errData = await res.json().catch(() => ({}));
            throw new Error(errData.detail || "Error analyzing document");
        }

        const data = await res.json();
        const rawResponse = data.markdown_summary || "";
        const suggestedQuestions = data.suggested_next_questions || [];
        const formatted = renderCopilotMarkdown(rawResponse, suggestedQuestions);

        botLoading.innerHTML = `
            <div class="h-7 w-7 rounded-lg bg-purple-600/20 border border-purple-500/30 text-purple-400 flex items-center justify-center flex-shrink-0 mt-0.5">
                <i data-lucide="sparkles" class="w-3.5 h-3.5"></i>
            </div>
            <div class="copilot-bot-bubble bg-[#131722] border border-[#1e2330] p-4 rounded-2xl rounded-tl-sm text-xs sm:text-sm text-zinc-200 leading-relaxed max-w-2xl shadow-sm" data-raw-content="${escapeHtml(rawResponse).replace(/"/g, '&quot;')}">
                ${formatted}
            </div>
        `;
        if (window.lucide) lucide.createIcons();
        showToast(`Document Intelligence analysis complete for ${file.name}`, "success");
    } catch (err) {
        botLoading.innerHTML = `
            <div class="h-7 w-7 rounded-lg bg-rose-600/20 border border-rose-500/30 text-rose-400 flex items-center justify-center flex-shrink-0 mt-0.5">
                <i data-lucide="alert-circle" class="w-3.5 h-3.5"></i>
            </div>
            <div class="bg-[#1a1114] border border-rose-500/30 p-3.5 rounded-2xl rounded-tl-sm text-xs sm:text-sm text-rose-300">
                Failed to analyze document: ${escapeHtml(err.message)}
            </div>
        `;
        if (window.lucide) lucide.createIcons();
        showToast("Document analysis failed", "error");
    }
    chatWindow.scrollTop = chatWindow.scrollHeight;
}

function askCopilotPrompt(promptText) {
    openCopilotModal();
    const input = document.getElementById("copilot-input");
    if (input) input.value = "";
    executeCopilotQuery(promptText);
}

function handleCopilotSubmit(event) {
    event.preventDefault();
    const input = document.getElementById("copilot-input");
    const query = input.value.trim();
    if (!query) return;
    executeCopilotQuery(query);
    input.value = "";
}

function renderCopilotMarkdown(rawText, suggestedQuestions = []) {
    let formatted = escapeHtml(rawText);

    // Unescape intentional line breaks
    formatted = formatted.replace(/&lt;br\s*\/?&gt;/gi, "<br/>");

    // Headers
    formatted = formatted.replace(/^### (.*?)$/gm, "<h4 class='text-sm font-bold text-white mt-3.5 mb-1.5 flex items-center space-x-1.5 border-b border-[#1c2233] pb-1'><span>$1</span></h4>");
    formatted = formatted.replace(/^#### (.*?)$/gm, "<h5 class='text-xs font-bold text-indigo-300 mt-2.5 mb-1'>$1</h5>");
    formatted = formatted.replace(/^---$/gm, "<hr class='border-[#1e2330] my-2.5'/>");

    // Parse Markdown Tables before converting newlines
    formatted = formatted.replace(/((?:\|[^\n]+\|\r?\n?)+)/g, function(tableBlock) {
        const rawLines = tableBlock.trim().split(/\r?\n/);
        if (rawLines.length < 2) return tableBlock;
        let sepIdx = -1;
        for (let i = 1; i < rawLines.length; i++) {
            if (/^\|(?:\s*:?-+:?\s*\|)+$/.test(rawLines[i].trim())) {
                sepIdx = i;
                break;
            }
        }
        if (sepIdx > 0) {
            const headerCells = rawLines[0].split("|").filter((_, idx, arr) => idx > 0 && idx < arr.length - 1);
            let thead = "<thead><tr class='bg-[#111728] border-b border-[#232c40]'>";
            headerCells.forEach((c, idx) => {
                const align = idx === 0 ? "text-left" : "text-center";
                thead += `<th class='px-2.5 py-1.5 ${align} text-[11px] font-semibold text-zinc-300 font-mono'>${c.trim()}</th>`;
            });
            thead += "</tr></thead>";

            let tbody = "<tbody class='divide-y divide-[#171e2e]'>";
            for (let i = sepIdx + 1; i < rawLines.length; i++) {
                const rowLine = rawLines[i].trim();
                if (!rowLine) continue;
                const cells = rowLine.split("|").filter((_, ci, arr) => ci > 0 && ci < arr.length - 1);
                tbody += "<tr class='hover:bg-[#121826] transition'>";
                cells.forEach((c, cIdx) => {
                    const align = cIdx === 0 ? "text-left font-medium" : "text-center";
                    tbody += `<td class='px-2.5 py-1.5 text-[11px] text-zinc-300 ${align}'>${c.trim()}</td>`;
                });
                tbody += "</tr>";
            }
            tbody += "</tbody>";

            return `<div class='overflow-x-auto my-3 rounded-xl border border-[#20293d] bg-[#090d16] shadow-sm'><table class='min-w-full divide-y divide-[#20293d]'>${thead}${tbody}</table></div>\n`;
        }
        return tableBlock;
    });

    // Clickable Action Links: [label](action:tab:NAME)
    formatted = formatted.replace(
        /\[(.*?)\]\(action:tab:([a-z0-9_-]+)\)/g,
        "<button type='button' onclick=\"switchTab('$2'); closeCopilotModal();\" class='inline-flex items-center space-x-1 px-2.5 py-1 my-1 mr-1.5 rounded-lg bg-indigo-600/30 hover:bg-indigo-600 text-indigo-300 hover:text-white border border-indigo-500/40 text-xs font-semibold transition cursor-pointer shadow-sm'><span>$1</span></button>"
    );
    // Clickable Modal Links: [label](action:modal:data)
    formatted = formatted.replace(
        /\[(.*?)\]\(action:modal:data\)/g,
        "<button type='button' onclick=\"openDataModal(); closeCopilotModal();\" class='inline-flex items-center space-x-1 px-2.5 py-1 my-1 mr-1.5 rounded-lg bg-purple-600/30 hover:bg-purple-600 text-purple-300 hover:text-white border border-purple-500/40 text-xs font-semibold transition cursor-pointer shadow-sm'><span>$1</span></button>"
    );
    // Dynamic Budget Setting Link: [label](action:set_budget:AMOUNT)
    formatted = formatted.replace(
        /\[(.*?)\]\(action:set_budget:([0-9.]+)\)/g,
        "<button type='button' onclick=\"applyCopilotBudget('$2')\" class='inline-flex items-center space-x-1 px-2.5 py-1 my-1 mr-1.5 rounded-lg bg-emerald-600/30 hover:bg-emerald-600 text-emerald-300 hover:text-white border border-emerald-500/40 text-xs font-semibold transition cursor-pointer shadow-sm'><span>$1</span></button>"
    );
    // Dynamic Dataset Switching Link: [label](action:load_dataset:ID)
    formatted = formatted.replace(
        /\[(.*?)\]\(action:load_dataset:([a-z0-9_-]+)\)/g,
        "<button type='button' onclick=\"applyCopilotDataset('$2')\" class='inline-flex items-center space-x-1 px-2.5 py-1 my-1 mr-1.5 rounded-lg bg-blue-600/30 hover:bg-blue-600 text-blue-300 hover:text-white border border-blue-500/40 text-xs font-semibold transition cursor-pointer shadow-sm'><span>$1</span></button>"
    );
    // Dynamic Scenario Run Link: [label](action:run_scenario:ID)
    formatted = formatted.replace(
        /\[(.*?)\]\(action:run_scenario:([a-zA-Z0-9_-]+)\)/g,
        "<button type='button' onclick=\"applyCopilotScenario('$2')\" class='inline-flex items-center space-x-1 px-2.5 py-1 my-1 mr-1.5 rounded-lg bg-amber-600/30 hover:bg-amber-600 text-amber-300 hover:text-white border border-amber-500/40 text-xs font-semibold transition cursor-pointer shadow-sm'><span>$1</span></button>"
    );
    // Dynamic Currency Setting Link: [label](action:set_currency:CURR)
    formatted = formatted.replace(
        /\[(.*?)\]\(action:set_currency:([A-Z]{3})\)/g,
        "<button type='button' onclick=\"applyCopilotCurrency('$2')\" class='inline-flex items-center space-x-1 px-2.5 py-1 my-1 mr-1.5 rounded-lg bg-cyan-600/30 hover:bg-cyan-600 text-cyan-300 hover:text-white border border-cyan-500/40 text-xs font-semibold transition cursor-pointer shadow-sm'><span>$1</span></button>"
    );
    // Export Full Risk Dossier: [label](action:export_dossier)
    formatted = formatted.replace(
        /\[(.*?)\]\(action:export_dossier\)/g,
        "<button type='button' onclick=\"exportFullDossier()\" class='inline-flex items-center space-x-1 px-2.5 py-1 my-1 mr-1.5 rounded-lg bg-purple-600/30 hover:bg-purple-600 text-purple-300 hover:text-white border border-purple-500/40 text-xs font-semibold transition cursor-pointer shadow-sm'><span>$1</span></button>"
    );
    // Export Chat Conversation: [label](action:export_chat)
    formatted = formatted.replace(
        /\[(.*?)\]\(action:export_chat\)/g,
        "<button type='button' onclick=\"exportCopilotConversation()\" class='inline-flex items-center space-x-1 px-2.5 py-1 my-1 mr-1.5 rounded-lg bg-zinc-600/30 hover:bg-zinc-600 text-zinc-300 hover:text-white border border-zinc-500/40 text-xs font-semibold transition cursor-pointer shadow-sm'><span>$1</span></button>"
    );

    // Code blocks
    formatted = formatted.replace(/```bash\n([\s\S]*?)```/g, "<pre class='bg-[#080b12] p-2.5 rounded-xl text-[11px] font-mono text-zinc-300 border border-[#1e2330] overflow-x-auto my-2'><code>$1</code></pre>");
    formatted = formatted.replace(/```\n([\s\S]*?)```/g, "<pre class='bg-[#080b12] p-2.5 rounded-xl text-[11px] font-mono text-zinc-300 border border-[#1e2330] overflow-x-auto my-2'><code>$1</code></pre>");

    // Inline elements
    formatted = formatted
        .replace(/\n\n/g, "<br/><br/>")
        .replace(/\n/g, "<br/>")
        .replace(/\*\*(.*?)\*\*/g, "<strong class='text-white font-semibold'>$1</strong>")
        .replace(/\*(.*?)\*/g, "<em>$1</em>")
        .replace(/`(.*?)`/g, "<code class='bg-[#101420] px-1 py-0.5 rounded text-amber-300 font-mono text-xs border border-[#1e2330]'>$1</code>");

    // Bullet points
    formatted = formatted.replace(/• (.*?)(?=<br\/>|$)/g, "<span class='flex items-start space-x-1.5 my-0.5'><span class='text-cyan-400 font-bold'>•</span><span>$1</span></span>");

    // Append suggested questions chips if available
    if (suggestedQuestions && suggestedQuestions.length > 0) {
        const chipsHtml = suggestedQuestions.map(sq => {
            const safeSq = escapeHtml(sq);
            return `<button type="button" onclick="askCopilotPrompt('${escapeHtml(sq).replace(/'/g, "\\'")}')" class="px-2.5 py-1 rounded-lg bg-[#0e131f] hover:bg-[#161c2d] text-zinc-300 hover:text-white border border-[#222a3d] hover:border-cyan-500/40 text-[11px] transition whitespace-nowrap cursor-pointer flex items-center space-x-1"><span>${safeSq}</span></button>`;
        }).join("");

        formatted += `
            <div class="mt-3 pt-2.5 border-t border-[#1a2030] space-y-1.5">
                <span class="text-[10px] font-mono text-zinc-500 uppercase tracking-wider block">Suggested Next Questions:</span>
                <div class="flex flex-wrap gap-1.5">
                    ${chipsHtml}
                </div>
            </div>
        `;
    }

    // Add Integrated AI header banner with 1-click Copy button
    const headerBar = `
        <div class="flex items-center justify-between border-b border-[#1c2233] pb-1.5 mb-2.5">
            <span class="text-[10px] font-mono text-cyan-400 font-semibold tracking-wider flex items-center space-x-1">
                <i data-lucide="sparkles" class="w-3 h-3 text-cyan-400"></i>
                <span>RISKLENS INTEGRATED AI</span>
            </span>
            <button type="button" onclick="copyCopilotResponse(this)" class="text-[11px] font-medium text-zinc-400 hover:text-white px-2 py-0.5 rounded-lg bg-[#0e131f] hover:bg-zinc-800 border border-[#222a3d] transition flex items-center space-x-1 cursor-pointer" title="Copy response text">
                <i data-lucide="copy" class="w-3 h-3"></i>
                <span>Copy</span>
            </button>
        </div>
    `;

    return headerBar + formatted;
}

async function executeCopilotQuery(query) {
    const chatWindow = document.getElementById("copilot-chat-window");

    // Append user message with full HTML entity escaping
    const userDiv = document.createElement("div");
    userDiv.className = "flex items-start justify-end space-x-2";
    const safeQuery = escapeHtml(query);
    userDiv.innerHTML = `
        <div class="p-3.5 rounded-2xl rounded-tr-none text-xs sm:text-sm bg-gradient-to-r from-purple-600 to-indigo-600 text-white max-w-xl shadow-md shadow-purple-600/30 leading-relaxed">
            ${safeQuery}
        </div>
    `;
    chatWindow.appendChild(userDiv);
    chatWindow.scrollTop = chatWindow.scrollHeight;

    // Loading placeholder
    const botLoading = document.createElement("div");
    botLoading.className = "flex items-start space-x-3";
    botLoading.innerHTML = `
        <div class="h-7 w-7 rounded-lg bg-purple-600/20 border border-purple-500/30 text-purple-400 flex items-center justify-center flex-shrink-0 mt-0.5">
            <i data-lucide="sparkles" class="w-3.5 h-3.5 animate-spin"></i>
        </div>
        <div class="bg-[#131722] border border-[#1e2330] p-3.5 rounded-2xl rounded-tl-sm text-xs sm:text-sm text-zinc-400 leading-relaxed max-w-xl">
            Recalling conversation memory, analyzing project telemetry & synthesizing answer...
        </div>
    `;
    chatWindow.appendChild(botLoading);
    chatWindow.scrollTop = chatWindow.scrollHeight;
    if (window.lucide) lucide.createIcons();

    try {
        const headers = { "Content-Type": "application/json" };
        if (authToken) headers["Authorization"] = `Bearer ${authToken}`;

        const res = await fetch("/api/assistant/query", {
            method: "POST",
            headers: headers,
            body: JSON.stringify({
                query: query,
                session_id: copilotSessionId,
                active_tab: currentActiveTab
            })
        });
        if (!res.ok) {
            const errData = await res.json().catch(() => ({}));
            throw new Error(errData.detail || "Server error processing inquiry");
        }
        const data = await res.json();

        // Update memory badge with remembered turns
        if (data.turns_remembered) {
            updateCopilotMemoryBadge(data.turns_remembered);
        }

        // Convert structured markdown to HTML safely with action buttons & chips
        const rawResponse = data.response_markdown || "";
        const suggestedQuestions = data.suggested_next_questions || [];
        const formatted = renderCopilotMarkdown(rawResponse, suggestedQuestions);

        botLoading.innerHTML = `
            <div class="h-7 w-7 rounded-lg bg-purple-600/20 border border-purple-500/30 text-purple-400 flex items-center justify-center flex-shrink-0 mt-0.5">
                <i data-lucide="sparkles" class="w-3.5 h-3.5"></i>
            </div>
            <div class="copilot-bot-bubble bg-[#131722] border border-[#1e2330] p-4 rounded-2xl rounded-tl-sm text-xs sm:text-sm text-zinc-200 leading-relaxed max-w-2xl shadow-sm" data-raw-content="${escapeHtml(rawResponse).replace(/"/g, '&quot;')}">
                ${formatted}
            </div>
        `;
        if (window.lucide) lucide.createIcons();
    } catch (err) {
        botLoading.innerHTML = `
            <div class="h-7 w-7 rounded-lg bg-rose-600/20 border border-rose-500/30 text-rose-400 flex items-center justify-center flex-shrink-0 mt-0.5">
                <i data-lucide="alert-circle" class="w-3.5 h-3.5"></i>
            </div>
            <div class="bg-[#1a1114] border border-rose-500/30 p-3.5 rounded-2xl rounded-tl-sm text-xs sm:text-sm text-rose-300">
                Sorry, I encountered an error while processing your query. Please verify that the platform service is running.
            </div>
        `;
        if (window.lucide) lucide.createIcons();
    }
    chatWindow.scrollTop = chatWindow.scrollHeight;
}

// ================= AI COPILOT INTERACTIVE ACTIONS & TOOLS =================

function applyCopilotBudget(amountInr) {
    const amount = parseFloat(amountInr);
    if (isNaN(amount) || amount <= 0) return;

    switchTab("optimizer");
    closeCopilotModal();

    const slider = document.getElementById("budget-slider");
    if (slider) {
        slider.value = amount;
        updateSliderLabel(amount);
    }
    fetchOptimization(amount);
    showToast(`Integrated AI applied budget: ₹${(amount / 10000000).toFixed(2)} Crore`, "success");
}

async function applyCopilotDataset(datasetId) {
    closeCopilotModal();
    showToast(`Integrated AI loading ${datasetId} telemetry...`, "info");
    await onSelectIndustryDataset(datasetId);
}

async function applyCopilotScenario(scenarioId) {
    switchTab("scenarios");
    closeCopilotModal();
    selectScenario(scenarioId);
    await runActiveScenario();
    showToast("Integrated AI executed scenario stress test", "success");
}

function applyCopilotCurrency(curr) {
    setCurrency(curr);
    showToast(`Integrated AI switched display currency to ${curr}`, "info");
}

async function copyCopilotResponse(button) {
    try {
        const bubble = button.closest(".copilot-bot-bubble");
        if (!bubble) return;
        const textToCopy = bubble.getAttribute("data-raw-content") || bubble.innerText;
        await navigator.clipboard.writeText(textToCopy);
        const originalHtml = button.innerHTML;
        button.innerHTML = `<i data-lucide="check" class="w-3 h-3 text-emerald-400"></i><span class="text-emerald-400 font-semibold">Copied!</span>`;
        if (window.lucide) lucide.createIcons();
        setTimeout(() => {
            button.innerHTML = originalHtml;
            if (window.lucide) lucide.createIcons();
        }, 2000);
    } catch (e) {
        showToast("Failed to copy response text", "error");
    }
}

async function exportCopilotConversation() {
    try {
        showToast("Generating Executive AI Briefing report...", "info");
        const headers = {};
        if (authToken) headers["Authorization"] = `Bearer ${authToken}`;
        const res = await fetch(`/api/assistant/history?session_id=${encodeURIComponent(copilotSessionId)}`, { headers });
        if (!res.ok) throw new Error("Could not fetch conversation history");
        const data = await res.json();
        const messages = data.messages || [];

        if (messages.length === 0) {
            showToast("No conversation history to export yet.", "warning");
            return;
        }

        const nowStr = new Date().toISOString();
        let md = `# RiskLens AI Executive Cyber Risk Briefing\n\n`;
        md += `**Generated**: ${nowStr}\n`;
        md += `**Session ID**: \`${copilotSessionId}\`\n`;
        if (riskSummaryData) {
            md += `**Enterprise Risk Score**: ${riskSummaryData.enterprise_risk_score}/100\n`;
            md += `**Expected Annual Loss (EAL)**: ₹${riskSummaryData.expected_annual_loss_inr.toLocaleString()} ($${riskSummaryData.expected_annual_loss_usd.toLocaleString()} USD)\n`;
            md += `**95% Value at Risk (VaR)**: ₹${riskSummaryData.var_95_inr.toLocaleString()}\n`;
        }
        md += `\n---\n\n## Conversational Transcript\n\n`;

        messages.forEach((m, idx) => {
            const role = m.role === "user" ? "### 👤 Executive Inquiry" : "### 🤖 RiskLens AI Intelligence";
            md += `${role} (${m.created_at || "Turn " + (idx + 1)})\n\n${m.content}\n\n---\n\n`;
        });

        // Trigger file download
        const blob = new Blob([md], { type: "text/markdown;charset=utf-8" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `RiskLens_AI_Briefing_${new Date().toISOString().slice(0, 10)}.md`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

        showToast("Executive Briefing downloaded successfully.", "success");
    } catch (e) {
        showToast("Failed to export briefing: " + e.message, "error");
    }
}

function updateContextualTopicPills(tabName) {
    const pillsContainer = document.getElementById("copilot-topic-pills");
    if (!pillsContainer) return;

    let pills = [];
    if (tabName === "optimizer") {
        pills = [
            { label: "👋 Hi / Help", prompt: "Hi, I need help exploring our cyber risks", icon: "sparkles", color: "cyan" },
            { label: "🧠 Retrain (100x)", prompt: "Retrain it 100 times and fine tune 20x times more", icon: "cpu", color: "indigo" },
            { label: "💡 AI Insights", prompt: "Identify recurring risks, weak controls, risk trends and areas requiring management attention", icon: "lightbulb", color: "amber" },
            { label: "📜 Compliance Assistant", prompt: "Map our identified risks and controls to relevant frameworks like ISO 27001, NIST CSF and regulatory requirements", icon: "scale", color: "purple" },
            { label: "📡 Risk Monitoring", prompt: "Reassess risks after our latest asset, control, and incident updates", icon: "activity", color: "emerald" },
            { label: "🔍 Root Cause", prompt: "Perform root cause analysis on our top risk to identify underlying causes and dependencies", icon: "search-code", color: "violet" },
            { label: "🧪 Scenario Analysis", prompt: "What happens if our primary server goes offline?", icon: "flask-conical", color: "amber" },
            { label: "⚡ Prioritize Risks", prompt: "Rank our enterprise risks based on severity, business impact, urgency and existing controls", icon: "zap", color: "red" },
            { label: "0-1 Knapsack & ROSI", prompt: "How does the Investment Optimizer and 0-1 Knapsack work?", icon: "trending-up", color: "emerald" },
            { label: "Diminishing Returns Knee", prompt: "What is the threshold of diminishing returns on the efficient frontier?", icon: "activity", color: "amber" },
            { label: "Optimize ₹1.5 Cr Budget", prompt: "How should we allocate a 1.5 crore security budget?", icon: "zap", color: "cyan" },
            { label: "Highest ROSI Controls", prompt: "Which security initiatives have the highest ROSI?", icon: "check-circle", color: "indigo" },
        ];
    } else if (tabName === "scenarios") {
        pills = [
            { label: "👋 Hi / Help", prompt: "Hi, I need help exploring our cyber risks", icon: "sparkles", color: "cyan" },
            { label: "🧠 Retrain (100x)", prompt: "Retrain it 100 times and fine tune 20x times more", icon: "cpu", color: "indigo" },
            { label: "💡 AI Insights", prompt: "Identify recurring risks, weak controls, risk trends and areas requiring management attention", icon: "lightbulb", color: "amber" },
            { label: "📜 Compliance Assistant", prompt: "Map our identified risks and controls to relevant frameworks like ISO 27001, NIST CSF and regulatory requirements", icon: "scale", color: "purple" },
            { label: "📡 Risk Monitoring", prompt: "Reassess risks after our latest asset, control, and incident updates", icon: "activity", color: "emerald" },
            { label: "🔍 Root Cause", prompt: "Perform root cause analysis on our top risk to identify underlying causes and dependencies", icon: "search-code", color: "violet" },
            { label: "🧪 Primary Server Offline?", prompt: "What happens if our primary server goes offline?", icon: "flask-conical", color: "amber" },
            { label: "⚡ Prioritize Risks", prompt: "Rank our enterprise risks based on severity, business impact, urgency and existing controls", icon: "zap", color: "red" },
            { label: "Simulate Ransomware", prompt: "Run ransomware scenario on core switch", icon: "alert-triangle", color: "rose" },
            { label: "30-Day Patch Delay", prompt: "What happens if we delay patching by 30 days?", icon: "clock", color: "amber" },
            { label: "100% MFA Rollout", prompt: "What is the impact of enforcing Phishing-Resistant MFA?", icon: "lock", color: "emerald" },
            { label: "Identify Threat: DB/S3", prompt: "Our customer database is publicly accessible", icon: "crosshair", color: "rose" },
        ];
    } else if (tabName === "compliance") {
        pills = [
            { label: "👋 Hi / Help", prompt: "Hi, I need help exploring our cyber risks", icon: "sparkles", color: "cyan" },
            { label: "🧠 Retrain (100x)", prompt: "Retrain it 100 times and fine tune 20x times more", icon: "cpu", color: "indigo" },
            { label: "💡 AI Insights", prompt: "Identify recurring risks, weak controls, risk trends and areas requiring management attention", icon: "lightbulb", color: "amber" },
            { label: "📜 Compliance Assistant", prompt: "Map our identified risks and controls to relevant frameworks like ISO 27001, NIST CSF and regulatory requirements", icon: "scale", color: "purple" },
            { label: "📡 Risk Monitoring", prompt: "Reassess risks after our latest asset, control, and incident updates", icon: "activity", color: "emerald" },
            { label: "🔍 Root Cause", prompt: "Perform root cause analysis on our top risk to identify underlying causes and dependencies", icon: "search-code", color: "violet" },
            { label: "🧪 Scenario Analysis", prompt: "What happens if our primary server goes offline?", icon: "flask-conical", color: "amber" },
            { label: "⚡ Prioritize Risks", prompt: "Rank our enterprise risks based on severity, business impact, urgency and existing controls", icon: "zap", color: "red" },
            { label: "Identify Risk: Public DB", prompt: "Our customer database is publicly accessible", icon: "crosshair", color: "rose" },
            { label: "Audit Findings & Gaps", prompt: "What are our compliance audit findings?", icon: "alert-circle", color: "rose" },
            { label: "DPDP Act Penalties", prompt: "What is statutory penalty exposure under DPDP Act 2023?", icon: "scale", color: "purple" },
            { label: "Compliance Radar Scoring", prompt: "Explain the Regulatory & Compliance Framework Radar", icon: "radar", color: "indigo" },
        ];
    } else if (tabName === "assets") {
        pills = [
            { label: "👋 Hi / Help", prompt: "Hi, I need help exploring our cyber risks", icon: "sparkles", color: "cyan" },
            { label: "🧠 Retrain (100x)", prompt: "Retrain it 100 times and fine tune 20x times more", icon: "cpu", color: "indigo" },
            { label: "💡 AI Insights", prompt: "Identify recurring risks, weak controls, risk trends and areas requiring management attention", icon: "lightbulb", color: "amber" },
            { label: "📜 Compliance Assistant", prompt: "Map our identified risks and controls to relevant frameworks like ISO 27001, NIST CSF and regulatory requirements", icon: "scale", color: "purple" },
            { label: "📡 Risk Monitoring", prompt: "Reassess risks after our latest asset, control, and incident updates", icon: "activity", color: "emerald" },
            { label: "🔍 Root Cause", prompt: "Perform root cause analysis on our top risk to identify underlying causes and dependencies", icon: "search-code", color: "violet" },
            { label: "🧪 Scenario Analysis", prompt: "What happens if our primary server goes offline?", icon: "flask-conical", color: "amber" },
            { label: "⚡ Prioritize Risks", prompt: "Rank our enterprise risks based on severity, business impact, urgency and existing controls", icon: "zap", color: "red" },
            { label: "Identify Risk: Public DB", prompt: "Our customer database is publicly accessible", icon: "crosshair", color: "rose" },
            { label: "EPSS vs CVSS Matrix", prompt: "How does the EPSS vs CVSS exploit matrix prioritize vulnerabilities?", icon: "crosshair", color: "rose" },
            { label: "CISA KEV Exploits", prompt: "Which assets have active CISA KEV exploitation weaponization?", icon: "flame", color: "amber" },
            { label: "Downtime Outage Cost", prompt: "What is the downtime cost of our top asset?", icon: "clock", color: "emerald" },
        ];
    } else {
        // Default / Boardroom
        pills = [
            { label: "👋 Hi / Help", prompt: "Hi, I need help exploring our cyber risks", icon: "sparkles", color: "cyan" },
            { label: "🧠 Retrain (100x)", prompt: "Retrain it 100 times and fine tune 20x times more", icon: "cpu", color: "indigo" },
            { label: "💡 AI Insights", prompt: "Identify recurring risks, weak controls, risk trends and areas requiring management attention", icon: "lightbulb", color: "amber" },
            { label: "📜 Compliance Assistant", prompt: "Map our identified risks and controls to relevant frameworks like ISO 27001, NIST CSF and regulatory requirements", icon: "scale", color: "purple" },
            { label: "📡 Risk Monitoring", prompt: "Reassess risks after our latest asset, control, and incident updates", icon: "activity", color: "emerald" },
            { label: "🔍 Root Cause", prompt: "Perform root cause analysis on our top risk to identify underlying causes and dependencies", icon: "search-code", color: "violet" },
            { label: "🧪 Scenario Analysis", prompt: "What happens if our primary server goes offline?", icon: "flask-conical", color: "amber" },
            { label: "⚡ Risk Prioritization", prompt: "Rank our enterprise risks based on severity, business impact, urgency and existing controls", icon: "zap", color: "red" },
            { label: "🎯 AI Risk Identifier", prompt: "Our customer database is publicly accessible", icon: "crosshair", color: "rose" },
            { label: "All Web Components", prompt: "Explain every single dashboard and component on main web page", icon: "layout-grid", color: "indigo" },
            { label: "How It Works & Math", prompt: "How does RiskLens work and what are its mathematical foundations?", icon: "binary", color: "cyan" },
            { label: "EAL vs 95% VaR", prompt: "Explain the difference between EAL and 95% Value at Risk (VaR)", icon: "bar-chart-2", color: "purple" },
            { label: "Risk Drift Forecast", prompt: "What is our 90-day risk trajectory forecast if we do nothing?", icon: "trending-up", color: "amber" },
        ];
    }

    const html = `<span class="text-[10px] font-mono text-zinc-500 uppercase tracking-wider flex-shrink-0 mr-1">Topics:</span>` +
        pills.map(p => `
            <button type="button" onclick="askCopilotPrompt('${escapeHtml(p.prompt).replace(/'/g, "\\'")}')" class="px-2.5 py-1 rounded-lg bg-${p.color}-500/10 hover:bg-${p.color}-500/20 text-${p.color}-300 border border-${p.color}-500/30 font-medium whitespace-nowrap transition flex items-center space-x-1 cursor-pointer">
                <i data-lucide="${p.icon}" class="w-3 h-3 text-${p.color}-400"></i>
                <span>${escapeHtml(p.label)}</span>
            </button>
        `).join("");

    pillsContainer.innerHTML = html;
    if (window.lucide) lucide.createIcons();
}


// ================= AUTHENTICATION & SESSION MANAGEMENT =================

function showAuthAlert(message, type = "error") {
    const alertBox = document.getElementById("auth-alert");
    if (!alertBox) return;

    alertBox.classList.remove("hidden", "bg-rose-500/10", "border-rose-500/30", "text-rose-300", "bg-emerald-500/10", "border-emerald-500/30", "text-emerald-300");

    if (type === "success") {
        alertBox.className = "p-3.5 rounded-xl text-xs border bg-emerald-500/10 border-emerald-500/30 text-emerald-300 flex items-center space-x-2";
        alertBox.innerHTML = `<i data-lucide="check-circle" class="w-4 h-4 flex-shrink-0"></i><span>${message}</span>`;
    } else {
        alertBox.className = "p-3.5 rounded-xl text-xs border bg-rose-500/10 border-rose-500/30 text-rose-300 flex items-center space-x-2";
        alertBox.innerHTML = `<i data-lucide="alert-circle" class="w-4 h-4 flex-shrink-0"></i><span>${message}</span>`;
    }
    if (window.lucide) lucide.createIcons();
}

function clearAuthAlert() {
    const alertBox = document.getElementById("auth-alert");
    if (alertBox) alertBox.classList.add("hidden");
}

function switchAuthMode(mode) {
    clearAuthAlert();
    const signinTab = document.getElementById("tab-auth-signin");
    const signupTab = document.getElementById("tab-auth-signup");
    const signinForm = document.getElementById("form-signin");
    const signupForm = document.getElementById("form-signup");
    const forgotView = document.getElementById("auth-forgot-view");
    const authNav = document.getElementById("auth-nav-tabs");

    if (mode === "signin") {
        authNav.classList.remove("hidden");
        signinForm.classList.remove("hidden");
        signupForm.classList.add("hidden");
        forgotView.classList.add("hidden");

        signinTab.classList.add("active");
        signupTab.classList.remove("active");
    } else if (mode === "signup") {
        authNav.classList.remove("hidden");
        signupForm.classList.remove("hidden");
        signinForm.classList.add("hidden");
        forgotView.classList.add("hidden");

        signupTab.classList.add("active");
        signinTab.classList.remove("active");
    } else if (mode === "forgot") {
        authNav.classList.add("hidden");
        forgotView.classList.remove("hidden");
        signinForm.classList.add("hidden");
        signupForm.classList.add("hidden");

        // Reset forgot sub-forms
        document.getElementById("form-forgot-request").classList.remove("hidden");
        document.getElementById("form-reset-password").classList.add("hidden");
    }
    if (window.lucide) lucide.createIcons();
}

function showDashboard(user) {
    currentUser = user;
    const loginPage = document.getElementById("login-page");
    if (loginPage) loginPage.classList.add("hidden");
    const appHeader = document.getElementById("app-header");
    if (appHeader) appHeader.classList.remove("hidden");
    document.getElementById("dashboard-container").classList.remove("hidden");
    document.getElementById("nav-tabs-container").classList.remove("hidden");
    document.getElementById("nav-tabs-container").classList.add("flex");

    const profileEl = document.getElementById("header-user-profile");
    profileEl.classList.remove("hidden");
    profileEl.classList.add("flex");

    // Populate user profile in header
    document.getElementById("user-display-name").innerText = user.full_name;
    const shortRole = user.role.split("(")[0].replace("Chief", "Chief").trim();
    document.getElementById("user-display-role").innerText = shortRole;

    const parts = user.full_name.trim().split(" ");
    const initials = (parts[0][0] + (parts.length > 1 ? parts[parts.length - 1][0] : "")).toUpperCase();
    document.getElementById("user-avatar-initials").innerText = initials;

    // Immediate primary render: Boardroom KPIs and core charts
    loadExecutiveDashboard();

    // Staged non-blocking pre-fetch: Optimizer loaded without competing for initial frame budget
    setTimeout(() => {
        if (!optimizerLoaded) {
            fetchOptimization(10000000.0);
        }
    }, 120);

    if (window.lucide) lucide.createIcons();
}

function showAuth(mode = "signin") {
    currentUser = null;
    optimizerLoaded = false;
    complianceLoaded = false;
    const loginPage = document.getElementById("login-page");
    if (loginPage) loginPage.classList.remove("hidden");
    const appHeader = document.getElementById("app-header");
    if (appHeader) appHeader.classList.add("hidden");
    document.getElementById("dashboard-container").classList.add("hidden");
    document.getElementById("nav-tabs-container").classList.add("hidden");
    document.getElementById("nav-tabs-container").classList.remove("flex");

    const profileEl = document.getElementById("header-user-profile");
    profileEl.classList.add("hidden");
    profileEl.classList.remove("flex");

    // Ensure all auth inputs are completely empty
    const signinForm = document.getElementById("form-signin");
    if (signinForm) signinForm.reset();
    const signupForm = document.getElementById("form-signup");
    if (signupForm) signupForm.reset();
    const forgotForm = document.getElementById("form-forgot-request");
    if (forgotForm) forgotForm.reset();
    const resetForm = document.getElementById("form-reset-password");
    if (resetForm) resetForm.reset();

    const meterBar = document.getElementById("signup-pw-meter-bar");
    if (meterBar) meterBar.style.width = "0%";
    const meterLabel = document.getElementById("signup-pw-meter-label");
    if (meterLabel) meterLabel.innerText = "";

    switchAuthMode(mode);
    if (window.lucide) lucide.createIcons();
}

function togglePasswordVisibility(inputId, iconId) {
    const input = document.getElementById(inputId);
    const icon = document.getElementById(iconId);
    if (!input || !icon) return;

    if (input.type === "password") {
        input.type = "text";
        icon.setAttribute("data-lucide", "eye-off");
    } else {
        input.type = "password";
        icon.setAttribute("data-lucide", "eye");
    }
    if (window.lucide) lucide.createIcons();
}

function checkPasswordStrength(val) {
    const bar = document.getElementById("signup-pw-meter-bar");
    const label = document.getElementById("signup-pw-meter-label");
    if (!bar || !label) return;

    if (!val) {
        bar.style.width = "0%";
        label.innerText = "";
        return;
    }

    let score = 0;
    if (val.length >= 6) score += 1;
    if (val.length >= 10) score += 1;
    if (/[0-9]/.test(val)) score += 1;
    if (/[^A-Za-z0-9]/.test(val)) score += 1;

    if (score <= 1) {
        bar.style.width = "30%";
        bar.className = "h-full rounded-full transition-all duration-300 bg-rose-500";
        label.innerText = "Weak";
        label.className = "text-[10px] font-semibold text-rose-400";
    } else if (score <= 3) {
        bar.style.width = "65%";
        bar.className = "h-full rounded-full transition-all duration-300 bg-amber-500";
        label.innerText = "Medium";
        label.className = "text-[10px] font-semibold text-amber-400";
    } else {
        bar.style.width = "100%";
        bar.className = "h-full rounded-full transition-all duration-300 bg-emerald-500";
        label.innerText = "Strong";
        label.className = "text-[10px] font-semibold text-emerald-400";
    }
}

async function checkAuthSession() {
    if (!authToken) {
        showAuth("signin");
        return;
    }

    try {
        const res = await fetch("/api/auth/me", {
            headers: { "Authorization": `Bearer ${authToken}` }
        });

        if (res.ok) {
            const user = await res.json();
            showDashboard(user);
        } else {
            // Invalid or expired token
            localStorage.removeItem("risklens_auth_token");
            authToken = null;
            showAuth("signin");
        }
    } catch (err) {
        console.error("Session check failed:", err);
        showAuth("signin");
    }
}

async function handleSignInSubmit(event) {
    event.preventDefault();
    clearAuthAlert();
    const email = document.getElementById("signin-email").value.trim();
    const password = document.getElementById("signin-password").value;
    const btn = document.getElementById("signin-submit-btn");

    btn.disabled = true;
    btn.innerHTML = `<span class="animate-spin mr-2">⏳</span> Authenticating...`;

    try {
        const res = await fetch("/api/auth/signin", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email, password })
        });

        const data = await res.json();
        if (!res.ok) {
            showAuthAlert(data.detail || "Authentication failed. Please verify your credentials.");
            return;
        }

        authToken = data.token;
        if (document.getElementById("signin-remember").checked) {
            localStorage.setItem("risklens_auth_token", authToken);
        } else {
            sessionStorage.setItem("risklens_auth_token", authToken);
        }

        showDashboard(data.user);
    } catch (err) {
        showAuthAlert("Network error while connecting to security auth service.");
    } finally {
        btn.disabled = false;
        btn.innerHTML = `<i data-lucide="log-in" class="w-4 h-4"></i><span>Sign In to Platform</span>`;
        if (window.lucide) lucide.createIcons();
    }
}

async function handleSignUpSubmit(event) {
    event.preventDefault();
    clearAuthAlert();

    const fullName = document.getElementById("signup-name").value.trim();
    const email = document.getElementById("signup-email").value.trim();
    const organization = document.getElementById("signup-org").value.trim();
    const role = document.getElementById("signup-role").value;
    const password = document.getElementById("signup-password").value;
    const confirmPassword = document.getElementById("signup-confirm-password").value;
    const btn = document.getElementById("signup-submit-btn");

    if (password !== confirmPassword) {
        showAuthAlert("Passwords do not match. Please re-enter.");
        return;
    }

    btn.disabled = true;
    btn.innerHTML = `<span class="animate-spin mr-2">⏳</span> Creating Account...`;

    try {
        const res = await fetch("/api/auth/signup", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                full_name: fullName,
                email: email,
                organization: organization,
                role: role,
                password: password
            })
        });

        const data = await res.json();
        if (!res.ok) {
            showAuthAlert(data.detail || "Account creation failed.");
            return;
        }

        authToken = data.token;
        localStorage.setItem("risklens_auth_token", authToken);
        showDashboard(data.user);
    } catch (err) {
        showAuthAlert("Failed to register account with auth service.");
    } finally {
        btn.disabled = false;
        btn.innerHTML = `<i data-lucide="user-plus" class="w-4 h-4"></i><span>Create Enterprise Account</span>`;
        if (window.lucide) lucide.createIcons();
    }
}

async function handleForgotRequestSubmit(event) {
    event.preventDefault();
    clearAuthAlert();
    const email = document.getElementById("forgot-email").value.trim();
    const btn = document.getElementById("forgot-submit-btn");

    btn.disabled = true;
    btn.innerHTML = `<span class="animate-spin mr-2">⏳</span> Generating Token...`;

    try {
        const res = await fetch("/api/auth/forgot-password", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email })
        });

        const data = await res.json();
        if (!res.ok) {
            showAuthAlert(data.detail || "Could not generate recovery token for this email.");
            return;
        }

        // Show Step 2
        document.getElementById("form-forgot-request").classList.add("hidden");
        const resetForm = document.getElementById("form-reset-password");
        resetForm.classList.remove("hidden");

        // Display generated verification token code (or corporate dispatch message)
        if (data.reset_token) {
            document.getElementById("display-reset-token").innerText = data.reset_token;
            document.getElementById("reset-token-input").value = "";
            showAuthAlert("Recovery token generated successfully. Enter your new password below.", "success");
        } else {
            document.getElementById("display-reset-token").innerText = "(Dispatched via corporate email)";
            document.getElementById("reset-token-input").value = "";
            showAuthAlert(data.message || "If registered, a recovery verification token has been dispatched to your corporate email.", "success");
        }
    } catch (err) {
        showAuthAlert("Error contacting password recovery service.");
    } finally {
        btn.disabled = false;
        btn.innerHTML = `Generate Verification Token`;
        if (window.lucide) lucide.createIcons();
    }
}

async function handleResetPasswordSubmit(event) {
    event.preventDefault();
    clearAuthAlert();
    const email = document.getElementById("forgot-email").value.trim();
    const token = document.getElementById("reset-token-input").value.trim();
    const newPassword = document.getElementById("reset-new-password").value;
    const btn = document.getElementById("reset-submit-btn");

    btn.disabled = true;
    btn.innerHTML = `<span class="animate-spin mr-2">⏳</span> Updating Password...`;

    try {
        const res = await fetch("/api/auth/reset-password", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                email: email,
                reset_token: token,
                new_password: newPassword
            })
        });

        const data = await res.json();
        if (!res.ok) {
            showAuthAlert(data.detail || "Password reset failed.");
            return;
        }

        // Return to sign in view with empty fields
        switchAuthMode("signin");
        showAuthAlert("Password updated successfully! Please sign in with your new credentials.", "success");
    } catch (err) {
        showAuthAlert("Error contacting reset password service.");
    } finally {
        btn.disabled = false;
        btn.innerHTML = `Update Password & Return to Sign In`;
        if (window.lucide) lucide.createIcons();
    }
}

async function handleSignOut() {
    try {
        if (authToken) {
            await fetch("/api/auth/logout", {
                method: "POST",
                headers: { "Authorization": `Bearer ${authToken}` }
            });
        }
    } catch (e) {
        // Continue logout anyway
    }

    localStorage.removeItem("risklens_auth_token");
    sessionStorage.removeItem("risklens_auth_token");
    authToken = null;
    currentUser = null;
    showAuth("signin");
}

function clearAuthInputs() {
    const ids = ["signin-email", "signin-password", "signup-name", "signup-email", "signup-org", "signup-password", "signup-confirm-password", "forgot-email"];
    ids.forEach(id => {
        const el = document.getElementById(id);
        if (el && !el.dataset.userActive && !el.value) {
            el.value = "";
        }
    });
}

function showEmailSuggestions() {
    const dropdown = document.getElementById("signin-email-autocomplete");
    if (dropdown) dropdown.classList.remove("hidden");
}

function hideEmailSuggestions() {
    const dropdown = document.getElementById("signin-email-autocomplete");
    if (dropdown) dropdown.classList.add("hidden");
}

function autofillLogin(email, password) {
    const emailEl = document.getElementById("signin-email");
    const pwEl = document.getElementById("signin-password");
    if (emailEl) {
        emailEl.value = email;
        emailEl.dataset.userActive = "true";
        emailEl.dispatchEvent(new Event("input", { bubbles: true }));
        emailEl.dispatchEvent(new Event("change", { bubbles: true }));
    }
    if (pwEl) {
        pwEl.value = password;
        pwEl.dataset.userActive = "true";
        pwEl.dispatchEvent(new Event("input", { bubbles: true }));
        pwEl.dispatchEvent(new Event("change", { bubbles: true }));
    }
    hideEmailSuggestions();
    if (pwEl) pwEl.focus();
}

function quickDemoLogin(email, password) {
    autofillLogin(email, password);
    document.getElementById("form-signin").requestSubmit();
}


// ================= DATA EXCHANGE (IMPORT & EXPORT) & 20 PRESETS =================

let allIndustryDatasets = [];
let allStoredCustomDatasets = [];
let activePresetCategory = "all";
let activeCustomCategory = "all";
let activeDatasetId = "DATASET-BANKING";

function getSectorCategory(sector) {
    if (!sector) return "other";
    const s = sector.toLowerCase();
    if (s.includes("bank") || s.includes("finance") || s.includes("fintech") || s.includes("payment") || s.includes("trading") || s.includes("capital") || s.includes("insurance") || s.includes("insurtech")) {
        return "finance";
    }
    if (s.includes("health") || s.includes("hospital") || s.includes("pharma") || s.includes("biotech") || s.includes("life science")) {
        return "healthcare";
    }
    if (s.includes("cloud") || s.includes("software") || s.includes("tech") || s.includes("saas") || s.includes("telecom") || s.includes("semiconductor")) {
        return "tech";
    }
    if (s.includes("energy") || s.includes("power") || s.includes("grid") || s.includes("defense") || s.includes("aerospace") || s.includes("utility") || s.includes("aviation") || s.includes("smartcity") || s.includes("smart city") || s.includes("public") || s.includes("iot") || s.includes("maritime") || s.includes("transport")) {
        return "infrastructure";
    }
    if (s.includes("retail") || s.includes("commerce") || s.includes("consumer") || s.includes("hospitality") || s.includes("travel") || s.includes("media") || s.includes("education")) {
        return "consumer";
    }
    return "other";
}

function getSectorBadgeClass(sector) {
    const cat = getSectorCategory(sector);
    switch (cat) {
        case "finance":
            return "bg-emerald-500/10 text-emerald-300 border-emerald-500/30";
        case "healthcare":
            return "bg-cyan-500/10 text-cyan-300 border-cyan-500/30";
        case "tech":
            return "bg-purple-500/10 text-purple-300 border-purple-500/30";
        case "infrastructure":
            return "bg-amber-500/10 text-amber-300 border-amber-500/30";
        default:
            return "bg-indigo-500/10 text-indigo-300 border-indigo-500/30";
    }
}

async function loadIndustryDatasetsCatalog() {
    try {
        const headers = {};
        if (authToken) headers["Authorization"] = `Bearer ${authToken}`;

        const [datasetsRes, customRes, activeRes] = await Promise.all([
            fetch("/api/datasets"),
            fetch("/api/data/imports", { headers }).catch(() => null),
            fetch("/api/data/active-dataset").catch(() => null)
        ]);

        if (datasetsRes && datasetsRes.ok) {
            allIndustryDatasets = await datasetsRes.json();
        }
        if (customRes && customRes.ok) {
            allStoredCustomDatasets = await customRes.json();
        } else {
            allStoredCustomDatasets = [];
        }

        if (activeRes && activeRes.ok) {
            const activeMeta = await activeRes.json();
            if (activeMeta && activeMeta.id) {
                if (activeMeta.is_custom) {
                    activeDatasetId = activeMeta.id.startsWith("CUSTOM:") ? activeMeta.id : `CUSTOM:${activeMeta.id}`;
                } else {
                    activeDatasetId = activeMeta.id;
                }
            }
        }

        updateDatasetSelectDropdowns();
        applyPresetFilters();
        renderStoredDatasetsList(allStoredCustomDatasets);
    } catch (err) {
        console.error("Failed to load industry datasets catalog:", err);
    }
}

function updateDatasetSelectDropdowns() {
    const headerSelect = document.getElementById("global-industry-dataset-select");
    const assetSelect = document.getElementById("asset-tab-dataset-select");

    let optionsHtml = "";

    // 1. Custom Imported Enterprise Datasets
    if (allStoredCustomDatasets && allStoredCustomDatasets.length > 0) {
        optionsHtml += `<optgroup label="🏢 Custom & Imported Enterprise Datasets (${allStoredCustomDatasets.length})">`;
        allStoredCustomDatasets.forEach(cs => {
            const val = `CUSTOM:${cs.dataset_id}`;
            const isSel = (val === activeDatasetId || cs.dataset_id === activeDatasetId);
            optionsHtml += `<option value="${val}" ${isSel ? 'selected' : ''}>🏢 ${escapeHtml(cs.name)} [${escapeHtml(cs.sector)} • ${cs.asset_count} Assets]</option>`;
        });
        optionsHtml += `</optgroup>`;
    }

    // 2. Pre-configured Industry Benchmarks (20)
    optionsHtml += `<optgroup label="🌐 Pre-Configured Industry Benchmarks (20)">`;
    allIndustryDatasets.forEach(d => {
        const isSel = (d.id === activeDatasetId);
        optionsHtml += `<option value="${d.id}" ${isSel ? 'selected' : ''}>${escapeHtml(d.sector)}: ${escapeHtml(d.name)}</option>`;
    });
    optionsHtml += `</optgroup>`;

    if (headerSelect) {
        headerSelect.innerHTML = optionsHtml;
        headerSelect.value = activeDatasetId;
    }
    if (assetSelect) {
        assetSelect.innerHTML = optionsHtml;
        assetSelect.value = activeDatasetId;
    }

    // Update count badge on tab 0 filter pill
    const customCountBadge = document.getElementById("preset-cat-custom-count");
    if (customCountBadge) {
        customCountBadge.textContent = (allStoredCustomDatasets || []).length;
    }

    const customTotalBadge = document.getElementById("custom-datasets-total-count");
    if (customTotalBadge) {
        customTotalBadge.textContent = `${(allStoredCustomDatasets || []).length} Stored`;
    }
}

function setPresetCategoryFilter(category) {
    activePresetCategory = category;

    const pillIds = {
        "all": "preset-cat-all",
        "finance": "preset-cat-finance",
        "healthcare": "preset-cat-healthcare",
        "tech": "preset-cat-tech",
        "infrastructure": "preset-cat-infrastructure",
        "custom": "preset-cat-custom"
    };

    Object.entries(pillIds).forEach(([cat, id]) => {
        const el = document.getElementById(id);
        if (!el) return;
        if (cat === category) {
            el.className = "preset-filter-pill px-2.5 py-1 rounded-lg text-xs font-semibold bg-indigo-600 text-white shadow-md shadow-indigo-600/30 border border-indigo-400/50 transition whitespace-nowrap";
        } else {
            el.className = "preset-filter-pill px-2.5 py-1 rounded-lg text-xs font-medium text-zinc-400 hover:text-white bg-[#121215] border border-[#222225] hover:border-zinc-700 transition whitespace-nowrap";
        }
    });

    applyPresetFilters();
}

function applyPresetFilters() {
    const searchInput = document.getElementById("preset-search-input");
    const query = searchInput ? searchInput.value.toLowerCase().trim() : "";

    let itemsToDisplay = [];

    if (activePresetCategory === "custom") {
        itemsToDisplay = (allStoredCustomDatasets || []).map(c => ({
            id: `CUSTOM:${c.dataset_id}`,
            name: c.name,
            sector: c.sector || "Custom Sector",
            description: `Imported custom dataset with ${c.asset_count} assets & ${c.total_cves} CVEs. Persisted in SQLite.`,
            risk_profile: `Custom Enterprise Risk • EAL: ${typeof formatMoney === "function" ? formatMoney(c.recalculated_eal_inr) : '₹' + Math.round(c.recalculated_eal_inr || 0).toLocaleString()}`,
            asset_count: c.asset_count,
            regulatory_focus: ["Enterprise FAIR", "Custom Telemetry"],
            is_custom: true
        }));
    } else {
        let filteredPresets = allIndustryDatasets;
        if (activePresetCategory !== "all") {
            filteredPresets = allIndustryDatasets.filter(d => getSectorCategory(d.sector) === activePresetCategory);
        }

        let matchingCustom = (allStoredCustomDatasets || []).filter(c => {
            if (activePresetCategory === "all") return true;
            return getSectorCategory(c.sector) === activePresetCategory;
        }).map(c => ({
            id: `CUSTOM:${c.dataset_id}`,
            name: c.name,
            sector: c.sector || "Custom Sector",
            description: `Imported custom dataset with ${c.asset_count} assets & ${c.total_cves} CVEs. Persisted in SQLite.`,
            risk_profile: `Custom Enterprise Risk • EAL: ${typeof formatMoney === "function" ? formatMoney(c.recalculated_eal_inr) : '₹' + Math.round(c.recalculated_eal_inr || 0).toLocaleString()}`,
            asset_count: c.asset_count,
            regulatory_focus: ["Enterprise FAIR", "Custom Telemetry"],
            is_custom: true
        }));

        itemsToDisplay = [...matchingCustom, ...filteredPresets];
    }

    if (query) {
        itemsToDisplay = itemsToDisplay.filter(d =>
            d.name.toLowerCase().includes(query) ||
            d.sector.toLowerCase().includes(query) ||
            d.description.toLowerCase().includes(query) ||
            d.risk_profile.toLowerCase().includes(query) ||
            (d.regulatory_focus && d.regulatory_focus.some(r => r.toLowerCase().includes(query)))
        );
    }

    const summaryEl = document.getElementById("preset-filter-summary");
    if (summaryEl) {
        summaryEl.innerHTML = `<span>Showing <span class="font-bold text-white">${itemsToDisplay.length}</span> datasets ${query ? `matching "<span class="text-indigo-300">${escapeHtml(query)}</span>"` : ''}</span>`;
    }

    renderDatasetsGrid(itemsToDisplay);
}

function renderDatasetsGrid(datasets) {
    const container = document.getElementById("datasets-grid-container");
    if (!container) return;

    if (!datasets || datasets.length === 0) {
        container.innerHTML = `
            <div class="p-8 text-center text-xs text-zinc-500 col-span-2 border border-dashed border-[#222225] rounded-xl space-y-2">
                <i data-lucide="layers" class="w-6 h-6 mx-auto text-zinc-600"></i>
                <p>No matching enterprise datasets found in this category.</p>
                <button type="button" onclick="setPresetCategoryFilter('all')" class="text-indigo-400 hover:underline text-xs">Reset All Category Filters</button>
            </div>
        `;
        if (window.lucide) lucide.createIcons();
        return;
    }

    container.innerHTML = "";
    datasets.forEach(d => {
        const isCustom = Boolean(d.is_custom);
        const cleanCustomId = isCustom ? d.id.replace('CUSTOM:', '') : d.id;
        const isActive = (d.id === activeDatasetId || (isCustom && (activeDatasetId === d.id || activeDatasetId === `CUSTOM:${cleanCustomId}` || activeDatasetId === cleanCustomId)));

        const card = document.createElement("div");
        card.className = `p-3.5 rounded-xl border transition space-y-2.5 flex flex-col justify-between ${
            isActive
                ? 'bg-[#0f0f26] border-indigo-500 shadow-lg shadow-indigo-950/50 ring-1 ring-indigo-500/40'
                : isCustom
                    ? 'bg-[#0b0b14] border-cyan-900/30 hover:border-cyan-500/50'
                    : 'bg-[#09090b] border-[#1e1e22] hover:border-[#333338]'
        }`;

        const sectorColor = getSectorBadgeClass(d.sector);

        card.innerHTML = `
            <div class="space-y-2">
                <div class="flex items-center justify-between gap-1">
                    <div class="flex items-center space-x-1.5 min-w-0">
                        ${isCustom ? `
                            <span class="text-[9px] font-bold uppercase tracking-wider text-cyan-300 bg-cyan-500/10 px-1.5 py-0.5 rounded border border-cyan-500/30 flex-shrink-0 flex items-center space-x-1">
                                <span class="h-1.5 w-1.5 rounded-full bg-cyan-400"></span>
                                <span>Custom</span>
                            </span>
                        ` : ''}
                        <span class="text-[9px] font-bold uppercase tracking-wider ${sectorColor} px-2 py-0.5 rounded border truncate">${escapeHtml(d.sector)}</span>
                    </div>
                    <span class="text-[10px] text-zinc-400 font-mono flex items-center space-x-1 flex-shrink-0">
                        <i data-lucide="server" class="w-3 h-3 text-cyan-400"></i>
                        <span>${Number(d.asset_count || 0)} Assets</span>
                    </span>
                </div>
                <div>
                    <h4 class="text-xs font-bold text-white leading-snug flex items-center space-x-1.5">
                        <span class="truncate">${escapeHtml(d.name)}</span>
                        ${isActive ? '<span class="text-[9px] px-1.5 py-0.2 rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/40 font-mono flex-shrink-0">● Active</span>' : ''}
                    </h4>
                    <p class="text-[11px] text-zinc-400 leading-tight mt-1 line-clamp-2">${escapeHtml(d.description)}</p>
                </div>
                <div>
                    <span class="text-[10px] px-1.5 py-0.5 rounded ${isCustom ? 'bg-indigo-500/10 text-indigo-300 border border-indigo-500/30' : 'bg-rose-500/10 text-rose-300 border border-rose-500/30'} block truncate" title="${escapeHtml(d.risk_profile)}">
                        ${isCustom ? '🏢' : '⚠️'} ${escapeHtml(d.risk_profile)}
                    </span>
                </div>
            </div>
            <div class="pt-2 flex items-center justify-between border-t border-[#18181b] gap-2">
                <div class="flex items-center space-x-1 text-[9px] text-zinc-500 truncate max-w-[150px]">
                    ${(d.regulatory_focus || []).slice(0, 2).map(r => `<span class="bg-[#121215] px-1.5 py-0.5 rounded text-zinc-400 border border-[#1f1f24]">${escapeHtml(r)}</span>`).join('')}
                </div>
                <button type="button" onclick="onSelectIndustryDataset('${escapeHtml(d.id)}')" class="px-3 py-1 rounded-lg text-xs font-semibold transition whitespace-nowrap ${
                    isActive
                        ? 'bg-indigo-600 text-white cursor-default shadow-sm'
                        : isCustom
                            ? 'bg-cyan-600/20 hover:bg-cyan-600 text-cyan-300 hover:text-white border border-cyan-500/40 cursor-pointer'
                            : 'bg-[#18181e] hover:bg-indigo-600 hover:text-white text-zinc-300 border border-[#27272a] cursor-pointer'
                }">
                    ${isActive ? '✓ Active' : (isCustom ? 'Activate' : 'Load Dataset')}
                </button>
            </div>
        `;
        container.appendChild(card);
    });

    if (window.lucide) lucide.createIcons();
}

function filterPresetCards(query) {
    applyPresetFilters();
}

async function onSelectIndustryDataset(datasetId) {
    if (!datasetId) return;

    activeDatasetId = datasetId;

    // Sync select dropdowns
    const headerSelect = document.getElementById("global-industry-dataset-select");
    if (headerSelect) headerSelect.value = datasetId;
    const assetSelect = document.getElementById("asset-tab-dataset-select");
    if (assetSelect) assetSelect.value = datasetId;

    if (datasetId.startsWith("CUSTOM:")) {
        const customId = datasetId.replace("CUSTOM:", "");
        await activateStoredDataset(customId);
        return;
    }

    try {
        const headers = {};
        if (authToken) headers["Authorization"] = `Bearer ${authToken}`;
        const res = await fetch(`/api/datasets/${datasetId}/load`, { method: "POST", headers });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || "Failed to load dataset");

        const badge = document.getElementById("active-dataset-badge");
        if (badge) {
            badge.innerText = `${data.sector}: ${data.name} (${data.asset_count} Assets)`;
            badge.className = "px-2 py-0.5 rounded text-[10px] font-semibold bg-indigo-500/10 text-indigo-400 border border-indigo-500/30 whitespace-nowrap";
        }

        const headerBadge = document.getElementById("header-telemetry-badge");
        if (headerBadge) {
            headerBadge.textContent = `${data.asset_count} Assets Live`;
        }

        updateDatasetSelectDropdowns();
        applyPresetFilters();
        renderStoredDatasetsList(allStoredCustomDatasets);

        // Invalidate and refresh all dashboard views
        assetInventoryData = [];
        optimizerLoaded = false;
        complianceLoaded = false;
        currentVaRMode = "auto";
        await loadExecutiveDashboard();
        await loadAssets();
        refreshActiveTabViews();

        showToast(`Successfully loaded industry dataset: ${data.name} (${data.asset_count} assets)`, "success");

        // If modal is open, close after short delay
        const modal = document.getElementById("data-exchange-modal");
        if (modal && !modal.classList.contains("hidden")) {
            setTimeout(closeDataModal, 800);
        }
    } catch (err) {
        showToast("Error loading dataset: " + err.message, "error");
    }
}

function openDataModal(tab = "presets") {
    const modal = document.getElementById("data-exchange-modal");
    if (modal) modal.classList.remove("hidden");
    switchModalTab(tab);
    if (window.lucide) lucide.createIcons();
}

function closeDataModal() {
    const modal = document.getElementById("data-exchange-modal");
    if (modal) modal.classList.add("hidden");
    const banner = document.getElementById("import-feedback-banner");
    if (banner) banner.classList.add("hidden");
}

function switchModalTab(tab) {
    const tabs = ["presets", "import", "export", "template"];
    tabs.forEach(t => {
        const sec = document.getElementById(`modal-section-${t}`);
        const btn = document.getElementById(`modal-tab-${t}-btn`);
        if (sec) {
            if (t === tab) sec.classList.remove("hidden");
            else sec.classList.add("hidden");
        }
        if (btn) {
            if (t === tab) {
                btn.classList.add("active");
                btn.classList.remove("text-zinc-400");
                btn.classList.add("text-white");
            } else {
                btn.classList.remove("active");
                btn.classList.add("text-zinc-400");
                btn.classList.remove("text-white");
            }
        }
    });
    if (tab === "import") {
        loadStoredDatasets();
    }
    if (window.lucide) lucide.createIcons();
}

function onImportFormatChange(fmt) {
    const textarea = document.getElementById("data-import-textarea");
    const fileInput = document.getElementById("data-import-file-input");
    if (fmt === "csv") {
        if (fileInput) fileInput.accept = ".csv";
        if (textarea) textarea.placeholder = "Paste CSV rows (asset_id, name, business_unit, criticality, revenue_per_hour_inr, pii_records_count, cve_ids...) here...";
    } else {
        if (fileInput) fileInput.accept = ".json";
        if (textarea) textarea.placeholder = "Paste JSON object ({\"assets\": [...]}) or array of asset objects here...";
    }
}

function setImportPreset(name, sector) {
    const nameInput = document.getElementById("import-dataset-name");
    const sectorSelect = document.getElementById("import-dataset-sector");
    if (nameInput) nameInput.value = name;
    if (sectorSelect && sector) sectorSelect.value = sector;
    loadSampleIntoTextarea();
}

function processFileObject(file) {
    if (!file) return;

    const label = document.getElementById("import-file-label");
    if (label) label.innerText = `Selected: ${file.name} (${(file.size / 1024).toFixed(1)} KB)`;

    const nameInput = document.getElementById("import-dataset-name");
    if (nameInput && !nameInput.value.trim()) {
        const cleanName = file.name
            .replace(/\.[^/.]+$/, "")
            .replace(/[_-]+/g, " ")
            .replace(/\b\w/g, l => l.toUpperCase())
            .trim();
        nameInput.value = cleanName;
    }

    const isJson = file.name.endsWith(".json");
    const fmt = isJson ? "json" : "csv";
    const radio = document.querySelector(`input[name="import-format"][value="${fmt}"]`);
    if (radio) radio.checked = true;
    onImportFormatChange(fmt);

    const reader = new FileReader();
    reader.onload = (e) => {
        const text = e.target.result;
        const textarea = document.getElementById("data-import-textarea");
        if (textarea) textarea.value = text;
        showImportFeedback(`File loaded: ${file.name}. Click 'Import & Quantify Risk' to proceed.`, "info");
    };
    reader.readAsText(file);
}

function handleFileSelected(event) {
    const file = event.target.files && event.target.files[0];
    if (file) processFileObject(file);
}

function initDropZone() {
    const dropZone = document.getElementById("import-drop-zone");
    if (!dropZone) return;

    ['dragenter', 'dragover'].forEach(eventName => {
        dropZone.addEventListener(eventName, (e) => {
            e.preventDefault();
            e.stopPropagation();
            dropZone.classList.add("border-indigo-500", "bg-indigo-500/10");
        }, false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
        dropZone.addEventListener(eventName, (e) => {
            e.preventDefault();
            e.stopPropagation();
            dropZone.classList.remove("border-indigo-500", "bg-indigo-500/10");
        }, false);
    });

    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        e.stopPropagation();
        const dt = e.dataTransfer;
        const files = dt && dt.files;
        if (files && files.length > 0) {
            processFileObject(files[0]);
        }
    }, false);
}

function loadSampleIntoTextarea() {
    const isCsv = document.querySelector('input[name="import-format"]:checked')?.value === "csv";
    const textarea = document.getElementById("data-import-textarea");
    const nameInput = document.getElementById("import-dataset-name");
    const sectorSelect = document.getElementById("import-dataset-sector");

    if (nameInput && !nameInput.value.trim()) {
        nameInput.value = "State Bank of XYZ";
    }
    if (sectorSelect && !sectorSelect.value) {
        sectorSelect.value = "Banking & Financial Services";
    }

    if (!textarea) return;

    if (isCsv) {
        textarea.value = `asset_id,name,business_unit,criticality,revenue_per_hour_inr,pii_records_count,cve_ids,top_cvss,top_epss,avg_control_score
REAL-001,Core Banking Transaction Switch,Retail Banking & Payments,Tier 1 - Crown Jewel,7500000,1200000,"CVE-2024-21887;CVE-2023-4966",9.8,0.94,0.65
REAL-002,Online Customer Banking Portal,Retail Banking & Payments,Tier 1 - Crown Jewel,4200000,18500000,"CVE-2023-38606",8.8,0.72,0.75
REAL-003,Customer Master KYC Database,Corporate & Treasury,Tier 1 - Crown Jewel,2500000,4500000,"CVE-2023-34362",9.8,0.95,0.58
REAL-004,Cloud Infrastructure Kubernetes Cluster,Cloud & Core Infrastructure,Tier 2 - Business Operational,1800000,0,"CVE-2023-27997",8.2,0.48,0.70
REAL-005,Enterprise Identity & IAM Gateway,Cloud & Core Infrastructure,Tier 1 - Crown Jewel,3100000,200000,"CVE-2024-21413",9.8,0.88,0.55`;
    } else {
        textarea.value = JSON.stringify({
            organization: nameInput ? nameInput.value : "State Bank of XYZ",
            sector: sectorSelect ? sectorSelect.value : "Banking & Financial Services",
            assets: [
                {
                    asset_id: "REAL-001",
                    name: "Core Banking Transaction Switch",
                    business_unit: "Retail Banking & Payments",
                    criticality: "Tier 1 - Crown Jewel",
                    revenue_per_hour_inr: 7500000.0,
                    pii_records_count: 1200000,
                    data_classification: "Treasury Confidential",
                    ip_or_endpoint: "10.100.4.1",
                    cloud_provider: "Hybrid On-Prem",
                    vulnerabilities: [
                        { cve_id: "CVE-2024-21887", cvss_score: 9.8, epss_score: 0.94, is_cisa_kev: true }
                    ]
                },
                {
                    asset_id: "REAL-002",
                    name: "Online Customer Banking Portal",
                    business_unit: "Retail Banking & Payments",
                    criticality: "Tier 1 - Crown Jewel",
                    revenue_per_hour_inr: 4200000.0,
                    pii_records_count: 18500000,
                    data_classification: "PCI-DSS / Customer PII",
                    ip_or_endpoint: "api.retail.prod",
                    cloud_provider: "AWS",
                    vulnerabilities: [
                        { cve_id: "CVE-2023-38606", cvss_score: 8.8, epss_score: 0.72, is_cisa_kev: false }
                    ]
                }
            ]
        }, null, 2);
    }
    showImportFeedback("Sample enterprise dataset inserted. Click 'Import & Quantify Risk' to run analysis.", "info");
}

function showImportFeedback(msg, type = "info") {
    const banner = document.getElementById("import-feedback-banner");
    const text = document.getElementById("import-feedback-text");
    const icon = document.getElementById("import-feedback-icon");
    if (!banner || !text) return;

    banner.classList.remove("hidden");
    text.innerText = msg;

    if (type === "success") {
        banner.className = "p-3 rounded-xl text-xs flex items-center space-x-2 bg-emerald-500/10 text-emerald-300 border border-emerald-500/30";
        if (icon) icon.setAttribute("data-lucide", "check-circle");
    } else if (type === "error") {
        banner.className = "p-3 rounded-xl text-xs flex items-center space-x-2 bg-rose-500/10 text-rose-300 border border-rose-500/30";
        if (icon) icon.setAttribute("data-lucide", "alert-triangle");
    } else {
        banner.className = "p-3 rounded-xl text-xs flex items-center space-x-2 bg-indigo-500/10 text-indigo-300 border border-indigo-500/30";
        if (icon) icon.setAttribute("data-lucide", "info");
    }
    if (window.lucide) lucide.createIcons();
}

async function executeDataImport() {
    const textarea = document.getElementById("data-import-textarea");
    const content = textarea ? textarea.value.trim() : "";
    if (!content) {
        showImportFeedback("Please paste or upload CSV / JSON asset inventory data first.", "error");
        return;
    }

    const nameInput = document.getElementById("import-dataset-name");
    const datasetName = (nameInput && nameInput.value.trim()) ? nameInput.value.trim() : "State Bank of XYZ";
    const sectorSelect = document.getElementById("import-dataset-sector");
    const datasetSector = sectorSelect ? sectorSelect.value : "Banking & Financial Services";
    const overwrite = document.getElementById("import-dataset-overwrite")?.checked || false;

    const fmt = document.querySelector('input[name="import-format"]:checked')?.value || "csv";
    const btn = document.getElementById("import-submit-btn");
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = `<span class="animate-spin mr-1">⏳</span> Ingesting ${datasetName} & Quantifying FAIR Risk...`;
    }

    try {
        const payload = {
            format: fmt,
            content: content,
            dataset_name: datasetName,
            organization: datasetName,
            sector: datasetSector,
            overwrite: overwrite
        };
        const headers = { "Content-Type": "application/json" };
        if (authToken) headers["Authorization"] = `Bearer ${authToken}`;
        const res = await fetch("/api/data/import", {
            method: "POST",
            headers,
            body: JSON.stringify(payload)
        });

        const data = await res.json();
        if (!res.ok) {
            if (res.status === 401) {
                showImportFeedback("Authentication required: Please sign in with an administrative account to import data.", "error");
                showToast("Authentication required to import enterprise telemetry.", "error");
                showAuth("signin");
                return;
            }
            if (res.status === 409) {
                showImportFeedback(data.detail || "Duplicate dataset rejected: Identical telemetry or dataset name already exists.", "error");
                showToast("Duplicate Rejected: Identical data or name conflict", "error");
                return;
            }
            throw new Error(data.detail || "Import failed");
        }

        const badge = document.getElementById("active-dataset-badge");
        if (badge) {
            badge.innerText = `🏢 ${data.dataset_name || datasetName} (${data.imported_assets_count} Assets Live)`;
            badge.className = "px-2 py-0.5 rounded text-[10px] font-semibold bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 whitespace-nowrap";
        }

        const headerBadge = document.getElementById("header-telemetry-badge");
        if (headerBadge) {
            headerBadge.textContent = `${data.dataset_name || datasetName} • ${data.imported_assets_count} Assets Live`;
        }

        showImportFeedback(`Success: Ingested & persisted ${data.imported_assets_count} assets for "${data.dataset_name || datasetName}" (${data.total_cves_count} CVEs) into database. Recalculated EAL: ${formatMoney(data.recalculated_risk.eal_inr)}.`, "success");
        showToast(`Successfully saved ${data.dataset_name || datasetName} to database`, "success");

        // Sync active dataset ID to the newly imported custom dataset
        if (data.dataset_id) {
            activeDatasetId = `CUSTOM:${data.dataset_id}`;
        }

        // Refresh dropdowns, dataset catalog, and stored datasets list in modal
        await loadIndustryDatasetsCatalog();
        await loadStoredDatasets();

        // Invalidate frontend caches and reload all tabs
        assetInventoryData = [];
        optimizerLoaded = false;
        complianceLoaded = false;
        currentVaRMode = "auto";
        await loadExecutiveDashboard();
        await loadAssets();
        refreshActiveTabViews();
    } catch (err) {
        showImportFeedback(err.message, "error");
        showToast("Import failed: " + err.message, "error");
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = `<i data-lucide="play" class="w-3.5 h-3.5"></i><span>Import & Quantify Risk</span>`;
            if (window.lucide) lucide.createIcons();
        }
    }
}

async function loadStoredDatasets() {
    const container = document.getElementById("stored-datasets-container");
    try {
        const headers = {};
        if (authToken) headers["Authorization"] = `Bearer ${authToken}`;
        const res = await fetch("/api/data/imports", { headers });
        if (!res.ok) {
            if (container) container.innerHTML = `<div class="text-[11px] text-zinc-500 text-center py-3 border border-dashed border-[#222225] rounded-xl">Unable to load stored datasets.</div>`;
            return;
        }
        allStoredCustomDatasets = await res.json();
        if (!Array.isArray(allStoredCustomDatasets)) {
            allStoredCustomDatasets = [];
        }

        updateDatasetSelectDropdowns();
        applyCustomDatasetFilters();
    } catch (e) {
        if (container) container.innerHTML = `<div class="text-[11px] text-zinc-500 text-center py-3 border border-dashed border-[#222225] rounded-xl">Error loading stored datasets.</div>`;
    }
}

function setCustomCategoryFilter(category) {
    activeCustomCategory = category;

    const pillIds = {
        "all": "custom-cat-all",
        "finance": "custom-cat-finance",
        "healthcare": "custom-cat-healthcare",
        "tech": "custom-cat-tech",
        "other": "custom-cat-other"
    };

    Object.entries(pillIds).forEach(([cat, id]) => {
        const el = document.getElementById(id);
        if (!el) return;
        if (cat === category) {
            el.className = "custom-filter-pill px-2.5 py-1 rounded-md text-[11px] font-semibold bg-indigo-600 text-white shadow-sm border border-indigo-400/40 transition whitespace-nowrap";
        } else {
            el.className = "custom-filter-pill px-2.5 py-1 rounded-md text-[11px] font-medium text-zinc-400 hover:text-white bg-[#121215] border border-[#222225] hover:border-zinc-700 transition whitespace-nowrap";
        }
    });

    applyCustomDatasetFilters();
}

function applyCustomDatasetFilters() {
    const searchInput = document.getElementById("custom-search-input");
    const query = searchInput ? searchInput.value.toLowerCase().trim() : "";

    let filtered = allStoredCustomDatasets || [];

    if (activeCustomCategory !== "all") {
        filtered = filtered.filter(ds => getSectorCategory(ds.sector) === activeCustomCategory);
    }

    if (query) {
        filtered = filtered.filter(ds =>
            (ds.name && ds.name.toLowerCase().includes(query)) ||
            (ds.sector && ds.sector.toLowerCase().includes(query)) ||
            (ds.dataset_id && ds.dataset_id.toLowerCase().includes(query))
        );
    }

    renderStoredDatasetsList(filtered);
}

function renderStoredDatasetsList(datasets) {
    const container = document.getElementById("stored-datasets-container");
    if (!container) return;

    const totalCountBadge = document.getElementById("custom-datasets-total-count");
    if (totalCountBadge) {
        totalCountBadge.textContent = `${(allStoredCustomDatasets || []).length} Stored`;
    }

    if (!datasets || datasets.length === 0) {
        const isFiltering = (allStoredCustomDatasets && allStoredCustomDatasets.length > 0);
        container.innerHTML = `
            <div class="p-5 text-center text-xs text-zinc-500 border border-dashed border-[#222225] rounded-xl space-y-1.5">
                <i data-lucide="database" class="w-5 h-5 mx-auto text-zinc-600"></i>
                <p>${isFiltering ? 'No custom datasets match the current filter.' : 'No custom datasets stored yet. Import data above to save into backend database.'}</p>
                ${isFiltering ? '<button type="button" onclick="setCustomCategoryFilter(\'all\')" class="text-indigo-400 hover:underline text-[11px]">Clear Sector Filter</button>' : ''}
            </div>
        `;
        if (window.lucide) lucide.createIcons();
        return;
    }

    container.innerHTML = datasets.map(ds => {
        const dateStr = ds.created_at ? new Date(ds.created_at).toLocaleString() : "Recently";
        const ealStr = typeof formatMoney === "function" ? formatMoney(ds.recalculated_eal_inr) : `₹${Math.round(ds.recalculated_eal_inr || 0).toLocaleString()}`;
        const safeId = escapeHtml(ds.dataset_id);
        const safeName = escapeHtml(ds.name);
        const safeSector = escapeHtml(ds.sector || "Custom Sector");
        const category = getSectorCategory(ds.sector);

        const isActive = (activeDatasetId === `CUSTOM:${ds.dataset_id}` || activeDatasetId === ds.dataset_id);

        let borderAccent = "border-l-indigo-500";
        if (category === "finance") borderAccent = "border-l-emerald-500";
        else if (category === "healthcare") borderAccent = "border-l-cyan-500";
        else if (category === "tech") borderAccent = "border-l-purple-500";
        else if (category === "infrastructure") borderAccent = "border-l-amber-500";

        const sectorBadgeClass = getSectorBadgeClass(ds.sector);

        return `
            <div class="p-3 rounded-xl border border-[#222226] ${borderAccent} border-l-4 bg-[#0c0c10] hover:border-indigo-500/50 hover:bg-[#0f0f15] transition space-y-2">
                <div class="flex items-start justify-between gap-2">
                    <div class="min-w-0 flex-1">
                        <div class="flex items-center space-x-2 flex-wrap gap-y-1">
                            <span class="text-xs font-bold text-white truncate max-w-[240px]">${safeName}</span>
                            <span class="px-2 py-0.5 rounded-full text-[10px] ${sectorBadgeClass} border font-mono font-medium">${safeSector}</span>
                            ${isActive ? `
                                <span class="inline-flex items-center space-x-1 px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                                    <span class="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
                                    <span>Active Now</span>
                                </span>
                            ` : `
                                <span class="text-[10px] text-zinc-500 font-mono">SQLite Stored</span>
                            `}
                        </div>
                        <div class="text-[11px] text-zinc-400 mt-1 flex items-center space-x-3 flex-wrap gap-y-1 font-mono">
                            <span class="flex items-center space-x-1 text-cyan-300">
                                <i data-lucide="server" class="w-3 h-3 text-cyan-400"></i>
                                <span>${ds.asset_count} assets</span>
                            </span>
                            <span class="flex items-center space-x-1 ${ds.total_cves > 0 ? 'text-rose-300' : 'text-emerald-400'}">
                                <i data-lucide="shield-alert" class="w-3 h-3"></i>
                                <span>${ds.total_cves} CVEs</span>
                            </span>
                            <span class="flex items-center space-x-1 text-amber-300">
                                <i data-lucide="coins" class="w-3 h-3 text-amber-400"></i>
                                <span>EAL: ${ealStr}</span>
                            </span>
                            <span class="flex items-center space-x-1 text-zinc-500 text-[10px]">
                                <i data-lucide="clock" class="w-3 h-3"></i>
                                <span>${dateStr}</span>
                            </span>
                        </div>
                    </div>
                    <div class="flex items-center space-x-2 flex-shrink-0">
                        ${isActive ? `
                            <button disabled class="px-3 py-1.5 rounded-lg bg-emerald-600/20 text-emerald-300 border border-emerald-500/40 text-xs font-semibold flex items-center space-x-1 cursor-default">
                                <i data-lucide="check" class="w-3.5 h-3.5"></i>
                                <span>Active</span>
                            </button>
                        ` : `
                            <button type="button" onclick="activateStoredDataset('${safeId}')" title="Load and quantify risk for this dataset" class="px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold shadow-md shadow-indigo-600/30 transition flex items-center space-x-1 cursor-pointer">
                                <i data-lucide="play" class="w-3.5 h-3.5"></i>
                                <span>Activate</span>
                            </button>
                        `}
                        <button type="button" onclick="deleteStoredDataset('${safeId}')" title="Delete from persistent database" class="p-1.5 rounded-lg text-zinc-500 hover:text-rose-400 hover:bg-rose-500/10 transition cursor-pointer">
                            <i data-lucide="trash-2" class="w-4 h-4"></i>
                        </button>
                    </div>
                </div>
            </div>
        `;
    }).join("");

    if (window.lucide) lucide.createIcons();
}

async function activateStoredDataset(datasetId) {
    try {
        const cleanId = datasetId.replace("CUSTOM:", "");
        activeDatasetId = `CUSTOM:${cleanId}`;

        const headers = {};
        if (authToken) headers["Authorization"] = `Bearer ${authToken}`;
        const res = await fetch(`/api/data/imports/${encodeURIComponent(cleanId)}/activate`, {
            method: "POST",
            headers
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || "Activation failed");

        const badge = document.getElementById("active-dataset-badge");
        if (badge) {
            badge.innerText = `🏢 ${data.dataset_name} (${data.asset_count} Assets Live)`;
            badge.className = "px-2 py-0.5 rounded text-[10px] font-semibold bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 whitespace-nowrap";
        }
        const headerBadge = document.getElementById("header-telemetry-badge");
        if (headerBadge) {
            headerBadge.textContent = `${data.dataset_name} • ${data.asset_count} Assets Live`;
        }

        updateDatasetSelectDropdowns();
        applyPresetFilters();
        await loadStoredDatasets();

        showToast(`Dataset "${data.dataset_name}" activated from database`, "success");
        showImportFeedback(`Dataset "${data.dataset_name}" is active (${data.asset_count} assets). Recalculated EAL: ${formatMoney(data.recalculated_risk.eal_inr)}.`, "success");

        assetInventoryData = [];
        optimizerLoaded = false;
        complianceLoaded = false;
        currentVaRMode = "auto";
        await loadExecutiveDashboard();
        await loadAssets();
        refreshActiveTabViews();

        const modal = document.getElementById("data-exchange-modal");
        if (modal && !modal.classList.contains("hidden")) {
            setTimeout(closeDataModal, 800);
        }
    } catch (err) {
        showToast("Activation error: " + err.message, "error");
        showImportFeedback("Activation error: " + err.message, "error");
    }
}

async function deleteStoredDataset(datasetId) {
    const cleanId = datasetId.replace("CUSTOM:", "");
    if (!confirm(`Are you sure you want to delete dataset '${cleanId}' from the persistent database?`)) return;
    try {
        const headers = {};
        if (authToken) headers["Authorization"] = `Bearer ${authToken}`;
        const res = await fetch(`/api/data/imports/${encodeURIComponent(cleanId)}`, {
            method: "DELETE",
            headers
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || "Deletion failed");
        showToast("Dataset removed from database", "info");

        if (activeDatasetId === `CUSTOM:${cleanId}` || activeDatasetId === cleanId) {
            activeDatasetId = "DATASET-BANKING";
            await onSelectIndustryDataset("DATASET-BANKING");
        }

        await loadIndustryDatasetsCatalog();
        await loadStoredDatasets();
    } catch (err) {
        showToast("Delete error: " + err.message, "error");
    }
}

async function resetToBenchmarkData() {
    if (!confirm("Reset asset inventory and telemetry back to default banking benchmark dataset?")) {
        return;
    }

    try {
        const headers = {};
        if (authToken) headers["Authorization"] = `Bearer ${authToken}`;
        const res = await fetch("/api/data/reset", { method: "POST", headers });
        if (!res.ok) throw new Error("Server returned error resetting telemetry data.");
        const data = await res.json();

        activeDatasetId = "DATASET-BANKING";
        await loadIndustryDatasetsCatalog();
        await loadStoredDatasets();

        const badge = document.getElementById("active-dataset-badge");
        if (badge) {
            badge.innerText = "Banking & Financial Services: Tier-1 Bank (7 Assets)";
            badge.className = "px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 whitespace-nowrap";
        }

        const headerBadge = document.getElementById("header-telemetry-badge");
        if (headerBadge) {
            headerBadge.textContent = "Live Feed";
        }

        const nameInput = document.getElementById("import-dataset-name");
        if (nameInput) nameInput.value = "";

        showImportFeedback("Asset telemetry successfully reset to default benchmark data.", "success");
        showToast("Asset inventory reset to baseline benchmark dataset.", "success");
        assetInventoryData = [];
        optimizerLoaded = false;
        complianceLoaded = false;
        currentVaRMode = "auto";
        await loadExecutiveDashboard();
        await loadAssets();
        refreshActiveTabViews();

        const textarea = document.getElementById("data-import-textarea");
        if (textarea) textarea.value = "";
        const label = document.getElementById("import-file-label");
        if (label) label.innerText = "Click to browse or drop CSV/JSON file here";

        setTimeout(() => {
            closeDataModal();
        }, 800);
    } catch (err) {
        showImportFeedback("Failed to reset dataset: " + err.message, "error");
        showToast("Failed to reset dataset: " + err.message, "error");
    }
}

async function loadActiveDatasetMetadata() {
    try {
        const res = await fetch("/api/data/active-dataset");
        if (!res.ok) return;
        const meta = await res.json();
        const badge = document.getElementById("active-dataset-badge");
        const headerBadge = document.getElementById("header-telemetry-badge");
        if (meta && meta.name) {
            if (meta.is_custom) {
                if (badge) {
                    badge.innerText = `🏢 ${meta.name} (${meta.asset_count || 12} Assets Live)`;
                    badge.className = "px-2 py-0.5 rounded text-[10px] font-semibold bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 whitespace-nowrap";
                }
                if (headerBadge) {
                    headerBadge.textContent = `${meta.name} • ${meta.asset_count || 12} Assets Live`;
                }
            } else if (meta.id && meta.id.startsWith("DATASET-")) {
                if (badge) {
                    badge.innerText = `${meta.sector}: ${meta.name} (${meta.asset_count} Assets)`;
                    badge.className = "px-2 py-0.5 rounded text-[10px] font-semibold bg-indigo-500/10 text-indigo-400 border border-indigo-500/30 whitespace-nowrap";
                }
                if (headerBadge) {
                    headerBadge.textContent = `${meta.name} • ${meta.asset_count} Assets Live`;
                }
            }
        }
    } catch (_) {}
}

async function downloadDataExport(endpoint, defaultFilename) {
    try {
        const headers = {};
        if (authToken) {
            headers["Authorization"] = `Bearer ${authToken}`;
        }
        let url = endpoint;
        if (authToken && !url.includes("token=")) {
            url += (url.includes("?") ? "&" : "?") + `token=${encodeURIComponent(authToken)}`;
        }

        const res = await fetch(url, { headers });
        if (!res.ok) {
            let errorMsg = `Server error ${res.status}`;
            try {
                const errData = await res.json();
                if (errData && errData.detail) errorMsg = errData.detail;
            } catch (_) {}
            if (res.status === 401) {
                showToast("Authentication required: Please sign in to export corporate risk data.", "error");
                showAuth("signin");
                return;
            }
            throw new Error(errorMsg);
        }

        const blob = await res.blob();
        const blobUrl = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = blobUrl;
        a.download = defaultFilename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        setTimeout(() => URL.revokeObjectURL(blobUrl), 2000);
        showToast("Export downloaded successfully.", "success");
    } catch (err) {
        showToast("Export failed: " + err.message, "error");
    }
}

function exportFullDossier() {
    showToast("Generating full Open FAIR™ risk dossier export...", "info");
    const filename = `RiskLens_Full_Risk_Analysis_Dossier_${new Date().toISOString().slice(0, 10)}.json`;
    downloadDataExport("/api/data/export?format=json&type=full", filename);
}

function exportAssetsCsv() {
    showToast("Generating enterprise asset inventory CSV...", "info");
    const filename = `RiskLens_Enterprise_Assets_${new Date().toISOString().slice(0, 10)}.csv`;
    downloadDataExport("/api/data/export?format=csv", filename);
}

function exportAssetsJson() {
    showToast("Generating asset inventory JSON...", "info");
    const filename = `RiskLens_Enterprise_Assets_${new Date().toISOString().slice(0, 10)}.json`;
    downloadDataExport("/api/data/export?format=json&type=assets", filename);
}

function downloadTemplate(fmt) {
    showToast(`Downloading asset import template (${fmt.toUpperCase()})...`, "info");
    const filename = `risklens_asset_template.${fmt}`;
    downloadDataExport(`/api/data/template?format=${fmt}`, filename);
}


// Initialize Application
document.addEventListener("DOMContentLoaded", () => {
    applyTheme(currentTheme, false);
    checkAuthSession();
    loadIndustryDatasetsCatalog();
    loadActiveDatasetMetadata();
    initDropZone();

    // Auto-fill suggestions & password sync for login page
    const signinEmail = document.getElementById("signin-email");
    const signinPassword = document.getElementById("signin-password");
    const emailDropdown = document.getElementById("signin-email-autocomplete");

    if (signinEmail) {
        // Show interactive suggestions on focus or click
        signinEmail.addEventListener("focus", () => {
            showEmailSuggestions();
        });
        signinEmail.addEventListener("click", () => {
            showEmailSuggestions();
        });

        // Hide suggestions when clicking outside
        document.addEventListener("click", (e) => {
            if (!signinEmail.contains(e.target) && (!emailDropdown || !emailDropdown.contains(e.target))) {
                hideEmailSuggestions();
            }
        });

        // Auto-fill matching password when demo email is selected or typed
        const DEMO_CREDENTIALS = {
            "ciso@enterprisebank.com": "RiskLens@2026",
            "risk@enterprisebank.com": "RiskLens@2026",
            "board@enterprisebank.com": "RiskLens@2026"
        };

        const handleEmailInput = () => {
            const val = (signinEmail.value || "").trim().toLowerCase();
            if (DEMO_CREDENTIALS[val] && signinPassword && !signinPassword.value) {
                signinPassword.value = DEMO_CREDENTIALS[val];
                signinPassword.dataset.userActive = "true";
            }
            // Filter dropdown options when typing
            if (emailDropdown) {
                const buttons = emailDropdown.querySelectorAll("button");
                let anyVisible = false;
                buttons.forEach(btn => {
                    const text = btn.innerText.toLowerCase();
                    if (!val || text.includes(val)) {
                        btn.style.display = "flex";
                        anyVisible = true;
                    } else {
                        btn.style.display = "none";
                    }
                });
                if (anyVisible) {
                    showEmailSuggestions();
                } else {
                    hideEmailSuggestions();
                }
            }
        };

        signinEmail.addEventListener("input", handleEmailInput);
        signinEmail.addEventListener("change", handleEmailInput);
    }

    // Escape key closes open modals (Data Exchange & Copilot)
    window.addEventListener("keydown", (e) => {
        if (e.key === "Escape") {
            closeCopilotModal();
            closeDataModal();
        }
    });

    if (window.lucide) lucide.createIcons();
});
