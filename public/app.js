const $ = (s) => document.querySelector(s);
const fa = n => Number(n || 0).toLocaleString("fa-IR");
let dashboardData = null;

async function api(url, options = {}) {
  const res = await fetch(url, {
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || "خطایی رخ داد.");
  return data;
}
function toast(message) {
  const el = $("#toast"); el.textContent = message; el.classList.remove("hidden");
  clearTimeout(toast.timer); toast.timer = setTimeout(() => el.classList.add("hidden"), 3200);
}
function showNotice(el, message, error = false) {
  el.textContent = message; el.classList.remove("hidden", "error");
  if (error) el.classList.add("error");
}
function showApp(authenticated) {
  $("#loginView").classList.toggle("hidden", authenticated);
  $("#appView").classList.toggle("hidden", !authenticated);
  $("#logoutBtn").classList.toggle("hidden", !authenticated);
  if (authenticated) loadDashboard();
}
async function checkSession() {
  try { const me = await api("/api/me"); showApp(me.authenticated); }
  catch { showApp(false); }
}
$("#loginForm").addEventListener("submit", async e => {
  e.preventDefault();
  const form = new FormData(e.currentTarget);
  try {
    await api("/api/login", { method: "POST", body: JSON.stringify(Object.fromEntries(form)) });
    $("#loginError").classList.add("hidden"); e.currentTarget.reset(); showApp(true);
  } catch (err) { showNotice($("#loginError"), err.message, true); }
});
$("#logoutBtn").addEventListener("click", async () => {
  try { await api("/api/logout", { method: "POST" }); showApp(false); }
  catch (e) { toast(e.message); }
});

document.querySelectorAll(".tab").forEach(btn => btn.addEventListener("click", () => {
  document.querySelectorAll(".tab").forEach(x => x.classList.toggle("active", x === btn));
  ["register","customers","referrals","weekly"].forEach(id => $(`#${id}Panel`).classList.toggle("hidden", id !== btn.dataset.tab));
  if (btn.dataset.tab === "customers") loadCustomers();
  if (btn.dataset.tab === "referrals") loadReferrals();
  if (btn.dataset.tab === "weekly") renderWeekly();
}));

$("#sendOtpBtn").addEventListener("click", async () => {
  const phone = $("#customerForm [name=phone]").value.trim();
  try {
    const result = await api("/api/otp/send", { method: "POST", body: JSON.stringify({ phone }) });
    showNotice($("#registerMessage"), result.message);
  } catch (e) { showNotice($("#registerMessage"), e.message, true); }
});
$("#customerForm").addEventListener("submit", async e => {
  e.preventDefault();
  const data = Object.fromEntries(new FormData(e.currentTarget));
  try {
    const result = await api("/api/customers", { method: "POST", body: JSON.stringify(data) });
    const c = result.customer;
    $("#newCustomerCard").innerHTML = `<div>مشتری با موفقیت ثبت شد</div><strong>${escapeHtml(c.publicId)}</strong><div>${escapeHtml(c.name)} · ${escapeHtml(c.phone)}</div><small>شناسه اختصاصی مشتری را به او اعلام کنید.</small>`;
    $("#newCustomerCard").classList.remove("hidden");
    $("#registerMessage").classList.add("hidden");
    e.currentTarget.reset();
    await loadDashboard();
    toast("مشتری جدید ثبت شد.");
  } catch (err) { showNotice($("#registerMessage"), err.message, true); }
});
function escapeHtml(s) {
  return String(s ?? "").replace(/[&<>"']/g, c => ({ "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#39;" }[c]));
}
async function loadDashboard() {
  try {
    dashboardData = await api("/api/dashboard");
    $("#totalCount").textContent = fa(dashboardData.total);
    $("#weekCount").textContent = fa(dashboardData.week);
    $("#todayCount").textContent = fa(dashboardData.today);
    $("#referralCount").textContent = fa(dashboardData.referrals);
    $("#todayLabel").textContent = new Intl.DateTimeFormat("fa-IR", { dateStyle:"medium" }).format(new Date());
  } catch (e) { if (e.message) toast(e.message); }
}
async function loadCustomers() {
  try {
    const q = $("#customerSearch").value.trim();
    const result = await api(`/api/customers?q=${encodeURIComponent(q)}`);
    $("#customersBody").innerHTML = result.customers.map(c => `<tr>
      <td class="id-tag">${escapeHtml(c.public_id)}</td><td>${escapeHtml(c.name)}</td><td>${escapeHtml(c.phone)}</td>
      <td>${c.referrer_code ? `${escapeHtml(c.referrer_name)} (${escapeHtml(c.referrer_code)})` : "—"}</td>
      <td>${fa(c.referral_count)}</td><td>${new Date(c.created_at.replace(" ","T")+"Z").toLocaleDateString("fa-IR")}</td>
    </tr>`).join("") || `<tr><td colspan="6">موردی پیدا نشد.</td></tr>`;
  } catch (e) { toast(e.message); }
}
$("#searchBtn").addEventListener("click", loadCustomers);
$("#customerSearch").addEventListener("keydown", e => { if (e.key === "Enter") loadCustomers(); });

async function loadReferrals() {
  if (!dashboardData) await loadDashboard();
  const rows = dashboardData?.topReferrers || [];
  $("#referralsBody").innerHTML = rows.map(c => `<tr><td class="id-tag">${escapeHtml(c.public_id)}</td><td>${escapeHtml(c.name)}</td><td>${escapeHtml(c.phone)}</td><td><b>${fa(c.referral_count)}</b></td></tr>`).join("") || `<tr><td colspan="4">هنوز اطلاعاتی ثبت نشده است.</td></tr>`;
}
function renderWeekly() {
  const rows = dashboardData?.weekly || [];
  const max = Math.max(1, ...rows.map(r => r.count));
  const days = [];
  for (let i=6; i>=0; i--) {
    const d = new Date(); d.setDate(d.getDate()-i);
    const key = `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,"0")}-${String(d.getDate()).padStart(2,"0")}`;
    const found = rows.find(r => r.day === key);
    days.push({ day:d.toLocaleDateString("fa-IR",{weekday:"long",day:"numeric"}), count:found?.count || 0 });
  }
  $("#weeklyBars").innerHTML = days.map(d => `<div class="bar-row"><span>${d.day}</span><div class="bar-track"><div class="bar-fill" style="width:${d.count/max*100}%"></div></div><b>${fa(d.count)}</b></div>`).join("");
}
if ("serviceWorker" in navigator) window.addEventListener("load", () => navigator.serviceWorker.register("/sw.js").catch(()=>{}));
checkSession();
