"use strict";

const invoke = window.__TAURI__.core.invoke;
const listElement = document.getElementById("list");
const form = document.getElementById("add");
const submitButton = form.querySelector("button[type=submit]");

const escapeHtml = value => String(value ?? "").replace(/[&<>"']/g, character => ({
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  "\"": "&quot;",
  "'": "&#39;"
})[character]);

let toastTimer;
function toast(message) {
  const element = document.getElementById("toast");
  element.textContent = String(message);
  element.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => element.classList.remove("show"), 3600);
}

function pointerRow(secret) {
  const name = escapeHtml(secret.name);
  const account = secret.account
    ? `<button class="chip acct" type="button" data-action="account" data-name="${name}" title="Copy the account/ID">👤 ${escapeHtml(secret.account)}</button>`
    : "";
  const allowed = (secret.allowed_for || [])
    .map(entry => `<span class="chip">${escapeHtml(entry)}</span>`)
    .join("");
  return `<div class="row">
    <div class="id">
      <div class="name">${name}</div>
      <div class="meta">
        <span class="env">$${escapeHtml(secret.env)}</span>
        ${secret.service ? `<span>${escapeHtml(secret.service)}</span>` : ""}
        ${account}${allowed}
      </div>
    </div>
    <span class="used">${secret.last_used ? `used ${escapeHtml(secret.last_used)}` : "never used"}</span>
    <button class="btn" type="button" data-action="copy" data-name="${name}">Copy 30s</button>
    <button class="btn danger" type="button" data-action="remove" data-name="${name}">Delete</button>
  </div>`;
}

async function refresh() {
  try {
    const data = await invoke("list_secrets");
    if (!data.secrets || !data.secrets.length) {
      listElement.innerHTML = '<div class="empty"><b>No secrets yet.</b><br>Add one on the right. The pointer appears here; the value never does.</div>';
      return;
    }
    listElement.innerHTML = data.secrets.map(pointerRow).join("");
  } catch (error) {
    listElement.innerHTML = '<div class="empty"><b>Could not load the vault.</b><br>See the notification for details.</div>';
    toast(error);
  }
}

listElement.addEventListener("click", async event => {
  const button = event.target.closest("button[data-action]");
  if (!button) return;
  const { action, name } = button.dataset;
  button.disabled = true;
  try {
    if (action === "copy") {
      toast(await invoke("copy_secret", { name }));
    } else if (action === "account") {
      toast(await invoke("copy_account", { name }));
    } else if (action === "remove" && window.confirm(`Delete '${name}' from the OS vault and pointer manifest?`)) {
      toast(await invoke("remove_secret", { name }));
      await refresh();
    }
  } catch (error) {
    toast(error);
  } finally {
    button.disabled = false;
  }
});

form.addEventListener("submit", async event => {
  event.preventDefault();
  const field = name => form.elements.namedItem(name).value;
  const args = {
    name: field("name"),
    value: field("value"),
    service: field("service"),
    env: field("env"),
    allow: field("allow"),
    note: field("note"),
    account: field("account")
  };
  submitButton.disabled = true;
  try {
    const message = await invoke("add_secret", args);
    form.reset();
    toast(message);
    await refresh();
  } catch (error) {
    toast(error);
  } finally {
    args.value = "";
    form.elements.namedItem("value").value = "";
    submitButton.disabled = false;
  }
});

window.addEventListener("keydown", event => {
  if (event.key === "Escape") {
    window.__TAURI__.window.getCurrentWindow().hide();
  }
});
window.addEventListener("focus", refresh);

async function initialize() {
  try {
    const info = await invoke("app_info");
    document.getElementById("backend").textContent = `local · ${info.backend}`;
    document.getElementById("shortcut").textContent = info.shortcut;
  } catch (error) {
    toast(error);
  }
  await refresh();
}

initialize();

