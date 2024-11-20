

---

# 🌟 **azauthlib** 🌟

> **Your Simplified Authentication Companion for Azure Microsoft Graph**

`azauthlib` is a Python library that **streamlines the authentication process** with Azure Microsoft Graph. From interactive logins to client credentials flow, `azauthlib` provides an intuitive interface, robust token management, and a GUI for seamless configuration.  

🔐 Whether you're building applications that interact with Microsoft Graph APIs or automating workflows, `azauthlib` has you covered.

---

## ✨ **Features** ✨

✅ **Multiple Authentication Flows**  
- Silent Authentication  
- Interactive Authentication  
- Device Code Flow  
- Client Credentials  

✅ **Graphical User Interface (GUI)**  
- Configure credentials with an easy-to-use GUI.

✅ **Token Management**  
- Automatic refresh for access tokens  
- Secure token storage  

✅ **Flexible Environment Configuration**  
- Use `.env` files, OS variables, or direct input.  

✅ **Customizable Permissions**  
- Specify Microsoft Graph API scopes effortlessly.

---

## 🚀 **Installation**

### Install from PyPI  

```bash
pip install azauthlib
```

### Install from Source  

```bash
git clone https://github.com/cedricmoorejr/azauthlib.git
cd azauthlib
pip install .
```

### 📋 **Requirements**
- Python 3.7+
- `msal`
- `portalocker`
- `python-dotenv`

Install dependencies manually if needed:  

```bash
pip install -r requirements.txt
```

---

## 🛠 **Getting Started**

### 1️⃣ **Prerequisites**
- Register an app in **Azure Active Directory** via the [Azure Portal](https://portal.azure.com/).
- Collect the following:
  - `CLIENT_ID`
  - `TENANT_ID`
  - (Optional) `CLIENT_SECRET`  

- Assign the appropriate Microsoft Graph API permissions.

### 2️⃣ **Configuration Options**
#### 🌐 **Option A: GUI Mode**

Launch the GUI for intuitive configuration:

```bash
python config_app.py
```

> 💡 **What You Can Do in the GUI:**  
> - Enter credentials (`CLIENT_ID`, `TENANT_ID`, etc.).  
> - Choose your authentication method.  
> - Credentials are saved securely in a `.env` file.  

![GUI Screenshot](https://raw.githubusercontent.com/cedricmoorejr/azauthlib/v1.0.0b1/assets/gui_main.png)

---

#### 🛠 **Option B: Non-GUI Mode**

1. **Using Environment Variables** (Recommended):  

```bash
export TENANT_ID="your-tenant-id"
export CLIENT_ID="your-client-id"
export CLIENT_SECRET="your-client-secret"
```

2. **Hardcoding in Code** (⚠️ Not Recommended):  

```python
from azauthlib import Authentication

auth = Authentication(scopes="Files.ReadWrite.All")
auth.Build.WithEntry(
    client_id="your-client-id",
    tenant_id="your-tenant-id",
    client_secret="your-client-secret"
)
```

---

## 🔑 **Authentication Flows**

### 🔒 **Silent Authentication**  
Authenticate using cached tokens.  

```python
auth.Silent()
```

### 🌐 **Interactive Authentication**  
Prompts user to log in via a browser.

```python
auth.Interactive()
```

### 📱 **Device Code Flow**  
Displays a device code for cross-device authentication.

```python
auth.DeviceCodeFlow(webbrowser_enabled=True)
```

### 🤝 **Client Credentials Flow**  
Authenticate server-to-server.

```python
auth.ClientCredentials()
```

---

## 💼 **Token Management**

- **Access Token**: Retrieve the active token.  

  ```python
  token = auth.access_token
  ```

- **Token Expiry**: Check token lifetime.  

  ```python
  print("Token expires in:", auth.token_expires_in)
  ```

- **Automatic Refresh**: Tokens are refreshed seamlessly.

---

## 📜 **Logging**

Easily track authentication flow and token operations using Python’s `logging` module. Customize as needed!

---

## 🤝 **Contributing**

We welcome contributions! 🚀 Here's how you can help:  
1. Fork the repo.  
2. Create a feature or bugfix branch.  
3. Submit a PR with a detailed description.  

---

## 📄 **License**

This project is licensed under the **Apache License 2.0**. See the `LICENSE` file for more details.

---

## ℹ️ **Trademarks**

- This project references **Microsoft** trademarks such as Azure and Microsoft Graph. Please ensure compliance with Microsoft’s [Trademark Guidelines](https://www.microsoft.com/trademarks).

---

🔗 **[GitHub Repository](https://github.com/cedricmoorejr/azauthlib/tree/v1.0.0b1)**  
💬 **Feedback? Issues?** We’d love to hear from you!

--- 



