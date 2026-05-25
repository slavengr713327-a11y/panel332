# 漏洞知识库 (Vulnerability Knowledge Base)

这是一个自动同步 GitHub 漏洞数据并展示的 Web 应用。

## 🚀 核心功能
- **自动化同步**：每小时自动从指定 GitHub 仓库同步漏洞数据（JSON/Markdown/YAML），并存入 SQLite 数据库。
- **数据去重与更新**：基于文件路径进行 Upsert 操作，确保数据唯一且最新。
- **多维分类**：支持按 **年份** 和 **漏洞类型**（注入、RCE、认证等）进行自动分类。
- **认证功能**：集成登录系统，只有授权用户才能访问漏洞详情。
- **响应式展示**：基于 Flask + Jinja2 + TailwindCSS 构建。

## 🛠 技术栈
- **后端**：Python 3.9+, Flask, Flask-SQLAlchemy, Flask-Login
- **数据库**：SQLite (本地文件 `vulnerability.db`)
- **同步**：Requests, PyYAML

## ⚙️ 本地运行
1. **安装依赖**：
   ```bash
   pip install -r requirements.txt
   ```
2. **初始化数据库并创建管理员**：
   ```bash
   # 初始化表结构
   python app.py 
   # 在另一个终端创建管理员账号
   flask create-admin
   ```
3. **运行同步脚本**：
   ```bash
   python scripts/sync.py
   ```
4. **启动 Web 应用**：
   ```bash
   python app.py
   ```
   访问 `http://localhost:5000` 并使用创建的账号登录。

## 📂 数据库说明
数据存储在项目根目录的 `vulnerability.db` 中。主要字段包括：
- `year`: 从发布日期自动提取。
- `vuln_type`: 根据标题和描述自动识别分类（如 Injection, RCE, Auth 等）。
- `references_json`: 以 JSON 字符串形式存储参考链接。

## 🌐 GitHub Actions 配置
1. 将本项目推送到 GitHub 仓库。
2. 在仓库设置中：
   - `Settings` -> `Actions` -> `General` -> `Workflow permissions` 确保开启了 `Read and write permissions`。
   - `Settings` -> `Pages` -> `Build and deployment` -> `Source` 选择 `GitHub Actions`。
3. 脚本会自动在每小时运行一次同步，并将结果部署到 GitHub Pages。

## ❓ 常见问题
- **API 限流**：GitHub API 对匿名请求有限制（每小时 60 次）。在 GitHub Actions 中，脚本会自动使用 `GITHUB_TOKEN`，限额会提升至每小时 5000 次。
- **数据解析失败**：如果某个文件解析失败，脚本会跳过该文件并记录错误，不会中断整体同步。
