.PHONY: help install install-dev check lint format typecheck test contracts integration cli-smoke verify-real verify-loop release-pkg clean

#: 版本单一真源：pyproject.toml（发布包名由它派生，页面下载链接与之一致）
VERSION := $(shell sed -n 's/^version = "\(.*\)"/\1/p' pyproject.toml | head -1)
RELEASE_PKG := pea-$(VERSION)-release.zip

help: ## 显示可用目标
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

install: ## 安装（仅运行时，零第三方依赖）
	pip install -e .

install-dev: ## 开发安装
	pip install -e ".[dev]"

lint: ## ruff 检查
	ruff check src tests scripts

format: ## ruff 自动修复
	ruff check src tests scripts --fix

typecheck: ## mypy 类型检查
	mypy

test: ## 单元测试
	python -m pytest tests -q

contracts: ## 契约一致性门（schemas 为唯一真源）
	python -m pytest tests/test_contracts.py -q

integration: ## 全集成面（需可选依赖 mcp>=2.0：协议层 + 契约 + 工具面随 SDK 走真实子进程）
	pip install -e ".[dev,mcp]"
	python -m pytest tests/test_mcpstdio.py tests/test_toolschemas.py -q

cli-smoke: ## CLI 冒烟
	pea catalog
	pea search --target javascript --goal obfuscation
	pea plan --request examples/protection-request.example.json --out /tmp/pea-plan.json

verify-real: ## L2 真实工兵层（对合成形态 canary 产物跑真实域；按 REA 纪律单独触发，不在 check 内）
	python3 scripts/verify_real.py

verify-loop: ## WP4 执行闭环端到端（真实工具 + node 子进程；单独触发，不在 check 内）
	python3 scripts/verify_loop.py

release-pkg: ## 生成发布包 pea-<版本>-release.zip（仅跟踪文件；上传到仓库根目录供页面按钮下载）
	git archive --format=zip --prefix=pea-$(VERSION)/ -o $(RELEASE_PKG) HEAD
	@echo "生成 $(RELEASE_PKG)（版本 $(VERSION)）；上传到仓库根目录后，index.html 的下载按钮即可指向它"

check: lint typecheck test contracts ## 全量检查（CI 等价）

clean: ## 清理构建与缓存产物
	rm -rf build dist *.egg-info .pytest_cache .mypy_cache .ruff_cache htmlcov coverage.xml
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +
