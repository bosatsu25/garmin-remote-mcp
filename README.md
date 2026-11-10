# garmin-remote-mcp

Garmin Connect のデータを claude.ai（Web / スマホアプリ）から使うための **Remote MCP サーバー**です。
1人のオーナー専用で、OAuth 2.1 の認可サーバーを内蔵し、Streamable HTTP で動きます。Fly.io にデプロイする前提です。

> [!WARNING]
> Garmin には個人向けの公式 API がありません。このサーバーは非公式ライブラリ
> [`python-garminconnect`](https://github.com/cyberjunky/python-garminconnect) を使っています。
> Garmin 側の仕様変更で突然動かなくなることがあり、2026年3月にも実際に起きました。
> Garmin の利用規約上もグレーです。自己責任で、自分のアカウントにだけ使ってください。

## 仕組み

```
claude.ai ──OAuth 2.1 (DCR + PKCE)──▶ このサーバー (/authorize, /token, /register)
    │                                     │  同意画面でオーナーパスワードを入力
    └──── Bearer token ──▶ /mcp ──────────┴─▶ Garmin Connect (DI トークン, /data に永続化)
```

- **Garmin のパスワードはサーバーに置きません。** 手元の PC で一度だけログインしてトークンを発行し、Fly の secret 経由で渡します。以後のリフレッシュはサーバーが行い、Volume に保存します。サーバーから SSO ログインを繰り返すと Garmin に 429 でブロックされるので、それを避ける設計です。
- **書き込みは接続ごとの明示的な許可が必要です。** 同意画面で「書き込みも許可する」にチェックしない限り、その接続のトークンは `garmin:read` だけになり、書き込みツールはサーバー側で必ず拒否されます。Garmin のデータに悪意ある指示が紛れ込んでいても（プロンプトインジェクション）、読み取り専用の接続からはワークアウトを消せません。
- **オーナーパスワードは scrypt ハッシュで渡せます**（`OWNER_PASSWORD_HASH`）。サーバーは平文を持ちません。
- **盗まれたリフレッシュトークンは使い捨てになります。** リフレッシュのたびにトークンをローテーションし、使用済みのトークンが再提示されたらその接続のトークンをすべて失効させます。使用済みの認可コードが再提示された場合も同じです。接続の寿命は最長90日です。
- **接続は自分で確認・取り消しできます。** `https://<your-app>.fly.dev/oauth/connections` にオーナーパスワードでログインすると、有効な接続の一覧が出て、個別にもまとめても取り消せます。
- MCP 側のトークンは SHA-256 ハッシュだけを、権限 0600 のファイルに保存します。
- OAuth のリダイレクト先は `claude.ai` / `claude.com` / `localhost` に限っています。userinfo（`claude.ai@evil.com`）、フラグメント、制御文字を含む URL は拒否します。
- パスワード入力は IP ごとに 15 分で 5 回、全体で 1 時間に 30 回までです。
- エラーメッセージからトークンらしい文字列を除去してから返します。応答にはセキュリティヘッダー（HSTS、CSP、X-Frame-Options など）を付け、ボディは 256KiB までに制限しています。
- 依存パッケージはハッシュ付きロックファイルで固定し、CI で脆弱性スキャンとミューテーションテストを実行します。

テスト設計とリスク分析は [docs/test-plan.md](docs/test-plan.md) にまとめています（JSTQB FL V4.0 準拠）。

## ツール

| 種別 | ツール |
|---|---|
| プロフィール | `get_profile` |
| ウェルネス | `get_daily_summary`, `get_sleep`, `get_sleep_range`, `get_hrv`, `get_hrv_range`, `get_body_battery`, `get_stress`, `get_heart_rate`, `get_steps_range`, `get_body_composition` |
| トレーニング | `get_training_readiness`, `get_training_status`, `get_vo2max`, `get_race_predictions`, `get_endurance_score` |
| アクティビティ | `list_activities`, `get_activity` |
| ワークアウト（読み取り） | `list_workouts`, `get_workout`, `get_calendar` |
| 汎用（デフォルト無効） | `garmin_api_get`（任意の Connect API パスへの読み取り専用 GET。`GARMIN_ENABLE_RAW_API=true` で有効） |
| **書き込み** | `create_workout`, `schedule_workout`, `unschedule_workout`, `delete_workout` |

- 書き込み系ツールは、同意画面で書き込みを許可した接続でしか動きません。`GARMIN_ALLOW_WRITE=false` にすると、ツール自体が公開されず、同意画面にもチェックボックスが出ません。
- `create_workout` はランニング、サイクリング、ウォーキング、ハイキング、カーディオ、その他に対応しています。水泳と筋トレは Garmin 側で専用フィールドが必要なので未対応です。
- 時系列データ（心拍の全サンプルなど）はデフォルトで省略し、コンテキストを節約します。必要なときは `raw=true` を指定してください。

## セットアップ

### 1. Garmin トークンを手元で発行する

Python 3.12 以上が必要です。

```bash
git clone https://github.com/bosatsu25/garmin-remote-mcp && cd garmin-remote-mcp
```

```bash
python -m venv .venv && . .venv/bin/activate && pip install -e .
```

```bash
garmin-mcp-login > garmin-tokens.env
```

メールアドレス、パスワード、MFA コード（設定している場合）を聞かれます。
出力された `garmin-tokens.env` には `GARMIN_TOKENS=...` が1行だけ入っています。**パスワードと同じ扱い**にしてください。

### 2. Fly.io にデプロイする

`fly.toml` の `app` と `PUBLIC_URL` を、自分のアプリ名に書き換えます（2か所の `garmin-mcp-CHANGE-ME`）。

```bash
fly launch --no-deploy --copy-config
```

```bash
fly volumes create garmin_data --size 1 --region nrt
```

オーナーパスワード（16文字以上）を決めて、パスワードマネージャーに保存します。claude.ai から接続を許可するときに入力します。生成する場合は次のコマンドを使います。

```bash
openssl rand -base64 24
```

手元でハッシュ化して、ハッシュだけをサーバーに渡します（入力した値は画面に表示されません）。

```bash
garmin-mcp-hash-password | fly secrets import --stage
```

```bash
fly secrets import --stage < garmin-tokens.env
```

```bash
fly deploy --ha=false
```

```bash
rm garmin-tokens.env
```

`--ha=false` は必須です。Volume は 1 台のマシンにしか付けられないので、マシンは 1 台で動かします。

### 3. claude.ai に追加する

1. claude.ai の **設定 → コネクタ → カスタムコネクタを追加** を開きます。
2. URL に `https://<your-app>.fly.dev/mcp` を入力します。
3. 「接続」を押すと同意画面が開くので、オーナーパスワードを入力します。ワークアウトの作成・削除もさせたい場合だけ「書き込みも許可する」にチェックします。

読み取り専用で接続した後に書き込みが必要になったら、コネクタを切断して接続し直し、チェックを入れてください。

スマホアプリでは、Web で追加したコネクタがそのまま使えます。

## 運用

**Garmin トークンが失効したとき**（ツールが「Garmin rejected the stored tokens」と返す場合）は、手順1をやり直してから次を実行します。

```bash
fly ssh console -C "rm /data/garmin/garmin_tokens.json"
```

```bash
fly secrets import < garmin-tokens.env
```

Volume 上のトークンが優先され、seed は Volume にトークンがないときだけ使われます。そのため、先に Volume のファイルを消す必要があります。

**接続を取り消したいとき**（スマホをなくした、身に覚えのない接続がある、など）は、ブラウザで `https://<your-app>.fly.dev/oauth/connections` を開き、オーナーパスワードを入力して取り消します。

**オーナーパスワードを変えたいとき**は、新しいハッシュを設定してから、上の画面ですべての接続を取り消してください。

```bash
garmin-mcp-hash-password | fly secrets import
```

## ローカル開発

```bash
pip install --require-hashes -r requirements-dev.lock && pip install --no-deps -e .
```

単体・統合・システム・受け入れの全テストを、ブランチカバレッジのゲート付きで実行します。

```bash
pytest --cov
```

意図的にセキュリティバグを埋め込み、テストが検出できるか確認します（数分かかります）。

```bash
python tools/mutation_check.py
```

```bash
PUBLIC_URL=http://localhost:8000 OWNER_PASSWORD=dev-password-123456 DATA_DIR=./data garmin-mcp
```

## 設定（環境変数）

| 変数 | 必須 | 説明 |
|---|---|---|
| `PUBLIC_URL` | ✓ | 外部から見える URL。`https://` 必須（localhost のみ http 可） |
| `OWNER_PASSWORD_HASH` | ✓※ | `garmin-mcp-hash-password` の出力（推奨） |
| `OWNER_PASSWORD` | ✓※ | 平文のパスワード（16〜1024文字、制御文字不可）。※どちらか片方だけ指定。全角・半角や濁点の合成の違いは NFKC 正規化で吸収します |
| `GARMIN_TOKENS` | 初回 | `garmin-mcp-login` の出力。JSON または base64 |
| `DATA_DIR` | | 永続化ディレクトリ（デフォルトは `/data`） |
| `GARMIN_ALLOW_WRITE` | | `false` で書き込み系ツールを無効化（デフォルトは `true`。有効でも接続ごとの許可が必要） |
| `GARMIN_ENABLE_RAW_API` | | `true` で `garmin_api_get` を有効化（デフォルトは `false`） |
| `TRUST_FLY_CLIENT_IP` | | レート制限に `Fly-Client-IP` ヘッダーを使うか。Fly 上（`FLY_APP_NAME` がある）ではデフォルト `true`、それ以外では `false`。Fly のプロキシ以外ではこのヘッダーは偽装できます |
| `ALLOWED_REDIRECT_HOSTS` | | OAuth リダイレクト先として許可するホスト（カンマ区切り） |
| `PORT` | | 待ち受けポート（デフォルトは `8000`） |

## 依存パッケージの更新

ロックファイルはハッシュ付きです。`pyproject.toml` を変えたら再生成してください（CI が不一致を検出します）。

```bash
uv pip compile pyproject.toml --generate-hashes --python-version 3.13 --python-platform x86_64-manylinux_2_28 -o requirements.lock
```

```bash
uv pip compile pyproject.toml --extra dev --generate-hashes --python-version 3.13 --python-platform x86_64-manylinux_2_28 -o requirements-dev.lock
```
