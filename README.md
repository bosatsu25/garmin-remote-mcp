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
    │                                     │  同意画面で OWNER_PASSWORD を入力
    └──── Bearer token ──▶ /mcp ──────────┴─▶ Garmin Connect (DI トークン, /data に永続化)
```

- **Garmin のパスワードはサーバーに置きません。** 手元の PC で一度だけログインしてトークンを発行し、Fly の secret 経由で渡します。以後のリフレッシュはサーバーが行い、Volume に保存します。サーバーから SSO ログインを繰り返すと Garmin に 429 でブロックされるので、それを避ける設計です。
- MCP 側のアクセストークンは SHA-256 ハッシュだけをディスクに保存します。
- OAuth のリダイレクト先は `claude.ai` / `claude.com` / `localhost` に限っています。第三者がクライアントを登録して、認可コードを自分のサーバーに送らせることはできません。
- パスワード入力は IP ごとに 15 分で 5 回、全体で 1 時間に 30 回までです。

## ツール

| 種別 | ツール |
|---|---|
| プロフィール | `get_profile` |
| ウェルネス | `get_daily_summary`, `get_sleep`, `get_sleep_range`, `get_hrv`, `get_hrv_range`, `get_body_battery`, `get_stress`, `get_heart_rate`, `get_steps_range`, `get_body_composition` |
| トレーニング | `get_training_readiness`, `get_training_status`, `get_vo2max`, `get_race_predictions`, `get_endurance_score` |
| アクティビティ | `list_activities`, `get_activity` |
| ワークアウト（読み取り） | `list_workouts`, `get_workout`, `get_calendar` |
| 汎用 | `garmin_api_get`（任意の Connect API パスへの読み取り専用 GET） |
| **書き込み** | `create_workout`, `schedule_workout`, `unschedule_workout`, `delete_workout` |

- 書き込み系は `GARMIN_ALLOW_WRITE=false` にすると公開されません。
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

```bash
fly secrets set OWNER_PASSWORD='ここに保存した値' --stage
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
3. 「接続」を押すと同意画面が開くので、`OWNER_PASSWORD` を入力します。

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

**全クライアントの接続を切りたいとき**:

```bash
fly ssh console -C "rm /data/oauth_state.json"
```

```bash
fly apps restart
```

## ローカル開発

```bash
pip install -e ".[dev]"
```

```bash
pytest
```

```bash
PUBLIC_URL=http://localhost:8000 OWNER_PASSWORD=dev-password-123456 DATA_DIR=./data garmin-mcp
```

## 設定（環境変数）

| 変数 | 必須 | 説明 |
|---|---|---|
| `PUBLIC_URL` | ✓ | 外部から見える URL。`https://` 必須（localhost のみ http 可） |
| `OWNER_PASSWORD` | ✓ | 同意画面のパスワード（16文字以上） |
| `GARMIN_TOKENS` | 初回 | `garmin-mcp-login` の出力。JSON または base64 |
| `DATA_DIR` | | 永続化ディレクトリ（デフォルトは `/data`） |
| `GARMIN_ALLOW_WRITE` | | `false` で書き込み系ツールを無効化（デフォルトは `true`） |
| `ALLOWED_REDIRECT_HOSTS` | | OAuth リダイレクト先として許可するホスト（カンマ区切り） |
| `PORT` | | 待ち受けポート（デフォルトは `8000`） |
