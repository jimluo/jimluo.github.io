+++
title = "[翻译]Rust中的密码验证,从头开始,攻击和最佳实践"
[taxonomies]
tags = [ "Linux" ]
+++

本文翻译自书[Zero To Production In Rust](https://www.zero2prod.com/)作者的blog章节[Rust中的密码验证](https://www.lpalmieri.com/posts/password-authentication-in-rust/#blocking-alice)

机器翻译味道浓厚，如有不妥请麻告知。
本文讲了支付系统中遇到的安全问题，层层深入问题，遇到的业务及安全知识逐步推开，再辅之以代码就单元测试，学起来不会就不会从入门到放弃了。

我再其中学到安全知识如下
1. 密码认证， Basic Auth
2. 密码存储，（本文重点），加密密码及其攻击方式和预防方法
3. 密码网络交换，TLS
4. 认证流程， OAuth

主要用到RustCrypto crate，其中sha3,base64,argon2

**以下正文开始**

> 本文是Rust中从零到生产的示例,一本关于Rust后端开发的书。<br>
> 您可以在zero2prod.com上获得该书的副本。<br>
> 邮件订阅后能及时收到新发布文章的通知。<br>

## 1. 保护我们的 API
在第9章中,我们为API添加了一个新端点,POST /newsletters.
它将新闻简报问题作为输入,并向所有的订阅者发送电子邮件。

但是我们有一个问题, 任何人都可以点击API并将他们想要的任何内容广播到我们的整个邮件列表中。

是时候升级我们的API安全能力了。<br>
虽然密码身份验证是最简单的身份验证方法,但其中有一些坑,所以我们将从头开始基本身份验证,从中检查针对API的几类攻击, 以及应对方法。

> 出于教学目的,本章和书中其他章节里处理的一样,从犯错中学习。如果您不想养成不良的安全习惯,请务必阅读到文章末尾！

第10章,第0部分
1. 保护我们的API
2. 认证
    1. 缺点
        1. 他们知道的事情
        2. 他们有的东西
        3. 他们是什么
    2. 多因素身份验证
3. 基于密码的认证
    1. 基本认证
        1. 提取凭证
    2. 密码验证,天真的方法
    3. 密码存储
        1. 无需存储原始密码
        2. 使用加密哈希
        3. 原像攻击
        4. 朴素字典攻击
        5. 字典攻击
        6. Aragon2
        7. 盐
        8. PHC字符串格式
    4. 不要阻塞异步执行器
        1. 跟踪上下文是线程本地的
    5. 用户枚举
4. 安全吗？
    1. 传输层安全 (TLS)
    2. 重设密码
    3. 交互类型
    4. 机器对机器
        1. 通过 OAuth2的客户端凭据
    5. 人通过浏览器
        1. 联合身份
    6. 机器对机器,代表一个人
5. 我们接下来应该做什么

## 2. 认证
我们需要一种方法来检查**谁**调用POST /newsletters。
只有少数人（负责内容的人）能发送邮件到整个邮件列表。

先得找到调用者的**身份**,再对他们进行身份**验证**。
如何做？

要求调用者提供的自己独特信息。
这有多种方法,都归为3类：
1. 他们知道的东西（例如密码、PIN、安全问题）；
2. 他们拥有的东西（例如智能手机,使用身份验证器应用程序）；
3. 它们是某种东西（例如指纹、Apple 的 Face ID）。

每种方法都有其弱点。

### 2.1. 缺点
#### 2.1.1. 他们知道的事情
密码必须够长,短的容易受到暴力攻击。<br>
密码必须独特,公开信息（例如出生日期、家庭成员姓名等）不应给攻击者任何“猜测”密码的机会。<br>
密码不应该重复使用,如果其中任何一个被泄露,您就有可能授予对共享相同密码的其他服务的访问权限。<br>

平均而言,一个人拥有100个或更多的在线帐户,不能要求他们记住数百个长的独特密码。
密码管理器有所帮助,但它们还不是主流,而且用户体验通常不是最理想的。

#### 2.1.2. 他们拥有的东西
智能手机和U2F密钥可能会丢失,从而将用户锁定在他们的帐户之外。它们也可能被窃取或泄露,从而为攻击者提供了冒充受害者的机会。 

#### 2.1.3.它们是某种东西
生物识别技术,与密码不同,无法更改,您无法“旋转”指纹或更改视网膜血管的图案。事实证明,伪造指纹比大多数人想象的要容易,这也是政府机构经常能获得到的信息,他们可能会滥用或丢失它。 

### 2.2.多因子身份验证
既然每种方法都有自己的缺陷,那么我们应该怎么做呢？好吧,我们可以把它们结合起来！

这几乎就是多因素身份验证(MFA),它要求用户提供至少两种不同类型的身份验证因素才能获得访问权限。

## 3. 基于密码的认证
让我们跨越理论到实践：我们如何实现认证？

密码看起来是我们提到的三种方法中最简单的方法。
我们应该如何将用户名和密码传递给我们的API？

### 3.1. 基本认证
我们可以使用“基本”身份验证方案,这是Internet工程任务组 (IETF) 在RFC 2617中定义的标准,后来由RFC 7617更新。

https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Authentication

API必须在传入请求中查找Authorization header,其结构如下：
```
Authorization: Basic <encoded credentials>
```
其中<encoded credentials>是{username}:{password}[^1]的base64编码

根据规范,我们需要将API划分为保护空间或realm,同一realm内的资源使用相同的身份验证方案和一组凭据进行保护。
我们只要保护一个端点POST /newsletters。因此,我们将拥有一个名为publish的realm。

API必须拒绝所有缺少标头或使用无效凭据的请求,响应必须使用401 Unauthorized状态代码并包含特殊标头WWW-Authenticate, 包含质询。
质询是一个字符串,向API调用者解释我们希望在相关realm看到什么类型的身份验证方案。
在我们的例子中,使用基本身份验证,它应该是：
```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Basic realm="publish"
```
让我们来实现它！

#### 3.1.1. 提取凭证
从传入的请求中提取用户名和密码将是我们的第一个里程碑。<br>
让我们从一个不愉快的案例开始,被拒绝的传入请求,没有Authorization标头。

```rs
//! tests/api/newsletter.rs
// [...]

#[tokio::test]
async fn requests_missing_authorization_are_rejected() {
    // Arrange
    let app = spawn_app().await;

    let response = reqwest::Client::new()
        .post(&format!("{}/newsletters", &app.address))
        .json(&serde_json::json!({
            "title": "Newsletter title",
            "content": {
                "text": "Newsletter body as plain text",
                "html": "<p>Newsletter body as HTML</p>",
            }
        }))
        .send()
        .await
        .expect("Failed to execute request.");

    // Assert
    assert_eq!(401, response.status().as_u16());
    assert_eq!(r#"Basic realm="publish""#, response.headers()["WWW-Authenticate"]);
}
```

它在第一个断言处失败：
```sh
thread 'newsletter::requests_missing_authorization_are_rejected' panicked at 
'assertion failed: `(left == right)`
  left: `401`,
 right: `400`'
```
我们必须更新程序以满足新的要求。
我们可以使用HttpRequest提取器来访问与传入请求关联的标头：

```rs
//! src/routes/newsletters.rs
// [...]
use secrecy::Secret;
use actix_web::http::{HttpRequest, header::HeaderMap};

pub async fn publish_newsletter(
    // [...]
    // New extractor!
    request: HttpRequest,
) -> Result<HttpResponse, PublishError> {
    let _credentials = basic_authentication(request.headers());
    // [...]
}

struct Credentials {
    username: String,
    password: Secret<String>,
}

fn basic_authentication(headers: &HeaderMap) -> Result<Credentials, anyhow::Error> {
    todo!()
}
```

要提取凭证,我们需要处理 base64 编码。
让我们将base64 crate添加为依赖项：
```toml
[dependencies]
# [...]
base64 = "0.13"
```

我们现在可以写下basic_authentication:
```rs
//! src/routes/newsletters.rs
// [...]

fn basic_authentication(headers: &HeaderMap) -> Result<Credentials, anyhow::Error> {
    // The header value, if present, must be a valid UTF8 string
    let header_value = headers
        .get("Authorization")
        .context("The 'Authorization' header was missing")?
        .to_str()
        .context("The 'Authorization' header was not a valid UTF8 string.")?;
    let base64encoded_segment = header_value
        .strip_prefix("Basic ")
        .context("The authorization scheme was not 'Basic'.")?;
    let decoded_bytes = base64::decode_config(base64encoded_segment, base64::STANDARD)
        .context("Failed to base64-decode 'Basic' credentials.")?;
    let decoded_credentials = String::from_utf8(decoded_bytes)
        .context("The decoded credential string is not valid UTF8.")?;

    // Split into two segments, using ':' as delimitator
    let mut credentials = decoded_credentials.splitn(2, ':');
    let username = credentials
        .next()
        .ok_or_else(|| anyhow::anyhow!("A username must be provided in 'Basic' auth."))?
        .to_string();
    let password = credentials
        .next()
        .ok_or_else(|| anyhow::anyhow!("A password must be provided in 'Basic' auth."))?
        .to_string();

    Ok(Credentials {
        username,
        password: Secret::new(password)
    })
}
```

花点时间逐行浏览代码,并完全理解发生了什么。许多可能出错的操作！<br>
打开RFC比对本书内容会有所帮助！<br>

我们还没有完成,我们的测试仍然失败。<br>
我们需要对返回的错误采取行动basic_authentication：<br>

```rs
//! src/routes/newsletters.rs
// [...]

#[derive(thiserror::Error)]
pub enum PublishError {
    // New error variant!
    #[error("Authentication failed.")]
    AuthError(#[source] anyhow::Error),
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

impl ResponseError for PublishError {
    fn status_code(&self) -> StatusCode {
        match self {
            PublishError::UnexpectedError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            // Return a 401 for auth errors
            PublishError::AuthError(_) => StatusCode::UNAUTHORIZED,
        }
    }
}


pub async fn publish_newsletter(/* */) -> Result<HttpResponse, PublishError> {
    let _credentials = basic_authentication(request.headers())
        // Bubble up the error, performing the necessary conversion
        .map_err(PublishError::AuthError)?;
    // [...]
}
```
我们的状态码断言高兴通过了,但完成第2个断言还缺个标题：

```sh
thread 'newsletter::requests_missing_authorization_are_rejected' panicked at 
'no entry found for key "WWW-Authenticate"'
```

到目前为止,指定为每个错误返回哪个状态代码就足够了。现在我们需要更多的东西,一个标题。
我们需要将关注点ResponseError::status_code从ResponseError::error_response：
```rs
//! src/routes/newsletters.rs
// [...]
use actix_web::http::{StatusCode, header};
use actix_web::http::header::{HeaderMap, HeaderValue};

impl ResponseError for PublishError {
    fn error_response(&self) -> HttpResponse {
        match self {
            PublishError::UnexpectedError(_) => {
                HttpResponse::new(StatusCode::INTERNAL_SERVER_ERROR)
            }
            PublishError::AuthError(_) => {
                let mut response = HttpResponse::new(StatusCode::UNAUTHORIZED);
                let header_value = HeaderValue::from_str(r#"Basic realm="publish""#)
                    .unwrap();
                response
                    .headers_mut()
                    // actix_web::http::header provides a collection of constants
                    // for the names of several well-known/standard HTTP headers
                    .insert(header::WWW_AUTHENTICATE, header_value);
                response
            }
        }
    }
    
    // `status_code` is invoked by the default `error_response`
    // implementation. We are providing a bespoke `error_response` implementation
    // therefore there is no need to maintain a `status_code` implementation anymore.
}
```
我们的认证测试通过了！
另一部分代码又报错了：
```sh
test newsletter::newsletters_are_not_delivered_to_unconfirmed_subscribers ... FAILED
test newsletter::newsletters_are_delivered_to_confirmed_subscribers ... FAILED

thread 'newsletter::newsletters_are_not_delivered_to_unconfirmed_subscribers' 
panicked at 'assertion failed: `(left == right)`
  left: `401`,
 right: `200`'

thread 'newsletter::newsletters_are_delivered_to_confirmed_subscribers' 
panicked at 'assertion failed: `(left == right)`
  left: `401`,
 right: `200`'
 ```

POST /newsletters现在拒绝所有未经身份验证的请求,包括我们在黑盒测试中提出的请求。
我们可以通过提供用户名和密码的随机组合来止血：

```rs
//! tests/api/helpers.rs
// [...]

impl TestApp {
    pub async fn post_newsletters(&self, body: serde_json::Value) -> reqwest::Response {
        reqwest::Client::new()
            .post(&format!("{}/newsletters", &self.address))
            // Random credentials!
            // `reqwest` does all the encoding/formatting heavy-lifting for us.
            .basic_auth(Uuid::new_v4().to_string(), Some(Uuid::new_v4().to_string()))
            .json(&body)
            .send()
            .await
            .expect("Failed to execute request.")
    }
    
    // [...]
}
```
测试套件再次变绿。

### 3.2. 密码验证,天真的方法
接受随机凭据的身份验证层并不理想。<br>
我们需要开始验证我们从Authorization标头中提取的凭据,它们应该与已知用户列表进行比较。

我们将创建一个新的usersPostgres表来存储这个列表：
```
sqlx migrate add create_users_table
```
架构的初稿可能如下所示：
```sql
-,migrations/20210815112026_create_users_table.sql 
CREATE TABLE users(
   user_id uuid PRIMARY KEY,
   username TEXT NOT NULL UNIQUE,
   password TEXT NOT NULL
);
```
然后,我们可以更新我们的处理程序以在每次执行身份验证时查询它：

```rs
//! src/routes/newsletters.rs
use secrecy::ExposeSecret;
// [...]

async fn validate_credentials(
    credentials: Credentials,
    pool: &PgPool,
) -> Result<uuid::Uuid, PublishError> {
    let user_id: Option<_> = sqlx::query!(
        r#"
        SELECT user_id
        FROM users
        WHERE username = $1 AND password = $2
        "#,
        credentials.username,
        credentials.password.expose_secret()
    )
    .fetch_optional(pool)
    .await
    .context("Failed to perform a query to validate auth credentials.")
    .map_err(PublishError::UnexpectedError)?;

    user_id
        .map(|row| row.user_id)
        .ok_or_else(|| anyhow::anyhow!("Invalid username or password."))
        .map_err(PublishError::AuthError)
}

pub async fn publish_newsletter(/* */) -> Result<HttpResponse, PublishError> {
    let credentials = basic_authentication(request.headers())
        .map_err(PublishError::AuthError)?;
    let user_id = validate_credentials(credentials, &pool).await?;
    // [...]
}
```

记录谁在调用是个好主意POST /newsletters,让我们在处理程序周围添加一个tracing追踪：

```rs
//! src/routes/newsletters.rs
// [...]

#[tracing::instrument(
    name = "Publish a newsletter issue",
    skip(body, pool, email_client, request),
    fields(username=tracing::field::Empty, user_id=tracing::field::Empty)
)]
pub async fn publish_newsletter(/* */) -> Result<HttpResponse, PublishError> {
    let credentials = basic_authentication(request.headers())
        .map_err(PublishError::AuthError)?;
    tracing::Span::current().record(
        "username",
        &tracing::field::display(&credentials.username)
    );
    let user_id = validate_credentials(credentials, &pool).await?;
    tracing::Span::current().record("user_id", &tracing::field::display(&user_id));
    // [...]
}
```
我们现在需要更新我们的快乐路径测试以指定一个被validate_credentials.
我们将为我们的测试应用程序的每个实例生成一个测试用户。我们还没有为新闻简报编辑实现注册流程,因此我们不能采用完全黑盒的方法,我们暂时将测试用户详细信息直接注入数据库：

```rs
//! tests/api/helpers.rs
// [...]

pub async fn spawn_app() -> TestApp {
    // [...]

    let test_app = TestApp {/* */};
    add_test_user(&test_app.db_pool).await;
    test_app
}

async fn add_test_user(pool: &PgPool) {
    sqlx::query!(
        "INSERT INTO users (user_id, username, password)
        VALUES ($1, $2, $3)",
        Uuid::new_v4(),
        Uuid::new_v4().to_string(),
        Uuid::new_v4().to_string(),
    )
    .execute(pool)
    .await
    .expect("Failed to create test users.");
}
```

TestApp将提供一个帮助方法来检索其用户名和密码

```rs
//! tests/api/helpers.rs
// [...]

impl TestApp {
    // [...]

    pub async fn test_user(&self) -> (String, String) {
        let row = sqlx::query!("SELECT username, password FROM users LIMIT 1",)
            .fetch_one(&self.db_pool)
            .await
            .expect("Failed to create test users.");
        (row.username, row.password)
    }
}
```
然后我们将从我们的post_newsletters方法中调用它,而不是使用随机凭据：

```rs
//! tests/api/helpers.rs
// [...]

impl TestApp {
    // [...]

    pub async fn post_newsletters(&self, body: serde_json::Value) -> reqwest::Response {
        let (username, password) = self.test_user().await;
        reqwest::Client::new()
            .post(&format!("{}/newsletters", &self.address))
            // No longer randomly generated on the spot!
            .basic_auth(username, Some(password))
            .json(&body)
            .send()
            .await
            .expect("Failed to execute request.")
    }
}
```
我们所有的测试现在都通过了。

### 3.3. 密码存储
在数据库中存储原始用户密码不是一个好主意。

有权访问您存储数据的攻击者可以立即开始冒充您的用户,用户名和密码都已准备就绪。<br>
他们甚至不必破坏您的实时数据库,未加密的备份就足够了。

#### 3.3.1. 无需存储原始密码
为什么我们首先要存储密码？<br>
我们需要执行相等性检查, 每次用户尝试进行身份验证时,我们都会验证他们提供的密码是否与我们期望的密码匹配。

如果平等是我们所关心的,我们可以开始设计一个更复杂的策略。<br>
例如,我们可以通过在比较密码之前应用一个函数来转换密码。

给定相同的输入,所有确定性函数都返回相同的输出。<br>
让我们的确定性函数f：psw_candidate == expected_psw 暗示 f(psw_candidate) == f(expected_psw)。<br>
但这还不够,如果为每个可能的输入字符串f返回怎么办？hello无论提供什么输入,密码验证都会成功。

我们需要朝相反的方向走：if f(psw_candidate) == f(expected_psw) then psw_candidate == expected_psw。
假设我们的函数f有一个附加属性,这是可能的：它必须是单射的,if x != ythen f(x) != f(y)。

如果我们有这样的功能f,我们可以完全避免存储原始密码：当用户注册时,我们计算f(password)并将其存储在我们的数据库中。password被丢弃。
当同一用户尝试登录时,我们会计算f(psw_candidate)并检查它是否与f(password)我们在注册期间存储的值匹配。原始密码永远不会保留。

这真的改善了我们的安全态势吗？
这取决于f！

定义一个单射函数并不难,逆函数f("hello") = "olleh"满足我们的标准。同样容易猜出如何反转转换以恢复原始密码,它不会妨碍攻击者。
我们可以使转换变得更加复杂,复杂到足以让攻击者难以找到逆变换。
即使这样可能还不够。攻击者通常能够从输出中恢复输入的某些属性（例如长度）以实施例如有针对性的蛮力攻击就足够了。我们需要更强大的东西,两个输入的相似程度和相应输出的相似程度之间应该没有关系。x与y不相识于f(x)与f(y)。

我们想要一个密码散列函数。<br>
哈希函数将字符串从输入空间映射到固定长度的输出。<br>
形容词密码学指的是我们刚刚讨论的一致性属性,也称为雪崩效应：输入的微小差异导致输出如此不同,以至于看起来不相关。

有一个警告：哈希函数不是单射的2,碰撞的风险很小, if f(x) == f(y)有很高的概率（不是 100%！）x == y。

#### 3.3.2. 使用加密哈希
理论说得够多了,让我们在存储密码之前更新我们的实现以散列密码。

有几种加密哈希函数,MD5、SHA-1、SHA-2、 SHA-3、KangarooTwelve等。
我们不打算深入研究每种算法的优缺点,当涉及到密码,原因将在几页后变得清晰。
就本节而言,让我们继续介绍SHA-3,它是安全散列算法系列的最新成员。

在算法之上,我们还需要选择输出大小,例如SHA3-224使用SHA-3算法来产生224位的固定大小的输出。
选项有224、256、384和512。输出越长,我们就越不可能遇到碰撞。另一方面,我们将需要更多的存储空间并通过使用更长的哈希值来消耗更多的带宽。
SHA3​​-256 对于我们的用例应该绰绰有余。

Rust Crypto组织提供了SHA-3的实现,即crate sha3。让我们将它添加到我们的依赖项中：
```toml
#! Cargo.toml
#! [...]

[dependencies]
# [...]
sha3 = "0.9"
```
为清楚起见,让我们将password列重命名为password_hash：
```
sqlx migrate add rename_password_column
```
```sql
-,migrations/20210815112028_rename_password_column.sql
ALTER TABLE users RENAME password TO password_hash;
```
我们的项目应该停止编译：
```sh
error: error returned from database: column "password" does not exist
  --> src/routes/newsletters.rs
   |
90 |       let user_id: Option<_> = sqlx::query!(
   |  ______________________________^
91 | |         r#"
92 | |         SELECT user_id
93 | |         FROM users
...  |
97 | |         credentials.password
98 | |     )
   | |_____^
   ```
sqlx::query!发现我们的一个查询正在使用当前模式中不再存在的列。
SQL查询的编译时验证非常简洁,不是吗？

我们的validate_credentials函数如下所示：

```rs
//! src/routes/newsletters.rs
//! [...]

async fn validate_credentials(
    credentials: Credentials,
    pool: &PgPool,
) -> Result<uuid::Uuid, PublishError> {
    let user_id: Option<_> = sqlx::query!(
        r#"
        SELECT user_id
        FROM users
        WHERE username = $1 AND password = $2
        "#,
        credentials.username,
        credentials.password.expose_secret()
    )
    // [...]
}
```
让我们更新它以使用散列密码：

```rs
//! src/routes/newsletters.rs
//! [...]
use sha3::Digest;

async fn validate_credentials(/* */) -> Result<uuid::Uuid, PublishError> {
    let password_hash = sha3::Sha3_256::digest(
        credentials.password.expose_secret().as_bytes()
    );
    let user_id: Option<_> = sqlx::query!(
        r#"
        SELECT user_id
        FROM users
        WHERE username = $1 AND password_hash = $2
        "#,
        credentials.username,
        password_hash
    )
    // [...]
}
```
不幸的是,它不会立即编译：
```rs
error[E0308]: mismatched types
  --> src/routes/newsletters.rs:99:9
   |
99 |         password_hash
   |         ^^^^^^^^^^^^^ expected `&str`, found struct `GenericArray`
   |
   = note: expected reference `&str`
                 found struct `GenericArray<u8, UInt<..>>`
```
Digest::digest返回一个固定长度的字节数组,而我们的password_hash列的类型TEXT是字符串。<br>
我们可以更改users表的模式以存储password_hash为binary。或者,我们可以使用十六进制格式将返回的字节编码Digest::digest为字符串。

让我们通过使用第二个选项来避免另一个迁移：

```rs
//! [...]

async fn validate_credentials(/* */) -> Result<uuid::Uuid, PublishError> {
    let password_hash = sha3::Sha3_256::digest(
        credentials.password.expose_secret().as_bytes()
    );
    // Lowercase hexadecimal encoding.
    let password_hash = format!("{:x}", password_hash);
    // [...]
}
```
应用程序代码现在应该可以编译了。相反,测试套件需要更多的工作。
辅助方法是通过test_user查询表来恢复一组有效的凭据users,现在我们存储的是哈希而不是原始密码,这不再可行！

```rs
//! tests/api/helpers.rs
//! [...]
 
impl TestApp {
    // [...]
    
    pub async fn test_user(&self) -> (String, String) {
        let row = sqlx::query!("SELECT username, password FROM users LIMIT 1",)
            .fetch_one(&self.db_pool)
            .await
            .expect("Failed to create test users.");
        (row.username, row.password)
    }
}

pub async fn spawn_app() -> TestApp {
    // [...]
    let test_app = TestApp {/* */};
    add_test_user(&test_app.db_pool).await;
    test_app
}

async fn add_test_user(pool: &PgPool) {
    sqlx::query!(
        "INSERT INTO users (user_id, username, password)
        VALUES ($1, $2, $3)",
        Uuid::new_v4(),
        Uuid::new_v4().to_string(),
        Uuid::new_v4().to_string(),
    )
    .execute(pool)
    .await
    .expect("Failed to create test users.");
}
```
我们需要TestApp存储随机生成的密码,以便我们在辅助方法中访问它。
让我们从创建一个新的辅助结构开始,TestUser：

```rs
//! tests/api/helpers.rs
//! [...]
use sha3::Digest;

pub struct TestUser {
    pub user_id: Uuid,
    pub username: String,
    pub password: String
}

impl TestUser {
    pub fn generate() -> Self {
        Self {
            user_id: Uuid::new_v4(),
            username: Uuid::new_v4().to_string(),
            password: Uuid::new_v4().to_string()
        }
    }

    async fn store(&self, pool: &PgPool) {
        let password_hash = sha3::Sha3_256::digest(
            credentials.password.expose_secret().as_bytes()
        );
        let password_hash = format!("{:x}", password_hash);
        sqlx::query!(
            "INSERT INTO users (user_id, username, password_hash)
            VALUES ($1, $2, $3)",
            self.user_id,
            self.username,
            password_hash,
        )
        .execute(pool)
        .await
        .expect("Failed to store test user.");
    }
}
```
然后我们可以附加TestUserto的一个实例TestApp,作为一个新字段：

```rs
//! tests/api/helpers.rs
//! [...]

pub struct TestApp {
    // [...]
    test_user: TestUser
}

pub async fn spawn_app() -> TestApp {
    // [...]
    let test_app = TestApp {
        // [...]
        test_user: TestUser::generate()
    };
    test_app.test_user.store(&test_app.db_pool).await;
    test_app
}
```
最后,让我们删除add_test_user和TestApp::test_user更新TestApp::post_newsletters：

```rs
//! tests/api/helpers.rs
//! [...]

impl TestApp {
    // [..]
    pub async fn post_newsletters(&self, body: serde_json::Value) -> reqwest::Response {
        reqwest::Client::new()
            .post(&format!("{}/newsletters", &self.address))
            .basic_auth(&self.test_user.username, Some(&self.test_user.password))
            // [...]
    }
}
```
测试套件现在应该可以编译并成功运行。

#### 3.3.3. 原像攻击
如果攻击者拿到我们的桌子,SHA3-256是否足以保护我们用户的密码users？

让我们假设攻击想要破解我们数据库中的特定密码哈希。
攻击者甚至不需要检索原始密码。为了成功进行身份验证,他们只需要找到一个sSHA3-256 哈希值与他们试图破解的密码匹配的输入字符串,换句话说,就是一个冲突。<br>
这称为原像攻击。

有多难？

数学有点棘手,但蛮力攻击具有指数 时间复杂度2^n,其中n是哈希长度（以位为单位）。
如果n > 128,则认为计算不可行。
除非在SHA-3中发现漏洞,否则我们无需担心针对SHA3-256的原像攻击。

#### 3.3.4. 朴素字典攻击
不过,我们不会对任意输入进行散列处理,我们可以通过对原始密码做出一些假设来减少搜索空间：它有多长？使用了哪些符号？
假设我们正在寻找一个少于17个字符3的字母数字密码。[^3]

我们可以统计候选密码的数量：
```
// (26 letters + 10 number symbols) ^ Password Length
// for all allowed password lengths
36^1 +
36^2 +
... +
36^16
``` 
它概括了大致的8 * 10^24可能性。
我无法找到专门关于SHA3-256的数据,但研究人员设法使用图形处理单元(GPU)每秒计算约9亿个SHA3-512哈希值。

假设每秒的哈希率~10^9,我们需要~10^15秒来哈希所有候选密码。宇宙的大致年龄是4 * 10^17秒。<br>
即使我们使用100万个GPU并行化我们的搜索,它仍然需要~10^9秒,大约30年。[^4] 

#### 3.3.5. 字典攻击
让我们回到本章开头讨论的内容,一个人不可能记住数百个在线服务的唯一密码。<br>
他们要么依赖密码管理器,要么在多个帐户中重复使用一个或多个密码。

此外,即使重复使用,大多数密码也远非随机,常用词、全名、日期、流行运动队的名称等
。攻击者可以轻松设计一个简单的算法来生成数千个似是而非的密码,他们可以从过去十年中众多安全漏洞的密码数据集里以找到最常见的密码来尝试攻击。

他们可以在几分钟内预先计算出最常用的1000万个密码的SHA3-256哈希值。然后他们开始扫描我们的数据库以寻找匹配项。

这被称为字典攻击,它非常有效。

到目前为止,我们提到的所有加密哈希函数都设计得很快。
速度足够快,任何人都可以在无需使用专用硬件的情况下进行字典攻击。

我们需要慢得多的东西,但具有与密码散列函数相同的一组数学属性。

#### 3.3.6. Aragon2
开放式 Web 应用程序安全项目 (OWASP) [^5]提供了有关安全密码存储的有用指南,关于如何选择正确的散列算法的整个部分：

https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

>使用 Argon2id,最小配置为15MiB内存,迭代次数为2,并行度为1。<br>
>如果Argon2id不可用,请使用工作系数为10或更高且密码限制为72字节的bcrypt。<br>
>对于使用scrypt的旧系统,使用最小CPU/内存成本参数 (2^16)、最小块大小 8（1024字节）和并行化参数1。<br>
>如果需要符合 FIPS-140,请使用工作因子为 310,000 或更高的 PBKDF2,并使用 HMAC-SHA-256 的内部哈希函数进行设置。<br>
>考虑使用辣椒来提供额外的深度防御（尽管单独使用,它没有提供额外的安全特性）。<br>

所有这些选项,Argon2、bcrypt、scrypt、PBKDF2,都被设计成对计算要求很高。<br>
它们还公开了配置参数（例如 bcrypt 的工作因子）以进一步减慢哈希计算：应用程序开发人员可以调整一些旋钮以跟上硬件加速,无需每隔几年迁移到更新的算法。

按照OWASP的建议,让我们用Argon2id替换SHA-3。<br>
Rust Crypto组织再次提供了一个纯Rust实现的argon2。[^2]

让我们将它添加到我们的依赖项中：

```toml
#! Cargo.toml
#! [...]

[dependencies]
# [...]
argon2 = { version = "0.4", features = ["std"] }
```
要散列密码,我们需要创建一个Argon2结构实例。方法签名如下所示

```rs
//! argon2/lib.rs
/// [...]
 
impl<'key> Argon2<'key> {
    /// Create a new Argon2 context.
    pub fn new(algorithm: Algorithm, version: Version, params: Params) -> Self {
        // [...]
    }
    // [...]
}
```
Algorithm是一个枚举：它让我们可以选择要使用的Argon2的哪个变体,Argon2d、Argon2i、Argon2id。为了遵守OWASP的建议,我们将选择Algorithm::Argon2id。

Version实现了类似的目的,我们将选择最近的,Version::V0x13。

Params,Params::new指定我们需要提供的所有强制参数来构建一个。
```rs
//! argon2/params.rs
// [...]

/// Create new parameters.
pub fn new(
    m_cost: u32, 
    t_cost: u32, 
    p_cost: u32, 
    output_len: Option<usize>
) -> Result<Self> {
    // [...]
}
```
m_cost,t_cost并p_cost映射到 OWASP 的要求：

- m_cost是内存大小,以千字节表示
- t_cost是迭代次数；
- p_cost是并行度。
- output_len,相反,确定返回哈希的长度。如果省略,它将默认为32字节。这等于256位,与我们通过 SHA3-256 获得的哈希长度相同。

在这一点上,我们知道的足够多,可以构建一个：

```rs
//! src/routes/newsletters.rs
use argon2::{Algorithm, Argon2, Version, Params};
// [...]

async fn validate_credentials(
    credentials: Credentials,
    pool: &PgPool,
) -> Result<uuid::Uuid, PublishError> {
    let hasher = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(15000, 2, 1, None)
            .context("Failed to build Argon2 parameters")
            .map_err(PublishError::UnexpectedError)?,
    );
    let password_hash = sha3::Sha3_256::digest(
        credentials.password.expose_secret().as_bytes()
    );
   // [...]
}
```
Argon2实现PasswordHasher trait：

```rs
//! password_hash/traits.rs

pub trait PasswordHasher {
    // [...]
    fn hash_password<'a, S>(
        &self, 
        password: &[u8], 
        salt: &'a S
    ) -> Result<PasswordHash<'a>>
    where
        S: AsRef<str> + ?Sized;
}
```
password-hash是crate的重新导出的统一接口,用于处理由各种算法（当前为Argon2、PBKDF2和scrypt）支持的密码哈希。

PasswordHasher::hash_password有点不同Sha3_256::digest,它要求在原始密码之上添加一个附加参数 salt。

#### 3.3.7. 盐
Argon2比SHA-3慢很多,但这还不足以使字典攻击不可行。散列最常见的1000万个密码需要更长的时间,但不会太长。

但是,如果攻击者必须为我们数据库中的每个用户重新散列整个字典怎么办？
它变得更具挑战性！

这就是加盐的作用。对于每个用户,我们生成一个唯一的随机字符串,盐。
在生成哈希之前,盐会添加到用户密码之前。 PasswordHasher::hash_password为我们处理前置事务。

salt存储在我们数据库中的密码哈希旁边。
如果攻击者获得数据库备份,他们将可以访问所有 salts。[^6]
但他们必须计算dictionary_size * n_users 散列而不是dictionary_size。此外,预先计算哈希不再是一种选择,这为我们赢得了检测违规行为并采取行动的时间（例如,强制为所有用户重置密码）。

让我们在users表中添加一个password_salt列：

```rs
//! src/routes/newsletters.rs
// [...]
use argon2::PasswordHasher;

async fn validate_credentials(
    credentials: Credentials,
    pool: &PgPool,
) -> Result<uuid::Uuid, PublishError> {
    let hasher = argon2::Argon2::new(/* */);
    let row: Option<_> = sqlx::query!(
        r#"
        SELECT user_id, password_hash, salt
        FROM users
        WHERE username = $1
        "#,
        credentials.username,
    )
    .fetch_optional(pool)
    .await
    .context("Failed to perform a query to retrieve stored credentials.")
    .map_err(PublishError::UnexpectedError)?;

    let (expected_password_hash, user_id, salt) = match row {
        Some(row) => (row.password_hash, row.user_id, row.salt),
        None => {
            return Err(PublishError::AuthError(anyhow::anyhow!(
                "Unknown username."
            )));
        }
    };

    let password_hash = hasher
        .hash_password(
            credentials.password.expose_secret().as_bytes(),
            &salt
        )
        .context("Failed to hash password")
        .map_err(PublishError::UnexpectedError)?;
    
    let password_hash = format!("{:x}", password_hash.hash.unwrap());

    if password_hash != expected_password_hash {
        Err(PublishError::AuthError(anyhow::anyhow!(
            "Invalid password."
        )))
    } else {
        Ok(user_id)
    }
}
```
不幸的是,无法通过编译：

```sh
error[E0277]: the trait bound 
`argon2::password_hash::Output: LowerHex` is not satisfied
   --> src/routes/newsletters.rs
    |
125 |     let password_hash = format!("{:x}", password_hash.hash.unwrap());
    |                                         ^^^^^^^^^^^^^^^^^^^^^^^^^^^ 
    the trait `LowerHex` is not implemented for `argon2::password_hash::Output`
```
Output提供了其他方法来获取字符串表示。例如输出::b64_encode。只要我们乐于更改存储在数据库中的散列的假定编码,它就会起作用。

鉴于有必要进行更改,我们可以寻找比 base64 编码更好的东西。

#### 3.3.8. PHC String Format
为了对用户进行身份验证,我们需要可重复性：我们必须每次都运行相同的哈希例程。
Salt 和密码只是 Argon2id 输入的一个子集。在给定相同的盐和密码对的情况下,所有其他负载参数（t_cost、m_cost、p_cost）对于获得相同的哈希值同样重要。

如果我们存储哈希的 base64 编码表示,我们会​​做出一个强隐式假设：存储在 password_hash 列中的所有值都是使用相同的加载参数计算的。

正如我们前几节所讨论的,硬件功能会随着时间的推移而发展：应用程序开发人员需要通过使用更高负载参数增加散列的计算成本来跟上。
当您必须将存储的密码迁移到较新的哈希配置时会发生什么？

为了继续对旧用户进行身份验证,我们必须在每个哈希旁边存储用于计算它的确切负载参数集。
这允许在两种不同的负载配置之间进行无缝迁移：当旧用户进行身份验证时,我们使用存储的负载参数验证密码有效性；然后我们使用新的加载参数重新计算密码哈希并相应地更新存储的信息。

我们可以采用简单的方法,在我们的用户表中添加三个新列：t_cost、m_cost 和 p_cost。
只要算法仍然是 Argon2id,它就会起作用。

如果在Argon2id中发现漏洞并且我们被迫迁移离开它会发生什么？
我们可能想要添加一个算法列,以及用于存储Argon2id替换的负载参数的新列。

可以做到,但很乏味。
幸运的是,有一个更好的解决方案：PHC 字符串格式。 PHC 字符串格式为密码散列提供标准表示：它包括散列本身、盐、算法及其所有相关参数。

使用PHC字符串格式,Argon2id 密码哈希如下所示：

```sh
# ${algorithm}${algorithm version}${$-separated algorithm parameters}${hash}${salt}
$argon2id$v=19$m=65536,t=2,p=1$gZiV/M1gPc22ElAH/Jh1Hw$CWOrkoo7oJBQ/iyh7uJ0LO2aLEfrHwTWllSAxT0zRno
```
argon2 crate 开放了PasswordHash,这是PHC格式的Rust实现：

```rs
//! argon2/lib.rs
// [...]

pub struct PasswordHash<'a> {
    pub algorithm: Ident<'a>,
    pub version: Option<Decimal>,
    pub params: ParamsString,
    pub salt: Option<Salt<'a>>,
    pub hash: Option<Output>,
}
```
以 PHC 字符串格式存储密码哈希使我们不必Argon2使用显式参数7初始化结构。
我们可以依赖trait Argon2的实现：PasswordVerifier [^7]
```rs
pub trait PasswordVerifier {
    fn verify_password(
        &self,
        password: &[u8],
        hash: &PasswordHash<'_>
    ) -> Result<()>;
}
```
通过传递预期的哈希PasswordHash,Argon2可以自动推断应该使用什么负载参数和盐来验证候选密码是否匹配[^8]

让我们更新我们的实现：
```rs
//! src/routes/newsletters.rs
use argon2::{Argon2, PasswordHash, PasswordVerifier};
// [...]

async fn validate_credentials(
    credentials: Credentials,
    pool: &PgPool,
) -> Result<uuid::Uuid, PublishError> {
    let row: Option<_> = sqlx::query!(
        r#"
        SELECT user_id, password_hash
        FROM users
        WHERE username = $1
        "#,
        credentials.username,
    )
    .fetch_optional(pool)
    .await
    .context("Failed to perform a query to retrieve stored credentials.")
    .map_err(PublishError::UnexpectedError)?;

    let (expected_password_hash,user_id) = match row {
        Some(row) => (row.password_hash,row.user_id),
        None => {
            return Err(PublishError::AuthError(anyhow::anyhow!(
                "Unknown username."
            )))
        }
    };

    let expected_password_hash = PasswordHash::new(&expected_password_hash)
        .context("Failed to parse hash in PHC string format.")
        .map_err(PublishError::UnexpectedError)?;

    Argon2::default()
        .verify_password(
             credentials.password.expose_secret().as_bytes(), 
             &expected_password_hash
        )
        .context("Invalid password.")
        .map_err(PublishError::AuthError)?;

    Ok(user_id)
}
```
它编译成功。
您可能还注意到我们不再直接处理盐,PHC字符串格式隐含地为我们处理它。
我们可以完全摆脱该salt列：

```
sqlx migrate add remove_salt_from_users
```
```sql
-,migrations/20210815112222_remove_salt_from_users.sql 
ALTER TABLE users DROP COLUMN salt;
```
我们的测试呢？
其中两个失败：
```sh
---,newsletter::newsletters_are_not_delivered_to_unconfirmed_subscribers stdout ----
'newsletter::newsletters_are_not_delivered_to_unconfirmed_subscribers' panicked at 
'assertion failed: `(left == right)`
  left: `500`,
 right: `200`',

---,newsletter::newsletters_are_delivered_to_confirmed_subscribers stdout ----
'newsletter::newsletters_are_delivered_to_confirmed_subscribers' panicked at 
'assertion failed: `(left == right)`
  left: `500`,
  ```
我们可以查看日志以找出问题所在：
```sh
TEST_LOG=true cargo t newsletters_are_not_delivered | bunyan
[2021-08-29T20:14:50.367Z] ERROR: [HTTP REQUEST,EVENT] 
  Error encountered while processing the incoming HTTP request: 
  Failed to parse hash in PHC string format.

  Caused by:
     password hash string invalid
```
让我们看看我们的测试用户的密码生成代码：
```rs
//! tests/api/helpers.rs
// [...]

impl TestUser {
    // [...]
    async fn store(&self, pool: &PgPool) {
        let password_hash = sha3::Sha3_256::digest(
            credentials.password.expose_secret().as_bytes()
        );
        let password_hash = format!("{:x}", password_hash);
        // [...]
    }
}
```
我们仍在使用 SHA-3！
让我们更新一下：
```rs
//! tests/api/helpers.rs
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHasher};
// [...]

impl TestUser {
    // [...]
    async fn store(&self, pool: &PgPool) {
        let salt = SaltString::generate(&mut rand::thread_rng());
        // We don't care about the exact Argon2 parameters here
        // given that it's for testing purposes!
        let password_hash = Argon2::default()
            .hash_password(self.password.as_bytes(), &salt)
            .unwrap()
            .to_string();
        // [...]
    }
}
```

测试套件现在应该通过了。
我们已经从我们的项目中删除了所有提到的 sha3,我们现在可以从 Cargo.toml 的依赖项列表中删除它。

### 3.4.不要阻塞异步执行器
运行我们的集成测试时验证用户凭据需要多长时间？
我们目前没有围绕密码散列的追踪,让我们修复它：

```rs
//! src/routes/newsletters.rs
// [...]

#[tracing::instrument(name = "Validate credentials", skip(credentials, pool))]
async fn validate_credentials(
    credentials: Credentials,
    pool: &PgPool,
) -> Result<uuid::Uuid, PublishError> {
    let (user_id, expected_password_hash) = get_stored_credentials(
            &credentials.username, 
            &pool
        )
        .await
        .map_err(PublishError::UnexpectedError)?
        .ok_or_else(|| PublishError::AuthError(anyhow::anyhow!("Unknown username.")))?;

    let expected_password_hash = PasswordHash::new(
            &expected_password_hash.expose_secret()
        )
        .context("Failed to parse hash in PHC string format.")
        .map_err(PublishError::UnexpectedError)?;

    tracing::info_span!("Verify password hash")
        .in_scope(|| {
            Argon2::default()
                .verify_password(
                    credentials.password.expose_secret().as_bytes(), 
                    expected_password_hash
                )
        })
        .context("Invalid password.")
        .map_err(PublishError::AuthError)?;

    Ok(user_id)
}

// We extracted the db-querying logic in its own function with its own span.
#[tracing::instrument(name = "Get stored credentials", skip(username, pool))]
async fn get_stored_credentials(
    username: &str,
    pool: &PgPool,
) -> Result<Option<(uuid::Uuid, Secret<String>)>, anyhow::Error> {
    let row = sqlx::query!(
        r#"
        SELECT user_id, password_hash
        FROM users
        WHERE username = $1
        "#,
        username,
    )
    .fetch_optional(pool)
    .await
    .context("Failed to perform a query to retrieve stored credentials.")?
    .map(|row| (row.user_id, Secret::new(row.password_hash)));
    Ok(row)
}
```

我们现在可以查看其中一项集成测试的日志：
```sh
TEST_LOG=true cargo test --quiet --release \
  newsletters_are_delivered | grep "VERIFY PASSWORD" | bunyan
[...]  [VERIFY PASSWORD HASH,END] (elapsed_milliseconds=11, ...)
```
大约 10 毫秒。
这可能会导致负载问题,臭名昭著的阻塞问题。

Rust中的async/await是围绕一个称为协作调度的概念构建的。

它是如何工作的？
让我们看一个例子：
```rs
async fn my_fn() {
    a().await;
    b().await;
    c().await;
}
```
my_fn 返回一个未来。
当等待未来时,我们的异步运行时（tokio）进入画面：它开始轮询它。

my_fn返回的Future如何实现poll？
你可以把它想象成一个状态机：
```rs
enum MyFnFuture {
    Initialized,
    CallingA,
    CallingB,
    CallingC,
    Complete
}
```
每次调用poll时,它都会尝试通过到达下一个状态来取得进展。例如如果 a.await() 返回,我们开始等待 b() [^9]。

对于异步函数体中的每个 .await,我们在 MyFnFuture 中都有不同的状态。
这就是为什么 .await 调用通常被命名为让步点的原因,我们的未来会从前一个 .await 前进到下一个,然后将控制权交还给执行程序。

然后,执行者可以选择再次轮询同一个未来,或者优先考虑在另一个任务上取得进展。这就是异步运行时（如 tokio）如何设法在多个任务上同时取得进展,通过不断地停放和恢复每个任务。
在某种程度上,您可以将异步运行时视为出色的杂耍者。

基本假设是大多数异步任务正在执行某种输入输出（IO）工作,它们的大部分执行时间将花在等待其他事情发生（例如,操作系统通知我们有数据可供读取在一个套接字上）,因此我们可以有效地同时执行比我们通过为每个任务指定一个并行执行单元（例如每个操作系统内核一个线程）来实现的任务更多的任务。

假设任务通过频繁将控制权交还给执行者来合作,这个模型非常有效。
换句话说,poll 预计会很快,它应该在不到 10-100 微秒内返回[^10]。如果调用 poll 需要更长的时间（或者更糟糕的是,永远不会返回）,那么异步执行器无法在任何其他任务上取得进展,这就是人们说“任务正在阻塞执行器/异步线程”时所指的”。

您应该始终注意可能需要超过 1 毫秒的 CPU 密集型工作负载,密码哈希就是一个很好的例子。
为了更好地使用tokio,我们必须使用tokio::task::spawn_blocking. 这些线程保留用于阻塞操作,不会干扰异步任务的调度。

让我们开始工作吧！
```rs
//! src/routes/newsletters.rs
// [...]

#[tracing::instrument(name = "Validate credentials", skip(credentials, pool))]
async fn validate_credentials(
    credentials: Credentials,
    pool: &PgPool,
) -> Result<uuid::Uuid, PublishError> {
    // [...]
    tokio::task::spawn_blocking(move || {
        tracing::info_span!("Verify password hash").in_scope(|| {
            Argon2::default()
                .verify_password(
                    credentials.password.expose_secret().as_bytes(), 
                    &expected_password_hash)
        })
    })
    .await
    // spawn_blocking is fallible,we have a nested Result here!
    .context("Failed to spawn blocking task.")
    .map_err(PublishError::UnexpectedError)?
    .context("Invalid password.")
    .map_err(PublishError::AuthError)?;
    // [...]
}
```
借用检查吐槽：
```sh
error[E0597]: `expected_password_hash` does not live long enough
   --> src/routes/newsletters.rs
    |
117 |     PasswordHash::new(&expected_password_hash)
    |     ------------------^^^^^^^^^^^^^^^^^^^^^^^-
    |     |                 |
    |     |                 borrowed value does not live long enough
    |     argument requires that `expected_password_hash` is borrowed for `'static`
...
134 | }
    |,`expected_password_hash` dropped here while still borrowed
```
我们正在一个单独的线程上启动一个计算,线程本身可能比我们从中产生它的异步任务寿命更长。为了避免这个问题,spawn_blocking需要它的参数有一个'static生命周期,这会阻止我们将对当前函数上下文的引用传递到闭包中。

您可能会争辩,“我们正在使用move || {},闭包应该拥有expected_password_hash！”。
你是对的！但这还不够。
我们再来看看是如何PasswordHash定义的：

```rs
pub struct PasswordHash<'a> {
    pub algorithm: Ident<'a>,
    pub salt: Option<Salt<'a>>,
    // [...]
}
```
它包含对其解析的字符串的引用。
我们需要将原始字符串的所有权移到我们的闭包中,同时将解析逻辑也移到其中。

为清楚起见,让我们创建一个单独的函数 , verify_password_hash：
```rs
//! src/routes/newsletters.rs
// [...]

#[tracing::instrument(name = "Validate credentials", skip(credentials, pool))]
async fn validate_credentials(
    credentials: Credentials,
    pool: &PgPool,
) -> Result<uuid::Uuid, PublishError> {
    // [...]
    tokio::task::spawn_blocking(move || {
        verify_password_hash(
            expected_password_hash, 
            credentials.password
        )
    })
    .await
    .context("Failed to spawn blocking task.")
    .map_err(PublishError::UnexpectedError)??;

    Ok(user_id)
}

#[tracing::instrument(
    name = "Verify password hash", 
    skip(expected_password_hash, password_candidate)
)]
fn verify_password_hash(
    expected_password_hash: Secret<String>,
    password_candidate: Secret<String>,
) -> Result<(), PublishError> {
    let expected_password_hash = PasswordHash::new(
            expected_password_hash.expose_secret()
        )
        .context("Failed to parse hash in PHC string format.")
        .map_err(PublishError::UnexpectedError)?;

    Argon2::default()
        .verify_password(
            password_candidate.expose_secret().as_bytes(),
            &expected_password_hash
        )
        .context("Invalid password.")
        .map_err(PublishError::AuthError)
}
```
编译ok！

#### 3.4.1. 跟踪上下文是线程本地的
让我们再次查看verify password hashspan 的日志：
```sh
TEST_LOG=true cargo test --quiet --release \
  newsletters_are_delivered | grep "VERIFY PASSWORD" | bunyan
[2021-08-30T10:03:07.613Z]  [VERIFY PASSWORD HASH,START] 
  (file="...", line="...", target="...")
[2021-08-30T10:03:07.624Z]  [VERIFY PASSWORD HASH,END]
  (file="...", line="...", target="...")
```
我们缺少从相应请求的根追踪继承的所有属性,例如request_id, http.method,http.route等。为什么？

让我们看看tracing's 的文档：

> Spans 形成一个树结构,除非它是根 span,否则所有 span 都有一个 parent,并且可能有一个或多个children。创建新追踪时,当前追踪成为新追踪的父级。

当前追踪是由返回的追踪tracing::Span::current(),让我们检查一下它的文档：

> 返回一个句柄,指向被认为Collector是当前追踪的追踪。

> 如果收集器指示它不跟踪当前追踪,或者调用此函数的线程当前不在追踪内,则返回的追踪将被禁用。

“当前追踪”实际上是指“当前线程的活动追踪”。
这就是我们不继承任何属性的原因：我们在一个单独的线程上产生我们的计算,并且在它执行时tracing::info_span!没有找到任何与之关联的活动。Span

我们可以通过将当前追踪显式附加到新生成的线程来解决此问题：
```rs
//! src/routes/newsletters.rs
// [...]

#[tracing::instrument(name = "Validate credentials", skip(credentials, pool))]
async fn validate_credentials(
    credentials: Credentials,
    pool: &PgPool,
) -> Result<uuid::Uuid, PublishError> {
    // [...]
    // This executes before spawning the new thread
    let current_span = tracing::Span::current();
    tokio::task::spawn_blocking(move || {
        // We then pass ownership to it into the closure
        // and explicitly executes all our computation
        // within its scope.
        current_span.in_scope(|| {
            verify_password_hash(/* */)
        })
    })
    // [...]
}
```
您可以验证它是否有效,我们现在正在获取我们关心的所有属性。
虽然有点冗长,让我们编写一个辅助函数：
```rs
//! src/telemetry.rs
use tokio::task::JoinHandle;
// [...]

// Just copied trait bounds and signature from `spawn_blocking`
pub fn spawn_blocking_with_tracing<F, R>(f: F) -> JoinHandle<R>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    let current_span = tracing::Span::current();
    tokio::task::spawn_blocking(move || current_span.in_scope(f))
}
//! src/routes/newsletters.rs
use crate::telemetry::spawn_blocking_with_tracing;
// [...]

#[tracing::instrument(name = "Validate credentials", skip(credentials, pool))]
async fn validate_credentials(
    credentials: Credentials,
    pool: &PgPool,
) -> Result<uuid::Uuid, PublishError> {
    // [...]
    spawn_blocking_with_tracing(move || {
        verify_password_hash(/* */)
    })
    // [...]
}
```
现在,每当我们需要将一些 CPU 密集型计算卸载到专用线程池时,我们都可以轻松地使用它。

### 3.5. 用户枚举
让我们添加一个新的测试用例：
```rs
//! tests/api/newsletter.rs
use uuid::Uuid;
// [...]

#[tokio::test]
async fn non_existing_user_is_rejected() {
    // Arrange
    let app = spawn_app().await;
    // Random credentials
    let username = Uuid::new_v4().to_string();
    let password = Uuid::new_v4().to_string();

    let response = reqwest::Client::new()
        .post(&format!("{}/newsletters", &app.address))
        .basic_auth(username, Some(password))
        .json(&serde_json::json!({
            "title": "Newsletter title",
            "content": {
                "text": "Newsletter body as plain text",
                "html": "<p>Newsletter body as HTML</p>",
            }
        }))
        .send()
        .await
        .expect("Failed to execute request.");

    // Assert
    assert_eq!(401, response.status().as_u16());
    assert_eq!(
        r#"Basic realm="publish""#,
        response.headers()["WWW-Authenticate"]
    );
}
```
测试应该立即通过。
不过需要多长时间？

让我们看看日志！
```sh
TEST_LOG=true cargo test --quiet --release \
  non_existing_user_is_rejected | grep "HTTP REQUEST" | bunyan
# [...] Omitting setup requests
[...] [HTTP REQUEST,END]
  (http.route = "/newsletters", elapsed_milliseconds=1, ...)
```
大约1ms。

让我们添加另一个测试：这次我们传递了一个有效的用户名和一个错误的密码。
```rs
//! tests/api/newsletter.rs
// [...]

#[tokio::test]
async fn invalid_password_is_rejected() {
    // Arrange
    let app = spawn_app().await;
    let username = &app.test_user.username;
    // Random password
    let password = Uuid::new_v4().to_string();
    assert_ne!(app.test_user.password, password);

    let response = reqwest::Client::new()
        .post(&format!("{}/newsletters", &app.address))
        .basic_auth(username, Some(password))
        .json(&serde_json::json!({
            "title": "Newsletter title",
            "content": {
                "text": "Newsletter body as plain text",
                "html": "<p>Newsletter body as HTML</p>",
            }
        }))
        .send()
        .await
        .expect("Failed to execute request.");

    // Assert
    assert_eq!(401, response.status().as_u16());
    assert_eq!(
        r#"Basic realm="publish""#,
        response.headers()["WWW-Authenticate"]
    );
}
```
这个也应该通过。请求失败需要多长时间？

```sh
TEST_LOG=true cargo test --quiet --release \
  invalid_password_is_rejected | grep "HTTP REQUEST" | bunyan
# [...] Omitting setup requests
[...] [HTTP REQUEST,END]
  (http.route = "/newsletters", elapsed_milliseconds=11, ...)
```
大约 10 毫秒,它小了一个数量级！
我们可以利用这种差异来执行定时攻击,这是更广泛的旁路信道攻击类别的成员。

如果攻击者知道至少一个有效的用户名,他们可以检查服务器响应时间[^11]以确认是否存在另一个用户名,我们正在研究一个潜在的用户枚举漏洞。
这是一个问题吗？

这取决于,如果您正在运行 Gmail,还有很多其他方法可以确定@gmail.com电子邮件地址是否存在。电子邮件地址的有效性不是秘密！

如果您正在运行SaaS产品,情况可能会更加微妙。
让我们假设一个虚构的场景：您的 SaaS 产品提供工资单服务并使用电子邮件地址作为用户名。有单独的员工和管理员登录页面。
我的目标是访问工资单数据,我需要让具有特权访问权限的员工妥协。我们可以抓取LinkedIn以获取财务部门所有员工的姓名和姓氏。公司电子邮件遵循可预测的结构 ( name.surname@payrollaces.com ),因此我们有一份候选人名单。
我们现在可以对管理员登录页面执行定时攻击,以将列表缩小到有权访问的人。

即使在我们虚构的示例中,用户枚举本身也不足以提升我们的权限。
但它可以作为垫脚石来缩小一组目标以进行更精确的攻击。

我们如何预防？
两种策略：

- 去除因密码无效导致认证失败与用户名不存在导致认证失败的时间差；
- 限制给定 IP/用户名的身份验证尝试失败次数。
第二个通常作为对暴力攻击的保护很有价值,但它需要保持一些状态,我们将把它留到以后。

让我们专注于第一个。
为了消除时间差异,我们需要在两种情况下执行相同数量的工作。

现在,我们遵循这个食谱：

获取给定用户名的存储凭据；
如果它们不存在,则返回 401；
如果存在,则对候选密码进行哈希处理并与存储的哈希值进行比较。
我们需要删除那个提前退出,我们应该有一个回退预期密码（带有盐和负载参数）,可以与密码候选的哈希值进行比较。

```rs
//! src/routes/newsletters.rs
// [...]

#[tracing::instrument(name = "Validate credentials", skip(credentials, pool))]
async fn validate_credentials(
    credentials: Credentials,
    pool: &PgPool,
) -> Result<uuid::Uuid, PublishError> {
    let mut user_id = None;
    let mut expected_password_hash = Secret::new(
        "$argon2id$v=19$m=15000,t=2,p=1$\
        gZiV/M1gPc22ElAH/Jh1Hw$\
        CWOrkoo7oJBQ/iyh7uJ0LO2aLEfrHwTWllSAxT0zRno"
            .to_string()
    );

   if let Some((stored_user_id, stored_password_hash)) =
        get_stored_credentials(&credentials.username, &pool)
            .await
            .map_err(PublishError::UnexpectedError)?
    {
        user_id = Some(stored_user_id);
        expected_password_hash = stored_password_hash;
    }

    spawn_blocking_with_tracing(move || {
        verify_password_hash(expected_password_hash, credentials.password)
    })
    .await
    .context("Failed to spawn blocking task.")
    .map_err(PublishError::UnexpectedError)??;

    // This is only set to `Some` if we found credentials in the store
    // So, even if the default password ends up matching (somehow)
    // with the provided password, 
    // we never authenticate a non-existing user.
    // You can easily add a unit test for that precise scenario.
    user_id.ok_or_else(|| 
        PublishError::AuthError(anyhow::anyhow!("Unknown username."))
    )
}
//! tests/api/helpers.rs
use argon2::{Algorithm, Argon2, Params, PasswordHasher, Version};
// [...]

impl TestUser {
    async fn store(&self, pool: &PgPool) {
        let salt = SaltString::generate(&mut rand::thread_rng());
        // Match parameters of the default password
        let password_hash = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(15000, 2, 1, None).unwrap(),
        )
        .hash_password(self.password.as_bytes(), &salt)
        .unwrap()
        .to_string();
        // [...]
    }
    // [...]
}
```
现在不应该有任何统计上显着的时间差异。

## 4. 安全吗？
在构建基于密码的身份验证流程时,我们竭尽全力遵循所有最常见的最佳实践。
是时候问问自己了：它安全吗？

### 4.1. 传输层安全 (TLS)
在构建基于密码的身份验证流程时,我们竭尽全力遵循所有最常见的最佳实践。
是时候问问自己了：它安全吗？

我们使用“基本”身份验证方案在客户端和服务器之间传递凭据,用户名和密码已编码,但未加密。
我们必须使用传输层安全 (TLS) 来确保没有人可以窃听客户端和服务器之间的流量来破坏用户凭据（中间人攻击,MITM）[^12]。
我们的 API 已经通过 HTTPS 提供服务,所以这里无事可做。

### 4.2.重设密码
如果攻击者设法窃取了一组有效的用户凭据,会发生什么？
密码不会过期,它们是长期存在的秘密。

目前,用户无法重置密码。这绝对是我们需要填补的空白。

### 4.3.交互类型
到目前为止,我们对于谁在调用我们的 API 还很模糊。

当涉及到身份验证时,我们需要支持的交互类型是一个关键的决策因素。

我们将查看三类调用者：

其他 API（机器对机器）；
一个人,通过浏览器；
另一个API,代表一个人。

### 4.4.机器对机器
您的 API 的使用者可能是一台机器（例如另一个 API）。
这通常是微服务架构中的情况,您的功能来自通过网络交互的各种服务。

为了显着提高我们的安全配置文件,我们必须加入他们拥有的东西（例如请求签名）或他们拥有的东西（例如 IP 范围限制）。
当所有服务都归同一个组织所有时,一种流行的选择是双向 TLS (mTLS)。

签名和 mTLS 都依赖于公钥加密,必须提供、轮换和管理密钥。仅当系统达到一定大小时,开销才合理。

#### 4.4.1. 通过 OAuth2 的客户端凭据
另一种选择是使用 OAuth2 客户端凭据流。稍后我们将更多地谈论 OAuth2,但让我们谈谈它的战术优缺点。

API 不再需要管理密码（客户端机密,在 OAuth2 术语中）,这个问题被委托给一个集中的授权服务器。授权服务器有多种交钥匙实现,OSS 和商业。您可以依靠它们而不是自己滚动。

调用者向授权服务器进行身份验证,如果成功,则身份验证服务器授予他们一组临时凭证（JWT 访问令牌）,可用于调用我们的 API。
我们的 API 可以使用公钥加密验证访问令牌的有效性,而无需保留任何状态。我们的 API 永远不会看到实际的密码,即客户端密码。

JWT 验证并非没有风险,规范充满了危险的边缘情况。稍后我们将对此进行更多讨论。

### 4.5. 人通过浏览器
如果我们使用网络浏览器与人打交道怎么办？

“基本”身份验证要求客户端在每个请求中都提供他们的凭据。
我们现在有一个受保护的端点,但您可以轻松地描绘一个提供特权功能的五页或十页的情况。就目前而言,“基本”身份验证将强制用户在每个页面上提交他们的凭据。不是很好。

我们需要一种方法来记住用户在片刻之前进行了身份验证,即将某种状态附加到来自同一浏览器的一系列请求。这是使用会话完成的。

要求用户通过登录表单[^13]进行一次身份验证：如果成功,则服务器生成一次性机密,一个经过身份验证的会话令牌。令牌作为安全 cookie存储在浏览器中。
会话与密码不同,旨在过期,这降低了有效会话令牌被破坏的可能性（尤其是在非活动用户自动注销的情况下）。如果怀疑他们的会话已被劫持,它还可以防止用户必须重置密码,强制注销比自动密码重置更容易接受。

这种方法通常称为基于会话的身份验证。

#### 4.5.1. 联合身份
使用基于会话的身份验证,我们仍然需要处理一个身份验证步骤,登录表单。
我们可以继续自己动手,我们学到的关于密码的一切仍然是相关的,即使我们放弃了“基本”身份验证方案。

许多网站选择为其用户提供额外的选项：通过社交资料登录,例如“使用 Google 登录”。这消除了注册流程中的摩擦（无需创建另一个密码！）,增加转换,一个理想的结果。

社交登录依赖于身份联合,我们将身份验证步骤委托给第三方身份提供商,后者又与我们共享我们要求的信息（例如电子邮件地址、全名和出生日期）。

身份联合的常见实现依赖于 OpenID Connect,它是 OAuth2 标准之上的身份层。

### 4.6. 机器对机器,代表一个人
还有一种情况：一个人授权一台机器（例如第三方服务）代表他们对我们的 API 执行操作。
例如,为 Twitter 提供替代 UI 的移动应用程序。

重要的是要强调这与我们审查的第一个场景（纯机器对机器身份验证）有何不同。
在这种情况下,第三方服务无权单独对我们的 API 执行任何操作。第三方服务只有在用户授予他们访问权限时才能对我们的 API 执行操作,范围仅限于他们的权限集。
我可以安装一个移动应用程序来代表我写推文,但我不能授权它代表 David Guetta 发推文。

“基本”身份验证在这里非常不合适：我们不想与第三方应用程序共享我们的密码。越多的人看到我们的密码,就越有可能被泄露。

此外,使用共享凭证保持审计跟踪是一场噩梦。当出现问题时,无法确定谁做了什么：真的是我吗？它是我与之共享凭据的 20 个应用程序之一吗？谁负责？

这是 OAuth 2 的教科书场景,第三方永远不会看到我们的用户名和密码。他们从认证服务器接收到一个不透明的访问令牌,我们的 API 知道如何检查以授予（或拒绝）访问权限。

## 5. 我们接下来应该做什么
浏览器是我们的主要目标,它已经决定了。我们的身份验证策略需要相应地发展！

我们将首先将我们的“基本”身份验证流程转换为具有基于会话的身份验证的登录表单。
我们将从头开始构建一个管理仪表板。它将包括一个登录表单、一个注销链接和一个更改密码的表单。它将给我们一个机会来讨论一些安全挑战（例如 XSS）,介绍新概念（例如 cookie、HMAC 标签）并尝试新工具（例如 flash 消息actix-session）。

这将是下一集的路线图！再见！

## 5.脚注
[^1] base64-encoding 确保输出中的所有字符都是ASCII,但它不提供任何保护：解码不需要秘密。换句话说,编码不是加密！<br>
[^2] 假设输入空间是有限的（即密码长度有上限）,理论上可以找到一个完美的散列函数 f(x) == f(y)隐含x == y。<br>
[^3] 在研究蛮力攻击时,您经常会看到彩虹表的提及,一种用于预先计算和查找哈希的有效数据结构。<br>
[^4] 这种粗略的计算应该清楚地表明,即使服务器使用快速散列算法存储密码,使用随机生成的密码也可以为您作为用户提供针对暴力攻击的显着保护级别. 始终使用密码管理器确实是提升安全配置文件的最简单方法之一。<br>
[^5] 一般来说,OWASP 是有关 Web 应用程序安全性的优质教育材料的宝库。您应该尽可能熟悉 OWASP 的材料,特别是如果您的团队/组织中没有应用程序安全专家来支持您。在我们链接的备忘单之上,确保浏览他们的应用程序安全验证标准。<br>
[^6] 这就是为什么 OWASP 建议增加一个额外的防御层的原因。存储在数据库中的所有哈希都使用共享密钥加密,只有应用程序知道。然而,加密也带来了一系列挑战：我们将把密钥存储在哪里？我们如何旋转它？答案通常涉及硬件安全模块 (HSM) 或秘密保险库,例如 AWS CloudHSM、AWS KMS 或 Hashicorp Vault。对密钥管理的全面概述超出了本书的范围。<br>
[^7] 我没有深入研究实现的不同哈希算法的源代码PasswordVerifier,但我确实想知道为什么verify_password需要将&self其作为参数。Argon2它绝对没有用,但它迫使我们通过一个Argon2::default才能调用verify_password.<br>
[^8] PasswordVerifier::verify_password还做了一件事,它依赖Output于比较两个哈希,而不是使用原始字节。Output的实现PartialEq和Eq旨在以恒定时间进行评估,无论输入有多么不同或相似,函数执行都将花费相同的时间。假设攻击者完全了解服务器正在使用的哈希算法配置,他们可以分析每次身份验证尝试的响应时间,以推断密码哈希的第一个字节,结合字典,这可以帮助他们破解密码。这种攻击的可行性是值得商榷的,当加盐到位时更是如此。尽管如此,这并不需要我们付出任何代价,安全总比后悔好。<br>
[^9] 我们的示例是故意过分简化的。实际上,这些状态中的每一个都将依次具有子状态 .await我们正在调用的函数体中的每个状态。未来可以变成一个深度嵌套的状态机！<br>
[^10] 在“异步：什么是阻塞？”中报告了这种启发式方法。由tokio的维护者之一 Alice Rhyl 提供。我强烈建议您阅读一篇文章,以更好地理解其基本tokio机制async/await！<br>
[^11] 在现实生活场景中,攻击者和您的服务器之间存在网络。负载和网络差异可能会掩盖一组有限尝试的速度差异,但如果您收集足够的数据点,应该可以注意到延迟的统计显着差异。<br>
[^12] 这就是为什么您永远不应该将密码输入不使用 HTTPS 的网站,即 HTTP + TLS。<br>
[^13] 实现一个安全的登录表单是它自己的挑战,你好CSRF！我们将在本章后面更仔细地研究它。
