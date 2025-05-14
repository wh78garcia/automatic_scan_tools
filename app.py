from flask import Flask, request
import sqlite3

app = Flask(__name__)

# init database（SQLite）
def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT
        )
    ''')
    # 插入测试数据
    cursor.execute("INSERT INTO users (username, password) VALUES ('user1', 'user1pass')")
    cursor.execute("INSERT INTO users (username, password) VALUES ('admin', '123456')")
    cursor.execute("INSERT INTO users (username, password) VALUES ('guest', 'password')")
    conn.commit()
    conn.close()

# 有漏洞的查询接口
@app.route('/user')
def get_user():
    user_id = request.args.get('id')  # 直接拼接SQL，存在注入漏洞！
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # The vulnerability is here!
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    result = cursor.fetchall()
    conn.close()
    
    if result:
        return f"user infomation is : {result}"
    else:
        return "user doesn't exist"

@app.route('/admin')
def get_admin_info():
    return 'admin is hackme'


@app.route('/config')
def get_config_info():
    return 'You get the config info'


if __name__ == '__main__':
    init_db()
    app.run(debug=True)  # 启动Flask服务