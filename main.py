from chat_app import create_app

# 创建 Flask 应用实例和 SocketIO 实例
app, socketio = create_app()

# 只有当该脚本作为主程序运行时才执行
if __name__ == '__main__':
    # 启动 SocketIO 服务器，并运行 Flask 应用
    # debug=True 开启调试模式，方便开发
    socketio.run(app, debug=True)