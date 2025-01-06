// 监控网络请求的 Frida 脚本
Java.perform(function() {
    // 监控 URL 请求
    var URL = Java.use("java.net.URL");
    URL.$init.overload('java.lang.String').implementation = function(url) {
        send({
            type: 'url',
            url: url,
            timestamp: new Date().toISOString()
        });
        return this.$init(url);
    };
    
    // 监控 Socket 连接
    var Socket = Java.use("java.net.Socket");
    Socket.$init.overload('java.lang.String', 'int').implementation = function(host, port) {
        send({
            type: 'socket',
            host: host,
            port: port,
            timestamp: new Date().toISOString()
        });
        return this.$init(host, port);
    };
}); 