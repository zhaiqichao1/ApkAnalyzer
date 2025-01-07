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

    // 监控 WebView
    try {
        var WebView = Java.use('android.webkit.WebView');
        
        // 监控 loadUrl
        WebView.loadUrl.overload('java.lang.String').implementation = function(url) {
            send({
                type: 'webview',
                url: url,
                method: 'loadUrl',
                timestamp: new Date().toISOString()
            });
            return this.loadUrl(url);
        };
        
        // 监控 loadData
        WebView.loadData.implementation = function(data, mimeType, encoding) {
            send({
                type: 'webview',
                data: data,
                mimeType: mimeType,
                encoding: encoding,
                method: 'loadData',
                timestamp: new Date().toISOString()
            });
            return this.loadData(data, mimeType, encoding);
        };
        
        // 监控 loadDataWithBaseURL
        WebView.loadDataWithBaseURL.implementation = function(baseUrl, data, mimeType, encoding, historyUrl) {
            send({
                type: 'webview',
                baseUrl: baseUrl,
                data: data,
                mimeType: mimeType,
                encoding: encoding,
                historyUrl: historyUrl,
                method: 'loadDataWithBaseURL',
                timestamp: new Date().toISOString()
            });
            return this.loadDataWithBaseURL(baseUrl, data, mimeType, encoding, historyUrl);
        };
        
        // 监控 postUrl
        WebView.postUrl.implementation = function(url, postData) {
            send({
                type: 'webview',
                url: url,
                postData: postData ? postData.toString() : null,
                method: 'postUrl',
                timestamp: new Date().toISOString()
            });
            return this.postUrl(url, postData);
        };
        
        // 监控 WebViewClient
        var WebViewClient = Java.use('android.webkit.WebViewClient');
        
        WebViewClient.onLoadResource.implementation = function(view, url) {
            send({
                type: 'webview',
                url: url.toString(),
                method: 'onLoadResource',
                timestamp: new Date().toISOString()
            });
            return this.onLoadResource(view, url);
        };
        
        WebViewClient.shouldInterceptRequest.overload('android.webkit.WebView', 'java.lang.String').implementation = function(view, url) {
            send({
                type: 'webview',
                url: url,
                method: 'shouldInterceptRequest',
                timestamp: new Date().toISOString()
            });
            return this.shouldInterceptRequest(view, url);
        };
    } catch(e) {
        console.log("WebView hook error: " + e);
    }

    // 添加 HttpURLConnection 监控
    var HttpURLConnection = Java.use("java.net.HttpURLConnection");
    HttpURLConnection.connect.implementation = function() {
        try {
            var url = this.getURL().toString();
            var host = this.getURL().getHost();
            send({
                type: 'http',
                url: url,
                host: host,
                timestamp: new Date().toISOString()
            });
        } catch(e) {}
        return this.connect();
    };

    // 添加 OkHttp 监控
    try {
        var OkHttpClient = Java.use('okhttp3.OkHttpClient');
        OkHttpClient.newCall.implementation = function(request) {
            try {
                var url = request.url().toString();
                var host = request.url().host();
                send({
                    type: 'okhttp',
                    url: url,
                    host: host,
                    timestamp: new Date().toISOString()
                });
            } catch(e) {}
            return this.newCall(request);
        };
    } catch(e) {}

    // 添加 Apache HttpClient 监控
    try {
        var DefaultHttpClient = Java.use('org.apache.http.impl.client.DefaultHttpClient');
        DefaultHttpClient.execute.overload('org.apache.http.HttpHost', 'org.apache.http.HttpRequest').implementation = function(host, request) {
            try {
                send({
                    type: 'apache',
                    host: host ? host.getHostName() : '',
                    timestamp: new Date().toISOString()
                });
            } catch(e) {}
            return this.execute(host, request);
        };
    } catch(e) {}

    // 添加 SSLSocket 监控
    try {
        var SSLSocket = Java.use('javax.net.ssl.SSLSocket');
        SSLSocket.startHandshake.implementation = function() {
            try {
                var host = this.getInetAddress().getHostName();
                var port = this.getPort();
                send({
                    type: 'ssl',
                    host: host,
                    port: port,
                    timestamp: new Date().toISOString()
                });
            } catch(e) {}
            return this.startHandshake();
        };
    } catch(e) {}
}); 