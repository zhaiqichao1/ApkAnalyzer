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
        var WebViewClient = Java.use('android.webkit.WebViewClient');
        var WebResourceRequest = Java.use('android.webkit.WebResourceRequest');
        var WebResourceResponse = Java.use('android.webkit.WebResourceResponse');
        
        // 监控所有 WebView loadUrl 方法
        WebView.loadUrl.overload('java.lang.String').implementation = function(url) {
            send({
                type: 'webview',
                subtype: 'loadUrl',
                url: url,
                timestamp: new Date().toISOString()
            });
            return this.loadUrl(url);
        };

        WebView.loadUrl.overload('java.lang.String', 'java.util.Map').implementation = function(url, headers) {
            send({
                type: 'webview',
                subtype: 'loadUrlWithHeaders',
                url: url,
                headers: JSON.stringify(headers),
                timestamp: new Date().toISOString()
            });
            return this.loadUrl(url, headers);
        };

        // 监控 WebViewClient 的所有网络相关方法
        WebViewClient.$init.implementation = function() {
            var client = this.$init();

            // 重写 shouldInterceptRequest 方法
            if (!this.shouldInterceptRequest.overload('android.webkit.WebView', 'android.webkit.WebResourceRequest').implementation) {
                this.shouldInterceptRequest.overload('android.webkit.WebView', 'android.webkit.WebResourceRequest').implementation = function(view, request) {
                    try {
                        var url = request.getUrl().toString();
                        var method = request.getMethod();
                        var headers = request.getRequestHeaders();
                        
                        send({
                            type: 'webview',
                            subtype: 'shouldInterceptRequest',
                            url: url,
                            method: method,
                            headers: JSON.stringify(headers),
                            timestamp: new Date().toISOString()
                        });
                    } catch(e) {}
                    return this.shouldInterceptRequest(view, request);
                };
            }

            // 监控页面开始加载
            if (!this.onPageStarted.implementation) {
                this.onPageStarted.implementation = function(view, url, favicon) {
                    send({
                        type: 'webview',
                        subtype: 'onPageStarted',
                        url: url,
                        timestamp: new Date().toISOString()
                    });
                    return this.onPageStarted(view, url, favicon);
                };
            }

            // 监控资源加载
            if (!this.onLoadResource.implementation) {
                this.onLoadResource.implementation = function(view, url) {
                    send({
                        type: 'webview',
                        subtype: 'onLoadResource',
                        url: url,
                        timestamp: new Date().toISOString()
                    });
                    return this.onLoadResource(view, url);
                };
            }

            return client;
        };

        // 监控 WebChromeClient
        try {
            var WebChromeClient = Java.use('android.webkit.WebChromeClient');
            WebChromeClient.$init.implementation = function() {
                var client = this.$init();

                // 监控 onConsoleMessage
                if (!this.onConsoleMessage.implementation) {
                    this.onConsoleMessage.implementation = function(consoleMessage) {
                        try {
                            var message = consoleMessage.message();
                            if (message.indexOf('http') !== -1 || message.indexOf('https') !== -1) {
                                send({
                                    type: 'webview',
                                    subtype: 'console',
                                    url: message,
                                    timestamp: new Date().toISOString()
                                });
                            }
                        } catch(e) {}
                        return this.onConsoleMessage(consoleMessage);
                    };
                }

                return client;
            };
        } catch(e) {}

        // 监控 WebSettings
        var WebSettings = Java.use('android.webkit.WebSettings');
        WebSettings.setJavaScriptEnabled.implementation = function(enabled) {
            send({
                type: 'webview',
                subtype: 'settings',
                action: 'setJavaScriptEnabled',
                value: enabled,
                timestamp: new Date().toISOString()
            });
            return this.setJavaScriptEnabled(enabled);
        };

    } catch(e) {
        console.log("WebView hook error: " + e);
    }

    // 监控 XMLHttpRequest
    try {
        var XMLHttpRequest = Java.use('org.chromium.android_webview.AwContents');
        XMLHttpRequest.onRequest.implementation = function(request) {
            try {
                send({
                    type: 'webview',
                    subtype: 'xhr',
                    url: request.url.toString(),
                    method: request.method,
                    timestamp: new Date().toISOString()
                });
            } catch(e) {}
            return this.onRequest(request);
        };
    } catch(e) {}

    // 监控 Fetch API
    try {
        var fetch = Java.use('com.android.webview.chromium.WebViewChromium');
        fetch.loadUrl.implementation = function(url) {
            if (url.indexOf('fetch') !== -1) {
                send({
                    type: 'webview',
                    subtype: 'fetch',
                    url: url,
                    timestamp: new Date().toISOString()
                });
            }
            return this.loadUrl(url);
        };
    } catch(e) {}

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

    // 监控 WebSocket
    try {
        // 监控标准 WebSocket
        var WebSocket = Java.use('java.net.WebSocket');
        if (WebSocket) {
            WebSocket.connect.implementation = function() {
                try {
                    var url = this.getURI().toString();
                    send({
                        type: 'websocket',
                        subtype: 'connect',
                        url: url,
                        timestamp: new Date().toISOString()
                    });
                } catch(e) {}
                return this.connect();
            };
        }
    } catch(e) {}

    // 监控 OkHttp WebSocket
    try {
        var OkHttpClient = Java.use('okhttp3.OkHttpClient');
        var WebSocketListener = Java.use('okhttp3.WebSocketListener');
        
        OkHttpClient.newWebSocket.implementation = function(request, listener) {
            try {
                var url = request.url().toString();
                send({
                    type: 'websocket',
                    subtype: 'okhttp',
                    url: url,
                    timestamp: new Date().toISOString()
                });
            } catch(e) {}
            return this.newWebSocket(request, listener);
        };
    } catch(e) {}

    // 监控 Android WebSocket
    try {
        var WebSocketClient = Java.use('org.java_websocket.client.WebSocketClient');
        WebSocketClient.connect.implementation = function() {
            try {
                var url = this.getURI().toString();
                send({
                    type: 'websocket',
                    subtype: 'java_websocket',
                    url: url,
                    timestamp: new Date().toISOString()
                });
            } catch(e) {}
            return this.connect();
        };
    } catch(e) {}

    // 监控 WebView WebSocket
    try {
        var WebView = Java.use('android.webkit.WebView');
        
        // 监控 WebSocket JavaScript Bridge
        WebView.evaluateJavascript.implementation = function(script, callback) {
            try {
                if (script.indexOf('WebSocket') !== -1) {
                    var wsMatch = script.match(/WebSocket\(['"](.*?)['"]\)/);
                    if (wsMatch) {
                        send({
                            type: 'websocket',
                            subtype: 'webview_js',
                            url: wsMatch[1],
                            timestamp: new Date().toISOString()
                        });
                    }
                }
            } catch(e) {}
            return this.evaluateJavascript(script, callback);
        };
    } catch(e) {}

    // 监控 Jetty WebSocket
    try {
        var WebSocketClientFactory = Java.use('org.eclipse.jetty.websocket.client.WebSocketClient');
        WebSocketClientFactory.connect.implementation = function(uri, handler) {
            try {
                send({
                    type: 'websocket',
                    subtype: 'jetty',
                    url: uri.toString(),
                    timestamp: new Date().toISOString()
                });
            } catch(e) {}
            return this.connect(uri, handler);
        };
    } catch(e) {}

    // 监控 Apache Tomcat WebSocket
    try {
        var WsWebSocketContainer = Java.use('org.apache.tomcat.websocket.WsWebSocketContainer');
        WsWebSocketContainer.connectToServer.implementation = function(endpoint, path) {
            try {
                send({
                    type: 'websocket',
                    subtype: 'tomcat',
                    url: path.toString(),
                    timestamp: new Date().toISOString()
                });
            } catch(e) {}
            return this.connectToServer(endpoint, path);
        };
    } catch(e) {}
}); 