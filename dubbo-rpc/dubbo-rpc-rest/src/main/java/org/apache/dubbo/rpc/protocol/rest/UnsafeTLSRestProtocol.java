package org.apache.dubbo.rpc.protocol.rest;

import static org.apache.dubbo.common.constants.CommonConstants.COMMA_SPLIT_PATTERN;
import static org.apache.dubbo.common.constants.CommonConstants.DEFAULT_TIMEOUT;
import static org.apache.dubbo.common.constants.CommonConstants.INTERFACE_KEY;
import static org.apache.dubbo.common.constants.CommonConstants.TIMEOUT_KEY;
import static org.apache.dubbo.remoting.Constants.CONNECTIONS_KEY;
import static org.apache.dubbo.remoting.Constants.CONNECT_TIMEOUT_KEY;
import static org.apache.dubbo.remoting.Constants.DEFAULT_CONNECT_TIMEOUT;
import static org.apache.dubbo.remoting.Constants.SERVER_KEY;
import static org.apache.dubbo.rpc.protocol.rest.Constants.EXTENSION_KEY;

import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLContext;
import javax.servlet.ServletContext;
import javax.ws.rs.ProcessingException;
import javax.ws.rs.WebApplicationException;

import org.apache.dubbo.common.URL;
import org.apache.dubbo.common.utils.StringUtils;
import org.apache.dubbo.remoting.http.HttpBinder;
import org.apache.dubbo.remoting.http.servlet.BootstrapListener;
import org.apache.dubbo.remoting.http.servlet.ServletManager;
import org.apache.dubbo.rpc.RpcException;
import org.apache.dubbo.rpc.model.ApplicationModel;
import org.apache.dubbo.rpc.protocol.AbstractProxyProtocol;
import org.apache.http.HeaderElement;
import org.apache.http.HeaderElementIterator;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.config.SocketConfig;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.LayeredConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLContexts;
import org.apache.http.conn.ssl.TrustStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.message.BasicHeaderElementIterator;
import org.apache.http.protocol.HTTP;
import org.jboss.resteasy.client.jaxrs.ResteasyClient;
import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
import org.jboss.resteasy.client.jaxrs.ResteasyWebTarget;
import org.jboss.resteasy.client.jaxrs.engines.ApacheHttpClient4Engine;
import org.jboss.resteasy.util.GetRestful;

/**
 * @author mpc
 * 2019-11-28
 * 完全照抄了RestProtocol，修改了doRefer，改为支持https，并且信任任何证书，并且不进行主机验证。
 *
 */
public class UnsafeTLSRestProtocol extends AbstractProxyProtocol {

    private static final int DEFAULT_PORT = 80;
    private static final String DEFAULT_SERVER = "jetty";

    private static final int HTTPCLIENTCONNECTIONMANAGER_MAXPERROUTE = 20;
    private static final int HTTPCLIENTCONNECTIONMANAGER_MAXTOTAL = 20;
    private static final int HTTPCLIENT_KEEPALIVEDURATION = 30 * 1000;
    private static final int HTTPCLIENTCONNECTIONMANAGER_CLOSEWAITTIME_MS = 1000;
    private static final int HTTPCLIENTCONNECTIONMANAGER_CLOSEIDLETIME_S = 30;

    private final Map<String, RestServer> servers = new ConcurrentHashMap<>();

    private final RestServerFactory serverFactory = new RestServerFactory();

    // TODO in the future maybe we can just use a single rest client and connection manager
    private final List<ResteasyClient> clients = Collections.synchronizedList(new LinkedList<>());

    private volatile ConnectionMonitor connectionMonitor;

    public UnsafeTLSRestProtocol() {
        super(WebApplicationException.class, ProcessingException.class);
    }

    public void setHttpBinder(HttpBinder httpBinder) {
        serverFactory.setHttpBinder(httpBinder);
    }

    @Override
    public int getDefaultPort() {
        return DEFAULT_PORT;
    }

    @SuppressWarnings("rawtypes")
    @Override
    protected <T> Runnable doExport(T impl, Class<T> type, URL url) throws RpcException {
        String addr = getAddr(url);
        
        Class implClass = ApplicationModel.getProviderModel(url.getPathKey()).getServiceInstance().getClass();
        RestServer server = servers.computeIfAbsent(addr, restServer -> {
            RestServer s = serverFactory.createServer(url.getParameter(SERVER_KEY, DEFAULT_SERVER));
            s.start(url);
            return s;
        });

        String contextPath = getContextPath(url);
        if ("servlet".equalsIgnoreCase(url.getParameter(SERVER_KEY, DEFAULT_SERVER))) {
            ServletContext servletContext = ServletManager.getInstance().getServletContext(ServletManager.EXTERNAL_SERVER_PORT);
            if (servletContext == null) {
                throw new RpcException("No servlet context found. Since you are using server='servlet', " +
                        "make sure that you've configured " + BootstrapListener.class.getName() + " in web.xml");
            }
            String webappPath = servletContext.getContextPath();
            if (StringUtils.isNotEmpty(webappPath)) {
                webappPath = webappPath.substring(1);
                if (!contextPath.startsWith(webappPath)) {
                    throw new RpcException("Since you are using server='servlet', " +
                            "make sure that the 'contextpath' property starts with the path of external webapp");
                }
                contextPath = contextPath.substring(webappPath.length());
                if (contextPath.startsWith("/")) {
                    contextPath = contextPath.substring(1);
                }
            }
        }

        final Class resourceDef = GetRestful.getRootResourceClass(implClass) != null ? implClass : type;

        server.deploy(resourceDef, impl, contextPath);

        final RestServer s = server;
        return () -> {
            // TODO due to dubbo's current architecture,
            // it will be called from registry protocol in the shutdown process and won't appear in logs
            s.undeploy(resourceDef);
        };
    }

    @Override
    protected <T> T doRefer(Class<T> serviceType, URL url) throws RpcException {
        LayeredConnectionSocketFactory sslSF = null;
        try {  
            KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
            //信任任何链接  
            TrustStrategy anyTrustStrategy = new TrustStrategy() {  
                @Override  
                public boolean isTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {  
                    return true;  
                }  
            };  
            SSLContext sslContext = SSLContexts.custom().useTLS().loadTrustMaterial(trustStore, anyTrustStrategy).build();  
            sslSF = new SSLConnectionSocketFactory(sslContext, SSLConnectionSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);  
        } catch (KeyStoreException e) {  
            throw new RuntimeException(e);  
        } catch (KeyManagementException e) {  
            throw new RuntimeException(e);  
        } catch (NoSuchAlgorithmException e) {  
            throw new RuntimeException(e);  
        }  
        
        
        
        Registry<ConnectionSocketFactory> registry = RegistryBuilder.<ConnectionSocketFactory>create()
        .register("http", PlainConnectionSocketFactory.getSocketFactory())
        .register("https", sslSF)
        .build();
        
        PoolingHttpClientConnectionManager connectionManager = new PoolingHttpClientConnectionManager(registry);
        // 20 is the default maxTotal of current PoolingClientConnectionManager
        connectionManager.setMaxTotal(url.getParameter(CONNECTIONS_KEY, HTTPCLIENTCONNECTIONMANAGER_MAXTOTAL));
        connectionManager.setDefaultMaxPerRoute(url.getParameter(CONNECTIONS_KEY, HTTPCLIENTCONNECTIONMANAGER_MAXPERROUTE));

        if (connectionMonitor == null) {
            connectionMonitor = new ConnectionMonitor();
            connectionMonitor.start();
        }
        connectionMonitor.addConnectionManager(connectionManager);
        
        RequestConfig requestConfig = RequestConfig.custom()
                .setConnectTimeout(url.getParameter(CONNECT_TIMEOUT_KEY, DEFAULT_CONNECT_TIMEOUT))
                .setSocketTimeout(url.getParameter(TIMEOUT_KEY, DEFAULT_TIMEOUT))
                .build();

        SocketConfig socketConfig = SocketConfig.custom()
                .setSoKeepAlive(true)
                .setTcpNoDelay(true)
                .build();

        CloseableHttpClient httpClient = HttpClientBuilder.create()
                .setConnectionManager(connectionManager)
                .setKeepAliveStrategy((response, context) -> {
                    HeaderElementIterator it = new BasicHeaderElementIterator(response.headerIterator(HTTP.CONN_KEEP_ALIVE));
                    while (it.hasNext()) {
                        HeaderElement he = it.nextElement();
                        String param = he.getName();
                        String value = he.getValue();
                        if (value != null && param.equalsIgnoreCase(TIMEOUT_KEY)) {
                            return Long.parseLong(value) * 1000;
                        }
                    }
                    return HTTPCLIENT_KEEPALIVEDURATION;
                })
                .setDefaultRequestConfig(requestConfig)
                .setDefaultSocketConfig(socketConfig)
                .build();

        ApacheHttpClient4Engine engine = new ApacheHttpClient4Engine(httpClient);

        ResteasyClient client = new ResteasyClientBuilder().httpEngine(engine).build();
        clients.add(client);

        client.register(RpcContextFilter.class);
        for (String clazz : COMMA_SPLIT_PATTERN.split(url.getParameter(EXTENSION_KEY, ""))) {
            if (!StringUtils.isEmpty(clazz)) {
                try {
                    client.register(Thread.currentThread().getContextClassLoader().loadClass(clazz.trim()));
                } catch (ClassNotFoundException e) {
                    throw new RpcException("Error loading JAX-RS extension class: " + clazz.trim(), e);
                }
            }
        }

        // TODO protocol
        ResteasyWebTarget target = client.target("https://" + url.getHost() + ":" + url.getPort() + "/" + getContextPath(url));
        return target.proxy(serviceType);
    }

    @Override
    protected int getErrorCode(Throwable e) {
        // TODO
        return super.getErrorCode(e);
    }

    @Override
    public void destroy() {
        super.destroy();

        if (connectionMonitor != null) {
            connectionMonitor.shutdown();
        }

        for (Map.Entry<String, RestServer> entry : servers.entrySet()) {
            try {
                if (logger.isInfoEnabled()) {
                    logger.info("Closing the rest server at " + entry.getKey());
                }
                entry.getValue().stop();
            } catch (Throwable t) {
                logger.warn("Error closing rest server", t);
            }
        }
        servers.clear();

        if (logger.isInfoEnabled()) {
            logger.info("Closing rest clients");
        }
        for (ResteasyClient client : clients) {
            try {
                client.close();
            } catch (Throwable t) {
                logger.warn("Error closing rest client", t);
            }
        }
        clients.clear();
    }

    /**
     *  getPath() will return: [contextpath + "/" +] path
     *  1. contextpath is empty if user does not set through ProtocolConfig or ProviderConfig
     *  2. path will never be empty, it's default value is the interface name.
     *
     * @return return path only if user has explicitly gave then a value.
     */
    protected String getContextPath(URL url) {
        String contextPath = url.getPath();
        if (contextPath != null) {
            if (contextPath.equalsIgnoreCase(url.getParameter(INTERFACE_KEY))) {
                return "";
            }
            if (contextPath.endsWith(url.getParameter(INTERFACE_KEY))) {
                contextPath = contextPath.substring(0, contextPath.lastIndexOf(url.getParameter(INTERFACE_KEY)));
            }
            return contextPath.endsWith("/") ? contextPath.substring(0, contextPath.length() - 1) : contextPath;
        } else {
            return "";
        }
    }

    protected class ConnectionMonitor extends Thread {
        private volatile boolean shutdown;
        private final List<PoolingHttpClientConnectionManager> connectionManagers = Collections.synchronizedList(new LinkedList<>());

        public void addConnectionManager(PoolingHttpClientConnectionManager connectionManager) {
            connectionManagers.add(connectionManager);
        }

        @Override
        public void run() {
            try {
                while (!shutdown) {
                    synchronized (this) {
                        wait(HTTPCLIENTCONNECTIONMANAGER_CLOSEWAITTIME_MS);
                        for (PoolingHttpClientConnectionManager connectionManager : connectionManagers) {
                            connectionManager.closeExpiredConnections();
                            connectionManager.closeIdleConnections(HTTPCLIENTCONNECTIONMANAGER_CLOSEIDLETIME_S, TimeUnit.SECONDS);
                        }
                    }
                }
            } catch (InterruptedException ex) {
                shutdown();
            }
        }

        public void shutdown() {
            shutdown = true;
            connectionManagers.clear();
            synchronized (this) {
                notifyAll();
            }
        }
    }
}
