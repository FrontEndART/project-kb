package org.infinispan.server.test.security.rest;

import static org.junit.Assert.assertEquals;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.SocketException;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.TrustManager;

import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpHead;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.HttpClientConnectionManager;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.infinispan.arquillian.core.InfinispanResource;
import org.infinispan.arquillian.core.RemoteInfinispanServer;
import org.infinispan.arquillian.core.RunningServer;
import org.infinispan.arquillian.core.WithRunningServer;
import org.infinispan.security.TestCachePermission;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.security.JBossJSSESecurityDomain;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;

/**
 * Tests CLIENT-CERT security for REST endpoint as is configured via "auth-method" attribute on "rest-connector" element
 * in datagrid subsystem.
 * <p/>
 * In order to configure CLIENT-CERT security, we add a new security-domain in the security subsystem
 * and a new https connector in the web subsystem. This is done via XSL transformations.
 * <p/>
 * Client authenticates himself with client.keystore file. Server contains jsse.keystore file in security subsystem as a
 * truststore and server.keystore file in the web connector as a certificate file. How to create and inspect those files
 * is described e.g. at http://docs.oracle.com/javase/6/docs/technotes/guides/security/jsse/JSSERefGuide.html
 * <p/>
 * Password for all the files is the same: "changeit" The user is allowed to connect to the secured REST endpoint with
 * "test" alias cos the server has this alias registered in its truststore. There's also another alias "test2" which is
 * used to verify that authentication fails - server does not have it in its truststore.
 * <p/>
 * The REST endpoint requires users to be in "REST" role which is defined in roles.properties.
 *
 * @author <a href="mailto:mgencur@redhat.com">Martin Gencur</a>
 */
@RunWith(Arquillian.class)
public class RESTCertSecurityIT {
    private static final String CONTAINER = "rest-security-cert";

    private static final String KEY_A = "a";
    private static final String KEY_B = "b";
    private static final String KEY_C = "c";
    private static final String KEY_D = "d";
    private static final String testAlias = "test";
    private static final String test2Alias = "test2";

    @InfinispanResource("rest-security-cert")
    RemoteInfinispanServer server;

    static CloseableHttpClient securedTest;
    static CloseableHttpClient securedTest2;

    @BeforeClass
    public static void setup() throws Exception {
       securedTest = securedClient(testAlias);
       securedTest2 = securedClient(test2Alias);
    }

    @AfterClass
    public static void tearDown() {
       try {
          securedTest.close();
       } catch (IOException e) {
       }
       try {
          securedTest2.close();
       } catch (IOException e) {
       }
    }


    @Ignore
    public void testSecuredReadWriteOperations() throws Exception {
        //correct alias for the certificate
        put(securedTest, keyAddress(KEY_A), HttpStatus.SC_OK);
        //test wrong authorization, 1. wrong alias for the certificate
        put(securedTest2, keyAddress(KEY_B), HttpStatus.SC_FORBIDDEN);
        //2. access over 8080
        put(securedTest, keyAddressUnsecured(KEY_B), HttpStatus.SC_UNAUTHORIZED);
        post(securedTest, keyAddress(KEY_C), HttpStatus.SC_OK);
        post(securedTest2, keyAddress(KEY_D), HttpStatus.SC_FORBIDDEN);
        //get is secured too
        HttpResponse resp = get(securedTest, keyAddress(KEY_A), HttpStatus.SC_OK);
        String content = new BufferedReader(new InputStreamReader(resp.getEntity().getContent())).readLine();
        assertEquals("data", content);
        //test wrong authorization, 1. wrong alias for the certificate
        get(securedTest2, keyAddress(KEY_A), HttpStatus.SC_FORBIDDEN);
        //2. access over 8080
        get(securedTest, keyAddressUnsecured(KEY_A), HttpStatus.SC_UNAUTHORIZED);
        head(securedTest2, keyAddress(KEY_A), HttpStatus.SC_FORBIDDEN);
        //access over 8080
        head(securedTest, keyAddressUnsecured(KEY_A), HttpStatus.SC_UNAUTHORIZED);
        head(securedTest, keyAddress(KEY_A), HttpStatus.SC_OK);
        delete(securedTest2, keyAddress(KEY_A), HttpStatus.SC_FORBIDDEN);
        delete(securedTest, keyAddress(KEY_A), HttpStatus.SC_OK);
        delete(securedTest, keyAddress(KEY_C), HttpStatus.SC_OK);
    }

    @Test
    @WithRunningServer({@RunningServer(name = CONTAINER, config = "testsuite/rest-sec-cert.xml")})
    public void testValidCertificateAccess() throws Exception {
        put(securedTest, keyAddress(KEY_A), HttpStatus.SC_OK);
    }

    @Test
    @WithRunningServer({@RunningServer(name = CONTAINER, config = "testsuite/rest-sec-cert.xml")})
    public void testInvalidCertificateAccess() throws Exception {
        put(securedTest2, keyAddress(KEY_A), HttpStatus.SC_FORBIDDEN);
    }

    private String keyAddress(String key) {
        return "https://" + server.getRESTEndpoint().getInetAddress().getHostName() + ":8443"
                + server.getRESTEndpoint().getContextPath() + "/default/" + key;
    }

    private String keyAddressUnsecured(String key) {
        return "http://" + server.getRESTEndpoint().getInetAddress().getHostName() + ":8080"
                + server.getRESTEndpoint().getContextPath() + "/default/" + key;
    }

    private HttpResponse handleIOException(IOException e, int expectedCode) throws IOException {
       if ((expectedCode == HttpStatus.SC_FORBIDDEN) && ((e instanceof SSLHandshakeException) || (e instanceof SocketException)))
          return null;
       else throw e;
    }

    private HttpResponse put(CloseableHttpClient httpClient, String uri, int expectedCode) throws Exception {
        HttpResponse response;
        HttpPut put = new HttpPut(uri);
        put.setEntity(new StringEntity("data", "UTF-8"));
        try {
           response = httpClient.execute(put);
           assertEquals(expectedCode, response.getStatusLine().getStatusCode());
           return response;
        } catch (IOException e) {
           return handleIOException(e, expectedCode);
        }
    }

    private HttpResponse post(CloseableHttpClient httpClient, String uri, int expectedCode) throws Exception {
        HttpResponse response;

        HttpPost post = new HttpPost(uri);
        post.setEntity(new StringEntity("data", "UTF-8"));
        response = httpClient.execute(post);
        assertEquals(expectedCode, response.getStatusLine().getStatusCode());
        return response;
    }

    private HttpResponse get(CloseableHttpClient httpClient, String uri, int expectedCode) throws Exception {
        HttpResponse response;
        HttpGet get = new HttpGet(uri);
        response = httpClient.execute(get);
        assertEquals(expectedCode, response.getStatusLine().getStatusCode());
        return response;
    }

    private HttpResponse delete(CloseableHttpClient httpClient, String uri, int expectedCode) throws Exception {
        HttpResponse response;
        HttpDelete delete = new HttpDelete(uri);
        response = httpClient.execute(delete);
        assertEquals(expectedCode, response.getStatusLine().getStatusCode());
        return response;
    }

    private HttpResponse head(CloseableHttpClient httpClient, String uri, int expectedCode) throws Exception {
        HttpResponse response;
        HttpHead head = new HttpHead(uri);
        response = httpClient.execute(head);
        assertEquals(expectedCode, response.getStatusLine().getStatusCode());
        return response;
    }

    public static CloseableHttpClient securedClient(String alias) throws Exception {
       ClassLoader tccl = Thread.currentThread().getContextClassLoader();
       SSLContext ctx = SSLContext.getInstance("TLS");
       JBossJSSESecurityDomain jsseSecurityDomain = new JBossJSSESecurityDomain("client_cert_auth");
       jsseSecurityDomain.setKeyStoreURL(tccl.getResource("client.keystore").getPath());
       jsseSecurityDomain.setKeyStorePassword("secret");
       jsseSecurityDomain.setClientAlias(alias);
       jsseSecurityDomain.setTrustStoreURL(tccl.getResource("truststore_client.jks").getPath());
       jsseSecurityDomain.setTrustStorePassword("secret");
       jsseSecurityDomain.reloadKeyAndTrustStore();
       KeyManager[] keyManagers = jsseSecurityDomain.getKeyManagers();
       TrustManager[] trustManagers = jsseSecurityDomain.getTrustManagers();
       ctx.init(keyManagers, trustManagers, null);
       HostnameVerifier verifier = (hostname, sslSession) -> true;
       ConnectionSocketFactory sslssf = new SSLConnectionSocketFactory(ctx, verifier);
       ConnectionSocketFactory plainsf = new PlainConnectionSocketFactory();
       Registry<ConnectionSocketFactory> sr = RegistryBuilder.<ConnectionSocketFactory>create()
               .register("http", plainsf)
               .register("https", sslssf)
               .build();
       HttpClientConnectionManager pcm = new PoolingHttpClientConnectionManager(sr);
       CloseableHttpClient httpClient = HttpClients.custom()
               .setConnectionManager(pcm)
               .build();

       return httpClient;
    }
}
