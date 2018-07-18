package com.liangfan.main.auth;

import com.alibaba.fastjson.JSON;
import com.liangfan.main.context.LiangFanContext;
import com.liangfan.main.context.LiangFanToken;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.HttpEntity;
import org.apache.http.NameValuePair;
import org.apache.http.StatusLine;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.apache.http.util.TextUtils;
import sun.misc.BASE64Encoder;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.*;

public class OauthService {
    public final static Random RAND = new Random();

    public static String buildUri(String methodName, String uri, List<SignatureParam> params,LiangFanToken token,String username,String password) {

        StringBuilder sb=new StringBuilder();
        if (null == params) {
            params = new ArrayList<SignatureParam>();
        }
        long timestamp = System.currentTimeMillis() / 1000;
        long nonce = timestamp + RAND.nextInt();
        List<SignatureParam> oAuthHeaderParams = new ArrayList<>();
        oAuthHeaderParams.add(new SignatureParam("oauth_consumer_key", LiangFanContext.CONSUMER_KEY));
        oAuthHeaderParams.add(new SignatureParam("oauth_signature_method", LiangFanContext.SIGNATURE_METHOD));
        oAuthHeaderParams.add(new SignatureParam("oauth_timestamp", String.valueOf(timestamp)));
        oAuthHeaderParams.add(new SignatureParam("oauth_nonce", String.valueOf(nonce)));
        oAuthHeaderParams.add(new SignatureParam("oauth_version", LiangFanContext.OAUTH_VERSION));
        oAuthHeaderParams.add(new SignatureParam("x_auth_username", username));
        oAuthHeaderParams.add(new SignatureParam("x_auth_password", password));
        oAuthHeaderParams.add(new SignatureParam("x_auth_mode", "client_auth"));

        if (token != null) {
            oAuthHeaderParams.add(new SignatureParam("oauth_token", token.getToken()));
        }
        List<SignatureParam> baseParams = new ArrayList<>(params.size() + oAuthHeaderParams.size());
        baseParams.addAll(oAuthHeaderParams);
        if (params != null && methodName != HttpGet.METHOD_NAME.toString() && !SignatureParam.hasFile(params)) {
            baseParams.addAll(params);
        }

        //解析URL中可能存在的参数
        parseGetParam(uri, baseParams);
        //编码BaseURL
        String encodeUrl = encodeUrl(constructRequestURL(uri));
        //参数排序
        Collections.sort(baseParams);
        //参数拼接
        String s = concatParam(baseParams);
        //参数编码
        String encodeParam = encodeUrl(s);

        StringBuffer base = new StringBuffer(methodName).append("&")
                .append(encodeUrl).append("&").append(encodeParam);
        System.out.println("basestring is "+base);
        SecretKeySpec secretKeySpec = getSecretKeySpec(token);
        oAuthHeaderParams.add(new SignatureParam("oauth_signature", getSignature(base.toString(), secretKeySpec)));
        System.out.println("参数:" + JSON.toJSONString(oAuthHeaderParams));

        for (SignatureParam param : oAuthHeaderParams) {
            if(sb.length()!=0){
                sb.append("&");
            }
            sb.append(param.getName()+"="+param.getValue());
        }
        uri+=sb.toString();
        return uri;

    }

    private static String getSignature(final String data,
                                       final SecretKeySpec spec) {
        byte[] byteHMAC = null;
        try {
            final Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(spec);
            byteHMAC = mac.doFinal(data.getBytes());
        } catch (final InvalidKeyException ike) {
            throw new AssertionError(ike);
        } catch (final NoSuchAlgorithmException nsae) {
            throw new AssertionError(nsae);
        }
        return new BASE64Encoder().encode(byteHMAC);
    }

    private static String constructRequestURL(String url) {
        final int index = url.indexOf("?");
        if (-1 != index) {
            url = url.substring(0, index);
        }
        final int slashIndex = url.indexOf("/", 8);
        final String baseURL = url.substring(0, slashIndex).toLowerCase();
        url = baseURL + url.substring(slashIndex);

        return url;
    }


    static SecretKeySpec getSecretKeySpec(final LiangFanToken token) {
        if (null == token) {
            final String oauthSignature = encodeUrl(LiangFanContext.CONSUMER_SECRET) + "&";
            return new SecretKeySpec(oauthSignature.getBytes(), "HmacSHA1");
        } else {
            final String oauthSignature = encodeUrl(LiangFanContext.CONSUMER_SECRET)
                    + "&"
                    + encodeUrl(token.getTokenSecret());
            return new SecretKeySpec(oauthSignature.getBytes(), "HmacSHA1");
        }
    }

    private static String concatParam(List<SignatureParam> baseParams) {
        StringBuilder sb = new StringBuilder();
        for (SignatureParam param : baseParams) {
            if (!param.isFile()) {
                if(sb.length()!=0){
                    sb.append("&");
                }
                sb.append(encodeUrl(param.getName()));
                sb.append("=");
                sb.append(encodeUrl(param.getValue()));
            }
        }
        return sb.toString();
    }

    //重新编码URI,替换其中的特殊字符
    private static String encodeUrl(String uri) {
        String encoded = null;
        try {
            encoded = URLEncoder.encode(uri, "UTF-8");
        } catch (final UnsupportedEncodingException ignore) {
        }
        if (!TextUtils.isEmpty(encoded)) {
            final StringBuilder buf = new StringBuilder(encoded.length());
            char focus;
            for (int i = 0; i < encoded.length(); i++) {
                focus = encoded.charAt(i);
                if (focus == '*') {
                    buf.append("%2A");
                } else if (focus == '+') {
                    buf.append("%20");
                } else if ((focus == '%') && ((i + 1) < encoded.length())
                        && (encoded.charAt(i + 1) == '7')
                        && (encoded.charAt(i + 2) == 'E')) {
                    buf.append('~');
                    i += 2;
                } else {
                    buf.append(focus);
                }
            }
            return buf.toString();
        }
        return uri;
    }

    //解析URL中可能存在的参数
    private static void parseGetParam(String uri, List<SignatureParam> baseParams) {
        int i = uri.indexOf("?");
        if (i != -1) {
            String substring = uri.substring(i + 1);
            String[] split = substring.split("&");
            if (split.length > 0) {
                for (String item : split) {
                    String[] nameValuePair = item.split("=");
                    if (nameValuePair.length == 2) {
                        try {
                            baseParams.add(new SignatureParam(URLDecoder.decode(nameValuePair[0], "UTF-8"), URLDecoder.decode(nameValuePair[1], "UTF-8")));
                        } catch (UnsupportedEncodingException e) {
                            e.printStackTrace();
                        }
                    }
                }
            }
        }
    }

    public static void main(String[] args) {
        String uri="http://api.fanfou.com/account/find_friends.json?";

        //StringBuilder sb=new StringBuilder();
        //String s1 = buildUri("GET", uri, null, null, "slsongliang@gmail.com", "sl15838920071");


        CloseableHttpClient httpClient = HttpClients.createDefault();
        String s1 = buildUri("GET", LiangFanContext.ACCESS_TOKEN_URL+"?", null, null, "slsongliang@gmail.com", "sl15838920071");
        System.out.println(s1);


        try {
            HttpGet httpGet = new HttpGet(s1);
            CloseableHttpResponse execute = httpClient.execute(httpGet);

            HttpEntity entity = execute.getEntity();
            String s = EntityUtils.toString(entity);
            LiangFanToken from = LiangFanToken.from(s);
           // String s2 = buildUri("GET", uri, null, from, "slsongliang@gmail.com", "sl15838920071");
            String s2 = buildUri("POST", uri, null, from, "slsongliang@gmail.com", "sl15838920071");
//            HttpGet httpGet2 = new HttpGet(s2);
//            CloseableHttpResponse execute2 = httpClient.execute(httpGet2);
//            HttpEntity entity1 = execute2.getEntity();
//            String ss = EntityUtils.toString(entity1);
//
//            System.out.println(ss);
            execPost(s2);


        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    public static void execPost(String s){
        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpPost post=new HttpPost(s);
        //装填参数
        List<NameValuePair> nvps = new ArrayList<NameValuePair>();
        List<NameValuePair> map=new ArrayList<>();

        try {
            CloseableHttpResponse execute = httpClient.execute(post);
            HttpEntity entity1 = execute.getEntity();
            String ss = EntityUtils.toString(entity1);

            System.out.println(ss);

        } catch (IOException e) {


        }
    }
}
